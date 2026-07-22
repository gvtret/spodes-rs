use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{ActionSet, ValueDefinition};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`RegisterMonitor`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterMonitorConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of threshold values, of the monitored attribute's type.
    pub thresholds: Vec<CosemDataType>,
    /// Attribute 3: `value_definition` structure { class_id, logical_name, attribute_index }.
    pub monitored_value: ValueDefinition,
    /// Attribute 4: array of `action_set` structures paired with the thresholds.
    pub actions: Vec<ActionSet>,
}

/// `Register monitor` interface class (class_id = 21, version = 0) per
/// IEC 62056-6-2 §4.5.6. Executes scripts when the monitored value crosses one
/// of the thresholds.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterMonitor {
    logical_name: ObisCode,
    thresholds: Vec<CosemDataType>,
    monitored_value: ValueDefinition,
    actions: Vec<ActionSet>,
}

impl RegisterMonitor {
    /// Builds a new [`RegisterMonitor`] from its configuration.
    pub fn new(config: RegisterMonitorConfig) -> Self {
        RegisterMonitor {
            logical_name: config.logical_name,
            thresholds: config.thresholds,
            monitored_value: config.monitored_value,
            actions: config.actions,
        }
    }
}

impl InterfaceClass for RegisterMonitor {
    fn class_id(&self) -> u16 {
        21
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.thresholds.clone())),
            (3, CosemDataType::from(self.monitored_value.clone())),
            (4, CosemDataType::Array(self.actions.iter().map(|a| CosemDataType::from(a.clone())).collect())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The Register monitor class defines no specific methods.
        vec![]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?; // length = element count
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
        };
        // class_id + 4 attributes.
        if seq.len() != 5 {
            return Err(BerError::InvalidLength);
        }
        if let CosemDataType::LongUnsigned(class_id) = seq[0] {
            if class_id != self.class_id() {
                return Err(BerError::InvalidValue);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::OctetString(obis) = &seq[1] {
            if obis.len() == 6 {
                self.logical_name = ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
            } else {
                return Err(BerError::InvalidLength);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        self.thresholds = match &seq[2] {
            CosemDataType::Array(list) => list.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.monitored_value = ValueDefinition::try_from(&seq[3]).map_err(|_| BerError::InvalidTag)?;
        self.actions = match &seq[4] {
            CosemDataType::Array(list) => {
                list.iter().map(ActionSet::try_from).collect::<Result<Vec<_>, _>>().map_err(|_| BerError::InvalidTag)?
            }
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for Register monitor (no specific methods)"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a BER length octet (short or long form).
fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::attrs::ActionItem;

    fn sample() -> RegisterMonitor {
        RegisterMonitor::new(RegisterMonitorConfig {
            logical_name: ObisCode::new(0, 0, 16, 1, 0, 255),
            thresholds: vec![CosemDataType::LongUnsigned(230), CosemDataType::LongUnsigned(250)],
            monitored_value: ValueDefinition {
                class_id: 3,
                logical_name: ObisCode::new(1, 0, 32, 7, 0, 255),
                attribute_index: 2,
            },
            actions: vec![ActionSet {
                action_up: ActionItem { script_logical_name: ObisCode::new(0, 0, 10, 0, 1, 255), script_selector: 1 },
                action_down: ActionItem { script_logical_name: ObisCode::new(0, 0, 10, 0, 1, 255), script_selector: 2 },
            }],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 21);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 4);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.thresholds = vec![];
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
