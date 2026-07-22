use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::ValueDefinition;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`ParameterMonitor`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParameterMonitorConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: `value_definition` of the monitored attribute.
    pub monitored_value: ValueDefinition,
    /// Attribute 3: thresholds structure applied to the monitored value.
    pub thresholds: CosemDataType,
    /// Attribute 4: array of recorded monitoring events.
    pub events: Vec<CosemDataType>,
    /// Attribute 5: minimal duration (seconds) before an event is recorded.
    pub minimal_duration: u32,
}

/// `Parameter monitor` interface class (class_id = 65, version = 0) per
/// IEC 62056-6-2 §4.5.10. Monitors an attribute of a referenced object against
/// the thresholds and records crossing events.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParameterMonitor {
    logical_name: ObisCode,
    monitored_value: ValueDefinition,
    thresholds: CosemDataType,
    events: Vec<CosemDataType>,
    minimal_duration: u32,
}

impl ParameterMonitor {
    /// Builds a new [`ParameterMonitor`] from its configuration.
    pub fn new(config: ParameterMonitorConfig) -> Self {
        ParameterMonitor {
            logical_name: config.logical_name,
            monitored_value: config.monitored_value,
            thresholds: config.thresholds,
            events: config.events,
            minimal_duration: config.minimal_duration,
        }
    }

    /// Records a monitoring event (host-driven).
    pub fn record_event(&mut self, event: CosemDataType) {
        self.events.push(event);
    }

    /// Returns the recorded events (attribute 4).
    pub fn events(&self) -> &[CosemDataType] {
        &self.events
    }
}

impl InterfaceClass for ParameterMonitor {
    fn class_id(&self) -> u16 {
        65
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
            (2, self.monitored_value.clone().into()),
            (3, self.thresholds.clone()),
            (4, CosemDataType::Array(self.events.clone())),
            (5, CosemDataType::DoubleLongUnsigned(self.minimal_duration)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The parameter monitor class defines no specific methods.
        vec![]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?;
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
        if seq.len() != 6 {
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
        self.monitored_value = ValueDefinition::try_from(&seq[2]).map_err(|_| BerError::InvalidValue)?;
        self.thresholds = seq[3].clone();
        self.events = match &seq[4] {
            CosemDataType::Array(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.minimal_duration = match seq[5] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for Parameter monitor (no specific methods)"))
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

    fn sample() -> ParameterMonitor {
        ParameterMonitor::new(ParameterMonitorConfig {
            logical_name: ObisCode::new(0, 0, 16, 2, 0, 255),
            monitored_value: ValueDefinition {
                class_id: 3,
                logical_name: ObisCode::new(1, 0, 12, 7, 0, 255),
                attribute_index: 2,
            },
            thresholds: CosemDataType::Structure(vec![
                CosemDataType::DoubleLongUnsigned(207_000),
                CosemDataType::DoubleLongUnsigned(253_000),
            ]),
            events: vec![],
            minimal_duration: 60,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 65);
        assert_eq!(obj.attributes().len(), 5);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let mut obj = sample();
        obj.record_event(CosemDataType::Structure(vec![
            CosemDataType::Unsigned(1),
            CosemDataType::DoubleLongUnsigned(260_000),
        ]));
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
        assert_eq!(decoded.events().len(), 1);
    }
}
