use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::ActionItem;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`Arbitrator`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ArbitratorConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of `action` structures that can be requested.
    pub actions: Vec<ActionItem>,
    /// Attribute 3: permissions table (array of bit-strings, one per actor).
    pub permissions_table: Vec<CosemDataType>,
    /// Attribute 4: weightings table (array).
    pub weightings_table: Vec<CosemDataType>,
    /// Attribute 5: most recent requests table (array of bit-strings).
    pub most_recent_requests_table: Vec<CosemDataType>,
    /// Attribute 6: index of the action selected by the last arbitration.
    pub last_outcome: u8,
}

/// `Arbitrator` interface class (class_id = 68, version = 0) per IEC 62056-6-2
/// §4.5.12. Arbitrates action requests from several actors according to the
/// permissions and weightings tables.
///
/// The full weighting/permission arbitration algorithm is out of scope for this
/// data-model class: `request_action` records the request and `reset` clears the
/// request table.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Arbitrator {
    logical_name: ObisCode,
    actions: Vec<ActionItem>,
    permissions_table: Vec<CosemDataType>,
    weightings_table: Vec<CosemDataType>,
    most_recent_requests_table: Vec<CosemDataType>,
    last_outcome: u8,
}

impl Arbitrator {
    /// Builds a new [`Arbitrator`] from its configuration.
    pub fn new(config: ArbitratorConfig) -> Self {
        Arbitrator {
            logical_name: config.logical_name,
            actions: config.actions,
            permissions_table: config.permissions_table,
            weightings_table: config.weightings_table,
            most_recent_requests_table: config.most_recent_requests_table,
            last_outcome: config.last_outcome,
        }
    }

    /// Method 1: `request_action` — records a request in the most-recent-requests
    /// table (IEC 62056-6-2 §4.5.12.3).
    fn request_action(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        self.most_recent_requests_table.push(data);
        Ok(CosemDataType::Null)
    }

    /// Method 2: `reset` — clears the most-recent-requests table and the last
    /// outcome.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.most_recent_requests_table.clear();
        self.last_outcome = 0;
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for Arbitrator {
    fn class_id(&self) -> u16 {
        68
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
            (2, CosemDataType::Array(self.actions.iter().map(|a| CosemDataType::from(a.clone())).collect())),
            (3, CosemDataType::Array(self.permissions_table.clone())),
            (4, CosemDataType::Array(self.weightings_table.clone())),
            (5, CosemDataType::Array(self.most_recent_requests_table.clone())),
            (6, CosemDataType::Unsigned(self.last_outcome)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "request_action".to_string()), (2, "reset".to_string())]
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
        // class_id + 6 attributes.
        if seq.len() != 7 {
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
        self.actions = take_array(&seq[2])?
            .into_iter()
            .map(|v| ActionItem::try_from(&v).map_err(|_| BerError::InvalidValue))
            .collect::<Result<Vec<_>, _>>()?;
        self.permissions_table = take_array(&seq[3])?;
        self.weightings_table = take_array(&seq[4])?;
        self.most_recent_requests_table = take_array(&seq[5])?;
        self.last_outcome = match seq[6] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.request_action(params.ok_or("Missing method parameter")?),
            2 => self.reset(),
            _ => Err(format!("Method {method_id} not supported for Arbitrator")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_array(value: &CosemDataType) -> Result<Vec<CosemDataType>, BerError> {
    match value {
        CosemDataType::Array(list) => Ok(list.clone()),
        _ => Err(BerError::InvalidTag),
    }
}

/// Writes a BER length octet (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
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

    fn sample() -> Arbitrator {
        Arbitrator::new(ArbitratorConfig {
            logical_name: ObisCode::new(0, 0, 96, 3, 20, 255),
            actions: vec![ActionItem { script_logical_name: ObisCode::new(0, 0, 10, 0, 1, 255), script_selector: 1 }],
            permissions_table: vec![CosemDataType::BitString(vec![0x80])],
            weightings_table: vec![CosemDataType::Array(vec![CosemDataType::LongUnsigned(1)])],
            most_recent_requests_table: vec![],
            last_outcome: 0,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 68);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 6);
        assert_eq!(obj.methods().len(), 2);
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.last_outcome = 9;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn request_then_reset() {
        let mut obj = sample();
        obj.invoke_method(1, Some(CosemDataType::BitString(vec![0x80]))).unwrap();
        assert_eq!(obj.most_recent_requests_table.len(), 1);
        obj.invoke_method(2, None).unwrap();
        assert_eq!(obj.most_recent_requests_table.len(), 0);
        assert_eq!(obj.attributes()[5].1, CosemDataType::Unsigned(0));
    }
}
