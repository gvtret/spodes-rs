use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`UtilityTables`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UtilityTablesConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: table identifier (per the referenced table standard).
    pub table_id: u16,
    /// Attribute 3: length of the table contents in octets.
    pub length: u32,
    /// Attribute 4: the encapsulated table contents.
    pub buffer: Vec<u8>,
}

/// `Utility tables` interface class (class_id = 26, version = 0) per
/// IEC 62056-6-2 §4.3.6. Encapsulates ANSI C12.19 (or other) table data as an
/// octet-string.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UtilityTables {
    logical_name: ObisCode,
    table_id: u16,
    length: u32,
    buffer: Vec<u8>,
}

impl UtilityTables {
    /// Builds a new [`UtilityTables`] from its configuration.
    pub fn new(config: UtilityTablesConfig) -> Self {
        UtilityTables {
            logical_name: config.logical_name,
            table_id: config.table_id,
            length: config.length,
            buffer: config.buffer,
        }
    }
}

impl InterfaceClass for UtilityTables {
    fn class_id(&self) -> u16 {
        26
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
            (2, CosemDataType::LongUnsigned(self.table_id)),
            (3, CosemDataType::DoubleLongUnsigned(self.length)),
            (4, CosemDataType::OctetString(self.buffer.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The utility tables class defines no specific methods.
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
        self.table_id = match seq[2] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.length = match seq[3] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.buffer = match &seq[4] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for Utility tables (no specific methods)"))
    }

    fn as_any(&self) -> &dyn Any {
        self
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

    fn sample() -> UtilityTables {
        UtilityTables::new(UtilityTablesConfig {
            logical_name: ObisCode::new(0, 0, 65, 0, 0, 255),
            table_id: 23,
            length: 4,
            buffer: vec![0xDE, 0xAD, 0xBE, 0xEF],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 26);
        assert_eq!(obj.attributes().len(), 4);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = UtilityTables::new(UtilityTablesConfig {
            logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
            table_id: 0,
            length: 0,
            buffer: vec![],
        });
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
