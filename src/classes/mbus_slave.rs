use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`MbusSlave`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MbusSlaveConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: primary (physical) address on the M-Bus.
    pub physical_address: u16,
    /// Attribute 3: logical (secondary) address.
    pub logical_address: u16,
    /// Attribute 4: device identification number (octet-string, BCD).
    pub id_number: Vec<u8>,
    /// Attribute 5: manufacturer identification (octet-string).
    pub manufacturer: Vec<u8>,
    /// Attribute 6: device version / generation.
    pub version: u8,
    /// Attribute 7: medium (per EN 13757-3, Table 3).
    pub medium: u8,
}

/// `M-Bus slave` device descriptor interface class (class_id = 76, version = 0),
/// describing an M-Bus device attached behind the port (addresses,
/// identification, manufacturer, medium).
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MbusSlave {
    logical_name: ObisCode,
    physical_address: u16,
    logical_address: u16,
    id_number: Vec<u8>,
    manufacturer: Vec<u8>,
    version: u8,
    medium: u8,
}

impl MbusSlave {
    /// Builds a new [`MbusSlave`] from its configuration.
    pub fn new(config: MbusSlaveConfig) -> Self {
        MbusSlave {
            logical_name: config.logical_name,
            physical_address: config.physical_address,
            logical_address: config.logical_address,
            id_number: config.id_number,
            manufacturer: config.manufacturer,
            version: config.version,
            medium: config.medium,
        }
    }
}

impl InterfaceClass for MbusSlave {
    fn class_id(&self) -> u16 {
        76
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
            (2, CosemDataType::LongUnsigned(self.physical_address)),
            (3, CosemDataType::LongUnsigned(self.logical_address)),
            (4, CosemDataType::OctetString(self.id_number.clone())),
            (5, CosemDataType::OctetString(self.manufacturer.clone())),
            (6, CosemDataType::Unsigned(self.version)),
            (7, CosemDataType::Unsigned(self.medium)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The M-Bus slave class defines no specific methods.
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
        if seq.len() != 8 {
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
        self.physical_address = take_long_unsigned(&seq[2])?;
        self.logical_address = take_long_unsigned(&seq[3])?;
        self.id_number = take_octets(&seq[4])?;
        self.manufacturer = take_octets(&seq[5])?;
        self.version = take_unsigned(&seq[6])?;
        self.medium = take_unsigned(&seq[7])?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for M-Bus slave (no specific methods)"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_long_unsigned(value: &CosemDataType) -> Result<u16, BerError> {
    match value {
        CosemDataType::LongUnsigned(v) => Ok(*v),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_unsigned(value: &CosemDataType) -> Result<u8, BerError> {
    match value {
        CosemDataType::Unsigned(v) => Ok(*v),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_octets(value: &CosemDataType) -> Result<Vec<u8>, BerError> {
    match value {
        CosemDataType::OctetString(v) => Ok(v.clone()),
        _ => Err(BerError::InvalidTag),
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

    fn sample() -> MbusSlave {
        MbusSlave::new(MbusSlaveConfig {
            logical_name: ObisCode::new(0, 1, 24, 1, 0, 255),
            physical_address: 5,
            logical_address: 0,
            id_number: vec![0x12, 0x34, 0x56, 0x78],
            manufacturer: vec![b'A', b'B', b'C'],
            version: 1,
            medium: 7, // water
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 76);
        assert_eq!(obj.attributes().len(), 7);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = MbusSlave::new(MbusSlaveConfig {
            logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
            physical_address: 0,
            logical_address: 0,
            id_number: vec![],
            manufacturer: vec![],
            version: 0,
            medium: 0,
        });
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
