use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`MbusSlavePortSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MbusSlavePortSetupConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: default baud rate (enum).
    pub default_baud: u8,
    /// Attribute 3: available baud rates (enum).
    pub avail_baud: u8,
    /// Attribute 4: address assignment state (enum).
    pub addr_state: u8,
    /// Attribute 5: bus address.
    pub bus_address: u8,
}

/// `M-Bus slave port setup` interface class (class_id = 25, version = 0) per
/// IEC 62056-6-2 §4.8.2. Configures the M-Bus slave communication port.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MbusSlavePortSetup {
    logical_name: ObisCode,
    default_baud: u8,
    avail_baud: u8,
    addr_state: u8,
    bus_address: u8,
}

impl MbusSlavePortSetup {
    /// Builds a new [`MbusSlavePortSetup`] from its configuration.
    pub fn new(config: MbusSlavePortSetupConfig) -> Self {
        MbusSlavePortSetup {
            logical_name: config.logical_name,
            default_baud: config.default_baud,
            avail_baud: config.avail_baud,
            addr_state: config.addr_state,
            bus_address: config.bus_address,
        }
    }
}

impl InterfaceClass for MbusSlavePortSetup {
    fn class_id(&self) -> u16 {
        25
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
            (2, CosemDataType::Enum(self.default_baud)),
            (3, CosemDataType::Enum(self.avail_baud)),
            (4, CosemDataType::Enum(self.addr_state)),
            (5, CosemDataType::Unsigned(self.bus_address)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The M-Bus slave port setup class defines no specific methods.
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
        // class_id + 5 attributes.
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
        self.default_baud = take_enum(&seq[2])?;
        self.avail_baud = take_enum(&seq[3])?;
        self.addr_state = take_enum(&seq[4])?;
        self.bus_address = match seq[5] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for M-Bus slave port setup (no specific methods)"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_enum(value: &CosemDataType) -> Result<u8, BerError> {
    match value {
        CosemDataType::Enum(v) => Ok(*v),
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

    fn sample() -> MbusSlavePortSetup {
        MbusSlavePortSetup::new(MbusSlavePortSetupConfig {
            logical_name: ObisCode::new(0, 0, 24, 0, 0, 255),
            default_baud: 0,
            avail_baud: 3,
            addr_state: 1,
            bus_address: 5,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 25);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 5);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.bus_address = 0;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
