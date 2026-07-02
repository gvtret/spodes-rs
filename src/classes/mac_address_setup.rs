use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`MacAddressSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MacAddressSetupConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: the Ethernet MAC address (octet-string, typically 6 octets).
    pub mac_address: Vec<u8>,
}

/// `MAC address setup` interface class (class_id = 43, version = 0) per
/// IEC 62056-6-2 §4.9.4. Holds the Ethernet MAC address of the device.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MacAddressSetup {
    logical_name: ObisCode,
    mac_address: Vec<u8>,
}

impl MacAddressSetup {
    /// Builds a new [`MacAddressSetup`] from its configuration.
    pub fn new(config: MacAddressSetupConfig) -> Self {
        MacAddressSetup {
            logical_name: config.logical_name,
            mac_address: config.mac_address,
        }
    }
}

impl InterfaceClass for MacAddressSetup {
    fn class_id(&self) -> u16 {
        43
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
            (2, CosemDataType::OctetString(self.mac_address.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The MAC address setup class defines no specific methods.
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
        let seq = match tlv {
            CosemDataType::Structure(seq) => seq,
            _ => return Err(BerError::InvalidTag),
        };
        // class_id + 2 attributes.
        if seq.len() != 3 {
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
        self.mac_address = match &seq[2] {
            CosemDataType::OctetString(bytes) => bytes.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        _params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        Err(format!("Method {} not supported for MAC address setup (no specific methods)", method_id))
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

    fn sample() -> MacAddressSetup {
        MacAddressSetup::new(MacAddressSetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 2, 0, 255),
            mac_address: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 43);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 2);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.mac_address = vec![];
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
