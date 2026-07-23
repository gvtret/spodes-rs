use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`IecLocalPortSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IecLocalPortSetupConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Class version: 0 or 1 (identical attribute set).
    pub version: u8,
    /// Attribute 2: default communication mode (enum).
    pub default_mode: u8,
    /// Attribute 3: default baud rate (enum).
    pub default_baud: u8,
    /// Attribute 4: proposed baud rate (enum).
    pub prop_baud: u8,
    /// Attribute 5: response time (enum).
    pub response_time: u8,
    /// Attribute 6: device address (octet-string).
    pub device_addr: Vec<u8>,
    /// Attribute 7: password 1 (octet-string).
    pub pass_p1: Vec<u8>,
    /// Attribute 8: password 2 (octet-string).
    pub pass_p2: Vec<u8>,
    /// Attribute 9: password W5 (octet-string).
    pub pass_w5: Vec<u8>,
}

/// `IEC local port setup` interface class (class_id = 19) per IEC 62056-6-2
/// §4.7.1. Configures the local (optical) port. Versions 0 and 1 share the same
/// nine attributes. This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IecLocalPortSetup {
    version: u8,
    logical_name: ObisCode,
    default_mode: u8,
    default_baud: u8,
    prop_baud: u8,
    response_time: u8,
    device_addr: Vec<u8>,
    pass_p1: Vec<u8>,
    pass_p2: Vec<u8>,
    pass_w5: Vec<u8>,
}

impl IecLocalPortSetup {
    /// Builds a new [`IecLocalPortSetup`] from its configuration.
    pub fn new(config: IecLocalPortSetupConfig) -> Self {
        IecLocalPortSetup {
            version: config.version,
            logical_name: config.logical_name,
            default_mode: config.default_mode,
            default_baud: config.default_baud,
            prop_baud: config.prop_baud,
            response_time: config.response_time,
            device_addr: config.device_addr,
            pass_p1: config.pass_p1,
            pass_p2: config.pass_p2,
            pass_w5: config.pass_w5,
        }
    }
}

impl InterfaceClass for IecLocalPortSetup {
    fn class_id(&self) -> u16 {
        19
    }

    fn version(&self) -> u8 {
        self.version
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Enum(self.default_mode)),
            (3, CosemDataType::Enum(self.default_baud)),
            (4, CosemDataType::Enum(self.prop_baud)),
            (5, CosemDataType::Enum(self.response_time)),
            (6, CosemDataType::OctetString(self.device_addr.clone())),
            (7, CosemDataType::OctetString(self.pass_p1.clone())),
            (8, CosemDataType::OctetString(self.pass_p2.clone())),
            (9, CosemDataType::OctetString(self.pass_w5.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The IEC local port setup class defines no specific methods.
        vec![]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf); // length = element count
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
        // class_id + 9 attributes.
        if seq.len() != 10 {
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
        self.default_mode = take_enum(&seq[2])?;
        self.default_baud = take_enum(&seq[3])?;
        self.prop_baud = take_enum(&seq[4])?;
        self.response_time = take_enum(&seq[5])?;
        self.device_addr = take_octet_string(&seq[6])?;
        self.pass_p1 = take_octet_string(&seq[7])?;
        self.pass_p2 = take_octet_string(&seq[8])?;
        self.pass_w5 = take_octet_string(&seq[9])?;
        Ok(())
    }

    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        match attribute_id {
            2 => {
                self.default_mode = take_enum(&value).map_err(|_| "default_mode must be enum".to_string())?;
                Ok(())
            }
            3 => {
                self.default_baud = take_enum(&value).map_err(|_| "default_baud must be enum".to_string())?;
                Ok(())
            }
            4 => {
                self.prop_baud = take_enum(&value).map_err(|_| "prop_baud must be enum".to_string())?;
                Ok(())
            }
            5 => {
                self.response_time = take_enum(&value).map_err(|_| "response_time must be enum".to_string())?;
                Ok(())
            }
            6 => {
                self.device_addr = take_octet_string(&value).map_err(|_| "device_addr must be octet-string".to_string())?;
                Ok(())
            }
            7 => {
                self.pass_p1 = take_octet_string(&value).map_err(|_| "pass_p1 must be octet-string".to_string())?;
                Ok(())
            }
            8 => {
                self.pass_p2 = take_octet_string(&value).map_err(|_| "pass_p2 must be octet-string".to_string())?;
                Ok(())
            }
            9 => {
                self.pass_w5 = take_octet_string(&value).map_err(|_| "pass_w5 must be octet-string".to_string())?;
                Ok(())
            }
            _ => Err(format!("IecLocalPortSetup attribute {attribute_id} is not writable")),
        }
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for IEC local port setup (no specific methods)"))
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

fn take_octet_string(value: &CosemDataType) -> Result<Vec<u8>, BerError> {
    match value {
        CosemDataType::OctetString(bytes) => Ok(bytes.clone()),
        _ => Err(BerError::InvalidTag),
    }
}

/// Writes a BER length octet (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_versioned(version: u8) -> IecLocalPortSetup {
        IecLocalPortSetup::new(IecLocalPortSetupConfig {
            logical_name: ObisCode::new(0, 0, 20, 0, 0, 255),
            version,
            default_mode: 0,
            default_baud: 5,
            prop_baud: 5,
            response_time: 0,
            device_addr: b"01".to_vec(),
            pass_p1: b"pass1".to_vec(),
            pass_p2: b"pass2".to_vec(),
            pass_w5: b"passw5".to_vec(),
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample_versioned(1);
        assert_eq!(obj.class_id(), 19);
        assert_eq!(obj.version(), 1);
        assert_eq!(obj.attributes().len(), 9);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip_all_versions() {
        for version in 0..=1u8 {
            let obj = sample_versioned(version);
            let mut buf = Vec::new();
            obj.serialize_ber(&mut buf).unwrap();
            let mut decoded = sample_versioned(version);
            decoded.default_mode = 9;
            decoded.deserialize_ber(&buf).unwrap();
            assert_eq!(decoded.attributes(), obj.attributes());
        }
    }
}
