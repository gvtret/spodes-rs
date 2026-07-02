use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`DataProtection`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DataProtectionConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: protected data buffer (octet-string).
    pub protection_buffer: Vec<u8>,
    /// Attribute 3: array of protection object list entries.
    pub protection_object_list: Vec<CosemDataType>,
    /// Attribute 4: array of GET protection parameters.
    pub protection_parameters_get: Vec<CosemDataType>,
    /// Attribute 5: array of SET protection parameters.
    pub protection_parameters_set: Vec<CosemDataType>,
    /// Attribute 6: the protection required for the operations (enum).
    pub required_protection: u8,
}

/// `Data protection` interface class (class_id = 30, version = 0) per
/// IEC 62056-6-2 §4.4.9. Provides end-to-end protection of grouped attributes
/// and method invocations.
///
/// The actual cryptographic protection (compression / encryption /
/// authentication / digital signature) belongs to the ciphering layer, which is
/// not implemented here. The three methods therefore validate their parameters
/// and return best-effort results.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DataProtection {
    logical_name: ObisCode,
    protection_buffer: Vec<u8>,
    protection_object_list: Vec<CosemDataType>,
    protection_parameters_get: Vec<CosemDataType>,
    protection_parameters_set: Vec<CosemDataType>,
    required_protection: u8,
}

impl DataProtection {
    /// Builds a new [`DataProtection`] from its configuration.
    pub fn new(config: DataProtectionConfig) -> Self {
        DataProtection {
            logical_name: config.logical_name,
            protection_buffer: config.protection_buffer,
            protection_object_list: config.protection_object_list,
            protection_parameters_get: config.protection_parameters_get,
            protection_parameters_set: config.protection_parameters_set,
            required_protection: config.required_protection,
        }
    }

    /// Method 1: `get_protected_attributes` — returns the protected data built
    /// from the object list. Best-effort: returns the current protection buffer.
    fn get_protected_attributes(&self, _data: CosemDataType) -> Result<CosemDataType, String> {
        Ok(CosemDataType::OctetString(self.protection_buffer.clone()))
    }

    /// Method 2: `set_protected_attributes` — applies protected attribute values.
    /// Best-effort: stores the supplied protected data into the buffer.
    fn set_protected_attributes(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        match data {
            CosemDataType::OctetString(bytes) => {
                self.protection_buffer = bytes;
                Ok(CosemDataType::Null)
            }
            CosemDataType::Structure(_) => Ok(CosemDataType::Null),
            _ => Err("set_protected_attributes expects an octet-string or structure".to_string()),
        }
    }

    /// Method 3: `invoke_protected_method` — invokes a protected method.
    /// Best-effort: succeeds after validating a parameter is present.
    fn invoke_protected_method(&mut self, _data: CosemDataType) -> Result<CosemDataType, String> {
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for DataProtection {
    fn class_id(&self) -> u16 {
        30
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
            (2, CosemDataType::OctetString(self.protection_buffer.clone())),
            (3, CosemDataType::Array(self.protection_object_list.clone())),
            (4, CosemDataType::Array(self.protection_parameters_get.clone())),
            (5, CosemDataType::Array(self.protection_parameters_set.clone())),
            (6, CosemDataType::Enum(self.required_protection)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "get_protected_attributes".to_string()),
            (2, "set_protected_attributes".to_string()),
            (3, "invoke_protected_method".to_string()),
        ]
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
        self.protection_buffer = match &seq[2] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.protection_object_list = take_array(&seq[3])?;
        self.protection_parameters_get = take_array(&seq[4])?;
        self.protection_parameters_set = take_array(&seq[5])?;
        self.required_protection = match seq[6] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        let params = params.ok_or("Missing method parameter")?;
        match method_id {
            1 => self.get_protected_attributes(params),
            2 => self.set_protected_attributes(params),
            3 => self.invoke_protected_method(params),
            _ => Err(format!("Method {} not supported for Data protection", method_id)),
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

    fn sample() -> DataProtection {
        DataProtection::new(DataProtectionConfig {
            logical_name: ObisCode::new(0, 0, 30, 0, 0, 255),
            protection_buffer: vec![0x01, 0x02, 0x03],
            protection_object_list: vec![],
            protection_parameters_get: vec![],
            protection_parameters_set: vec![],
            required_protection: 1,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 30);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 6);
        assert_eq!(obj.methods().len(), 3);
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.required_protection = 9;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn get_and_set_protection_buffer() {
        let mut obj = sample();
        assert_eq!(
            obj.invoke_method(1, Some(CosemDataType::Null)).unwrap(),
            CosemDataType::OctetString(vec![0x01, 0x02, 0x03])
        );
        obj.invoke_method(2, Some(CosemDataType::OctetString(vec![0xAA, 0xBB]))).unwrap();
        assert_eq!(obj.attributes()[1].1, CosemDataType::OctetString(vec![0xAA, 0xBB]));
    }
}
