use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::Choice;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// The `Data` interface class (class_id = 1) holding simple data such as
/// identifiers or static parameters, per IEC 62056-6-2.
///
/// Attributes (IEC 62056-6-2, Table 5):
/// - attr 1: logical_name (octet-string) — OBIS code
/// - attr 2: value (CHOICE) — any COSEM data type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    logical_name: ObisCode,
    value: Choice,
}

impl Data {
    /// Creates a new `Data` object.
    pub fn new(logical_name: ObisCode, value: Choice) -> Self {
        Data { logical_name, value }
    }

    /// Returns the value attribute (attr 2).
    pub fn value(&self) -> &Choice {
        &self.value
    }

    /// Sets the value attribute (attr 2).
    pub fn set_value(&mut self, value: Choice) {
        self.value = value;
    }
}

impl InterfaceClass for Data {
    fn class_id(&self) -> u16 {
        1
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![(1, CosemDataType::OctetString(self.logical_name.to_bytes())), (2, self.value.clone())]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(&mut seq_buf)?;
        self.value.serialize_ber(&mut seq_buf)?;
        buf.push(0x02); // structure [2]
        write_length(3, buf)?; // element count: class_id, logical_name, value
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if rest.is_empty() {
            if let CosemDataType::Structure(seq) = tlv {
                if seq.len() == 3 {
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
                    self.value = seq[2].clone();
                    return Ok(());
                }
            }
        }
        Err(BerError::InvalidTag)
    }

    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        if attribute_id == 2 {
            self.value = value;
            Ok(())
        } else {
            Err(format!("Attribute {} not writable for Data", attribute_id))
        }
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            // Method 1: `reset` — sets the value to its default (null-data),
            // per IEC 62056-6-2 §4.3.1.3.1.
            1 => {
                self.value = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            _ => Err(format!("Method {method_id} not supported for Data class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a length in BER (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_bytes = 8 - first_non_zero;
        buf.push(0x80 | num_bytes as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}
