use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Values of the `capture_method` attribute (IEC 62056-6-2 §4.3.8).
pub mod capture_method {
    /// Method 2 `capture` stores all values (invoked explicitly).
    pub const INVOKE: u8 = 0;
    /// The values are captured implicitly on read of the compact buffer.
    pub const IMPLICIT: u8 = 1;
}

/// Configuration structure used to build a [`CompactData`] object.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompactDataConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: the compact buffer (octet-string of concatenated values).
    pub compact_buffer: Vec<u8>,
    /// Attribute 3: the objects captured into the buffer, paired with the
    /// captured attribute index.
    #[serde(skip)]
    pub capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
    /// Attribute 4: identifier of the template describing the buffer contents.
    pub template_id: u8,
    /// Attribute 5: template description (octet-string of type tags).
    pub template_description: Vec<u8>,
    /// Attribute 6: capture method (see [`capture_method`]).
    pub capture_method: u8,
}

impl fmt::Debug for CompactDataConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactDataConfig")
            .field("logical_name", &self.logical_name)
            .field("compact_buffer", &self.compact_buffer)
            .field("capture_objects", &format_args!("Vec<...> (len={})", self.capture_objects.len()))
            .field("template_id", &self.template_id)
            .field("template_description", &self.template_description)
            .field("capture_method", &self.capture_method)
            .finish()
    }
}

/// `Compact data` interface class (class_id = 62, version = 0) per
/// IEC 62056-6-2 §4.3.8. Holds the values of the capture objects in a compact
/// (contents-only) encoding described by the template.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompactData {
    logical_name: ObisCode,
    compact_buffer: Vec<u8>,
    #[serde(skip)]
    capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
    template_id: u8,
    template_description: Vec<u8>,
    capture_method: u8,
}

impl fmt::Debug for CompactData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactData")
            .field("logical_name", &self.logical_name)
            .field("compact_buffer", &self.compact_buffer)
            .field("capture_objects", &format_args!("Vec<...> (len={})", self.capture_objects.len()))
            .field("template_id", &self.template_id)
            .field("template_description", &self.template_description)
            .field("capture_method", &self.capture_method)
            .finish()
    }
}

impl CompactData {
    /// Builds a new [`CompactData`] from its configuration.
    pub fn new(config: CompactDataConfig) -> Self {
        CompactData {
            logical_name: config.logical_name,
            compact_buffer: config.compact_buffer,
            capture_objects: config.capture_objects,
            template_id: config.template_id,
            template_description: config.template_description,
            capture_method: config.capture_method,
        }
    }

    /// Method 1: `reset` — clears the compact buffer.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.compact_buffer.clear();
        Ok(CosemDataType::Null)
    }

    /// Method 2: `capture` — reads every capture object's attribute and stores
    /// the serialized values (full TLV encoding, one after another) into the
    /// compact buffer.
    fn capture(&mut self) -> Result<CosemDataType, String> {
        if self.capture_objects.is_empty() {
            return Err("No capture objects configured".to_string());
        }
        let mut buffer = Vec::new();
        for (obj, attr_id) in &self.capture_objects {
            let value = obj
                .attributes()
                .into_iter()
                .find(|(id, _)| id == attr_id)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("Capture object has no attribute {attr_id}"))?;
            value.serialize_ber(&mut buffer).map_err(|e| format!("Capture serialization failed: {e:?}"))?;
        }
        self.compact_buffer = buffer;
        Ok(CosemDataType::Null)
    }

    /// Returns the compact buffer (attribute 2).
    pub fn compact_buffer(&self) -> &[u8] {
        &self.compact_buffer
    }
}

impl InterfaceClass for CompactData {
    fn class_id(&self) -> u16 {
        62
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        let capture_objects = CosemDataType::Array(
            self.capture_objects
                .iter()
                .map(|(obj, attr_id)| {
                    CosemDataType::Structure(vec![
                        CosemDataType::LongUnsigned(obj.class_id()),
                        CosemDataType::OctetString(obj.logical_name().to_bytes()),
                        CosemDataType::Integer(*attr_id as i8), // attribute_index (integer)
                        CosemDataType::LongUnsigned(0),         // data_index (long-unsigned, default 0)
                    ])
                })
                .collect(),
        );
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::OctetString(self.compact_buffer.clone())),
            (3, capture_objects),
            (4, CosemDataType::Unsigned(self.template_id)),
            (5, CosemDataType::OctetString(self.template_description.clone())),
            (6, CosemDataType::Enum(self.capture_method)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string()), (2, "capture".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.compact_buffer.clone()).serialize_ber(&mut seq_buf)?;
        CosemDataType::Unsigned(self.template_id).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.template_description.clone()).serialize_ber(&mut seq_buf)?;
        CosemDataType::Enum(self.capture_method).serialize_ber(&mut seq_buf)?;
        buf.push(0x02); // structure [2]
        write_length(6, buf)?;
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
        self.compact_buffer = match &seq[2] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.template_id = match seq[3] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.template_description = match &seq[4] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.capture_method = match seq[5] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            2 => self.capture(),
            _ => Err(format!("Method {} not supported for Compact data class", method_id)),
        }
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
    use crate::classes::data::Data;

    fn sample() -> CompactData {
        CompactData::new(CompactDataConfig {
            logical_name: ObisCode::new(0, 0, 66, 0, 1, 255),
            compact_buffer: vec![],
            capture_objects: vec![(
                Arc::new(Data::new(ObisCode::new(0, 0, 96, 1, 0, 255), CosemDataType::LongUnsigned(0x1234))),
                2,
            )],
            template_id: 1,
            template_description: vec![0x12],
            capture_method: capture_method::INVOKE,
        })
    }

    #[test]
    fn class_id_attributes_and_methods() {
        let obj = sample();
        assert_eq!(obj.class_id(), 62);
        assert_eq!(obj.attributes().len(), 6);
        assert_eq!(obj.methods().len(), 2);
    }

    #[test]
    fn capture_fills_and_reset_clears_buffer() {
        let mut obj = sample();
        obj.invoke_method(2, None).unwrap();
        // long-unsigned 0x1234 → 12 12 34.
        assert_eq!(obj.compact_buffer(), &[0x12, 0x12, 0x34]);
        obj.invoke_method(1, None).unwrap();
        assert!(obj.compact_buffer().is_empty());
    }

    #[test]
    fn round_trip() {
        let mut obj = sample();
        obj.invoke_method(2, None).unwrap();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.compact_buffer(), obj.compact_buffer());
        assert_eq!(decoded.attributes()[4], obj.attributes()[4]);
    }
}
