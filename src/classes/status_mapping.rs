use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// One entry of the `status_mappings` attribute: a status flag mapped to the
/// referenced status object.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StatusMappingEntry {
    /// The status flag identifier (bit number).
    pub status_flag_id: u8,
    /// Logical name of the referenced status-word object.
    pub status_reference: ObisCode,
}

impl From<StatusMappingEntry> for CosemDataType {
    fn from(e: StatusMappingEntry) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Unsigned(e.status_flag_id),
            CosemDataType::OctetString(e.status_reference.to_bytes()),
        ])
    }
}

impl TryFrom<&CosemDataType> for StatusMappingEntry {
    type Error = String;

    fn try_from(value: &CosemDataType) -> Result<Self, Self::Error> {
        let fields = match value {
            CosemDataType::Structure(fields) if fields.len() == 2 => fields,
            _ => return Err("Expected structure { status_flag_id, status_reference }".to_string()),
        };
        let CosemDataType::Unsigned(status_flag_id) = fields[0] else {
            return Err("status_flag_id must be unsigned".to_string());
        };
        let status_reference = match &fields[1] {
            CosemDataType::OctetString(v) if v.len() == 6 => ObisCode::new(v[0], v[1], v[2], v[3], v[4], v[5]),
            _ => return Err("status_reference must be a 6-octet logical name".to_string()),
        };
        Ok(StatusMappingEntry { status_flag_id, status_reference })
    }
}

/// Configuration structure used to build a [`StatusMapping`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StatusMappingConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of status mappings.
    pub status_mappings: Vec<StatusMappingEntry>,
}

/// `Status mapping` interface class (class_id = 63, version = 0) per
/// IEC 62056-6-2 §4.3.9. Maps the bits of a status word onto referenced status
/// objects.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StatusMapping {
    logical_name: ObisCode,
    status_mappings: Vec<StatusMappingEntry>,
}

impl StatusMapping {
    /// Builds a new [`StatusMapping`] from its configuration.
    pub fn new(config: StatusMappingConfig) -> Self {
        StatusMapping { logical_name: config.logical_name, status_mappings: config.status_mappings }
    }

    /// Returns the status mappings (attribute 2).
    pub fn status_mappings(&self) -> &[StatusMappingEntry] {
        &self.status_mappings
    }
}

impl InterfaceClass for StatusMapping {
    fn class_id(&self) -> u16 {
        63
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
            (2, CosemDataType::Array(self.status_mappings.iter().cloned().map(CosemDataType::from).collect())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The status mapping class defines no specific methods.
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
        self.status_mappings = match &seq[2] {
            CosemDataType::Array(entries) => entries
                .iter()
                .map(StatusMappingEntry::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for Status mapping (no specific methods)"))
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

    fn sample() -> StatusMapping {
        StatusMapping::new(StatusMappingConfig {
            logical_name: ObisCode::new(0, 0, 96, 10, 1, 255),
            status_mappings: vec![
                StatusMappingEntry { status_flag_id: 0, status_reference: ObisCode::new(0, 0, 97, 97, 0, 255) },
                StatusMappingEntry { status_flag_id: 3, status_reference: ObisCode::new(0, 0, 97, 97, 1, 255) },
            ],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 63);
        assert_eq!(obj.attributes().len(), 2);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = StatusMapping::new(StatusMappingConfig {
            logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
            status_mappings: vec![],
        });
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
        assert_eq!(decoded.status_mappings(), obj.status_mappings());
    }
}
