use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::SapAssignmentEntry;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`SapAssignment`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SapAssignmentConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of `sap_assignment` structures
    /// { SAP: long-unsigned, logical_device_name: octet-string }.
    pub sap_assignment_list: Vec<SapAssignmentEntry>,
}

/// `SAP assignment` interface class (class_id = 17, version = 0) per
/// IEC 62056-6-2 §4.4.5. Maps SAPs to logical devices.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SapAssignment {
    logical_name: ObisCode,
    sap_assignment_list: Vec<SapAssignmentEntry>,
}

impl SapAssignment {
    /// Builds a new [`SapAssignment`] from its configuration.
    pub fn new(config: SapAssignmentConfig) -> Self {
        SapAssignment { logical_name: config.logical_name, sap_assignment_list: config.sap_assignment_list }
    }

    /// Method 1: `connect_logical_device` — adds or updates a SAP-to-logical-device
    /// assignment (IEC 62056-6-2 §4.4.5.3). An empty logical device name removes
    /// the assignment for that SAP.
    fn connect_logical_device(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let (sap, ldn) = match &data {
            CosemDataType::Structure(fields) if fields.len() == 2 => match (&fields[0], &fields[1]) {
                (CosemDataType::LongUnsigned(sap), CosemDataType::OctetString(ldn)) => (*sap, ldn.clone()),
                _ => return Err("Expected structure { SAP: long-unsigned, ldn: octet-string }".to_string()),
            },
            _ => return Err("Expected structure { SAP, logical_device_name }".to_string()),
        };
        self.sap_assignment_list.retain(|e| e.sap != sap);
        if !ldn.is_empty() {
            let entry = SapAssignmentEntry::try_from(&data)?;
            self.sap_assignment_list.push(entry);
        }
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for SapAssignment {
    fn class_id(&self) -> u16 {
        17
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
            (2, CosemDataType::Array(self.sap_assignment_list.iter().cloned().map(CosemDataType::from).collect())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "connect_logical_device".to_string())]
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
        self.sap_assignment_list = match &seq[2] {
            CosemDataType::Array(list) => list
                .iter()
                .map(SapAssignmentEntry::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.connect_logical_device(params.ok_or("Missing method parameter")?),
            _ => Err(format!("Method {method_id} not supported for SAP assignment")),
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

    fn sample() -> SapAssignment {
        SapAssignment::new(SapAssignmentConfig {
            logical_name: ObisCode::new(0, 0, 41, 0, 0, 255),
            sap_assignment_list: vec![SapAssignmentEntry { sap: 1, logical_device_name: b"MANLD".to_vec() }],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 17);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 2);
        assert_eq!(obj.methods().len(), 1);
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.sap_assignment_list = vec![];
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn connect_adds_updates_and_removes() {
        let mut obj = sample();
        // Update SAP 1.
        obj.invoke_method(
            1,
            Some(CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(1),
                CosemDataType::OctetString(b"NEWLD".to_vec()),
            ])),
        )
        .unwrap();
        assert_eq!(obj.sap_assignment_list.len(), 1);
        // Add SAP 2.
        obj.invoke_method(
            1,
            Some(CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(2),
                CosemDataType::OctetString(b"OTHER".to_vec()),
            ])),
        )
        .unwrap();
        assert_eq!(obj.sap_assignment_list.len(), 2);
        // Remove SAP 1 with an empty name.
        obj.invoke_method(
            1,
            Some(CosemDataType::Structure(vec![CosemDataType::LongUnsigned(1), CosemDataType::OctetString(vec![])])),
        )
        .unwrap();
        assert_eq!(obj.sap_assignment_list.len(), 1);
    }
}
