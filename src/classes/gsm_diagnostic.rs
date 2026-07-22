use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{CellInfo, DateTime, GsmAdjacentCell};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`GsmDiagnostic`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GsmDiagnosticConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Class version: 0, 1 or 2 (same attribute set; later versions extend the
    /// internal `cell_info` structure).
    pub version: u8,
    /// Attribute 2: name of the current network operator (visible-string).
    pub operator: Vec<u8>,
    /// Attribute 3: modem registration status (enum).
    pub status: u8,
    /// Attribute 4: circuit-switched attachment status (enum).
    pub cs_attachment: u8,
    /// Attribute 5: packet-switched status (enum).
    pub ps_status: u8,
    /// Attribute 6: serving `cell_info` structure.
    pub cell_info: CellInfo,
    /// Attribute 7: array of adjacent cell structures.
    pub adjacent_cells: Vec<GsmAdjacentCell>,
    /// Attribute 8: capture time of the diagnostic values (date-time).
    pub capture_time: DateTime,
}

/// `GSM diagnostic` interface class (class_id = 47) per IEC 62056-6-2 §4.7.8.
/// Reports the diagnostic values of the GSM/GPRS/LTE modem.
///
/// Versions 0, 1 and 2 share the same eight attributes. This class defines no
/// specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GsmDiagnostic {
    version: u8,
    logical_name: ObisCode,
    operator: Vec<u8>,
    status: u8,
    cs_attachment: u8,
    ps_status: u8,
    cell_info: CellInfo,
    adjacent_cells: Vec<GsmAdjacentCell>,
    capture_time: DateTime,
}

impl GsmDiagnostic {
    /// Builds a new [`GsmDiagnostic`] from its configuration.
    pub fn new(config: GsmDiagnosticConfig) -> Self {
        GsmDiagnostic {
            version: config.version,
            logical_name: config.logical_name,
            operator: config.operator,
            status: config.status,
            cs_attachment: config.cs_attachment,
            ps_status: config.ps_status,
            cell_info: config.cell_info,
            adjacent_cells: config.adjacent_cells,
            capture_time: config.capture_time,
        }
    }
}

impl InterfaceClass for GsmDiagnostic {
    fn class_id(&self) -> u16 {
        47
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
            (2, CosemDataType::OctetString(self.operator.clone())),
            (3, CosemDataType::Enum(self.status)),
            (4, CosemDataType::Enum(self.cs_attachment)),
            (5, CosemDataType::Enum(self.ps_status)),
            (6, CosemDataType::from(self.cell_info.clone())),
            (7, CosemDataType::Array(self.adjacent_cells.iter().cloned().map(CosemDataType::from).collect())),
            (8, self.capture_time.clone().into()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The GSM diagnostic class defines no specific methods.
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
        // class_id + 8 attributes.
        if seq.len() != 9 {
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
        self.operator = match &seq[2] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.status = take_enum(&seq[3])?;
        self.cs_attachment = take_enum(&seq[4])?;
        self.ps_status = take_enum(&seq[5])?;
        self.cell_info = CellInfo::try_from(&seq[6]).map_err(|_| BerError::InvalidValue)?;
        self.adjacent_cells = match &seq[7] {
            CosemDataType::Array(list) => list
                .iter()
                .map(GsmAdjacentCell::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        self.capture_time = DateTime::try_from(&seq[8]).map_err(|_| BerError::InvalidValue)?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for GSM diagnostic (no specific methods)"))
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

    fn sample_versioned(version: u8) -> GsmDiagnostic {
        GsmDiagnostic::new(GsmDiagnosticConfig {
            logical_name: ObisCode::new(0, 0, 25, 6, 0, 255),
            version,
            operator: b"Operator".to_vec(),
            status: 4,
            cs_attachment: 2,
            ps_status: 5,
            cell_info: CellInfo {
                cell_id: vec![],
                location_id: vec![],
                imsi: vec![],
                imei: vec![],
                rn: vec![],
                cn: vec![],
                signal_quality: vec![],
                signal_strength: vec![],
                channel_number: vec![],
                cell_parameter_id: vec![],
                bsic: vec![],
                iccid: vec![],
                lac: vec![],
                mcc: vec![],
                mnc: vec![],
                tmsi: vec![],
                tmgi: vec![],
                gprs_status: vec![],
                routing_area_code: vec![],
                geographic_address: vec![],
                access_point_name: vec![],
                data_transport_state: vec![],
                nma_message: vec![],
            },
            adjacent_cells: vec![],
            capture_time: DateTime::new([0; 12]),
        })
    }

    #[test]
    fn attribute_and_method_counts() {
        for version in 0..=2u8 {
            let obj = sample_versioned(version);
            assert_eq!(obj.class_id(), 47);
            assert_eq!(obj.version(), version);
            assert_eq!(obj.attributes().len(), 8);
            assert!(obj.methods().is_empty());
        }
    }

    #[test]
    fn round_trip_all_versions() {
        for version in 0..=2u8 {
            let obj = sample_versioned(version);
            let mut buf = Vec::new();
            obj.serialize_ber(&mut buf).unwrap();
            let mut decoded = sample_versioned(version);
            decoded.status = 0;
            decoded.deserialize_ber(&buf).unwrap();
            assert_eq!(decoded.attributes(), obj.attributes());
        }
    }
}
