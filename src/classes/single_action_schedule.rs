use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`SingleActionSchedule`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SingleActionScheduleConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: `script` structure { script_logical_name, script_selector }.
    pub executed_script: CosemDataType,
    /// Attribute 3: schedule type (enum 1..6, defines date/time wildcard handling).
    pub schedule_type: u8,
    /// Attribute 4: array of `execution_time` structures { time, date }.
    pub execution_time: Vec<CosemDataType>,
}

/// `Single action schedule` interface class (class_id = 22, version = 0) per
/// IEC 62056-6-2 §4.5.7. Schedules the execution of a single script at the
/// configured times.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SingleActionSchedule {
    logical_name: ObisCode,
    executed_script: CosemDataType,
    schedule_type: u8,
    execution_time: Vec<CosemDataType>,
}

impl SingleActionSchedule {
    /// Builds a new [`SingleActionSchedule`] from its configuration.
    pub fn new(config: SingleActionScheduleConfig) -> Self {
        SingleActionSchedule {
            logical_name: config.logical_name,
            executed_script: config.executed_script,
            schedule_type: config.schedule_type,
            execution_time: config.execution_time,
        }
    }
}

impl InterfaceClass for SingleActionSchedule {
    fn class_id(&self) -> u16 {
        22
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
            (2, self.executed_script.clone()),
            (3, CosemDataType::Enum(self.schedule_type)),
            (4, CosemDataType::Array(self.execution_time.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The Single action schedule class defines no specific methods.
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
        // class_id + 4 attributes.
        if seq.len() != 5 {
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
        self.executed_script = seq[2].clone();
        self.schedule_type = match seq[3] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.execution_time = match &seq[4] {
            CosemDataType::Array(list) => list.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {} not supported for Single action schedule (no specific methods)", method_id))
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

    fn sample() -> SingleActionSchedule {
        SingleActionSchedule::new(SingleActionScheduleConfig {
            logical_name: ObisCode::new(0, 0, 15, 0, 0, 255),
            executed_script: CosemDataType::Structure(vec![
                CosemDataType::OctetString(vec![0, 0, 10, 0, 100, 255]),
                CosemDataType::LongUnsigned(1),
            ]),
            schedule_type: 1,
            execution_time: vec![CosemDataType::Structure(vec![
                CosemDataType::OctetString(vec![0x00, 0x00, 0x00, 0xFF]),
                CosemDataType::OctetString(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            ])],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 22);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 4);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.schedule_type = 0;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
