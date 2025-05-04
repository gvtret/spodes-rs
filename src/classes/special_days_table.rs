use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Конфигурационная структура для создания объекта `SpecialDaysTable`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SpecialDaysTableConfig {
    pub logical_name: ObisCode,
    pub entries: Vec<CosemDataType>,
}

/// Интерфейсный класс `SpecialDaysTable` (class_id = 11, version = 0) для управления списком особых дней,
/// в соответствии с IEC 62056-6-2:2019.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SpecialDaysTable {
    logical_name: ObisCode,
    entries: Vec<CosemDataType>,
}

impl SpecialDaysTable {
    pub fn new(config: SpecialDaysTableConfig) -> Self {
        SpecialDaysTable {
            logical_name: config.logical_name,
            entries: config.entries,
        }
    }

    fn insert(&mut self, date: CosemDataType) -> Result<CosemDataType, String> {
        match date {
            CosemDataType::DateTime(ref dt) if dt.len() == 12 => {
                self.entries.push(date);
                Ok(CosemDataType::Null)
            }
            CosemDataType::DateTime(_) => Err("Invalid DateTime length".to_string()),
            _ => Err("Expected DateTime for insert".to_string()),
        }
    }

    fn delete(&mut self, date: CosemDataType) -> Result<CosemDataType, String> {
        match date {
            CosemDataType::DateTime(ref dt) if dt.len() == 12 => {
                self.entries.retain(|entry| entry != &CosemDataType::DateTime(dt.clone()));
                Ok(CosemDataType::Null)
            }
            CosemDataType::DateTime(_) => Err("Invalid DateTime length".to_string()),
            _ => Err("Expected DateTime for delete".to_string()),
        }
    }
}

impl InterfaceClass for SpecialDaysTable {
    fn class_id(&self) -> u16 {
        11
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
            (2, CosemDataType::Array(self.entries.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "insert".to_string()),
            (2, "delete".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0xA2);
        write_length(seq_buf.len(), buf)?;
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
            if let CosemDataType::Array(entries) = &seq[2] {
                for entry in entries {
                    if let CosemDataType::DateTime(dt) = entry {
                        if dt.len() != 12 {
                            return Err(BerError::InvalidLength);
                        }
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                }
                self.entries = entries.clone();
            } else {
                return Err(BerError::InvalidTag);
            }
            Ok(())
        } else {
            Err(BerError::InvalidLength)
        }
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.insert(params.ok_or("Missing parameter for insert method")?),
            2 => self.delete(params.ok_or("Missing parameter for delete method")?),
            _ => Err(format!("Method {} not supported for SpecialDaysTable", method_id)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

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