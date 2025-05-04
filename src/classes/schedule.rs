use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Конфигурационная структура для создания объекта `Schedule`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScheduleConfig {
    pub logical_name: ObisCode,
    pub entries: Vec<CosemDataType>,
    pub enabled: bool,
}

/// Интерфейсный класс `Schedule` (class_id = 10) для управления расписаниями,
/// определяющими временные точки для выполнения действий, в соответствии с IEC 62056-6-2
/// в библиотеке `spodes-rs`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Schedule {
    logical_name: ObisCode,
    entries: Vec<CosemDataType>, // Array of Structure (time, action)
    enabled: bool, // Состояние расписания (включено/выключено)
}

impl Schedule {
    /// Создает новый объект `Schedule` из конфигурации.
    ///
    /// # Arguments
    /// * `config` - Конфигурация для создания объекта.
    ///
    /// # Returns
    /// Новая структура `Schedule`.
    pub fn new(config: ScheduleConfig) -> Self {
        Schedule {
            logical_name: config.logical_name,
            entries: config.entries,
            enabled: config.enabled,
        }
    }

    /// Включает расписание.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если расписание включено успешно.
    fn enable(&mut self) -> Result<CosemDataType, String> {
        self.enabled = true;
        Ok(CosemDataType::Null)
    }

    /// Выключает расписание.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если расписание выключено успешно.
    fn disable(&mut self) -> Result<CosemDataType, String> {
        self.enabled = false;
        Ok(CosemDataType::Null)
    }

    /// Возвращает состояние расписания (включено/выключено).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl InterfaceClass for Schedule {
    fn class_id(&self) -> u16 {
        10
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
        vec![(1, "enable".to_string()), (2, "disable".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        seq_buf.push(0x83); // Тег BOOLEAN (исправлено с 0x01 на 0x83)
        seq_buf.push(0x01); // Длина
        seq_buf.push(if self.enabled { 0xFF } else { 0x00 }); // Значение enabled
        buf.push(0xA2); // Тег STRUCTURE
        write_length(seq_buf.len(), buf)?;
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        println!("Deserializing Schedule: tlv={:?}, rest={:?}", tlv, rest);
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        let seq = match tlv {
            CosemDataType::Structure(seq) => seq,
            other => {
                println!("Unexpected tlv type: {:?}", other);
                return Err(BerError::InvalidTag);
            }
        };
        println!("Sequence: {:?}", seq);
        if seq.len() == 4 {
            if let CosemDataType::LongUnsigned(class_id) = seq[0] {
                println!("Class ID: {}", class_id);
                if class_id != self.class_id() {
                    return Err(BerError::InvalidValue);
                }
            } else {
                println!("Invalid class_id type: {:?}", seq[0]);
                return Err(BerError::InvalidTag);
            }
            if let CosemDataType::OctetString(obis) = &seq[1] {
                println!("OBIS: {:?}", obis);
                if obis.len() == 6 {
                    self.logical_name = ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
                } else {
                    return Err(BerError::InvalidLength);
                }
            } else {
                println!("Invalid logical_name type: {:?}", seq[1]);
                return Err(BerError::InvalidTag);
            }
            if let CosemDataType::Array(entries) = &seq[2] {
                println!("Entries: {:?}", entries);
                self.entries = entries.clone();
            } else {
                println!("Invalid entries type: {:?}", seq[2]);
                return Err(BerError::InvalidTag);
            }
            if let CosemDataType::Boolean(enabled) = seq[3] {
                println!("Enabled: {}", enabled);
                self.enabled = enabled;
            } else {
                println!("Invalid enabled type: {:?}", seq[3]);
                return Err(BerError::InvalidTag);
            }
            Ok(())
        } else {
            println!("Invalid sequence length: {}", seq.len());
            Err(BerError::InvalidLength)
        }
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        _params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.enable(),
            2 => self.disable(),
            _ => Err(format!("Method {} not supported for Schedule class", method_id)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Записывает длину в формате BER (короткая или длинная форма).
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