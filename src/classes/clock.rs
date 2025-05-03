use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::Arc;

/// Конфигурационная структура для создания объекта `Clock`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClockConfig {
    pub logical_name: ObisCode,
    pub time: CosemDataType,
    pub time_zone: CosemDataType,
    pub status: CosemDataType,
    pub daylight_savings_begin: CosemDataType,
    pub daylight_savings_end: CosemDataType,
    pub daylight_savings_deviation: CosemDataType,
    pub daylight_savings_enabled: CosemDataType,
    pub clock_base: CosemDataType,
}

/// Интерфейсный класс `Clock` (class_id = 8) для управления временем и датой
/// в соответствии с IEC 62056-6-2 в библиотеке `spodes-rs`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Clock {
    logical_name: ObisCode,
    time: CosemDataType, // DateTime
    time_zone: CosemDataType, // Long
    status: CosemDataType, // Unsigned
    daylight_savings_begin: CosemDataType, // DateTime
    daylight_savings_end: CosemDataType, // DateTime
    daylight_savings_deviation: CosemDataType, // Integer
    daylight_savings_enabled: CosemDataType, // Boolean
    clock_base: CosemDataType, // Enum
}

impl Clock {
    /// Создает новый объект `Clock` из конфигурации.
    ///
    /// # Arguments
    /// * `config` - Конфигурация для создания объекта.
    ///
    /// # Returns
    /// Новая структура `Clock`.
    pub fn new(config: ClockConfig) -> Self {
        Clock {
            logical_name: config.logical_name,
            time: config.time,
            time_zone: config.time_zone,
            status: config.status,
            daylight_savings_begin: config.daylight_savings_begin,
            daylight_savings_end: config.daylight_savings_end,
            daylight_savings_deviation: config.daylight_savings_deviation,
            daylight_savings_enabled: config.daylight_savings_enabled,
            clock_base: config.clock_base,
        }
    }

    /// Настраивает время на ближайший квартал часа.
    fn adjust_to_quarter(&mut self) -> Result<CosemDataType, String> {
        if let CosemDataType::DateTime(mut dt) = self.time.clone() {
            if dt.len() == 12 {
                let minutes = dt[6];
                let seconds = dt[7];
                let new_minutes = ((minutes as u32 + 7) / 15 * 15) % 60;
                dt[6] = new_minutes as u8;
                dt[7] = 0; // Обнуляем секунды
                dt[8] = 0; // Обнуляем сотые доли секунды
                self.time = CosemDataType::DateTime(dt);
                return Ok(CosemDataType::Null);
            }
        }
        Err("Invalid DateTime format".to_string())
    }

    /// Настраивает время на ближайшую минуту.
    fn adjust_to_minute(&mut self) -> Result<CosemDataType, String> {
        if let CosemDataType::DateTime(mut dt) = self.time.clone() {
            if dt.len() == 12 {
                dt[7] = 0; // Обнуляем секунды
                dt[8] = 0; // Обнуляем сотые доли секунды
                self.time = CosemDataType::DateTime(dt);
                return Ok(CosemDataType::Null);
            }
        }
        Err("Invalid DateTime format".to_string())
    }

    /// Устанавливает предустановленное время.
    fn adjust_to_preset_time(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        if let Some(CosemDataType::DateTime(dt)) = params {
            if dt.len() == 12 {
                self.time = CosemDataType::DateTime(dt);
                return Ok(CosemDataType::Null);
            }
        }
        Err("Invalid DateTime parameter".to_string())
    }

    /// Предварительная настройка времени (заглушка).
    fn preset_adjusting_time(&mut self) -> Result<CosemDataType, String> {
        // Реализация зависит от требований, пока заглушка
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for Clock {
    fn class_id(&self) -> u16 {
        8
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
            (2, self.time.clone()),
            (3, self.time_zone.clone()),
            (4, self.status.clone()),
            (5, self.daylight_savings_begin.clone()),
            (6, self.daylight_savings_end.clone()),
            (7, self.daylight_savings_deviation.clone()),
            (8, self.daylight_savings_enabled.clone()),
            (9, self.clock_base.clone()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "adjust_to_quarter".to_string()),
            (2, "adjust_to_minute".to_string()),
            (3, "adjust_to_preset_time".to_string()),
            (4, "preset_adjusting_time".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0xA2); // Тег STRUCTURE
        write_length(seq_buf.len(), buf)?;
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::Structure(seq) = tlv {
            if seq.len() == 10 {
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
                self.time = seq[2].clone();
                self.time_zone = seq[3].clone();
                self.status = seq[4].clone();
                self.daylight_savings_begin = seq[5].clone();
                self.daylight_savings_end = seq[6].clone();
                self.daylight_savings_deviation = seq[7].clone();
                self.daylight_savings_enabled = seq[8].clone();
                self.clock_base = seq[9].clone();
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.adjust_to_quarter(),
            2 => self.adjust_to_minute(),
            3 => self.adjust_to_preset_time(params),
            4 => self.preset_adjusting_time(),
            _ => Err(format!("Method {} not supported for Clock class", method_id)),
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
        let num_bytes = 8 - first_non_zero;
        buf.push(0x80 | num_bytes as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}