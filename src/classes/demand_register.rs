use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Конфигурационная структура для создания объекта `DemandRegister`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DemandRegisterConfig {
    pub logical_name: ObisCode,
    pub current_average_value: CosemDataType,
    pub last_average_value: CosemDataType,
    pub scaler_unit: CosemDataType,
    pub status: CosemDataType,
    pub capture_time: CosemDataType,
    pub start_time_current: CosemDataType,
    pub period: CosemDataType,
    pub number_of_periods: CosemDataType,
}

/// Интерфейсный класс `DemandRegister` (class_id = 5) для управления измеряемыми
/// величинами спроса, такими как максимальная мощность за период, с поддержкой
/// периодов измерения и времени захвата, в соответствии с IEC 62056-6-2 в библиотеке `spodes-rs`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DemandRegister {
    logical_name: ObisCode,
    current_average_value: CosemDataType,
    last_average_value: CosemDataType,
    scaler_unit: CosemDataType,
    status: CosemDataType,
    capture_time: CosemDataType,
    start_time_current: CosemDataType,
    period: CosemDataType,
    number_of_periods: CosemDataType,
}

impl DemandRegister {
    /// Создает новый объект `DemandRegister` из конфигурации.
    ///
    /// # Arguments
    /// * `config` - Конфигурация для создания объекта.
    ///
    /// # Returns
    /// Новая структура `DemandRegister`.
    pub fn new(config: DemandRegisterConfig) -> Self {
        DemandRegister {
            logical_name: config.logical_name,
            current_average_value: config.current_average_value,
            last_average_value: config.last_average_value,
            scaler_unit: config.scaler_unit,
            status: config.status,
            capture_time: config.capture_time,
            start_time_current: config.start_time_current,
            period: config.period,
            number_of_periods: config.number_of_periods,
        }
    }

    /// Сбрасывает значения `current_average_value` и `last_average_value` до 0,
    /// очищает статус, время захвата и время начала текущего периода.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если сброс прошел успешно.
    /// * `Err(String)` - Если тип значения не поддерживает сброс.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        match &self.current_average_value {
            CosemDataType::Integer(_) => {
                self.current_average_value = CosemDataType::Integer(0);
                self.last_average_value = CosemDataType::Integer(0);
            }
            CosemDataType::Long(_) => {
                self.current_average_value = CosemDataType::Long(0);
                self.last_average_value = CosemDataType::Long(0);
            }
            CosemDataType::DoubleLong(_) => {
                self.current_average_value = CosemDataType::DoubleLong(0);
                self.last_average_value = CosemDataType::DoubleLong(0);
            }
            CosemDataType::Unsigned(_) => {
                self.current_average_value = CosemDataType::Unsigned(0);
                self.last_average_value = CosemDataType::Unsigned(0);
            }
            CosemDataType::LongUnsigned(_) => {
                self.current_average_value = CosemDataType::LongUnsigned(0);
                self.last_average_value = CosemDataType::LongUnsigned(0);
            }
            CosemDataType::DoubleLongUnsigned(_) => {
                self.current_average_value = CosemDataType::DoubleLongUnsigned(0);
                self.last_average_value = CosemDataType::DoubleLongUnsigned(0);
            }
            _ => return Err("Unsupported value type for reset".to_string()),
        }
        self.status = CosemDataType::Null;
        self.capture_time = CosemDataType::Null;
        self.start_time_current = CosemDataType::Null;
        Ok(CosemDataType::Null)
    }

    /// Переходит к следующему периоду измерения, перемещая `current_average_value`
    /// в `last_average_value`, сбрасывая `current_average_value`, обновляя статус
    /// и время захвата, а также устанавливая новое время начала периода.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если переход прошел успешно.
    /// * `Err(String)` - Если тип значения не поддерживает сброс.
    fn next_period(&mut self) -> Result<CosemDataType, String> {
        // Перемещаем текущее значение в последнее
        self.last_average_value = self.current_average_value.clone();
        // Сбрасываем текущее значение
        match &self.current_average_value {
            CosemDataType::Integer(_) => self.current_average_value = CosemDataType::Integer(0),
            CosemDataType::Long(_) => self.current_average_value = CosemDataType::Long(0),
            CosemDataType::DoubleLong(_) => self.current_average_value = CosemDataType::DoubleLong(0),
            CosemDataType::Unsigned(_) => self.current_average_value = CosemDataType::Unsigned(0),
            CosemDataType::LongUnsigned(_) => self.current_average_value = CosemDataType::LongUnsigned(0),
            CosemDataType::DoubleLongUnsigned(_) => self.current_average_value = CosemDataType::DoubleLongUnsigned(0),
            _ => return Err("Unsupported value type for next_period".to_string()),
        }
        // Обновляем статус (например, 1 означает успешное измерение)
        self.status = CosemDataType::Unsigned(1);
        // Обновляем время захвата и начала текущего периода (пример: 2025-05-01 00:00:00)
        let new_time = CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02, // День недели: вторник
            0x00, 0x00, 0x00, // Час: 0, Минуты: 0, Секунды: 0
            0x00, // Сотые доли секунды: 0
            0x00, 0x00, 0x00, // Отклонение от UTC: 0
        ]);
        self.capture_time = new_time.clone();
        self.start_time_current = new_time;
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for DemandRegister {
    fn class_id(&self) -> u16 {
        5
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
            (2, self.current_average_value.clone()),
            (3, self.last_average_value.clone()),
            (4, self.scaler_unit.clone()),
            (5, self.status.clone()),
            (6, self.capture_time.clone()),
            (7, self.start_time_current.clone()),
            (8, self.period.clone()),
            (9, self.number_of_periods.clone()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string()), (2, "next_period".to_string())]
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
                self.current_average_value = seq[2].clone();
                self.last_average_value = seq[3].clone();
                self.scaler_unit = seq[4].clone();
                self.status = seq[5].clone();
                self.capture_time = seq[6].clone();
                self.start_time_current = seq[7].clone();
                self.period = seq[8].clone();
                self.number_of_periods = seq[9].clone();
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        _params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            2 => self.next_period(),
            _ => Err(format!("Method {} not supported for DemandRegister class", method_id)),
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