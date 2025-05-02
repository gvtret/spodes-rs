use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::Arc;

/// Интерфейсный класс `ProfileGeneric` (class_id = 7) для хранения профилей данных,
/// таких как нагрузочные профили или журналы событий, в соответствии с IEC 62056-6-2
/// в библиотеке `spodes-rs`.
///
/// Поддерживает захват данных из указанных объектов и их атрибутов.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileGeneric {
    logical_name: ObisCode,
    buffer: Vec<CosemDataType>,
    #[serde(skip)]
    capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
    capture_period: u32,
    sort_method: u8,
    sort_object: CosemDataType,
    entries_in_use: u32,
    profile_entries: u32,
}

impl ProfileGeneric {
    /// Создает новый объект `ProfileGeneric`.
    ///
    /// # Arguments
    /// * `logical_name` - OBIS-код объекта.
    /// * `buffer` - Буфер записей профиля.
    /// * `capture_objects` - Список пар (объект, идентификатор атрибута) для захвата.
    /// * `capture_period` - Период захвата данных (в секундах).
    /// * `sort_method` - Метод сортировки (например, 1 для FIFO).
    /// * `sort_object` - Объект сортировки.
    /// * `entries_in_use` - Количество используемых записей.
    /// * `profile_entries` - Максимальное количество записей.
    ///
    /// # Returns
    /// Новая структура `ProfileGeneric`.
    pub fn new(
        logical_name: ObisCode,
        buffer: Vec<CosemDataType>,
        capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
        capture_period: u32,
        sort_method: u8,
        sort_object: CosemDataType,
        entries_in_use: u32,
        profile_entries: u32,
    ) -> Self {
        ProfileGeneric {
            logical_name,
            buffer,
            capture_objects,
            capture_period,
            sort_method,
            sort_object,
            entries_in_use,
            profile_entries,
        }
    }

    /// Сбрасывает буфер профиля, очищая все записи.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если сброс прошел успешно.
    /// * `Err(String)` - Если произошла ошибка.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.buffer.clear();
        self.entries_in_use = 0;
        Ok(CosemDataType::Null)
    }

    /// Захватывает новую запись в буфер профиля, извлекая значения атрибутов
    /// из объектов, указанных в `capture_objects`.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если захват прошел успешно.
    /// * `Err(String)` - Если буфер полон или атрибут не найден.
    fn capture(&mut self) -> Result<CosemDataType, String> {
        if self.entries_in_use >= self.profile_entries {
            return Err("Buffer is full".to_string());
        }

        let mut captured_values = Vec::new();

        for (obj, attr_id) in &self.capture_objects {
            let attributes = obj.attributes();
            if let Some((_, value)) = attributes.iter().find(|(id, _)| *id == *attr_id) {
                captured_values.push(value.clone());
            } else {
                return Err(format!("Attribute {} not found in object", attr_id));
            }
        }

        // Добавляем текущую метку времени
        captured_values.push(CosemDataType::DateTime(vec![0x07, 0xE5, 0x05, 0x01])); // Пример

        let new_entry = CosemDataType::Structure(captured_values);
        self.buffer.push(new_entry);
        self.entries_in_use += 1;

        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for ProfileGeneric {
    fn class_id(&self) -> u16 {
        7
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
                        CosemDataType::Integer(*attr_id as i8),
                        CosemDataType::Integer(0), // Индекс атрибута (по умолчанию 0)
                    ])
                })
                .collect(),
        );

        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.buffer.clone())),
            (3, capture_objects),
            (4, CosemDataType::DoubleLongUnsigned(self.capture_period)),
            (5, CosemDataType::Unsigned(self.sort_method)),
            (6, self.sort_object.clone()),
            (7, CosemDataType::DoubleLongUnsigned(self.entries_in_use)),
            (8, CosemDataType::DoubleLongUnsigned(self.profile_entries)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string()), (2, "capture".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(&mut seq_buf)?;
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
        if rest.is_empty() {
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
                            self.logical_name =
                                ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
                        } else {
                            return Err(BerError::InvalidLength);
                        }
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    if let CosemDataType::Array(buffer) = &seq[2] {
                        self.buffer = buffer.clone();
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    if let CosemDataType::Array(_) = &seq[3] {
                        // capture_objects десериализуются отдельно, если нужно
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    if let CosemDataType::DoubleLongUnsigned(capture_period) = seq[4] {
                        self.capture_period = capture_period;
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    if let CosemDataType::Unsigned(sort_method) = seq[5] {
                        self.sort_method = sort_method;
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    self.sort_object = seq[6].clone();
                    if let CosemDataType::DoubleLongUnsigned(entries_in_use) = seq[7] {
                        self.entries_in_use = entries_in_use;
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    if let CosemDataType::DoubleLongUnsigned(profile_entries) = seq[8] {
                        self.profile_entries = profile_entries;
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    return Ok(());
                }
            }
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
            2 => self.capture(),
            _ => Err(format!(
                "Method {} not supported for ProfileGeneric class",
                method_id
            )),
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
