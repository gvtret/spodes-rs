use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Конфигурационная структура для создания объекта `ScriptTable`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScriptTableConfig {
    pub logical_name: ObisCode,
    pub scripts: Vec<CosemDataType>,
}

/// Интерфейсный класс `ScriptTable` (class_id = 9) для управления скриптами,
/// определяющими действия в системе учета энергии, в соответствии с IEC 62056-6-2
/// в библиотеке `spodes-rs`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScriptTable {
    logical_name: ObisCode,
    scripts: Vec<CosemDataType>, // Array of Structure (script_identifier, action)
}

impl ScriptTable {
    /// Создает новый объект `ScriptTable` из конфигурации.
    ///
    /// # Arguments
    /// * `config` - Конфигурация для создания объекта.
    ///
    /// # Returns
    /// Новая структура `ScriptTable`.
    pub fn new(config: ScriptTableConfig) -> Self {
        ScriptTable {
            logical_name: config.logical_name,
            scripts: config.scripts,
        }
    }

    /// Выполняет скрипт по указанному идентификатору.
    ///
    /// # Arguments
    /// * `params` - Параметр типа `CosemDataType::LongUnsigned` (идентификатор скрипта).
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если скрипт найден и выполнен успешно.
    /// * `Err(String)` - Если скрипт не найден или параметр неверный.
    fn execute(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        if let Some(CosemDataType::LongUnsigned(script_id)) = params {
            for script in &self.scripts {
                if let CosemDataType::Structure(script_data) = script {
                    if script_data.len() == 2 {
                        if let CosemDataType::LongUnsigned(id) = script_data[0] {
                            if id == script_id {
                                // Здесь должна быть логика выполнения действия (script_data[1]).
                                // Для примера возвращаем успех, предполагая, что действие выполнено.
                                return Ok(CosemDataType::Null);
                            }
                        }
                    }
                }
            }
            return Err(format!("Script with ID {} not found", script_id));
        }
        Err("Invalid script ID parameter".to_string())
    }
}

impl InterfaceClass for ScriptTable {
    fn class_id(&self) -> u16 {
        9
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
            (2, CosemDataType::Array(self.scripts.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "execute".to_string())]
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
                if let CosemDataType::Array(scripts) = &seq[2] {
                    self.scripts = scripts.clone();
                } else {
                    return Err(BerError::InvalidTag);
                }
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
            1 => self.execute(params),
            _ => Err(format!("Method {} not supported for ScriptTable class", method_id)),
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