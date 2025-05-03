use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Интерфейсный класс `Register` (class_id = 3) для хранения текущего значения
/// измеряемой величины и связанной с ней единицы измерения,
/// в соответствии с IEC 62056-6-2 в библиотеке `spodes-rs`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Register {
    logical_name: ObisCode,
    value: CosemDataType,
    scaler_unit: CosemDataType,
}

impl Register {
    /// Создает новый объект `Register`.
    ///
    /// # Arguments
    /// * `logical_name` - OBIS-код объекта.
    /// * `value` - Текущее значение (например, CosemDataType::DoubleLong).
    /// * `scaler_unit` - Единица измерения и масштаб (CosemDataType::OctetString).
    ///
    /// # Returns
    /// Новая структура `Register`.
    pub fn new(logical_name: ObisCode, value: CosemDataType, scaler_unit: CosemDataType) -> Self {
        Register {
            logical_name,
            value,
            scaler_unit,
        }
    }

    /// Сбрасывает значение регистра до 0.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - Если сброс прошел успешно.
    /// * `Err(String)` - Если тип значения не поддерживает сброс.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        match &self.value {
            CosemDataType::Integer(_) => {
                self.value = CosemDataType::Integer(0);
                Ok(CosemDataType::Null)
            }
            CosemDataType::Long(_) => {
                self.value = CosemDataType::Long(0);
                Ok(CosemDataType::Null)
            }
            CosemDataType::DoubleLong(_) => {
                self.value = CosemDataType::DoubleLong(0);
                Ok(CosemDataType::Null)
            }
            CosemDataType::Unsigned(_) => {
                self.value = CosemDataType::Unsigned(0);
                Ok(CosemDataType::Null)
            }
            CosemDataType::LongUnsigned(_) => {
                self.value = CosemDataType::LongUnsigned(0);
                Ok(CosemDataType::Null)
            }
            CosemDataType::DoubleLongUnsigned(_) => {
                self.value = CosemDataType::DoubleLongUnsigned(0);
                Ok(CosemDataType::Null)
            }
            _ => Err("Unsupported value type for reset".to_string()),
        }
    }
}

impl InterfaceClass for Register {
    fn class_id(&self) -> u16 {
        3
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
            (2, self.value.clone()),
            (3, self.scaler_unit.clone()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string())]
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
        if rest.is_empty() {
            if let CosemDataType::Structure(seq) = tlv {
                if seq.len() == 4 {
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
                    self.value = seq[2].clone();
                    self.scaler_unit = seq[3].clone();
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
            _ => Err(format!("Method {} not supported for Register class", method_id)),
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