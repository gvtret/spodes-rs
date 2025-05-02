use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Интерфейсный класс `Data` (class_id = 1) для хранения простых данных,
/// таких как идентификаторы или статические параметры, в соответствии
/// с IEC 62056-6-2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    logical_name: ObisCode,
    value: CosemDataType,
}

impl Data {
    /// Создает новый объект `Data`.
    ///
    /// # Arguments
    /// * `logical_name` - OBIS-код объекта.
    /// * `value` - Значение объекта в формате `CosemDataType`.
    ///
    /// # Returns
    /// Новая структура `Data`.
    pub fn new(logical_name: ObisCode, value: CosemDataType) -> Self {
        Data {
            logical_name,
            value,
        }
    }
}

impl InterfaceClass for Data {
    fn class_id(&self) -> u16 {
        1
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
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(&mut seq_buf)?;
        self.value.serialize_ber(&mut seq_buf)?;
        buf.push(0xA2); // Тег STRUCTURE
        write_length(seq_buf.len(), buf)?;
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if rest.is_empty() {
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
                            self.logical_name =
                                ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
                        } else {
                            return Err(BerError::InvalidLength);
                        }
                    } else {
                        return Err(BerError::InvalidTag);
                    }
                    self.value = seq[2].clone();
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
        Err(format!("Method {} not supported for Data class", method_id))
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
