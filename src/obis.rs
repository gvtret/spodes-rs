use serde::{Deserialize, Serialize};
use std::fmt;

/// Структура для представления OBIS-кода (Object Identification System),
/// используемого в COSEM для идентификации объектов.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ObisCode {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
}

impl ObisCode {
    /// Создает новый OBIS-код из шести компонентов.
    ///
    /// # Arguments
    /// * `a`, `b`, `c`, `d`, `e`, `f` - Компоненты OBIS-кода.
    ///
    /// # Returns
    /// Новая структура `ObisCode`.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        ObisCode { a, b, c, d, e, f }
    }

    /// Возвращает OBIS-код в виде массива байтов.
    ///
    /// # Returns
    /// Вектор из шести байтов, представляющий OBIS-код.
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.a, self.b, self.c, self.d, self.e, self.f]
    }
}

impl fmt::Display for ObisCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-{}.{}.{}.{}.{}",
            self.a, self.b, self.c, self.d, self.e, self.f
        )
    }
}