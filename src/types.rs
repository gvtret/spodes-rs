use serde::{Deserialize, Serialize};
use std::fmt;

/// Ошибка при работе с BER-кодированием.
#[derive(Debug, PartialEq)]
pub enum BerError {
    InvalidTag,
    InvalidLength,
    InvalidValue,
    BufferTooSmall,
    UnexpectedEof,
}

impl std::error::Error for BerError {}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BerError::InvalidTag => write!(f, "Invalid BER tag"),
            BerError::InvalidLength => write!(f, "Invalid BER length"),
            BerError::InvalidValue => write!(f, "Invalid BER value"),
            BerError::BufferTooSmall => write!(f, "Buffer too small for BER data"),
            BerError::UnexpectedEof => write!(f, "Unexpected end of input"),
        }
    }
}

/// Перечисление, представляющее типы данных COSEM, определенные в IEC 62056-6-2.
///
/// Поддерживает все стандартные типы данных, включая простые (`Integer`, `Boolean`),
/// а также сложные (`Array`, `Structure`, `CompactArray`), которые требуют рекурсивной
/// обработки при сериализации и десериализации в формате BER.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CosemDataType {
    /// Пустое значение (NULL).
    Null,
    /// Булево значение.
    Boolean(bool),
    /// 8-битное целое число со знаком.
    Integer(i8),
    /// 16-битное целое число со знаком.
    Long(i16),
    /// 32-битное целое число со знаком.
    DoubleLong(i32),
    /// 64-битное целое число со знаком.
    Long64(i64),
    /// 8-битное целое число без знака.
    Unsigned(u8),
    /// 16-битное целое число без знака.
    LongUnsigned(u16),
    /// 32-битное целое число без знака.
    DoubleLongUnsigned(u32),
    /// 64-битное целое число без знака.
    Long64Unsigned(u64),
    /// 32-битное число с плавающей точкой.
    Float32(f32),
    /// 64-битное число с плавающей точкой.
    Float64(f64),
    /// Последовательность байтов.
    OctetString(Vec<u8>),
    /// Строка из символов ASCII.
    VisibleString(String),
    /// Строка в кодировке UTF-8.
    Utf8String(String),
    /// Двоично-десятичное число (BCD).
    Bcd(u8),
    /// Битовая строка.
    BitString(String),
    /// Дата и время в формате, определенном IEC 62056-6-1.
    DateTime(Vec<u8>),
    /// Массив элементов `CosemDataType` (рекурсивный тип).
    Array(Vec<CosemDataType>),
    /// Структура из элементов `CosemDataType` (рекурсивный тип).
    Structure(Vec<CosemDataType>),
    /// Сжатый массив в виде последовательности байтов.
    CompactArray(Vec<u8>),
}

impl CosemDataType {
    /// Сериализует значение `CosemDataType` в формат BER согласно IEC 62056-6-2.
    ///
    /// # Arguments
    /// * `buf` - Буфер для записи сериализованных данных.
    ///
    /// # Returns
    /// * `Ok(())` - Если сериализация прошла успешно.
    /// * `Err(BerError)` - Если произошла ошибка сериализации.
    pub fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let tag = match self {
            CosemDataType::Null => 0x80,
            CosemDataType::Boolean(_) => 0x83,
            CosemDataType::Integer(_) => 0x8F,
            CosemDataType::Long(_) => 0x90,
            CosemDataType::DoubleLong(_) => 0x85,
            CosemDataType::Long64(_) => 0x94,
            CosemDataType::Unsigned(_) => 0x91,
            CosemDataType::LongUnsigned(_) => 0x92,
            CosemDataType::DoubleLongUnsigned(_) => 0x86,
            CosemDataType::Long64Unsigned(_) => 0x95,
            CosemDataType::Float32(_) => 0x97,
            CosemDataType::Float64(_) => 0x98,
            CosemDataType::OctetString(_) => 0x89,
            CosemDataType::VisibleString(_) => 0x8A,
            CosemDataType::Utf8String(_) => 0x8C,
            CosemDataType::Bcd(_) => 0x8D,
            CosemDataType::BitString(_) => 0x84,
            CosemDataType::DateTime(_) => 0x99,
            CosemDataType::CompactArray(_) => 0x93,
            CosemDataType::Array(_) => 0xA1,
            CosemDataType::Structure(_) => 0xA2,
        };
        buf.push(tag);
        if matches!(self, CosemDataType::Array(_) | CosemDataType::Structure(_)) {
            let mut seq_buf = Vec::new();
            match self {
                CosemDataType::Array(arr) => {
                    for item in arr {
                        item.serialize_ber(&mut seq_buf)?;
                    }
                }
                CosemDataType::Structure(struc) => {
                    for item in struc {
                        item.serialize_ber(&mut seq_buf)?;
                    }
                }
                _ => unreachable!(),
            }
            write_length(seq_buf.len(), buf)?;
            buf.extend_from_slice(&seq_buf);
        } else {
            let length = match self {
                CosemDataType::Null => 0,
                CosemDataType::Boolean(_) => 1,
                CosemDataType::Integer(_) => 1,
                CosemDataType::Long(_) => 2,
                CosemDataType::DoubleLong(_) => 4,
                CosemDataType::Long64(_) => 8,
                CosemDataType::Unsigned(_) => 1,
                CosemDataType::LongUnsigned(_) => 2,
                CosemDataType::DoubleLongUnsigned(_) => 4,
                CosemDataType::Long64Unsigned(_) => 8,
                CosemDataType::Float32(_) => 4,
                CosemDataType::Float64(_) => 8,
                CosemDataType::OctetString(os) => os.len(),
                CosemDataType::VisibleString(vs) => vs.as_bytes().len(),
                CosemDataType::Utf8String(utf8) => utf8.as_bytes().len(),
                CosemDataType::Bcd(_) => 1,
                CosemDataType::BitString(bs) => {
                    let bit_len = bs.len();
                    let num_octets = (bit_len + 7) / 8;
                    1 + num_octets // 1 для unused_bits
                }
                CosemDataType::DateTime(dt) => dt.len(),
                CosemDataType::CompactArray(ca) => ca.len(),
                _ => unreachable!(),
            };
            write_length(length, buf)?;
            match self {
                CosemDataType::Null => {}
                CosemDataType::Boolean(b) => buf.push(if *b { 0xFF } else { 0x00 }),
                CosemDataType::Integer(i) => buf.push(*i as u8),
                CosemDataType::Long(l) => buf.extend_from_slice(&l.to_be_bytes()),
                CosemDataType::DoubleLong(dl) => buf.extend_from_slice(&dl.to_be_bytes()),
                CosemDataType::Long64(l64) => buf.extend_from_slice(&l64.to_be_bytes()),
                CosemDataType::Unsigned(u) => buf.push(*u),
                CosemDataType::LongUnsigned(lu) => buf.extend_from_slice(&lu.to_be_bytes()),
                CosemDataType::DoubleLongUnsigned(dlu) => buf.extend_from_slice(&dlu.to_be_bytes()),
                CosemDataType::Long64Unsigned(lu64) => buf.extend_from_slice(&lu64.to_be_bytes()),
                CosemDataType::Float32(f) => buf.extend_from_slice(&f.to_bits().to_be_bytes()),
                CosemDataType::Float64(f) => buf.extend_from_slice(&f.to_bits().to_be_bytes()),
                CosemDataType::OctetString(os) => buf.extend_from_slice(os),
                CosemDataType::VisibleString(vs) => buf.extend_from_slice(vs.as_bytes()),
                CosemDataType::Utf8String(utf8) => buf.extend_from_slice(utf8.as_bytes()),
                CosemDataType::Bcd(bcd) => buf.push(*bcd),
                CosemDataType::BitString(bs) => {
                    let bit_len = bs.len();
                    let num_octets = (bit_len + 7) / 8;
                    let unused_bits = (num_octets * 8 - bit_len) as u8;
                    buf.push(unused_bits);
                    let mut bytes = vec![0u8; num_octets];
                    for (i, c) in bs.chars().enumerate() {
                        if c == '1' {
                            let byte_index = i / 8;
                            let bit_index = 7 - (i % 8);
                            bytes[byte_index] |= 1 << bit_index;
                        }
                    }
                    buf.extend_from_slice(&bytes);
                }
                CosemDataType::DateTime(dt) => buf.extend_from_slice(dt),
                CosemDataType::CompactArray(ca) => buf.extend_from_slice(ca),
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    /// Десериализует значение `CosemDataType` из формата BER.
    ///
    /// # Arguments
    /// * `bytes` - Входные данные в формате BER.
    ///
    /// # Returns
    /// * `Ok((CosemDataType, &[u8]))` - Десериализованное значение и оставшиеся байты.
    /// * `Err(BerError)` - Если произошла ошибка десериализации.
    pub fn deserialize_ber(bytes: &[u8]) -> Result<(Self, &[u8]), BerError> {
        if bytes.is_empty() {
            return Err(BerError::UnexpectedEof);
        }
        let tag = bytes[0];
        let (length, len_bytes) = read_length(&bytes[1..])?;
        let value_start = 1 + len_bytes;
        if value_start + length > bytes.len() {
            return Err(BerError::UnexpectedEof);
        }
        let value = &bytes[value_start..value_start + length];
        let rest = &bytes[value_start + length..];
        match tag {
            0x80 => {
                if length != 0 {
                    return Err(BerError::InvalidLength);
                }
                Ok((CosemDataType::Null, rest))
            }
            0x83 => {
                if length != 1 {
                    return Err(BerError::InvalidLength);
                }
                let b = value[0] != 0x00;
                Ok((CosemDataType::Boolean(b), rest))
            }
            0x8F => {
                if length != 1 {
                    return Err(BerError::InvalidLength);
                }
                let i = value[0] as i8;
                Ok((CosemDataType::Integer(i), rest))
            }
            0x90 => {
                if length != 2 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 2];
                buf.copy_from_slice(value);
                let l = i16::from_be_bytes(buf);
                Ok((CosemDataType::Long(l), rest))
            }
            0x85 => {
                if length != 4 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(value);
                let dl = i32::from_be_bytes(buf);
                Ok((CosemDataType::DoubleLong(dl), rest))
            }
            0x94 => {
                if length != 8 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(value);
                let l64 = i64::from_be_bytes(buf);
                Ok((CosemDataType::Long64(l64), rest))
            }
            0x91 => {
                if length != 1 {
                    return Err(BerError::InvalidLength);
                }
                let u = value[0];
                Ok((CosemDataType::Unsigned(u), rest))
            }
            0x92 => {
                if length != 2 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 2];
                buf.copy_from_slice(value);
                let lu = u16::from_be_bytes(buf);
                Ok((CosemDataType::LongUnsigned(lu), rest))
            }
            0x86 => {
                if length != 4 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(value);
                let dlu = u32::from_be_bytes(buf);
                Ok((CosemDataType::DoubleLongUnsigned(dlu), rest))
            }
            0x95 => {
                if length != 8 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(value);
                let lu64 = u64::from_be_bytes(buf);
                Ok((CosemDataType::Long64Unsigned(lu64), rest))
            }
            0x97 => {
                if length != 4 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(value);
                let f = f32::from_bits(u32::from_be_bytes(buf));
                Ok((CosemDataType::Float32(f), rest))
            }
            0x98 => {
                if length != 8 {
                    return Err(BerError::InvalidLength);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(value);
                let f = f64::from_bits(u64::from_be_bytes(buf));
                Ok((CosemDataType::Float64(f), rest))
            }
            0x89 => Ok((CosemDataType::OctetString(value.to_vec()), rest)),
            0x8A => {
                let vs = String::from_utf8(value.to_vec()).map_err(|_| BerError::InvalidValue)?;
                Ok((CosemDataType::VisibleString(vs), rest))
            }
            0x8C => {
                let utf8 = String::from_utf8(value.to_vec()).map_err(|_| BerError::InvalidValue)?;
                Ok((CosemDataType::Utf8String(utf8), rest))
            }
            0x8D => {
                if length != 1 {
                    return Err(BerError::InvalidLength);
                }
                let bcd = value[0];
                Ok((CosemDataType::Bcd(bcd), rest))
            }
            0x84 => {
                if length < 1 {
                    return Err(BerError::InvalidLength);
                }
                let unused_bits = value[0];
                if unused_bits > 7 {
                    return Err(BerError::InvalidValue);
                }
                let bit_len = (length - 1) * 8 - (unused_bits as usize);
                let mut s = String::new();
                for byte in &value[1..] {
                    for i in (0..8).rev() {
                        if s.len() < bit_len {
                            if (byte & (1 << i)) != 0 {
                                s.push('1');
                            } else {
                                s.push('0');
                            }
                        }
                    }
                }
                Ok((CosemDataType::BitString(s), rest))
            }
            0x99 => {
                if length != 12 {
                    return Err(BerError::InvalidLength);
                }
                Ok((CosemDataType::DateTime(value.to_vec()), rest))
            }
            0x93 => Ok((CosemDataType::CompactArray(value.to_vec()), rest)),
            0xA1 => {
                let mut items = Vec::new();
                let mut current_bytes = value;
                while !current_bytes.is_empty() {
                    let (item, rest) = CosemDataType::deserialize_ber(current_bytes)?;
                    items.push(item);
                    current_bytes = rest;
                }
                Ok((CosemDataType::Array(items), rest))
            }
            0xA2 => {
                let mut items = Vec::new();
                let mut current_bytes = value;
                while !current_bytes.is_empty() {
                    let (item, rest) = CosemDataType::deserialize_ber(current_bytes)?;
                    items.push(item);
                    current_bytes = rest;
                }
                Ok((CosemDataType::Structure(items), rest))
            }
            _ => Err(BerError::InvalidTag),
        }
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

/// Читает длину в формате BER (короткая или длинная форма).
fn read_length(bytes: &[u8]) -> Result<(usize, usize), BerError> {
    if bytes.is_empty() {
        return Err(BerError::UnexpectedEof);
    }
    let first = bytes[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 8 || num_bytes > bytes.len() - 1 {
            return Err(BerError::InvalidLength);
        }
        let mut length_bytes = [0u8; 8];
        length_bytes[8 - num_bytes..].copy_from_slice(&bytes[1..1 + num_bytes]);
        let length = u64::from_be_bytes(length_bytes) as usize;
        Ok((length, 1 + num_bytes))
    }
}

impl fmt::Display for CosemDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CosemDataType::Null => write!(f, "NULL"),
            CosemDataType::Boolean(b) => write!(f, "Boolean({})", b),
            CosemDataType::Integer(i) => write!(f, "Integer({})", i),
            CosemDataType::Long(l) => write!(f, "Long({})", l),
            CosemDataType::DoubleLong(dl) => write!(f, "DoubleLong({})", dl),
            CosemDataType::Long64(l64) => write!(f, "Long64({})", l64),
            CosemDataType::Unsigned(u) => write!(f, "Unsigned({})", u),
            CosemDataType::LongUnsigned(lu) => write!(f, "LongUnsigned({})", lu),
            CosemDataType::DoubleLongUnsigned(dlu) => write!(f, "DoubleLongUnsigned({})", dlu),
            CosemDataType::Long64Unsigned(lu64) => write!(f, "Long64Unsigned({})", lu64),
            CosemDataType::Float32(f32) => write!(f, "Float32({})", f32),
            CosemDataType::Float64(f64) => write!(f, "Float64({})", f64),
            CosemDataType::OctetString(os) => write!(f, "OctetString({:?})", os),
            CosemDataType::VisibleString(vs) => write!(f, "VisibleString({})", vs),
            CosemDataType::Utf8String(utf8) => write!(f, "Utf8String({})", utf8),
            CosemDataType::Bcd(bcd) => write!(f, "Bcd({})", bcd),
            CosemDataType::BitString(bs) => write!(f, "BitString({})", bs),
            CosemDataType::DateTime(dt) => write!(f, "DateTime({:?})", dt),
            CosemDataType::Array(arr) => write!(f, "Array({:?})", arr),
            CosemDataType::Structure(struc) => write!(f, "Structure({:?})", struc),
            CosemDataType::CompactArray(ca) => write!(f, "CompactArray({:?})", ca),
        }
    }
}