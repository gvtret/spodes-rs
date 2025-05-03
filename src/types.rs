use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CosemDataType {
    Null,
    Array(Vec<CosemDataType>),
    Structure(Vec<CosemDataType>),
    Boolean(bool),
    Integer(i8),
    Long(i16),
    Unsigned(u8),
    LongUnsigned(u16),
    DoubleLong(i32),
    DoubleLongUnsigned(u32),
    OctetString(Vec<u8>),
    DateTime(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum BerError {
    InvalidTag,
    InvalidLength,
    InvalidValue,
}

impl CosemDataType {
    pub fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        match self {
            CosemDataType::Null => {
                buf.push(0x00);
                buf.push(0x00);
                Ok(())
            }
            CosemDataType::Array(items) => {
                buf.push(0xA1); // Тег ARRAY
                let mut seq_buf = Vec::new();
                for item in items {
                    item.serialize_ber(&mut seq_buf)?;
                }
                write_length(seq_buf.len(), buf)?;
                buf.extend_from_slice(&seq_buf);
                Ok(())
            }
            CosemDataType::Structure(items) => {
                buf.push(0xA2); // Тег STRUCTURE
                let mut seq_buf = Vec::new();
                for item in items {
                    item.serialize_ber(&mut seq_buf)?;
                }
                write_length(seq_buf.len(), buf)?;
                buf.extend_from_slice(&seq_buf);
                Ok(())
            }
            CosemDataType::Boolean(b) => {
                buf.push(0x83);
                buf.push(0x01);
                buf.push(if *b { 0x01 } else { 0x00 });
                Ok(())
            }
            CosemDataType::Integer(i) => {
                buf.push(0x85);
                buf.push(0x01);
                buf.push(*i as u8);
                Ok(())
            }
            CosemDataType::Long(i) => {
                buf.push(0x86);
                buf.push(0x02);
                buf.extend_from_slice(&i.to_be_bytes());
                Ok(())
            }
            CosemDataType::Unsigned(u) => {
                buf.push(0x87);
                buf.push(0x01);
                buf.push(*u);
                Ok(())
            }
            CosemDataType::LongUnsigned(u) => {
                buf.push(0x88);
                buf.push(0x02);
                buf.extend_from_slice(&u.to_be_bytes());
                Ok(())
            }
            CosemDataType::DoubleLong(i) => {
                buf.push(0x89);
                buf.push(0x04);
                buf.extend_from_slice(&i.to_be_bytes());
                Ok(())
            }
            CosemDataType::DoubleLongUnsigned(u) => {
                buf.push(0x8A);
                buf.push(0x04);
                buf.extend_from_slice(&u.to_be_bytes());
                Ok(())
            }
            CosemDataType::OctetString(s) => {
                buf.push(0x8C);
                write_length(s.len(), buf)?;
                buf.extend_from_slice(s);
                Ok(())
            }
            CosemDataType::DateTime(dt) => {
                buf.push(0x99);
                write_length(dt.len(), buf)?;
                buf.extend_from_slice(dt);
                Ok(())
            }
        }
    }

    pub fn deserialize_ber(data: &[u8]) -> Result<(Self, &[u8]), BerError> {
        if data.is_empty() {
            return Err(BerError::InvalidTag);
        }
        match data[0] {
            0x00 => {
                if data.len() >= 2 && data[1] == 0x00 {
                    Ok((CosemDataType::Null, &data[2..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0xA1 => {
                let (len, rest) = read_length(&data[1..])?;
                let mut items = Vec::new();
                let mut remaining = &rest[..len];
                while !remaining.is_empty() {
                    let (item, next) = CosemDataType::deserialize_ber(remaining)?;
                    items.push(item);
                    remaining = next;
                }
                Ok((CosemDataType::Array(items), &rest[len..]))
            }
            0xA2 => {
                let (len, rest) = read_length(&data[1..])?;
                let mut items = Vec::new();
                let mut remaining = &rest[..len];
                while !remaining.is_empty() {
                    let (item, next) = CosemDataType::deserialize_ber(remaining)?;
                    items.push(item);
                    remaining = next;
                }
                Ok((CosemDataType::Structure(items), &rest[len..]))
            }
            0x83 => {
                if data.len() >= 3 && data[1] == 0x01 {
                    Ok((CosemDataType::Boolean(data[2] != 0), &data[3..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x85 => {
                if data.len() >= 3 && data[1] == 0x01 {
                    Ok((CosemDataType::Integer(data[2] as i8), &data[3..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x86 => {
                if data.len() >= 4 && data[1] == 0x02 {
                    let value = i16::from_be_bytes([data[2], data[3]]);
                    Ok((CosemDataType::Long(value), &data[4..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x87 => {
                if data.len() >= 3 && data[1] == 0x01 {
                    Ok((CosemDataType::Unsigned(data[2]), &data[3..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x88 => {
                if data.len() >= 4 && data[1] == 0x02 {
                    let value = u16::from_be_bytes([data[2], data[3]]);
                    Ok((CosemDataType::LongUnsigned(value), &data[4..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x89 => {
                if data.len() >= 6 && data[1] == 0x04 {
                    let value = i32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                    Ok((CosemDataType::DoubleLong(value), &data[6..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x8A => {
                if data.len() >= 6 && data[1] == 0x04 {
                    let value = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                    Ok((CosemDataType::DoubleLongUnsigned(value), &data[6..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x8C => {
                let (len, rest) = read_length(&data[1..])?;
                if rest.len() >= len {
                    Ok((CosemDataType::OctetString(rest[..len].to_vec()), &rest[len..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x99 => {
                let (len, rest) = read_length(&data[1..])?;
                if rest.len() >= len {
                    Ok((CosemDataType::DateTime(rest[..len].to_vec()), &rest[len..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            _ => Err(BerError::InvalidTag),
        }
    }
}

fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
        Ok(())
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
        Ok(())
    }
}

fn read_length(data: &[u8]) -> Result<(usize, &[u8]), BerError> {
    if data.is_empty() {
        return Err(BerError::InvalidLength);
    }
    if data[0] & 0x80 == 0 {
        Ok((data[0] as usize, &data[1..]))
    } else {
        let num_octets = (data[0] & 0x7F) as usize;
        if num_octets == 0 || data.len() < num_octets + 1 {
            return Err(BerError::InvalidLength);
        }
        let mut len = 0;
        for &b in &data[1..=num_octets] {
            len = (len << 8) + b as usize;
        }
        Ok((len, &data[num_octets + 1..]))
    }
}

impl fmt::Display for CosemDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CosemDataType::Null => write!(f, "Null"),
            CosemDataType::Array(items) => {
                write!(f, "Array([")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "])")
            }
            CosemDataType::Structure(items) => {
                write!(f, "Structure([")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "])")
            }
            CosemDataType::Boolean(b) => write!(f, "Boolean({})", b),
            CosemDataType::Integer(i) => write!(f, "Integer({})", i),
            CosemDataType::Long(i) => write!(f, "Long({})", i),
            CosemDataType::Unsigned(u) => write!(f, "Unsigned({})", u),
            CosemDataType::LongUnsigned(u) => write!(f, "LongUnsigned({})", u),
            CosemDataType::DoubleLong(i) => write!(f, "DoubleLong({})", i),
            CosemDataType::DoubleLongUnsigned(u) => write!(f, "DoubleLongUnsigned({})", u),
            CosemDataType::OctetString(s) => write!(f, "OctetString({:?})", s),
            CosemDataType::DateTime(dt) => write!(f, "DateTime({:?})", dt),
        }
    }
}