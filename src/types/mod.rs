pub mod attrs;

use serde::{Deserialize, Serialize};
use std::fmt;

/// A COSEM common data type (IEC 62056-6-2, Table 3), with A-XDR (BER)
/// serialization via [`CosemDataType::serialize_ber`] /
/// [`CosemDataType::deserialize_ber`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CosemDataType {
    /// `null-data` (tag 0).
    Null,
    /// `array` (tag 1) — a sequence of same-typed elements.
    Array(Vec<CosemDataType>),
    /// `structure` (tag 2) — a sequence of (possibly differently typed) elements.
    Structure(Vec<CosemDataType>),
    /// `boolean` (tag 3).
    Boolean(bool),
    /// `integer` — signed 8-bit (tag 15).
    Integer(i8),
    /// `long` — signed 16-bit (tag 16).
    Long(i16),
    /// `unsigned` — unsigned 8-bit (tag 17).
    Unsigned(u8),
    /// `long-unsigned` — unsigned 16-bit (tag 18).
    LongUnsigned(u16),
    /// `double-long` — signed 32-bit (tag 5).
    DoubleLong(i32),
    /// `double-long-unsigned` — unsigned 32-bit (tag 6).
    DoubleLongUnsigned(u32),
    /// `octet-string` (tag 9).
    OctetString(Vec<u8>),
    /// `date-time` (tag 25) — a 12-octet date-time value.
    DateTime(Vec<u8>),
    /// `bit-string` (tag 4) — held as raw octets.
    BitString(Vec<u8>),
    /// `enum` — an enumerated 8-bit value (tag 22).
    Enum(u8),
}

/// An error while encoding or decoding a [`CosemDataType`] in BER.
#[derive(Debug, PartialEq)]
pub enum BerError {
    /// The tag octet was not a recognized COSEM data type.
    InvalidTag,
    /// The value ended before all declared octets were present.
    InvalidLength,
    /// A value did not conform to its type.
    InvalidValue,
}

impl CosemDataType {
    /// Appends the A-XDR (BER) encoding of this value to `buf`.
    pub fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        // A-XDR encoding of the common data types (IEC 62056-6-2, Table 3).
        // Tags are the one-octet values from the table; fixed scalar types and
        // enums are encoded as [tag][value] with no length octet; array/structure
        // carry a length equal to the ELEMENT COUNT (not the byte count).
        match self {
            CosemDataType::Null => {
                buf.push(0x00); // null-data [0]: no length and no content
                Ok(())
            }
            CosemDataType::Array(items) => {
                buf.push(0x01); // array [1]
                write_length(items.len(), buf)?; // length = element count
                for item in items {
                    item.serialize_ber(buf)?;
                }
                Ok(())
            }
            CosemDataType::Structure(items) => {
                buf.push(0x02); // structure [2]
                write_length(items.len(), buf)?; // length = element count
                for item in items {
                    item.serialize_ber(buf)?;
                }
                Ok(())
            }
            CosemDataType::Boolean(b) => {
                buf.push(0x03); // boolean [3]
                buf.push(if *b { 0x01 } else { 0x00 });
                Ok(())
            }
            CosemDataType::Integer(i) => {
                buf.push(0x0F); // integer [15]
                buf.push(*i as u8);
                Ok(())
            }
            CosemDataType::Long(i) => {
                buf.push(0x10); // long [16]
                buf.extend_from_slice(&i.to_be_bytes());
                Ok(())
            }
            CosemDataType::Unsigned(u) => {
                buf.push(0x11); // unsigned [17]
                buf.push(*u);
                Ok(())
            }
            CosemDataType::LongUnsigned(u) => {
                buf.push(0x12); // long-unsigned [18]
                buf.extend_from_slice(&u.to_be_bytes());
                Ok(())
            }
            CosemDataType::DoubleLong(i) => {
                buf.push(0x05); // double-long [5]
                buf.extend_from_slice(&i.to_be_bytes());
                Ok(())
            }
            CosemDataType::DoubleLongUnsigned(u) => {
                buf.push(0x06); // double-long-unsigned [6]
                buf.extend_from_slice(&u.to_be_bytes());
                Ok(())
            }
            CosemDataType::OctetString(s) => {
                buf.push(0x09); // octet-string [9]
                write_length(s.len(), buf)?;
                buf.extend_from_slice(s);
                Ok(())
            }
            CosemDataType::DateTime(dt) => {
                buf.push(0x19); // date-time [25]: octet-string SIZE(12) with a length octet
                write_length(dt.len(), buf)?;
                buf.extend_from_slice(dt);
                Ok(())
            }
            CosemDataType::BitString(s) => {
                buf.push(0x04); // bit-string [4]
                                // NB: in A-XDR the bit-string length is given in BITS; here the
                                // byte count is stored, since the type model holds a raw Vec<u8>.
                write_length(s.len(), buf)?;
                buf.extend_from_slice(s);
                Ok(())
            }
            CosemDataType::Enum(e) => {
                buf.push(0x16); // enum [22]
                buf.push(*e);
                Ok(())
            }
        }
    }

    /// Decodes one A-XDR (BER) value from `data`, returning it and the
    /// unconsumed remainder.
    pub fn deserialize_ber(data: &[u8]) -> Result<(Self, &[u8]), BerError> {
        if data.is_empty() {
            return Err(BerError::InvalidTag);
        }
        match data[0] {
            0x00 => Ok((CosemDataType::Null, &data[1..])),
            0x01 => {
                let (count, mut rest) = read_length(&data[1..])?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let (item, next) = CosemDataType::deserialize_ber(rest)?;
                    items.push(item);
                    rest = next;
                }
                Ok((CosemDataType::Array(items), rest))
            }
            0x02 => {
                let (count, mut rest) = read_length(&data[1..])?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let (item, next) = CosemDataType::deserialize_ber(rest)?;
                    items.push(item);
                    rest = next;
                }
                Ok((CosemDataType::Structure(items), rest))
            }
            0x03 => {
                if data.len() >= 2 {
                    Ok((CosemDataType::Boolean(data[1] != 0), &data[2..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x0F => {
                if data.len() >= 2 {
                    Ok((CosemDataType::Integer(data[1] as i8), &data[2..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x10 => {
                if data.len() >= 3 {
                    let value = i16::from_be_bytes([data[1], data[2]]);
                    Ok((CosemDataType::Long(value), &data[3..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x11 => {
                if data.len() >= 2 {
                    Ok((CosemDataType::Unsigned(data[1]), &data[2..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x12 => {
                if data.len() >= 3 {
                    let value = u16::from_be_bytes([data[1], data[2]]);
                    Ok((CosemDataType::LongUnsigned(value), &data[3..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x05 => {
                if data.len() >= 5 {
                    let value = i32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    Ok((CosemDataType::DoubleLong(value), &data[5..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x06 => {
                if data.len() >= 5 {
                    let value = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    Ok((CosemDataType::DoubleLongUnsigned(value), &data[5..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x09 => {
                let (len, rest) = read_length(&data[1..])?;
                if rest.len() >= len {
                    Ok((CosemDataType::OctetString(rest[..len].to_vec()), &rest[len..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x19 => {
                let (len, rest) = read_length(&data[1..])?;
                if rest.len() >= len {
                    Ok((CosemDataType::DateTime(rest[..len].to_vec()), &rest[len..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x04 => {
                let (len, rest) = read_length(&data[1..])?;
                if rest.len() >= len {
                    Ok((CosemDataType::BitString(rest[..len].to_vec()), &rest[len..]))
                } else {
                    Err(BerError::InvalidLength)
                }
            }
            0x16 => {
                if data.len() >= 2 {
                    Ok((CosemDataType::Enum(data[1]), &data[2..]))
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
        // Longer length fields would overflow on crafted input; 4 octets
        // (lengths up to 2^32-1) are more than any DLMS PDU can carry.
        if num_octets == 0 || num_octets > 4 || data.len() < num_octets + 1 {
            return Err(BerError::InvalidLength);
        }
        let mut len: usize = 0;
        for &b in &data[1..=num_octets] {
            len = (len << 8) + b as usize;
        }
        let rest = &data[num_octets + 1..];
        // A declared length beyond the remaining buffer is malformed; rejecting
        // it here prevents oversized allocations from crafted headers.
        if len > rest.len() {
            return Err(BerError::InvalidLength);
        }
        Ok((len, rest))
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
                    write!(f, "{item}")?;
                }
                write!(f, "])")
            }
            CosemDataType::Structure(items) => {
                write!(f, "Structure([")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "])")
            }
            CosemDataType::Boolean(b) => write!(f, "Boolean({b})"),
            CosemDataType::Integer(i) => write!(f, "Integer({i})"),
            CosemDataType::Long(i) => write!(f, "Long({i})"),
            CosemDataType::Unsigned(u) => write!(f, "Unsigned({u})"),
            CosemDataType::LongUnsigned(u) => write!(f, "LongUnsigned({u})"),
            CosemDataType::DoubleLong(i) => write!(f, "DoubleLong({i})"),
            CosemDataType::DoubleLongUnsigned(u) => write!(f, "DoubleLongUnsigned({u})"),
            CosemDataType::OctetString(s) => write!(f, "OctetString({s:?})"),
            CosemDataType::DateTime(dt) => write!(f, "DateTime({dt:?})"),
            CosemDataType::BitString(s) => write!(f, "BitString({s:?})"),
            CosemDataType::Enum(e) => write!(f, "Enum({e})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &CosemDataType) -> Vec<u8> {
        let mut buf = Vec::new();
        v.serialize_ber(&mut buf).unwrap();
        buf
    }

    /// A crafted long-form length must not overflow or allocate: more than
    /// 4 length octets, or a declared length beyond the buffer, is rejected.
    #[test]
    fn crafted_ber_length_is_rejected() {
        // octet-string, long form with 9 length octets (would shift-overflow).
        let crafted = [0x09, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(CosemDataType::deserialize_ber(&crafted).is_err());
        // octet-string declaring 0xFFFFFFFF octets with an empty body.
        let oversized = [0x09, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(CosemDataType::deserialize_ber(&oversized).is_err());
    }

    /// Reference A-XDR vector from DLMS UA 1000-1 (context_name encoding example,
    /// context_id(1)): a 7-element structure → 02 07 11 02 11 10 12 02 F4 11 05 11 08 11 01 11 01.
    #[test]
    fn axdr_reference_context_name() {
        let s = CosemDataType::Structure(vec![
            CosemDataType::Unsigned(2),
            CosemDataType::Unsigned(16),
            CosemDataType::LongUnsigned(756),
            CosemDataType::Unsigned(5),
            CosemDataType::Unsigned(8),
            CosemDataType::Unsigned(1),
            CosemDataType::Unsigned(1),
        ]);
        assert_eq!(
            enc(&s),
            vec![0x02, 0x07, 0x11, 0x02, 0x11, 0x10, 0x12, 0x02, 0xF4, 0x11, 0x05, 0x11, 0x08, 0x11, 0x01, 0x11, 0x01]
        );
    }

    /// Simple-type tags per Table 3, and the absence of a length octet on scalars.
    #[test]
    fn axdr_scalar_tags() {
        assert_eq!(enc(&CosemDataType::Null), vec![0x00]);
        assert_eq!(enc(&CosemDataType::Boolean(true)), vec![0x03, 0x01]);
        assert_eq!(enc(&CosemDataType::Integer(-1)), vec![0x0F, 0xFF]);
        assert_eq!(enc(&CosemDataType::Long(-2)), vec![0x10, 0xFF, 0xFE]);
        assert_eq!(enc(&CosemDataType::DoubleLong(1)), vec![0x05, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(enc(&CosemDataType::DoubleLongUnsigned(1)), vec![0x06, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(enc(&CosemDataType::Unsigned(5)), vec![0x11, 0x05]);
        assert_eq!(enc(&CosemDataType::LongUnsigned(756)), vec![0x12, 0x02, 0xF4]);
        assert_eq!(enc(&CosemDataType::Enum(3)), vec![0x16, 0x03]);
        assert_eq!(enc(&CosemDataType::OctetString(vec![0xAB, 0xCD])), vec![0x09, 0x02, 0xAB, 0xCD]);
        assert_eq!(enc(&CosemDataType::Array(vec![CosemDataType::Unsigned(1)])), vec![0x01, 0x01, 0x11, 0x01]);
    }

    #[test]
    fn axdr_round_trip() {
        let samples = vec![
            CosemDataType::Null,
            CosemDataType::Boolean(false),
            CosemDataType::Integer(-128),
            CosemDataType::Long(-32768),
            CosemDataType::Unsigned(255),
            CosemDataType::LongUnsigned(65535),
            CosemDataType::DoubleLong(-1),
            CosemDataType::DoubleLongUnsigned(4_000_000_000),
            CosemDataType::Enum(7),
            CosemDataType::OctetString(vec![1, 2, 3]),
            CosemDataType::DateTime(vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            CosemDataType::Array(vec![CosemDataType::Unsigned(1), CosemDataType::Unsigned(2)]),
            CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(7),
                CosemDataType::OctetString(vec![0, 0, 96, 1, 0, 255]),
                CosemDataType::Array(vec![CosemDataType::Enum(1)]),
            ]),
        ];
        for s in samples {
            let bytes = enc(&s);
            let (decoded, rest) = CosemDataType::deserialize_ber(&bytes).unwrap();
            assert!(rest.is_empty(), "trailing bytes for {s:?}");
            assert_eq!(decoded, s);
        }
    }
}
