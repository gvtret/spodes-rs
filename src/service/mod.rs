//! Application-layer xDLMS services with LN referencing (IEC 62056-5-3).
//!
//! Each service is modelled as request/response APDUs that encode to and decode
//! from the byte payloads carried by the [`crate::transport`] data-link layer.
//! Common building blocks — the invoke-id-and-priority octet, the COSEM
//! attribute/method descriptors and the data-access-result codes — live here;
//! the individual services are in the sub-modules.

use crate::obis::ObisCode;
use crate::types::BerError;

pub mod acse;
pub mod action;
pub mod ciphering;
pub mod error;
pub mod gbt;
pub mod general_ciphering;
pub mod get;
pub mod initiate;
pub mod notification;
pub mod set;

/// APDU tags of the xDLMS services (LN referencing), IEC 62056-5-3 Table 60.
pub mod tag {
    pub const DATA_NOTIFICATION: u8 = 0x0F;
    pub const GET_REQUEST: u8 = 0xC0;
    pub const SET_REQUEST: u8 = 0xC1;
    pub const EVENT_NOTIFICATION_REQUEST: u8 = 0xC2;
    pub const ACTION_REQUEST: u8 = 0xC3;
    pub const GET_RESPONSE: u8 = 0xC4;
    pub const SET_RESPONSE: u8 = 0xC5;
    pub const ACTION_RESPONSE: u8 = 0xC7;
    pub const EXCEPTION_RESPONSE: u8 = 0xD8;
    pub const CONFIRMED_SERVICE_ERROR: u8 = 0x0E;
}

/// `Data-Access-Result` codes (IEC 62056-5-3). Returned by GET/SET and, for the
/// optional return parameters, by ACTION.
pub mod data_access_result {
    pub const SUCCESS: u8 = 0;
    pub const HARDWARE_FAULT: u8 = 1;
    pub const TEMPORARY_FAILURE: u8 = 2;
    pub const READ_WRITE_DENIED: u8 = 3;
    pub const OBJECT_UNDEFINED: u8 = 4;
    pub const OBJECT_CLASS_INCONSISTENT: u8 = 9;
    pub const OBJECT_UNAVAILABLE: u8 = 11;
    pub const TYPE_UNMATCHED: u8 = 12;
    pub const SCOPE_OF_ACCESS_VIOLATED: u8 = 13;
    pub const DATA_BLOCK_UNAVAILABLE: u8 = 14;
    pub const LONG_GET_ABORTED: u8 = 15;
    pub const NO_LONG_GET_IN_PROGRESS: u8 = 16;
    pub const LONG_SET_ABORTED: u8 = 17;
    pub const NO_LONG_SET_IN_PROGRESS: u8 = 18;
    pub const DATA_BLOCK_NUMBER_INVALID: u8 = 19;
    pub const OTHER_REASON: u8 = 250;
}

/// Errors that can occur while decoding a service APDU.
#[derive(Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The APDU tag was not the expected one.
    UnexpectedTag(u8),
    /// The request/response type octet was not the expected one.
    UnexpectedType(u8),
    /// The APDU ended before all mandatory fields were read.
    Truncated,
    /// A value did not conform to the expected encoding.
    InvalidData,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ServiceError {}

impl From<BerError> for ServiceError {
    fn from(_: BerError) -> Self {
        ServiceError::InvalidData
    }
}

/// Builds the invoke-id-and-priority octet: bits 0..3 the invoke id, bit 6 the
/// service class (1 = confirmed), bit 7 the priority (1 = high).
pub fn invoke_id_and_priority(invoke_id: u8, confirmed: bool, high_priority: bool) -> u8 {
    (invoke_id & 0x0F) | if confirmed { 0x40 } else { 0x00 } | if high_priority { 0x80 } else { 0x00 }
}

/// A COSEM attribute descriptor: the (class-id, instance-id, attribute-id)
/// triple that references one attribute of one object instance. Encoded as
/// 2 + 6 + 1 = 9 raw octets.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeDescriptor {
    pub class_id: u16,
    pub instance_id: ObisCode,
    pub attribute_id: i8,
}

impl AttributeDescriptor {
    pub fn new(class_id: u16, instance_id: ObisCode, attribute_id: i8) -> Self {
        AttributeDescriptor { class_id, instance_id, attribute_id }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.class_id.to_be_bytes());
        buf.extend_from_slice(&self.instance_id.to_bytes());
        buf.push(self.attribute_id as u8);
    }

    pub fn decode(bytes: &[u8]) -> Result<(AttributeDescriptor, usize), ServiceError> {
        if bytes.len() < 9 {
            return Err(ServiceError::Truncated);
        }
        let class_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let o = &bytes[2..8];
        let instance_id = ObisCode::new(o[0], o[1], o[2], o[3], o[4], o[5]);
        Ok((AttributeDescriptor { class_id, instance_id, attribute_id: bytes[8] as i8 }, 9))
    }
}

/// A COSEM method descriptor: the (class-id, instance-id, method-id) triple that
/// references one method of one object instance. Encoded as 9 raw octets.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodDescriptor {
    pub class_id: u16,
    pub instance_id: ObisCode,
    pub method_id: i8,
}

impl MethodDescriptor {
    pub fn new(class_id: u16, instance_id: ObisCode, method_id: i8) -> Self {
        MethodDescriptor { class_id, instance_id, method_id }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.class_id.to_be_bytes());
        buf.extend_from_slice(&self.instance_id.to_bytes());
        buf.push(self.method_id as u8);
    }

    pub fn decode(bytes: &[u8]) -> Result<(MethodDescriptor, usize), ServiceError> {
        if bytes.len() < 9 {
            return Err(ServiceError::Truncated);
        }
        let class_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let o = &bytes[2..8];
        let instance_id = ObisCode::new(o[0], o[1], o[2], o[3], o[4], o[5]);
        Ok((MethodDescriptor { class_id, instance_id, method_id: bytes[8] as i8 }, 9))
    }
}

/// `DataBlock-SA`: one block of a SET/ACTION block transfer. Encoded as
/// `last-block (boolean) ‖ block-number (u32) ‖ raw-data (A-XDR octet-string)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBlockSa {
    pub last_block: bool,
    pub block_number: u32,
    pub raw_data: Vec<u8>,
}

impl DataBlockSa {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.last_block as u8);
        buf.extend_from_slice(&self.block_number.to_be_bytes());
        push_length(self.raw_data.len(), buf);
        buf.extend_from_slice(&self.raw_data);
    }

    pub fn decode(bytes: &[u8]) -> Result<(DataBlockSa, usize), ServiceError> {
        let last_block = *bytes.first().ok_or(ServiceError::Truncated)? != 0;
        let b = bytes.get(1..5).ok_or(ServiceError::Truncated)?;
        let block_number = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let (len, header) = read_length(&bytes[5..])?;
        let start = 5 + header;
        let raw_data = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
        Ok((DataBlockSa { last_block, block_number, raw_data }, start + len))
    }
}

/// Writes an A-XDR length octet (short or long form).
pub(crate) fn push_length(length: usize, buf: &mut Vec<u8>) {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let n = 8 - first;
        buf.push(0x80 | n as u8);
        buf.extend_from_slice(&bytes[first..]);
    }
}

/// Reads an A-XDR length octet, returning the length and octets consumed.
pub(crate) fn read_length(bytes: &[u8]) -> Result<(usize, usize), ServiceError> {
    let first = *bytes.first().ok_or(ServiceError::Truncated)?;
    if first < 128 {
        Ok((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        let slice = bytes.get(1..1 + n).ok_or(ServiceError::Truncated)?;
        let mut len = 0usize;
        for &b in slice {
            len = (len << 8) | b as usize;
        }
        Ok((len, 1 + n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_id_and_priority_bits() {
        // invoke-id 1, confirmed, high priority → 0xC1 (as in IEC 62056-5-3 Annex F).
        assert_eq!(invoke_id_and_priority(1, true, true), 0xC1);
        assert_eq!(invoke_id_and_priority(0, false, false), 0x00);
    }

    #[test]
    fn attribute_descriptor_round_trips() {
        let d = AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2);
        let mut buf = Vec::new();
        d.encode(&mut buf);
        // class-id 0001, instance 0000800000FF, attr 02.
        assert_eq!(buf, vec![0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02]);
        let (decoded, n) = AttributeDescriptor::decode(&buf).unwrap();
        assert_eq!(n, 9);
        assert_eq!(decoded, d);
    }

    #[test]
    fn method_descriptor_round_trips() {
        let d = MethodDescriptor::new(70, ObisCode::new(0, 0, 96, 3, 10, 255), 1);
        let mut buf = Vec::new();
        d.encode(&mut buf);
        let (decoded, n) = MethodDescriptor::decode(&buf).unwrap();
        assert_eq!(n, 9);
        assert_eq!(decoded, d);
    }

    #[test]
    fn data_block_sa_round_trips() {
        let block = DataBlockSa { last_block: true, block_number: 3, raw_data: vec![0x0A; 17] };
        let mut buf = Vec::new();
        block.encode(&mut buf);
        // 01 00000003 11 <17 octets> — as in IEC 62056-5-3 Annex F.8.
        assert_eq!(buf[..6], [0x01, 0x00, 0x00, 0x00, 0x03, 0x11]);
        let (decoded, n) = DataBlockSa::decode(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(decoded, block);
    }
}
