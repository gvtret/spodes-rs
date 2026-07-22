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
    /// `data-notification` (tag 15).
    pub const DATA_NOTIFICATION: u8 = 0x0F;
    /// `get-request` (tag 192).
    pub const GET_REQUEST: u8 = 0xC0;
    /// `set-request` (tag 193).
    pub const SET_REQUEST: u8 = 0xC1;
    /// `event-notification-request` (tag 194).
    pub const EVENT_NOTIFICATION_REQUEST: u8 = 0xC2;
    /// `action-request` (tag 195).
    pub const ACTION_REQUEST: u8 = 0xC3;
    /// `get-response` (tag 196).
    pub const GET_RESPONSE: u8 = 0xC4;
    /// `set-response` (tag 197).
    pub const SET_RESPONSE: u8 = 0xC5;
    /// `action-response` (tag 199).
    pub const ACTION_RESPONSE: u8 = 0xC7;
    /// `exception-response` (tag 216).
    pub const EXCEPTION_RESPONSE: u8 = 0xD8;
    /// `confirmed-service-error` (tag 14).
    pub const CONFIRMED_SERVICE_ERROR: u8 = 0x0E;
}

/// `Data-Access-Result` codes (IEC 62056-5-3). Returned by GET/SET and, for the
/// optional return parameters, by ACTION.
pub mod data_access_result {
    /// The access succeeded.
    pub const SUCCESS: u8 = 0;
    /// Hardware fault.
    pub const HARDWARE_FAULT: u8 = 1;
    /// Temporary failure.
    pub const TEMPORARY_FAILURE: u8 = 2;
    /// Read or write denied.
    pub const READ_WRITE_DENIED: u8 = 3;
    /// The object is not defined.
    pub const OBJECT_UNDEFINED: u8 = 4;
    /// The object class is inconsistent with the request.
    pub const OBJECT_CLASS_INCONSISTENT: u8 = 9;
    /// The object is unavailable.
    pub const OBJECT_UNAVAILABLE: u8 = 11;
    /// The supplied type does not match the attribute.
    pub const TYPE_UNMATCHED: u8 = 12;
    /// The scope of access was violated.
    pub const SCOPE_OF_ACCESS_VIOLATED: u8 = 13;
    /// The requested data block is unavailable.
    pub const DATA_BLOCK_UNAVAILABLE: u8 = 14;
    /// The long GET was aborted.
    pub const LONG_GET_ABORTED: u8 = 15;
    /// No long GET is in progress.
    pub const NO_LONG_GET_IN_PROGRESS: u8 = 16;
    /// The long SET was aborted.
    pub const LONG_SET_ABORTED: u8 = 17;
    /// No long SET is in progress.
    pub const NO_LONG_SET_IN_PROGRESS: u8 = 18;
    /// The data-block number is invalid.
    pub const DATA_BLOCK_NUMBER_INVALID: u8 = 19;
    /// Other reason.
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
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ServiceError {}

impl From<ServiceError> for std::io::Error {
    fn from(e: ServiceError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

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
    /// Interface class id of the referenced object.
    pub class_id: u16,
    /// Logical name (OBIS) of the object instance.
    pub instance_id: ObisCode,
    /// Attribute index within the object.
    pub attribute_id: i8,
}

impl AttributeDescriptor {
    /// Creates an attribute descriptor.
    pub fn new(class_id: u16, instance_id: ObisCode, attribute_id: i8) -> Self {
        AttributeDescriptor { class_id, instance_id, attribute_id }
    }

    /// Appends the 9-octet encoding to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.class_id.to_be_bytes());
        buf.extend_from_slice(&self.instance_id.to_bytes());
        buf.push(self.attribute_id as u8);
    }

    /// Decodes a descriptor, returning it and the 9 octets consumed.
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
    /// Interface class id of the referenced object.
    pub class_id: u16,
    /// Logical name (OBIS) of the object instance.
    pub instance_id: ObisCode,
    /// Method index within the object.
    pub method_id: i8,
}

impl MethodDescriptor {
    /// Creates a method descriptor.
    pub fn new(class_id: u16, instance_id: ObisCode, method_id: i8) -> Self {
        MethodDescriptor { class_id, instance_id, method_id }
    }

    /// Appends the 9-octet encoding to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.class_id.to_be_bytes());
        buf.extend_from_slice(&self.instance_id.to_bytes());
        buf.push(self.method_id as u8);
    }

    /// Decodes a descriptor, returning it and the 9 octets consumed.
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
    /// Whether this is the last block of the transfer.
    pub last_block: bool,
    /// The block number.
    pub block_number: u32,
    /// The raw block data.
    pub raw_data: Vec<u8>,
}

/// A raw APDU with an arbitrary tag and body.
///
/// This type allows sending and receiving APDUs without parsing their content,
/// which is useful for manufacturer-specific or extension APDUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawApdu {
    /// The APDU tag byte.
    pub tag: u8,
    /// The raw body bytes (after the length octet).
    pub body: Vec<u8>,
}

impl RawApdu {
    /// Creates a new raw APDU with the given tag and body.
    pub fn new(tag: u8, body: Vec<u8>) -> Self {
        RawApdu { tag, body }
    }

    /// Creates a raw APDU from a complete byte slice (tag + length + body).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.is_empty() {
            return Err(ServiceError::Truncated);
        }
        let tag = bytes[0];
        let (len, header) = read_length(&bytes[1..])?;
        let start = 1 + header;
        let body = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
        Ok(RawApdu { tag, body })
    }

    /// Encodes the APDU to bytes (tag + length + body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.body.len());
        buf.push(self.tag);
        push_length(self.body.len(), &mut buf);
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Returns the tag byte.
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Returns the body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the body as a mutable slice.
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    /// Consumes the APDU and returns the tag and body.
    pub fn into_parts(self) -> (u8, Vec<u8>) {
        (self.tag, self.body)
    }
}

impl DataBlockSa {
    /// Appends the block encoding to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(u8::from(self.last_block));
        buf.extend_from_slice(&self.block_number.to_be_bytes());
        push_length(self.raw_data.len(), buf);
        buf.extend_from_slice(&self.raw_data);
    }

    /// Decodes a block, returning it and the octets consumed.
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

    #[test]
    fn raw_apdu_encode_decode_round_trip() {
        let raw = RawApdu::new(0xC0, vec![0x01, 0x02, 0x03]);
        let encoded = raw.encode();
        let decoded = RawApdu::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.tag(), 0xC0);
        assert_eq!(decoded.body(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn raw_apdu_from_bytes_with_length() {
        // tag=0xC1, length=5, body=[0xAA; 5]
        let bytes = vec![0xC1, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        let raw = RawApdu::from_bytes(&bytes).unwrap();
        assert_eq!(raw.tag(), 0xC1);
        assert_eq!(raw.body(), &[0xAA; 5]);
    }

    #[test]
    fn raw_apdu_empty_body() {
        let raw = RawApdu::new(0xC2, vec![]);
        let encoded = raw.encode();
        assert_eq!(encoded, vec![0xC2, 0x00]);
        let decoded = RawApdu::from_bytes(&encoded).unwrap();
        assert!(decoded.body().is_empty());
    }

    #[test]
    fn raw_apdu_truncated_returns_error() {
        let bytes = vec![0xC0]; // tag only, no length
        assert!(RawApdu::from_bytes(&bytes).is_err());
    }

    #[test]
    fn raw_apdu_mutable_body() {
        let mut raw = RawApdu::new(0xC3, vec![0x01]);
        raw.body_mut().push(0x02);
        assert_eq!(raw.body(), &[0x01, 0x02]);
    }
}
