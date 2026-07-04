//! The xDLMS GET service (IEC 62056-5-3, 6.9): read one or more COSEM object
//! attributes.
//!
//! Request bytes for GET-REQUEST-NORMAL, from IEC 62056-5-3 Annex F.1:
//!
//! ```text
//! C0 01 C1 0001 0000800000FF 02 00
//! ^tag                            ^^ access-selection (0 = none)
//!    ^^ normal   ^^ invoke-id-and-priority
//!         ^^^^^^^^^^^^^^^^^^^^^^^ attribute descriptor (class-id, obis, attr-id)
//! ```

use crate::types::CosemDataType;

use super::{tag, AttributeDescriptor, ServiceError};

/// Request-type octets of the GET service.
mod request_type {
    pub const NORMAL: u8 = 1;
    pub const NEXT: u8 = 2;
    pub const WITH_LIST: u8 = 3;
}

/// Response-type octets of the GET service.
mod response_type {
    pub const NORMAL: u8 = 1;
    pub const WITH_DATABLOCK: u8 = 2;
    pub const WITH_LIST: u8 = 3;
}

/// Optional selective-access parameters attached to an attribute descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessSelection {
    /// The access selector (which selective-access method to apply).
    pub selector: u8,
    /// The selective-access parameters for the chosen selector.
    pub parameters: CosemDataType,
}

impl AccessSelection {
    /// Encodes an optional selective-access descriptor (0x00 = absent).
    pub fn encode_into(this: &Option<AccessSelection>, buf: &mut Vec<u8>) -> Result<(), ServiceError> {
        match this {
            None => buf.push(0x00),
            Some(sel) => {
                buf.push(0x01);
                buf.push(sel.selector);
                sel.parameters.serialize_ber(buf)?;
            }
        }
        Ok(())
    }

    /// Decodes an optional selective-access descriptor, returning it and the
    /// number of octets consumed.
    pub fn decode_from(bytes: &[u8]) -> Result<(Option<AccessSelection>, usize), ServiceError> {
        match bytes.first() {
            Some(0x00) => Ok((None, 1)),
            Some(0x01) => {
                let selector = *bytes.get(1).ok_or(ServiceError::Truncated)?;
                let (parameters, rest) = CosemDataType::deserialize_ber(&bytes[2..])?;
                let consumed = 2 + (bytes.len() - 2 - rest.len());
                Ok((Some(AccessSelection { selector, parameters }), consumed))
            }
            Some(&other) => Err(ServiceError::UnexpectedType(other)),
            None => Err(ServiceError::Truncated),
        }
    }
}

/// A GET-Request APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum GetRequest {
    /// GET-REQUEST-NORMAL: read a single attribute.
    Normal {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The attribute to read.
        attribute: AttributeDescriptor,
        /// Optional selective access applied to the attribute.
        access_selection: Option<AccessSelection>,
    },
    /// GET-REQUEST-NEXT: request the next data block during block transfer.
    Next {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The number of the block being acknowledged/requested.
        block_number: u32,
    },
    /// GET-REQUEST-WITH-LIST: read several attributes in one request.
    WithList {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// Each entry is an attribute descriptor with optional selective access.
        attributes: Vec<(AttributeDescriptor, Option<AccessSelection>)>,
    },
}

impl GetRequest {
    /// Encodes the request APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::GET_REQUEST];
        match self {
            GetRequest::Normal { invoke_id_and_priority, attribute, access_selection } => {
                buf.push(request_type::NORMAL);
                buf.push(*invoke_id_and_priority);
                attribute.encode(&mut buf);
                AccessSelection::encode_into(access_selection, &mut buf)?;
            }
            GetRequest::Next { invoke_id_and_priority, block_number } => {
                buf.push(request_type::NEXT);
                buf.push(*invoke_id_and_priority);
                buf.extend_from_slice(&block_number.to_be_bytes());
            }
            GetRequest::WithList { invoke_id_and_priority, attributes } => {
                buf.push(request_type::WITH_LIST);
                buf.push(*invoke_id_and_priority);
                push_length(attributes.len(), &mut buf);
                for (attribute, access_selection) in attributes {
                    attribute.encode(&mut buf);
                    AccessSelection::encode_into(access_selection, &mut buf)?;
                }
            }
        }
        Ok(buf)
    }

    /// Decodes a request APDU.
    pub fn decode(bytes: &[u8]) -> Result<GetRequest, ServiceError> {
        if bytes.len() < 3 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::GET_REQUEST {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            request_type::NORMAL => {
                let (attribute, n) = AttributeDescriptor::decode(&bytes[3..])?;
                let (access_selection, _) = AccessSelection::decode_from(&bytes[3 + n..])?;
                Ok(GetRequest::Normal { invoke_id_and_priority, attribute, access_selection })
            }
            request_type::NEXT => {
                let b = bytes.get(3..7).ok_or(ServiceError::Truncated)?;
                let block_number = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                Ok(GetRequest::Next { invoke_id_and_priority, block_number })
            }
            request_type::WITH_LIST => {
                let (count, header) = read_length(&bytes[3..])?;
                let mut pos = 3 + header;
                let mut attributes = Vec::with_capacity(count);
                for _ in 0..count {
                    let (attribute, n) = AttributeDescriptor::decode(&bytes[pos..])?;
                    pos += n;
                    let (access_selection, m) = AccessSelection::decode_from(&bytes[pos..])?;
                    pos += m;
                    attributes.push((attribute, access_selection));
                }
                Ok(GetRequest::WithList { invoke_id_and_priority, attributes })
            }
            other => Err(ServiceError::UnexpectedType(other)),
        }
    }
}

/// The result carried by a GET-RESPONSE-NORMAL: either the attribute value or a
/// data-access-result code.
#[derive(Debug, Clone, PartialEq)]
pub enum GetDataResult {
    /// The attribute value was read successfully.
    Data(CosemDataType),
    /// The read failed with this data-access-result code.
    AccessResult(u8),
}

/// A GET-Response APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum GetResponse {
    /// GET-RESPONSE-NORMAL: the full result fits in a single APDU.
    Normal {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The result (value or data-access-result).
        result: GetDataResult,
    },
    /// GET-RESPONSE-WITH-DATABLOCK: one block of a longer result.
    WithDataBlock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// Whether this is the last block of the result.
        last_block: bool,
        /// The number of this block.
        block_number: u32,
        /// Raw data of this block, or a data-access-result code on failure.
        raw_data: Result<Vec<u8>, u8>,
    },
    /// GET-RESPONSE-WITH-LIST: one result per requested attribute.
    WithList {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// One result per attribute of the request, in order.
        results: Vec<GetDataResult>,
    },
}

impl GetResponse {
    /// Encodes the response APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::GET_RESPONSE];
        match self {
            GetResponse::Normal { invoke_id_and_priority, result } => {
                buf.push(response_type::NORMAL);
                buf.push(*invoke_id_and_priority);
                match result {
                    GetDataResult::Data(data) => {
                        buf.push(0x00);
                        data.serialize_ber(&mut buf)?;
                    }
                    GetDataResult::AccessResult(code) => {
                        buf.push(0x01);
                        buf.push(*code);
                    }
                }
            }
            GetResponse::WithDataBlock { invoke_id_and_priority, last_block, block_number, raw_data } => {
                buf.push(response_type::WITH_DATABLOCK);
                buf.push(*invoke_id_and_priority);
                buf.push(*last_block as u8);
                buf.extend_from_slice(&block_number.to_be_bytes());
                match raw_data {
                    Ok(data) => {
                        buf.push(0x00);
                        push_length(data.len(), &mut buf);
                        buf.extend_from_slice(data);
                    }
                    Err(code) => {
                        buf.push(0x01);
                        buf.push(*code);
                    }
                }
            }
            GetResponse::WithList { invoke_id_and_priority, results } => {
                buf.push(response_type::WITH_LIST);
                buf.push(*invoke_id_and_priority);
                push_length(results.len(), &mut buf);
                for result in results {
                    match result {
                        GetDataResult::Data(data) => {
                            buf.push(0x00);
                            data.serialize_ber(&mut buf)?;
                        }
                        GetDataResult::AccessResult(code) => {
                            buf.push(0x01);
                            buf.push(*code);
                        }
                    }
                }
            }
        }
        Ok(buf)
    }

    /// Decodes a response APDU.
    pub fn decode(bytes: &[u8]) -> Result<GetResponse, ServiceError> {
        if bytes.len() < 3 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::GET_RESPONSE {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            response_type::NORMAL => {
                let choice = *bytes.get(3).ok_or(ServiceError::Truncated)?;
                let result = match choice {
                    0x00 => {
                        let (data, _) = CosemDataType::deserialize_ber(&bytes[4..])?;
                        GetDataResult::Data(data)
                    }
                    0x01 => GetDataResult::AccessResult(*bytes.get(4).ok_or(ServiceError::Truncated)?),
                    other => return Err(ServiceError::UnexpectedType(other)),
                };
                Ok(GetResponse::Normal { invoke_id_and_priority, result })
            }
            response_type::WITH_DATABLOCK => {
                let last_block = *bytes.get(3).ok_or(ServiceError::Truncated)? != 0;
                let b = bytes.get(4..8).ok_or(ServiceError::Truncated)?;
                let block_number = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let choice = *bytes.get(8).ok_or(ServiceError::Truncated)?;
                let raw_data = match choice {
                    0x00 => {
                        let (len, header) = read_length(&bytes[9..])?;
                        let start = 9 + header;
                        let slice = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?;
                        Ok(slice.to_vec())
                    }
                    0x01 => Err(*bytes.get(9).ok_or(ServiceError::Truncated)?),
                    other => return Err(ServiceError::UnexpectedType(other)),
                };
                Ok(GetResponse::WithDataBlock { invoke_id_and_priority, last_block, block_number, raw_data })
            }
            response_type::WITH_LIST => {
                let (count, header) = read_length(&bytes[3..])?;
                let mut pos = 3 + header;
                let mut results = Vec::with_capacity(count);
                for _ in 0..count {
                    let choice = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
                    pos += 1;
                    match choice {
                        0x00 => {
                            let (data, rest) = CosemDataType::deserialize_ber(&bytes[pos..])?;
                            pos = bytes.len() - rest.len();
                            results.push(GetDataResult::Data(data));
                        }
                        0x01 => {
                            results.push(GetDataResult::AccessResult(*bytes.get(pos).ok_or(ServiceError::Truncated)?));
                            pos += 1;
                        }
                        other => return Err(ServiceError::UnexpectedType(other)),
                    }
                }
                Ok(GetResponse::WithList { invoke_id_and_priority, results })
            }
            other => Err(ServiceError::UnexpectedType(other)),
        }
    }
}

/// Writes an A-XDR length octet (short or long form).
fn push_length(length: usize, buf: &mut Vec<u8>) {
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

/// Reads an A-XDR length octet, returning the length and the octets consumed.
fn read_length(bytes: &[u8]) -> Result<(usize, usize), ServiceError> {
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
    use crate::obis::ObisCode;
    use crate::service::invoke_id_and_priority;

    #[test]
    fn get_request_normal_matches_reference_bytes() {
        // IEC 62056-5-3 Annex F.1: C0 01 C1 0001 0000800000FF 02 00.
        let req = GetRequest::Normal {
            invoke_id_and_priority: invoke_id_and_priority(1, true, true),
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
        };
        assert_eq!(
            req.encode().unwrap(),
            vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02, 0x00]
        );
        assert_eq!(GetRequest::decode(&req.encode().unwrap()).unwrap(), req);
    }

    #[test]
    fn get_request_next_round_trips() {
        let req = GetRequest::Next { invoke_id_and_priority: 0xC1, block_number: 1 };
        let bytes = req.encode().unwrap();
        assert_eq!(bytes, vec![0xC0, 0x02, 0xC1, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(GetRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn get_response_normal_with_data_round_trips() {
        let resp = GetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
        };
        let bytes = resp.encode().unwrap();
        // C4 01 C1 00 <12 12 34> ; long-unsigned tag 0x12.
        assert_eq!(bytes, vec![0xC4, 0x01, 0xC1, 0x00, 0x12, 0x12, 0x34]);
        assert_eq!(GetResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn get_response_normal_with_access_result_round_trips() {
        let resp = GetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: GetDataResult::AccessResult(super::super::data_access_result::OBJECT_UNDEFINED),
        };
        let bytes = resp.encode().unwrap();
        assert_eq!(bytes, vec![0xC4, 0x01, 0xC1, 0x01, 0x04]);
        assert_eq!(GetResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn get_request_with_list_round_trips() {
        let req = GetRequest::WithList {
            invoke_id_and_priority: 0xC1,
            attributes: vec![
                (AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2), None),
                (AttributeDescriptor::new(8, ObisCode::new(0, 0, 1, 0, 0, 0xFF), 2), None),
            ],
        };
        let bytes = req.encode().unwrap();
        // C0 03 C1 02 <attr1 9> 00 <attr2 9> 00.
        assert_eq!(bytes[..4], [0xC0, 0x03, 0xC1, 0x02]);
        assert_eq!(GetRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn get_response_with_list_round_trips() {
        let resp = GetResponse::WithList {
            invoke_id_and_priority: 0xC1,
            results: vec![
                GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
                GetDataResult::AccessResult(super::super::data_access_result::OBJECT_UNDEFINED),
            ],
        };
        let bytes = resp.encode().unwrap();
        // C4 03 C1 02 00 <12 12 34> 01 04.
        assert_eq!(bytes, vec![0xC4, 0x03, 0xC1, 0x02, 0x00, 0x12, 0x12, 0x34, 0x01, 0x04]);
        assert_eq!(GetResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn get_response_with_datablock_round_trips() {
        let resp = GetResponse::WithDataBlock {
            invoke_id_and_priority: 0xC1,
            last_block: false,
            block_number: 1,
            raw_data: Ok(vec![0x02, 0x00, 0x09]),
        };
        let bytes = resp.encode().unwrap();
        // C4 02 C1 00 00000001 00 03 020009.
        assert_eq!(bytes, vec![0xC4, 0x02, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x00, 0x09]);
        assert_eq!(GetResponse::decode(&bytes).unwrap(), resp);
    }
}
