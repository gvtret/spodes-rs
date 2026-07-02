//! The xDLMS SET service (IEC 62056-5-3, 6.10): write one or more COSEM object
//! attributes.
//!
//! Request bytes for SET-REQUEST-NORMAL, from IEC 62056-5-3 Annex F.1:
//!
//! ```text
//! C1 01 C1 0001 0000800000FF 02 00 0932 <50 octets>
//! ^tag                            ^^ access-selection   ^^ value (A-XDR)
//!    ^^ normal   ^^ iid  ^^^^^^^^ attribute descriptor
//! ```
//!
//! Block transfer (SET-REQUEST-WITH-FIRST-DATABLOCK and friends) is not modelled
//! yet.

use crate::types::CosemDataType;

use super::get::AccessSelection;
use super::{tag, AttributeDescriptor, DataBlockSa, ServiceError};

mod request_type {
    pub const NORMAL: u8 = 1;
    pub const WITH_FIRST_DATABLOCK: u8 = 2;
    pub const WITH_DATABLOCK: u8 = 3;
}

mod response_type {
    pub const NORMAL: u8 = 1;
    pub const DATABLOCK: u8 = 2;
    pub const LAST_DATABLOCK: u8 = 3;
}

/// A SET-Request APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum SetRequest {
    /// SET-REQUEST-NORMAL: write a single attribute.
    Normal {
        invoke_id_and_priority: u8,
        attribute: AttributeDescriptor,
        access_selection: Option<AccessSelection>,
        value: CosemDataType,
    },
    /// SET-REQUEST-WITH-FIRST-DATABLOCK: the attribute reference and the first
    /// block of the value.
    WithFirstDatablock {
        invoke_id_and_priority: u8,
        attribute: AttributeDescriptor,
        access_selection: Option<AccessSelection>,
        datablock: DataBlockSa,
    },
    /// SET-REQUEST-WITH-DATABLOCK: a subsequent block of the value.
    WithDatablock {
        invoke_id_and_priority: u8,
        datablock: DataBlockSa,
    },
}

impl SetRequest {
    /// Encodes the request APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::SET_REQUEST];
        match self {
            SetRequest::Normal { invoke_id_and_priority, attribute, access_selection, value } => {
                buf.push(request_type::NORMAL);
                buf.push(*invoke_id_and_priority);
                attribute.encode(&mut buf);
                AccessSelection::encode_into(access_selection, &mut buf)?;
                value.serialize_ber(&mut buf)?;
            }
            SetRequest::WithFirstDatablock { invoke_id_and_priority, attribute, access_selection, datablock } => {
                buf.push(request_type::WITH_FIRST_DATABLOCK);
                buf.push(*invoke_id_and_priority);
                attribute.encode(&mut buf);
                AccessSelection::encode_into(access_selection, &mut buf)?;
                datablock.encode(&mut buf);
            }
            SetRequest::WithDatablock { invoke_id_and_priority, datablock } => {
                buf.push(request_type::WITH_DATABLOCK);
                buf.push(*invoke_id_and_priority);
                datablock.encode(&mut buf);
            }
        }
        Ok(buf)
    }

    /// Decodes a request APDU.
    pub fn decode(bytes: &[u8]) -> Result<SetRequest, ServiceError> {
        if bytes.len() < 3 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::SET_REQUEST {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            request_type::NORMAL => {
                let (attribute, n) = AttributeDescriptor::decode(&bytes[3..])?;
                let (access_selection, m) = AccessSelection::decode_from(&bytes[3 + n..])?;
                let (value, _) = CosemDataType::deserialize_ber(&bytes[3 + n + m..])?;
                Ok(SetRequest::Normal { invoke_id_and_priority, attribute, access_selection, value })
            }
            request_type::WITH_FIRST_DATABLOCK => {
                let (attribute, n) = AttributeDescriptor::decode(&bytes[3..])?;
                let (access_selection, m) = AccessSelection::decode_from(&bytes[3 + n..])?;
                let (datablock, _) = DataBlockSa::decode(&bytes[3 + n + m..])?;
                Ok(SetRequest::WithFirstDatablock { invoke_id_and_priority, attribute, access_selection, datablock })
            }
            request_type::WITH_DATABLOCK => {
                let (datablock, _) = DataBlockSa::decode(&bytes[3..])?;
                Ok(SetRequest::WithDatablock { invoke_id_and_priority, datablock })
            }
            other => Err(ServiceError::UnexpectedType(other)),
        }
    }
}

/// A SET-Response APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse {
    /// SET-RESPONSE-NORMAL: carries a single data-access-result code.
    Normal {
        invoke_id_and_priority: u8,
        result: u8,
    },
    /// SET-RESPONSE-DATABLOCK: acknowledges reception of an intermediate block.
    Datablock {
        invoke_id_and_priority: u8,
        block_number: u32,
    },
    /// SET-RESPONSE-LAST-DATABLOCK: acknowledges the last block and delivers the
    /// result.
    LastDatablock {
        invoke_id_and_priority: u8,
        result: u8,
        block_number: u32,
    },
}

impl SetResponse {
    /// Encodes the response APDU.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SetResponse::Normal { invoke_id_and_priority, result } => {
                vec![tag::SET_RESPONSE, response_type::NORMAL, *invoke_id_and_priority, *result]
            }
            SetResponse::Datablock { invoke_id_and_priority, block_number } => {
                let mut buf = vec![tag::SET_RESPONSE, response_type::DATABLOCK, *invoke_id_and_priority];
                buf.extend_from_slice(&block_number.to_be_bytes());
                buf
            }
            SetResponse::LastDatablock { invoke_id_and_priority, result, block_number } => {
                let mut buf = vec![tag::SET_RESPONSE, response_type::LAST_DATABLOCK, *invoke_id_and_priority, *result];
                buf.extend_from_slice(&block_number.to_be_bytes());
                buf
            }
        }
    }

    /// Decodes a response APDU.
    pub fn decode(bytes: &[u8]) -> Result<SetResponse, ServiceError> {
        if bytes.len() < 4 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::SET_RESPONSE {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            response_type::NORMAL => Ok(SetResponse::Normal { invoke_id_and_priority, result: bytes[3] }),
            response_type::DATABLOCK => {
                let b = bytes.get(3..7).ok_or(ServiceError::Truncated)?;
                Ok(SetResponse::Datablock {
                    invoke_id_and_priority,
                    block_number: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                })
            }
            response_type::LAST_DATABLOCK => {
                let result = bytes[3];
                let b = bytes.get(4..8).ok_or(ServiceError::Truncated)?;
                Ok(SetResponse::LastDatablock {
                    invoke_id_and_priority,
                    result,
                    block_number: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                })
            }
            other => Err(ServiceError::UnexpectedType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obis::ObisCode;
    use crate::service::data_access_result;

    #[test]
    fn set_request_normal_matches_reference_bytes() {
        // IEC 62056-5-3 Annex F.1 prefix: C1 01 C1 0001 0000800000FF 02 00 09 02 AABB.
        let req = SetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
            value: CosemDataType::OctetString(vec![0xAA, 0xBB]),
        };
        assert_eq!(
            req.encode().unwrap(),
            vec![0xC1, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02, 0x00, 0x09, 0x02, 0xAA, 0xBB]
        );
        assert_eq!(SetRequest::decode(&req.encode().unwrap()).unwrap(), req);
    }

    #[test]
    fn set_response_normal_matches_reference_bytes() {
        // IEC 62056-5-3 Annex F: C5 01 C1 00 (Success).
        let resp = SetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: data_access_result::SUCCESS,
        };
        assert_eq!(resp.encode(), vec![0xC5, 0x01, 0xC1, 0x00]);
        assert_eq!(SetResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn set_request_with_datablock_matches_reference_bytes() {
        // IEC 62056-5-3 Annex F.8: C1 03 C1 01 00000003 11 <17 octets>.
        let raw = vec![
            0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x0A, 0x03, 0x30, 0x30, 0x30,
        ];
        let req = SetRequest::WithDatablock {
            invoke_id_and_priority: 0xC1,
            datablock: DataBlockSa { last_block: true, block_number: 3, raw_data: raw },
        };
        let bytes = req.encode().unwrap();
        assert_eq!(&bytes[..6], &[0xC1, 0x03, 0xC1, 0x01, 0x00, 0x00]);
        assert_eq!(SetRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn set_response_datablock_variants_round_trip() {
        let ack = SetResponse::Datablock { invoke_id_and_priority: 0xC1, block_number: 1 };
        assert_eq!(ack.encode(), vec![0xC5, 0x02, 0xC1, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(SetResponse::decode(&ack.encode()).unwrap(), ack);

        let last = SetResponse::LastDatablock { invoke_id_and_priority: 0xC1, result: 0, block_number: 3 };
        assert_eq!(last.encode(), vec![0xC5, 0x03, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x03]);
        assert_eq!(SetResponse::decode(&last.encode()).unwrap(), last);
    }
}
