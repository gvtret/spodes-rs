//! The xDLMS ACTION service (IEC 62056-5-3, 6.11): invoke a COSEM object method.
//!
//! Request bytes for ACTION-REQUEST-NORMAL:
//!
//! ```text
//! C3 01 C1 0040 0000280000FF 01 01 <method params, A-XDR>
//! ^tag                            ^^ params present (0 = absent)
//!    ^^ normal  ^^ iid   ^^^^^^^^ method descriptor
//! ```
//!
//! The response carries the action-result code and, optionally, the method
//! return value as a Get-Data-Result. Block transfer is not modelled yet.

use crate::types::CosemDataType;

use super::get::GetDataResult;
use super::{tag, DataBlockSa, MethodDescriptor, ServiceError};

mod request_type {
    pub const NORMAL: u8 = 1;
    pub const NEXT_PBLOCK: u8 = 2;
    pub const WITH_FIRST_PBLOCK: u8 = 4;
    pub const WITH_PBLOCK: u8 = 6;
}

mod response_type {
    pub const NORMAL: u8 = 1;
    pub const WITH_PBLOCK: u8 = 2;
    pub const NEXT_PBLOCK: u8 = 4;
}

/// An ACTION-Request APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest {
    /// ACTION-REQUEST-NORMAL: invoke a single method.
    Normal {
        invoke_id_and_priority: u8,
        method: MethodDescriptor,
        /// Method invocation parameters, if any.
        parameters: Option<CosemDataType>,
    },
    /// ACTION-REQUEST-NEXT-PBLOCK: acknowledge a response block and ask for the next.
    NextPblock {
        invoke_id_and_priority: u8,
        block_number: u32,
    },
    /// ACTION-REQUEST-WITH-FIRST-PBLOCK: method reference and the first block of
    /// the invocation parameters.
    WithFirstPblock {
        invoke_id_and_priority: u8,
        method: MethodDescriptor,
        datablock: DataBlockSa,
    },
    /// ACTION-REQUEST-WITH-PBLOCK: a subsequent block of the invocation parameters.
    WithPblock {
        invoke_id_and_priority: u8,
        datablock: DataBlockSa,
    },
}

impl ActionRequest {
    /// Encodes the request APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::ACTION_REQUEST];
        match self {
            ActionRequest::Normal { invoke_id_and_priority, method, parameters } => {
                buf.push(request_type::NORMAL);
                buf.push(*invoke_id_and_priority);
                method.encode(&mut buf);
                match parameters {
                    None => buf.push(0x00),
                    Some(data) => {
                        buf.push(0x01);
                        data.serialize_ber(&mut buf)?;
                    }
                }
            }
            ActionRequest::NextPblock { invoke_id_and_priority, block_number } => {
                buf.push(request_type::NEXT_PBLOCK);
                buf.push(*invoke_id_and_priority);
                buf.extend_from_slice(&block_number.to_be_bytes());
            }
            ActionRequest::WithFirstPblock { invoke_id_and_priority, method, datablock } => {
                buf.push(request_type::WITH_FIRST_PBLOCK);
                buf.push(*invoke_id_and_priority);
                method.encode(&mut buf);
                datablock.encode(&mut buf);
            }
            ActionRequest::WithPblock { invoke_id_and_priority, datablock } => {
                buf.push(request_type::WITH_PBLOCK);
                buf.push(*invoke_id_and_priority);
                datablock.encode(&mut buf);
            }
        }
        Ok(buf)
    }

    /// Decodes a request APDU.
    pub fn decode(bytes: &[u8]) -> Result<ActionRequest, ServiceError> {
        if bytes.len() < 3 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::ACTION_REQUEST {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            request_type::NORMAL => {
                let (method, n) = MethodDescriptor::decode(&bytes[3..])?;
                let rest = &bytes[3 + n..];
                let parameters = match rest.first() {
                    Some(0x00) => None,
                    Some(0x01) => Some(CosemDataType::deserialize_ber(&rest[1..])?.0),
                    Some(&other) => return Err(ServiceError::UnexpectedType(other)),
                    None => return Err(ServiceError::Truncated),
                };
                Ok(ActionRequest::Normal { invoke_id_and_priority, method, parameters })
            }
            request_type::NEXT_PBLOCK => {
                let b = bytes.get(3..7).ok_or(ServiceError::Truncated)?;
                Ok(ActionRequest::NextPblock {
                    invoke_id_and_priority,
                    block_number: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                })
            }
            request_type::WITH_FIRST_PBLOCK => {
                let (method, n) = MethodDescriptor::decode(&bytes[3..])?;
                let (datablock, _) = DataBlockSa::decode(&bytes[3 + n..])?;
                Ok(ActionRequest::WithFirstPblock { invoke_id_and_priority, method, datablock })
            }
            request_type::WITH_PBLOCK => {
                let (datablock, _) = DataBlockSa::decode(&bytes[3..])?;
                Ok(ActionRequest::WithPblock { invoke_id_and_priority, datablock })
            }
            other => Err(ServiceError::UnexpectedType(other)),
        }
    }
}

/// An ACTION-Response APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionResponse {
    /// ACTION-RESPONSE-NORMAL: action-result plus optional return parameters.
    Normal {
        invoke_id_and_priority: u8,
        result: u8,
        return_parameters: Option<GetDataResult>,
    },
    /// ACTION-RESPONSE-WITH-PBLOCK: one block of the return parameters.
    WithPblock {
        invoke_id_and_priority: u8,
        datablock: DataBlockSa,
    },
    /// ACTION-RESPONSE-NEXT-PBLOCK: acknowledge a request block and ask for the next.
    NextPblock {
        invoke_id_and_priority: u8,
        block_number: u32,
    },
}

impl ActionResponse {
    /// Encodes the response APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::ACTION_RESPONSE];
        match self {
            ActionResponse::Normal { invoke_id_and_priority, result, return_parameters } => {
                buf.push(response_type::NORMAL);
                buf.push(*invoke_id_and_priority);
                buf.push(*result);
                match return_parameters {
                    None => buf.push(0x00),
                    Some(GetDataResult::Data(data)) => {
                        buf.push(0x01);
                        buf.push(0x00);
                        data.serialize_ber(&mut buf)?;
                    }
                    Some(GetDataResult::AccessResult(code)) => {
                        buf.push(0x01);
                        buf.push(0x01);
                        buf.push(*code);
                    }
                }
            }
            ActionResponse::WithPblock { invoke_id_and_priority, datablock } => {
                buf.push(response_type::WITH_PBLOCK);
                buf.push(*invoke_id_and_priority);
                datablock.encode(&mut buf);
            }
            ActionResponse::NextPblock { invoke_id_and_priority, block_number } => {
                buf.push(response_type::NEXT_PBLOCK);
                buf.push(*invoke_id_and_priority);
                buf.extend_from_slice(&block_number.to_be_bytes());
            }
        }
        Ok(buf)
    }

    /// Decodes a response APDU.
    pub fn decode(bytes: &[u8]) -> Result<ActionResponse, ServiceError> {
        if bytes.len() < 4 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != tag::ACTION_RESPONSE {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let invoke_id_and_priority = bytes[2];
        match bytes[1] {
            response_type::NORMAL => {
                let result = bytes[3];
                let rest = &bytes[4..];
                let return_parameters = match rest.first() {
                    Some(0x00) => None,
                    Some(0x01) => {
                        let choice = *rest.get(1).ok_or(ServiceError::Truncated)?;
                        match choice {
                            0x00 => Some(GetDataResult::Data(CosemDataType::deserialize_ber(&rest[2..])?.0)),
                            0x01 => Some(GetDataResult::AccessResult(*rest.get(2).ok_or(ServiceError::Truncated)?)),
                            other => return Err(ServiceError::UnexpectedType(other)),
                        }
                    }
                    Some(&other) => return Err(ServiceError::UnexpectedType(other)),
                    None => return Err(ServiceError::Truncated),
                };
                Ok(ActionResponse::Normal { invoke_id_and_priority, result, return_parameters })
            }
            response_type::WITH_PBLOCK => {
                let (datablock, _) = DataBlockSa::decode(&bytes[3..])?;
                Ok(ActionResponse::WithPblock { invoke_id_and_priority, datablock })
            }
            response_type::NEXT_PBLOCK => {
                let b = bytes.get(3..7).ok_or(ServiceError::Truncated)?;
                Ok(ActionResponse::NextPblock {
                    invoke_id_and_priority,
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

    fn method() -> MethodDescriptor {
        // Disconnect control (class 70) remote_disconnect (method 1).
        MethodDescriptor::new(70, ObisCode::new(0, 0, 96, 3, 10, 255), 1)
    }

    #[test]
    fn action_request_without_parameters_round_trips() {
        let req = ActionRequest::Normal {
            invoke_id_and_priority: 0xC1,
            method: method(),
            parameters: None,
        };
        let bytes = req.encode().unwrap();
        // C3 01 C1 0046 0000600310FF 01 00.
        assert_eq!(
            bytes,
            vec![0xC3, 0x01, 0xC1, 0x00, 0x46, 0x00, 0x00, 0x60, 0x03, 0x0A, 0xFF, 0x01, 0x00]
        );
        assert_eq!(ActionRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn action_request_with_parameters_round_trips() {
        let req = ActionRequest::Normal {
            invoke_id_and_priority: 0xC1,
            method: method(),
            parameters: Some(CosemDataType::Integer(0)),
        };
        let bytes = req.encode().unwrap();
        assert_eq!(ActionRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn action_response_success_no_return_round_trips() {
        let resp = ActionResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: data_access_result::SUCCESS,
            return_parameters: None,
        };
        let bytes = resp.encode().unwrap();
        assert_eq!(bytes, vec![0xC7, 0x01, 0xC1, 0x00, 0x00]);
        assert_eq!(ActionResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn action_response_with_return_data_round_trips() {
        let resp = ActionResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: data_access_result::SUCCESS,
            return_parameters: Some(GetDataResult::Data(CosemDataType::Unsigned(7))),
        };
        let bytes = resp.encode().unwrap();
        // C7 01 C1 00 01 00 <11 07>.
        assert_eq!(bytes, vec![0xC7, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x11, 0x07]);
        assert_eq!(ActionResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn action_request_block_variants_round_trip() {
        let next = ActionRequest::NextPblock { invoke_id_and_priority: 0xC1, block_number: 2 };
        assert_eq!(next.encode().unwrap(), vec![0xC3, 0x02, 0xC1, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(ActionRequest::decode(&next.encode().unwrap()).unwrap(), next);

        let first = ActionRequest::WithFirstPblock {
            invoke_id_and_priority: 0xC1,
            method: method(),
            datablock: DataBlockSa { last_block: false, block_number: 1, raw_data: vec![0xAA, 0xBB] },
        };
        assert_eq!(ActionRequest::decode(&first.encode().unwrap()).unwrap(), first);

        let more = ActionRequest::WithPblock {
            invoke_id_and_priority: 0xC1,
            datablock: DataBlockSa { last_block: true, block_number: 2, raw_data: vec![0xCC] },
        };
        assert_eq!(ActionRequest::decode(&more.encode().unwrap()).unwrap(), more);
    }

    #[test]
    fn action_response_block_variants_round_trip() {
        let block = ActionResponse::WithPblock {
            invoke_id_and_priority: 0xC1,
            datablock: DataBlockSa { last_block: false, block_number: 1, raw_data: vec![0x01, 0x02, 0x03] },
        };
        assert_eq!(ActionResponse::decode(&block.encode().unwrap()).unwrap(), block);

        let next = ActionResponse::NextPblock { invoke_id_and_priority: 0xC1, block_number: 1 };
        assert_eq!(next.encode().unwrap(), vec![0xC7, 0x04, 0xC1, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(ActionResponse::decode(&next.encode().unwrap()).unwrap(), next);
    }
}
