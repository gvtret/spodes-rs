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
use super::{push_length, read_length, tag, DataBlockSa, MethodDescriptor, ServiceError};

mod request_type {
    pub const NORMAL: u8 = 1;
    pub const NEXT_PBLOCK: u8 = 2;
    pub const WITH_LIST: u8 = 3;
    pub const WITH_FIRST_PBLOCK: u8 = 4;
    pub const WITH_PBLOCK: u8 = 6;
}

mod response_type {
    pub const NORMAL: u8 = 1;
    pub const WITH_PBLOCK: u8 = 2;
    pub const WITH_LIST: u8 = 3;
    pub const NEXT_PBLOCK: u8 = 4;
}

/// An ACTION-Request APDU.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest {
    /// ACTION-REQUEST-NORMAL: invoke a single method.
    Normal {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The method to invoke.
        method: MethodDescriptor,
        /// Method invocation parameters, if any.
        parameters: Option<CosemDataType>,
    },
    /// ACTION-REQUEST-NEXT-PBLOCK: acknowledge a response block and ask for the next.
    NextPblock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The number of the response block being acknowledged.
        block_number: u32,
    },
    /// ACTION-REQUEST-WITH-FIRST-PBLOCK: method reference and the first block of
    /// the invocation parameters.
    WithFirstPblock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The method to invoke.
        method: MethodDescriptor,
        /// The first block of the invocation parameters.
        datablock: DataBlockSa,
    },
    /// ACTION-REQUEST-WITH-PBLOCK: a subsequent block of the invocation parameters.
    WithPblock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The next block of the invocation parameters.
        datablock: DataBlockSa,
    },
    /// ACTION-REQUEST-WITH-LIST: invoke several methods in one request. The
    /// invocation-parameters list holds one `Data` per method (`Null` when a
    /// method takes no parameters).
    WithList {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The methods to invoke, in order.
        methods: Vec<MethodDescriptor>,
        /// The invocation parameters, one per method in order.
        parameters: Vec<CosemDataType>,
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
            ActionRequest::WithList { invoke_id_and_priority, methods, parameters } => {
                buf.push(request_type::WITH_LIST);
                buf.push(*invoke_id_and_priority);
                push_length(methods.len(), &mut buf);
                for method in methods {
                    method.encode(&mut buf);
                }
                push_length(parameters.len(), &mut buf);
                for data in parameters {
                    data.serialize_ber(&mut buf)?;
                }
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
            request_type::WITH_LIST => {
                let (count, header) = read_length(&bytes[3..])?;
                let mut pos = 3 + header;
                let mut methods = Vec::with_capacity(count);
                for _ in 0..count {
                    let (method, n) = MethodDescriptor::decode(&bytes[pos..])?;
                    pos += n;
                    methods.push(method);
                }
                let (pcount, pheader) = read_length(&bytes[pos..])?;
                pos += pheader;
                let mut parameters = Vec::with_capacity(pcount);
                for _ in 0..pcount {
                    let (data, rest) = CosemDataType::deserialize_ber(&bytes[pos..])?;
                    pos = bytes.len() - rest.len();
                    parameters.push(data);
                }
                Ok(ActionRequest::WithList { invoke_id_and_priority, methods, parameters })
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
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The action-result code.
        result: u8,
        /// The method's return data, if any.
        return_parameters: Option<GetDataResult>,
    },
    /// ACTION-RESPONSE-WITH-PBLOCK: one block of the return parameters.
    WithPblock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// One block of the return parameters.
        datablock: DataBlockSa,
    },
    /// ACTION-RESPONSE-NEXT-PBLOCK: acknowledge a request block and ask for the next.
    NextPblock {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// The number of the request block being acknowledged.
        block_number: u32,
    },
    /// ACTION-RESPONSE-WITH-LIST: one action-result (plus optional return data)
    /// per invoked method.
    WithList {
        /// The invoke-id and priority byte.
        invoke_id_and_priority: u8,
        /// One (action-result, optional return data) pair per method, in order.
        results: Vec<(u8, Option<GetDataResult>)>,
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
            ActionResponse::WithList { invoke_id_and_priority, results } => {
                buf.push(response_type::WITH_LIST);
                buf.push(*invoke_id_and_priority);
                push_length(results.len(), &mut buf);
                for (result, return_parameters) in results {
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
            response_type::WITH_LIST => {
                let (count, header) = read_length(&bytes[3..])?;
                let mut pos = 3 + header;
                let mut results = Vec::with_capacity(count);
                for _ in 0..count {
                    let result = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
                    pos += 1;
                    let flag = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
                    pos += 1;
                    let return_parameters = match flag {
                        0x00 => None,
                        0x01 => {
                            let choice = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
                            pos += 1;
                            match choice {
                                0x00 => {
                                    let (data, rest) = CosemDataType::deserialize_ber(&bytes[pos..])?;
                                    pos = bytes.len() - rest.len();
                                    Some(GetDataResult::Data(data))
                                }
                                0x01 => {
                                    let code = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
                                    pos += 1;
                                    Some(GetDataResult::AccessResult(code))
                                }
                                other => return Err(ServiceError::UnexpectedType(other)),
                            }
                        }
                        other => return Err(ServiceError::UnexpectedType(other)),
                    };
                    results.push((result, return_parameters));
                }
                Ok(ActionResponse::WithList { invoke_id_and_priority, results })
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
        let req = ActionRequest::Normal { invoke_id_and_priority: 0xC1, method: method(), parameters: None };
        let bytes = req.encode().unwrap();
        // C3 01 C1 0046 0000600310FF 01 00.
        assert_eq!(bytes, vec![0xC3, 0x01, 0xC1, 0x00, 0x46, 0x00, 0x00, 0x60, 0x03, 0x0A, 0xFF, 0x01, 0x00]);
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
    fn action_request_with_list_round_trips() {
        let req = ActionRequest::WithList {
            invoke_id_and_priority: 0xC1,
            methods: vec![method(), MethodDescriptor::new(70, ObisCode::new(0, 0, 96, 3, 10, 255), 2)],
            parameters: vec![CosemDataType::Integer(0), CosemDataType::Null],
        };
        let bytes = req.encode().unwrap();
        // C3 03 C1 02 <method1> <method2> 02 <0F 00> <00>.
        assert_eq!(bytes[..4], [0xC3, 0x03, 0xC1, 0x02]);
        assert_eq!(ActionRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn action_response_with_list_round_trips() {
        let resp = ActionResponse::WithList {
            invoke_id_and_priority: 0xC1,
            results: vec![
                (data_access_result::SUCCESS, None),
                (data_access_result::SUCCESS, Some(GetDataResult::Data(CosemDataType::Unsigned(7)))),
            ],
        };
        let bytes = resp.encode().unwrap();
        // C7 03 C1 02 00 00 00 01 00 <11 07>.
        assert_eq!(bytes, vec![0xC7, 0x03, 0xC1, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x07]);
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
