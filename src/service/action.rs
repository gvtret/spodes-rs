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
use super::{tag, MethodDescriptor, ServiceError};

mod request_type {
    pub const NORMAL: u8 = 1;
}

mod response_type {
    pub const NORMAL: u8 = 1;
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
}
