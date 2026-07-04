//! A server-side request dispatcher (IEC 62056-5-3 / IEC 62056-53 server CF).
//!
//! [`crate::server::RequestDispatcher`] holds a set of COSEM interface objects and turns an
//! incoming GET / SET / ACTION request APDU into the matching response APDU by
//! routing it to the addressed object: GET reads an attribute, SET writes one
//! (via [`crate::interface::InterfaceClass::set_attribute`]), ACTION invokes a method. Objects are
//! addressed by their (class-id, logical-name) pair; an unknown address yields a
//! `object-undefined` data-access-result rather than an error.
//!
//! Only the NORMAL and WITH-LIST variants are dispatched; block-transfer request
//! types produce an EXCEPTION-RESPONSE, since block reassembly is the caller's
//! responsibility.

use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::service::action::{ActionRequest, ActionResponse};
use crate::service::error::{service_error, state_error, ExceptionResponse};
use crate::service::get::{GetDataResult, GetRequest, GetResponse};
use crate::service::set::{SetRequest, SetResponse};
use crate::service::{data_access_result, tag, AttributeDescriptor, MethodDescriptor, ServiceError};

/// A collection of COSEM objects that answers GET/SET/ACTION requests.
#[derive(Default)]
pub struct RequestDispatcher {
    objects: Vec<Box<dyn InterfaceClass>>,
}

impl RequestDispatcher {
    /// Creates an empty dispatcher.
    pub fn new() -> Self {
        RequestDispatcher { objects: Vec::new() }
    }

    /// Registers an object.
    pub fn add(&mut self, object: Box<dyn InterfaceClass>) {
        self.objects.push(object);
    }

    /// Locates a registered object by class-id and logical name.
    fn find(&mut self, class_id: u16, instance: &ObisCode) -> Option<&mut Box<dyn InterfaceClass>> {
        self.objects
            .iter_mut()
            .find(|o| o.class_id() == class_id && o.logical_name() == instance)
    }

    /// Reads one attribute, returning its value or a data-access-result code.
    fn read_attribute(&mut self, d: &AttributeDescriptor) -> GetDataResult {
        let attr_id = d.attribute_id;
        match self.find(d.class_id, &d.instance_id) {
            None => GetDataResult::AccessResult(data_access_result::OBJECT_UNDEFINED),
            Some(obj) => match obj.attributes().into_iter().find(|(id, _)| *id as i8 == attr_id) {
                Some((_, value)) => GetDataResult::Data(value),
                None => GetDataResult::AccessResult(data_access_result::OBJECT_UNAVAILABLE),
            },
        }
    }

    /// Writes one attribute, returning a data-access-result code.
    fn write_attribute(&mut self, d: &AttributeDescriptor, value: crate::types::CosemDataType) -> u8 {
        match self.find(d.class_id, &d.instance_id) {
            None => data_access_result::OBJECT_UNDEFINED,
            Some(obj) => match obj.set_attribute(d.attribute_id as u8, value) {
                Ok(()) => data_access_result::SUCCESS,
                Err(_) => data_access_result::READ_WRITE_DENIED,
            },
        }
    }

    /// Invokes one method, returning the action-result and optional return data.
    fn invoke(&mut self, d: &MethodDescriptor, params: Option<crate::types::CosemDataType>) -> (u8, Option<GetDataResult>) {
        match self.find(d.class_id, &d.instance_id) {
            None => (data_access_result::OBJECT_UNDEFINED, None),
            Some(obj) => match obj.invoke_method(d.method_id as u8, params) {
                Ok(crate::types::CosemDataType::Null) => (data_access_result::SUCCESS, None),
                Ok(value) => (data_access_result::SUCCESS, Some(GetDataResult::Data(value))),
                Err(_) => (data_access_result::OTHER_REASON, None),
            },
        }
    }

    /// Dispatches one request APDU to the addressed object and returns the
    /// encoded response APDU. Malformed or unsupported requests yield an
    /// EXCEPTION-RESPONSE.
    pub fn dispatch(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match request.first() {
            Some(&tag::GET_REQUEST) => self.dispatch_get(request),
            Some(&tag::SET_REQUEST) => self.dispatch_set(request),
            Some(&tag::ACTION_REQUEST) => self.dispatch_action(request),
            Some(&other) => Ok(unsupported(other)),
            None => Err(ServiceError::Truncated),
        }
    }

    fn dispatch_get(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match GetRequest::decode(request)? {
            GetRequest::Normal { invoke_id_and_priority, attribute, .. } => {
                let result = self.read_attribute(&attribute);
                GetResponse::Normal { invoke_id_and_priority, result }.encode()
            }
            GetRequest::WithList { invoke_id_and_priority, attributes } => {
                let results = attributes.iter().map(|(a, _)| self.read_attribute(a)).collect();
                GetResponse::WithList { invoke_id_and_priority, results }.encode()
            }
            // Block transfer is left to the caller.
            GetRequest::Next { .. } => Ok(not_possible()),
        }
    }

    fn dispatch_set(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match SetRequest::decode(request)? {
            SetRequest::Normal { invoke_id_and_priority, attribute, value, .. } => {
                let result = self.write_attribute(&attribute, value);
                Ok(SetResponse::Normal { invoke_id_and_priority, result }.encode())
            }
            SetRequest::WithList { invoke_id_and_priority, attributes, values } => {
                let results = attributes
                    .iter()
                    .zip(values)
                    .map(|((a, _), v)| self.write_attribute(a, v))
                    .collect();
                Ok(SetResponse::WithList { invoke_id_and_priority, results })
                    .map(|r| r.encode())
            }
            SetRequest::WithFirstDatablock { .. } | SetRequest::WithDatablock { .. } => Ok(not_possible()),
        }
    }

    fn dispatch_action(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match ActionRequest::decode(request)? {
            ActionRequest::Normal { invoke_id_and_priority, method, parameters } => {
                let (result, return_parameters) = self.invoke(&method, parameters);
                ActionResponse::Normal { invoke_id_and_priority, result, return_parameters }.encode()
            }
            ActionRequest::WithList { invoke_id_and_priority, methods, parameters } => {
                let mut params = parameters.into_iter();
                let results = methods
                    .iter()
                    .map(|m| self.invoke(m, params.next().filter(|p| *p != crate::types::CosemDataType::Null)))
                    .collect();
                ActionResponse::WithList { invoke_id_and_priority, results }.encode()
            }
            ActionRequest::NextPblock { .. }
            | ActionRequest::WithFirstPblock { .. }
            | ActionRequest::WithPblock { .. } => Ok(not_possible()),
        }
    }
}

/// EXCEPTION-RESPONSE for an unsupported service tag.
fn unsupported(_tag: u8) -> Vec<u8> {
    ExceptionResponse {
        state_error: state_error::SERVICE_UNKNOWN,
        service_error: service_error::SERVICE_NOT_SUPPORTED,
    }
    .encode()
}

/// EXCEPTION-RESPONSE for a well-formed but unhandled request (e.g. block transfer).
fn not_possible() -> Vec<u8> {
    ExceptionResponse {
        state_error: state_error::SERVICE_NOT_ALLOWED,
        service_error: service_error::OPERATION_NOT_POSSIBLE,
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classes::data::Data;
    use crate::types::CosemDataType;

    fn dispatcher_with_data() -> RequestDispatcher {
        let mut d = RequestDispatcher::new();
        let data = Data::new(ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), CosemDataType::LongUnsigned(0x1234));
        d.add(Box::new(data));
        d
    }

    #[test]
    fn get_reads_registered_attribute() {
        let mut d = dispatcher_with_data();
        let req = GetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
        };
        let resp = GetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(
            resp,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
            }
        );
    }

    #[test]
    fn get_unknown_object_returns_object_undefined() {
        let mut d = dispatcher_with_data();
        let req = GetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(9, 9, 9, 9, 9, 9), 2),
            access_selection: None,
        };
        let resp = GetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(
            resp,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::AccessResult(data_access_result::OBJECT_UNDEFINED),
            }
        );
    }

    #[test]
    fn set_on_read_only_attribute_is_denied() {
        // Data class does not override set_attribute → read-write-denied.
        let mut d = dispatcher_with_data();
        let req = SetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
            value: CosemDataType::LongUnsigned(0x9999),
        };
        let resp = SetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(
            resp,
            SetResponse::Normal { invoke_id_and_priority: 0xC1, result: data_access_result::READ_WRITE_DENIED }
        );
    }

    #[test]
    fn get_with_list_reads_each_attribute() {
        let mut d = dispatcher_with_data();
        let req = GetRequest::WithList {
            invoke_id_and_priority: 0xC1,
            attributes: vec![
                (AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2), None),
                (AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 1), None),
            ],
        };
        let resp = GetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        match resp {
            GetResponse::WithList { results, .. } => {
                assert_eq!(results[0], GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)));
                // Attribute 1 is the logical name.
                assert!(matches!(results[1], GetDataResult::Data(CosemDataType::OctetString(_))));
            }
            _ => panic!("expected WITH-LIST response"),
        }
    }

    #[test]
    fn unsupported_tag_yields_exception_response() {
        let mut d = dispatcher_with_data();
        let resp = d.dispatch(&[tag::DATA_NOTIFICATION, 0x00]).unwrap();
        assert_eq!(resp[0], tag::EXCEPTION_RESPONSE);
    }
}
