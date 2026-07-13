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

use crate::classes::association_ln::AssociationLn;
use crate::interface::InterfaceClass;
use crate::obis::ObisCode;

use crate::service::action::{ActionRequest, ActionResponse};
use crate::service::error::{service_error, state_error, ExceptionResponse};
use crate::service::get::{GetDataResult, GetRequest, GetResponse};
use crate::service::set::{SetRequest, SetResponse};
use crate::service::{data_access_result, tag, AttributeDescriptor, DataBlockSa, MethodDescriptor, ServiceError};
use crate::types::CosemDataType;
#[cfg(feature = "tracing")]
use tracing::{debug, warn};

/// Default block-transfer payload size. A GET result larger than this is sent in
/// GET-RESPONSE-WITH-DATABLOCK blocks of at most this many octets.
const DEFAULT_MAX_PDU: usize = 256;

/// An outbound GET result being delivered in blocks.
struct PendingGet {
    /// The serialized data awaiting block-by-block delivery.
    data: Vec<u8>,
    /// The block number of the next block to send.
    next_block: u32,
}

/// An inbound SET value being reassembled from datablocks.
struct PendingSet {
    attribute: AttributeDescriptor,
    /// The accumulated A-XDR value bytes.
    buffer: Vec<u8>,
}

/// A collection of COSEM objects that answers GET/SET/ACTION requests.
pub struct RequestDispatcher {
    objects: Vec<Box<dyn InterfaceClass>>,
    max_pdu: usize,
    pending_get: Option<PendingGet>,
    pending_set: Option<PendingSet>,
    /// Current association for access rights checking (IEC 62056-5-3, 5.3.7).
    /// When set, GET/SET/ACTION are checked against the association's object_list.
    association: Option<AssociationLn>,
}

impl Default for RequestDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestDispatcher {
    /// Creates an empty dispatcher with the default block size.
    pub fn new() -> Self {
        RequestDispatcher {
            objects: Vec::new(),
            max_pdu: DEFAULT_MAX_PDU,
            pending_get: None,
            pending_set: None,
            association: None,
        }
    }

    /// Sets the maximum block-transfer payload size (octets). Results larger
    /// than this are delivered in GET-RESPONSE-WITH-DATABLOCK blocks.
    pub fn set_max_pdu(&mut self, max_pdu: usize) {
        self.max_pdu = max_pdu.max(1);
    }

    /// Registers an object.
    pub fn add(&mut self, object: Box<dyn InterfaceClass>) {
        #[cfg(feature = "tracing")]
        debug!(
            class_id = object.class_id(),
            logical_name = %object.logical_name(),
            "registering COSEM object"
        );
        self.objects.push(object);
    }

    /// Sets the current association for access rights checking.
    /// When an association is set, all GET/SET/ACTION requests are checked
    /// against the association's object_list access_rights.
    pub fn set_association(&mut self, assoc: AssociationLn) {
        #[cfg(feature = "tracing")]
        debug!("setting association for access rights checking");
        self.association = Some(assoc);
    }

    /// Returns a reference to the current association, if any.
    pub fn association(&self) -> Option<&AssociationLn> {
        self.association.as_ref()
    }

    /// Locates a registered object by class-id and logical name.
    fn find(&mut self, class_id: u16, instance: &ObisCode) -> Option<&mut Box<dyn InterfaceClass>> {
        self.objects.iter_mut().find(|o| o.class_id() == class_id && o.logical_name() == instance)
    }

    /// Checks whether a read is allowed for the given object and attribute.
    /// Returns true if no association is set (unrestricted access).
    fn check_read(&self, class_id: u16, instance: &ObisCode, attribute_id: i8) -> bool {
        match &self.association {
            None => true, // No association — unrestricted
            Some(assoc) => assoc.can_read(class_id, instance, attribute_id),
        }
    }

    /// Checks whether a write is allowed for the given object and attribute.
    /// Returns true if no association is set (unrestricted access).
    fn check_write(&self, class_id: u16, instance: &ObisCode, attribute_id: i8) -> bool {
        match &self.association {
            None => true, // No association — unrestricted
            Some(assoc) => assoc.can_write(class_id, instance, attribute_id),
        }
    }

    /// Checks whether a method invocation is allowed.
    /// Returns true if no association is set (unrestricted access).
    fn check_invoke(&self, class_id: u16, instance: &ObisCode, method_id: i8) -> bool {
        match &self.association {
            None => true, // No association — unrestricted
            Some(assoc) => assoc.can_invoke(class_id, instance, method_id),
        }
    }

    /// Reads one attribute, returning its value or a data-access-result code.
    /// Checks access rights from the current association's object_list.
    fn read_attribute(&mut self, d: &AttributeDescriptor) -> GetDataResult {
        let attr_id = d.attribute_id;
        // Check access rights first.
        if !self.check_read(d.class_id, &d.instance_id, attr_id) {
            #[cfg(feature = "tracing")]
            warn!(
                class_id = d.class_id,
                instance = %d.instance_id,
                attr_id,
                "GET denied by access rights"
            );
            return GetDataResult::AccessResult(data_access_result::READ_WRITE_DENIED);
        }
        match self.find(d.class_id, &d.instance_id) {
            None => {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    attr_id,
                    "GET: object undefined"
                );
                GetDataResult::AccessResult(data_access_result::OBJECT_UNDEFINED)
            }
            Some(obj) => match obj.attributes().into_iter().find(|(id, _)| *id as i8 == attr_id) {
                Some((_, value)) => {
                    #[cfg(feature = "tracing")]
                    debug!(
                        class_id = d.class_id,
                        instance = %d.instance_id,
                        attr_id,
                        "GET: success"
                    );
                    GetDataResult::Data(value)
                }
                None => GetDataResult::AccessResult(data_access_result::OBJECT_UNAVAILABLE),
            },
        }
    }

    /// Writes one attribute, returning a data-access-result code.
    /// Checks access rights from the current association's object_list.
    fn write_attribute(&mut self, d: &AttributeDescriptor, value: crate::types::CosemDataType) -> u8 {
        // Check access rights first.
        if !self.check_write(d.class_id, &d.instance_id, d.attribute_id) {
            #[cfg(feature = "tracing")]
            warn!(
                class_id = d.class_id,
                instance = %d.instance_id,
                attr_id = d.attribute_id,
                "SET denied by access rights"
            );
            return data_access_result::READ_WRITE_DENIED;
        }
        match self.find(d.class_id, &d.instance_id) {
            None => {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    attr_id = d.attribute_id,
                    "SET: object undefined"
                );
                data_access_result::OBJECT_UNDEFINED
            }
            Some(obj) => match obj.set_attribute(d.attribute_id as u8, value) {
                Ok(()) => {
                    #[cfg(feature = "tracing")]
                    debug!(
                        class_id = d.class_id,
                        instance = %d.instance_id,
                        attr_id = d.attribute_id,
                        "SET: success"
                    );
                    data_access_result::SUCCESS
                }
                Err(_) => data_access_result::READ_WRITE_DENIED,
            },
        }
    }

    /// Invokes one method, returning the action-result and optional return data.
    /// Checks method access rights from the current association's object_list.
    fn invoke(
        &mut self,
        d: &MethodDescriptor,
        params: Option<crate::types::CosemDataType>,
    ) -> (u8, Option<GetDataResult>) {
        // Check method access rights first.
        if !self.check_invoke(d.class_id, &d.instance_id, d.method_id) {
            #[cfg(feature = "tracing")]
            warn!(
                class_id = d.class_id,
                instance = %d.instance_id,
                method_id = d.method_id,
                "ACTION denied by access rights"
            );
            return (data_access_result::READ_WRITE_DENIED, None);
        }
        match self.find(d.class_id, &d.instance_id) {
            None => {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    method_id = d.method_id,
                    "ACTION: object undefined"
                );
                (data_access_result::OBJECT_UNDEFINED, None)
            }
            Some(obj) => match obj.invoke_method(d.method_id as u8, params) {
                Ok(crate::types::CosemDataType::Null) => {
                    #[cfg(feature = "tracing")]
                    debug!(
                        class_id = d.class_id,
                        instance = %d.instance_id,
                        method_id = d.method_id,
                        "ACTION: success"
                    );
                    (data_access_result::SUCCESS, None)
                }
                Ok(value) => {
                    #[cfg(feature = "tracing")]
                    debug!(
                        class_id = d.class_id,
                        instance = %d.instance_id,
                        method_id = d.method_id,
                        "ACTION: success (with return value)"
                    );
                    (data_access_result::SUCCESS, Some(GetDataResult::Data(value)))
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    warn!(
                        class_id = d.class_id,
                        instance = %d.instance_id,
                        method_id = d.method_id,
                        "ACTION: method returned error"
                    );
                    (data_access_result::OTHER_REASON, None)
                }
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
                match self.read_attribute(&attribute) {
                    // A too-large value is segmented into datablocks.
                    GetDataResult::Data(value) => {
                        let mut raw = Vec::new();
                        value.serialize_ber(&mut raw)?;
                        if raw.len() > self.max_pdu {
                            return Ok(self.start_get_blocks(invoke_id_and_priority, raw));
                        }
                        GetResponse::Normal { invoke_id_and_priority, result: GetDataResult::Data(value) }.encode()
                    }
                    result => GetResponse::Normal { invoke_id_and_priority, result }.encode(),
                }
            }
            GetRequest::WithList { invoke_id_and_priority, attributes } => {
                let results = attributes.iter().map(|(a, _)| self.read_attribute(a)).collect();
                GetResponse::WithList { invoke_id_and_priority, results }.encode()
            }
            // Deliver the next block of a segmented result.
            GetRequest::Next { invoke_id_and_priority, block_number } => {
                Ok(self.next_get_block(invoke_id_and_priority, block_number))
            }
        }
    }

    /// Stores a segmented GET result and returns the first datablock response.
    fn start_get_blocks(&mut self, invoke_id_and_priority: u8, data: Vec<u8>) -> Vec<u8> {
        self.pending_get = Some(PendingGet { data, next_block: 1 });
        self.next_get_block(invoke_id_and_priority, 0)
    }

    /// Returns the datablock following `acked_block` (0 for the first).
    fn next_get_block(&mut self, invoke_id_and_priority: u8, acked_block: u32) -> Vec<u8> {
        let max_pdu = self.max_pdu;
        let Some(pending) = self.pending_get.as_mut() else {
            return ExceptionResponse {
                state_error: state_error::SERVICE_NOT_ALLOWED,
                service_error: service_error::OPERATION_NOT_POSSIBLE,
            }
            .encode();
        };
        let block_number = pending.next_block;
        // The client acknowledges the previous block by its number in GET-NEXT.
        if acked_block != 0 && acked_block + 1 != block_number {
            return ExceptionResponse {
                state_error: state_error::SERVICE_NOT_ALLOWED,
                service_error: service_error::OTHER_REASON,
            }
            .encode();
        }
        let start = (block_number as usize - 1) * max_pdu;
        let end = (start + max_pdu).min(pending.data.len());
        let chunk = pending.data[start..end].to_vec();
        let last_block = end >= pending.data.len();
        pending.next_block += 1;
        let response =
            GetResponse::WithDataBlock { invoke_id_and_priority, last_block, block_number, raw_data: Ok(chunk) };
        if last_block {
            self.pending_get = None;
        }
        response.encode().unwrap_or_default()
    }

    fn dispatch_set(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match SetRequest::decode(request)? {
            SetRequest::Normal { invoke_id_and_priority, attribute, value, .. } => {
                let result = self.write_attribute(&attribute, value);
                Ok(SetResponse::Normal { invoke_id_and_priority, result }.encode())
            }
            SetRequest::WithList { invoke_id_and_priority, attributes, values } => {
                let results = attributes.iter().zip(values).map(|((a, _), v)| self.write_attribute(a, v)).collect();
                Ok(SetResponse::WithList { invoke_id_and_priority, results }.encode())
            }
            // Begin reassembling a block-transferred value.
            SetRequest::WithFirstDatablock { invoke_id_and_priority, attribute, datablock, .. } => {
                self.pending_set = Some(PendingSet { attribute, buffer: Vec::new() });
                Ok(self.accumulate_set_block(invoke_id_and_priority, datablock))
            }
            SetRequest::WithDatablock { invoke_id_and_priority, datablock } => {
                if self.pending_set.is_none() {
                    return Ok(not_possible());
                }
                Ok(self.accumulate_set_block(invoke_id_and_priority, datablock))
            }
        }
    }

    /// Appends one SET datablock; on the last block, decodes and writes the value.
    fn accumulate_set_block(&mut self, invoke_id_and_priority: u8, datablock: DataBlockSa) -> Vec<u8> {
        let Some(pending) = self.pending_set.as_mut() else {
            return not_possible();
        };
        pending.buffer.extend_from_slice(&datablock.raw_data);
        if !datablock.last_block {
            return SetResponse::Datablock { invoke_id_and_priority, block_number: datablock.block_number }.encode();
        }
        // Final block: decode the accumulated A-XDR value and write it.
        let PendingSet { attribute, buffer } = self.pending_set.take().unwrap();
        let result = match CosemDataType::deserialize_ber(&buffer) {
            Ok((value, _)) => self.write_attribute(&attribute, value),
            Err(_) => data_access_result::TYPE_UNMATCHED,
        };
        SetResponse::LastDatablock { invoke_id_and_priority, result, block_number: datablock.block_number }.encode()
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
    ExceptionResponse { state_error: state_error::SERVICE_UNKNOWN, service_error: service_error::SERVICE_NOT_SUPPORTED }
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

    /// A registered object whose attribute 2 is writable, for SET reassembly.
    #[derive(Clone)]
    struct Writable {
        obis: ObisCode,
        value: CosemDataType,
    }

    impl crate::interface::InterfaceClass for Writable {
        fn class_id(&self) -> u16 {
            1
        }
        fn version(&self) -> u8 {
            0
        }
        fn logical_name(&self) -> &ObisCode {
            &self.obis
        }
        fn attributes(&self) -> Vec<(u8, CosemDataType)> {
            vec![(1, CosemDataType::OctetString(self.obis.to_bytes())), (2, self.value.clone())]
        }
        fn methods(&self) -> Vec<(u8, String)> {
            vec![]
        }
        fn serialize_ber(&self, _: &mut Vec<u8>) -> Result<(), crate::types::BerError> {
            Ok(())
        }
        fn deserialize_ber(&mut self, _: &[u8]) -> Result<(), crate::types::BerError> {
            Ok(())
        }
        fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
            if attribute_id == 2 {
                self.value = value;
                Ok(())
            } else {
                Err("read only".to_string())
            }
        }
        fn invoke_method(&mut self, _: u8, _: Option<CosemDataType>) -> Result<CosemDataType, String> {
            Err("no methods".to_string())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn large_get_is_delivered_in_datablocks() {
        // A 300-octet octet-string exceeds the small block size and is segmented.
        let obis = ObisCode::new(0, 0, 0x80, 0, 0, 0xFF);
        let big = CosemDataType::OctetString(vec![0xAB; 300]);
        let mut d = RequestDispatcher::new();
        d.set_max_pdu(128);
        d.add(Box::new(Data::new(obis.clone(), big.clone())));

        let req = GetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, obis, 2),
            access_selection: None,
        };
        let mut reassembled = Vec::new();
        let mut resp = GetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        let mut block = 1u32;
        loop {
            match resp {
                GetResponse::WithDataBlock { last_block, block_number, raw_data: Ok(chunk), .. } => {
                    assert_eq!(block_number, block);
                    reassembled.extend_from_slice(&chunk);
                    if last_block {
                        break;
                    }
                    let next = GetRequest::Next { invoke_id_and_priority: 0xC1, block_number };
                    resp = GetResponse::decode(&d.dispatch(&next.encode().unwrap()).unwrap()).unwrap();
                    block += 1;
                }
                other => panic!("expected datablock, got {other:?}"),
            }
        }
        // The reassembled blocks decode back to the original value.
        let (value, _) = CosemDataType::deserialize_ber(&reassembled).unwrap();
        assert_eq!(value, big);
    }

    #[test]
    fn set_reassembles_datablocks_and_writes() {
        let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
        let mut d = RequestDispatcher::new();
        d.add(Box::new(Writable { obis: obis.clone(), value: CosemDataType::LongUnsigned(0) }));

        // The value to write, split into two datablocks.
        let mut value_bytes = Vec::new();
        CosemDataType::OctetString(vec![0x5A; 40]).serialize_ber(&mut value_bytes).unwrap();
        let (first, second) = value_bytes.split_at(20);

        let req1 = SetRequest::WithFirstDatablock {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, obis.clone(), 2),
            access_selection: None,
            datablock: DataBlockSa { last_block: false, block_number: 1, raw_data: first.to_vec() },
        };
        let r1 = SetResponse::decode(&d.dispatch(&req1.encode().unwrap()).unwrap()).unwrap();
        assert!(matches!(r1, SetResponse::Datablock { block_number: 1, .. }));

        let req2 = SetRequest::WithDatablock {
            invoke_id_and_priority: 0xC1,
            datablock: DataBlockSa { last_block: true, block_number: 2, raw_data: second.to_vec() },
        };
        let r2 = SetResponse::decode(&d.dispatch(&req2.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(
            r2,
            SetResponse::LastDatablock {
                invoke_id_and_priority: 0xC1,
                result: data_access_result::SUCCESS,
                block_number: 2
            }
        );

        // The reassembled value was written to the object.
        let got = d
            .dispatch(
                &GetRequest::Normal {
                    invoke_id_and_priority: 0xC1,
                    attribute: AttributeDescriptor::new(1, obis, 2),
                    access_selection: None,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
        match GetResponse::decode(&got).unwrap() {
            GetResponse::Normal { result: GetDataResult::Data(v), .. } => {
                assert_eq!(v, CosemDataType::OctetString(vec![0x5A; 40]));
            }
            other => panic!("unexpected {other:?}"),
        }
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
