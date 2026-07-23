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
use crate::security::AuthMechanism;

use crate::classes::push_setup::{PushDeliveryRequest, PushSetup};
use crate::service::acse::{self, AssociationResponse};
use crate::service::action::{ActionRequest, ActionResponse};
use crate::service::error::{service_error, state_error, ConfirmedServiceError, ExceptionResponse};
use crate::service::get::{GetDataResult, GetRequest, GetResponse};
use crate::service::initiate::{InitiateRequest, InitiateResponse};
use crate::service::notification::DataNotification;
use crate::service::set::{SetRequest, SetResponse};
use crate::service::{data_access_result, tag, AttributeDescriptor, DataBlockSa, MethodDescriptor, ServiceError};
use crate::types::CosemDataType;
#[cfg(feature = "tracing")]
use tracing::{debug, warn};

/// Default block-transfer payload size. A GET result larger than this is sent in
/// GET-RESPONSE-WITH-DATABLOCK blocks of at most this many octets.
const DEFAULT_MAX_PDU: usize = 256;

/// The DLMS version number negotiated by [`RequestDispatcher::handle_aarq`].
const DLMS_VERSION: u8 = 6;

/// The smallest client-max-receive-pdu-size the server accepts.
const MIN_CLIENT_PDU: u16 = 12;

/// Server-max-receive-pdu-size offered in the negotiated InitiateResponse.
const SERVER_MAX_PDU: u16 = 0x0800;

/// The server's conformance block: GET, SET, ACTION, selective access,
/// block transfer with GET/SET and multiple references.
const SERVER_CONFORMANCE: u32 = 0x00_18_5F;

/// `association_status` values (IEC 62056-6-2, Association LN attribute 8).
mod association_status {
    /// No association is open.
    pub const NON_ASSOCIATED: u8 = 0;
    /// The HLS handshake is still in progress (pass 3/4 pending).
    pub const ASSOCIATION_PENDING: u8 = 1;
    /// The association is open.
    pub const ASSOCIATED: u8 = 2;
}

/// `initiateError` values of the ConfirmedServiceError sent when the
/// InitiateRequest is rejected (IEC 62056-5-3).
mod initiate_error {
    /// The proposed DLMS version is lower than 6.
    pub const DLMS_VERSION_TOO_LOW: u8 = 1;
    /// The proposed conformance has no supported service in common.
    pub const INCOMPATIBLE_CONFORMANCE: u8 = 2;
    /// The proposed client PDU size is too small.
    pub const PDU_SIZE_TOO_SHORT: u8 = 3;
}

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

    /// Returns a mutable reference to the current association, if any.
    pub fn association_mut(&mut self) -> Option<&mut AssociationLn> {
        self.association.as_mut()
    }

    /// Assembles a [`PushDeliveryRequest`] for `push_setup`'s ACTION method 1
    /// (`push`): reads each object in `push_object_list` from this
    /// dispatcher's registry, wraps the values in a DataNotification
    /// (an Array when more than one object is listed), and pairs it with the
    /// destination and client SAP from `push_setup`.
    ///
    /// Mirrors the reference implementation's `push_build_notification_body` /
    /// `push_try_schedule_delivery`: the host is expected to call this from
    /// the `push` ACTION handler (this dispatcher owns the object registry
    /// that `PushSetup` itself does not hold) and then deliver `body` over the
    /// configured transport.
    pub fn build_push_delivery_request(
        &mut self,
        push_setup: &PushSetup,
        long_invoke_id_and_priority: u32,
    ) -> Result<PushDeliveryRequest, String> {
        let objects = push_setup.push_object_list();
        if objects.is_empty() {
            return Err("No push objects configured".to_string());
        }
        let mut values = Vec::with_capacity(objects.len());
        for entry in objects {
            let obj = self
                .find(entry.class_id, &entry.logical_name)
                .ok_or_else(|| format!("Push object {} (class {}) not found", entry.logical_name, entry.class_id))?;
            let value = obj
                .attributes()
                .into_iter()
                .find(|(id, _)| *id == entry.attribute_index)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("Push object has no attribute {}", entry.attribute_index))?;
            values.push(value);
        }
        let body = if values.len() == 1 { values.remove(0) } else { CosemDataType::Array(values) };
        let notification =
            DataNotification { long_invoke_id_and_priority, date_time: Vec::new(), notification_body: body };
        let encoded = notification.encode().map_err(|e| format!("Failed to encode push body: {e:?}"))?;
        let destination = push_setup.send_destination_and_method();
        Ok(PushDeliveryRequest {
            destination: destination.destination.clone(),
            transport_service: destination.transport_service,
            client_sap: push_setup.push_client_sap(),
            body: encoded,
        })
    }

    /// Locates a registered object by class-id and logical name.
    fn find(&mut self, class_id: u16, instance: &ObisCode) -> Option<&mut Box<dyn InterfaceClass>> {
        self.objects.iter_mut().find(|o| o.class_id() == class_id && o.logical_name() == instance)
    }

    /// Checks whether a read is allowed for the given object and attribute.
    /// Returns true if no association is set (unrestricted access).
    fn check_read(&self, class_id: u16, instance: &ObisCode, attribute_id: i8) -> bool {
        // No association — unrestricted.
        self.association.as_ref().is_none_or(|assoc| assoc.can_read(class_id, instance, attribute_id))
    }

    /// Checks whether a write is allowed for the given object and attribute.
    /// Returns true if no association is set (unrestricted access).
    fn check_write(&self, class_id: u16, instance: &ObisCode, attribute_id: i8) -> bool {
        // No association — unrestricted.
        self.association.as_ref().is_none_or(|assoc| assoc.can_write(class_id, instance, attribute_id))
    }

    /// Checks whether a method invocation is allowed.
    /// Returns true if no association is set (unrestricted access).
    fn check_invoke(&self, class_id: u16, instance: &ObisCode, method_id: i8) -> bool {
        // No association — unrestricted.
        self.association.as_ref().is_none_or(|assoc| assoc.can_invoke(class_id, instance, method_id))
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
        self.find(d.class_id, &d.instance_id).map_or_else(
            || {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    attr_id,
                    "GET: object undefined"
                );
                GetDataResult::AccessResult(data_access_result::OBJECT_UNDEFINED)
            },
            // Attribute ids are always <128 in practice (i8-valued on the wire).
            #[allow(clippy::cast_possible_wrap)]
            |obj| match obj.attributes().into_iter().find(|(id, _)| *id as i8 == attr_id) {
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
        )
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
        self.find(d.class_id, &d.instance_id).map_or_else(
            || {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    attr_id = d.attribute_id,
                    "SET: object undefined"
                );
                data_access_result::OBJECT_UNDEFINED
            },
            |obj| {
                // Attribute ids are always <128 in practice (i8-valued on the wire).
                #[allow(clippy::cast_sign_loss)]
                let attribute_id = d.attribute_id as u8;
                match obj.set_attribute(attribute_id, value) {
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
                }
            },
        )
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
        // HLS reply_to_authentication and other Association LN methods must hit
        // the live association state, not a cloned registry object.
        let routed_to_assoc = d.class_id == 15
            && self.association.is_some()
            && (d.instance_id == ObisCode::new(0, 0, 40, 0, 0, 255)
                || self.association.as_ref().is_some_and(|assoc| assoc.logical_name() == &d.instance_id));
        if routed_to_assoc {
            // Method ids are always <128 in practice (i8-valued on the wire).
            #[allow(clippy::cast_sign_loss)]
            let method_id = d.method_id as u8;
            return match self.association.as_mut().expect("association routing").invoke_method(method_id, params) {
                Ok(crate::types::CosemDataType::Null) => (data_access_result::SUCCESS, None),
                Ok(value) => (data_access_result::SUCCESS, Some(GetDataResult::Data(value))),
                Err(_) => (data_access_result::OTHER_REASON, None),
            };
        }
        self.find(d.class_id, &d.instance_id).map_or_else(
            || {
                #[cfg(feature = "tracing")]
                debug!(
                    class_id = d.class_id,
                    instance = %d.instance_id,
                    method_id = d.method_id,
                    "ACTION: object undefined"
                );
                (data_access_result::OBJECT_UNDEFINED, None)
            },
            |obj| {
                // Method ids are always <128 in practice (i8-valued on the wire).
                #[allow(clippy::cast_sign_loss)]
                let method_id = d.method_id as u8;
                match obj.invoke_method(method_id, params) {
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
                }
            },
        )
    }

    /// Dispatches one request APDU to the addressed object and returns the
    /// encoded response APDU. Malformed or unsupported requests yield an
    /// EXCEPTION-RESPONSE. An AARQ is answered with an AARE via
    /// [`Self::handle_aarq`].
    pub fn dispatch(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        match request.first() {
            Some(&acse::AARQ_TAG) => Ok(self.handle_aarq(request)),
            Some(&acse::RLRQ_TAG) => Ok(self.handle_rlrq(request)),
            Some(&tag) => {
                if !self.xdlms_services_allowed(request) {
                    return Ok(not_possible());
                }
                match tag {
                    tag::GET_REQUEST => self.dispatch_get(request),
                    tag::SET_REQUEST => Ok(self.dispatch_set(request)),
                    tag::ACTION_REQUEST => self.dispatch_action(request),
                    other => Ok(unsupported(other)),
                }
            }
            None => Err(ServiceError::Truncated),
        }
    }

    /// xDLMS GET/SET/ACTION are allowed only when associated. While HLS is
    /// pending, only `reply_to_HLS_authentication` (Association LN method 1)
    /// is accepted — everything else yields EXCEPTION-RESPONSE (C++
    /// `hls_pending` gate / Yellow Book APPL_OPEN HLS pass 3).
    fn xdlms_services_allowed(&self, request: &[u8]) -> bool {
        match self.association.as_ref().map(AssociationLn::association_status) {
            None | Some(association_status::ASSOCIATED) => true,
            Some(association_status::ASSOCIATION_PENDING) => is_hls_pass3_action(request),
            Some(_) => false,
        }
    }

    /// Validates an AARQ against the configured association and answers with an
    /// AARE carrying a structured ACSE diagnostic (IEC 62056-5-3 §7.3.5):
    ///
    /// * unsupported application context → `application-context-name-not-supported`;
    /// * ciphering / title-bound HLS without an 8-octet calling-AP-title →
    ///   `calling-AP-title-not-recognized`;
    /// * bad InitiateRequest parameters → `initiateError` ConfirmedServiceError
    ///   in the user-information (DLMS version / conformance / PDU size);
    /// * missing, unknown, or mismatching authentication →
    ///   `authentication-required` / `-mechanism-name-not-recognised` /
    ///   `authentication-failure`;
    /// * LLS: the calling-authentication-value is compared with the
    ///   association's secret;
    /// * HLS: the CtoS challenge is stored, a random StoC is generated and
    ///   returned, and the association is left `association-pending` until the
    ///   `reply_to_HLS_authentication` ACTION (pass 3/4) completes.
    ///
    /// Requires an association to be configured via [`Self::set_association`];
    /// without one, only mechanism 0 (lowest) AARQs are accepted.
    pub fn handle_aarq(&mut self, request: &[u8]) -> Vec<u8> {
        use crate::service::acse::{
            acse_diagnostic as diag, acse_provider_diagnostic as pdiag, application_context, AssociationRequest,
            PROTOCOL_VERSION_1,
        };

        // Fresh AARQ clears any prior AA (C++ resets associated/hls_pending).
        if let Some(assoc) = self.association.as_mut() {
            assoc.set_association_status(association_status::NON_ASSOCIATED);
        }

        let Ok(aarq) = AssociationRequest::decode(request) else {
            return reject_aare(application_context::LN, diag::NULL, false, None);
        };
        let echo_context = aarq.application_context;

        // Application context: LN with or without ciphering.
        if aarq.application_context != application_context::LN
            && aarq.application_context != application_context::LN_CIPHERING
        {
            return reject_aare(application_context::LN, diag::APPLICATION_CONTEXT_NAME_NOT_SUPPORTED, false, None);
        }

        // Protocol-version must be absent or {version1} (`02 84`).
        if let Some(pv) = aarq.protocol_version {
            if pv != PROTOCOL_VERSION_1 {
                return reject_aare(echo_context, pdiag::NO_COMMON_ACSE_VERSION, true, None);
            }
        }

        // Ciphering and title-bound HLS mechanisms require an 8-octet client
        // system title in the calling-AP-title.
        let mech_id = aarq.mechanism_name.unwrap_or(0);
        let title_bound = aarq.application_context == application_context::LN_CIPHERING || mech_id >= 5;
        if title_bound && aarq.calling_ap_title.as_ref().map(Vec::len) != Some(8) {
            return reject_aare(echo_context, diag::CALLING_AP_TITLE_NOT_RECOGNIZED, false, None);
        }

        // Validate the xDLMS InitiateRequest, when present and well-formed.
        let initiate = InitiateRequest::decode(&aarq.user_information).ok();
        if let Some(ireq) = &initiate {
            let err = if ireq.proposed_dlms_version != 0 && ireq.proposed_dlms_version < DLMS_VERSION {
                Some(initiate_error::DLMS_VERSION_TOO_LOW)
            } else if ireq.proposed_conformance == 0 {
                Some(initiate_error::INCOMPATIBLE_CONFORMANCE)
            } else if ireq.client_max_receive_pdu_size > 0 && ireq.client_max_receive_pdu_size < MIN_CLIENT_PDU {
                Some(initiate_error::PDU_SIZE_TOO_SHORT)
            } else {
                None
            };
            if let Some(value) = err {
                return reject_aare(echo_context, diag::NULL, false, Some(value));
            }
        }

        // Authentication, against the configured association (C++ `aarq_validate` order).
        let required = self.association.as_ref().map(|a| a.authentication_mechanism()).unwrap_or(AuthMechanism::None);
        if required != AuthMechanism::None {
            let has_mech = aarq.mechanism_name.is_some();
            let has_auth = aarq.calling_authentication_value.is_some();
            if !has_mech && !has_auth {
                return reject_aare(echo_context, diag::AUTHENTICATION_REQUIRED, false, None);
            }
            if let Some(bits) = aarq.sender_acse_requirements {
                if bits != 0x80 {
                    return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
                }
            }
            if !has_mech {
                return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
            }
            let Some(mech) = aarq.mechanism_name.and_then(AuthMechanism::from_id) else {
                return reject_aare(echo_context, diag::AUTHENTICATION_MECHANISM_NAME_NOT_RECOGNISED, false, None);
            };
            if !has_auth && mech != AuthMechanism::None {
                return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
            }
            if !Self::aarq_mechanism_matches_assoc(mech, required) {
                return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
            }
        }

        let mechanism = aarq.mechanism_name.and_then(AuthMechanism::from_id).unwrap_or(AuthMechanism::None);
        let user_information = Self::negotiate_initiate_response(initiate.as_ref());
        match mechanism {
            AuthMechanism::None => {
                if let Some(assoc) = self.association.as_mut() {
                    assoc.set_association_status(association_status::ASSOCIATED);
                }
                AssociationResponse {
                    protocol_version: Some(PROTOCOL_VERSION_1),
                    application_context: echo_context,
                    result: acse::result::ACCEPTED,
                    diagnostic: diag::NULL,
                    user_information,
                    ..AssociationResponse::default()
                }
                .encode()
            }
            AuthMechanism::Lls => {
                let secret_ok = match (&self.association, &aarq.calling_authentication_value) {
                    (Some(assoc), Some(pw)) => !assoc.secret().is_empty() && assoc.secret() == pw.as_slice(),
                    _ => false,
                };
                if !secret_ok {
                    return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
                }
                if let Some(assoc) = self.association.as_mut() {
                    assoc.set_association_status(association_status::ASSOCIATED);
                }
                AssociationResponse {
                    protocol_version: Some(PROTOCOL_VERSION_1),
                    application_context: echo_context,
                    result: acse::result::ACCEPTED,
                    diagnostic: diag::NULL,
                    user_information,
                    ..AssociationResponse::default()
                }
                .encode()
            }
            _ => {
                // HLS pass 1/2: store CtoS, reply with a fresh StoC; the
                // handshake completes with the reply_to_HLS_authentication
                // ACTION (pass 3/4), served by the Association LN object.
                let Some(ctos) = aarq.calling_authentication_value else {
                    return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
                };
                let Some(assoc) = self.association.as_mut() else {
                    return reject_aare(echo_context, diag::AUTHENTICATION_FAILURE, false, None);
                };
                assoc.set_ctos(ctos);
                if let Some(title) = aarq.calling_ap_title {
                    assoc.set_client_system_title(title);
                }
                assoc.set_hls_handshake_mechanism(mechanism);
                let stoc = assoc.generate_stoc(16);
                assoc.set_association_status(association_status::ASSOCIATION_PENDING);
                // Responding-AP-title: required with ciphering / title-bound HLS
                // (GMAC+); omit for Gurux HIGH (mech 2) over plain LN (etalon).
                let responding_ap_title = if echo_context == application_context::LN_CIPHERING
                    || matches!(
                        mechanism,
                        AuthMechanism::HlsGmac
                            | AuthMechanism::HlsSha256
                            | AuthMechanism::HlsEcdsa
                            | AuthMechanism::HlsGostCmac
                            | AuthMechanism::HlsGostStreebog
                            | AuthMechanism::HlsGostSignature
                    ) {
                    assoc.responding_ap_title_for_hls()
                } else {
                    None
                };
                AssociationResponse {
                    protocol_version: Some(PROTOCOL_VERSION_1),
                    application_context: echo_context,
                    // Yellow Book: accepted + authentication-required while HLS pending.
                    result: acse::result::ACCEPTED,
                    diagnostic: diag::AUTHENTICATION_REQUIRED,
                    responding_ap_title,
                    mechanism_name: Some(mechanism.id()),
                    responding_authentication_value: Some(stoc),
                    user_information,
                    ..AssociationResponse::default()
                }
                .encode()
            }
        }
    }

    /// Gurux HIGH authentication advertises mechanism 2 (`HlsManufacturer`);
    /// СПОДЭС Configurator associations are configured as HLS-GMAC (5). Accept
    /// that pairing for AARQ, then finish the handshake with GMAC.
    fn aarq_mechanism_matches_assoc(requested: AuthMechanism, required: AuthMechanism) -> bool {
        requested == required || (requested == AuthMechanism::HlsManufacturer && required == AuthMechanism::HlsGmac)
    }

    /// Answers an RLRQ with RLRE (IEC 62056-5-3 §7.3.6) and clears any
    /// configured association state back to non-associated. A malformed RLRQ
    /// is still answered with a normal-release RLRE, since releasing is
    /// best-effort.
    pub fn handle_rlrq(&mut self, request: &[u8]) -> Vec<u8> {
        use crate::service::acse::ReleaseRequest;
        if let Some(assoc) = self.association.as_mut() {
            assoc.set_association_status(association_status::NON_ASSOCIATED);
        }
        ReleaseRequest::decode_rlrq(request).map_or_else(
            |_| ReleaseRequest { reason: Some(acse::release_reason::NORMAL), user_information: None }.encode_rlre(),
            |release| release.encode_rlre(),
        )
    }

    /// Builds the negotiated InitiateResponse: the conformance is ANDed with
    /// the client's proposal and the PDU size capped by the client's maximum.
    fn negotiate_initiate_response(ireq: Option<&InitiateRequest>) -> Vec<u8> {
        let mut conformance = SERVER_CONFORMANCE;
        let mut pdu = SERVER_MAX_PDU;
        if let Some(ireq) = ireq {
            if ireq.proposed_conformance != 0 {
                conformance &= ireq.proposed_conformance;
            }
            if ireq.client_max_receive_pdu_size > 0 && ireq.client_max_receive_pdu_size < pdu {
                pdu = ireq.client_max_receive_pdu_size;
            }
        }
        InitiateResponse {
            negotiated_quality_of_service: None,
            negotiated_dlms_version: DLMS_VERSION,
            negotiated_conformance: conformance,
            server_max_receive_pdu_size: pdu,
            vaa_name: 0x0007,
        }
        .encode()
    }

    fn dispatch_get(&mut self, request: &[u8]) -> Result<Vec<u8>, ServiceError> {
        // A malformed GET from an associated client is answered with a
        // data-access-result instead of dropping the session (the invoke-id is
        // salvaged from the raw APDU when present).
        let Ok(decoded) = GetRequest::decode(request) else {
            let invoke_id_and_priority = request.get(2).copied().unwrap_or(0);
            return GetResponse::Normal {
                invoke_id_and_priority,
                result: GetDataResult::AccessResult(data_access_result::OTHER_REASON),
            }
            .encode();
        };
        match decoded {
            GetRequest::Normal { invoke_id_and_priority, attribute, access_selection } => {
                let read = self.read_attribute(&attribute);
                match apply_selective_access(&attribute, read, access_selection.as_ref()) {
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
                let results = attributes
                    .iter()
                    .map(|(a, sel)| {
                        let read = self.read_attribute(a);
                        apply_selective_access(a, read, sel.as_ref())
                    })
                    .collect();
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

    fn dispatch_set(&mut self, request: &[u8]) -> Vec<u8> {
        // A malformed SET is answered with a data-access-result instead of
        // dropping the session.
        let Ok(decoded) = SetRequest::decode(request) else {
            let invoke_id_and_priority = request.get(2).copied().unwrap_or(0);
            return SetResponse::Normal { invoke_id_and_priority, result: data_access_result::OTHER_REASON }.encode();
        };
        match decoded {
            SetRequest::Normal { invoke_id_and_priority, attribute, value, .. } => {
                let result = self.write_attribute(&attribute, value);
                SetResponse::Normal { invoke_id_and_priority, result }.encode()
            }
            SetRequest::WithList { invoke_id_and_priority, attributes, values } => {
                let results = attributes.iter().zip(values).map(|((a, _), v)| self.write_attribute(a, v)).collect();
                SetResponse::WithList { invoke_id_and_priority, results }.encode()
            }
            // Begin reassembling a block-transferred value.
            SetRequest::WithFirstDatablock { invoke_id_and_priority, attribute, datablock, .. } => {
                self.pending_set = Some(PendingSet { attribute, buffer: Vec::new() });
                self.accumulate_set_block(invoke_id_and_priority, &datablock)
            }
            SetRequest::WithDatablock { invoke_id_and_priority, datablock } => {
                if self.pending_set.is_none() {
                    return not_possible();
                }
                self.accumulate_set_block(invoke_id_and_priority, &datablock)
            }
        }
    }

    /// Appends one SET datablock; on the last block, decodes and writes the value.
    fn accumulate_set_block(&mut self, invoke_id_and_priority: u8, datablock: &DataBlockSa) -> Vec<u8> {
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

/// Applies GET selective access to a read result (IEC 62056-5-3 §7.4.1.6 /
/// IEC 62056-6-2 §4.3.6.2). Only the ProfileGeneric buffer (class 7,
/// attribute 2) is filtered:
///
/// * selector 2 (`entry_descriptor`) — keeps the 1-based entry window
///   `[from_entry, to_entry]` of the buffer array; `to_entry` = 0 keeps all
///   remaining entries.
/// * selector 1 (`range_descriptor`) — value-range filtering needs the sort
///   column; like the reference implementation the buffer is returned
///   unfiltered.
///
/// Any other selector on the buffer, or a malformed descriptor, yields
/// `other-reason`; selective access on other attributes is ignored.
fn apply_selective_access(
    attribute: &AttributeDescriptor,
    read: GetDataResult,
    selection: Option<&crate::service::get::AccessSelection>,
) -> GetDataResult {
    let Some(sel) = selection else { return read };
    if attribute.class_id != 7 || attribute.attribute_id != 2 {
        return read;
    }
    let GetDataResult::Data(CosemDataType::Array(rows)) = read else { return read };
    match sel.selector {
        1 => GetDataResult::Data(CosemDataType::Array(rows)),
        2 => {
            let fields = match &sel.parameters {
                CosemDataType::Structure(fields) if fields.len() >= 2 => fields,
                _ => return GetDataResult::AccessResult(data_access_result::OTHER_REASON),
            };
            let (Some(from), Some(to)) = (selective_index(&fields[0]), selective_index(&fields[1])) else {
                return GetDataResult::AccessResult(data_access_result::OTHER_REASON);
            };
            if from == 0 {
                return GetDataResult::AccessResult(data_access_result::OTHER_REASON);
            }
            let start = (from - 1) as usize;
            let end = if to == 0 { rows.len() } else { (to as usize).min(rows.len()) };
            let slice = if start < end { rows[start..end].to_vec() } else { Vec::new() };
            GetDataResult::Data(CosemDataType::Array(slice))
        }
        _ => GetDataResult::AccessResult(data_access_result::OTHER_REASON),
    }
}

/// Reads a non-negative COSEM integer used as a selective-access entry index.
fn selective_index(value: &CosemDataType) -> Option<u32> {
    match value {
        CosemDataType::DoubleLongUnsigned(v) => Some(*v),
        CosemDataType::LongUnsigned(v) => Some(u32::from(*v)),
        CosemDataType::Unsigned(v) => Some(u32::from(*v)),
        _ => None,
    }
}

/// Builds a permanently-rejecting AARE with the given diagnostic;
/// `initiate_err` adds an `initiateError` ConfirmedServiceError to the
/// user-information. `diagnostic_is_provider` selects the acse-service-provider
/// CHOICE (e.g. no-common-acse-version).
fn reject_aare(
    application_context: u8,
    diagnostic: u8,
    diagnostic_is_provider: bool,
    initiate_err: Option<u8>,
) -> Vec<u8> {
    use crate::service::acse::PROTOCOL_VERSION_1;
    let user_information = initiate_err.map_or_else(Vec::new, |value| {
        ConfirmedServiceError {
            service: crate::service::error::service::INITIATE_ERROR,
            category: crate::service::error::category::INITIATE,
            value,
        }
        .encode()
    });
    AssociationResponse {
        protocol_version: Some(PROTOCOL_VERSION_1),
        application_context,
        result: acse::result::REJECTED_PERMANENT,
        diagnostic,
        diagnostic_is_provider,
        user_information,
        ..AssociationResponse::default()
    }
    .encode()
}

/// True when the APDU is Association LN `reply_to_HLS_authentication` (method 1).
fn is_hls_pass3_action(request: &[u8]) -> bool {
    match ActionRequest::decode(request) {
        Ok(ActionRequest::Normal { method, .. }) => method.class_id == 15 && method.method_id == 1,
        _ => false,
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

    /// An AssociationLn requiring the given mechanism, with an LLS secret.
    fn association(mechanism: AuthMechanism) -> AssociationLn {
        use crate::classes::association_ln::{AssociationLnConfig, AssociationLnVersion};
        use crate::types::attrs::{AssociatedPartnersId, ContextName, XDLMSContextInfo};
        AssociationLn::new(AssociationLnConfig {
            logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
            version: AssociationLnVersion::Version1,
            object_list: vec![],
            associated_partners_id: AssociatedPartnersId { client_sap: 0, server_sap: 1 },
            application_context_name: ContextName::OctetString(vec![
                0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
            ]),
            xdlms_context_info: XDLMSContextInfo {
                conformance: vec![0x00; 18],
                max_receive_pdu_size: 1024,
                max_send_pdu_size: 1024,
                dlms_version_number: 6,
                quality_of_service: -1,
                cyphering_info: vec![],
            },
            authentication_mechanism: mechanism,
            secret: b"password".to_vec(),
            association_status: 0,
            security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
            user_list: vec![],
            current_user: None,
        })
    }

    fn aarq(context: u8, mechanism: Option<u8>, auth: Option<&[u8]>) -> Vec<u8> {
        crate::service::acse::AssociationRequest {
            application_context: context,
            calling_ap_title: None,
            sender_acse_requirements: mechanism.map(|_| 0x80),
            mechanism_name: mechanism,
            calling_authentication_value: auth.map(<[u8]>::to_vec),
            user_information: InitiateRequest {
                dedicated_key: None,
                response_allowed: true,
                proposed_quality_of_service: None,
                proposed_dlms_version: 6,
                proposed_conformance: 0x00_18_5F,
                client_max_receive_pdu_size: 0x0400,
            }
            .encode(),
            ..Default::default()
        }
        .encode()
    }

    #[test]
    fn aarq_lowest_is_accepted_without_association() {
        let mut d = dispatcher_with_data();
        let resp = d.dispatch(&aarq(1, None, None)).unwrap();
        let aare = AssociationResponse::decode(&resp).unwrap();
        assert_eq!(aare.result, acse::result::ACCEPTED);
        // Negotiated InitiateResponse: version 6, PDU capped by the client.
        let iresp = InitiateResponse::decode(&aare.user_information).unwrap();
        assert_eq!(iresp.negotiated_dlms_version, 6);
        assert_eq!(iresp.server_max_receive_pdu_size, 0x0400);
    }

    #[test]
    fn aarq_unsupported_context_is_rejected() {
        let mut d = dispatcher_with_data();
        // Short-name referencing (context 2) is not supported.
        let resp = d.handle_aarq(&aarq(2, None, None));
        let aare = AssociationResponse::decode(&resp).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::APPLICATION_CONTEXT_NAME_NOT_SUPPORTED);
    }

    #[test]
    fn aarq_without_auth_when_required_is_rejected() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::Lls));
        let resp = d.handle_aarq(&aarq(1, None, None));
        let aare = AssociationResponse::decode(&resp).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_REQUIRED);
    }

    #[test]
    fn aarq_lls_secret_is_checked() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::Lls));
        // Wrong password.
        let aare = AssociationResponse::decode(&d.handle_aarq(&aarq(1, Some(1), Some(b"wrong")))).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_FAILURE);
        // Right password.
        let aare = AssociationResponse::decode(&d.handle_aarq(&aarq(1, Some(1), Some(b"password")))).unwrap();
        assert_eq!(aare.result, acse::result::ACCEPTED);
    }

    #[test]
    fn aarq_mechanism_mismatch_is_rejected() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::HlsSha256));
        let resp = d.handle_aarq(&aarq(1, Some(1), Some(b"password")));
        let aare = AssociationResponse::decode(&resp).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_FAILURE);
    }

    #[test]
    fn aarq_hls_pass1_returns_stoc_and_leaves_pending() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::HlsSha256));
        // Title-bound HLS without a calling-AP-title is rejected.
        let aare = AssociationResponse::decode(&d.handle_aarq(&aarq(1, Some(6), Some(b"CTOS0123CTOS0123")))).unwrap();
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::CALLING_AP_TITLE_NOT_RECOGNIZED);

        // With an 8-octet title: accepted, StoC returned, pass 3/4 pending.
        let mut req =
            crate::service::acse::AssociationRequest::decode(&aarq(1, Some(6), Some(b"CTOS0123CTOS0123"))).unwrap();
        req.calling_ap_title = Some(b"CLIENT01".to_vec());
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::ACCEPTED);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_REQUIRED);
        let stoc = aare.responding_authentication_value.expect("StoC missing");
        assert_eq!(stoc.len(), 16);
    }

    #[test]
    fn aarq_bad_protocol_version_is_provider_reject() {
        let mut d = dispatcher_with_data();
        let mut req = crate::service::acse::AssociationRequest::decode(&aarq(1, None, None)).unwrap();
        req.protocol_version = Some([0x02, 0x44]);
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert!(aare.diagnostic_is_provider);
        assert_eq!(aare.diagnostic, acse::acse_provider_diagnostic::NO_COMMON_ACSE_VERSION);
    }

    #[test]
    fn aarq_wrong_acse_requirements_is_auth_failure() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::Lls));
        let mut req =
            crate::service::acse::AssociationRequest::decode(&aarq(1, Some(1), Some(b"password"))).unwrap();
        req.sender_acse_requirements = Some(0x00);
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_FAILURE);
    }

    #[test]
    fn aarq_missing_mechanism_with_auth_is_auth_failure() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::Lls));
        let mut req = crate::service::acse::AssociationRequest::decode(&aarq(1, None, None)).unwrap();
        req.sender_acse_requirements = Some(0x80);
        req.calling_authentication_value = Some(b"password".to_vec());
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(aare.diagnostic, acse::acse_diagnostic::AUTHENTICATION_FAILURE);
    }

    #[test]
    fn get_while_hls_pending_is_service_not_allowed() {
        let mut d = dispatcher_with_data();
        d.set_association(association(AuthMechanism::HlsSha1));
        let req =
            crate::service::acse::AssociationRequest::decode(&aarq(1, Some(4), Some(b"CTOS0123CTOS0123"))).unwrap();
        // HlsSha1 (4) is not title-bound (>=5); no calling-AP-title needed.
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::ACCEPTED);
        assert_eq!(d.association().unwrap().association_status(), association_status::ASSOCIATION_PENDING);

        let get = GetRequest::Normal {
            invoke_id_and_priority: 0xC0,
            attribute: AttributeDescriptor {
                class_id: 15,
                instance_id: ObisCode::new(0, 0, 40, 0, 0, 255),
                attribute_id: 1,
            },
            access_selection: None,
        }
        .encode()
        .unwrap();
        let resp = d.dispatch(&get).unwrap();
        assert_eq!(resp[0], 0xD8); // EXCEPTION-RESPONSE
        let ex = ExceptionResponse::decode(&resp).unwrap();
        assert_eq!(ex.state_error, state_error::SERVICE_NOT_ALLOWED);
        assert_eq!(ex.service_error, service_error::OPERATION_NOT_POSSIBLE);

        // After HLS completes (status → associated), GET is allowed again.
        d.association_mut().unwrap().set_association_status(association_status::ASSOCIATED);
        let resp = d.dispatch(&get).unwrap();
        assert_ne!(resp[0], 0xD8, "GET after HLS must not be Exception");
    }

    #[test]
    fn aarq_bad_initiate_yields_confirmed_service_error() {
        let mut d = dispatcher_with_data();
        let mut req = crate::service::acse::AssociationRequest::decode(&aarq(1, None, None)).unwrap();
        req.user_information = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version: 5, // too low
            proposed_conformance: 0x00_18_5F,
            client_max_receive_pdu_size: 0x0400,
        }
        .encode();
        let aare = AssociationResponse::decode(&d.handle_aarq(&req.encode())).unwrap();
        assert_eq!(aare.result, acse::result::REJECTED_PERMANENT);
        let cse = ConfirmedServiceError::decode(&aare.user_information).unwrap();
        assert_eq!(cse.value, initiate_error::DLMS_VERSION_TOO_LOW);
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
    fn malformed_get_returns_other_reason() {
        let mut d = dispatcher_with_data();
        // GET-REQUEST with an unknown choice (0x77) and a salvageable invoke-id.
        let resp = d.dispatch(&[tag::GET_REQUEST, 0x77, 0xC1]).unwrap();
        let decoded = GetResponse::decode(&resp).unwrap();
        assert_eq!(
            decoded,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::AccessResult(data_access_result::OTHER_REASON),
            }
        );
    }

    #[test]
    fn malformed_set_returns_other_reason() {
        let mut d = dispatcher_with_data();
        let resp = d.dispatch(&[tag::SET_REQUEST, 0x77, 0xC1]).unwrap();
        let decoded = SetResponse::decode(&resp).unwrap();
        assert_eq!(
            decoded,
            SetResponse::Normal { invoke_id_and_priority: 0xC1, result: data_access_result::OTHER_REASON }
        );
    }

    #[test]
    fn selective_access_by_entry_filters_profile_buffer() {
        use crate::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
        use crate::service::get::AccessSelection;

        let obis = ObisCode::new(1, 0, 99, 1, 0, 0xFF);
        let buffer: Vec<CosemDataType> =
            (1u32..=5).map(|i| CosemDataType::Structure(vec![CosemDataType::DoubleLongUnsigned(i)])).collect();
        let profile = ProfileGeneric::new(ProfileGenericConfig {
            logical_name: obis.clone(),
            version: 1,
            buffer,
            capture_objects: vec![],
            capture_period: 0,
            sort_method: crate::types::attrs::SortMethod::Fifo,
            sort_object: None,
            entries_in_use: 5,
            profile_entries: 10,
        });
        let mut d = RequestDispatcher::new();
        d.add(Box::new(profile));

        // entry_descriptor: entries 2..4 (1-based, inclusive).
        let req = GetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(7, obis, 2),
            access_selection: Some(AccessSelection {
                selector: 2,
                parameters: CosemDataType::Structure(vec![
                    CosemDataType::DoubleLongUnsigned(2),
                    CosemDataType::DoubleLongUnsigned(4),
                    CosemDataType::LongUnsigned(1),
                    CosemDataType::LongUnsigned(0),
                ]),
            }),
        };
        let resp = GetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        match resp {
            GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(rows)), .. } => {
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[0], CosemDataType::Structure(vec![CosemDataType::DoubleLongUnsigned(2)]));
                assert_eq!(rows[2], CosemDataType::Structure(vec![CosemDataType::DoubleLongUnsigned(4)]));
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
    fn set_on_data_value_attribute_succeeds() {
        let mut d = dispatcher_with_data();
        let req = SetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
            value: CosemDataType::LongUnsigned(0x9999),
        };
        let resp = SetResponse::decode(&d.dispatch(&req.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(resp, SetResponse::Normal { invoke_id_and_priority: 0xC1, result: data_access_result::SUCCESS });
        let get = GetRequest::Normal {
            invoke_id_and_priority: 0xC1,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
            access_selection: None,
        };
        let get_resp = GetResponse::decode(&d.dispatch(&get.encode().unwrap()).unwrap()).unwrap();
        assert_eq!(
            get_resp,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::Data(CosemDataType::LongUnsigned(0x9999)),
            }
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
    fn rlrq_is_answered_with_rlre() {
        let mut d = dispatcher_with_data();
        let rlrq =
            crate::service::acse::ReleaseRequest { reason: Some(acse::release_reason::NORMAL), user_information: None }
                .encode_rlrq();
        let resp = d.dispatch(&rlrq).unwrap();
        assert_eq!(resp.first(), Some(&acse::RLRE_TAG));
    }

    #[test]
    fn unsupported_tag_yields_exception_response() {
        let mut d = dispatcher_with_data();
        let resp = d.dispatch(&[tag::DATA_NOTIFICATION, 0x00]).unwrap();
        assert_eq!(resp[0], tag::EXCEPTION_RESPONSE);
    }

    fn push_setup_config() -> crate::classes::push_setup::PushSetupConfig {
        use crate::types::attrs::{ConfirmationParameters, DateTime, SendDestinationAndMethod};
        crate::classes::push_setup::PushSetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 9, 0, 255),
            version: 0,
            push_object_list: vec![],
            send_destination_and_method: SendDestinationAndMethod {
                transport_service: 0,
                destination: b"192.168.0.1:4059".to_vec(),
                message: 0,
            },
            communication_window: vec![],
            randomisation_start_interval: 0,
            number_of_retries: 3,
            repetition_delay: CosemDataType::LongUnsigned(0),
            port_reference: vec![],
            push_client_sap: 1,
            push_protection_parameters: vec![],
            push_operation_method: 0,
            confirmation_parameters: ConfirmationParameters { data: vec![] },
            last_confirmation_date_time: DateTime::new([0u8; 12]),
        }
    }

    #[test]
    fn push_delivery_request_reads_registered_objects() {
        use crate::classes::push_setup::PushSetup;
        use crate::types::attrs::CaptureObjectDefinition;

        let mut d = dispatcher_with_data();
        let mut config = push_setup_config();
        config.push_object_list = vec![CaptureObjectDefinition::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2, 0)];
        let push = PushSetup::new(config);

        let req = d.build_push_delivery_request(&push, 1).unwrap();
        assert_eq!(req.destination, b"192.168.0.1:4059");
        assert_eq!(req.client_sap, 1);
        let decoded = DataNotification::decode(&req.body).unwrap();
        assert_eq!(decoded.notification_body, CosemDataType::LongUnsigned(0x1234));
    }

    #[test]
    fn push_delivery_request_rejects_missing_object() {
        use crate::classes::push_setup::PushSetup;
        use crate::types::attrs::CaptureObjectDefinition;

        let mut d = dispatcher_with_data();
        let mut config = push_setup_config();
        config.push_object_list = vec![CaptureObjectDefinition::new(1, ObisCode::new(9, 9, 9, 9, 9, 9), 2, 0)];
        let push = PushSetup::new(config);

        assert!(d.build_push_delivery_request(&push, 1).is_err());
    }
}
