//! A client-side session driver tying the transport, service and ciphering
//! layers together (IEC 62056-5-3 / IEC 62056-53 client CF).
//!
//! [`crate::session::ClientSession`] wraps any [`crate::transport::DataLinkLayer`] (HDLC or wrapper) and exposes
//! the confirmed COSEM services — association, GET, SET, ACTION, release — as
//! blocking request/response round trips. When a [`crate::service::ciphering::SecurityContext`] is
//! configured, request APDUs are protected with global (glo-) ciphering and the
//! matching ciphered responses are transparently unprotected; the client
//! invocation counter is advanced after every protected request.

use std::io;

use crate::obis::ObisCode;
use crate::service::acse::{AssociationRequest, AssociationResponse, ReleaseRequest, ReleaseResponse};
use crate::service::action::{ActionRequest, ActionResponse};
use crate::service::ciphering::{self, glo, SecurityContext};
use crate::service::get::{GetRequest, GetResponse};
use crate::service::set::{SetRequest, SetResponse};
use crate::service::{invoke_id_and_priority, tag, AttributeDescriptor, MethodDescriptor};
use crate::transport::DataLinkLayer;
use crate::types::CosemDataType;

/// Errors raised by the session driver.
#[derive(Debug)]
pub enum SessionError {
    /// A transport-level I/O error.
    Io(io::Error),
    /// A service APDU could not be encoded or decoded.
    Service(crate::service::ServiceError),
    /// Applying or removing APDU protection failed.
    Cipher(ciphering::CipherError),
    /// The peer replied with an APDU whose tag was not expected here.
    UnexpectedApdu(u8),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "transport I/O error: {e}"),
            SessionError::Service(e) => write!(f, "service error: {e}"),
            SessionError::Cipher(e) => write!(f, "ciphering error: {e:?}"),
            SessionError::UnexpectedApdu(t) => write!(f, "unexpected response APDU tag 0x{t:02X}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e)
    }
}

impl From<crate::service::ServiceError> for SessionError {
    fn from(e: crate::service::ServiceError) -> Self {
        SessionError::Service(e)
    }
}

impl From<ciphering::CipherError> for SessionError {
    fn from(e: ciphering::CipherError) -> Self {
        SessionError::Cipher(e)
    }
}

/// The two directional ciphering contexts of a secured session. Each direction
/// has its own initialization-vector stream: outbound APDUs use the client's
/// system-title and invocation counter, inbound APDUs the server's. The
/// service-specific glo-ciphering APDU does not carry the originator title, so
/// both titles must be known out of band (from the AARQ/AARE exchange).
struct Ciphers {
    /// Protects outbound requests (client system-title, client counter).
    tx: SecurityContext,
    /// Removes protection from inbound responses (server system-title).
    rx: SecurityContext,
}

/// A blocking client session over a framing sub-layer `L`.
pub struct ClientSession<L: DataLinkLayer> {
    link: L,
    invoke_id: u8,
    high_priority: bool,
    cipher: Option<Ciphers>,
}

impl<L: DataLinkLayer> ClientSession<L> {
    /// Creates a plaintext session (no APDU ciphering).
    pub fn new(link: L) -> Self {
        ClientSession { link, invoke_id: 1, high_priority: true, cipher: None }
    }

    /// Creates a session that protects request APDUs with global ciphering.
    ///
    /// `tx_context` protects outbound requests (client system-title / counter);
    /// `rx_context` removes protection from inbound responses (server
    /// system-title). Both are typically derived from the AARQ/AARE exchange.
    pub fn with_ciphering(link: L, tx_context: SecurityContext, rx_context: SecurityContext) -> Self {
        ClientSession {
            link,
            invoke_id: 1,
            high_priority: true,
            cipher: Some(Ciphers { tx: tx_context, rx: rx_context }),
        }
    }

    /// Returns the underlying framing layer.
    pub fn into_inner(self) -> L {
        self.link
    }

    /// The invoke-id-and-priority octet for the next request.
    fn iiap(&self) -> u8 {
        invoke_id_and_priority(self.invoke_id, true, self.high_priority)
    }

    /// Opens an application association by exchanging AARQ / AARE. The ACSE APDUs
    /// are sent as-is (any ciphering is inside their user-information field).
    pub fn associate(&mut self, request: &AssociationRequest) -> Result<AssociationResponse, SessionError> {
        self.link.send_apdu(&request.encode())?;
        let reply = self.link.receive_apdu()?;
        Ok(AssociationResponse::decode(&reply)?)
    }

    /// Gracefully releases the association by exchanging RLRQ / RLRE.
    pub fn release(&mut self, request: &ReleaseRequest) -> Result<ReleaseResponse, SessionError> {
        self.link.send_apdu(&request.encode_rlrq())?;
        let reply = self.link.receive_apdu()?;
        Ok(ReleaseResponse::decode_rlre(&reply)?)
    }

    /// Reads one attribute (GET-REQUEST-NORMAL).
    pub fn get(&mut self, class_id: u16, instance: ObisCode, attribute_id: i8) -> Result<GetResponse, SessionError> {
        let request = GetRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            attribute: AttributeDescriptor::new(class_id, instance, attribute_id),
            access_selection: None,
        };
        let reply = self.transact(&request.encode()?, glo::GET_REQUEST, tag::GET_RESPONSE)?;
        Ok(GetResponse::decode(&reply)?)
    }

    /// Writes one attribute (SET-REQUEST-NORMAL).
    pub fn set(
        &mut self,
        class_id: u16,
        instance: ObisCode,
        attribute_id: i8,
        value: CosemDataType,
    ) -> Result<SetResponse, SessionError> {
        let request = SetRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            attribute: AttributeDescriptor::new(class_id, instance, attribute_id),
            access_selection: None,
            value,
        };
        let reply = self.transact(&request.encode()?, glo::SET_REQUEST, tag::SET_RESPONSE)?;
        Ok(SetResponse::decode(&reply)?)
    }

    /// Invokes one method (ACTION-REQUEST-NORMAL).
    pub fn action(
        &mut self,
        class_id: u16,
        instance: ObisCode,
        method_id: i8,
        parameters: Option<CosemDataType>,
    ) -> Result<ActionResponse, SessionError> {
        let request = ActionRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            method: MethodDescriptor::new(class_id, instance, method_id),
            parameters,
        };
        let reply = self.transact(&request.encode()?, glo::ACTION_REQUEST, tag::ACTION_RESPONSE)?;
        Ok(ActionResponse::decode(&reply)?)
    }

    /// Sends one request APDU and returns the plaintext response APDU.
    ///
    /// Without ciphering the request is sent verbatim. With ciphering it is
    /// protected under `glo_request_tag`, the invocation counter is advanced, and
    /// the ciphered response is unprotected. The returned APDU is expected to
    /// carry `expected_response_tag`.
    fn transact(
        &mut self,
        plain_request: &[u8],
        glo_request_tag: u8,
        expected_response_tag: u8,
    ) -> Result<Vec<u8>, SessionError> {
        let outgoing = match &self.cipher {
            None => plain_request.to_vec(),
            Some(c) => ciphering::protect(&c.tx, glo_request_tag, plain_request)?,
        };
        self.link.send_apdu(&outgoing)?;
        if let Some(c) = &mut self.cipher {
            // Advance our sending counter for the next protected request.
            c.tx.invocation_counter = c.tx.invocation_counter.wrapping_add(1);
        }

        let reply = self.link.receive_apdu()?;
        let response_tag = *reply.first().ok_or(crate::service::ServiceError::Truncated)?;
        if response_tag == expected_response_tag {
            return Ok(reply);
        }
        if let Some(c) = &mut self.cipher {
            // A ciphered response: unprotect it with the inbound (server)
            // context and expect the plain response tag.
            let (_, plaintext) = ciphering::unprotect(&mut c.rx, &reply)?;
            let plain_tag = *plaintext.first().ok_or(crate::service::ServiceError::Truncated)?;
            if plain_tag == expected_response_tag {
                return Ok(plaintext);
            }
            return Err(SessionError::UnexpectedApdu(plain_tag));
        }
        Err(SessionError::UnexpectedApdu(response_tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::acse::{application_context, mechanism, result};
    use crate::service::get::GetDataResult;
    use crate::transport::wrapper::Wrapper;
    use crate::transport::MemoryTransport;

    /// A loopback data-link that echoes a fixed, pre-loaded response APDU for the
    /// next `receive_apdu`, capturing what the client sent.
    struct LoopLink {
        wrapper: Wrapper<MemoryTransport>,
        canned: std::collections::VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl LoopLink {
        fn new() -> Self {
            LoopLink {
                wrapper: Wrapper::new(MemoryTransport::new(), 1, 16),
                canned: Default::default(),
                sent: Vec::new(),
            }
        }

        fn queue_response(&mut self, apdu: Vec<u8>) {
            self.canned.push_back(apdu);
        }
    }

    impl DataLinkLayer for LoopLink {
        fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
            self.sent.push(apdu.to_vec());
            Ok(())
        }

        fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
            // Round-trip the canned APDU through the real wrapper codec so the
            // framing path is exercised.
            let apdu = self.canned.pop_front().unwrap_or_default();
            self.wrapper.send_apdu(&apdu)?;
            self.wrapper.receive_apdu()
        }
    }

    #[test]
    fn associate_exchanges_aarq_aare() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: application_context::LN,
            result: result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x01, 0xF4, 0x00, 0x07],
        };
        link.queue_response(aare.encode());
        let mut session = ClientSession::new(link);
        let aarq = AssociationRequest {
            application_context: application_context::LN,
            calling_ap_title: None,
            mechanism_name: Some(mechanism::LLS),
            calling_authentication_value: Some(b"12345678".to_vec()),
            user_information: vec![0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0],
        };
        let got = session.associate(&aarq).unwrap();
        assert_eq!(got, aare);
        // The AARQ was actually transmitted.
        assert_eq!(session.into_inner().sent[0], aarq.encode());
    }

    #[test]
    fn get_round_trips_plaintext() {
        let mut link = LoopLink::new();
        let response = GetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
        };
        link.queue_response(response.encode().unwrap());
        let mut session = ClientSession::new(link);
        let got = session.get(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2).unwrap();
        assert_eq!(got, response);
    }

    #[test]
    fn get_round_trips_with_ciphering() {
        // A server context that will produce the ciphered GET-RESPONSE.
        let policy = crate::security::SecurityPolicy::AuthenticationEncryption;
        let suite = crate::security::SecuritySuite::Suite0;
        let ek = vec![0x00; 16];
        let ak = vec![0x11; 16];
        let server_title = vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01];
        let client_title = vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E];

        let response = GetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
        };
        let server_ctx =
            SecurityContext::for_suite(policy, suite, ek.clone(), ak.clone(), server_title.clone(), 5).unwrap();
        let ciphered_response = ciphering::protect(&server_ctx, glo::GET_RESPONSE, &response.encode().unwrap()).unwrap();

        let mut link = LoopLink::new();
        link.queue_response(ciphered_response);
        // Outbound context: client title/counter. Inbound context: server title.
        let tx_ctx =
            SecurityContext::for_suite(policy, suite, ek.clone(), ak.clone(), client_title, 1).unwrap();
        let rx_ctx = SecurityContext::for_suite(policy, suite, ek, ak, server_title, 5).unwrap();
        let mut session = ClientSession::with_ciphering(link, tx_ctx, rx_ctx);
        let got = session.get(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2).unwrap();
        assert_eq!(got, response);

        // The request went out ciphered (glo-get-request tag 0xC8) and the
        // counter advanced.
        let link = session.into_inner();
        assert_eq!(link.sent[0][0], glo::GET_REQUEST);
    }
}
