//! A client-side session driver tying the transport, service and ciphering
//! layers together (IEC 62056-5-3 / IEC 62056-53 client CF).
//!
//! [`crate::session::ClientSession`] wraps any [`crate::transport::DataLinkLayer`] (HDLC or wrapper) and exposes
//! the confirmed COSEM services — association, GET, SET, ACTION, release — as
//! blocking request/response round trips. When a [`crate::service::ciphering::SecurityContext`] is
//! configured, request APDUs are protected with global (glo-) ciphering and the
//! matching ciphered responses are transparently unprotected; the client
//! invocation counter is advanced after every protected request.
//!
//! # Timeouts and retries
//!
//! Use [`ClientSession::builder`] to configure per-request timeouts and
//! automatic retries for transient errors:
//!
//! ```no_run
//! # use spodes_rs::session::ClientSessionBuilder;
//! # use spodes_rs::transport::wrapper::Wrapper;
//! # use spodes_rs::transport::MemoryTransport;
//! # fn example() {
//! let transport = MemoryTransport::new();
//! let wrapper = Wrapper::new(transport, 1, 1024);
//! let mut session = ClientSessionBuilder::new(wrapper)
//!     .request_timeout(std::time::Duration::from_secs(5))
//!     .max_retries(3)
//!     .retry_delay(std::time::Duration::from_millis(200))
//!     .build();
//! # }
//! ```

use std::io;
use std::time::{Duration, Instant};

#[cfg(feature = "tracing")]
use tracing::{debug, error, info, trace, warn};

use crate::obis::ObisCode;
use crate::service::acse;
use crate::service::acse::{AssociationRequest, AssociationResponse, ReleaseRequest, ReleaseResponse};
use crate::service::action::{ActionRequest, ActionResponse};
use crate::service::ciphering::{self, glo, SecurityContext};
use crate::service::get::{GetRequest, GetResponse};
use crate::service::set::{SetRequest, SetResponse};
use crate::service::{invoke_id_and_priority, tag, AttributeDescriptor, MethodDescriptor, RawApdu};
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
    /// The request timed out waiting for a response.
    Timeout,
    /// Maximum number of retries exceeded.
    MaxRetries(u32),
}

/// Configuration for timeouts and retries.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum time to wait for a response before retrying or failing.
    pub request_timeout: Option<Duration>,
    /// Maximum number of retry attempts for transient errors.
    pub max_retries: u32,
    /// Delay between retry attempts.
    pub retry_delay: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { request_timeout: None, max_retries: 0, retry_delay: Duration::from_millis(100) }
    }
}

impl SessionConfig {
    /// Creates a new config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of retries.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the delay between retries.
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "transport I/O error: {e}"),
            SessionError::Service(e) => write!(f, "service error: {e}"),
            SessionError::Cipher(e) => write!(f, "ciphering error: {e:?}"),
            SessionError::UnexpectedApdu(t) => write!(f, "unexpected response APDU tag 0x{t:02X}"),
            SessionError::Timeout => write!(f, "request timed out"),
            SessionError::MaxRetries(n) => write!(f, "maximum retries ({n}) exceeded"),
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

/// Current state of the application association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationState {
    /// No association established.
    Idle,
    /// AARQ sent, waiting for AARE.
    Pending,
    /// Association established and active.
    Associated,
}

/// A blocking client session over a framing sub-layer `L`.
pub struct ClientSession<L: DataLinkLayer> {
    link: L,
    invoke_id: u8,
    high_priority: bool,
    cipher: Option<Ciphers>,
    config: SessionConfig,
    state: AssociationState,
    /// Negotiated application context (from AARQ/AARE).
    application_context: u8,
    /// Negotiated mechanism (from AARQ/AARE).
    mechanism: Option<u8>,
}

/// Builder for AARQ construction with a fluent API.
pub struct AarqBuilder {
    application_context: u8,
    calling_ap_title: Option<Vec<u8>>,
    mechanism_name: Option<u8>,
    calling_authentication_value: Option<Vec<u8>>,
    user_information: Vec<u8>,
}

impl AarqBuilder {
    /// Creates a new AARQ builder with LN referencing (no ciphering).
    pub fn new() -> Self {
        AarqBuilder {
            application_context: acse::application_context::LN,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        }
    }

    /// Sets the application context (LN, SN, LN_CIPHERING, SN_CIPHERING).
    pub fn application_context(mut self, ctx: u8) -> Self {
        self.application_context = ctx;
        self
    }

    /// Sets the calling AP title (client system title) for ciphering.
    pub fn calling_ap_title(mut self, title: Vec<u8>) -> Self {
        self.calling_ap_title = Some(title);
        self
    }

    /// Sets the authentication mechanism (LLS, HLS_MD5, HLS_SHA1, HLS_GMAC).
    pub fn mechanism(mut self, mech: u8) -> Self {
        self.mechanism_name = Some(mech);
        self
    }

    /// Sets the calling authentication value (LLS password or HLS challenge).
    pub fn authentication_value(mut self, value: Vec<u8>) -> Self {
        self.calling_authentication_value = Some(value);
        self
    }

    /// Sets the user information (InitiateRequest APDU).
    pub fn user_information(mut self, info: Vec<u8>) -> Self {
        self.user_information = info;
        self
    }

    /// Builds the AARQ request.
    pub fn build(self) -> AssociationRequest {
        AssociationRequest {
            application_context: self.application_context,
            calling_ap_title: self.calling_ap_title,
            mechanism_name: self.mechanism_name,
            calling_authentication_value: self.calling_authentication_value,
            user_information: self.user_information,
        }
    }
}

impl Default for AarqBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a [`ClientSession`] with custom configuration.
pub struct ClientSessionBuilder<L: DataLinkLayer> {
    link: L,
    config: SessionConfig,
    tx_cipher: Option<SecurityContext>,
    rx_cipher: Option<SecurityContext>,
}

impl<L: DataLinkLayer> ClientSessionBuilder<L> {
    /// Creates a new builder with the given transport link.
    pub fn new(link: L) -> Self {
        ClientSessionBuilder { link, config: SessionConfig::default(), tx_cipher: None, rx_cipher: None }
    }

    /// Sets the request timeout. If a response is not received within this
    /// duration, the request is retried (if retries are configured) or
    /// a [`SessionError::Timeout`] error is returned.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of retry attempts for transient errors
    /// (I/O errors, unexpected APDUs). Set to 0 for no retries.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    /// Sets the delay between retry attempts.
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.config.retry_delay = delay;
        self
    }

    /// Configures global ciphering for the session.
    pub fn with_ciphering(mut self, tx: SecurityContext, rx: SecurityContext) -> Self {
        self.tx_cipher = Some(tx);
        self.rx_cipher = Some(rx);
        self
    }

    /// Builds the [`ClientSession`].
    pub fn build(self) -> ClientSession<L> {
        let cipher = match (self.tx_cipher, self.rx_cipher) {
            (Some(tx), Some(rx)) => Some(Ciphers { tx, rx }),
            _ => None,
        };
        ClientSession {
            link: self.link,
            invoke_id: 1,
            high_priority: true,
            cipher,
            config: self.config,
            state: AssociationState::Idle,
            application_context: acse::application_context::LN,
            mechanism: None,
        }
    }
}

impl<L: DataLinkLayer> ClientSession<L> {
    /// Creates a plaintext session (no APDU ciphering).
    pub fn new(link: L) -> Self {
        ClientSession {
            link,
            invoke_id: 1,
            high_priority: true,
            cipher: None,
            config: SessionConfig::default(),
            state: AssociationState::Idle,
            application_context: acse::application_context::LN,
            mechanism: None,
        }
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
            config: SessionConfig::default(),
            state: AssociationState::Idle,
            application_context: acse::application_context::LN_CIPHERING,
            mechanism: None,
        }
    }

    /// Returns a builder for configuring this session's timeouts and retries.
    pub fn builder(link: L) -> ClientSessionBuilder<L> {
        ClientSessionBuilder::new(link)
    }

    /// Returns the underlying framing layer.
    pub fn into_inner(self) -> L {
        self.link
    }

    /// Returns a reference to the current session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Updates the session configuration.
    pub fn set_config(&mut self, config: SessionConfig) {
        self.config = config;
    }

    /// Sets the request timeout.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.config.request_timeout = Some(timeout);
    }

    /// Sets the maximum number of retries.
    pub fn set_max_retries(&mut self, retries: u32) {
        self.config.max_retries = retries;
    }

    /// Sets the retry delay.
    pub fn set_retry_delay(&mut self, delay: Duration) {
        self.config.retry_delay = delay;
    }

    /// The invoke-id-and-priority octet for the next request.
    fn iiap(&self) -> u8 {
        invoke_id_and_priority(self.invoke_id, true, self.high_priority)
    }

    /// Returns the current association state.
    pub fn state(&self) -> AssociationState {
        self.state
    }

    /// Returns the negotiated application context.
    pub fn application_context(&self) -> u8 {
        self.application_context
    }

    /// Returns the negotiated authentication mechanism, if any.
    pub fn mechanism(&self) -> Option<u8> {
        self.mechanism
    }

    /// Returns true if the session is currently associated.
    pub fn is_associated(&self) -> bool {
        self.state == AssociationState::Associated
    }

    /// Opens an application association by exchanging AARQ / AARE. The ACSE APDUs
    /// are sent as-is (any ciphering is inside their user-information field).
    ///
    /// On success, updates the session state to `Associated` and records the
    /// negotiated application context and mechanism.
    pub fn associate(&mut self, request: &AssociationRequest) -> Result<AssociationResponse, SessionError> {
        #[cfg(feature = "tracing")]
        info!("sending AARQ association request");
        self.state = AssociationState::Pending;
        self.application_context = request.application_context;
        self.mechanism = request.mechanism_name;
        self.link.send_apdu(&request.encode())?;
        let reply = self.link.receive_apdu()?;
        let response = AssociationResponse::decode(&reply)?;
        #[cfg(feature = "tracing")]
        info!(result = response.result, "received AARE association response");
        if response.result == acse::result::ACCEPTED {
            self.state = AssociationState::Associated;
        } else {
            self.state = AssociationState::Idle;
        }
        Ok(response)
    }

    /// Convenience method: associates with no security (mechanism 0).
    pub fn associate_no_security(&mut self, initiate_request: Vec<u8>) -> Result<AssociationResponse, SessionError> {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN)
            .user_information(initiate_request)
            .build();
        self.associate(&aarq)
    }

    /// Convenience method: associates with Low-Level Security (password).
    pub fn associate_lls(
        &mut self,
        password: Vec<u8>,
        initiate_request: Vec<u8>,
    ) -> Result<AssociationResponse, SessionError> {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN)
            .mechanism(acse::mechanism::LLS)
            .authentication_value(password)
            .user_information(initiate_request)
            .build();
        self.associate(&aarq)
    }

    /// Convenience method: associates with High-Level Security (SHA-1).
    pub fn associate_hls_sha1(
        &mut self,
        challenge: Vec<u8>,
        initiate_request: Vec<u8>,
    ) -> Result<AssociationResponse, SessionError> {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN)
            .mechanism(acse::mechanism::HLS_SHA1)
            .authentication_value(challenge)
            .user_information(initiate_request)
            .build();
        self.associate(&aarq)
    }

    /// Convenience method: associates with GMAC (mechanism 5) and ciphering.
    pub fn associate_gmac(
        &mut self,
        client_system_title: Vec<u8>,
        initiate_request: Vec<u8>,
    ) -> Result<AssociationResponse, SessionError> {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN_CIPHERING)
            .calling_ap_title(client_system_title)
            .mechanism(acse::mechanism::HLS_GMAC)
            .user_information(initiate_request)
            .build();
        self.associate(&aarq)
    }

    /// Gracefully releases the association by exchanging RLRQ / RLRE.
    ///
    /// On success, resets the session state to `Idle`.
    pub fn release(&mut self, request: &ReleaseRequest) -> Result<ReleaseResponse, SessionError> {
        #[cfg(feature = "tracing")]
        info!("sending RLRQ release request");
        self.link.send_apdu(&request.encode_rlrq())?;
        let reply = self.link.receive_apdu()?;
        let response = ReleaseResponse::decode_rlre(&reply)?;
        #[cfg(feature = "tracing")]
        info!("received RLRE release response");
        self.state = AssociationState::Idle;
        Ok(response)
    }

    /// Convenience method: releases with normal reason.
    pub fn release_normal(&mut self) -> Result<ReleaseResponse, SessionError> {
        let rlrq = ReleaseRequest { reason: Some(acse::release_reason::NORMAL), user_information: None };
        self.release(&rlrq)
    }

    // ========================================================================
    // Raw APDU support
    // ========================================================================

    /// Sends a raw APDU and receives a raw response without parsing.
    ///
    /// This method bypasses the typed service layer and works directly with
    /// raw bytes, which is useful for:
    /// - Manufacturer-specific APDUs
    /// - Extension APDUs not defined in IEC 62056-5-3
    /// - Testing and debugging
    /// - Custom protocol extensions
    ///
    /// If ciphering is configured, the raw APDU is protected/unprotected
    /// transparently.
    pub fn send_raw(&mut self, apdu: &RawApdu) -> Result<RawApdu, SessionError> {
        #[cfg(feature = "tracing")]
        debug!(tag = format_args!("0x{:02X}", apdu.tag()), body_len = apdu.body().len(), "sending raw APDU");
        let encoded = apdu.encode();
        let outgoing = match &self.cipher {
            None => encoded,
            Some(c) => {
                // Determine the glo tag from the raw tag
                let glo_tag = match apdu.tag() {
                    tag::GET_REQUEST => glo::GET_REQUEST,
                    tag::SET_REQUEST => glo::SET_REQUEST,
                    tag::ACTION_REQUEST => glo::ACTION_REQUEST,
                    tag::GET_RESPONSE => glo::GET_RESPONSE,
                    tag::SET_RESPONSE => glo::SET_RESPONSE,
                    tag::ACTION_RESPONSE => glo::ACTION_RESPONSE,
                    _ => apdu.tag(), // pass through unknown tags
                };
                ciphering::protect(&c.tx, glo_tag, &encoded)?
            }
        };
        self.link.send_apdu(&outgoing)?;
        if let Some(c) = &mut self.cipher {
            c.tx.invocation_counter = c.tx.invocation_counter.wrapping_add(1);
        }

        let reply = self.link.receive_apdu()?;
        let response = match &self.cipher {
            None => RawApdu::from_bytes(&reply)?,
            Some(c) => {
                let (_, plaintext) = ciphering::unprotect(&mut c.rx.clone(), &reply)?;
                RawApdu::from_bytes(&plaintext)?
            }
        };
        #[cfg(feature = "tracing")]
        debug!(tag = format_args!("0x{:02X}", response.tag()), body_len = response.body().len(), "received raw APDU");
        Ok(response)
    }

    /// Sends raw bytes and receives raw bytes without any parsing or protection.
    ///
    /// This is the lowest-level send/receive method, bypassing even the
    /// raw APDU framing. Use for completely custom protocols.
    pub fn send_raw_bytes(&mut self, data: &[u8]) -> Result<Vec<u8>, SessionError> {
        #[cfg(feature = "tracing")]
        debug!(len = data.len(), "sending raw bytes");
        self.link.send_apdu(data)?;
        let reply = self.link.receive_apdu()?;
        #[cfg(feature = "tracing")]
        debug!(len = reply.len(), "received raw bytes");
        Ok(reply)
    }

    /// Creates a raw APDU with the given tag and body.
    pub fn make_raw_apdu(tag: u8, body: Vec<u8>) -> RawApdu {
        RawApdu::new(tag, body)
    }

    /// Parses a raw APDU from bytes.
    pub fn parse_raw_apdu(bytes: &[u8]) -> Result<RawApdu, SessionError> {
        Ok(RawApdu::from_bytes(bytes)?)
    }

    /// Reads one attribute (GET-REQUEST-NORMAL).
    pub fn get(&mut self, class_id: u16, instance: ObisCode, attribute_id: i8) -> Result<GetResponse, SessionError> {
        #[cfg(feature = "tracing")]
        debug!(class_id, instance = %instance, attribute_id, "sending GET request");
        let request = GetRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            attribute: AttributeDescriptor::new(class_id, instance, attribute_id),
            access_selection: None,
        };
        let reply = self.transact(&request.encode()?, glo::GET_REQUEST, tag::GET_RESPONSE)?;
        let response = GetResponse::decode(&reply)?;
        #[cfg(feature = "tracing")]
        debug!("GET response received");
        Ok(response)
    }

    /// Writes one attribute (SET-REQUEST-NORMAL).
    pub fn set(
        &mut self,
        class_id: u16,
        instance: ObisCode,
        attribute_id: i8,
        value: CosemDataType,
    ) -> Result<SetResponse, SessionError> {
        #[cfg(feature = "tracing")]
        debug!(class_id, instance = %instance, attribute_id, "sending SET request");
        let request = SetRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            attribute: AttributeDescriptor::new(class_id, instance, attribute_id),
            access_selection: None,
            value,
        };
        let reply = self.transact(&request.encode()?, glo::SET_REQUEST, tag::SET_RESPONSE)?;
        let response = SetResponse::decode(&reply)?;
        #[cfg(feature = "tracing")]
        debug!("SET response received");
        Ok(response)
    }

    /// Invokes one method (ACTION-REQUEST-NORMAL).
    pub fn action(
        &mut self,
        class_id: u16,
        instance: ObisCode,
        method_id: i8,
        parameters: Option<CosemDataType>,
    ) -> Result<ActionResponse, SessionError> {
        #[cfg(feature = "tracing")]
        debug!(class_id, instance = %instance, method_id, "sending ACTION request");
        let request = ActionRequest::Normal {
            invoke_id_and_priority: self.iiap(),
            method: MethodDescriptor::new(class_id, instance, method_id),
            parameters,
        };
        let reply = self.transact(&request.encode()?, glo::ACTION_REQUEST, tag::ACTION_RESPONSE)?;
        let response = ActionResponse::decode(&reply)?;
        #[cfg(feature = "tracing")]
        debug!("ACTION response received");
        Ok(response)
    }

    /// Sends one request APDU and returns the plaintext response APDU.
    ///
    /// Without ciphering the request is sent verbatim. With ciphering it is
    /// protected under `glo_request_tag`, the invocation counter is advanced, and
    /// the ciphered response is unprotected. The returned APDU is expected to
    /// carry `expected_response_tag`.
    ///
    /// If timeouts and retries are configured via [`SessionConfig`], this method
    /// will retry on transient errors (I/O errors, unexpected APDUs) up to
    /// `max_retries` times with the configured `retry_delay` between attempts.
    fn transact(
        &mut self,
        plain_request: &[u8],
        glo_request_tag: u8,
        expected_response_tag: u8,
    ) -> Result<Vec<u8>, SessionError> {
        let max_attempts = self.config.max_retries + 1;
        let mut last_error = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                #[cfg(feature = "tracing")]
                warn!(attempt, max_attempts, "retrying after transient error");
                std::thread::sleep(self.config.retry_delay);
            }

            let result = self.transact_once(plain_request, glo_request_tag, expected_response_tag);

            match result {
                Ok(reply) => {
                    #[cfg(feature = "tracing")]
                    trace!(attempt, "transaction completed successfully");
                    return Ok(reply);
                }
                Err(SessionError::Io(e)) if is_transient_io(&e) && attempt + 1 < max_attempts => {
                    #[cfg(feature = "tracing")]
                    warn!(attempt, error = %e, "transient I/O error, will retry");
                    last_error = Some(SessionError::Io(e));
                    continue;
                }
                Err(SessionError::UnexpectedApdu(t)) if attempt + 1 < max_attempts => {
                    #[cfg(feature = "tracing")]
                    warn!(attempt, tag = format_args!("0x{t:02X}"), "unexpected APDU tag, will retry");
                    last_error = Some(SessionError::UnexpectedApdu(t));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        #[cfg(feature = "tracing")]
        error!(max_attempts, "all retry attempts exhausted");
        Err(last_error.unwrap_or(SessionError::MaxRetries(max_attempts)))
    }

    /// Single attempt at a transaction (no retries).
    fn transact_once(
        &mut self,
        plain_request: &[u8],
        glo_request_tag: u8,
        expected_response_tag: u8,
    ) -> Result<Vec<u8>, SessionError> {
        let deadline = self.config.request_timeout.map(|t| Instant::now() + t);

        let outgoing = match &self.cipher {
            None => plain_request.to_vec(),
            Some(c) => {
                #[cfg(feature = "tracing")]
                trace!(counter = c.tx.invocation_counter, "encrypting request APDU");
                ciphering::protect(&c.tx, glo_request_tag, plain_request)?
            }
        };
        #[cfg(feature = "tracing")]
        trace!(len = outgoing.len(), "sending APDU");
        self.link.send_apdu(&outgoing)?;
        if let Some(c) = &mut self.cipher {
            // Advance our sending counter for the next protected request.
            c.tx.invocation_counter = c.tx.invocation_counter.wrapping_add(1);
        }

        // Check timeout before receive
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                #[cfg(feature = "tracing")]
                warn!("request timed out before receive");
                return Err(SessionError::Timeout);
            }
        }

        let reply = self.link.receive_apdu()?;

        // Check timeout after receive
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                #[cfg(feature = "tracing")]
                warn!("request timed out after receive");
                return Err(SessionError::Timeout);
            }
        }

        #[cfg(feature = "tracing")]
        trace!(len = reply.len(), "received APDU");

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

/// Checks if an I/O error is transient and worth retrying.
fn is_transient_io(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
    )
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
        let ciphered_response =
            ciphering::protect(&server_ctx, glo::GET_RESPONSE, &response.encode().unwrap()).unwrap();

        let mut link = LoopLink::new();
        link.queue_response(ciphered_response);
        // Outbound context: client title/counter. Inbound context: server title.
        let tx_ctx = SecurityContext::for_suite(policy, suite, ek.clone(), ak.clone(), client_title, 1).unwrap();
        let rx_ctx = SecurityContext::for_suite(policy, suite, ek, ak, server_title, 5).unwrap();
        let mut session = ClientSession::with_ciphering(link, tx_ctx, rx_ctx);
        let got = session.get(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2).unwrap();
        assert_eq!(got, response);

        // The request went out ciphered (glo-get-request tag 0xC8) and the
        // counter advanced.
        let link = session.into_inner();
        assert_eq!(link.sent[0][0], glo::GET_REQUEST);
    }

    // ========================================================================
    // Timeout and retry tests
    // ========================================================================

    #[test]
    fn builder_configures_timeout_and_retries() {
        let link = LoopLink::new();
        let session = ClientSession::builder(link)
            .request_timeout(Duration::from_secs(5))
            .max_retries(3)
            .retry_delay(Duration::from_millis(50))
            .build();

        assert_eq!(session.config().request_timeout, Some(Duration::from_secs(5)));
        assert_eq!(session.config().max_retries, 3);
        assert_eq!(session.config().retry_delay, Duration::from_millis(50));
    }

    #[test]
    fn set_config_updates_session() {
        let link = LoopLink::new();
        let mut session = ClientSession::new(link);

        session.set_request_timeout(Duration::from_secs(10));
        session.set_max_retries(5);
        session.set_retry_delay(Duration::from_millis(200));

        assert_eq!(session.config().request_timeout, Some(Duration::from_secs(10)));
        assert_eq!(session.config().max_retries, 5);
        assert_eq!(session.config().retry_delay, Duration::from_millis(200));
    }

    #[test]
    fn get_retries_on_transient_io_error() {
        use std::sync::{Arc, Mutex};

        struct FailingLink {
            #[allow(dead_code)]
            wrapper: Wrapper<MemoryTransport>,
            fail_count: Arc<Mutex<u32>>,
            fail_until: u32,
        }

        impl FailingLink {
            fn new(fail_until: u32) -> Self {
                FailingLink {
                    wrapper: Wrapper::new(MemoryTransport::new(), 1, 16),
                    fail_count: Arc::new(Mutex::new(0)),
                    fail_until,
                }
            }
        }

        impl DataLinkLayer for FailingLink {
            fn send_apdu(&mut self, _apdu: &[u8]) -> io::Result<()> {
                Ok(())
            }

            fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
                let mut count = self.fail_count.lock().unwrap();
                *count += 1;
                if *count <= self.fail_until {
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, "simulated failure"));
                }
                // Return a valid GET response
                let response = GetResponse::Normal {
                    invoke_id_and_priority: 0xC1,
                    result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
                };
                response.encode().map_err(|e| io::Error::other(e.to_string()))
            }
        }

        let fail_until = 2;
        let link = FailingLink::new(fail_until);

        let mut session = ClientSession::builder(link).max_retries(3).retry_delay(Duration::from_millis(10)).build();

        let got = session.get(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2).unwrap();
        assert_eq!(
            got,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::Data(CosemDataType::LongUnsigned(0x1234)),
            }
        );
    }

    #[test]
    fn get_fails_after_max_retries() {
        struct AlwaysFailLink {
            #[allow(dead_code)]
            wrapper: Wrapper<MemoryTransport>,
        }

        impl AlwaysFailLink {
            fn new() -> Self {
                AlwaysFailLink { wrapper: Wrapper::new(MemoryTransport::new(), 1, 16) }
            }
        }

        impl DataLinkLayer for AlwaysFailLink {
            fn send_apdu(&mut self, _apdu: &[u8]) -> io::Result<()> {
                Ok(())
            }

            fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "always fails"))
            }
        }

        let link = AlwaysFailLink::new();
        let mut session = ClientSession::builder(link).max_retries(2).retry_delay(Duration::from_millis(10)).build();

        let result = session.get(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("expected Io error, got: {other:?}"),
        }
    }

    #[test]
    fn default_config_has_no_retries() {
        let link = LoopLink::new();
        let session = ClientSession::new(link);
        assert_eq!(session.config().max_retries, 0);
        assert_eq!(session.config().request_timeout, None);
    }

    #[test]
    fn session_error_display() {
        assert_eq!(SessionError::Timeout.to_string(), "request timed out");
        assert_eq!(SessionError::MaxRetries(5).to_string(), "maximum retries (5) exceeded");
    }

    // ========================================================================
    // AARQ/AARE tests
    // ========================================================================

    #[test]
    fn aarq_builder_creates_valid_aarq() {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN)
            .mechanism(acse::mechanism::LLS)
            .authentication_value(b"password".to_vec())
            .user_information(vec![0x01, 0x00])
            .build();

        assert_eq!(aarq.application_context, acse::application_context::LN);
        assert_eq!(aarq.mechanism_name, Some(acse::mechanism::LLS));
        assert_eq!(aarq.calling_authentication_value, Some(b"password".to_vec()));
        assert_eq!(aarq.user_information, vec![0x01, 0x00]);
    }

    #[test]
    fn aarq_builder_default_is_ln_no_security() {
        let aarq = AarqBuilder::new().build();
        assert_eq!(aarq.application_context, acse::application_context::LN);
        assert_eq!(aarq.mechanism_name, None);
        assert_eq!(aarq.calling_ap_title, None);
    }

    #[test]
    fn aarq_builder_with_ciphering() {
        let aarq = AarqBuilder::new()
            .application_context(acse::application_context::LN_CIPHERING)
            .calling_ap_title(vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01])
            .mechanism(acse::mechanism::HLS_GMAC)
            .user_information(vec![0x01])
            .build();

        assert_eq!(aarq.application_context, acse::application_context::LN_CIPHERING);
        assert!(aarq.calling_ap_title.is_some());
        assert_eq!(aarq.mechanism_name, Some(acse::mechanism::HLS_GMAC));
    }

    #[test]
    fn associate_updates_state() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: acse::application_context::LN,
            result: acse::result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![],
        };
        link.queue_response(aare.encode());

        let mut session = ClientSession::new(link);
        assert_eq!(session.state(), AssociationState::Idle);
        assert!(!session.is_associated());

        let aarq = AssociationRequest {
            application_context: acse::application_context::LN,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: vec![],
        };
        let resp = session.associate(&aarq).unwrap();
        assert_eq!(resp.result, acse::result::ACCEPTED);
        assert_eq!(session.state(), AssociationState::Associated);
        assert!(session.is_associated());
        assert_eq!(session.application_context(), acse::application_context::LN);
    }

    #[test]
    fn associate_rejected_sets_idle() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: acse::application_context::LN,
            result: acse::result::REJECTED_PERMANENT,
            diagnostic: 1,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![],
        };
        link.queue_response(aare.encode());

        let mut session = ClientSession::new(link);
        let aarq = AssociationRequest {
            application_context: acse::application_context::LN,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: vec![],
        };
        let resp = session.associate(&aarq).unwrap();
        assert_eq!(resp.result, acse::result::REJECTED_PERMANENT);
        assert_eq!(session.state(), AssociationState::Idle);
        assert!(!session.is_associated());
    }

    #[test]
    fn associate_no_security_convenience() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: acse::application_context::LN,
            result: acse::result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![],
        };
        link.queue_response(aare.encode());

        let mut session = ClientSession::new(link);
        let resp = session.associate_no_security(vec![0x01, 0x00]).unwrap();
        assert_eq!(resp.result, acse::result::ACCEPTED);
        assert!(session.is_associated());
        assert_eq!(session.mechanism(), None);
    }

    #[test]
    fn associate_lls_convenience() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: acse::application_context::LN,
            result: acse::result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![],
        };
        link.queue_response(aare.encode());

        let mut session = ClientSession::new(link);
        let resp = session.associate_lls(b"12345678".to_vec(), vec![0x01, 0x00]).unwrap();
        assert_eq!(resp.result, acse::result::ACCEPTED);
        assert!(session.is_associated());
        assert_eq!(session.mechanism(), Some(acse::mechanism::LLS));
    }

    #[test]
    fn release_resets_state() {
        let mut link = LoopLink::new();
        let aare = AssociationResponse {
            application_context: acse::application_context::LN,
            result: acse::result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![],
        };
        link.queue_response(aare.encode());
        // Queue RLRE response
        let rlre = ReleaseRequest { reason: Some(acse::release_reason::NORMAL), user_information: None };
        link.queue_response(rlre.encode_rlre());

        let mut session = ClientSession::new(link);
        let aarq = AssociationRequest {
            application_context: acse::application_context::LN,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: vec![],
        };
        session.associate(&aarq).unwrap();
        assert!(session.is_associated());

        session.release_normal().unwrap();
        assert_eq!(session.state(), AssociationState::Idle);
        assert!(!session.is_associated());
    }

    #[test]
    fn release_normal_convenience() {
        let mut link = LoopLink::new();
        let rlre = ReleaseRequest { reason: Some(acse::release_reason::NORMAL), user_information: None };
        link.queue_response(rlre.encode_rlre());

        let mut session = ClientSession::new(link);
        let resp = session.release_normal().unwrap();
        assert_eq!(resp.reason, Some(acse::release_reason::NORMAL));
    }

    #[test]
    fn aarq_builder_encodes_correctly() {
        let aarq = AarqBuilder::new().mechanism(acse::mechanism::LLS).authentication_value(b"test".to_vec()).build();
        let encoded = aarq.encode();
        // Should be a valid AARQ APDU
        assert_eq!(encoded[0], acse::AARQ_TAG);
        // Should decode back correctly
        let decoded = AssociationRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.mechanism_name, Some(acse::mechanism::LLS));
        assert_eq!(decoded.calling_authentication_value, Some(b"test".to_vec()));
    }

    // ========================================================================
    // Raw APDU tests
    // ========================================================================

    #[test]
    fn raw_apdu_encode_decode_round_trip() {
        let raw = RawApdu::new(0xC0, vec![0x01, 0x02, 0x03]);
        let encoded = raw.encode();
        let decoded = RawApdu::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.tag(), 0xC0);
        assert_eq!(decoded.body(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn raw_apdu_from_bytes_round_trip() {
        let bytes = vec![0xC1, 0x04, 0x01, 0x02, 0x03, 0x04];
        let raw = RawApdu::from_bytes(&bytes).unwrap();
        assert_eq!(raw.tag(), 0xC1);
        assert_eq!(raw.body(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(raw.encode(), bytes);
    }

    #[test]
    fn raw_apdu_empty_body() {
        let raw = RawApdu::new(0xC2, vec![]);
        let encoded = raw.encode();
        assert_eq!(encoded, vec![0xC2, 0x00]);
        let decoded = RawApdu::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.body().len(), 0);
    }

    #[test]
    fn raw_apdu_large_body() {
        let body = vec![0xAA; 256];
        let raw = RawApdu::new(0xC3, body.clone());
        let encoded = raw.encode();
        let decoded = RawApdu::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.body(), &body);
    }

    #[test]
    fn raw_apdu_into_parts() {
        let raw = RawApdu::new(0xC4, vec![0x01, 0x02]);
        let (tag, body) = raw.into_parts();
        assert_eq!(tag, 0xC4);
        assert_eq!(body, vec![0x01, 0x02]);
    }

    #[test]
    fn send_raw_round_trip() {
        let mut link = LoopLink::new();
        let response = RawApdu::new(0xC4, vec![0x08, 0x00, 0x06]);
        link.queue_response(response.encode());

        let mut session = ClientSession::new(link);
        let request = RawApdu::new(0xC0, vec![0xC1, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02]);
        let reply = session.send_raw(&request).unwrap();
        assert_eq!(reply.tag(), 0xC4);
        assert_eq!(reply.body(), &[0x08, 0x00, 0x06]);
    }

    #[test]
    fn send_raw_bytes_round_trip() {
        let mut link = LoopLink::new();
        link.queue_response(vec![0xC4, 0x03, 0x08, 0x00, 0x06]);

        let mut session = ClientSession::new(link);
        let request = vec![0xC0, 0x09, 0xC1, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02];
        let reply = session.send_raw_bytes(&request).unwrap();
        assert_eq!(reply, vec![0xC4, 0x03, 0x08, 0x00, 0x06]);
    }

    #[test]
    fn make_raw_apdu_helper() {
        let raw = ClientSession::<LoopLink>::make_raw_apdu(0xC0, vec![0x01]);
        assert_eq!(raw.tag(), 0xC0);
        assert_eq!(raw.body(), &[0x01]);
    }
}
