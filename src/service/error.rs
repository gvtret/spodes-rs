//! Error-reporting APDUs (IEC 62056-5-3): the EXCEPTION-RESPONSE used with LN
//! referencing and the ConfirmedServiceError used with SN referencing.
//!
//! EXCEPTION-RESPONSE (`[216]`, tag 0xD8) is returned when a request cannot be
//! served for a reason not tied to a specific object (association not
//! established, PDU too long, deciphering error, …). ConfirmedServiceError
//! (`[14]`, tag 0x0E) reports the same class of failure in the SN world and, most
//! commonly, an InitiateRequest that the server cannot accept.

use super::{tag, ServiceError};

/// `state-error` values of an EXCEPTION-RESPONSE.
pub mod state_error {
    /// The service is not allowed in the current state.
    pub const SERVICE_NOT_ALLOWED: u8 = 1;
    /// The service is not known.
    pub const SERVICE_UNKNOWN: u8 = 2;
}

/// `service-error` values of an EXCEPTION-RESPONSE.
pub mod service_error {
    /// The operation is not possible.
    pub const OPERATION_NOT_POSSIBLE: u8 = 1;
    /// The service is not supported.
    pub const SERVICE_NOT_SUPPORTED: u8 = 2;
    /// Other reason.
    pub const OTHER_REASON: u8 = 3;
    /// The request PDU is too long.
    pub const PDU_TOO_LONG: u8 = 4;
    /// A deciphering error occurred.
    pub const DECIPHERING_ERROR: u8 = 5;
    /// The invocation counter was invalid (replay protection).
    pub const INVOCATION_COUNTER_ERROR: u8 = 6;
}

/// An EXCEPTION-RESPONSE APDU.
///
/// The optional `operation` field (present only with `invocation-counter-error`,
/// carrying the lowest acceptable invocation counter) is not modelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionResponse {
    /// The state-error code (see [`state_error`]).
    pub state_error: u8,
    /// The service-error code (see [`service_error`]).
    pub service_error: u8,
}

impl ExceptionResponse {
    /// Encodes the APDU: `D8 <state-error> <service-error>`.
    pub fn encode(&self) -> Vec<u8> {
        vec![tag::EXCEPTION_RESPONSE, self.state_error, self.service_error]
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<ExceptionResponse, ServiceError> {
        if bytes.first() != Some(&tag::EXCEPTION_RESPONSE) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let state_error = *bytes.get(1).ok_or(ServiceError::Truncated)?;
        let service_error = *bytes.get(2).ok_or(ServiceError::Truncated)?;
        Ok(ExceptionResponse { state_error, service_error })
    }
}

/// ConfirmedServiceError CHOICE selector (which service failed).
pub mod service {
    /// `initiateError` — the InitiateRequest failed.
    pub const INITIATE_ERROR: u8 = 1;
    /// `getStatus`.
    pub const GET_STATUS: u8 = 2;
    /// `read`.
    pub const READ: u8 = 5;
    /// `write`.
    pub const WRITE: u8 = 6;
}

/// ServiceError CHOICE selector (the error category).
pub mod category {
    /// `application-reference`.
    pub const APPLICATION_REFERENCE: u8 = 1;
    /// `hardware-resource`.
    pub const HARDWARE_RESOURCE: u8 = 2;
    /// `initiate` — an InitiateRequest error.
    pub const INITIATE: u8 = 6;
    /// `access`.
    pub const ACCESS: u8 = 9;
}

/// A ConfirmedServiceError APDU: a nested CHOICE of `service`, error `category`
/// and the final enumerated `value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedServiceError {
    /// Which service failed (see [`service`]).
    pub service: u8,
    /// The error category (see [`category`]).
    pub category: u8,
    /// The enumerated error value within the category.
    pub value: u8,
}

impl ConfirmedServiceError {
    /// Encodes the APDU: `0E <service> <category> <value>`.
    pub fn encode(&self) -> Vec<u8> {
        vec![tag::CONFIRMED_SERVICE_ERROR, self.service, self.category, self.value]
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<ConfirmedServiceError, ServiceError> {
        if bytes.first() != Some(&tag::CONFIRMED_SERVICE_ERROR) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        Ok(ConfirmedServiceError {
            service: *bytes.get(1).ok_or(ServiceError::Truncated)?,
            category: *bytes.get(2).ok_or(ServiceError::Truncated)?,
            value: *bytes.get(3).ok_or(ServiceError::Truncated)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_response_round_trips() {
        // Association not established: service-not-allowed / operation-not-possible.
        let ex = ExceptionResponse {
            state_error: state_error::SERVICE_NOT_ALLOWED,
            service_error: service_error::OPERATION_NOT_POSSIBLE,
        };
        assert_eq!(ex.encode(), vec![0xD8, 0x01, 0x01]);
        assert_eq!(ExceptionResponse::decode(&ex.encode()).unwrap(), ex);
    }

    #[test]
    fn confirmed_service_error_matches_reference_bytes() {
        // IEC 61334-6 Example 3: 0E 01 06 02 — initiateError / initiate /
        // incompatible-conformance.
        let e = ConfirmedServiceError { service: service::INITIATE_ERROR, category: category::INITIATE, value: 2 };
        assert_eq!(e.encode(), vec![0x0E, 0x01, 0x06, 0x02]);
        assert_eq!(ConfirmedServiceError::decode(&e.encode()).unwrap(), e);
    }
}
