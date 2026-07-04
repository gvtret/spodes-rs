//! The xDLMS InitiateRequest / InitiateResponse APDUs (IEC 62056-5-3, 11.2).
//!
//! These A-XDR SEQUENCEs are carried opaquely in the `user-information` field of
//! the ACSE AARQ / AARE APDUs (see [`super::acse`]). This module gives them a
//! structured form so callers can negotiate the DLMS version, conformance block
//! and PDU size without hand-assembling bytes.
//!
//! Reference (DLMS Green Book 11.2, LN referencing, no ciphering):
//!
//! ```text
//! request:  01 00 00 00 06 5F1F 04 00 00 7E 1F 04B0
//! response: 08    00 06 5F1F 04 00 00 7E 1F 01F4 0007
//! ```
//!
//! `conformance` is the 24-bit block of the `[APPLICATION 30]` BIT STRING; it is
//! kept here as the low 24 bits of a `u32`.

use super::ServiceError;

/// InitiateRequest APDU tag.
pub const INITIATE_REQUEST_TAG: u8 = 0x01;
/// InitiateResponse APDU tag.
pub const INITIATE_RESPONSE_TAG: u8 = 0x08;

/// The `[APPLICATION 30]` conformance BIT STRING identifier (two octets).
const CONFORMANCE_TAG: [u8; 2] = [0x5F, 0x1F];

/// An xDLMS InitiateRequest APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateRequest {
    /// Optional dedicated key (present only with ciphering).
    pub dedicated_key: Option<Vec<u8>>,
    /// `response-allowed` (BOOLEAN, default TRUE).
    pub response_allowed: bool,
    /// Optional proposed quality-of-service (not used in DLMS/COSEM).
    pub proposed_quality_of_service: Option<i8>,
    /// Proposed DLMS version number (6 for the current profile).
    pub proposed_dlms_version: u8,
    /// Proposed conformance block (low 24 bits).
    pub proposed_conformance: u32,
    /// Client-max-receive-pdu-size.
    pub client_max_receive_pdu_size: u16,
}

impl InitiateRequest {
    /// Encodes the APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![INITIATE_REQUEST_TAG];
        match &self.dedicated_key {
            None => buf.push(0x00),
            Some(key) => {
                buf.push(0x01);
                buf.push(key.len() as u8);
                buf.extend_from_slice(key);
            }
        }
        // response-allowed: usage flag then, if present, the boolean value.
        if self.response_allowed {
            buf.push(0x00); // default TRUE → omit value
        } else {
            buf.push(0x01);
            buf.push(0x00); // FALSE
        }
        match self.proposed_quality_of_service {
            None => buf.push(0x00),
            Some(q) => {
                buf.push(0x01);
                buf.push(q as u8);
            }
        }
        buf.push(self.proposed_dlms_version);
        push_conformance(self.proposed_conformance, &mut buf);
        buf.extend_from_slice(&self.client_max_receive_pdu_size.to_be_bytes());
        buf
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<InitiateRequest, ServiceError> {
        if bytes.first() != Some(&INITIATE_REQUEST_TAG) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let mut pos = 1;
        let dedicated_key = match bytes.get(pos) {
            Some(0x00) => {
                pos += 1;
                None
            }
            Some(0x01) => {
                let len = *bytes.get(pos + 1).ok_or(ServiceError::Truncated)? as usize;
                let start = pos + 2;
                let key = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
                pos = start + len;
                Some(key)
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let response_allowed = match bytes.get(pos) {
            Some(0x00) => {
                pos += 1;
                true
            }
            Some(0x01) => {
                let value = *bytes.get(pos + 1).ok_or(ServiceError::Truncated)? != 0;
                pos += 2;
                value
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let proposed_quality_of_service = match bytes.get(pos) {
            Some(0x00) => {
                pos += 1;
                None
            }
            Some(0x01) => {
                let q = *bytes.get(pos + 1).ok_or(ServiceError::Truncated)? as i8;
                pos += 2;
                Some(q)
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let proposed_dlms_version = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
        pos += 1;
        let (proposed_conformance, n) = take_conformance(&bytes[pos..])?;
        pos += n;
        let b = bytes.get(pos..pos + 2).ok_or(ServiceError::Truncated)?;
        let client_max_receive_pdu_size = u16::from_be_bytes([b[0], b[1]]);
        Ok(InitiateRequest {
            dedicated_key,
            response_allowed,
            proposed_quality_of_service,
            proposed_dlms_version,
            proposed_conformance,
            client_max_receive_pdu_size,
        })
    }
}

/// An xDLMS InitiateResponse APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateResponse {
    /// Optional negotiated quality-of-service (not used in DLMS/COSEM).
    pub negotiated_quality_of_service: Option<i8>,
    /// Negotiated DLMS version number.
    pub negotiated_dlms_version: u8,
    /// Negotiated conformance block (low 24 bits).
    pub negotiated_conformance: u32,
    /// Server-max-receive-pdu-size.
    pub server_max_receive_pdu_size: u16,
    /// VAA-name (0x0007 for LN referencing).
    pub vaa_name: u16,
}

impl InitiateResponse {
    /// Encodes the APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![INITIATE_RESPONSE_TAG];
        match self.negotiated_quality_of_service {
            None => buf.push(0x00),
            Some(q) => {
                buf.push(0x01);
                buf.push(q as u8);
            }
        }
        buf.push(self.negotiated_dlms_version);
        push_conformance(self.negotiated_conformance, &mut buf);
        buf.extend_from_slice(&self.server_max_receive_pdu_size.to_be_bytes());
        buf.extend_from_slice(&self.vaa_name.to_be_bytes());
        buf
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<InitiateResponse, ServiceError> {
        if bytes.first() != Some(&INITIATE_RESPONSE_TAG) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let mut pos = 1;
        let negotiated_quality_of_service = match bytes.get(pos) {
            Some(0x00) => {
                pos += 1;
                None
            }
            Some(0x01) => {
                let q = *bytes.get(pos + 1).ok_or(ServiceError::Truncated)? as i8;
                pos += 2;
                Some(q)
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let negotiated_dlms_version = *bytes.get(pos).ok_or(ServiceError::Truncated)?;
        pos += 1;
        let (negotiated_conformance, n) = take_conformance(&bytes[pos..])?;
        pos += n;
        let b = bytes.get(pos..pos + 2).ok_or(ServiceError::Truncated)?;
        let server_max_receive_pdu_size = u16::from_be_bytes([b[0], b[1]]);
        pos += 2;
        let v = bytes.get(pos..pos + 2).ok_or(ServiceError::Truncated)?;
        let vaa_name = u16::from_be_bytes([v[0], v[1]]);
        Ok(InitiateResponse {
            negotiated_quality_of_service,
            negotiated_dlms_version,
            negotiated_conformance,
            server_max_receive_pdu_size,
            vaa_name,
        })
    }
}

/// Encodes the conformance block: `5F 1F 04 <unused=00> <3 octets>`.
fn push_conformance(conformance: u32, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&CONFORMANCE_TAG);
    buf.push(0x04); // length: unused-bits octet + 3 conformance octets
    buf.push(0x00); // number of unused bits
    let b = conformance.to_be_bytes();
    buf.extend_from_slice(&b[1..]); // low 24 bits
}

/// Decodes a conformance block, returning its 24-bit value and octets consumed.
fn take_conformance(bytes: &[u8]) -> Result<(u32, usize), ServiceError> {
    if bytes.get(..2) != Some(&CONFORMANCE_TAG[..]) {
        return Err(ServiceError::InvalidData);
    }
    let len = *bytes.get(2).ok_or(ServiceError::Truncated)? as usize;
    // The value is <unused-bits> followed by the conformance octets.
    let value = bytes.get(3..3 + len).ok_or(ServiceError::Truncated)?;
    let mut conformance = 0u32;
    for &b in &value[1..] {
        conformance = (conformance << 8) | b as u32;
    }
    Ok((conformance, 3 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_request_matches_green_book_bytes() {
        // DLMS Green Book 11.2, LN referencing, no ciphering.
        let req = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version: 6,
            proposed_conformance: 0x007E1F,
            client_max_receive_pdu_size: 0x04B0,
        };
        let bytes = req.encode();
        assert_eq!(
            bytes,
            vec![0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0]
        );
        assert_eq!(InitiateRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn initiate_response_matches_green_book_bytes() {
        let resp = InitiateResponse {
            negotiated_quality_of_service: None,
            negotiated_dlms_version: 6,
            negotiated_conformance: 0x007E1F,
            server_max_receive_pdu_size: 0x01F4,
            vaa_name: 0x0007,
        };
        let bytes = resp.encode();
        assert_eq!(
            bytes,
            vec![0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x01, 0xF4, 0x00, 0x07]
        );
        assert_eq!(InitiateResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn initiate_request_with_dedicated_key_and_no_response_round_trips() {
        let req = InitiateRequest {
            dedicated_key: Some(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            response_allowed: false,
            proposed_quality_of_service: Some(4),
            proposed_dlms_version: 6,
            proposed_conformance: 0x101D,
            client_max_receive_pdu_size: 0x0200,
        };
        assert_eq!(InitiateRequest::decode(&req.encode()).unwrap(), req);
    }
}
