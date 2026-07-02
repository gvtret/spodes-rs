//! ACSE association establishment: the AARQ and AARE APDUs (IEC 62056-5-3, 7.2).
//!
//! These are BER-encoded (not A-XDR). The AARQ ([APPLICATION 0], tag 0x60) is
//! sent by the client to open an application association; the AARE
//! ([APPLICATION 1], tag 0x61) is the server's response.
//!
//! The `user_information` field carries the xDLMS InitiateRequest /
//! InitiateResponse APDU; it is treated here as an opaque octet string.
//!
//! Validated against the LLS AARQ of IEC 62056-5-3 Annex D.4.

use super::ServiceError;

/// AARQ APDU tag ([APPLICATION 0], constructed).
pub const AARQ_TAG: u8 = 0x60;
/// AARE APDU tag ([APPLICATION 1], constructed).
pub const AARE_TAG: u8 = 0x61;

/// Association result (AARE field [2]).
pub mod result {
    pub const ACCEPTED: u8 = 0;
    pub const REJECTED_PERMANENT: u8 = 1;
    pub const REJECTED_TRANSIENT: u8 = 2;
}

/// COSEM application-context-name identifiers (last arc of the OID
/// `2.16.756.5.8.1.x`).
pub mod application_context {
    /// Logical name referencing, no ciphering.
    pub const LN: u8 = 1;
    /// Short name referencing, no ciphering.
    pub const SN: u8 = 2;
    /// Logical name referencing with ciphering.
    pub const LN_CIPHERING: u8 = 3;
    /// Short name referencing with ciphering.
    pub const SN_CIPHERING: u8 = 4;
}

/// COSEM authentication-mechanism-name identifiers (last arc of the OID
/// `2.16.756.5.8.2.x`).
pub mod mechanism {
    pub const LOWEST: u8 = 0;
    pub const LLS: u8 = 1;
    pub const HLS_MD5: u8 = 3;
    pub const HLS_SHA1: u8 = 4;
    pub const HLS_GMAC: u8 = 5;
}

const OID_PREFIX_APP_CONTEXT: [u8; 6] = [0x60, 0x85, 0x74, 0x05, 0x08, 0x01];
const OID_PREFIX_MECHANISM: [u8; 6] = [0x60, 0x85, 0x74, 0x05, 0x08, 0x02];

/// An AARQ (application association request) APDU.
#[derive(Debug, Clone, PartialEq)]
pub struct AssociationRequest {
    /// Application-context-name identifier (see [`application_context`]).
    pub application_context: u8,
    /// Calling-AP-title (client system title), present when ciphering is used.
    pub calling_ap_title: Option<Vec<u8>>,
    /// Authentication-mechanism-name identifier, present for LLS/HLS.
    pub mechanism_name: Option<u8>,
    /// Calling-authentication-value (LLS password or HLS CtoS challenge).
    pub calling_authentication_value: Option<Vec<u8>>,
    /// User-information: the xDLMS InitiateRequest APDU (opaque).
    pub user_information: Vec<u8>,
}

impl AssociationRequest {
    /// Encodes the AARQ APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        // [1] application-context-name (OBJECT IDENTIFIER).
        ber_tlv(0xA1, &object_identifier(&OID_PREFIX_APP_CONTEXT, self.application_context), &mut content);
        // [6] calling-AP-title (OCTET STRING) — only with ciphering.
        if let Some(title) = &self.calling_ap_title {
            ber_tlv(0xA6, &octet_string(title), &mut content);
        }
        // Authentication functional unit ([10], [11], [12]) — for LLS/HLS.
        if let Some(mech) = self.mechanism_name {
            // [10] sender-acse-requirements: BIT STRING { authentication(0) }.
            content.extend_from_slice(&[0x8A, 0x02, 0x07, 0x80]);
            // [11] mechanism-name (OBJECT IDENTIFIER, IMPLICIT → raw 7 octets).
            content.push(0x8B);
            let oid = raw_oid(&OID_PREFIX_MECHANISM, mech);
            push_length(oid.len(), &mut content);
            content.extend_from_slice(&oid);
            // [12] calling-authentication-value (EXPLICIT CHOICE charstring [0]).
            if let Some(auth) = &self.calling_authentication_value {
                let mut inner = vec![0x80];
                push_length(auth.len(), &mut inner);
                inner.extend_from_slice(auth);
                ber_tlv(0xAC, &inner, &mut content);
            }
        }
        // [30] user-information (OCTET STRING carrying the InitiateRequest).
        ber_tlv(0xBE, &octet_string(&self.user_information), &mut content);

        let mut apdu = vec![AARQ_TAG];
        push_length(content.len(), &mut apdu);
        apdu.extend_from_slice(&content);
        apdu
    }

    /// Decodes an AARQ APDU.
    pub fn decode(bytes: &[u8]) -> Result<AssociationRequest, ServiceError> {
        let content = outer_content(bytes, AARQ_TAG)?;
        let mut req = AssociationRequest {
            application_context: 0,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        for (tag, value) in TlvIter::new(content) {
            match tag {
                0xA1 => req.application_context = parse_oid_last_arc(value)?,
                0xA6 => req.calling_ap_title = Some(parse_octet_string(value)?),
                0x8B => req.mechanism_name = Some(*value.last().ok_or(ServiceError::Truncated)?),
                0xAC => req.calling_authentication_value = Some(parse_auth_value(value)?),
                0xBE => req.user_information = parse_octet_string(value)?,
                _ => {} // ignore other/optional fields
            }
        }
        Ok(req)
    }
}

/// An AARE (application association response) APDU.
#[derive(Debug, Clone, PartialEq)]
pub struct AssociationResponse {
    /// Application-context-name identifier.
    pub application_context: u8,
    /// Association result (see [`result`]).
    pub result: u8,
    /// Result source diagnostic (the acse-service-user diagnostic value).
    pub diagnostic: u8,
    /// Responding-AP-title (server system title), present with ciphering.
    pub responding_ap_title: Option<Vec<u8>>,
    /// Responding-authentication-value (HLS StoC challenge).
    pub responding_authentication_value: Option<Vec<u8>>,
    /// User-information: the xDLMS InitiateResponse APDU (opaque).
    pub user_information: Vec<u8>,
}

impl AssociationResponse {
    /// Encodes the AARE APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        // [1] application-context-name.
        ber_tlv(0xA1, &object_identifier(&OID_PREFIX_APP_CONTEXT, self.application_context), &mut content);
        // [2] result (INTEGER).
        ber_tlv(0xA2, &[0x02, 0x01, self.result], &mut content);
        // [3] result-source-diagnostic (CHOICE acse-service-user [1]).
        ber_tlv(0xA3, &[0xA1, 0x03, 0x02, 0x01, self.diagnostic], &mut content);
        // [4] responding-AP-title (OCTET STRING) — with ciphering.
        if let Some(title) = &self.responding_ap_title {
            ber_tlv(0xA4, &octet_string(title), &mut content);
        }
        // [10] responding-authentication-value (EXPLICIT CHOICE charstring [0]) — HLS.
        if let Some(auth) = &self.responding_authentication_value {
            let mut inner = vec![0x80];
            push_length(auth.len(), &mut inner);
            inner.extend_from_slice(auth);
            ber_tlv(0xAA, &inner, &mut content);
        }
        // [30] user-information.
        ber_tlv(0xBE, &octet_string(&self.user_information), &mut content);

        let mut apdu = vec![AARE_TAG];
        push_length(content.len(), &mut apdu);
        apdu.extend_from_slice(&content);
        apdu
    }

    /// Decodes an AARE APDU.
    pub fn decode(bytes: &[u8]) -> Result<AssociationResponse, ServiceError> {
        let content = outer_content(bytes, AARE_TAG)?;
        let mut resp = AssociationResponse {
            application_context: 0,
            result: result::REJECTED_PERMANENT,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };
        for (tag, value) in TlvIter::new(content) {
            match tag {
                0xA1 => resp.application_context = parse_oid_last_arc(value)?,
                0xA2 => resp.result = *value.last().ok_or(ServiceError::Truncated)?,
                0xA3 => resp.diagnostic = *value.last().ok_or(ServiceError::Truncated)?,
                0xA4 => resp.responding_ap_title = Some(parse_octet_string(value)?),
                0xAA => resp.responding_authentication_value = Some(parse_auth_value(value)?),
                0xBE => resp.user_information = parse_octet_string(value)?,
                _ => {}
            }
        }
        Ok(resp)
    }
}

// --- BER helpers -----------------------------------------------------------

/// Builds an OBJECT IDENTIFIER TLV value: `06 07 <prefix(6) last_arc>`.
fn object_identifier(prefix: &[u8; 6], last_arc: u8) -> Vec<u8> {
    let mut v = vec![0x06, 0x07];
    v.extend_from_slice(prefix);
    v.push(last_arc);
    v
}

/// The raw 7-octet OID value (no tag), for IMPLICIT contexts.
fn raw_oid(prefix: &[u8; 6], last_arc: u8) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.push(last_arc);
    v
}

/// Builds an OCTET STRING TLV value: `04 <len> <bytes>`.
fn octet_string(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    push_length(bytes.len(), &mut v);
    v.extend_from_slice(bytes);
    v
}

fn ber_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    push_length(value.len(), out);
    out.extend_from_slice(value);
}

fn push_length(length: usize, out: &mut Vec<u8>) {
    if length < 128 {
        out.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let n = 8 - first;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

/// Reads a BER length, returning the length and the number of octets it took.
fn read_length(bytes: &[u8]) -> Result<(usize, usize), ServiceError> {
    let first = *bytes.first().ok_or(ServiceError::Truncated)?;
    if first < 128 {
        Ok((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        let slice = bytes.get(1..1 + n).ok_or(ServiceError::Truncated)?;
        let mut len = 0usize;
        for &b in slice {
            len = (len << 8) | b as usize;
        }
        Ok((len, 1 + n))
    }
}

/// Verifies the outer APDU tag and returns its content octets.
fn outer_content(bytes: &[u8], expected_tag: u8) -> Result<&[u8], ServiceError> {
    let tag = *bytes.first().ok_or(ServiceError::Truncated)?;
    if tag != expected_tag {
        return Err(ServiceError::UnexpectedTag(tag));
    }
    let (len, header) = read_length(&bytes[1..])?;
    let start = 1 + header;
    bytes.get(start..start + len).ok_or(ServiceError::Truncated)
}

/// Extracts the last arc of an application-context or mechanism OID from an
/// `A1`/context value `06 07 <prefix> <arc>`.
fn parse_oid_last_arc(value: &[u8]) -> Result<u8, ServiceError> {
    // value = 06 07 <7 octets>. The arc is the final octet.
    value.last().copied().ok_or(ServiceError::Truncated)
}

/// Extracts the bytes of an inner OCTET STRING (`04 <len> <bytes>`).
fn parse_octet_string(value: &[u8]) -> Result<Vec<u8>, ServiceError> {
    if value.first() != Some(&0x04) {
        return Err(ServiceError::InvalidData);
    }
    let (len, header) = read_length(&value[1..])?;
    let start = 1 + header;
    value.get(start..start + len).map(|s| s.to_vec()).ok_or(ServiceError::Truncated)
}

/// Extracts the authentication value from a `[12]`/`[10]` CHOICE
/// (`80 <len> <bytes>`).
fn parse_auth_value(value: &[u8]) -> Result<Vec<u8>, ServiceError> {
    if value.first() != Some(&0x80) {
        return Err(ServiceError::InvalidData);
    }
    let (len, header) = read_length(&value[1..])?;
    let start = 1 + header;
    value.get(start..start + len).map(|s| s.to_vec()).ok_or(ServiceError::Truncated)
}

/// Iterates over the top-level BER TLVs of a content buffer, yielding
/// `(tag, value)` pairs. Malformed trailing bytes stop the iteration.
struct TlvIter<'a> {
    rest: &'a [u8],
}

impl<'a> TlvIter<'a> {
    fn new(rest: &'a [u8]) -> Self {
        TlvIter { rest }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let tag = self.rest[0];
        let (len, header) = read_length(&self.rest[1..]).ok()?;
        let start = 1 + header;
        let value = self.rest.get(start..start + len)?;
        self.rest = &self.rest[start + len..];
        Some((tag, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aarq_lls_matches_reference_bytes() {
        // IEC 62056-5-3 Annex D.4, LN referencing, LLS.
        let initiate_request = vec![
            0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0,
        ];
        let aarq = AssociationRequest {
            application_context: application_context::LN,
            calling_ap_title: None,
            mechanism_name: Some(mechanism::LLS),
            calling_authentication_value: Some(b"12345678".to_vec()),
            user_information: initiate_request,
        };
        let encoded = aarq.encode();
        let expected = vec![
            0x60, 0x36, // AARQ, length 54
            0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01, // app-context LN
            0x8A, 0x02, 0x07, 0x80, // sender-acse-requirements
            0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01, // mechanism LLS
            0xAC, 0x0A, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // '12345678'
            0xBE, 0x10, 0x04, 0x0E, // user-information
            0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0,
        ];
        assert_eq!(encoded, expected);
        assert_eq!(AssociationRequest::decode(&encoded).unwrap(), aarq);
    }

    #[test]
    fn aarq_no_security_round_trips() {
        let aarq = AssociationRequest {
            application_context: application_context::LN,
            calling_ap_title: None,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: vec![0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0],
        };
        assert_eq!(AssociationRequest::decode(&aarq.encode()).unwrap(), aarq);
    }

    #[test]
    fn aare_accepted_round_trips() {
        let aare = AssociationResponse {
            application_context: application_context::LN,
            result: result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: None,
            responding_authentication_value: None,
            user_information: vec![0x08, 0x00, 0x06, 0x5F, 0x1F, 0x04, 0x00, 0x00, 0x7E, 0x1F, 0x04, 0xB0],
        };
        let encoded = aare.encode();
        assert_eq!(encoded[0], AARE_TAG);
        assert_eq!(AssociationResponse::decode(&encoded).unwrap(), aare);
    }

    #[test]
    fn aare_hls_carries_stoc_and_server_title() {
        let aare = AssociationResponse {
            application_context: application_context::LN_CIPHERING,
            result: result::ACCEPTED,
            diagnostic: 0,
            responding_ap_title: Some(vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E]),
            responding_authentication_value: Some(b"P6wRJ21F".to_vec()),
            user_information: vec![0x08, 0x00],
        };
        let decoded = AssociationResponse::decode(&aare.encode()).unwrap();
        assert_eq!(decoded, aare);
        assert_eq!(decoded.responding_authentication_value.unwrap(), b"P6wRJ21F");
    }
}
