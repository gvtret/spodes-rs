//! DLMS/COSEM security model.
//!
//! This module gathers the three orthogonal security concepts:
//!
//! * [`SecuritySuite`] — the cryptographic suite (0, 1 or 2) selecting the
//!   authenticated-encryption, signature, key-agreement and hash algorithms
//!   (IEC 62056-5-3, 5.3.7 / DLMS Green Book Table 19).
//! * [`SecurityPolicy`] — the protection level applied to APDUs (none,
//!   authentication, encryption or authenticated encryption).
//! * [`AuthMechanism`] — the authentication mechanism negotiated when opening an
//!   application association (mechanism_id 0..10), including the Russian GOST
//!   profile of Р 1323565.1, §7.5.
//!
//! The four-pass HLS handshake computations live in [`hls`].

pub mod hls;

/// A DLMS/COSEM security suite (IEC 62056-5-3, 5.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySuite {
    /// Suite 0 — AES-GCM-128, AES-128 key wrap. No PKI.
    Suite0,
    /// Suite 1 — ECDH-ECDSA-AES-GCM-128-SHA-256 (curve P-256).
    Suite1,
    /// Suite 2 — ECDH-ECDSA-AES-GCM-256-SHA-384 (curve P-384).
    Suite2,
}

impl SecuritySuite {
    /// The 4-bit suite id carried in the security control byte.
    pub fn id(&self) -> u8 {
        match self {
            SecuritySuite::Suite0 => 0,
            SecuritySuite::Suite1 => 1,
            SecuritySuite::Suite2 => 2,
        }
    }

    /// Parses a suite from its id.
    pub fn from_id(id: u8) -> Option<SecuritySuite> {
        match id {
            0 => Some(SecuritySuite::Suite0),
            1 => Some(SecuritySuite::Suite1),
            2 => Some(SecuritySuite::Suite2),
            _ => None,
        }
    }

    /// The standard suite name.
    pub fn name(&self) -> &'static str {
        match self {
            SecuritySuite::Suite0 => "AES-GCM-128",
            SecuritySuite::Suite1 => "ECDH-ECDSA-AES-GCM-128-SHA-256",
            SecuritySuite::Suite2 => "ECDH-ECDSA-AES-GCM-256-SHA-384",
        }
    }

    /// The AES key length in octets for authenticated encryption (16 or 32).
    pub fn aes_key_len(&self) -> usize {
        match self {
            SecuritySuite::Suite0 | SecuritySuite::Suite1 => 16,
            SecuritySuite::Suite2 => 32,
        }
    }

    /// Whether the suite provides digital signatures and key agreement (PKI).
    pub fn has_public_key(&self) -> bool {
        !matches!(self, SecuritySuite::Suite0)
    }
}

/// The protection level applied to an APDU. Together with the security suite it
/// determines the security control byte (SC) of a ciphered APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPolicy {
    /// No protection.
    None,
    /// Authentication only (GMAC / AES-GCM tag over the plaintext).
    Authentication,
    /// Encryption only.
    Encryption,
    /// Authenticated encryption (both).
    AuthenticationEncryption,
}

impl SecurityPolicy {
    /// The authentication/encryption bits of the security control byte
    /// (bit 4 = authentication, bit 5 = encryption).
    pub fn security_control_bits(&self) -> u8 {
        match self {
            SecurityPolicy::None => 0x00,
            SecurityPolicy::Authentication => 0x10,
            SecurityPolicy::Encryption => 0x20,
            SecurityPolicy::AuthenticationEncryption => 0x30,
        }
    }

    /// Derives the policy from a security control byte.
    pub fn from_security_control(sc: u8) -> SecurityPolicy {
        match (sc & 0x10 != 0, sc & 0x20 != 0) {
            (false, false) => SecurityPolicy::None,
            (true, false) => SecurityPolicy::Authentication,
            (false, true) => SecurityPolicy::Encryption,
            (true, true) => SecurityPolicy::AuthenticationEncryption,
        }
    }

    /// Builds the full security control byte for this policy and suite.
    pub fn security_control_byte(&self, suite: SecuritySuite) -> u8 {
        self.security_control_bits() | (suite.id() & 0x0F)
    }
}

/// An HLS/LLS authentication mechanism (mechanism_id 0..10).
///
/// Mechanisms 0..7 are defined by IEC 62056-5-3 / the DLMS Green Book;
/// mechanisms 8..10 are the Russian GOST profile of Р 1323565.1, §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthMechanism {
    /// (0) No authentication (lowest level security).
    None,
    /// (1) Low Level Security — password.
    Lls,
    /// (2) HLS, manufacturer-specific.
    HlsManufacturer,
    /// (3) HLS with MD5 (not recommended).
    HlsMd5,
    /// (4) HLS with SHA-1 (not recommended).
    HlsSha1,
    /// (5) HLS with GMAC.
    HlsGmac,
    /// (6) HLS with SHA-256.
    HlsSha256,
    /// (7) HLS with ECDSA.
    HlsEcdsa,
    /// (8) HLS CMAC — Kuznyechik CMAC (GOST, Р 1323565.1).
    HlsGostCmac,
    /// (9) HLS GOST34112018-256 — Streebog-256 hash (GOST, Р 1323565.1).
    HlsGostStreebog,
    /// (10) HLS GOST34102018-256 — GOST 34.10 signature (GOST, Р 1323565.1).
    HlsGostSignature,
}

impl AuthMechanism {
    /// The mechanism id (last arc of the mechanism-name OID).
    pub fn id(&self) -> u8 {
        match self {
            AuthMechanism::None => 0,
            AuthMechanism::Lls => 1,
            AuthMechanism::HlsManufacturer => 2,
            AuthMechanism::HlsMd5 => 3,
            AuthMechanism::HlsSha1 => 4,
            AuthMechanism::HlsGmac => 5,
            AuthMechanism::HlsSha256 => 6,
            AuthMechanism::HlsEcdsa => 7,
            AuthMechanism::HlsGostCmac => 8,
            AuthMechanism::HlsGostStreebog => 9,
            AuthMechanism::HlsGostSignature => 10,
        }
    }

    /// Parses a mechanism from its id.
    pub fn from_id(id: u8) -> Option<AuthMechanism> {
        Some(match id {
            0 => AuthMechanism::None,
            1 => AuthMechanism::Lls,
            2 => AuthMechanism::HlsManufacturer,
            3 => AuthMechanism::HlsMd5,
            4 => AuthMechanism::HlsSha1,
            5 => AuthMechanism::HlsGmac,
            6 => AuthMechanism::HlsSha256,
            7 => AuthMechanism::HlsEcdsa,
            8 => AuthMechanism::HlsGostCmac,
            9 => AuthMechanism::HlsGostStreebog,
            10 => AuthMechanism::HlsGostSignature,
            _ => return None,
        })
    }

    /// The COSEM authentication-mechanism-name OID `2.16.756.5.8.2.<id>`,
    /// encoded as the 7 raw octets of the OBJECT IDENTIFIER value.
    pub fn oid(&self) -> [u8; 7] {
        [0x60, 0x85, 0x74, 0x05, 0x08, 0x02, self.id()]
    }

    /// Whether the mechanism is a High Level Security mechanism (uses the
    /// four-pass challenge/response handshake).
    pub fn is_hls(&self) -> bool {
        self.id() >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_suite_ids_and_key_lengths() {
        assert_eq!(SecuritySuite::Suite0.id(), 0);
        assert_eq!(SecuritySuite::Suite2.id(), 2);
        assert_eq!(SecuritySuite::from_id(1), Some(SecuritySuite::Suite1));
        assert_eq!(SecuritySuite::from_id(3), None);
        assert_eq!(SecuritySuite::Suite1.aes_key_len(), 16);
        assert_eq!(SecuritySuite::Suite2.aes_key_len(), 32);
        assert!(!SecuritySuite::Suite0.has_public_key());
        assert!(SecuritySuite::Suite2.has_public_key());
    }

    #[test]
    fn security_policy_maps_to_control_byte() {
        assert_eq!(SecurityPolicy::None.security_control_bits(), 0x00);
        assert_eq!(SecurityPolicy::Authentication.security_control_bits(), 0x10);
        assert_eq!(SecurityPolicy::Encryption.security_control_bits(), 0x20);
        assert_eq!(SecurityPolicy::AuthenticationEncryption.security_control_bits(), 0x30);
        // Suite id occupies the low nibble.
        assert_eq!(
            SecurityPolicy::AuthenticationEncryption.security_control_byte(SecuritySuite::Suite2),
            0x32
        );
        assert_eq!(SecurityPolicy::from_security_control(0x30), SecurityPolicy::AuthenticationEncryption);
        assert_eq!(SecurityPolicy::from_security_control(0x10), SecurityPolicy::Authentication);
    }

    #[test]
    fn all_mechanisms_round_trip_and_have_oids() {
        for id in 0..=10u8 {
            let m = AuthMechanism::from_id(id).unwrap();
            assert_eq!(m.id(), id);
            let oid = m.oid();
            assert_eq!(&oid[..6], &[0x60, 0x85, 0x74, 0x05, 0x08, 0x02]);
            assert_eq!(oid[6], id);
        }
        assert_eq!(AuthMechanism::from_id(11), None);
        // GOST mechanisms are HLS.
        assert!(AuthMechanism::HlsGostStreebog.is_hls());
        assert!(!AuthMechanism::Lls.is_hls());
    }
}
