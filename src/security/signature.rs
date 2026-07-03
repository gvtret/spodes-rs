//! Digital-signature HLS mechanisms.
//!
//! Mechanism 7 (ECDSA) is provided here over the security-suite curves — P-256
//! for suite 1 and P-384 for suite 2 — hashing with SHA-256 / SHA-384 as the
//! suites specify (IEC 62056-5-3 Table 32). Mechanism 10 (GOST 34.10-2018-256)
//! is in [`super::gost3410`].
//!
//! During the HLS handshake the message is `SystemTitle-a ‖ SystemTitle-b ‖
//! challenge_a ‖ challenge_b`; the signer uses its private key and the verifier
//! the peer's public key. Public keys may be given either as a raw `x ‖ y`
//! point or in SEC1 form (with the `0x04` prefix).

use ecdsa::signature::{Signer, Verifier};

use super::SecuritySuite;

/// Errors from signing or verifying.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// The private key was malformed for the curve.
    InvalidPrivateKey,
    /// The public key was malformed for the curve.
    InvalidPublicKey,
    /// The signature was malformed for the curve.
    InvalidSignature,
    /// The signature did not verify.
    VerificationFailed,
    /// The mechanism/suite combination is not a signature scheme handled here.
    UnsupportedSuite,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SignError {}

/// Coordinate length (octets) of the suite's curve, or `None` if the suite has
/// no ECDSA curve.
fn coord_len(suite: SecuritySuite) -> Option<usize> {
    match suite {
        SecuritySuite::Suite1 => Some(32), // P-256
        SecuritySuite::Suite2 => Some(48), // P-384
        SecuritySuite::Suite0 => None,
    }
}

/// Normalizes a public key to SEC1 uncompressed form (`0x04 ‖ x ‖ y`).
fn to_sec1(point: &[u8], coord: usize) -> Vec<u8> {
    if point.len() == 2 * coord {
        let mut v = Vec::with_capacity(1 + point.len());
        v.push(0x04);
        v.extend_from_slice(point);
        v
    } else {
        point.to_vec()
    }
}

/// Signs `message` with an ECDSA private key (raw scalar) on the suite's curve,
/// returning the fixed-size `r ‖ s` signature (64 octets for P-256, 96 for
/// P-384). Signing is deterministic (RFC 6979).
pub fn ecdsa_sign(suite: SecuritySuite, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, SignError> {
    match suite {
        SecuritySuite::Suite1 => {
            use p256::ecdsa::{Signature, SigningKey};
            let sk = SigningKey::from_slice(private_key).map_err(|_| SignError::InvalidPrivateKey)?;
            let sig: Signature = sk.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
        SecuritySuite::Suite2 => {
            use p384::ecdsa::{Signature, SigningKey};
            let sk = SigningKey::from_slice(private_key).map_err(|_| SignError::InvalidPrivateKey)?;
            let sig: Signature = sk.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
        SecuritySuite::Suite0 => Err(SignError::UnsupportedSuite),
    }
}

/// Verifies an ECDSA `r ‖ s` signature over `message` with a public key
/// (raw `x ‖ y` or SEC1) on the suite's curve.
pub fn ecdsa_verify(suite: SecuritySuite, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SignError> {
    let coord = coord_len(suite).ok_or(SignError::UnsupportedSuite)?;
    let sec1 = to_sec1(public_key, coord);
    match suite {
        SecuritySuite::Suite1 => {
            use p256::ecdsa::{Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| SignError::InvalidPublicKey)?;
            let sig = Signature::from_slice(signature).map_err(|_| SignError::InvalidSignature)?;
            vk.verify(message, &sig).map_err(|_| SignError::VerificationFailed)
        }
        SecuritySuite::Suite2 => {
            use p384::ecdsa::{Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| SignError::InvalidPublicKey)?;
            let sig = Signature::from_slice(signature).map_err(|_| SignError::InvalidSignature)?;
            vk.verify(message, &sig).map_err(|_| SignError::VerificationFailed)
        }
        SecuritySuite::Suite0 => Err(SignError::UnsupportedSuite),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_sign_verify_round_trip() {
        // Green Book Annex C client signing key.
        let sk = hex(b"418073C239FA6125011DE4D6CD2E645780289F761BB21BFB0835CB5585E8B373");
        let signing = p256::ecdsa::SigningKey::from_slice(&sk).unwrap();
        let vk = signing.verifying_key();
        let pk = vk.to_encoded_point(false).as_bytes().to_vec(); // 0x04 ‖ x ‖ y
        let msg = b"SystemTitle-C||SystemTitle-S||StoC||CtoS";
        let sig = ecdsa_sign(SecuritySuite::Suite1, &sk, msg).unwrap();
        assert_eq!(sig.len(), 64);
        ecdsa_verify(SecuritySuite::Suite1, &pk, msg, &sig).unwrap();
        // A raw x‖y key (no 0x04) also verifies.
        ecdsa_verify(SecuritySuite::Suite1, &pk[1..], msg, &sig).unwrap();
        // Tampered message fails.
        assert_eq!(
            ecdsa_verify(SecuritySuite::Suite1, &pk, b"other", &sig),
            Err(SignError::VerificationFailed)
        );
    }

    #[test]
    fn p384_sign_verify_round_trip() {
        let sk = [0x11u8; 48];
        let signing = p384::ecdsa::SigningKey::from_slice(&sk).unwrap();
        let pk = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let msg = b"message";
        let sig = ecdsa_sign(SecuritySuite::Suite2, &sk, msg).unwrap();
        assert_eq!(sig.len(), 96);
        ecdsa_verify(SecuritySuite::Suite2, &pk, msg, &sig).unwrap();
    }

    #[test]
    fn suite0_has_no_ecdsa() {
        assert_eq!(ecdsa_sign(SecuritySuite::Suite0, &[0u8; 32], b"x"), Err(SignError::UnsupportedSuite));
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex"),
            }
        }
        s.chunks(2).map(|p| (nib(p[0]) << 4) | nib(p[1])).collect()
    }
}
