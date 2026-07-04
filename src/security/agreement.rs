//! Elliptic-curve key agreement for security suites 1 and 2 (IEC 62056-5-3,
//! 5.3.4 / DLMS Green Book Annex C).
//!
//! Two parties derive a shared symmetric key from a static/ephemeral EC key pair
//! each. The raw shared secret `Z` is the x-coordinate of the ECDH point
//! (`FE2OS(x)`); it is then run through the NIST SP 800-56A single-step (concat)
//! KDF to obtain the DLMS session key:
//!
//! ```text
//! K = Hash( counter(0x00000001) ‖ Z ‖ AlgorithmID ‖ PartyUInfo ‖ PartyVInfo )
//! ```
//!
//! where the hash is SHA-256 for suite 1 and SHA-384 for suite 2, PartyUInfo /
//! PartyVInfo are the two system-titles, and the encryption key is the leftmost
//! 16 (suite 1) or 32 (suite 2) octets of `K`. Validated against the One-Pass
//! Diffie-Hellman test vector of DLMS Green Book Table C.2.

use sha2::{Digest, Sha256, Sha384};

use super::SecuritySuite;

/// Errors from key agreement.
#[derive(Debug, PartialEq, Eq)]
pub enum AgreementError {
    /// The suite has no elliptic-curve key agreement (suite 0).
    UnsupportedSuite,
    /// The private key was malformed for the curve.
    InvalidPrivateKey,
    /// The peer public key was malformed for the curve.
    InvalidPublicKey,
}

impl std::fmt::Display for AgreementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AgreementError {}

/// Coordinate length (octets) of the suite's curve.
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

/// Computes the raw ECDH shared secret `Z = FE2OS(x)` between our `private_key`
/// (raw scalar) and the peer's `public_key` (raw `x ‖ y` or SEC1) on the suite's
/// curve.
pub fn ecdh(suite: SecuritySuite, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, AgreementError> {
    let coord = coord_len(suite).ok_or(AgreementError::UnsupportedSuite)?;
    let sec1 = to_sec1(public_key, coord);
    match suite {
        SecuritySuite::Suite1 => {
            let sk = p256::SecretKey::from_slice(private_key).map_err(|_| AgreementError::InvalidPrivateKey)?;
            let pk = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| AgreementError::InvalidPublicKey)?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        SecuritySuite::Suite2 => {
            let sk = p384::SecretKey::from_slice(private_key).map_err(|_| AgreementError::InvalidPrivateKey)?;
            let pk = p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| AgreementError::InvalidPublicKey)?;
            let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        SecuritySuite::Suite0 => Err(AgreementError::UnsupportedSuite),
    }
}

/// The NIST SP 800-56A single-step KDF over the suite's hash, producing
/// `output_len` octets from the shared secret `z` and the other-info fields
/// `algorithm_id ‖ party_u_info ‖ party_v_info`.
pub fn kdf(
    suite: SecuritySuite,
    z: &[u8],
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, AgreementError> {
    if suite == SecuritySuite::Suite0 {
        return Err(AgreementError::UnsupportedSuite);
    }
    let mut out = Vec::with_capacity(output_len);
    let mut counter: u32 = 1;
    while out.len() < output_len {
        let block = match suite {
            SecuritySuite::Suite2 => {
                let mut h = Sha384::new();
                h.update(counter.to_be_bytes());
                h.update(z);
                h.update(algorithm_id);
                h.update(party_u_info);
                h.update(party_v_info);
                h.finalize().to_vec()
            }
            _ => {
                let mut h = Sha256::new();
                h.update(counter.to_be_bytes());
                h.update(z);
                h.update(algorithm_id);
                h.update(party_u_info);
                h.update(party_v_info);
                h.finalize().to_vec()
            }
        };
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(output_len);
    Ok(out)
}

/// Performs the full DLMS key agreement: ECDH followed by the KDF, returning the
/// derived AES encryption key (16 octets for suite 1, 32 for suite 2).
///
/// `party_u_info` / `party_v_info` are the originator and recipient
/// system-titles as used in the KDF (Green Book Table C.2).
pub fn agree_key(
    suite: SecuritySuite,
    private_key: &[u8],
    peer_public_key: &[u8],
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
) -> Result<Vec<u8>, AgreementError> {
    let z = ecdh(suite, private_key, peer_public_key)?;
    let key = kdf(suite, &z, algorithm_id, party_u_info, party_v_info, suite.aes_key_len())?;
    Ok(key)
}

/// Derives the ephemeral public key (`FE2OS(x) ‖ FE2OS(y)`) from an ephemeral
/// private key on the suite's curve, for embedding as key-ciphered-data.
pub fn public_key(suite: SecuritySuite, private_key: &[u8]) -> Result<Vec<u8>, AgreementError> {
    // The SEC1 uncompressed encoding is `0x04 ‖ x ‖ y`; DLMS wants `x ‖ y`.
    match suite {
        SecuritySuite::Suite1 => {
            let sk = p256::SecretKey::from_slice(private_key).map_err(|_| AgreementError::InvalidPrivateKey)?;
            Ok(sk.public_key().to_sec1_bytes()[1..].to_vec())
        }
        SecuritySuite::Suite2 => {
            let sk = p384::SecretKey::from_slice(private_key).map_err(|_| AgreementError::InvalidPrivateKey)?;
            Ok(sk.public_key().to_sec1_bytes()[1..].to_vec())
        }
        SecuritySuite::Suite0 => Err(AgreementError::UnsupportedSuite),
    }
}

/// The originator side of a One-Pass Diffie-Hellman agreed-key exchange
/// (C(1e, 1s), IEC 62056-5-3 Annex C.2).
///
/// The originator holds an ephemeral key pair and the recipient's static public
/// key. It returns the derived AES session key and its ephemeral public key
/// (`FE2OS(x) ‖ FE2OS(y)`), which the caller embeds as the `key-ciphered-data`
/// of an agreed-key general-ciphering APDU so the recipient can derive the same
/// key. `party_u_info` / `party_v_info` are the KDF system-titles and must match
/// on both sides.
pub fn originator_agree(
    suite: SecuritySuite,
    ephemeral_private: &[u8],
    recipient_static_public: &[u8],
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AgreementError> {
    let ephemeral_public = public_key(suite, ephemeral_private)?;
    let key = agree_key(suite, ephemeral_private, recipient_static_public, algorithm_id, party_u_info, party_v_info)?;
    Ok((key, ephemeral_public))
}

/// The recipient side of a One-Pass Diffie-Hellman agreed-key exchange.
///
/// The recipient holds a static private key and receives the originator's
/// ephemeral public key (the `key-ciphered-data`). It derives the same session
/// key. `party_u_info` / `party_v_info` must be identical to the originator's.
pub fn recipient_agree(
    suite: SecuritySuite,
    recipient_static_private: &[u8],
    ephemeral_public: &[u8],
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
) -> Result<Vec<u8>, AgreementError> {
    agree_key(suite, recipient_static_private, ephemeral_public, algorithm_id, party_u_info, party_v_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn kdf_matches_green_book_c2_client_key() {
        // DLMS Green Book Table C.2 (One-Pass Diffie-Hellman, suite 1):
        // KDF(Z, AlgID, Sys-TC, Sys-TS) with the client shared secret.
        let z = hb("0D4385BA0DD756CBCAB9887EB538396EE8F090A14C1079B4359F115B977F4615");
        let alg_id = hb("60857405080300"); // AES-GCM-128
        let sys_tc = hb("4D4D4D0000BC614E");
        let sys_ts = hb("4D4D4D0000000001");
        let k = kdf(SecuritySuite::Suite1, &z, &alg_id, &sys_tc, &sys_ts, 32).unwrap();
        assert_eq!(k, hb("59A71FD81C929A86A99438DA17A66C058C6A93FD3065F5EE16A05D775927659B"));
        // The AES-128 encryption key is the leftmost 16 octets.
        let ek = kdf(SecuritySuite::Suite1, &z, &alg_id, &sys_tc, &sys_ts, 16).unwrap();
        assert_eq!(ek, hb("59A71FD81C929A86A99438DA17A66C05"));
    }

    #[test]
    fn kdf_matches_green_book_c2_server_key() {
        // Server side: KDF(Z-GC-S, AlgID, Sys-TS, Sys-TC).
        let z = hb("2B4302DC49790E2E78D990CFB52ED6E2F273DECE441A2D95E4301B93812A9FAC");
        let alg_id = hb("60857405080300");
        let sys_ts = hb("4D4D4D0000000001");
        let sys_tc = hb("4D4D4D0000BC614E");
        let ek = kdf(SecuritySuite::Suite1, &z, &alg_id, &sys_ts, &sys_tc, 16).unwrap();
        assert_eq!(ek, hb("F0184BDA9466BFA4601A64A7EF46504A"));
    }

    #[test]
    fn ecdh_round_trip_suite1() {
        // Two P-256 key pairs derive the same shared secret Z.
        let d_a = hb("418073C239FA6125011DE4D6CD2E645780289F761BB21BFB0835CB5585E8B373");
        let d_b = hb("AE55414FFE079F9FC95649536BD1C2B5653D200813727E07D501A8B550C69207");
        let pk_a = p256::SecretKey::from_slice(&d_a).unwrap().public_key();
        let pk_b = p256::SecretKey::from_slice(&d_b).unwrap().public_key();
        let pk_a_bytes = pk_a.to_sec1_bytes().to_vec();
        let pk_b_bytes = pk_b.to_sec1_bytes().to_vec();
        let z_ab = ecdh(SecuritySuite::Suite1, &d_a, &pk_b_bytes).unwrap();
        let z_ba = ecdh(SecuritySuite::Suite1, &d_b, &pk_a_bytes).unwrap();
        assert_eq!(z_ab, z_ba);
        assert_eq!(z_ab.len(), 32);
    }

    #[test]
    fn ecdh_round_trip_suite2() {
        let d_a = [0x11u8; 48];
        let d_b = [0x22u8; 48];
        let pk_a = p384::SecretKey::from_slice(&d_a).unwrap().public_key().to_sec1_bytes().to_vec();
        let pk_b = p384::SecretKey::from_slice(&d_b).unwrap().public_key().to_sec1_bytes().to_vec();
        let z_ab = agree_key(SecuritySuite::Suite2, &d_a, &pk_b, b"\x60\x85\x74\x05\x08\x03\x02", b"U", b"V").unwrap();
        let z_ba = agree_key(SecuritySuite::Suite2, &d_b, &pk_a, b"\x60\x85\x74\x05\x08\x03\x02", b"U", b"V").unwrap();
        assert_eq!(z_ab, z_ba);
        assert_eq!(z_ab.len(), 32); // AES-256 key
    }

    #[test]
    fn suite0_has_no_agreement() {
        assert_eq!(ecdh(SecuritySuite::Suite0, &[0u8; 32], &[0u8; 64]), Err(AgreementError::UnsupportedSuite));
    }

    #[test]
    fn one_pass_agreement_derives_shared_key() {
        // The client (originator) holds an ephemeral key pair; the server
        // (recipient) holds a static key pair.
        let ephemeral = hb("47DAB03842E5B6E74828EF4F449B378D7DD1A5DAE1FFCA5AE0B0BE0AD18EC57E");
        let server_static = hb("AE55414FFE079F9FC95649536BD1C2B5653D200813727E07D501A8B550C69207");
        let server_public = public_key(SecuritySuite::Suite1, &server_static).unwrap();
        let alg_id = hb("60857405080300");
        let sys_c = hb("4D4D4D0000BC614E");
        let sys_s = hb("4D4D4D0000000001");

        let (client_key, ephemeral_public) =
            originator_agree(SecuritySuite::Suite1, &ephemeral, &server_public, &alg_id, &sys_c, &sys_s).unwrap();
        let server_key =
            recipient_agree(SecuritySuite::Suite1, &server_static, &ephemeral_public, &alg_id, &sys_c, &sys_s).unwrap();

        // Both sides derive the same AES-128 session key.
        assert_eq!(client_key, server_key);
        assert_eq!(client_key.len(), 16);
    }

    #[test]
    fn agreed_key_is_usable_for_apdu_ciphering() {
        use crate::security::SecurityPolicy;
        use crate::service::ciphering::{self, glo, SecurityContext};
        use crate::service::general_ciphering::{GeneralCiphering, KeyInfo};

        let ephemeral = hb("47DAB03842E5B6E74828EF4F449B378D7DD1A5DAE1FFCA5AE0B0BE0AD18EC57E");
        let server_static = hb("AE55414FFE079F9FC95649536BD1C2B5653D200813727E07D501A8B550C69207");
        let server_public = public_key(SecuritySuite::Suite1, &server_static).unwrap();
        let alg_id = hb("60857405080300");
        let sys_c = vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E];
        let sys_s = vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01];

        // Client derives the session key and advertises its ephemeral key in an
        // agreed-key general-ciphering APDU.
        let (client_key, ephemeral_public) =
            originator_agree(SecuritySuite::Suite1, &ephemeral, &server_public, &alg_id, &sys_c, &sys_s).unwrap();
        let carrier = GeneralCiphering {
            transaction_id: vec![0x01; 8],
            originator_system_title: sys_c.clone(),
            recipient_system_title: sys_s.clone(),
            date_time: Vec::new(),
            other_information: Vec::new(),
            key_info: KeyInfo::AgreedKey { key_parameters: vec![0x01], key_ciphered_data: ephemeral_public },
            ciphered_content: Vec::new(),
        };

        // Server parses the APDU, extracts the ephemeral key and derives the
        // same session key.
        let parsed = GeneralCiphering::decode(&carrier.encode()).unwrap();
        let KeyInfo::AgreedKey { key_ciphered_data, .. } = &parsed.key_info else {
            panic!("expected agreed-key");
        };
        let server_key =
            recipient_agree(SecuritySuite::Suite1, &server_static, key_ciphered_data, &alg_id, &sys_c, &sys_s).unwrap();
        assert_eq!(client_key, server_key);

        // The agreed key protects and unprotects an APDU end to end (client
        // system-title in the IV on both directions of this exchange).
        let client_ctx = SecurityContext::for_suite(
            SecurityPolicy::AuthenticationEncryption,
            SecuritySuite::Suite1,
            client_key,
            vec![0x11; 16],
            sys_c.clone(),
            1,
        )
        .unwrap();
        let plaintext = vec![0xC4, 0x01, 0xC1, 0x00, 0x12, 0x12, 0x34];
        let protected = ciphering::protect(&client_ctx, glo::GET_RESPONSE, &plaintext).unwrap();
        let mut server_ctx = SecurityContext::for_suite(
            SecurityPolicy::AuthenticationEncryption,
            SecuritySuite::Suite1,
            server_key,
            vec![0x11; 16],
            sys_c,
            0,
        )
        .unwrap();
        let (_, recovered) = ciphering::unprotect(&mut server_ctx, &protected).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
