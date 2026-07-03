//! Four-pass HLS handshake computations for every supported mechanism.
//!
//! During High Level Security the client processes the server challenge `StoC`
//! and the server processes the client challenge `CtoS`; each side verifies the
//! peer's processed value before the association is established
//! (IEC 62056-5-3 Table 32; Р 1323565.1 §7.5).
//!
//! Each function computes `f(challenge)` for one mechanism. The GMAC mechanism
//! (5) lives in the Association LN class; the signature mechanisms (7 ECDSA and
//! 10 GOST 34.10) require a private key and are not computed here.

use cmac::{Cmac, Mac};
use kuznyechik::Kuznyechik;
use sha2::Digest;

use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use streebog::Streebog256;

use super::AuthMechanism;

/// Hashes the concatenation of `parts` with digest `D`.
fn digest_concat<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = D::new();
    for part in parts {
        d.update(part);
    }
    d.finalize().to_vec()
}

/// Mechanisms 3 (MD5) and 4 (SHA-1): `f(challenge) = HASH(challenge ‖ secret)`.
///
/// Returns `None` for other mechanisms.
pub fn hash_legacy(mechanism: AuthMechanism, challenge: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    match mechanism {
        AuthMechanism::HlsMd5 => Some(digest_concat::<Md5>(&[challenge, secret])),
        AuthMechanism::HlsSha1 => Some(digest_concat::<Sha1>(&[challenge, secret])),
        _ => None,
    }
}

/// Mechanisms 6 (SHA-256) and 9 (Streebog-256):
/// `f = HASH(secret ‖ st_a ‖ st_b ‖ challenge_a ‖ challenge_b)`.
///
/// For `f(StoC)` use `st_a = system-title-C`, `st_b = system-title-S`,
/// `challenge_a = StoC`, `challenge_b = CtoS`; for `f(CtoS)` swap both pairs
/// (IEC 62056-5-3 Table 32 mechanism 6; Р 1323565.1 §7.5.2 mechanism 9).
///
/// Returns `None` for other mechanisms.
pub fn hash_with_titles(
    mechanism: AuthMechanism,
    secret: &[u8],
    st_a: &[u8],
    st_b: &[u8],
    challenge_a: &[u8],
    challenge_b: &[u8],
) -> Option<Vec<u8>> {
    let parts = [secret, st_a, st_b, challenge_a, challenge_b];
    match mechanism {
        AuthMechanism::HlsSha256 => Some(digest_concat::<Sha256>(&parts)),
        AuthMechanism::HlsGostStreebog => Some(digest_concat::<Streebog256>(&parts)),
        _ => None,
    }
}

/// Mechanism 8 (HLS CMAC, GOST): `KUZN_CMAC(LSB256(K_EM), iv ‖ SC ‖ challenge_a ‖ challenge_b)`.
///
/// `K_EM` is the 512-bit global encryption/authentication key; its least
/// significant 256 bits (the last 32 octets) form the Kuznyechik CMAC key. The
/// resulting 16-octet MAC becomes the tail of `f = SC ‖ IC ‖ MAC`
/// (Р 1323565.1 §7.5.1). `iv` is `system-title ‖ IC`.
pub fn gost_cmac(
    k_em: &[u8],
    iv: &[u8],
    security_control: u8,
    challenge_a: &[u8],
    challenge_b: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if k_em.len() != 64 {
        return Err("K_EM must be 64 octets (512 bits)");
    }
    let key = &k_em[32..]; // LSB256(K_EM)
    let mut mac = Cmac::<Kuznyechik>::new_from_slice(key).map_err(|_| "invalid CMAC key length")?;
    mac.update(iv);
    mac.update(&[security_control]);
    mac.update(challenge_a);
    mac.update(challenge_b);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn sha1_legacy_matches() {
        // f(challenge) = SHA-1(challenge ‖ secret).
        let out = hash_legacy(AuthMechanism::HlsSha1, &[0xAA, 0xBB], b"secret").unwrap();
        let mut h = Sha1::new();
        h.update([0xAA, 0xBB]);
        h.update(b"secret");
        assert_eq!(out, h.finalize().to_vec());
    }

    #[test]
    fn streebog_matches_r1323565_a5_2_vector() {
        // Р 1323565.1, Annex A.5.2 (mechanism 9, HLS GOST34112018-256).
        let secret = hex(b"78797a7b7c7d7e7f707172737475767788898a8b8c8d8e8f8081828384858687");
        let st_c = hex(b"ff00ee11dd22cc33");
        let st_s = hex(b"bb44aa5599668877");
        let stoc = hex(b"8899aabbccddeeff");
        let ctos = hex(b"0011223344556677");
        let answer_c = hash_with_titles(AuthMechanism::HlsGostStreebog, &secret, &st_c, &st_s, &stoc, &ctos).unwrap();
        assert_eq!(
            answer_c,
            hex(b"4c375b843898b6f0a0744051f74e42f2a944581d46c495e743e97abdcd9d7c58")
        );
        // f(CtoS) swaps both pairs.
        let answer_s = hash_with_titles(AuthMechanism::HlsGostStreebog, &secret, &st_s, &st_c, &ctos, &stoc).unwrap();
        assert_eq!(
            answer_s,
            hex(b"55dcd7e597cc90ec215c2faae8f86c0a1d707ddeac1adf5cbd17dfaa5378c500")
        );
    }

    #[test]
    fn sha256_hash_with_titles_is_deterministic() {
        let a = hash_with_titles(AuthMechanism::HlsSha256, b"secret", b"CCCCCCCC", b"SSSSSSSS", &[1, 2], &[3, 4]).unwrap();
        assert_eq!(a.len(), 32);
        let b = hash_with_titles(AuthMechanism::HlsSha256, b"secret", b"CCCCCCCC", b"SSSSSSSS", &[1, 2], &[3, 4]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn gost_cmac_produces_16_octet_mac_and_verifies() {
        let k_em = hex(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let iv = hex(b"4d4d4d0000bc614e01234567"); // system-title ‖ IC
        let stoc = hex(b"8899aabbccddeeff");
        let ctos = hex(b"0011223344556677");
        let mac = gost_cmac(&k_em, &iv, 0x30, &stoc, &ctos).unwrap();
        assert_eq!(mac.len(), 16);
        // Recomputing over the same data verifies.
        let again = gost_cmac(&k_em, &iv, 0x30, &stoc, &ctos).unwrap();
        assert_eq!(mac, again);
        // K_EM must be 512 bits.
        assert!(gost_cmac(&[0u8; 32], &iv, 0x30, &stoc, &ctos).is_err());
    }
}
