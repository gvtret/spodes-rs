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

use cmac::{Cmac, KeyInit, Mac};
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

/// The AES S-box.
#[rustfmt::skip]
const S_BOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// The AES round constants.
#[rustfmt::skip]
const R_CON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// GF(2^8) `xtime` multiply-by-2 with the AES reduction polynomial.
fn xtime(v: u8) -> u8 {
    if v & 0x80 != 0 {
        (v << 1) ^ 0x1b
    } else {
        v << 1
    }
}

/// AES-128 single-block encryption with on-the-fly key expansion. `key` is
/// mutated in place to the final round key, matching the reference `Aes1Encrypt`.
fn aes128_block(block: &mut [u8; 16], key: &mut [u8; 16]) {
    for &rcon in R_CON.iter() {
        // AddRoundKey combined with SubBytes.
        for i in 0..16 {
            block[i] = S_BOX[(block[i] ^ key[i]) as usize];
        }
        // ShiftRows.
        let t = block[1];
        block[1] = block[5];
        block[5] = block[9];
        block[9] = block[13];
        block[13] = t;
        block.swap(2, 10);
        block.swap(6, 14);
        let t = block[15];
        block[15] = block[11];
        block[11] = block[7];
        block[7] = block[3];
        block[3] = t;
        // MixColumns (all rounds except the last).
        if rcon != 0x36 {
            for c in 0..4 {
                let b = c << 2;
                let all = block[b] ^ block[b + 1] ^ block[b + 2] ^ block[b + 3];
                let first = block[b];
                block[b] ^= xtime(block[b] ^ block[b + 1]) ^ all;
                block[b + 1] ^= xtime(block[b + 1] ^ block[b + 2]) ^ all;
                block[b + 2] ^= xtime(block[b + 2] ^ block[b + 3]) ^ all;
                block[b + 3] ^= xtime(block[b + 3] ^ first) ^ all;
            }
        }
        // Expand the round key in place.
        key[0] ^= S_BOX[key[13] as usize] ^ rcon;
        key[1] ^= S_BOX[key[14] as usize];
        key[2] ^= S_BOX[key[15] as usize];
        key[3] ^= S_BOX[key[12] as usize];
        for i in 4..16 {
            key[i] ^= key[i - 4];
        }
    }
    // Final AddRoundKey.
    for i in 0..16 {
        block[i] ^= key[i];
    }
}

/// HLS mechanism 2 (manufacturer-specific "high" authentication).
///
/// DLMS/COSEM does not specify mechanism 2, so implementations follow the widely
/// deployed Gurux / Texas-Instruments scheme: AES-128 over the zero-padded
/// `challenge`, keyed by the zero-padded `secret`. The challenge and secret are
/// padded to a common length that is a multiple of 16 (the larger of the two,
/// rounded up); each 16-octet block of the padded challenge is then encrypted.
/// As in the reference, the key is carried mutated from one block to the next,
/// so multi-block challenges are not plain ECB.
pub fn manufacturer_aes(secret: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut len = challenge.len().div_ceil(16) * 16;
    if secret.len() > challenge.len() {
        len = secret.len().div_ceil(16) * 16;
    }
    let mut key = [0u8; 16];
    let n = secret.len().min(16);
    key[..n].copy_from_slice(&secret[..n]);
    let mut out = vec![0u8; len];
    out[..challenge.len()].copy_from_slice(challenge);
    for chunk in out.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        aes128_block(&mut block, &mut key);
        chunk.copy_from_slice(&block);
    }
    out
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
    fn manufacturer_aes_matches_gurux_reference() {
        // Reference vectors produced by the Gurux Aes1Encrypt / Secure routine
        // (the algorithm this meter family uses for mechanism 2).
        // Single block: secret "12345678", challenge 00112233 44556677.
        let out = manufacturer_aes(b"12345678", &hex(b"0011223344556677"));
        assert_eq!(out, hex(b"3ce1760a845b8570bb2a2afe44392d0e"));

        // Multi-block: 16-octet secret 00..0f, 32-octet challenge 80..9f. The
        // second block is keyed by the mutated key, not plain ECB.
        let secret: Vec<u8> = (0u8..16).collect();
        let challenge: Vec<u8> = (0u8..32).map(|i| 0x80 + i).collect();
        let out = manufacturer_aes(&secret, &challenge);
        assert_eq!(out, hex(b"ac26591c0f8bd80ee7c7e3a2d14e2b2292dcb47a3f51368a5c18314b86eb4ae0"));
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
        assert_eq!(answer_c, hex(b"4c375b843898b6f0a0744051f74e42f2a944581d46c495e743e97abdcd9d7c58"));
        // f(CtoS) swaps both pairs.
        let answer_s = hash_with_titles(AuthMechanism::HlsGostStreebog, &secret, &st_s, &st_c, &ctos, &stoc).unwrap();
        assert_eq!(answer_s, hex(b"55dcd7e597cc90ec215c2faae8f86c0a1d707ddeac1adf5cbd17dfaa5378c500"));
    }

    #[test]
    fn sha256_hash_with_titles_is_deterministic() {
        let a =
            hash_with_titles(AuthMechanism::HlsSha256, b"secret", b"CCCCCCCC", b"SSSSSSSS", &[1, 2], &[3, 4]).unwrap();
        assert_eq!(a.len(), 32);
        let b =
            hash_with_titles(AuthMechanism::HlsSha256, b"secret", b"CCCCCCCC", b"SSSSSSSS", &[1, 2], &[3, 4]).unwrap();
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
