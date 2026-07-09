//! Service-specific glo-/ded-ciphering of xDLMS APDUs (IEC 62056-5-3, 5.7).
//!
//! A ciphered APDU has the form
//!
//! ```text
//! tag | length | SC | IC | [ciphertext] | [tag]
//! ```
//!
//! where the security header `SC ‖ IC` is the 1-octet security control byte and
//! the 4-octet invocation counter. The initialization vector is
//! `system-title ‖ IC`, the block cipher key is the (global or dedicated)
//! encryption key `EK`, and — when authentication is applied — the additional
//! authenticated data is `SC ‖ AK` (authenticated encryption) or
//! `SC ‖ AK ‖ plaintext` (authentication only). The GCM tag is truncated to 12
//! octets (security suite 0, AES-GCM-128).
//!
//! Validated against the authenticated-encryption test vector of IEC 62056-5-3
//! Annex E.5.

use aead::AeadInOut;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::{Aes128, Aes256};
use aes_gcm::{AesGcm, KeyInit, Nonce, Tag};

/// AES-128-GCM with a 96-bit (12-octet) authentication tag.
type Aes128Gcm12 = AesGcm<Aes128, U12, U12>;
/// AES-256-GCM with a 96-bit (12-octet) authentication tag.
type Aes256Gcm12 = AesGcm<Aes256, U12, U12>;

/// Bit masks of the security control byte (SC), IEC 62056-5-3 Table 27.
pub mod security_control {
    /// Authentication is applied (bit 4).
    pub const AUTHENTICATION: u8 = 0x10;
    /// Encryption is applied (bit 5).
    pub const ENCRYPTION: u8 = 0x20;
    /// The broadcast key set is used instead of the unicast one (bit 6).
    pub const KEY_SET_BROADCAST: u8 = 0x40;
    /// Compression is applied (bit 7).
    pub const COMPRESSION: u8 = 0x80;
    /// Convenience value: authenticated encryption with security suite 0.
    pub const AUTHENTICATED_ENCRYPTION: u8 = AUTHENTICATION | ENCRYPTION;
}

/// Ciphered-APDU tags for service-specific global ciphering.
pub mod glo {
    /// `glo-initiate-request`.
    pub const INITIATE_REQUEST: u8 = 0x21;
    /// `glo-initiate-response`.
    pub const INITIATE_RESPONSE: u8 = 0x28;
    /// `glo-get-request`.
    pub const GET_REQUEST: u8 = 0xC8;
    /// `glo-set-request`.
    pub const SET_REQUEST: u8 = 0xC9;
    /// `glo-action-request`.
    pub const ACTION_REQUEST: u8 = 0xCB;
    /// `glo-get-response`.
    pub const GET_RESPONSE: u8 = 0xCC;
    /// `glo-set-response`.
    pub const SET_RESPONSE: u8 = 0xCD;
    /// `glo-action-response`.
    pub const ACTION_RESPONSE: u8 = 0xCF;
}

/// Ciphered-APDU tags for service-specific dedicated ciphering.
pub mod ded {
    /// `ded-get-request`.
    pub const GET_REQUEST: u8 = 0xD0;
    /// `ded-set-request`.
    pub const SET_REQUEST: u8 = 0xD1;
    /// `ded-action-request`.
    pub const ACTION_REQUEST: u8 = 0xD3;
    /// `ded-get-response`.
    pub const GET_RESPONSE: u8 = 0xD4;
    /// `ded-set-response`.
    pub const SET_RESPONSE: u8 = 0xD5;
    /// `ded-action-response`.
    pub const ACTION_RESPONSE: u8 = 0xD7;
}

/// Errors from ciphering / deciphering.
#[derive(Debug, PartialEq, Eq)]
pub enum CipherError {
    /// The system title was not 8 octets.
    InvalidSystemTitle,
    /// The encryption key was not 16 or 32 octets.
    InvalidKey,
    /// The ciphered APDU was too short for its security header.
    Truncated,
    /// The authentication tag did not verify.
    AuthenticationFailed,
    /// The AES-GCM engine reported an error.
    CryptoError,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CipherError {}

/// The security material and parameters for one ciphering operation.
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Security control byte (SC).
    pub security_control: u8,
    /// Block cipher (encryption) key, 16 or 32 octets.
    pub encryption_key: Vec<u8>,
    /// Authentication key (AK), used in the additional authenticated data.
    pub authentication_key: Vec<u8>,
    /// System title, 8 octets (forms the IV together with the IC).
    pub system_title: Vec<u8>,
    /// Invocation counter (IC).
    pub invocation_counter: u32,
}

impl SecurityContext {
    /// Builds a context for a given protection level and security suite,
    /// validating that the encryption key length matches the suite
    /// (16 octets for suites 0/1, 32 for suite 2) and deriving the security
    /// control byte from the policy and the suite id.
    pub fn for_suite(
        policy: crate::security::SecurityPolicy,
        suite: crate::security::SecuritySuite,
        encryption_key: Vec<u8>,
        authentication_key: Vec<u8>,
        system_title: Vec<u8>,
        invocation_counter: u32,
    ) -> Result<SecurityContext, CipherError> {
        if encryption_key.len() != suite.aes_key_len() {
            return Err(CipherError::InvalidKey);
        }
        Ok(SecurityContext {
            security_control: policy.security_control_byte(suite),
            encryption_key,
            authentication_key,
            system_title,
            invocation_counter,
        })
    }

    fn authentication(&self) -> bool {
        self.security_control & security_control::AUTHENTICATION != 0
    }

    fn encryption(&self) -> bool {
        self.security_control & security_control::ENCRYPTION != 0
    }

    fn iv(&self) -> Result<[u8; 12], CipherError> {
        if self.system_title.len() != 8 {
            return Err(CipherError::InvalidSystemTitle);
        }
        let mut iv = [0u8; 12];
        iv[..8].copy_from_slice(&self.system_title);
        iv[8..].copy_from_slice(&self.invocation_counter.to_be_bytes());
        Ok(iv)
    }
}

/// Protects `plaintext` (a plain xDLMS APDU) and returns the ciphered APDU with
/// the given `ciphered_tag` (see [`glo`] / [`ded`]).
pub fn protect(ctx: &SecurityContext, ciphered_tag: u8, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let iv = ctx.iv()?;
    let sc = ctx.security_control;

    let mut protected = Vec::new();
    match (ctx.authentication(), ctx.encryption()) {
        (true, true) => {
            // Authenticated encryption: AAD = SC ‖ AK, output = ciphertext ‖ tag.
            let aad = [&[sc][..], &ctx.authentication_key].concat();
            let mut buf = plaintext.to_vec();
            let tag = gcm_encrypt_in_place(&ctx.encryption_key, &iv, &aad, &mut buf)?;
            protected.extend_from_slice(&buf);
            protected.extend_from_slice(&tag);
        }
        (true, false) => {
            // Authentication only: AAD = SC ‖ AK ‖ plaintext, output = plaintext ‖ tag.
            let aad = [&[sc][..], &ctx.authentication_key, plaintext].concat();
            let mut empty = Vec::new();
            let tag = gcm_encrypt_in_place(&ctx.encryption_key, &iv, &aad, &mut empty)?;
            protected.extend_from_slice(plaintext);
            protected.extend_from_slice(&tag);
        }
        (false, true) => {
            // Encryption only: no AAD, no tag, output = ciphertext.
            let mut buf = plaintext.to_vec();
            gcm_encrypt_in_place(&ctx.encryption_key, &iv, &[], &mut buf)?;
            protected.extend_from_slice(&buf);
        }
        (false, false) => protected.extend_from_slice(plaintext),
    }

    // tag | length | SC | IC | protected.
    let mut body = Vec::with_capacity(5 + protected.len());
    body.push(sc);
    body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
    body.extend_from_slice(&protected);

    let mut apdu = vec![ciphered_tag];
    push_length(body.len(), &mut apdu);
    apdu.extend_from_slice(&body);
    Ok(apdu)
}

/// Removes protection from a ciphered APDU, returning `(ciphered_tag, plaintext)`.
///
/// The invocation counter carried in the header is written into `ctx` so the
/// same context can decipher a following APDU with the peer's counter.
pub fn unprotect(ctx: &mut SecurityContext, apdu: &[u8]) -> Result<(u8, Vec<u8>), CipherError> {
    let ciphered_tag = *apdu.first().ok_or(CipherError::Truncated)?;
    let (len, header) = read_length(&apdu[1..]).ok_or(CipherError::Truncated)?;
    let body = apdu.get(1 + header..1 + header + len).ok_or(CipherError::Truncated)?;
    if body.len() < 5 {
        return Err(CipherError::Truncated);
    }
    let sc = body[0];
    ctx.security_control = sc;
    ctx.invocation_counter = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
    let protected = &body[5..];
    let iv = ctx.iv()?;

    let plaintext = match (ctx.authentication(), ctx.encryption()) {
        (true, true) => {
            if protected.len() < 12 {
                return Err(CipherError::Truncated);
            }
            let (ct, tag) = protected.split_at(protected.len() - 12);
            let aad = [&[sc][..], &ctx.authentication_key].concat();
            gcm_decrypt(&ctx.encryption_key, &iv, &aad, ct, tag)?
        }
        (true, false) => {
            if protected.len() < 12 {
                return Err(CipherError::Truncated);
            }
            let (plain, tag) = protected.split_at(protected.len() - 12);
            let aad = [&[sc][..], &ctx.authentication_key, plain].concat();
            // Verify by recomputing the tag over an empty message.
            let mut empty = Vec::new();
            let expected = gcm_encrypt_in_place(&ctx.encryption_key, &iv, &aad, &mut empty)?;
            if expected.as_slice() != tag {
                return Err(CipherError::AuthenticationFailed);
            }
            plain.to_vec()
        }
        (false, true) => {
            let mut buf = protected.to_vec();
            gcm_decrypt_no_tag(&ctx.encryption_key, &iv, &mut buf)?;
            buf
        }
        (false, false) => protected.to_vec(),
    };
    Ok((ciphered_tag, plaintext))
}

/// Encrypts `buf` in place and returns the 12-octet authentication tag.
fn gcm_encrypt_in_place(key: &[u8], iv: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 12], CipherError> {
    let nonce = Nonce::<U12>::from(*iv);
    let tag = match key.len() {
        16 => Aes128Gcm12::new_from_slice(key)
            .map_err(|_| CipherError::InvalidKey)?
            .encrypt_inout_detached(&nonce, aad, buf.into())
            .map_err(|_| CipherError::CryptoError)?,
        32 => Aes256Gcm12::new_from_slice(key)
            .map_err(|_| CipherError::InvalidKey)?
            .encrypt_inout_detached(&nonce, aad, buf.into())
            .map_err(|_| CipherError::CryptoError)?,
        _ => return Err(CipherError::InvalidKey),
    };
    let mut out = [0u8; 12];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypts `ct` and verifies the 12-octet `tag`, returning the plaintext.
fn gcm_decrypt(key: &[u8], iv: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, CipherError> {
    let nonce = Nonce::<U12>::from(*iv);
    let tag = Tag::<U12>::try_from(tag).map_err(|_| CipherError::InvalidKey)?;
    let mut buf = ct.to_vec();
    match key.len() {
        16 => Aes128Gcm12::new_from_slice(key)
            .map_err(|_| CipherError::InvalidKey)?
            .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
            .map_err(|_| CipherError::AuthenticationFailed)?,
        32 => Aes256Gcm12::new_from_slice(key)
            .map_err(|_| CipherError::InvalidKey)?
            .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
            .map_err(|_| CipherError::AuthenticationFailed)?,
        _ => return Err(CipherError::InvalidKey),
    }
    Ok(buf)
}

/// Decrypts `buf` in place with encryption only (no tag verification): recompute
/// the keystream by "encrypting" against an all-zero tag placeholder is not
/// possible, so decrypt with a throwaway tag over empty AAD via GCM's CTR core.
fn gcm_decrypt_no_tag(key: &[u8], iv: &[u8; 12], buf: &mut [u8]) -> Result<(), CipherError> {
    // GCM decryption is CTR-mode keystream XOR; recover the plaintext by
    // encrypting the ciphertext with the same key/nonce (CTR is symmetric).
    let nonce = Nonce::<U12>::from(*iv);
    match key.len() {
        16 => {
            Aes128Gcm12::new_from_slice(key)
                .map_err(|_| CipherError::InvalidKey)?
                .encrypt_inout_detached(&nonce, &[], buf.into())
                .map_err(|_| CipherError::CryptoError)?;
        }
        32 => {
            Aes256Gcm12::new_from_slice(key)
                .map_err(|_| CipherError::InvalidKey)?
                .encrypt_inout_detached(&nonce, &[], buf.into())
                .map_err(|_| CipherError::CryptoError)?;
        }
        _ => return Err(CipherError::InvalidKey),
    }
    Ok(())
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

fn read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 128 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        let slice = bytes.get(1..1 + n)?;
        let mut len = 0usize;
        for &b in slice {
            len = (len << 8) | b as usize;
        }
        Some((len, 1 + n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &[u8]) -> Vec<u8> {
        fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'F' => c - b'A' + 10,
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            }
        }
        s.chunks(2).map(|p| (nib(p[0]) << 4) | nib(p[1])).collect()
    }

    fn ctx() -> SecurityContext {
        SecurityContext {
            security_control: security_control::AUTHENTICATED_ENCRYPTION,
            encryption_key: hex(b"000102030405060708090A0B0C0D0E0F"),
            authentication_key: hex(b"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
            system_title: hex(b"4D4D4D0000BC614E"),
            invocation_counter: 0x01234567,
        }
    }

    #[test]
    fn protect_matches_blue_book_e5_vector() {
        // IEC 62056-5-3 Annex E.5: authenticated encryption of an InitiateResponse.
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let apdu = protect(&ctx(), glo::INITIATE_RESPONSE, &plaintext).unwrap();
        let expected = hex(b"281F30012345678912\
14A0845E475714383F65BC19745CA235906525E4F3E1C893");
        assert_eq!(apdu, expected);
    }

    #[test]
    fn protect_then_unprotect_round_trips() {
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let apdu = protect(&ctx(), glo::GET_RESPONSE, &plaintext).unwrap();
        let (tag, recovered) = unprotect(&mut ctx(), &apdu).unwrap();
        assert_eq!(tag, glo::GET_RESPONSE);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn unprotect_detects_tampering() {
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let mut apdu = protect(&ctx(), glo::GET_RESPONSE, &plaintext).unwrap();
        let n = apdu.len();
        apdu[n - 1] ^= 0x01; // corrupt the tag
        assert_eq!(unprotect(&mut ctx(), &apdu), Err(CipherError::AuthenticationFailed));
    }

    #[test]
    fn for_suite_validates_key_length_and_builds_sc() {
        use crate::security::{SecurityPolicy, SecuritySuite};
        // Suite 2 requires a 32-octet key; a 16-octet one is rejected.
        assert_eq!(
            SecurityContext::for_suite(
                SecurityPolicy::AuthenticationEncryption,
                SecuritySuite::Suite2,
                vec![0u8; 16],
                vec![0u8; 16],
                vec![0u8; 8],
                0,
            )
            .unwrap_err(),
            CipherError::InvalidKey
        );
        // Suite 0 authenticated encryption → SC = 0x30.
        let ctx = SecurityContext::for_suite(
            SecurityPolicy::AuthenticationEncryption,
            SecuritySuite::Suite0,
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 8],
            0,
        )
        .unwrap();
        assert_eq!(ctx.security_control, 0x30);
        // Suite 2 encryption-only → SC = 0x22.
        let ctx2 = SecurityContext::for_suite(
            SecurityPolicy::Encryption,
            SecuritySuite::Suite2,
            vec![0u8; 32],
            vec![0u8; 32],
            vec![0u8; 8],
            0,
        )
        .unwrap();
        assert_eq!(ctx2.security_control, 0x22);
    }

    #[test]
    fn authentication_only_round_trips() {
        let mut c = ctx();
        c.security_control = security_control::AUTHENTICATION;
        let plaintext = hex(b"C001C100080000010000FF0200");
        let apdu = protect(&c, glo::GET_REQUEST, &plaintext).unwrap();
        // Plaintext (after tag|len|SC|IC = 7 octets) is carried in the clear.
        assert_eq!(&apdu[7..7 + plaintext.len()], plaintext.as_slice());
        let (_, recovered) = unprotect(&mut c.clone(), &apdu).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
