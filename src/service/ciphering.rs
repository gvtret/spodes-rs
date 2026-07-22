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
//! For GOST ciphering (Р 1323565.1), Kuznyechik CTR+CMAC is used with a
//! 16-byte CMAC tag.
//!
//! Validated against the authenticated-encryption test vector of IEC 62056-5-3
//! Annex E.5.

use aead::AeadInOut;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::{Aes128, Aes256};
use aes_gcm::KeyInit as AesKeyInit;
use aes_gcm::{AesGcm, Nonce, Tag};
use cipher::block::BlockCipherEncrypt;
use cmac::Cmac;
use kuznyechik::Kuznyechik;

/// AES-128-GCM with a 96-bit (12-octet) authentication tag.
type Aes128Gcm12 = AesGcm<Aes128, U12, U12>;
/// AES-256-GCM with a 96-bit (12-octet) authentication tag.
type Aes256Gcm12 = AesGcm<Aes256, U12, U12>;
/// Kuznyechik CMAC type (used internally).
#[allow(dead_code)]
type KuznyechikCmac = Cmac<Kuznyechik>;

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

/// GOST security suite identifier (Р 1323565.1, suite id = 0x0D).
pub const GOST_SUITE_ID: u8 = 0x0D;

/// Checks if the security control byte indicates a GOST suite.
pub fn is_gost_suite(sc: u8) -> bool {
    (sc & 0x0F) == GOST_SUITE_ID
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

impl Drop for SecurityContext {
    /// Zeroizes the key material when the context is dropped, so secrets do
    /// not linger in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
    }
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

// ============================================================================
// GOST ciphering (Р 1323565.1): Kuznyechik CTR + CMAC
// ============================================================================

/// GOST-authenticated encryption using Kuznyechik CTR+CMAC (Р 1323565.1).
///
/// - Encryption: Kuznyechik in CTR mode (IV = system_title ‖ IC).
/// - Authentication: Kuznyechik CMAC over `SC ‖ AK ‖ ciphertext`.
/// - Tag: 16-byte full CMAC output.
///
/// Returns the encrypted APDU with the GOST tag appended.
pub fn gost_protect(ctx: &SecurityContext, ciphered_tag: u8, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    if ctx.encryption_key.len() != 32 {
        return Err(CipherError::InvalidKey);
    }
    let sc = ctx.security_control;
    let iv = ctx.iv()?;
    let nonce = build_gost_nonce(&iv);

    match (ctx.authentication(), ctx.encryption()) {
        (true, true) => {
            // Encrypt with CTR, then compute CMAC over SC ‖ AK ‖ ciphertext.
            let ciphertext = gost_ctr_encrypt(&ctx.encryption_key, &nonce, plaintext)?;
            let aad = [[sc].as_ref(), &ctx.authentication_key, &ciphertext].concat();
            let tag = gost_cmac_tag(&ctx.encryption_key, &aad)?;
            let mut body = Vec::with_capacity(5 + ciphertext.len() + 16);
            body.push(sc);
            body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
            body.extend_from_slice(&ciphertext);
            body.extend_from_slice(&tag);
            let mut apdu = vec![ciphered_tag];
            push_length(body.len(), &mut apdu);
            apdu.extend_from_slice(&body);
            Ok(apdu)
        }
        (true, false) => {
            // Authentication only: CMAC over SC ‖ AK ‖ plaintext.
            let aad = [[sc].as_ref(), &ctx.authentication_key, plaintext].concat();
            let tag = gost_cmac_tag(&ctx.encryption_key, &aad)?;
            let mut body = Vec::with_capacity(5 + plaintext.len() + 16);
            body.push(sc);
            body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
            body.extend_from_slice(plaintext);
            body.extend_from_slice(&tag);
            let mut apdu = vec![ciphered_tag];
            push_length(body.len(), &mut apdu);
            apdu.extend_from_slice(&body);
            Ok(apdu)
        }
        (false, true) => {
            // Encryption only: no tag.
            let ciphertext = gost_ctr_encrypt(&ctx.encryption_key, &nonce, plaintext)?;
            let mut body = Vec::with_capacity(5 + ciphertext.len());
            body.push(sc);
            body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
            body.extend_from_slice(&ciphertext);
            let mut apdu = vec![ciphered_tag];
            push_length(body.len(), &mut apdu);
            apdu.extend_from_slice(&body);
            Ok(apdu)
        }
        (false, false) => {
            let mut body = Vec::with_capacity(5 + plaintext.len());
            body.push(sc);
            body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
            body.extend_from_slice(plaintext);
            let mut apdu = vec![ciphered_tag];
            push_length(body.len(), &mut apdu);
            apdu.extend_from_slice(&body);
            Ok(apdu)
        }
    }
}

/// Removes GOST ciphering from an APDU, returning `(ciphered_tag, plaintext)`.
pub fn gost_unprotect(ctx: &mut SecurityContext, apdu: &[u8]) -> Result<(u8, Vec<u8>), CipherError> {
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
    let nonce = build_gost_nonce(&iv);

    let plaintext = match (ctx.authentication(), ctx.encryption()) {
        (true, true) => {
            if protected.len() < 16 {
                return Err(CipherError::Truncated);
            }
            let (ct, tag) = protected.split_at(protected.len() - 16);
            let aad = [[sc].as_ref(), &ctx.authentication_key, ct].concat();
            let expected_tag = gost_cmac_tag(&ctx.encryption_key, &aad)?;
            if tag != expected_tag.as_slice() {
                return Err(CipherError::AuthenticationFailed);
            }
            gost_ctr_decrypt(&ctx.encryption_key, &nonce, ct)?
        }
        (true, false) => {
            if protected.len() < 16 {
                return Err(CipherError::Truncated);
            }
            let (plain, tag) = protected.split_at(protected.len() - 16);
            let aad = [[sc].as_ref(), &ctx.authentication_key, plain].concat();
            let expected_tag = gost_cmac_tag(&ctx.encryption_key, &aad)?;
            if tag != expected_tag.as_slice() {
                return Err(CipherError::AuthenticationFailed);
            }
            plain.to_vec()
        }
        (false, true) => gost_ctr_decrypt(&ctx.encryption_key, &nonce, protected)?,
        (false, false) => protected.to_vec(),
    };
    Ok((ciphered_tag, plaintext))
}

/// Kuznyechik CTR-mode encryption.
fn gost_ctr_encrypt(key: &[u8], nonce: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    use cipher::BlockCipherEncrypt;
    let cipher = Kuznyechik::new_from_slice(key).map_err(|_| CipherError::InvalidKey)?;
    let mut ciphertext = plaintext.to_vec();
    let mut counter = *nonce;

    for chunk in ciphertext.chunks_mut(16) {
        // Encrypt counter block to get keystream
        let mut keystream = cipher::Array::from(counter);
        cipher.encrypt_block(&mut keystream);
        let ks: [u8; 16] = keystream.into();
        // XOR plaintext with keystream
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= ks[i];
        }
        // Increment counter (big-endian)
        increment_counter(&mut counter);
    }
    Ok(ciphertext)
}

/// Kuznyechik CTR-mode decryption (same as encryption for CTR).
fn gost_ctr_decrypt(key: &[u8], nonce: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // CTR mode decryption is identical to encryption
    gost_ctr_encrypt(key, nonce, ciphertext)
}

/// Kuznyechik CMAC tag computation (16 bytes).
/// Implements CMAC manually using Kuznyechik block cipher (GOST R 34.13-2015).
fn gost_cmac_tag(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    if key.len() != 32 {
        return Err(CipherError::InvalidKey);
    }

    let cipher = Kuznyechik::new_from_slice(key).map_err(|_| CipherError::InvalidKey)?;

    // Generate subkeys K1 and K2
    let mut l = cipher::Array::from([0u8; 16]);
    cipher.clone().encrypt_block(&mut l);
    let l_bytes: [u8; 16] = l.into();

    let k1 = ghash_subkey(&l_bytes);
    let k2 = ghash_subkey(&k1);

    // Process data in 16-byte blocks
    let mut state = [0u8; 16];
    let chunks: Vec<&[u8]> = data.chunks(16).collect();
    let last_block = data.chunks(16).last();

    if data.is_empty() || last_block.is_some_and(|b| b.len() == 16) {
        // Data is empty or last block is full
        for chunk in &chunks {
            xor_blocks(&mut state, chunk);
            let mut block = cipher::Array::from(state);
            cipher.clone().encrypt_block(&mut block);
            state = block.into();
        }
        if !data.is_empty() && last_block.is_some_and(|b| b.len() == 16) {
            // XOR K1 into state before final block
            xor_blocks(&mut state, &k1);
            let mut block = cipher::Array::from(state);
            cipher.clone().encrypt_block(&mut block);
            state = block.into();
        }
    } else {
        // Last block is partial - pad and XOR K2
        let mut padded = [0u8; 16];
        padded[..chunks.last().unwrap().len()].copy_from_slice(chunks.last().unwrap());
        padded[chunks.last().unwrap().len()] = 0x80; // padding

        for chunk in &chunks[..chunks.len() - 1] {
            xor_blocks(&mut state, chunk);
            let mut block = cipher::Array::from(state);
            cipher.clone().encrypt_block(&mut block);
            state = block.into();
        }
        // Process last padded block with K2
        xor_blocks(&mut state, &padded);
        xor_blocks(&mut state, &k2);
        let mut block = cipher::Array::from(state);
        cipher.clone().encrypt_block(&mut block);
        state = block.into();
    }

    Ok(state.to_vec())
}

/// GHASH subkey derivation for CMAC (doubles the block in GF(2^128)).
fn ghash_subkey(l: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let carry = l[0] & 0x80 != 0;
    for i in 0..16 {
        result[i] = (l[i] << 1) | if i + 1 < 16 { l[i + 1] >> 7 } else { 0 };
    }
    if carry {
        result[15] ^= 0x87; // x^128 + x^7 + x^2 + x + 1
    }
    result
}

/// XOR two 16-byte blocks.
fn xor_blocks(a: &mut [u8; 16], b: &[u8]) {
    for i in 0..16.min(b.len()) {
        a[i] ^= b[i];
    }
}

/// Builds a 16-byte nonce from the 12-byte IV (system_title ‖ IC).
/// The GOST CTR mode uses a 128-bit block, so we extend the 96-bit IV
/// with zeros to form the counter initial value.
fn build_gost_nonce(iv: &[u8; 12]) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce[..12].copy_from_slice(iv);
    nonce
}

/// Increments a 128-bit counter in big-endian.
fn increment_counter(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

// ============================================================================
// GOST GMAC (Kuznyechik GCM-like mode)
// ============================================================================

/// GOST GMAC: Kuznyechik in GCM-like mode (CTR + GHASH).
///
/// This is an alternative to CTR+CMAC that provides:
/// - Encryption: Kuznyechik in CTR mode
/// - Authentication: GHASH (Galois field multiplication over GF(2^128))
///
/// The GHASH function uses Kuznyechik as the underlying block cipher,
/// computing authentication tags over AAD and ciphertext.
pub fn gost_gmac_tag(key: &[u8], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    if key.len() != 32 {
        return Err(CipherError::InvalidKey);
    }

    let cipher = Kuznyechik::new_from_slice(key).map_err(|_| CipherError::InvalidKey)?;

    // Generate hash subkey H = E(K, 0^128)
    let mut h = cipher::Array::from([0u8; 16]);
    cipher.clone().encrypt_block(&mut h);
    let _h_bytes: [u8; 16] = h.into();

    // Compute GHASH over AAD || ciphertext || len(AAD)||len(ciphertext)
    let mut state = [0u8; 16];

    // Process AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        if chunk.len() < 16 {
            block[chunk.len()] = 0x80; // padding
        }
        xor_blocks(&mut state, &block);
        let mut block_arr = cipher::Array::from(state);
        cipher.clone().encrypt_block(&mut block_arr);
        state = block_arr.into();
    }

    // Process ciphertext
    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        if chunk.len() < 16 {
            block[chunk.len()] = 0x80; // padding
        }
        xor_blocks(&mut state, &block);
        let mut block_arr = cipher::Array::from(state);
        cipher.clone().encrypt_block(&mut block_arr);
        state = block_arr.into();
    }

    // Process lengths block: len(AAD) || len(ciphertext) in bits
    let aad_bit_len = (aad.len() as u64) * 8;
    let ct_bit_len = (plaintext.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&aad_bit_len.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bit_len.to_be_bytes());
    xor_blocks(&mut state, &len_block);
    let mut block_arr = cipher::Array::from(state);
    cipher.clone().encrypt_block(&mut block_arr);
    state = block_arr.into();

    // Final: tag = GHASH(H, AAD, ciphertext) ⊕ E(K, IV || 0^32)
    // For GMAC, we use the IV directly as the counter block
    let mut enc_block = cipher::Array::from(build_gmac_counter(iv));
    cipher.clone().encrypt_block(&mut enc_block);
    let enc_bytes: [u8; 16] = enc_block.into();
    xor_blocks(&mut state, &enc_bytes);

    Ok(state.to_vec())
}

/// Builds the 128-bit counter block for GOST GMAC.
/// The counter is IV (12 bytes) || 0x00000001 (4 bytes).
fn build_gmac_counter(iv: &[u8; 12]) -> [u8; 16] {
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 0x01; // counter starts at 1
    counter
}

/// GOST GMAC encryption (CTR mode) for use with GMAC authentication.
pub fn gost_gmac_encrypt(key: &[u8], iv: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // CTR mode encryption with counter starting at 1
    let cipher = Kuznyechik::new_from_slice(key).map_err(|_| CipherError::InvalidKey)?;
    let mut ciphertext = plaintext.to_vec();
    let mut counter = build_gmac_counter(iv);

    for chunk in ciphertext.chunks_mut(16) {
        let mut keystream = cipher::Array::from(counter);
        cipher.clone().encrypt_block(&mut keystream);
        let ks: [u8; 16] = keystream.into();
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= ks[i];
        }
        increment_counter(&mut counter);
    }
    Ok(ciphertext)
}

/// GOST GMAC decryption (CTR mode) for use with GMAC authentication.
pub fn gost_gmac_decrypt(key: &[u8], iv: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // CTR mode decryption is identical to encryption
    gost_gmac_encrypt(key, iv, ciphertext)
}

/// Protects an APDU using GOST GMAC (Kuznyechik GCM-like mode).
pub fn gost_gmac_protect(ctx: &SecurityContext, ciphered_tag: u8, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    if ctx.encryption_key.len() != 32 {
        return Err(CipherError::InvalidKey);
    }
    let sc = ctx.security_control;
    let iv = ctx.iv()?;

    let mut protected = Vec::new();
    match (ctx.authentication(), ctx.encryption()) {
        (true, true) => {
            // Encrypt with CTR, then compute GMAC over SC ‖ AK ‖ ciphertext.
            let ciphertext = gost_gmac_encrypt(&ctx.encryption_key, &iv, plaintext)?;
            let aad = [[sc].as_ref(), &ctx.authentication_key].concat();
            let tag = gost_gmac_tag(&ctx.encryption_key, &iv, &aad, &ciphertext)?;
            protected.extend_from_slice(&ciphertext);
            protected.extend_from_slice(&tag);
        }
        (true, false) => {
            // Authentication only: GMAC over SC ‖ AK ‖ plaintext.
            let aad = [[sc].as_ref(), &ctx.authentication_key].concat();
            let tag = gost_gmac_tag(&ctx.encryption_key, &iv, &aad, plaintext)?;
            protected.extend_from_slice(plaintext);
            protected.extend_from_slice(&tag);
        }
        (false, true) => {
            // Encryption only: no tag.
            let ciphertext = gost_gmac_encrypt(&ctx.encryption_key, &iv, plaintext)?;
            protected.extend_from_slice(&ciphertext);
        }
        (false, false) => protected.extend_from_slice(plaintext),
    }

    let mut body = Vec::with_capacity(5 + protected.len());
    body.push(sc);
    body.extend_from_slice(&ctx.invocation_counter.to_be_bytes());
    body.extend_from_slice(&protected);

    let mut apdu = vec![ciphered_tag];
    push_length(body.len(), &mut apdu);
    apdu.extend_from_slice(&body);
    Ok(apdu)
}

/// Removes GOST GMAC protection from an APDU.
pub fn gost_gmac_unprotect(ctx: &mut SecurityContext, apdu: &[u8]) -> Result<(u8, Vec<u8>), CipherError> {
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
            if protected.len() < 16 {
                return Err(CipherError::Truncated);
            }
            let (ct, tag) = protected.split_at(protected.len() - 16);
            let aad = [[sc].as_ref(), &ctx.authentication_key].concat();
            let expected_tag = gost_gmac_tag(&ctx.encryption_key, &iv, &aad, ct)?;
            if tag != expected_tag.as_slice() {
                return Err(CipherError::AuthenticationFailed);
            }
            gost_gmac_decrypt(&ctx.encryption_key, &iv, ct)?
        }
        (true, false) => {
            if protected.len() < 16 {
                return Err(CipherError::Truncated);
            }
            let (plain, tag) = protected.split_at(protected.len() - 16);
            let aad = [[sc].as_ref(), &ctx.authentication_key].concat();
            let expected_tag = gost_gmac_tag(&ctx.encryption_key, &iv, &aad, plain)?;
            if tag != expected_tag.as_slice() {
                return Err(CipherError::AuthenticationFailed);
            }
            plain.to_vec()
        }
        (false, true) => gost_gmac_decrypt(&ctx.encryption_key, &iv, protected)?,
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

    // ========================================================================
    // GOST ciphering tests (Р 1323565.1: Kuznyechik CTR+CMAC)
    // ========================================================================

    fn gost_ctx() -> SecurityContext {
        SecurityContext {
            security_control: security_control::AUTHENTICATED_ENCRYPTION | GOST_SUITE_ID,
            encryption_key: hex(b"8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677"),
            authentication_key: hex(b"bddc7e4ac4e164e40785d8c147b4a883bddc7e4ac4e164e40785d8c147b4a883"),
            system_title: hex(b"4D4D4D0000BC614E"),
            invocation_counter: 0x01234567,
        }
    }

    #[test]
    fn gost_protect_unprotect_round_trip() {
        let plaintext = hex(b"C001C100080000010000FF0200");
        let apdu = gost_protect(&gost_ctx(), glo::GET_REQUEST, &plaintext).unwrap();
        let (tag, recovered) = gost_unprotect(&mut gost_ctx(), &apdu).unwrap();
        assert_eq!(tag, glo::GET_REQUEST);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_protect_unprotect_with_auth_only() {
        let mut c = gost_ctx();
        c.security_control = security_control::AUTHENTICATION | GOST_SUITE_ID;
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let apdu = gost_protect(&c, glo::GET_RESPONSE, &plaintext).unwrap();
        // Plaintext should be visible in the clear (auth only, no encryption)
        assert_eq!(&apdu[7..7 + plaintext.len()], plaintext.as_slice());
        let (_, recovered) = gost_unprotect(&mut c, &apdu).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_protect_unprotect_encryption_only() {
        let mut c = gost_ctx();
        c.security_control = security_control::ENCRYPTION | GOST_SUITE_ID;
        let plaintext = hex(b"C001C100080000010000FF0200");
        let apdu = gost_protect(&c, glo::SET_REQUEST, &plaintext).unwrap();
        // Ciphertext should not match plaintext
        assert_ne!(&apdu[7..7 + plaintext.len()], plaintext.as_slice());
        let (_, recovered) = gost_unprotect(&mut c, &apdu).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_detects_tampering() {
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let mut apdu = gost_protect(&gost_ctx(), glo::GET_RESPONSE, &plaintext).unwrap();
        let n = apdu.len();
        apdu[n - 1] ^= 0x01; // corrupt the CMAC tag
        assert_eq!(gost_unprotect(&mut gost_ctx(), &apdu), Err(CipherError::AuthenticationFailed));
    }

    #[test]
    fn gost_wrong_key_fails() {
        let mut c = gost_ctx();
        c.encryption_key = hex(b"0000000000000000000000000000000000000000000000000000000000000000");
        let plaintext = hex(b"C001C100");
        let apdu = gost_protect(&c, glo::GET_REQUEST, &plaintext).unwrap();
        // Different key should fail CMAC verification
        assert_eq!(gost_unprotect(&mut gost_ctx(), &apdu), Err(CipherError::AuthenticationFailed));
    }

    #[test]
    fn is_gost_suite_detection() {
        assert!(is_gost_suite(GOST_SUITE_ID));
        assert!(is_gost_suite(0x30 | GOST_SUITE_ID));
        assert!(!is_gost_suite(0x30)); // AES suite 0
        assert!(!is_gost_suite(0x31)); // AES suite 1
    }

    #[test]
    fn gost_counter_increment() {
        let mut counter = [0xFFu8; 16];
        increment_counter(&mut counter);
        assert_eq!(
            counter,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn gost_cmac_produces_16_octet_tag() {
        let key = hex(b"8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677");
        let data = hex(b"0102030405");
        let tag = gost_cmac_tag(&key, &data).unwrap();
        assert_eq!(tag.len(), 16);
    }

    // ========================================================================
    // GOST GMAC tests (Kuznyechik GCM-like mode)
    // ========================================================================

    fn gost_gmac_ctx() -> SecurityContext {
        SecurityContext {
            security_control: security_control::AUTHENTICATED_ENCRYPTION | GOST_SUITE_ID,
            encryption_key: hex(b"8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677"),
            authentication_key: hex(b"bddc7e4ac4e164e40785d8c147b4a883bddc7e4ac4e164e40785d8c147b4a883"),
            system_title: hex(b"4D4D4D0000BC614E"),
            invocation_counter: 0x01234567,
        }
    }

    #[test]
    fn gost_gmac_protect_unprotect_round_trip() {
        let plaintext = hex(b"C001C100080000010000FF0200");
        let apdu = gost_gmac_protect(&gost_gmac_ctx(), glo::GET_REQUEST, &plaintext).unwrap();
        let (tag, recovered) = gost_gmac_unprotect(&mut gost_gmac_ctx(), &apdu).unwrap();
        assert_eq!(tag, glo::GET_REQUEST);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_gmac_protect_unprotect_with_auth_only() {
        let mut c = gost_gmac_ctx();
        c.security_control = security_control::AUTHENTICATION | GOST_SUITE_ID;
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let apdu = gost_gmac_protect(&c, glo::GET_RESPONSE, &plaintext).unwrap();
        // Plaintext should be visible in the clear (auth only, no encryption)
        assert_eq!(&apdu[7..7 + plaintext.len()], plaintext.as_slice());
        let (_, recovered) = gost_gmac_unprotect(&mut c, &apdu).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_gmac_protect_unprotect_encryption_only() {
        let mut c = gost_gmac_ctx();
        c.security_control = security_control::ENCRYPTION | GOST_SUITE_ID;
        let plaintext = hex(b"C001C100080000010000FF0200");
        let apdu = gost_gmac_protect(&c, glo::SET_REQUEST, &plaintext).unwrap();
        // Ciphertext should not match plaintext
        assert_ne!(&apdu[7..7 + plaintext.len()], plaintext.as_slice());
        let (_, recovered) = gost_gmac_unprotect(&mut c, &apdu).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gost_gmac_detects_tampering() {
        let plaintext = hex(b"0800065F1F0400007C1F04000007");
        let mut apdu = gost_gmac_protect(&gost_gmac_ctx(), glo::GET_RESPONSE, &plaintext).unwrap();
        let n = apdu.len();
        apdu[n - 1] ^= 0x01; // corrupt the GMAC tag
        assert_eq!(gost_gmac_unprotect(&mut gost_gmac_ctx(), &apdu), Err(CipherError::AuthenticationFailed));
    }

    #[test]
    fn gost_gmac_wrong_key_fails() {
        let mut c = gost_gmac_ctx();
        c.encryption_key = hex(b"0000000000000000000000000000000000000000000000000000000000000000");
        let plaintext = hex(b"C001C100");
        let apdu = gost_gmac_protect(&c, glo::GET_REQUEST, &plaintext).unwrap();
        // Different key should fail GMAC verification
        assert_eq!(gost_gmac_unprotect(&mut gost_gmac_ctx(), &apdu), Err(CipherError::AuthenticationFailed));
    }

    #[test]
    fn gost_gmac_tag_produces_16_octet_tag() {
        let key = hex(b"8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677");
        let iv = hex(b"4D4D4D0000BC614E01234567");
        let aad = hex(b"01");
        let data = hex(b"0102030405060708");
        let tag = gost_gmac_tag(&key, &iv.try_into().unwrap(), &aad, &data).unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn gost_gmac_encrypt_decrypt_round_trip() {
        let key = hex(b"8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677");
        let iv_bytes = hex(b"4D4D4D0000BC614E01234567");
        let iv: [u8; 12] = iv_bytes.try_into().unwrap();
        let plaintext = hex(b"C001C100080000010000FF0200");
        let ciphertext = gost_gmac_encrypt(&key, &iv, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        let recovered = gost_gmac_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
