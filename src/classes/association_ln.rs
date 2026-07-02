use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;
use sha1::{Sha1, Digest};
use md5::Md5;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use aead::Aead;
use rand::Rng;

/// Versions of the Association LN class.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum AssociationLnVersion {
    Version0,
    Version1,
    Version2,
}

/// Authentication mechanisms.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum AuthenticationMechanism {
    LLS,       // Low Level Security (password)
    HLS3MD5,   // High Level Security with MD5
    HLS4SHA1,  // High Level Security with SHA-1
    HLS5GMAC,  // High Level Security with GMAC
}

/// Cryptographic material for HLS mechanism 5 (GMAC), required to compute and
/// verify `f(challenge)` per IEC 62056-5-3, Table 32.
///
/// `f(challenge) = SC ‖ IC ‖ GMAC(SC ‖ AK ‖ challenge)`, where GMAC is the
/// AES-GCM tag (truncated to 12 octets) with key `EK`, initialization vector
/// `IV = system_title ‖ IC` and empty plaintext.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GmacContext {
    /// Security control byte (SC).
    pub security_control_byte: u8,
    /// Block cipher encryption key (EK), 16 or 32 octets.
    pub encryption_key: Vec<u8>,
    /// Authentication key (AK); part of the additional authenticated data.
    pub authentication_key: Vec<u8>,
    /// Server System-Title (8 octets) — used for the IV when producing `f(CtoS)`.
    pub server_system_title: Vec<u8>,
    /// Server invocation counter (IC); part of the IV and carried in `f(CtoS)`.
    pub server_invocation_counter: u32,
    /// Client System-Title (8 octets) — used for the IV when verifying `f(StoC)`.
    pub client_system_title: Vec<u8>,
}

/// Configuration structure used to build an `Association LN` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AssociationLnConfig {
    pub logical_name: ObisCode,
    pub version: AssociationLnVersion,
    pub object_list: Vec<CosemDataType>,
    pub associated_partners_id: CosemDataType,
    pub application_context_name: CosemDataType,
    pub xdlms_context_info: CosemDataType,
    pub authentication_mechanism: AuthenticationMechanism,
    pub secret: CosemDataType,
    pub association_status: CosemDataType,
    /// Attribute 9 (versions ≥ 1): OBIS reference to the `Security Setup` object (class 64).
    pub security_setup_reference: CosemDataType,
    /// Attribute 10 (version 2): array of `user { id, name }` entries.
    pub user_list: Vec<CosemDataType>,
    /// Attribute 11 (version 2): the currently associated user (structure).
    pub current_user: CosemDataType,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AssociationLn {
    logical_name: ObisCode,
    version: AssociationLnVersion,
    object_list: Vec<CosemDataType>,
    associated_partners_id: CosemDataType,
    application_context_name: CosemDataType,
    xdlms_context_info: CosemDataType,
    authentication_mechanism: AuthenticationMechanism,
    secret: CosemDataType,
    association_status: CosemDataType,
    security_setup_reference: CosemDataType,
    user_list: Vec<CosemDataType>,
    current_user: CosemDataType,
    /// Transient HLS handshake state — not part of the COSEM attributes.
    /// Client-to-server challenge (CtoS) received in the AARQ (Pass 1).
    #[serde(skip)]
    ctos: Option<Vec<u8>>,
    /// Server-to-client challenge (StoC) sent in the AARE (Pass 2).
    #[serde(skip)]
    stoc: Option<Vec<u8>>,
    /// Cryptographic material for HLS-GMAC (mechanism 5). Not needed for mechanisms 3/4.
    #[serde(skip)]
    gmac_context: Option<GmacContext>,
}

impl AssociationLn {
    pub fn new(config: AssociationLnConfig) -> Self {
        AssociationLn {
            logical_name: config.logical_name,
            version: config.version,
            object_list: config.object_list,
            associated_partners_id: config.associated_partners_id,
            application_context_name: config.application_context_name,
            xdlms_context_info: config.xdlms_context_info,
            authentication_mechanism: config.authentication_mechanism,
            secret: config.secret,
            association_status: config.association_status,
            security_setup_reference: config.security_setup_reference,
            user_list: config.user_list,
            current_user: config.current_user,
            ctos: None,
            stoc: None,
            gmac_context: None,
        }
    }

    /// Stores the client challenge (CtoS) received in the AARQ (Pass 1).
    pub fn set_ctos(&mut self, ctos: Vec<u8>) {
        self.ctos = Some(ctos);
    }

    /// Stores the server challenge (StoC) sent to the client in the AARE (Pass 2).
    pub fn set_stoc(&mut self, stoc: Vec<u8>) {
        self.stoc = Some(stoc);
    }

    /// Generates a random server challenge `StoC` of `len` octets (8..64 per
    /// IEC 62056-5-3, Table 32), stores it, and returns it for the AARE.
    pub fn generate_stoc(&mut self, len: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        let stoc: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        self.stoc = Some(stoc.clone());
        stoc
    }

    /// Sets the cryptographic material for HLS-GMAC (mechanism 5).
    pub fn set_gmac_context(&mut self, ctx: GmacContext) {
        self.gmac_context = Some(ctx);
    }

    /// Method 2: `change_HLS_secret` — replaces the secret (password/key).
    fn change_hls_secret(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        match data {
            CosemDataType::OctetString(secret) => {
                self.secret = CosemDataType::OctetString(secret);
                Ok(CosemDataType::Null)
            }
            _ => Err("Expected OctetString for HLS secret".to_string()),
        }
    }

    /// Method 1: `reply_to_HLS_authentication` (Pass 3 → Pass 4).
    ///
    /// The client sends its processed value of the server challenge `f(StoC)`.
    /// The server VERIFIES it against the stored `StoC` and the secret and, only
    /// on a match, returns its processed value of the client challenge `f(CtoS)`
    /// (IEC 62056-6-2 §5.3.5.3.1, IEC 62056-5-3 Table 32). On a mismatch the
    /// authentication is rejected and no data is returned.
    ///
    /// Requires `StoC` (Pass 2) and `CtoS` (Pass 1) to be set beforehand via
    /// [`AssociationLn::set_stoc`]/[`AssociationLn::generate_stoc`] and
    /// [`AssociationLn::set_ctos`]. For mechanism 5 (GMAC), also
    /// [`AssociationLn::set_gmac_context`].
    fn reply_to_hls_authentication(&self, data: CosemDataType) -> Result<CosemDataType, String> {
        let f_stoc = match data {
            CosemDataType::OctetString(bytes) => bytes,
            _ => return Err("Expected octet-string for f(StoC)".to_string()),
        };

        // LLS does not use the four-pass reply_to_HLS: the secret is compared
        // directly (compatible with the LLS password carried in the AARQ).
        if self.authentication_mechanism == AuthenticationMechanism::LLS {
            return match &self.secret {
                CosemDataType::OctetString(secret) if secret == &f_stoc => Ok(CosemDataType::Null),
                _ => Err("LLS authentication failed".to_string()),
            };
        }

        let stoc = self.stoc.as_ref().ok_or("StoC challenge not set (Pass 2 missing)")?;
        let ctos = self.ctos.as_ref().ok_or("CtoS challenge not set (Pass 1 missing)")?;

        match self.authentication_mechanism {
            AuthenticationMechanism::HLS3MD5 | AuthenticationMechanism::HLS4SHA1 => {
                let secret = match &self.secret {
                    CosemDataType::OctetString(s) => s,
                    _ => return Err("HLS secret must be an octet-string".to_string()),
                };
                let expected = hls_hash(&self.authentication_mechanism, stoc, secret);
                if expected != f_stoc {
                    return Err("HLS authentication failed: f(StoC) mismatch".to_string());
                }
                Ok(CosemDataType::OctetString(hls_hash(
                    &self.authentication_mechanism,
                    ctos,
                    secret,
                )))
            }
            AuthenticationMechanism::HLS5GMAC => {
                let ctx = self
                    .gmac_context
                    .as_ref()
                    .ok_or("GMAC context not configured for HLS mechanism 5")?;
                // f(StoC) = SC(1) ‖ IC(4) ‖ T(12); the client IC/System-Title form the IV.
                if f_stoc.len() != 17 {
                    return Err("f(StoC) must be 17 octets (SC ‖ IC ‖ 12-octet tag)".to_string());
                }
                let sc = f_stoc[0];
                if sc != ctx.security_control_byte {
                    return Err("f(StoC) security control byte mismatch".to_string());
                }
                let client_ic = &f_stoc[1..5];
                let client_iv = build_iv(&ctx.client_system_title, client_ic)?;
                let aad_stoc = [&[sc][..], &ctx.authentication_key, stoc].concat();
                let expected_tag = gmac_tag(&ctx.encryption_key, &client_iv, &aad_stoc)?;
                if expected_tag != f_stoc[5..17] {
                    return Err("HLS authentication failed: GMAC f(StoC) mismatch".to_string());
                }
                // f(CtoS) = SC ‖ IC_server ‖ GMAC(SC ‖ AK ‖ CtoS), server IV.
                let server_ic = ctx.server_invocation_counter.to_be_bytes();
                let server_iv = build_iv(&ctx.server_system_title, &server_ic)?;
                let aad_ctos = [&[ctx.security_control_byte][..], &ctx.authentication_key, ctos].concat();
                let tag = gmac_tag(&ctx.encryption_key, &server_iv, &aad_ctos)?;
                let mut f_ctos = Vec::with_capacity(17);
                f_ctos.push(ctx.security_control_byte);
                f_ctos.extend_from_slice(&server_ic);
                f_ctos.extend_from_slice(&tag);
                Ok(CosemDataType::OctetString(f_ctos))
            }
            AuthenticationMechanism::LLS => unreachable!("LLS handled above"),
        }
    }

    /// Method 3: `add_object` — adds an `object_list_element` to `object_list`.
    /// If an object with the same (class_id, logical_name) already exists, it is updated.
    fn add_object(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let key = object_key(&data).ok_or("Expected object_list_element structure")?;
        if let Some(existing) = self
            .object_list
            .iter_mut()
            .find(|e| object_key(e) == Some(key.clone()))
        {
            *existing = data;
        } else {
            self.object_list.push(data);
        }
        Ok(CosemDataType::Null)
    }

    /// Method 4: `remove_object` — removes an `object_list_element` from `object_list`.
    fn remove_object(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let key = object_key(&data).ok_or("Expected object_list_element structure")?;
        let before = self.object_list.len();
        self.object_list.retain(|e| object_key(e) != Some(key.clone()));
        if self.object_list.len() == before {
            return Err("Object not found in object_list".to_string());
        }
        Ok(CosemDataType::Null)
    }

    /// Method 5 (version 2): `add_user` — adds a `user { id, name }` entry to
    /// `user_list`. If an entry with the same user id already exists, it is
    /// updated (IEC 62056-6-2 §5.3.7.3.5).
    fn add_user(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let id = user_id(&data).ok_or("Expected user structure { id, name }")?;
        if let Some(existing) = self.user_list.iter_mut().find(|e| user_id(e) == Some(id)) {
            *existing = data;
        } else {
            self.user_list.push(data);
        }
        Ok(CosemDataType::Null)
    }

    /// Method 6 (version 2): `remove_user` — removes the `user` entry with the
    /// given id from `user_list` (IEC 62056-6-2 §5.3.7.3.6).
    fn remove_user(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let id = user_id(&data).ok_or("Expected user structure { id, name }")?;
        let before = self.user_list.len();
        self.user_list.retain(|e| user_id(e) != Some(id));
        if self.user_list.len() == before {
            return Err("User not found in user_list".to_string());
        }
        Ok(CosemDataType::Null)
    }
}

/// Extracts the user id from a `user ::= structure { id: unsigned, name: octet-string }`.
fn user_id(entry: &CosemDataType) -> Option<u8> {
    if let CosemDataType::Structure(fields) = entry {
        if let Some(CosemDataType::Unsigned(id)) = fields.first() {
            return Some(*id);
        }
    }
    None
}

/// Computes `HASH(challenge ‖ secret)` for HLS mechanisms 3 (MD5) and 4 (SHA-1)
/// per IEC 62056-5-3, Table 32. Not called for other mechanisms.
fn hls_hash(mechanism: &AuthenticationMechanism, challenge: &[u8], secret: &[u8]) -> Vec<u8> {
    match mechanism {
        AuthenticationMechanism::HLS3MD5 => {
            let mut h = Md5::new();
            h.update(challenge);
            h.update(secret);
            h.finalize().to_vec()
        }
        _ => {
            // SHA-1 (mechanism 4) is the only remaining hash mechanism.
            let mut h = Sha1::new();
            h.update(challenge);
            h.update(secret);
            h.finalize().to_vec()
        }
    }
}

/// Builds the 12-octet initialization vector `IV = system_title (8) ‖ IC (4)`.
fn build_iv(system_title: &[u8], invocation_counter: &[u8]) -> Result<[u8; 12], String> {
    if system_title.len() != 8 {
        return Err("System-Title must be 8 octets".to_string());
    }
    if invocation_counter.len() != 4 {
        return Err("Invocation counter must be 4 octets".to_string());
    }
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(system_title);
    iv[8..].copy_from_slice(invocation_counter);
    Ok(iv)
}

/// Computes the 12-octet GMAC tag (AES-GCM with empty plaintext) over the
/// additional authenticated data `aad`, with key `ek` (16 or 32 octets) and
/// initialization vector `iv`. The full 16-octet tag is truncated to 96 bits
/// (most significant octets) per NIST SP 800-38D / IEC 62056-5-3.
fn gmac_tag(ek: &[u8], iv: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = Nonce::from_slice(iv);
    let out = match ek.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(ek).map_err(|_| "invalid EK".to_string())?;
            cipher
                .encrypt(nonce, aead::Payload { msg: &[], aad })
                .map_err(|_| "GMAC computation failed".to_string())?
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(ek).map_err(|_| "invalid EK".to_string())?;
            cipher
                .encrypt(nonce, aead::Payload { msg: &[], aad })
                .map_err(|_| "GMAC computation failed".to_string())?
        }
        _ => return Err("EK must be 16 or 32 octets".to_string()),
    };
    // Empty plaintext → the output consists solely of the 16-octet tag.
    Ok(out[..12].to_vec())
}

/// Extracts (class_id, logical_name) from an `object_list_element`:
/// structure { class_id: long-unsigned, version: unsigned, logical_name: octet-string, ... }.
fn object_key(element: &CosemDataType) -> Option<(u16, Vec<u8>)> {
    if let CosemDataType::Structure(fields) = element {
        if fields.len() >= 3 {
            if let (CosemDataType::LongUnsigned(class_id), CosemDataType::OctetString(ln)) =
                (&fields[0], &fields[2])
            {
                return Some((*class_id, ln.clone()));
            }
        }
    }
    None
}

impl InterfaceClass for AssociationLn {
    fn class_id(&self) -> u16 {
        15
    }

    fn version(&self) -> u8 {
        match self.version {
            AssociationLnVersion::Version0 => 0,
            AssociationLnVersion::Version1 => 1,
            AssociationLnVersion::Version2 => 2,
        }
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        let mut attrs = vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.object_list.clone())),
            (3, self.associated_partners_id.clone()),
            (4, self.application_context_name.clone()),
            (5, self.xdlms_context_info.clone()),
            (6, self.authentication_mechanism_name()),
            (7, self.secret.clone()),
            (8, self.association_status.clone()),
        ];
        // Attribute 9 (security_setup_reference) is present starting from version 1.
        if matches!(self.version, AssociationLnVersion::Version1 | AssociationLnVersion::Version2) {
            attrs.push((9, self.security_setup_reference.clone()));
        }
        // Attributes 10 (user_list) and 11 (current_user) were added in version 2.
        if matches!(self.version, AssociationLnVersion::Version2) {
            attrs.push((10, CosemDataType::Array(self.user_list.clone())));
            attrs.push((11, self.current_user.clone()));
        }
        attrs
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // Method order and identifiers per IEC 62056-6-2 §5.3.5.1 / §5.3.7.1.
        let mut methods = vec![
            (1, "reply_to_HLS_authentication".to_string()),
            (2, "change_HLS_secret".to_string()),
            (3, "add_object".to_string()),
            (4, "remove_object".to_string()),
        ];
        // add_user / remove_user were added in version 2.
        if matches!(self.version, AssociationLnVersion::Version2) {
            methods.push((5, "add_user".to_string()));
            methods.push((6, "remove_user".to_string()));
        }
        methods
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?; // length = element count
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        let seq = match tlv {
            CosemDataType::Structure(seq) => seq,
            _ => return Err(BerError::InvalidTag),
        };
        // The element count (class_id + attributes) identifies the version:
        // 9 → v0 (8 attrs), 10 → v1 (+security_setup_reference),
        // 12 → v2 (+user_list, +current_user).
        if !matches!(seq.len(), 9 | 10 | 12) {
            return Err(BerError::InvalidLength);
        }
        if let CosemDataType::LongUnsigned(class_id) = seq[0] {
            if class_id != self.class_id() {
                return Err(BerError::InvalidValue);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::OctetString(obis) = &seq[1] {
            if obis.len() == 6 {
                self.logical_name = ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
            } else {
                return Err(BerError::InvalidLength);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        self.object_list = match &seq[2] {
            CosemDataType::Array(list) => list.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.associated_partners_id = seq[3].clone();
        self.application_context_name = seq[4].clone();
        self.xdlms_context_info = seq[5].clone();
        self.authentication_mechanism = match &seq[6] {
            CosemDataType::OctetString(mech) if mech.ends_with(&[0x01]) => AuthenticationMechanism::LLS,
            CosemDataType::OctetString(mech) if mech.ends_with(&[0x03]) => AuthenticationMechanism::HLS3MD5,
            CosemDataType::OctetString(mech) if mech.ends_with(&[0x04]) => AuthenticationMechanism::HLS4SHA1,
            CosemDataType::OctetString(mech) if mech.ends_with(&[0x05]) => AuthenticationMechanism::HLS5GMAC,
            _ => return Err(BerError::InvalidTag),
        };
        self.secret = seq[7].clone();
        self.association_status = seq[8].clone();
        // Attribute 9 (security_setup_reference) is present in versions 1 and 2.
        if seq.len() >= 10 {
            self.security_setup_reference = seq[9].clone();
        }
        // Attributes 10 and 11 are present only in version 2.
        self.version = if seq.len() == 12 {
            self.user_list = match &seq[10] {
                CosemDataType::Array(list) => list.clone(),
                _ => return Err(BerError::InvalidTag),
            };
            self.current_user = seq[11].clone();
            AssociationLnVersion::Version2
        } else if seq.len() == 10 {
            AssociationLnVersion::Version1
        } else {
            AssociationLnVersion::Version0
        };
        Ok(())
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        let params = params.ok_or("Missing method parameter")?;
        let is_v2 = matches!(self.version, AssociationLnVersion::Version2);
        match method_id {
            1 => self.reply_to_hls_authentication(params),
            2 => self.change_hls_secret(params),
            3 => self.add_object(params),
            4 => self.remove_object(params),
            // add_user / remove_user exist only in version 2.
            5 if is_v2 => self.add_user(params),
            6 if is_v2 => self.remove_user(params),
            _ => Err(format!(
                "Method {} not supported for Association LN version {}",
                method_id,
                self.version()
            )),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AssociationLn {
    /// Encodes attribute 6 `authentication_mechanism_name` as an octet-string
    /// containing the OBJECT IDENTIFIER `2.16.756.5.8.2.<mechanism_id>`
    /// (BER: tag 0x09, length 0x07, 7 value bytes). See DLMS UA 1000-1, 11.4 and
    /// IEC 62056-5-3, Table 65 (mechanism_id: LLS=1, MD5=3, SHA-1=4, GMAC=5).
    fn authentication_mechanism_name(&self) -> CosemDataType {
        let mechanism_id = match self.authentication_mechanism {
            AuthenticationMechanism::LLS => 0x01,
            AuthenticationMechanism::HLS3MD5 => 0x03,
            AuthenticationMechanism::HLS4SHA1 => 0x04,
            AuthenticationMechanism::HLS5GMAC => 0x05,
        };
        CosemDataType::OctetString(vec![
            0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, mechanism_id,
        ])
    }
}

fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: AssociationLnVersion) -> AssociationLn {
        AssociationLn::new(AssociationLnConfig {
            logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
            version,
            object_list: vec![],
            associated_partners_id: CosemDataType::Structure(vec![
                CosemDataType::Integer(1),
                CosemDataType::LongUnsigned(1),
            ]),
            application_context_name: CosemDataType::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
            xdlms_context_info: CosemDataType::Null,
            authentication_mechanism: AuthenticationMechanism::HLS4SHA1,
            secret: CosemDataType::OctetString(b"12345678".to_vec()),
            association_status: CosemDataType::Enum(0),
            security_setup_reference: CosemDataType::OctetString(vec![0, 0, 43, 0, 0, 255]),
            user_list: vec![],
            current_user: CosemDataType::Null,
        })
    }

    #[test]
    fn method_ids_match_standard() {
        let m = sample(AssociationLnVersion::Version1).methods();
        assert_eq!(m[0], (1, "reply_to_HLS_authentication".to_string()));
        assert_eq!(m[1], (2, "change_HLS_secret".to_string()));
        assert_eq!(m[2], (3, "add_object".to_string()));
        assert_eq!(m[3], (4, "remove_object".to_string()));
    }

    #[test]
    fn mechanism_name_oid_is_well_formed() {
        let obj = sample(AssociationLnVersion::Version0);
        // SHA-1 → mechanism_id 4; OID: 09 07 60 85 74 05 08 02 04
        if let CosemDataType::OctetString(oid) = obj.authentication_mechanism_name() {
            assert_eq!(oid, vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x04]);
            assert_eq!(oid[1] as usize, oid.len() - 2, "OID length must match");
        } else {
            panic!("mechanism name must be octet-string");
        }
    }

    #[test]
    fn attribute_and_method_counts_per_version() {
        let expected = [
            (AssociationLnVersion::Version0, 8usize, 4usize),
            (AssociationLnVersion::Version1, 9, 4),
            (AssociationLnVersion::Version2, 11, 6),
        ];
        for (v, attr_count, method_count) in expected {
            let obj = sample(v.clone());
            assert_eq!(obj.attributes().len(), attr_count);
            assert_eq!(obj.methods().len(), method_count);
        }
    }

    #[test]
    fn round_trip_all_versions() {
        for v in [
            AssociationLnVersion::Version0,
            AssociationLnVersion::Version1,
            AssociationLnVersion::Version2,
        ] {
            let obj = sample(v.clone());
            let mut buf = Vec::new();
            obj.serialize_ber(&mut buf).unwrap();
            let mut decoded = sample(AssociationLnVersion::Version0);
            decoded.deserialize_ber(&buf).unwrap();
            assert_eq!(decoded.version(), obj.version());
            assert_eq!(decoded.attributes().len(), obj.attributes().len());
        }
    }

    #[test]
    fn add_and_remove_user_v2_only() {
        let user = CosemDataType::Structure(vec![
            CosemDataType::Unsigned(7),
            CosemDataType::OctetString(b"operator".to_vec()),
        ]);
        // Version 2 supports add_user / remove_user.
        let mut obj = sample(AssociationLnVersion::Version2);
        obj.invoke_method(5, Some(user.clone())).unwrap();
        assert_eq!(obj.user_list.len(), 1);
        obj.invoke_method(6, Some(user.clone())).unwrap();
        assert_eq!(obj.user_list.len(), 0);
        // Version 1 does not.
        let mut v1 = sample(AssociationLnVersion::Version1);
        assert!(v1.invoke_method(5, Some(user)).is_err());
    }

    #[test]
    fn add_and_remove_object() {
        let mut obj = sample(AssociationLnVersion::Version1);
        let element = CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(1),
            CosemDataType::Unsigned(0),
            CosemDataType::OctetString(vec![0, 0, 96, 1, 0, 255]),
            CosemDataType::Array(vec![]),
        ]);
        obj.invoke_method(3, Some(element.clone())).unwrap();
        assert_eq!(obj.object_list.len(), 1);
        obj.invoke_method(4, Some(element)).unwrap();
        assert_eq!(obj.object_list.len(), 0);
    }

    /// HLS-4 (SHA-1), four-pass process: the server verifies f(StoC) and
    /// returns f(CtoS) = SHA-1(CtoS ‖ secret).
    #[test]
    fn hls4_sha1_verifies_fstoc_and_returns_fctos() {
        let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let ctos = vec![0x11, 0x22, 0x33, 0x44];
        let mut obj = sample(AssociationLnVersion::Version1);
        obj.secret = CosemDataType::OctetString(secret.clone());
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos.clone());

        let f_stoc = {
            let mut h = Sha1::new();
            h.update(&stoc);
            h.update(&secret);
            h.finalize().to_vec()
        };
        let expected_f_ctos = {
            let mut h = Sha1::new();
            h.update(&ctos);
            h.update(&secret);
            h.finalize().to_vec()
        };

        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("HLS4 authentication should succeed");
        assert_eq!(reply, CosemDataType::OctetString(expected_f_ctos));

        // A wrong f(StoC) → rejection.
        let mut wrong = f_stoc;
        wrong[0] ^= 0xFF;
        assert!(obj
            .invoke_method(1, Some(CosemDataType::OctetString(wrong)))
            .is_err());
    }

    /// HLS-5 (GMAC): reference test vector from IEC 62056-5-3, Table 33.
    #[test]
    fn hls5_gmac_matches_blue_book_test_vector() {
        let ek = hex(b"000102030405060708090A0B0C0D0E0F");
        let ak = hex(b"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");
        let client_st = hex(b"4D4D4D0000000001");
        let server_st = hex(b"4D4D4D0000BC614E");
        let ctos = hex(b"4B35366956616759"); // 'K56iVagY'
        let stoc = hex(b"503677524A323146"); // 'P6wRJ21F'
        let f_stoc = hex(b"10000000011A52FE7DD3E72748973C1E28");
        let expected_f_ctos = hex(b"1001234567FE1466AFB3DBCD4F9389E2B7");

        let mut obj = sample(AssociationLnVersion::Version1);
        obj.authentication_mechanism = AuthenticationMechanism::HLS5GMAC;
        obj.set_stoc(stoc);
        obj.set_ctos(ctos);
        obj.set_gmac_context(GmacContext {
            security_control_byte: 0x10,
            encryption_key: ek,
            authentication_key: ak,
            server_system_title: server_st,
            server_invocation_counter: 0x01234567,
            client_system_title: client_st,
        });

        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("GMAC authentication should succeed");
        assert_eq!(reply, CosemDataType::OctetString(expected_f_ctos));

        // Corrupting the client tag → f(StoC) verification fails.
        let mut bad = f_stoc;
        bad[16] ^= 0x01;
        assert!(obj
            .invoke_method(1, Some(CosemDataType::OctetString(bad)))
            .is_err());
    }

    /// Parses an ASCII-hex string into a byte vector (for test vectors).
    fn hex(s: &[u8]) -> Vec<u8> {
        fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'F' => c - b'A' + 10,
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("invalid hex digit"),
            }
        }
        s.chunks(2).map(|p| (nib(p[0]) << 4) | nib(p[1])).collect()
    }
}
