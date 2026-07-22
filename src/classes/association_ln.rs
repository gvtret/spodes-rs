use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::security::access_rights::ObjectListEntry;
use crate::security::{gost3410, hls, signature, AuthMechanism, SecuritySuite};
use crate::types::attrs::{AssociatedPartnersId, ContextName, ObjectListElement, User, XDLMSContextInfo};
use crate::types::{BerError, CosemDataType};
use aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use subtle::ConstantTimeEq;

/// Versions of the Association LN class.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum AssociationLnVersion {
    /// Version 0: attributes 1..8 (no `security_setup_reference`).
    Version0,
    /// Version 1: adds attribute 9 (`security_setup_reference`).
    Version1,
    /// Version 2: adds attributes 10 and 11 (`user_list`, `current_user`).
    Version2,
}

/// The authentication mechanism (mechanism_id 0..10), unified with the
/// crate-wide security model. See [`crate::security::AuthMechanism`].
pub use crate::security::AuthMechanism as AuthenticationMechanism;

/// Cryptographic material for the HLS handshake, shared by the mechanisms that
/// need more than the plain secret: GMAC (5), SHA-256 (6), Kuznyechik CMAC (8)
/// and Streebog (9). Fields not relevant to the negotiated mechanism may stay
/// empty (see [`Default`]).
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct HlsContext {
    /// Client System-Title (8 octets).
    pub client_system_title: Vec<u8>,
    /// Server System-Title (8 octets).
    pub server_system_title: Vec<u8>,
    /// Security control byte (SC) — GMAC / CMAC.
    pub security_control_byte: u8,
    /// Server invocation counter (IC) — carried in `f(CtoS)` for GMAC / CMAC.
    pub server_invocation_counter: u32,
    /// Block cipher encryption key (EK), 16 or 32 octets — GMAC (mechanism 5).
    pub encryption_key: Vec<u8>,
    /// Authentication key (AK) — GMAC (mechanism 5).
    pub authentication_key: Vec<u8>,
    /// Global key `K_EM` (64 octets, 512 bits) — Kuznyechik CMAC (mechanism 8).
    pub gost_key: Vec<u8>,
    /// Server signing private key — ECDSA (mechanism 7, `Vec256`/`Vec384` raw
    /// scalar) or GOST 34.10 (mechanism 10, little-endian `Vec256`).
    pub signing_key: Vec<u8>,
    /// Client verification public key — ECDSA (raw `x ‖ y` or SEC1) or GOST
    /// 34.10 (`π_x(Q) ‖ π_y(Q)`, 64 octets). Signature mechanisms 7 / 10.
    pub peer_public_key: Vec<u8>,
}

impl Drop for HlsContext {
    /// Zeroizes the key material when the context is dropped, so secrets do
    /// not linger in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
        self.gost_key.zeroize();
        self.signing_key.zeroize();
    }
}

/// Configuration structure used to build an `Association LN` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AssociationLnConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// The implemented class version (0, 1 or 2); selects the attribute set.
    pub version: AssociationLnVersion,
    /// Attribute 2: list of the COSEM objects visible within the association.
    pub object_list: Vec<ObjectListElement>,
    /// Attribute 3: `associated_partners_id` structure { client SAP, server SAP }.
    pub associated_partners_id: AssociatedPartnersId,
    /// Attribute 4: application context name (naming and ciphering in use).
    pub application_context_name: ContextName,
    /// Attribute 5: `xDLMS_context_info` structure (conformance, PDU sizes, …).
    pub xdlms_context_info: XDLMSContextInfo,
    /// Attribute 6: the authentication mechanism negotiated for the association.
    pub authentication_mechanism: AuthenticationMechanism,
    /// Attribute 7: the LLS/HLS secret (password or shared key).
    pub secret: Vec<u8>,
    /// Attribute 8: association status (non-associated / association-pending / associated).
    pub association_status: u8,
    /// Attribute 9 (versions ≥ 1): OBIS reference to the `Security Setup` object (class 64).
    pub security_setup_reference: ObisCode,
    /// Attribute 10 (version 2): array of `user { id, name }` entries.
    pub user_list: Vec<User>,
    /// Attribute 11 (version 2): the currently associated user (structure).
    pub current_user: Option<User>,
}

/// `Association LN` interface class (class_id = 15) per IEC 62056-6-2 §4.4.3.
/// Models the associations between a client and the server (logical device) and
/// carries the authentication mechanism and HLS handshake used to open them.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AssociationLn {
    logical_name: ObisCode,
    version: AssociationLnVersion,
    object_list: Vec<ObjectListElement>,
    associated_partners_id: AssociatedPartnersId,
    application_context_name: ContextName,
    xdlms_context_info: XDLMSContextInfo,
    authentication_mechanism: AuthenticationMechanism,
    secret: Vec<u8>,
    association_status: u8,
    security_setup_reference: ObisCode,
    user_list: Vec<User>,
    current_user: Option<User>,
    /// Parsed object_list with structured access rights.
    #[serde(skip)]
    parsed_object_list: Vec<ObjectListEntry>,
    /// Transient HLS handshake state — not part of the COSEM attributes.
    /// Client-to-server challenge (CtoS) received in the AARQ (Pass 1).
    #[serde(skip)]
    ctos: Option<Vec<u8>>,
    /// Server-to-client challenge (StoC) sent in the AARE (Pass 2).
    #[serde(skip)]
    stoc: Option<Vec<u8>>,
    /// Cryptographic material for the HLS handshake (mechanisms 5/6/8/9).
    /// Not needed for the plain-hash mechanisms 3/4.
    #[serde(skip)]
    hls_context: Option<HlsContext>,
    /// Mechanism used for the in-flight four-pass HLS handshake (may differ
    /// from [`Self::authentication_mechanism`] when the client proposes the
    /// generic mechanism 2 against a GMAC-configured association).
    #[serde(skip)]
    hls_handshake_mechanism: Option<AuthMechanism>,
    /// Consecutive failed `reply_to_HLS_authentication` attempts, for rate
    /// limiting (see [`Self::reply_to_hls_authentication_checked`]).
    #[serde(skip)]
    hls_failures: u8,
}

/// Consecutive HLS-authentication failures allowed before the association
/// locks out further attempts (a fresh AARQ Pass 1/2 is required to reset the
/// counter), mitigating brute-force guessing of the challenge response.
const MAX_HLS_FAILURES: u8 = 5;

impl AssociationLn {
    /// Builds a new [`AssociationLn`] from its configuration.
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
            parsed_object_list: Vec::new(),
            ctos: None,
            stoc: None,
            hls_context: None,
            hls_handshake_mechanism: None,
            hls_failures: 0,
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

    /// Sets the cryptographic material for the HLS handshake (mechanisms 5/6/8/9).
    pub fn set_hls_context(&mut self, ctx: HlsContext) {
        self.hls_context = Some(ctx);
    }

    /// Updates the client system title used by title-bound HLS mechanisms.
    pub fn set_client_system_title(&mut self, title: Vec<u8>) {
        if let Some(ctx) = self.hls_context.as_mut() {
            ctx.client_system_title = title;
        }
    }

    /// Records the mechanism proposed in the AARQ for the four-pass handshake.
    pub fn set_hls_handshake_mechanism(&mut self, mechanism: AuthMechanism) {
        self.hls_handshake_mechanism = Some(mechanism);
    }

    fn hls_mechanism(&self) -> AuthMechanism {
        self.hls_handshake_mechanism.unwrap_or(self.authentication_mechanism)
    }

    /// Server system title for the AARE responding-AP-title on HLS pass 1/2.
    pub fn responding_ap_title_for_hls(&self) -> Option<Vec<u8>> {
        self.hls_context.as_ref().map(|ctx| ctx.server_system_title.clone()).filter(|title| title.len() == 8)
    }

    /// Returns the authentication mechanism of this association (attribute 6).
    pub fn authentication_mechanism(&self) -> AuthenticationMechanism {
        self.authentication_mechanism
    }

    /// Returns the LLS/HLS secret (attribute 7).
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Sets the association status (attribute 8): 0 = non-associated,
    /// 1 = association-pending, 2 = associated.
    pub fn set_association_status(&mut self, status: u8) {
        self.association_status = status;
    }

    /// Current association status (attribute 8): 0 non-associated, 1 pending, 2 associated.
    pub fn association_status(&self) -> u8 {
        self.association_status
    }

    /// Method 2: `change_HLS_secret` — replaces the secret (password/key).
    fn change_hls_secret(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        match data {
            CosemDataType::OctetString(secret) => {
                // Zeroize the replaced secret so it does not linger in memory.
                zeroize::Zeroize::zeroize(&mut self.secret);
                self.secret = secret;
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
    /// [`AssociationLn::set_hls_context`].
    fn reply_to_hls_authentication(&self, data: CosemDataType) -> Result<CosemDataType, String> {
        let CosemDataType::OctetString(f_stoc) = data else {
            return Err("Expected octet-string for f(StoC)".to_string());
        };
        let mechanism = self.hls_mechanism();

        // LLS does not use the four-pass reply_to_HLS: the secret is compared
        // directly (compatible with the LLS password carried in the AARQ).
        if mechanism == AuthMechanism::Lls {
            return if self.secret.len() == f_stoc.len() && self.secret.ct_eq(f_stoc.as_slice()).into() {
                Ok(CosemDataType::Null)
            } else {
                Err("LLS authentication failed".to_string())
            };
        }

        let stoc = self.stoc.as_ref().ok_or("StoC challenge not set (Pass 2 missing)")?;
        let ctos = self.ctos.as_ref().ok_or("CtoS challenge not set (Pass 1 missing)")?;

        match mechanism {
            // Mechanisms 3/4: f(challenge) = HASH(challenge ‖ secret).
            AuthMechanism::HlsMd5 | AuthMechanism::HlsSha1 => {
                let secret = self.secret_bytes()?;
                let expected = hls::hash_legacy(mechanism, stoc, secret).ok_or("HLS hash computation failed")?;
                if expected != f_stoc {
                    return Err("HLS authentication failed: f(StoC) mismatch".to_string());
                }
                let f_ctos = hls::hash_legacy(mechanism, ctos, secret).ok_or("HLS hash computation failed")?;
                Ok(CosemDataType::OctetString(f_ctos))
            }
            // Mechanisms 6/9: f = HASH(secret ‖ ST_a ‖ ST_b ‖ chal_a ‖ chal_b).
            AuthMechanism::HlsSha256 | AuthMechanism::HlsGostStreebog => {
                let secret = self.secret_bytes()?;
                let ctx = self.hls_context.as_ref().ok_or("HLS context (system titles) not set")?;
                let expected = hls::hash_with_titles(
                    mechanism,
                    secret,
                    &ctx.client_system_title,
                    &ctx.server_system_title,
                    stoc,
                    ctos,
                )
                .ok_or("HLS hash computation failed")?;
                if expected != f_stoc {
                    return Err("HLS authentication failed: f(StoC) mismatch".to_string());
                }
                let f_ctos = hls::hash_with_titles(
                    mechanism,
                    secret,
                    &ctx.server_system_title,
                    &ctx.client_system_title,
                    ctos,
                    stoc,
                )
                .ok_or("HLS hash computation failed")?;
                Ok(CosemDataType::OctetString(f_ctos))
            }
            // Mechanism 5: f = SC ‖ IC ‖ GMAC(SC ‖ AK ‖ challenge), 12-octet tag.
            AuthMechanism::HlsGmac => {
                let ctx = self.hls_context.as_ref().ok_or("HLS context not configured for GMAC")?;
                if f_stoc.len() != 17 {
                    return Err("f(StoC) must be 17 octets (SC ‖ IC ‖ 12-octet tag)".to_string());
                }
                let sc = f_stoc[0];
                if sc != ctx.security_control_byte {
                    return Err("f(StoC) security control byte mismatch".to_string());
                }
                let client_iv = build_iv(&ctx.client_system_title, &f_stoc[1..5])?;
                let aad_stoc = [&[sc][..], &ctx.authentication_key, stoc].concat();
                if gmac_tag(&ctx.encryption_key, &client_iv, &aad_stoc)? != f_stoc[5..17] {
                    return Err("HLS authentication failed: GMAC f(StoC) mismatch".to_string());
                }
                let server_ic = ctx.server_invocation_counter.to_be_bytes();
                let server_iv = build_iv(&ctx.server_system_title, &server_ic)?;
                let aad_ctos = [&[ctx.security_control_byte][..], &ctx.authentication_key, ctos].concat();
                let tag = gmac_tag(&ctx.encryption_key, &server_iv, &aad_ctos)?;
                Ok(CosemDataType::OctetString(assemble_sc_ic_mac(ctx.security_control_byte, &server_ic, &tag)))
            }
            // Mechanism 8 (GOST): f = SC ‖ IC ‖ KUZN_CMAC(LSB256(K_EM), IV ‖ SC ‖ chal_a ‖ chal_b).
            AuthMechanism::HlsGostCmac => {
                let ctx = self.hls_context.as_ref().ok_or("HLS context not configured for GOST CMAC")?;
                if f_stoc.len() != 21 {
                    return Err("f(StoC) must be 21 octets (SC ‖ IC ‖ 16-octet MAC)".to_string());
                }
                let sc = f_stoc[0];
                if sc != ctx.security_control_byte {
                    return Err("f(StoC) security control byte mismatch".to_string());
                }
                let client_iv = build_iv(&ctx.client_system_title, &f_stoc[1..5])?;
                let expected = hls::gost_cmac(&ctx.gost_key, &client_iv, sc, stoc, ctos).map_err(str::to_string)?;
                if expected != f_stoc[5..21] {
                    return Err("HLS authentication failed: GOST CMAC f(StoC) mismatch".to_string());
                }
                let server_ic = ctx.server_invocation_counter.to_be_bytes();
                let server_iv = build_iv(&ctx.server_system_title, &server_ic)?;
                let mac = hls::gost_cmac(&ctx.gost_key, &server_iv, ctx.security_control_byte, ctos, stoc)
                    .map_err(str::to_string)?;
                Ok(CosemDataType::OctetString(assemble_sc_ic_mac(ctx.security_control_byte, &server_ic, &mac)))
            }
            // Mechanism 7 (ECDSA): f = SIGN(d, ST_a ‖ ST_b ‖ chal_a ‖ chal_b),
            // hashed with the suite's SHA-256 (P-256) or SHA-384 (P-384).
            AuthMechanism::HlsEcdsa => {
                let ctx = self.hls_context.as_ref().ok_or("HLS context not configured for ECDSA")?;
                let suite = SecuritySuite::from_id(ctx.security_control_byte & 0x0F)
                    .filter(|s| s.has_public_key())
                    .ok_or("ECDSA (mechanism 7) requires security suite 1 or 2")?;
                let msg_c = [&ctx.client_system_title[..], &ctx.server_system_title, stoc, ctos].concat();
                signature::ecdsa_verify(suite, &ctx.peer_public_key, &msg_c, &f_stoc)
                    .map_err(|e| format!("HLS authentication failed: ECDSA f(StoC) invalid: {e}"))?;
                let msg_s = [&ctx.server_system_title[..], &ctx.client_system_title, ctos, stoc].concat();
                let sig = signature::ecdsa_sign(suite, &ctx.signing_key, &msg_s).map_err(|e| e.to_string())?;
                Ok(CosemDataType::OctetString(sig))
            }
            // Mechanism 10 (GOST 34.10-2018-256): f = SIGN(d, ST_a ‖ ST_b ‖
            // chal_a ‖ chal_b) over curve paramSetB, Streebog-256.
            AuthMechanism::HlsGostSignature => {
                let ctx = self.hls_context.as_ref().ok_or("HLS context not configured for GOST signature")?;
                let msg_c = [&ctx.client_system_title[..], &ctx.server_system_title, stoc, ctos].concat();
                gost3410::gost_verify(&ctx.peer_public_key, &msg_c, &f_stoc)
                    .map_err(|e| format!("HLS authentication failed: GOST 34.10 f(StoC) invalid: {e:?}"))?;
                let msg_s = [&ctx.server_system_title[..], &ctx.client_system_title, ctos, stoc].concat();
                let sig = gost3410::gost_sign(&ctx.signing_key, &msg_s)
                    .map_err(|e| format!("GOST 34.10 signing failed: {e:?}"))?;
                Ok(CosemDataType::OctetString(sig.to_vec()))
            }
            // Mechanism 2 (manufacturer-specific): f(challenge) = AES-128 over
            // the challenge keyed by the secret (Gurux / TI "high" scheme).
            AuthMechanism::HlsManufacturer => {
                let secret = self.secret_bytes()?;
                let expected = hls::manufacturer_aes(secret, stoc);
                if expected != f_stoc {
                    return Err("HLS authentication failed: f(StoC) mismatch".to_string());
                }
                Ok(CosemDataType::OctetString(hls::manufacturer_aes(secret, ctos)))
            }
            AuthMechanism::None => Err("mechanism 0 does not use HLS authentication".to_string()),
            AuthMechanism::Lls => unreachable!("LLS handled above"),
        }
    }

    /// Rate-limited wrapper around [`Self::reply_to_hls_authentication`]
    /// (method 1): after [`MAX_HLS_FAILURES`] consecutive failed attempts,
    /// further attempts are rejected without even checking the response,
    /// mitigating brute-force guessing of the challenge response. The
    /// counter resets on a successful authentication.
    fn reply_to_hls_authentication_checked(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        if self.hls_failures >= MAX_HLS_FAILURES {
            return Err("HLS authentication locked out after too many failed attempts".to_string());
        }
        match self.reply_to_hls_authentication(data) {
            Ok(reply) => {
                self.hls_failures = 0;
                Ok(reply)
            }
            Err(e) => {
                self.hls_failures = self.hls_failures.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Returns the secret as bytes.
    fn secret_bytes(&self) -> Result<&[u8], String> {
        Ok(&self.secret)
    }

    /// Method 3: `add_object` — adds an `object_list_element` to `object_list`.
    /// If an object with the same (class_id, logical_name) already exists, it is updated.
    fn add_object(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let elem = ObjectListElement::try_from(&data)?;
        let key = (elem.class_id, elem.logical_name.to_bytes());
        if let Some(existing) = self.object_list.iter_mut().find(|e| (e.class_id, e.logical_name.to_bytes()) == key) {
            *existing = elem;
        } else {
            self.object_list.push(elem);
        }
        Ok(CosemDataType::Null)
    }

    /// Method 4: `remove_object` — removes an `object_list_element` from `object_list`.
    fn remove_object(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let elem = ObjectListElement::try_from(&data)?;
        let key = (elem.class_id, elem.logical_name.to_bytes());
        let before = self.object_list.len();
        self.object_list.retain(|e| (e.class_id, e.logical_name.to_bytes()) != key);
        if self.object_list.len() == before {
            return Err("Object not found in object_list".to_string());
        }
        Ok(CosemDataType::Null)
    }

    /// Method 5 (version 2): `add_user` — adds a `user { id, name }` entry to
    /// `user_list`. If an entry with the same user id already exists, it is
    /// updated (IEC 62056-6-2 §5.3.7.3.5).
    fn add_user(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let user = User::try_from(&data)?;
        let id = user.user_id;
        if let Some(existing) = self.user_list.iter_mut().find(|e| e.user_id == id) {
            *existing = user;
        } else {
            self.user_list.push(user);
        }
        Ok(CosemDataType::Null)
    }

    /// Method 6 (version 2): `remove_user` — removes the `user` entry with the
    /// given id from `user_list` (IEC 62056-6-2 §5.3.7.3.6).
    fn remove_user(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let user = User::try_from(&data)?;
        let id = user.user_id;
        let before = self.user_list.len();
        self.user_list.retain(|e| e.user_id != id);
        if self.user_list.len() == before {
            return Err("User not found in user_list".to_string());
        }
        Ok(CosemDataType::Null)
    }

    // --- Access rights methods (IEC 62056-5-3, 5.3.7.2.2) ---

    /// Finds an object_list entry by class_id and logical name.
    pub fn find_object(&self, class_id: u16, logical_name: &ObisCode) -> Option<&ObjectListEntry> {
        self.parsed_object_list.iter().find(|e| e.class_id == class_id && e.logical_name == logical_name.to_bytes())
    }

    /// Checks whether a read is allowed for the given object and attribute.
    pub fn can_read(&self, class_id: u16, logical_name: &ObisCode, attribute_id: i8) -> bool {
        self.find_object(class_id, logical_name).map(|e| e.can_read(attribute_id)).unwrap_or(false)
    }

    /// Checks whether a write is allowed for the given object and attribute.
    pub fn can_write(&self, class_id: u16, logical_name: &ObisCode, attribute_id: i8) -> bool {
        self.find_object(class_id, logical_name).map(|e| e.can_write(attribute_id)).unwrap_or(false)
    }

    /// Checks whether a method invocation is allowed.
    pub fn can_invoke(&self, class_id: u16, logical_name: &ObisCode, method_id: i8) -> bool {
        self.find_object(class_id, logical_name).map(|e| e.can_invoke(method_id)).unwrap_or(false)
    }

    /// Returns the parsed object_list.
    pub fn object_list_entries(&self) -> &[ObjectListEntry] {
        &self.parsed_object_list
    }

    /// Adds an object_list entry with the given access rights.
    pub fn add_object_with_access(&mut self, entry: ObjectListEntry) {
        // Remove existing entry for the same object.
        self.parsed_object_list.retain(|e| !(e.class_id == entry.class_id && e.logical_name == entry.logical_name));
        self.parsed_object_list.push(entry);
    }
}

/// Assembles the `SC ‖ IC ‖ MAC` response used by the GMAC (5) and GOST CMAC (8)
/// mechanisms.
fn assemble_sc_ic_mac(security_control: u8, invocation_counter: &[u8], mac: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + invocation_counter.len() + mac.len());
    out.push(security_control);
    out.extend_from_slice(invocation_counter);
    out.extend_from_slice(mac);
    out
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
    let nonce = Nonce::from(*iv);
    let out = match ek.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(ek).map_err(|_| "invalid EK".to_string())?;
            cipher
                .encrypt(&nonce, aead::Payload { msg: &[], aad })
                .map_err(|_| "GMAC computation failed".to_string())?
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(ek).map_err(|_| "invalid EK".to_string())?;
            cipher
                .encrypt(&nonce, aead::Payload { msg: &[], aad })
                .map_err(|_| "GMAC computation failed".to_string())?
        }
        _ => return Err("EK must be 16 or 32 octets".to_string()),
    };
    // Empty plaintext → the output consists solely of the 16-octet tag.
    Ok(out[..12].to_vec())
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
            (2, CosemDataType::Array(self.object_list.iter().cloned().map(CosemDataType::from).collect())),
            (3, CosemDataType::from(self.associated_partners_id.clone())),
            (4, CosemDataType::from(self.application_context_name.clone())),
            (5, CosemDataType::from(self.xdlms_context_info.clone())),
            (6, self.authentication_mechanism_name()),
            (7, CosemDataType::OctetString(self.secret.clone())),
            (8, CosemDataType::Enum(self.association_status)),
        ];
        // Attribute 9 (security_setup_reference) is present starting from version 1.
        if matches!(self.version, AssociationLnVersion::Version1 | AssociationLnVersion::Version2) {
            attrs.push((9, CosemDataType::OctetString(self.security_setup_reference.to_bytes())));
        }
        // Attributes 10 (user_list) and 11 (current_user) were added in version 2.
        if matches!(self.version, AssociationLnVersion::Version2) {
            attrs.push((10, CosemDataType::Array(self.user_list.iter().cloned().map(CosemDataType::from).collect())));
            match &self.current_user {
                Some(user) => attrs.push((11, CosemDataType::from(user.clone()))),
                None => attrs.push((11, CosemDataType::Null)),
            }
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
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
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
            CosemDataType::Array(list) => list
                .iter()
                .map(|e| ObjectListElement::try_from(e).map_err(|_| BerError::InvalidValue))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(BerError::InvalidTag),
        };
        self.associated_partners_id = AssociatedPartnersId::try_from(&seq[3]).map_err(|_| BerError::InvalidValue)?;
        self.application_context_name = ContextName::try_from(&seq[4]).map_err(|_| BerError::InvalidValue)?;
        self.xdlms_context_info = XDLMSContextInfo::try_from(&seq[5]).map_err(|_| BerError::InvalidValue)?;
        self.authentication_mechanism = match &seq[6] {
            CosemDataType::OctetString(mech) => {
                let id = *mech.last().ok_or(BerError::InvalidLength)?;
                AuthMechanism::from_id(id).ok_or(BerError::InvalidValue)?
            }
            _ => return Err(BerError::InvalidTag),
        };
        self.secret = match &seq[7] {
            CosemDataType::OctetString(s) => s.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.association_status = match &seq[8] {
            CosemDataType::Enum(v) | CosemDataType::Unsigned(v) => *v,
            _ => return Err(BerError::InvalidTag),
        };
        // Attribute 9 (security_setup_reference) is present in versions 1 and 2.
        if seq.len() >= 10 {
            self.security_setup_reference = match &seq[9] {
                CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                    ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                }
                _ => return Err(BerError::InvalidTag),
            };
        }
        // Attributes 10 and 11 are present only in version 2.
        self.version = if seq.len() == 12 {
            self.user_list = match &seq[10] {
                CosemDataType::Array(list) => list
                    .iter()
                    .map(|e| User::try_from(e).map_err(|_| BerError::InvalidValue))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(BerError::InvalidTag),
            };
            self.current_user = match &seq[11] {
                CosemDataType::Null => None,
                other => Some(User::try_from(other).map_err(|_| BerError::InvalidValue)?),
            };
            AssociationLnVersion::Version2
        } else if seq.len() == 10 {
            AssociationLnVersion::Version1
        } else {
            AssociationLnVersion::Version0
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let params = params.ok_or("Missing method parameter")?;
        let is_v2 = matches!(self.version, AssociationLnVersion::Version2);
        match method_id {
            1 => self.reply_to_hls_authentication_checked(params),
            2 => self.change_hls_secret(params),
            3 => self.add_object(params),
            4 => self.remove_object(params),
            // add_user / remove_user exist only in version 2.
            5 if is_v2 => self.add_user(params),
            6 if is_v2 => self.remove_user(params),
            _ => Err(format!("Method {} not supported for Association LN version {}", method_id, self.version())),
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
        let oid = self.authentication_mechanism.oid();
        let mut value = vec![0x09, 0x07];
        value.extend_from_slice(&oid);
        CosemDataType::OctetString(value)
    }
}

/// Writes a BER/A-XDR length octet (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
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
    use sha1::{Digest, Sha1};

    fn sample(version: AssociationLnVersion) -> AssociationLn {
        AssociationLn::new(AssociationLnConfig {
            logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
            version,
            object_list: vec![],
            associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
            application_context_name: ContextName::OctetString(vec![
                0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
            ]),
            xdlms_context_info: XDLMSContextInfo {
                conformance: vec![],
                max_receive_pdu_size: 0xFFFF,
                max_send_pdu_size: 0xFFFF,
                dlms_version_number: 6,
                quality_of_service: 0,
                cyphering_info: vec![],
            },
            authentication_mechanism: AuthenticationMechanism::HlsSha1,
            secret: b"12345678".to_vec(),
            association_status: 0,
            security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
            user_list: vec![],
            current_user: None,
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
        for v in [AssociationLnVersion::Version0, AssociationLnVersion::Version1, AssociationLnVersion::Version2] {
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
        use crate::types::attrs::ObjectListElement;
        let mut obj = sample(AssociationLnVersion::Version1);
        let element = CosemDataType::from(ObjectListElement {
            class_id: 1,
            version: 0,
            logical_name: ObisCode::new(0, 0, 96, 1, 0, 255),
            access_rights: crate::types::attrs::AccessRight { attribute_access: vec![], method_access: vec![] },
        });
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
        obj.secret = secret.clone();
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
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(wrong))).is_err());
    }

    /// After [`MAX_HLS_FAILURES`] consecutive wrong `f(StoC)` values, further
    /// attempts are rejected outright — even a correct one — mitigating
    /// brute-force guessing of the challenge response.
    #[test]
    fn hls_authentication_locks_out_after_repeated_failures() {
        let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let ctos = vec![0x11, 0x22, 0x33, 0x44];
        let mut obj = sample(AssociationLnVersion::Version1);
        obj.secret = secret.clone();
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos);

        let f_stoc = {
            let mut h = Sha1::new();
            h.update(&stoc);
            h.update(&secret);
            h.finalize().to_vec()
        };
        let mut wrong = f_stoc.clone();
        wrong[0] ^= 0xFF;

        for _ in 0..MAX_HLS_FAILURES {
            assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(wrong.clone()))).is_err());
        }
        // The correct response is now rejected too: the lockout persists.
        let err = obj.invoke_method(1, Some(CosemDataType::OctetString(f_stoc))).unwrap_err();
        assert!(err.contains("locked out"), "unexpected error: {err}");
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
        obj.authentication_mechanism = AuthenticationMechanism::HlsGmac;
        obj.set_stoc(stoc);
        obj.set_ctos(ctos);
        let mut ctx = HlsContext::default();
        ctx.security_control_byte = 0x10;
        ctx.encryption_key = ek;
        ctx.authentication_key = ak;
        ctx.server_system_title = server_st;
        ctx.server_invocation_counter = 0x01234567;
        ctx.client_system_title = client_st;
        obj.set_hls_context(ctx);

        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("GMAC authentication should succeed");
        assert_eq!(reply, CosemDataType::OctetString(expected_f_ctos));

        // Corrupting the client tag → f(StoC) verification fails.
        let mut bad = f_stoc;
        bad[16] ^= 0x01;
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
    }

    /// Mechanisms 6 (SHA-256) and 9 (Streebog): four-pass handshake through the
    /// association object, using the unified security model.
    #[test]
    fn hls_sha256_and_streebog_four_pass_via_association() {
        for mech in [AuthMechanism::HlsSha256, AuthMechanism::HlsGostStreebog] {
            let secret = b"0123456789abcdef".to_vec(); // >= 128 bits
            let st_c = b"CLIENT01".to_vec();
            let st_s = b"SERVER01".to_vec();
            let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD];
            let ctos = vec![0x11, 0x22, 0x33, 0x44];
            let mut obj = sample(AssociationLnVersion::Version1);
            obj.authentication_mechanism = mech;
            obj.secret = secret.clone();
            obj.set_stoc(stoc.clone());
            obj.set_ctos(ctos.clone());
            let mut ctx = HlsContext::default();
            ctx.client_system_title = st_c.clone();
            ctx.server_system_title = st_s.clone();
            obj.set_hls_context(ctx);
            let f_stoc = hls::hash_with_titles(mech, &secret, &st_c, &st_s, &stoc, &ctos).unwrap();
            let expected = hls::hash_with_titles(mech, &secret, &st_s, &st_c, &ctos, &stoc).unwrap();
            let reply = obj
                .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
                .expect("HLS hash authentication should succeed");
            assert_eq!(reply, CosemDataType::OctetString(expected));
            let mut bad = f_stoc;
            bad[0] ^= 0xFF;
            assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
        }
    }

    /// Mechanism 8 (GOST HLS CMAC, Kuznyechik): four-pass handshake through the
    /// association object.
    #[test]
    fn hls_gost_cmac_four_pass_via_association() {
        let k_em = hex(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let st_c = hex(b"4d4d4d0000000001");
        let st_s = hex(b"4d4d4d0000bc614e");
        let stoc = hex(b"8899aabbccddeeff");
        let ctos = hex(b"0011223344556677");
        let sc = 0x30u8;
        let client_ic = 0x0000_0001u32;
        let server_ic = 0x0123_4567u32;

        let mut obj = sample(AssociationLnVersion::Version1);
        obj.authentication_mechanism = AuthMechanism::HlsGostCmac;
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos.clone());
        let mut ctx = HlsContext::default();
        ctx.client_system_title = st_c.clone();
        ctx.server_system_title = st_s.clone();
        ctx.security_control_byte = sc;
        ctx.server_invocation_counter = server_ic;
        ctx.gost_key = k_em.clone();
        obj.set_hls_context(ctx);

        // Client's f(StoC) = SC ‖ IC_C ‖ KUZN_CMAC(K_EM, IV_C ‖ SC ‖ StoC ‖ CtoS).
        let iv_c = [&st_c[..], &client_ic.to_be_bytes()].concat();
        let mac_c = hls::gost_cmac(&k_em, &iv_c, sc, &stoc, &ctos).unwrap();
        let f_stoc = assemble_sc_ic_mac(sc, &client_ic.to_be_bytes(), &mac_c);

        let iv_s = [&st_s[..], &server_ic.to_be_bytes()].concat();
        let mac_s = hls::gost_cmac(&k_em, &iv_s, sc, &ctos, &stoc).unwrap();
        let expected = assemble_sc_ic_mac(sc, &server_ic.to_be_bytes(), &mac_s);

        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("GOST CMAC authentication should succeed");
        assert_eq!(reply, CosemDataType::OctetString(expected));

        let mut bad = f_stoc;
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
    }

    /// Mechanism 2 (manufacturer-specific AES): four-pass handshake through the
    /// association object.
    #[test]
    fn hls_manufacturer_four_pass_via_association() {
        let secret = b"12345678".to_vec();
        let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let ctos = vec![0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let mut obj = sample(AssociationLnVersion::Version1);
        obj.authentication_mechanism = AuthMechanism::HlsManufacturer;
        obj.secret = secret.clone();
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos.clone());
        let f_stoc = hls::manufacturer_aes(&secret, &stoc);
        let expected = hls::manufacturer_aes(&secret, &ctos);
        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("manufacturer HLS should succeed");
        assert_eq!(reply, CosemDataType::OctetString(expected));
        let mut bad = f_stoc;
        bad[0] ^= 0xFF;
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
    }

    /// Mechanism 7 (ECDSA, suite 1 / P-256): four-pass signature handshake
    /// through the association object.
    #[test]
    fn hls_ecdsa_four_pass_via_association() {
        use p256::ecdsa::SigningKey;
        let st_c = b"CLIENT01".to_vec();
        let st_s = b"SERVER01".to_vec();
        let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let ctos = vec![0x11, 0x22, 0x33, 0x44];
        let d_client = hex(b"418073C239FA6125011DE4D6CD2E645780289F761BB21BFB0835CB5585E8B373");
        let d_server = hex(b"1122334455667788112233445566778811223344556677881122334455667788");
        let pk_client =
            SigningKey::from_slice(&d_client).unwrap().verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let pk_server =
            SigningKey::from_slice(&d_server).unwrap().verifying_key().to_sec1_point(false).as_bytes().to_vec();

        let mut obj = sample(AssociationLnVersion::Version1);
        obj.authentication_mechanism = AuthMechanism::HlsEcdsa;
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos.clone());
        let mut ctx = HlsContext::default();
        ctx.client_system_title = st_c.clone();
        ctx.server_system_title = st_s.clone();
        ctx.security_control_byte = 0x31; // suite 1 in the low nibble
        ctx.signing_key = d_server;
        ctx.peer_public_key = pk_client;
        obj.set_hls_context(ctx);

        // Client's f(StoC) = SIGN(d_C, ST_C ‖ ST_S ‖ StoC ‖ CtoS).
        let msg_c = [&st_c[..], &st_s, &stoc, &ctos].concat();
        let f_stoc = signature::ecdsa_sign(SecuritySuite::Suite1, &d_client, &msg_c).unwrap();
        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("ECDSA authentication should succeed");
        // Server's f(CtoS) must verify against the server key over the swapped message.
        let msg_s = [&st_s[..], &st_c, &ctos, &stoc].concat();
        let CosemDataType::OctetString(sig) = reply else {
            panic!("expected octet-string reply");
        };
        signature::ecdsa_verify(SecuritySuite::Suite1, &pk_server, &msg_s, &sig).unwrap();

        let mut bad = f_stoc;
        bad[10] ^= 0x01;
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
    }

    /// Mechanism 10 (GOST 34.10-2018-256): four-pass signature handshake through
    /// the association object, with the A.5.3 client/server signing keys.
    #[test]
    fn hls_gost_signature_four_pass_via_association() {
        let st_c = hex(b"ff00ee11dd22cc33");
        let st_s = hex(b"bb44aa5599668877");
        let stoc = hex(b"8899aabbccddeeff");
        let ctos = hex(b"0011223344556677");
        let d_client = hex(b"48494a4b4c4d4e4f4041424344454647bbbbaaaa999988884444555566667777");
        let d_server = hex(b"58595a5b5c5d5e5f5051525354555657ffffffffeeeeeeee8888888899999999");
        let pk_client = gost3410::public_key(&d_client).unwrap();
        let pk_server = gost3410::public_key(&d_server).unwrap();

        let mut obj = sample(AssociationLnVersion::Version1);
        obj.authentication_mechanism = AuthMechanism::HlsGostSignature;
        obj.set_stoc(stoc.clone());
        obj.set_ctos(ctos.clone());
        let mut ctx = HlsContext::default();
        ctx.client_system_title = st_c.clone();
        ctx.server_system_title = st_s.clone();
        ctx.signing_key = d_server.to_vec();
        ctx.peer_public_key = pk_client.to_vec();
        obj.set_hls_context(ctx);

        // Client's f(StoC) = SIGN(d_C, ST_C ‖ ST_S ‖ StoC ‖ CtoS).
        let msg_c = [&st_c[..], &st_s, &stoc, &ctos].concat();
        let f_stoc = gost3410::gost_sign(&d_client, &msg_c).unwrap().to_vec();
        let reply = obj
            .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
            .expect("GOST 34.10 authentication should succeed");
        let msg_s = [&st_s[..], &st_c, &ctos, &stoc].concat();
        let CosemDataType::OctetString(sig) = reply else {
            panic!("expected octet-string reply");
        };
        gost3410::gost_verify(&pk_server, &msg_s, &sig).unwrap();

        let mut bad = f_stoc;
        bad[10] ^= 0x01;
        assert!(obj.invoke_method(1, Some(CosemDataType::OctetString(bad))).is_err());
    }

    /// Every mechanism id round-trips through attribute 6 (mechanism-name OID).
    #[test]
    fn mechanism_name_oid_covers_all_ids() {
        for id in 0..=10u8 {
            let mut obj = sample(AssociationLnVersion::Version0);
            obj.authentication_mechanism = AuthMechanism::from_id(id).unwrap();
            if let CosemDataType::OctetString(oid) = obj.authentication_mechanism_name() {
                assert_eq!(oid, vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, id]);
            } else {
                panic!("mechanism name must be an octet-string");
            }
        }
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
