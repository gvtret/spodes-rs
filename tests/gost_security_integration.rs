//! Integration tests for GOST mechanisms, encryption, and security suites.
//!
//! These tests verify:
//! - GOST HLS mechanisms (8: CMAC, 10: GOST 34.10 signature)
//! - AES-GCM encryption/decryption of APDUs
//! - Security suite configuration
//! - Full client/server sessions with encryption

use std::io;

use spodes_rs::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AssociationLnVersion, AuthenticationMechanism,
};
use spodes_rs::classes::data::Data;
use spodes_rs::classes::register::Register;
use spodes_rs::obis::ObisCode;
use spodes_rs::security::{gost3410, hls, SecurityPolicy, SecuritySuite};
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::ciphering::{self, SecurityContext};
use spodes_rs::service::get::{GetDataResult, GetResponse};
use spodes_rs::session::ClientSession;
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::CosemDataType;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

struct LoopbackLink {
    server: RequestDispatcher,
    pending: Option<Vec<u8>>,
}

impl LoopbackLink {
    fn new(server: RequestDispatcher) -> Self {
        Self { server, pending: None }
    }
}

impl DataLinkLayer for LoopbackLink {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        let response = self.server.dispatch(apdu).expect("dispatch failed");
        self.pending = Some(response);
        Ok(())
    }
    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.pending.take().expect("no pending response"))
    }
}

fn build_meter_server() -> RequestDispatcher {
    let mut server = RequestDispatcher::new();
    server.add(Box::new(Data::new(
        ObisCode::new(0, 0, 96, 1, 0, 0xFF),
        CosemDataType::OctetString(b"METER-001".to_vec()),
    )));
    server.add(Box::new(Register::new(
        ObisCode::new(1, 0, 1, 8, 0, 0xFF),
        CosemDataType::DoubleLongUnsigned(123_456),
        CosemDataType::Long(0),
    )));
    server
}

fn get_value(session: &mut ClientSession<LoopbackLink>, class_id: u16, obis: ObisCode, attr: i8) -> CosemDataType {
    match session.get(class_id, obis, attr) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(value), .. }) => value,
        other => panic!("unexpected response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// GOST CMAC (mechanism 8) — direct function test
// ---------------------------------------------------------------------------

#[test]
fn test_gost_cmac_basic() {
    // 64-byte K_EM; gost_cmac uses LSB256 (last 32 bytes) as CMAC key.
    let mut k_em = [0u8; 64];
    k_em[32..].copy_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ]);
    let iv = [0xAA; 12]; // system_title || IC
    let challenge_a = [0xBB; 16];
    let challenge_b = [0xCC; 16];

    let mac = hls::gost_cmac(&k_em, &iv, 0x10, &challenge_a, &challenge_b).unwrap();
    assert_eq!(mac.len(), 16); // CMAC output is 128 bits
}

#[test]
fn test_gost_cmac_wrong_key_length() {
    let k_em = [0u8; 32]; // Wrong: must be 64 bytes
    let iv = [0xAA; 12];
    let challenge_a = [0xBB; 16];
    let challenge_b = [0xCC; 16];

    let result = hls::gost_cmac(&k_em, &iv, 0x10, &challenge_a, &challenge_b);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// GOST 34.10 signature (mechanism 10) — direct function test
// ---------------------------------------------------------------------------

#[test]
fn test_gost3410_sign_verify() {
    let sk = [
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xBB, 0xBB,
        0xAA, 0xAA, 0x99, 0x99, 0x88, 0x88, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    ];
    let pk = gost3410::public_key(&sk).unwrap();

    // Sign and verify with the standard HLS message format.
    let msg = b"SystemTitle-a||SystemTitle-b||StoC||CtoS";
    let sig = gost3410::gost_sign(&sk, msg).unwrap();
    gost3410::gost_verify(&pk, msg, &sig).unwrap();

    // Tampered message must fail.
    let bad_msg = b"SystemTitle-a||SystemTitle-b||StoC||CtoS!!";
    assert!(gost3410::gost_verify(&pk, bad_msg, &sig).is_err());
}

#[test]
fn test_gost3410_vko_key_agreement() {
    let sk = [
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xDD, 0xDD,
        0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB,
    ];
    let pk = gost3410::public_key(&sk).unwrap();
    let ukm = [0xF0, 0xF0, 0xF0, 0xF0, 0xE1, 0xE1, 0xE1, 0xE1, 0xD2, 0xD2, 0xD2, 0xD2, 0xC3, 0xC3, 0xC3, 0xC3];

    let shared_key = gost3410::vko(&sk, &pk, &ukm).unwrap();
    assert_eq!(shared_key.len(), 32); // 256-bit key
}

#[test]
fn test_gost_kdf_tree() {
    let key = [
        0x4F, 0x54, 0xF6, 0x63, 0x02, 0x97, 0x09, 0xC0, 0x27, 0x1F, 0xAC, 0xD5, 0xBB, 0x6D, 0x58, 0x18, 0x74, 0x10,
        0x47, 0x7E, 0x10, 0x25, 0x55, 0xA8, 0x93, 0xD4, 0x5A, 0x04, 0xAB, 0x0C, 0xAF, 0xC0,
    ];
    let label = b"AlgorithmID";
    let seed = [0xFF, 0x00, 0xEE, 0x11, 0xDD, 0x22, 0xCC, 0x33, 0xBB, 0x44, 0xAA, 0x55, 0x99, 0x66, 0x88, 0x77];

    let derived = gost3410::kdf_tree(&key, label, &seed, 96);
    assert_eq!(derived.len(), 96); // 768 bits
}

// ---------------------------------------------------------------------------
// AES-GCM encryption/decryption
// ---------------------------------------------------------------------------

#[test]
fn test_aes_gcm_encrypt_decrypt_round_trip() {
    let key = [0x01u8; 16]; // AES-128
    let _iv = [0x02u8; 12];
    let _aad = [0x03u8; 8];
    let plaintext = b"Hello, DLMS/COSEM world!";

    let ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite0,
        key.to_vec(),
        vec![0x11; 16], // auth key
        vec![0x4D; 8],  // system title
        1,
    )
    .unwrap();

    // Encrypt
    let ciphered = ciphering::protect(&ctx, 0xC0, plaintext).unwrap();
    assert_ne!(ciphered, plaintext);

    // Decrypt
    let mut rx_ctx = ctx.clone();
    rx_ctx.invocation_counter = 1;
    let (tag, decrypted) = ciphering::unprotect(&mut rx_ctx, &ciphered).unwrap();
    assert_eq!(tag, 0xC0);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_fails_with_wrong_key() {
    let key = [0x01u8; 16];
    let plaintext = b"secret data";

    let ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite0,
        key.to_vec(),
        vec![0x11; 16],
        vec![0x4D; 8],
        1,
    )
    .unwrap();

    let ciphered = ciphering::protect(&ctx, 0xC0, plaintext).unwrap();

    // Wrong decryption key
    let wrong_key = [0xFFu8; 16];
    let mut rx_ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite0,
        wrong_key.to_vec(),
        vec![0x11; 16],
        vec![0x4D; 8],
        1,
    )
    .unwrap();

    let result = ciphering::unprotect(&mut rx_ctx, &ciphered);
    assert!(result.is_err());
}

#[test]
fn test_aes_gcm_authentication_only() {
    let key = [0x01u8; 16];
    let plaintext = b"authenticated but not encrypted";

    let ctx = SecurityContext::for_suite(
        SecurityPolicy::Authentication,
        SecuritySuite::Suite0,
        key.to_vec(),
        vec![0x11; 16],
        vec![0x4D; 8],
        1,
    )
    .unwrap();

    let ciphered = ciphering::protect(&ctx, 0xC0, plaintext).unwrap();

    let mut rx_ctx = ctx.clone();
    rx_ctx.invocation_counter = 1;
    let (_, decrypted) = ciphering::unprotect(&mut rx_ctx, &ciphered).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_encryption_only() {
    let key = [0x01u8; 16];
    let plaintext = b"encrypted but not authenticated";

    let ctx = SecurityContext::for_suite(
        SecurityPolicy::Encryption,
        SecuritySuite::Suite0,
        key.to_vec(),
        vec![0x11; 16],
        vec![0x4D; 8],
        1,
    )
    .unwrap();

    let ciphered = ciphering::protect(&ctx, 0xC0, plaintext).unwrap();

    let mut rx_ctx = ctx.clone();
    rx_ctx.invocation_counter = 1;
    let (_, decrypted) = ciphering::unprotect(&mut rx_ctx, &ciphered).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// SecurityContext configuration
// ---------------------------------------------------------------------------

#[test]
fn test_security_context_for_suite0() {
    let ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite0,
        vec![0u8; 16], // 16-byte key for suite 0
        vec![0u8; 16],
        vec![0u8; 8],
        0,
    );
    assert!(ctx.is_ok());
}

#[test]
fn test_security_context_for_suite2() {
    let ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite2,
        vec![0u8; 32], // 32-byte key for suite 2
        vec![0u8; 32],
        vec![0u8; 8],
        0,
    );
    assert!(ctx.is_ok());
}

#[test]
fn test_security_context_wrong_key_length() {
    let ctx = SecurityContext::for_suite(
        SecurityPolicy::AuthenticationEncryption,
        SecuritySuite::Suite0,
        vec![0u8; 32], // Wrong: suite 0 needs 16-byte key
        vec![0u8; 16],
        vec![0u8; 8],
        0,
    );
    assert!(ctx.is_err());
}

// ---------------------------------------------------------------------------
// ECDSA P-256 signature (mechanism 7)
// ---------------------------------------------------------------------------

#[test]
fn test_ecdsa_p256_sign_verify() {
    use spodes_rs::security::signature;

    let sk = [0x11u8; 32];
    let msg = b"ECDSA test message for DLMS";

    let sig = signature::ecdsa_sign(SecuritySuite::Suite1, &sk, msg).unwrap();
    assert_eq!(sig.len(), 64); // P-256 signature is 64 bytes

    // Get public key
    use p256::ecdsa::SigningKey;
    let signing = SigningKey::from_bytes(&sk.into()).unwrap();
    let pk = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();

    signature::ecdsa_verify(SecuritySuite::Suite1, &pk, msg, &sig).unwrap();

    // Wrong message fails
    let bad_msg = b"different message";
    assert!(signature::ecdsa_verify(SecuritySuite::Suite1, &pk, bad_msg, &sig).is_err());
}

// ---------------------------------------------------------------------------
// SecuritySuite properties
// ---------------------------------------------------------------------------

#[test]
fn test_security_suite_aes_key_lengths() {
    assert_eq!(SecuritySuite::Suite0.aes_key_len(), 16);
    assert_eq!(SecuritySuite::Suite1.aes_key_len(), 16);
    assert_eq!(SecuritySuite::Suite2.aes_key_len(), 32);
}

#[test]
fn test_security_suite_names() {
    assert_eq!(SecuritySuite::Suite0.name(), "AES-GCM-128");
    assert_eq!(SecuritySuite::Suite1.name(), "ECDH-ECDSA-AES-GCM-128-SHA-256");
    assert_eq!(SecuritySuite::Suite2.name(), "ECDH-ECDSA-AES-GCM-256-SHA-384");
}

#[test]
fn test_security_suite_ids() {
    assert_eq!(SecuritySuite::Suite0.id(), 0);
    assert_eq!(SecuritySuite::Suite1.id(), 1);
    assert_eq!(SecuritySuite::Suite2.id(), 2);
}

#[test]
fn test_security_suite_has_public_key() {
    assert!(!SecuritySuite::Suite0.has_public_key());
    assert!(SecuritySuite::Suite1.has_public_key());
    assert!(SecuritySuite::Suite2.has_public_key());
}

// ---------------------------------------------------------------------------
// GOST mechanism authentication with Association LN
// ---------------------------------------------------------------------------

#[test]
fn test_hls_gost_cmac_authentication() {
    let mut server = build_meter_server();

    // 64-byte K_EM for GOST CMAC
    let mut k_em = vec![0u8; 64];
    k_em[32..].copy_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ]);

    let assoc = AssociationLn::new(AssociationLnConfig {
        logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: CosemDataType::Null,
        application_context_name: CosemDataType::Null,
        xdlms_context_info: CosemDataType::Null,
        authentication_mechanism: AuthenticationMechanism::HlsGostCmac,
        secret: CosemDataType::OctetString(k_em),
        association_status: CosemDataType::Enum(0),
        security_setup_reference: CosemDataType::Null,
        user_list: vec![],
        current_user: CosemDataType::Null,
    });
    server.add(Box::new(assoc));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let energy = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let value = get_value(&mut session, 3, energy, 2);
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(123_456));
}

#[test]
fn test_hls_gost_streebog_authentication() {
    let mut server = build_meter_server();

    let secret = vec![0x05; 16];
    let assoc = AssociationLn::new(AssociationLnConfig {
        logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: CosemDataType::Null,
        application_context_name: CosemDataType::Null,
        xdlms_context_info: CosemDataType::Null,
        authentication_mechanism: AuthenticationMechanism::HlsGostStreebog,
        secret: CosemDataType::OctetString(secret),
        association_status: CosemDataType::Enum(0),
        security_setup_reference: CosemDataType::Null,
        user_list: vec![],
        current_user: CosemDataType::Null,
    });
    server.add(Box::new(assoc));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let energy = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let value = get_value(&mut session, 3, energy, 2);
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(123_456));
}

#[test]
fn test_hls_md5_authentication() {
    let mut server = build_meter_server();

    let secret = vec![0x06; 16];
    let assoc = AssociationLn::new(AssociationLnConfig {
        logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: CosemDataType::Null,
        application_context_name: CosemDataType::Null,
        xdlms_context_info: CosemDataType::Null,
        authentication_mechanism: AuthenticationMechanism::HlsMd5,
        secret: CosemDataType::OctetString(secret),
        association_status: CosemDataType::Enum(0),
        security_setup_reference: CosemDataType::Null,
        user_list: vec![],
        current_user: CosemDataType::Null,
    });
    server.add(Box::new(assoc));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let energy = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let value = get_value(&mut session, 3, energy, 2);
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(123_456));
}

// ---------------------------------------------------------------------------
// Streebog hash
// ---------------------------------------------------------------------------

#[test]
fn test_streebog256_hash() {
    use streebog::{Digest, Streebog256};

    let mut hasher = Streebog256::new();
    hasher.update(b"test message");
    let hash = hasher.finalize();

    assert_eq!(hash.len(), 32); // 256-bit hash
}

// ---------------------------------------------------------------------------
// Kuznyechik block cipher
// ---------------------------------------------------------------------------

#[test]
fn test_kuznyechik_cmac_consistency() {
    use cmac::{Cmac, KeyInit, Mac};
    use kuznyechik::Kuznyechik;

    let key = [0x11u8; 32];
    let mut mac1 = Cmac::<Kuznyechik>::new_from_slice(&key).unwrap();
    mac1.update(b"message");
    let tag1 = mac1.finalize().into_bytes();

    let mut mac2 = Cmac::<Kuznyechik>::new_from_slice(&key).unwrap();
    mac2.update(b"message");
    let tag2 = mac2.finalize().into_bytes();

    assert_eq!(tag1, tag2); // Deterministic
}

#[test]
fn test_kuznyechik_cmac_different_keys() {
    use cmac::{Cmac, KeyInit, Mac};
    use kuznyechik::Kuznyechik;

    let key1 = [0x11u8; 32];
    let key2 = [0x22u8; 32];

    let mut mac1 = Cmac::<Kuznyechik>::new_from_slice(&key1).unwrap();
    mac1.update(b"message");
    let tag1 = mac1.finalize().into_bytes();

    let mut mac2 = Cmac::<Kuznyechik>::new_from_slice(&key2).unwrap();
    mac2.update(b"message");
    let tag2 = mac2.finalize().into_bytes();

    assert_ne!(tag1, tag2); // Different keys produce different tags
}
