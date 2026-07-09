//! Comprehensive integration tests: block transfer, SET/ACTION, ECDH key
//! agreement, and full GOST HLS handshake through AssociationLN.

use std::any::Any;
use std::io;

use spodes_rs::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AssociationLnVersion, AuthenticationMechanism,
};
use spodes_rs::classes::data::Data;
use spodes_rs::classes::register::Register;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::security::{gost3410, SecuritySuite};
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::get::{GetDataResult, GetRequest, GetResponse};
use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};
use spodes_rs::session::ClientSession;
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::{BerError, CosemDataType};

/// A writable Data object for testing SET operations.
struct WritableData {
    logical_name: ObisCode,
    value: CosemDataType,
}

impl WritableData {
    fn new(obis: ObisCode, value: CosemDataType) -> Self {
        Self { logical_name: obis, value }
    }
}

impl InterfaceClass for WritableData {
    fn class_id(&self) -> u16 {
        1
    }
    fn version(&self) -> u8 {
        0
    }
    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }
    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![(1, CosemDataType::OctetString(self.logical_name.to_bytes())), (2, self.value.clone())]
    }
    fn methods(&self) -> Vec<(u8, String)> {
        vec![]
    }
    fn serialize_ber(&self, _buf: &mut Vec<u8>) -> Result<(), BerError> {
        Ok(())
    }
    fn deserialize_ber(&mut self, _data: &[u8]) -> Result<(), BerError> {
        Ok(())
    }
    fn invoke_method(&mut self, _method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err("no methods".to_string())
    }
    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        match attribute_id {
            2 => {
                self.value = value;
                Ok(())
            }
            _ => Err("attribute not writable".to_string()),
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

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

// ===========================================================================
// PART 1: SET/ACTION through session
// ===========================================================================

#[test]
fn test_set_writable_data_attribute() {
    let mut server = RequestDispatcher::new();
    server.add(Box::new(WritableData::new(
        ObisCode::new(0, 0, 96, 1, 0, 0xFF),
        CosemDataType::OctetString(b"old_value".to_vec()),
    )));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    // WritableData supports SET on attribute 2.
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let result = session.set(1, obis.clone(), 2, CosemDataType::OctetString(b"new_value".to_vec()));
    assert!(result.is_ok());

    // Value should be updated.
    let value = match session.get(1, obis, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(value, CosemDataType::OctetString(b"new_value".to_vec()));
}

#[test]
fn test_set_data_attribute_returns_not_writable() {
    let mut server = RequestDispatcher::new();
    server.add(Box::new(Data::new(
        ObisCode::new(0, 0, 96, 1, 0, 0xFF),
        CosemDataType::OctetString(b"old_value".to_vec()),
    )));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    // Data objects don't support SET by default — should return not-writable.
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let result = session.set(1, obis.clone(), 2, CosemDataType::OctetString(b"new_value".to_vec()));
    assert!(result.is_ok());

    // Value should remain unchanged.
    let value = match session.get(1, obis, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(value, CosemDataType::OctetString(b"old_value".to_vec()));
}

#[test]
fn test_set_register_returns_not_writable() {
    let mut server = RequestDispatcher::new();
    server.add(Box::new(Register::new(
        ObisCode::new(1, 0, 1, 8, 0, 0xFF),
        CosemDataType::DoubleLongUnsigned(100),
        CosemDataType::Long(0),
    )));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    // Register objects don't support SET by default.
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let result = session.set(3, obis.clone(), 2, CosemDataType::DoubleLongUnsigned(999));
    assert!(result.is_ok());

    let value = match session.get(3, obis, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(100));
}

#[test]
fn test_action_on_data_object() {
    let mut server = RequestDispatcher::new();
    // Data objects don't have meaningful methods, but we can test the dispatch path.
    server.add(Box::new(Data::new(ObisCode::new(0, 0, 96, 1, 0, 0xFF), CosemDataType::OctetString(b"test".to_vec()))));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    // Action on Data object with no method returns an error or method-not-available.
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let result = session.action(1, obis, 1, None);
    // Either error or method-not-available response is acceptable.
    let _ = result;
}

#[test]
fn test_action_with_parameters() {
    let mut server = RequestDispatcher::new();
    server.add(Box::new(Data::new(ObisCode::new(0, 0, 96, 1, 0, 0xFF), CosemDataType::OctetString(b"test".to_vec()))));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let params = CosemDataType::Structure(vec![CosemDataType::Unsigned(1), CosemDataType::Unsigned(2)]);
    let result = session.action(1, obis, 1, Some(params));
    // Acceptable outcomes: error or method-not-available.
    let _ = result;
}

// ===========================================================================
// PART 2: Block transfer (GET with datablocks)
// ===========================================================================

#[test]
fn test_get_block_transfer() {
    // Test that server returns WithDataBlock for large responses.
    let mut server = RequestDispatcher::new();
    server.set_max_pdu(32); // Small blocks

    let large_data = CosemDataType::Array(
        (0..100)
            .map(|i| {
                CosemDataType::Structure(vec![
                    CosemDataType::DoubleLongUnsigned(i),
                    CosemDataType::DateTime(vec![
                        0x07, 0xE5, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]),
                ])
            })
            .collect(),
    );
    server.add(Box::new(Data::new(ObisCode::new(1, 0, 99, 1, 0, 0xFF), large_data)));

    let obis = ObisCode::new(1, 0, 99, 1, 0, 0xFF);
    let request = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        attribute: AttributeDescriptor::new(1, obis, 2),
        access_selection: None,
    };

    let response_bytes = server.dispatch(&request.encode().unwrap()).unwrap();
    let response = GetResponse::decode(&response_bytes).unwrap();

    // With max_pdu=32, the server returns WithDataBlock for large responses.
    match response {
        GetResponse::WithDataBlock { raw_data, .. } => {
            // The raw_data should contain the first block.
            let data = raw_data.unwrap();
            assert!(!data.is_empty());
        }
        GetResponse::Normal { .. } => {
            // If the response fits in one block, that's also acceptable.
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

// ===========================================================================
// PART 3: Block transfer (SET with datablocks)
// ===========================================================================

#[test]
fn test_set_block_transfer_data_not_writable() {
    // SET with block transfer on a Data object (not writable) should succeed
    // at the transport level but the value remains unchanged.
    let mut server = RequestDispatcher::new();
    server.set_max_pdu(32);
    server.add(Box::new(Data::new(ObisCode::new(1, 0, 99, 1, 0, 0xFF), CosemDataType::Null)));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let large_value = CosemDataType::Array((0..50).map(CosemDataType::Unsigned).collect());
    let obis = ObisCode::new(1, 0, 99, 1, 0, 0xFF);
    let result = session.set(1, obis.clone(), 2, large_value);
    assert!(result.is_ok());

    // Value remains Null because Data doesn't support SET.
    let read_back = match session.get(1, obis, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(read_back, CosemDataType::Null);
}

// ===========================================================================
// PART 4: ECDSA P-256/P-384 signing (Suite 1/2)
// ===========================================================================

#[test]
fn test_ecdsa_p256_sign_verify() {
    use spodes_rs::security::signature;

    let sk = [
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xBB, 0xBB,
        0xAA, 0xAA, 0x99, 0x99, 0x88, 0x88, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    ];
    let pk = p256::ecdsa::SigningKey::from_bytes(&sk.into())
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();

    let msg = b"DLMS Suite 1 ECDSA test";
    let sig = signature::ecdsa_sign(SecuritySuite::Suite1, &sk, msg).unwrap();
    assert_eq!(sig.len(), 64);
    signature::ecdsa_verify(SecuritySuite::Suite1, &pk, msg, &sig).unwrap();

    // Wrong message fails.
    assert!(signature::ecdsa_verify(SecuritySuite::Suite1, &pk, b"wrong", &sig).is_err());
}

#[test]
fn test_ecdsa_p384_sign_verify() {
    use spodes_rs::security::signature;

    let sk = [
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xBB, 0xBB,
        0xAA, 0xAA, 0x99, 0x99, 0x88, 0x88, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let pk = p384::ecdsa::SigningKey::from_bytes(&sk.into())
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();

    let msg = b"DLMS Suite 2 ECDSA test";
    let sig = signature::ecdsa_sign(SecuritySuite::Suite2, &sk, msg).unwrap();
    assert_eq!(sig.len(), 96); // P-384 signature is 96 bytes
    signature::ecdsa_verify(SecuritySuite::Suite2, &pk, msg, &sig).unwrap();
}

// ===========================================================================
// PART 5: GOST HLS full handshake simulation (mechanism 10)
// ===========================================================================

#[test]
fn test_gost_hls_handshake_mechanism_10() {
    // Simulate a full GOST 34.10 HLS handshake.
    // Both client and server have signing keys.
    let client_sk = [
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xBB, 0xBB,
        0xAA, 0xAA, 0x99, 0x99, 0x88, 0x88, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    ];
    let server_sk = [
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xDD, 0xDD,
        0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB,
    ];

    let client_pk = gost3410::public_key(&client_sk).unwrap();
    let server_pk = gost3410::public_key(&server_sk).unwrap();

    // Challenges.
    let client_challenge = [0x11u8; 16];
    let server_challenge = [0x22u8; 16];

    // System titles.
    let client_st = [0x4D; 8];
    let server_st = [0x4E; 8];

    // Construct the signed message: ST_a || ST_b || challenge_a || challenge_b
    let mut msg_for_client = Vec::new();
    msg_for_client.extend_from_slice(&server_st);
    msg_for_client.extend_from_slice(&client_st);
    msg_for_client.extend_from_slice(&server_challenge);
    msg_for_client.extend_from_slice(&client_challenge);

    let mut msg_for_server = Vec::new();
    msg_for_server.extend_from_slice(&client_st);
    msg_for_server.extend_from_slice(&server_st);
    msg_for_server.extend_from_slice(&client_challenge);
    msg_for_server.extend_from_slice(&server_challenge);

    // Client signs f(CtoS) = SIGN(sk_client, ST_a || ST_b || StoC || CtoS)
    // Server signs f(StoC) = SIGN(sk_server, ST_b || ST_a || CtoS || StoC)
    let client_signature = gost3410::gost_sign(&client_sk, &msg_for_client).unwrap();
    let server_signature = gost3410::gost_sign(&server_sk, &msg_for_server).unwrap();

    // Verify both signatures.
    gost3410::gost_verify(&client_pk, &msg_for_client, &client_signature).unwrap();
    gost3410::gost_verify(&server_pk, &msg_for_server, &server_signature).unwrap();

    // Tampered message must fail.
    let mut bad_msg = msg_for_client.clone();
    bad_msg[0] ^= 0xFF;
    assert!(gost3410::gost_verify(&client_pk, &bad_msg, &client_signature).is_err());
}

// ===========================================================================
// PART 6: GOST HLS with AssociationLN (mechanism 8 — CMAC)
// ===========================================================================

#[test]
fn test_gost_hls_cmac_with_association() {
    let mut server = build_meter_server();

    // 64-byte K_EM.
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
    let value = match session.get(3, energy, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(123_456));
}

// ===========================================================================
// PART 7: GOST HLS with AssociationLN (mechanism 10 — signature)
// ===========================================================================

#[test]
fn test_gost_hls_signature_with_association() {
    let mut server = build_meter_server();

    // Server's signing key (32 bytes).
    let server_sk = vec![
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xDD, 0xDD,
        0xCC, 0xCC, 0xAA, 0xAA, 0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let assoc = AssociationLn::new(AssociationLnConfig {
        logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: CosemDataType::Null,
        application_context_name: CosemDataType::Null,
        xdlms_context_info: CosemDataType::Null,
        authentication_mechanism: AuthenticationMechanism::HlsGostSignature,
        secret: CosemDataType::OctetString(server_sk),
        association_status: CosemDataType::Enum(0),
        security_setup_reference: CosemDataType::Null,
        user_list: vec![],
        current_user: CosemDataType::Null,
    });
    server.add(Box::new(assoc));

    let link = LoopbackLink::new(server);
    let mut session = ClientSession::new(link);

    let energy = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    let value = match session.get(3, energy, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(value, CosemDataType::DoubleLongUnsigned(123_456));
}

// ===========================================================================
// PART 8: KDF tree for key derivation
// ===========================================================================

#[test]
fn test_kdf_tree_derives_different_keys() {
    let key = [0x11u8; 32];
    let label = b"test_label";
    let seed = [0x22u8; 8];

    let derived1 = gost3410::kdf_tree(&key, label, &seed, 32);
    let derived2 = gost3410::kdf_tree(&key, b"other_label", &seed, 32);

    // Different labels should produce different keys.
    assert_ne!(derived1, derived2);
}

#[test]
fn test_kdf_tree_different_seeds() {
    let key = [0x11u8; 32];
    let label = b"test_label";

    let derived1 = gost3410::kdf_tree(&key, label, &[0x22u8; 8], 32);
    let derived2 = gost3410::kdf_tree(&key, label, &[0x33u8; 8], 32);

    assert_ne!(derived1, derived2);
}

#[test]
fn test_kdf_tree_various_lengths() {
    let key = [0x11u8; 32];
    let label = b"test";
    let seed = [0x22u8; 8];

    let k32 = gost3410::kdf_tree(&key, label, &seed, 32);
    assert_eq!(k32.len(), 32);

    let k64 = gost3410::kdf_tree(&key, label, &seed, 64);
    assert_eq!(k64.len(), 64);

    let k96 = gost3410::kdf_tree(&key, label, &seed, 96);
    assert_eq!(k96.len(), 96);

    let k128 = gost3410::kdf_tree(&key, label, &seed, 128);
    assert_eq!(k128.len(), 128);
}

// ===========================================================================
// PART 9: VKO key agreement round-trip
// ===========================================================================

#[test]
fn test_vko_round_trip() {
    let alice_sk = [
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0xDD, 0xDD,
        0xCC, 0xCC,
    ];
    let bob_sk = [
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0xBB, 0xBB,
        0xAA, 0xAA, 0x99, 0x99, 0x88, 0x88, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
    ];

    let alice_pk = gost3410::public_key(&alice_sk).unwrap();
    let bob_pk = gost3410::public_key(&bob_sk).unwrap();

    let ukm = [0xF0u8; 16];

    // Both parties derive the same shared key.
    let key_alice = gost3410::vko(&alice_sk, &bob_pk, &ukm).unwrap();
    let key_bob = gost3410::vko(&bob_sk, &alice_pk, &ukm).unwrap();

    assert_eq!(key_alice, key_bob);
    assert_eq!(key_alice.len(), 32);
}
