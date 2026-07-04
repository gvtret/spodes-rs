//! Example: High-Level Security (HLS) authentication primitives.
//!
//! Shows the four-pass challenge/response for mechanism 6 (SHA-256) and a
//! GOST 34.10-2018 signature (mechanism 10) from the security module.
//!
//! Run with: `cargo run --example hls_handshake`

use spodes_rs::security::{gost3410, hls, AuthMechanism};

fn main() {
    hls_sha256();
    gost_signature();
}

/// Mechanism 6: `f(challenge) = HASH(secret ‖ ST_a ‖ ST_b ‖ chal_a ‖ chal_b)`.
fn hls_sha256() {
    let secret = b"0123456789abcdef"; // shared HLS secret (>= 128 bits)
    let st_client = b"CLIENT01";
    let st_server = b"SERVER01";
    let stoc = [0xAA, 0xBB, 0xCC, 0xDD]; // server-to-client challenge
    let ctos = [0x11, 0x22, 0x33, 0x44]; // client-to-server challenge

    // Client computes f(StoC); the server recomputes it to authenticate the client.
    let f_stoc = hls::hash_with_titles(AuthMechanism::HlsSha256, secret, st_client, st_server, &stoc, &ctos).unwrap();
    let check = hls::hash_with_titles(AuthMechanism::HlsSha256, secret, st_client, st_server, &stoc, &ctos).unwrap();
    assert_eq!(f_stoc, check);

    // The server answers f(CtoS) with the roles/challenges swapped.
    let f_ctos = hls::hash_with_titles(AuthMechanism::HlsSha256, secret, st_server, st_client, &ctos, &stoc).unwrap();

    println!("HLS SHA-256 (mechanism 6):");
    println!("  f(StoC) = {}", hex(&f_stoc));
    println!("  f(CtoS) = {}", hex(&f_ctos));
}

/// Mechanism 10: GOST 34.10-2018 signature over the handshake message.
fn gost_signature() {
    // Signing key (little-endian Vec256) and its derived public key.
    let d = hex_decode("48494a4b4c4d4e4f4041424344454647bbbbaaaa999988884444555566667777");
    let public = gost3410::public_key(&d).unwrap();

    let message = b"SystemTitle-C||SystemTitle-S||StoC||CtoS";
    let signature = gost3410::gost_sign(&d, message).unwrap();
    gost3410::gost_verify(&public, message, &signature).expect("signature verifies");

    println!("GOST 34.10 (mechanism 10):");
    println!("  signature = {}", hex(&signature));
    println!("  verified  = ok");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
