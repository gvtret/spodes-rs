//! End-to-end test of general block transfer (IEC 62056-5-3 §9.3) through a
//! real [`ClientSession`] and a server loop, driven over two threads
//! connected by in-memory channels — the multi-round-trip block/ack ping-pong
//! that GBT requires cannot be exercised through the single-call
//! `LoopbackLink` used by the other session integration tests.

use std::io;
use std::sync::mpsc::{channel, Receiver, Sender};

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::gbt;
use spodes_rs::service::get::{GetDataResult, GetResponse};
use spodes_rs::session::ClientSessionBuilder;
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::CosemDataType;

/// Extracts the value from a successful GET-RESPONSE-NORMAL, panicking with a
/// descriptive message otherwise.
fn get_value(result: Result<GetResponse, spodes_rs::session::SessionError>) -> CosemDataType {
    match result {
        Ok(GetResponse::Normal { result: GetDataResult::Data(v), .. }) => v,
        other => panic!("unexpected GET result: {other:?}"),
    }
}

/// One end of an in-memory duplex link: whole APDUs in, whole APDUs out.
struct ChannelLink {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl DataLinkLayer for ChannelLink {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        self.tx.send(apdu.to_vec()).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer gone"))
    }
    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        self.rx.recv().map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer gone"))
    }
}

/// Creates a connected pair of links (like a loopback socket).
fn channel_pair() -> (ChannelLink, ChannelLink) {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    (ChannelLink { tx: a_tx, rx: b_rx }, ChannelLink { tx: b_tx, rx: a_rx })
}

/// Runs a GBT-aware server loop for exactly one request/response, then
/// returns. Reassembles a GBT-framed request and, when the response exceeds
/// `block_payload_max`, segments it back via GBT. Builds the (non-`Send`)
/// [`RequestDispatcher`] itself so it never has to cross the thread
/// boundary.
fn serve_one(mut link: ChannelLink, obis: ObisCode, value: CosemDataType, block_payload_max: usize, window: u8) {
    let mut dispatcher = RequestDispatcher::new();
    // GBT replaces the service-specific WITH-DATABLOCK mechanism for wire
    // segmentation, so the dispatcher must be allowed to produce the full
    // response in one logical GetResponse::Normal for GBT to then segment.
    dispatcher.set_max_pdu(usize::MAX);
    dispatcher.add(Box::new(Data::new(obis, value)));

    let first = link.receive_apdu().expect("receive request");
    let request = if first.first() == Some(&gbt::GENERAL_BLOCK_TRANSFER) {
        gbt::receive(&mut link, &first).expect("reassemble GBT request")
    } else {
        first
    };
    let response = dispatcher.dispatch(&request).expect("dispatch");
    if response.len() > block_payload_max {
        gbt::send(&mut link, &response, block_payload_max, window, false).expect("send GBT response");
    } else {
        link.send_apdu(&response).expect("send response");
    }
}

#[test]
fn gbt_unconfirmed_round_trips_a_large_get_response() {
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let large_value = CosemDataType::OctetString(vec![0xAB; 500]);

    let (client_link, server_link) = channel_pair();
    let block_payload_max = gbt::DEFAULT_BLOCK_SIZE - gbt::HEADER_MAX;
    let server_obis = obis.clone();
    let server_value = large_value.clone();
    let handle = std::thread::spawn(move || serve_one(server_link, server_obis, server_value, block_payload_max, 0));

    let mut session = ClientSessionBuilder::new(client_link).with_gbt(gbt::DEFAULT_BLOCK_SIZE).build();
    let value = get_value(session.get(1, obis, 2));
    assert_eq!(value, large_value);

    handle.join().unwrap();
}

#[test]
fn gbt_confirmed_window_round_trips_a_large_get_response() {
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let large_value = CosemDataType::OctetString(vec![0xCD; 500]);

    let (client_link, server_link) = channel_pair();
    let block_payload_max = 32;
    let server_obis = obis.clone();
    let server_value = large_value.clone();
    let handle = std::thread::spawn(move || serve_one(server_link, server_obis, server_value, block_payload_max, 2));

    let mut session =
        ClientSessionBuilder::new(client_link).with_gbt(block_payload_max + gbt::HEADER_MAX).gbt_window(2).build();
    let value = get_value(session.get(1, obis, 2));
    assert_eq!(value, large_value);

    handle.join().unwrap();
}

#[test]
fn small_response_is_not_segmented_even_with_gbt_enabled() {
    // A response that fits within one block is sent as a single plain frame;
    // `serve_one`'s `response.len() > block_payload_max` check covers this,
    // so a normal (non-GBT) round trip proves it.
    let obis = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    let small_value = CosemDataType::LongUnsigned(0x1234);

    let (client_link, server_link) = channel_pair();
    let block_payload_max = gbt::DEFAULT_BLOCK_SIZE - gbt::HEADER_MAX;
    let server_obis = obis.clone();
    let server_value = small_value.clone();
    let handle = std::thread::spawn(move || serve_one(server_link, server_obis, server_value, block_payload_max, 0));

    let mut session = ClientSessionBuilder::new(client_link).with_gbt(gbt::DEFAULT_BLOCK_SIZE).build();
    let value = get_value(session.get(1, obis, 2));
    assert_eq!(value, small_value);

    handle.join().unwrap();
}
