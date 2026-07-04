//! Transparent pass-through to a meter (СТО 34.01-5.1-013-2023, §8.3 and §10.3).
//!
//! The head-end reaches an individual meter through the ИВКЭ by its `direct_id`
//! — a logical address unique within the ИВКЭ (the HDLC lower / Wrapper address,
//! range 200..16381, §8.3.5). The direct-channel table (§10.3, `0.0.94.7.129.255`)
//! maps `direct_id → {meter_id, channel_id}`; the ИВКЭ then forwards the request
//! frame to that meter and relays the response back.

use std::collections::HashMap;
use std::io;

use crate::classes::data::Data;
use crate::transport::DataLinkLayer;
use crate::types::CosemDataType;

use super::obis;

/// One direct-channel entry (§10.3, `direct_channel`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectChannel {
    /// `direct_id` — the meter's logical address within the ИВКЭ (200..16381).
    pub direct_id: u16,
    /// Meter identifier.
    pub meter_id: Vec<u8>,
    /// Communication channel to reach the meter.
    pub channel_id: u8,
}

/// The direct-channel table (§10.3, `0.0.94.7.129.255`).
#[derive(Clone, Debug, Default)]
pub struct DirectChannelTable {
    channels: Vec<DirectChannel>,
}

impl DirectChannelTable {
    /// Creates an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a direct-channel mapping.
    pub fn add(&mut self, channel: DirectChannel) {
        self.channels.push(channel);
    }

    /// Resolves the meter addressed by `direct_id`.
    pub fn by_direct_id(&self, direct_id: u16) -> Option<&DirectChannel> {
        self.channels.iter().find(|c| c.direct_id == direct_id)
    }

    /// Builds the COSEM `Data` (IC 1) object holding the table (§10.3).
    pub fn build(&self) -> Data {
        let array = self
            .channels
            .iter()
            .map(|c| {
                CosemDataType::Structure(vec![
                    CosemDataType::LongUnsigned(c.direct_id),
                    CosemDataType::OctetString(c.meter_id.clone()),
                    CosemDataType::Unsigned(c.channel_id),
                ])
            })
            .collect();
        Data::new(obis::direct_channel_table(), CosemDataType::Array(array))
    }
}

/// Errors raised while forwarding a request to a meter.
#[derive(Debug)]
pub enum ProxyError {
    /// No direct-channel entry for the requested `direct_id`.
    UnknownDirectId(u16),
    /// No downstream link is attached for the addressed meter.
    NoLink(Vec<u8>),
    /// A transport error on the downstream link.
    Io(io::Error),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::UnknownDirectId(id) => write!(f, "no direct-channel entry for direct_id {id}"),
            ProxyError::NoLink(meter) => write!(f, "no downstream link for meter {meter:02X?}"),
            ProxyError::Io(e) => write!(f, "downstream transport error: {e}"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// A transparent proxy: resolves `direct_id` to a meter via the direct-channel
/// table and forwards raw request APDUs to that meter's downstream link.
pub struct MeterProxy<L: DataLinkLayer> {
    table: DirectChannelTable,
    links: HashMap<Vec<u8>, L>,
}

impl<L: DataLinkLayer> MeterProxy<L> {
    /// Creates a proxy over the given direct-channel table.
    pub fn new(table: DirectChannelTable) -> Self {
        MeterProxy { table, links: HashMap::new() }
    }

    /// Attaches the downstream link used to reach `meter_id`.
    pub fn attach(&mut self, meter_id: Vec<u8>, link: L) {
        self.links.insert(meter_id, link);
    }

    /// The direct-channel table.
    pub fn table(&self) -> &DirectChannelTable {
        &self.table
    }

    /// Forwards a raw request APDU to the meter addressed by `direct_id` and
    /// returns its response APDU (transparent pass-through, §8.3).
    pub fn forward(&mut self, direct_id: u16, request: &[u8]) -> Result<Vec<u8>, ProxyError> {
        let meter_id =
            self.table.by_direct_id(direct_id).ok_or(ProxyError::UnknownDirectId(direct_id))?.meter_id.clone();
        let link = self.links.get_mut(&meter_id).ok_or_else(|| ProxyError::NoLink(meter_id.clone()))?;
        link.send_apdu(request).map_err(ProxyError::Io)?;
        link.receive_apdu().map_err(ProxyError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    /// A loopback link that returns a fixed canned response and records the sent APDU.
    struct MockLink {
        response: Vec<u8>,
        sent: Vec<u8>,
    }

    impl DataLinkLayer for MockLink {
        fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
            self.sent = apdu.to_vec();
            Ok(())
        }
        fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn direct_channel_table_builds_data_object() {
        let mut table = DirectChannelTable::new();
        table.add(DirectChannel { direct_id: 200, meter_id: b"SIT12260004".to_vec(), channel_id: 1 });
        assert_eq!(table.by_direct_id(200).unwrap().meter_id, b"SIT12260004");
        assert!(table.by_direct_id(999).is_none());

        let object = table.build();
        assert_eq!(object.class_id(), 1);
        assert_eq!(object.logical_name(), &obis::direct_channel_table());
        let CosemDataType::Array(rows) = &object.attributes()[1].1 else { panic!("array") };
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn proxy_forwards_to_the_addressed_meter() {
        let mut table = DirectChannelTable::new();
        table.add(DirectChannel { direct_id: 200, meter_id: b"SIT12260004".to_vec(), channel_id: 1 });
        let mut proxy = MeterProxy::new(table);
        proxy.attach(b"SIT12260004".to_vec(), MockLink { response: vec![0xC4, 0x01, 0xC1, 0x00], sent: Vec::new() });

        let request = vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0xFF, 0x02, 0x00];
        let response = proxy.forward(200, &request).unwrap();
        assert_eq!(response, vec![0xC4, 0x01, 0xC1, 0x00]);

        // An unknown direct_id is rejected.
        assert!(matches!(proxy.forward(999, &request), Err(ProxyError::UnknownDirectId(999))));
    }
}
