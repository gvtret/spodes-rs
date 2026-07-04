//! ИВКЭ channel list (СТО 34.01-5.1-013-2023, §10.4, `0.0.94.7.130.255`).
//!
//! Reference information about the ИВКЭ's communication channels to meters,
//! exposed as a `ProfileGeneric` (IC 7, v1) with the Table-5 columns:
//! `channel_id` and the interface name (e.g. `RS485_1:9600`).

use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;
use super::profile::reference_profile;

/// One channel of the ИВКЭ (§10.4, Table 5).
#[derive(Clone, Debug, Default)]
pub struct Channel {
    /// Channel identifier (`channel_id`).
    pub channel_id: u8,
    /// Interface name (e.g. `RS485_1:9600`).
    pub interface: Vec<u8>,
}

/// The ИВКЭ channel list (§10.4).
#[derive(Clone, Debug, Default)]
pub struct ChannelList {
    channels: Vec<Channel>,
}

impl ChannelList {
    /// Creates an empty channel list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a channel.
    pub fn add(&mut self, channel: Channel) {
        self.channels.push(channel);
    }

    /// Number of channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object (§10.4).
    pub fn build(&self) -> crate::classes::profile_generic::ProfileGeneric {
        let buffer = self
            .channels
            .iter()
            .map(|c| {
                CosemDataType::Structure(vec![
                    CosemDataType::Unsigned(c.channel_id),
                    CosemDataType::OctetString(c.interface.clone()),
                ])
            })
            .collect();
        let columns = [ObisCode::new(0, 0, 94, 7, 130, 1), ObisCode::new(0, 0, 94, 7, 130, 2)];
        reference_profile(obis::channel_list(), &columns, buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn channel_list_builds_profile() {
        let mut list = ChannelList::new();
        list.add(Channel { channel_id: 1, interface: b"RS485_1:9600".to_vec() });
        assert_eq!(list.len(), 1);

        let profile = list.build();
        assert_eq!(profile.class_id(), 7);
        assert_eq!(profile.version(), 1);
        assert_eq!(profile.logical_name(), &obis::channel_list());

        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols[0], CosemDataType::Unsigned(1));
        assert_eq!(cols[1], CosemDataType::OctetString(b"RS485_1:9600".to_vec()));
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 2);
    }
}
