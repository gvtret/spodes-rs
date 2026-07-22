//! Discovered-meters list (СТО 34.01-5.1-013-2023, §10.5, `0.0.94.7.131.255`).
//!
//! The ИВКЭ keeps a reference list of the meters it has found on its channels,
//! exposed as a `ProfileGeneric` (IC 7, v1) whose buffer rows follow the Table-6
//! column layout: `meter_id`, `meter_model`, `channel_id`, `address`,
//! first-contact time and last-contact time.

use std::sync::Arc;

use crate::classes::data::Data;
use crate::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::SortMethod;
use crate::types::CosemDataType;

use super::obis;

/// One entry of the discovered-meters list (§10.5, Table 6).
#[derive(Clone, Debug, Default)]
pub struct DiscoveredMeter {
    /// `meter_id` — meter identifier.
    pub meter_id: Vec<u8>,
    /// `meter_model` — meter model.
    pub meter_model: Vec<u8>,
    /// `channel_id` — communication channel.
    pub channel_id: u8,
    /// `address` — address within the channel.
    pub address: u16,
    /// First-contact time, as date-time octets.
    pub first_seen: Vec<u8>,
    /// Last-contact time, as date-time octets.
    pub last_seen: Vec<u8>,
}

impl DiscoveredMeter {
    /// The Table-6 buffer row for this meter.
    fn to_entry(&self) -> CosemDataType {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(self.meter_id.clone()),
            CosemDataType::OctetString(self.meter_model.clone()),
            CosemDataType::Unsigned(self.channel_id),
            CosemDataType::LongUnsigned(self.address),
            CosemDataType::DateTime(self.first_seen.clone()),
            CosemDataType::DateTime(self.last_seen.clone()),
        ])
    }
}

/// The discovered-meters list (§10.5).
#[derive(Clone, Debug, Default)]
pub struct DiscoveredMeters {
    records: Vec<DiscoveredMeter>,
}

impl DiscoveredMeters {
    /// Creates an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a discovered meter.
    pub fn record(&mut self, meter: DiscoveredMeter) {
        self.records.push(meter);
    }

    /// Number of recorded meters.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The Table-6 columns as capture-object markers (Data at `…131.0..5`, attr 2).
    fn columns() -> Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)> {
        (0u8..6)
            .map(|i| {
                let obj: Arc<dyn InterfaceClass + Send + Sync> =
                    Arc::new(Data::new(ObisCode::new(0, 0, 94, 7, 131, i), CosemDataType::Null));
                (obj, 2u8)
            })
            .collect()
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object for this list.
    pub fn build(&self) -> ProfileGeneric {
        let buffer: Vec<CosemDataType> = self.records.iter().map(DiscoveredMeter::to_entry).collect();
        // An in-memory buffer never approaches u32::MAX entries.
        #[allow(clippy::cast_possible_truncation)]
        let entries_in_use = buffer.len() as u32;
        ProfileGeneric::new(ProfileGenericConfig {
            logical_name: obis::discovered_meters(),
            version: 1,
            buffer,
            capture_objects: Self::columns(),
            capture_period: 0,
            sort_method: SortMethod::Fifo,
            sort_object: None,
            entries_in_use,
            profile_entries: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_meters_builds_profile_generic() {
        let mut list = DiscoveredMeters::new();
        list.record(DiscoveredMeter {
            meter_id: b"MTR-0001".to_vec(),
            meter_model: b"SiT".to_vec(),
            channel_id: 1,
            address: 0x0010,
            first_seen: vec![0x07, 0xE6, 0x07, 0x04],
            last_seen: vec![0x07, 0xE6, 0x07, 0x05],
        });
        assert_eq!(list.len(), 1);

        let profile = list.build();
        assert_eq!(profile.class_id(), 7);
        assert_eq!(profile.version(), 1);
        assert_eq!(profile.logical_name(), &obis::discovered_meters());

        let attrs = profile.attributes();
        // Attribute 2: the buffer — one row with the six typed columns.
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer is an array") };
        assert_eq!(rows.len(), 1);
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row is a structure") };
        assert_eq!(cols.len(), 6);
        assert_eq!(cols[0], CosemDataType::OctetString(b"MTR-0001".to_vec()));
        assert_eq!(cols[2], CosemDataType::Unsigned(1));
        assert_eq!(cols[3], CosemDataType::LongUnsigned(0x0010));

        // Attribute 3: six capture-object definitions.
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture objects is an array") };
        assert_eq!(caps.len(), 6);
    }
}
