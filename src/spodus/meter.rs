//! Meter registry and aggregation (СТО 34.01-5.1-013-2023, §10.2).
//!
//! The ИВКЭ keeps a configured list of the meters it serves (§10.2,
//! `0.0.94.7.128.255`, class Data). Each meter is described by its composite
//! identifier, model and communication channels. The registry also caches the
//! last-read attribute values per meter (the aggregation the ИВКЭ serves
//! upstream without re-polling).

use std::collections::HashMap;

use crate::classes::data::Data;
use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;

/// One communication channel of a meter (§10.2, `channel`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeterChannel {
    /// Channel identifier (`id`).
    pub id: u8,
    /// Meter address within the channel (`address`, may be empty).
    pub address: Vec<u8>,
}

/// A configured meter (§10.2, `device_description`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeterDescriptor {
    /// Composite meter identifier (manufacturer code + serial, e.g. `SIT12260004`).
    pub meter_id: Vec<u8>,
    /// Meter model.
    pub meter_model: Vec<u8>,
    /// Communication channels for reaching the meter.
    pub channels: Vec<MeterChannel>,
}

impl MeterDescriptor {
    fn to_structure(&self) -> CosemDataType {
        let channels = self
            .channels
            .iter()
            .map(|c| {
                CosemDataType::Structure(vec![
                    CosemDataType::Unsigned(c.id),
                    CosemDataType::OctetString(c.address.clone()),
                ])
            })
            .collect();
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(self.meter_id.clone()),
            CosemDataType::OctetString(self.meter_model.clone()),
            CosemDataType::Array(channels),
        ])
    }
}

/// The configured meter list plus a per-meter aggregation cache.
#[derive(Clone, Debug, Default)]
pub struct MeterRegistry {
    meters: Vec<MeterDescriptor>,
    /// Cached last-read values: `meter_id` → list of `(obis, attribute, value)`.
    cache: HashMap<Vec<u8>, Vec<(ObisCode, u8, CosemDataType)>>,
}

impl MeterRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a meter, replacing any existing entry with the same `meter_id`.
    pub fn add(&mut self, meter: MeterDescriptor) {
        self.remove(&meter.meter_id);
        self.meters.push(meter);
    }

    /// Removes a meter and all its cached data (§10.2: related data is removed).
    pub fn remove(&mut self, meter_id: &[u8]) {
        self.meters.retain(|m| m.meter_id != meter_id);
        self.cache.remove(meter_id);
    }

    /// Looks up a meter by its identifier.
    pub fn find(&self, meter_id: &[u8]) -> Option<&MeterDescriptor> {
        self.meters.iter().find(|m| m.meter_id == meter_id)
    }

    /// The configured meters.
    pub fn meters(&self) -> &[MeterDescriptor] {
        &self.meters
    }

    /// Stores (or updates) a cached attribute value read from a meter.
    pub fn store(&mut self, meter_id: &[u8], obis: ObisCode, attribute: u8, value: CosemDataType) {
        let entries = self.cache.entry(meter_id.to_vec()).or_default();
        if let Some(slot) = entries.iter_mut().find(|(o, a, _)| *o == obis && *a == attribute) {
            slot.2 = value;
        } else {
            entries.push((obis, attribute, value));
        }
    }

    /// Returns a cached attribute value, if present.
    pub fn cached(&self, meter_id: &[u8], obis: &ObisCode, attribute: u8) -> Option<&CosemDataType> {
        self.cache
            .get(meter_id)
            .and_then(|entries| entries.iter().find(|(o, a, _)| o == obis && *a == attribute).map(|(_, _, v)| v))
    }

    /// Builds the COSEM meter-list `Data` (IC 1) object (§10.2, `0.0.94.7.128.255`).
    pub fn build_meter_list(&self) -> Data {
        let array = self.meters.iter().map(MeterDescriptor::to_structure).collect();
        Data::new(obis::meter_list(), CosemDataType::Array(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    fn sample() -> MeterDescriptor {
        MeterDescriptor {
            meter_id: b"SIT12260004".to_vec(),
            meter_model: b"SiT".to_vec(),
            channels: vec![MeterChannel { id: 1, address: b"\x02".to_vec() }],
        }
    }

    #[test]
    fn registry_add_find_remove() {
        let mut registry = MeterRegistry::new();
        registry.add(sample());
        assert!(registry.find(b"SIT12260004").is_some());
        assert_eq!(registry.meters().len(), 1);

        // The meter-list object carries one device_description.
        let list = registry.build_meter_list();
        assert_eq!(list.class_id(), 1);
        assert_eq!(list.logical_name(), &obis::meter_list());
        let CosemDataType::Array(rows) = &list.attributes()[1].1 else { panic!("array") };
        assert_eq!(rows.len(), 1);

        registry.remove(b"SIT12260004");
        assert!(registry.find(b"SIT12260004").is_none());
    }

    #[test]
    fn aggregation_cache_stores_and_evicts() {
        let mut registry = MeterRegistry::new();
        registry.add(sample());
        let energy = ObisCode::new(1, 0, 1, 8, 0, 255);
        registry.store(b"SIT12260004", energy.clone(), 2, CosemDataType::DoubleLongUnsigned(1000));
        assert_eq!(registry.cached(b"SIT12260004", &energy, 2), Some(&CosemDataType::DoubleLongUnsigned(1000)));
        // Updating overwrites the cached value.
        registry.store(b"SIT12260004", energy.clone(), 2, CosemDataType::DoubleLongUnsigned(2000));
        assert_eq!(registry.cached(b"SIT12260004", &energy, 2), Some(&CosemDataType::DoubleLongUnsigned(2000)));
        // Removing the meter drops its cache.
        registry.remove(b"SIT12260004");
        assert_eq!(registry.cached(b"SIT12260004", &energy, 2), None);
    }
}
