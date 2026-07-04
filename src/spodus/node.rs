//! The ИВКЭ concentrator node (СТО 34.01-5.1-013-2023, §10).
//!
//! [`Concentrator`] holds the ИВКЭ information model — nameplate, meter registry,
//! discovered-meters list, access policies and journals — and assembles the
//! upstream [`RequestDispatcher`] that serves the head-end (ИВК) with the
//! mandatory COSEM object catalogue.

use crate::server::RequestDispatcher;

use super::access_policy::AccessPolicies;
use super::discovered::DiscoveredMeters;
use super::journals::{EventJournal, ExchangeStatusJournal};
use super::meter::MeterRegistry;
use super::nameplate::Nameplate;
use super::proxy::DirectChannelTable;

/// A СПОДУС concentrator (ИВКЭ): the meter aggregation model plus the upstream
/// server it exposes to the head-end.
#[derive(Clone, Debug, Default)]
pub struct Concentrator {
    /// Passport data (§10.14).
    pub nameplate: Nameplate,
    /// Configured meters and their aggregated values (§10.2).
    pub meters: MeterRegistry,
    /// Discovered-meters list (§10.5).
    pub discovered: DiscoveredMeters,
    /// Meter access policies (§10.6).
    pub access_policies: AccessPolicies,
    /// Direct-channel (pass-through) table (§10.3).
    pub direct_channels: DirectChannelTable,
    /// Data-exchange-status journal (§10.9).
    pub exchange_journal: ExchangeStatusJournal,
    /// ИВКЭ event journals (§10.13).
    pub event_journals: Vec<EventJournal>,
}

impl Concentrator {
    /// Creates an empty concentrator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assembles the upstream [`RequestDispatcher`] populated with the ИВКЭ
    /// object catalogue (nameplate, meter list, access policies, discovered
    /// meters and journals).
    pub fn dispatcher(&self) -> RequestDispatcher {
        let mut dispatcher = RequestDispatcher::new();
        for object in self.nameplate.objects() {
            dispatcher.add(Box::new(object));
        }
        dispatcher.add(Box::new(self.meters.build_meter_list()));
        dispatcher.add(Box::new(self.access_policies.build()));
        dispatcher.add(Box::new(self.direct_channels.build()));
        dispatcher.add(Box::new(self.discovered.build()));
        dispatcher.add(Box::new(self.exchange_journal.build()));
        for journal in &self.event_journals {
            dispatcher.add(Box::new(journal.build()));
        }
        dispatcher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obis::ObisCode;
    use crate::service::get::{GetDataResult, GetRequest, GetResponse};
    use crate::service::{invoke_id_and_priority, AttributeDescriptor};
    use crate::spodus::meter::MeterDescriptor;
    use crate::spodus::obis;
    use crate::types::CosemDataType;

    fn get(dispatcher: &mut RequestDispatcher, class_id: u16, instance: ObisCode, attr: i8) -> GetResponse {
        let request = GetRequest::Normal {
            invoke_id_and_priority: invoke_id_and_priority(1, true, true),
            attribute: AttributeDescriptor::new(class_id, instance, attr),
            access_selection: None,
        };
        GetResponse::decode(&dispatcher.dispatch(&request.encode().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn concentrator_serves_nameplate_and_meter_list() {
        let mut node = Concentrator::new();
        node.nameplate.serial_number = "IVKE-0001".to_string();
        node.meters.add(MeterDescriptor {
            meter_id: b"SIT12260004".to_vec(),
            meter_model: b"SiT".to_vec(),
            channels: vec![],
        });
        let mut dispatcher = node.dispatcher();

        // The head-end reads the ИВКЭ serial number (0.0.96.1.0.255, Data attr 2).
        let response = get(&mut dispatcher, 1, obis::serial_number(), 2);
        assert_eq!(
            response,
            GetResponse::Normal {
                invoke_id_and_priority: 0xC1,
                result: GetDataResult::Data(CosemDataType::OctetString(b"IVKE-0001".to_vec())),
            }
        );

        // And the meter list (0.0.94.7.128.255, Data attr 2) with one meter.
        let response = get(&mut dispatcher, 1, obis::meter_list(), 2);
        let GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(rows)), .. } = response else {
            panic!("expected an array of meters");
        };
        assert_eq!(rows.len(), 1);
    }
}
