//! The ИВКЭ concentrator node (СТО 34.01-5.1-013-2023, §10).
//!
//! [`Concentrator`] holds the ИВКЭ information model — nameplate, meter registry,
//! discovered-meters list, access policies and journals — and assembles the
//! upstream [`RequestDispatcher`] that serves the head-end (ИВК) with the
//! mandatory COSEM object catalogue.

use crate::classes::association_ln::AuthenticationMechanism;
use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::server::RequestDispatcher;
use crate::types::CosemDataType;

use super::access_policy::AccessPolicies;
use super::catalog;
use super::channels::ChannelList;
use super::discovered::DiscoveredMeters;
use super::journals::{EventJournal, ExchangeStatusJournal};
use super::meter::MeterRegistry;
use super::misc;
use super::nameplate::Nameplate;
use super::obis;
use super::profile_filter::ProfileDataFilter;
use super::proxy::DirectChannelTable;
use super::push::EventMessages;
use super::records::{CorrectionJournal, IncomingEventsTable, NumericJournal};
use super::status::MeterStatusTable;
use super::table_manager::TableManager;
use super::tasks::ExchangeTasks;

/// A СПОДУС concentrator (ИВКЭ): the meter aggregation model plus the upstream
/// server it exposes to the head-end. Its [`dispatcher`](Concentrator::dispatcher)
/// serves the full mandatory COSEM object catalogue of Appendix A.
#[derive(Clone, Debug, Default)]
pub struct Concentrator {
    /// Passport data (§10.14).
    pub nameplate: Nameplate,
    /// Configured meters and their aggregated values (§10.2).
    pub meters: MeterRegistry,
    /// ИВКЭ channel list (§10.4).
    pub channels: ChannelList,
    /// Discovered-meters list (§10.5).
    pub discovered: DiscoveredMeters,
    /// Meter access policies (§10.6).
    pub access_policies: AccessPolicies,
    /// Meter data-exchange task list (§10.7).
    pub exchange_tasks: ExchangeTasks,
    /// Direct-channel (pass-through) table (§10.3).
    pub direct_channels: DirectChannelTable,
    /// Meter status table (§10.8).
    pub meter_status: MeterStatusTable,
    /// Data-exchange-status journal (§10.9).
    pub exchange_journal: ExchangeStatusJournal,
    /// Object-correction journal (§10.10).
    pub correction_journal: CorrectionJournal,
    /// Numeric meter journal (§10.11).
    pub numeric_journal: NumericJournal,
    /// Incoming push-events table (§8.5.10).
    pub incoming_events: IncomingEventsTable,
    /// ИВКЭ event journals (§10.13).
    pub event_journals: Vec<EventJournal>,
    /// Aggregated event push-messages (§8.5.11).
    pub events: EventMessages,
    /// Time-difference-with-meters delta (`0.0.94.7.141.255`).
    pub time_delta: u8,
    /// Discrete-inputs state bitmask (`0.0.96.3.1.255`).
    pub discrete_inputs: u16,
    /// Server system-title, used by the Security-setup objects.
    pub server_system_title: Vec<u8>,
}

impl Concentrator {
    /// Creates an empty concentrator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assembles the upstream [`RequestDispatcher`] populated with the full
    /// ИВКЭ object catalogue (Appendix A).
    pub fn dispatcher(&self) -> RequestDispatcher {
        let mut d = RequestDispatcher::new();

        // Passport data (§10.14) and its reference profile.
        for object in self.nameplate.objects() {
            d.add(Box::new(object));
        }
        d.add(Box::new(self.nameplate.profile()));

        // Meter-interaction objects (§10.2..§10.11, §8.5.10).
        d.add(Box::new(self.meters.build_meter_list()));
        d.add(Box::new(self.direct_channels.build()));
        d.add(Box::new(self.channels.build()));
        d.add(Box::new(self.discovered.build()));
        d.add(Box::new(self.access_policies.build()));
        d.add(Box::new(self.exchange_tasks.build()));
        d.add(Box::new(self.meter_status.build()));
        d.add(Box::new(self.exchange_journal.build()));
        d.add(Box::new(self.correction_journal.build()));
        d.add(Box::new(self.numeric_journal.build()));
        d.add(Box::new(self.incoming_events.build()));

        // ИВКЭ event journals (§10.13) and single-value objects.
        for journal in &self.event_journals {
            d.add(Box::new(journal.build()));
        }
        d.add(Box::new(misc::time_delta(self.time_delta)));
        d.add(Box::new(misc::discrete_inputs(self.discrete_inputs)));

        // Notifications (§8.5).
        d.add(Box::new(self.events.build()));

        // Group-operation classes (§7): a Table manager over the meter list and
        // a Profile data filter over the numeric journal.
        let mut table_manager = TableManager::new(obis::meter_list(), 0);
        if let CosemDataType::Array(rows) = self.meters.build_meter_list().attributes()[1].1.clone() {
            table_manager.set_rows(rows);
        }
        d.add(Box::new(table_manager));
        d.add(Box::new(ProfileDataFilter::new(obis::numeric_meter_journal(), vec![])));

        // Standard catalogue objects (Appendix A): Clock, SAP assignment,
        // Security setup and Association LN for the connection types.
        d.add(Box::new(catalog::clock()));
        d.add(Box::new(catalog::sap_assignment(vec![])));
        let st = &self.server_system_title;
        for (e, policy) in [(0u8, 0u8), (1, 3), (2, 3)] {
            d.add(Box::new(catalog::security_setup(ObisCode::new(0, 0, 43, 0, e, 255), policy, vec![], st.clone())));
        }
        let associations = [
            (0u8, AuthenticationMechanism::None, 0u8),
            (1, AuthenticationMechanism::None, 0),
            (2, AuthenticationMechanism::Lls, 1),
            (3, AuthenticationMechanism::HlsGmac, 2),
            (4, AuthenticationMechanism::None, 0),
        ];
        for (e, mechanism, security) in associations {
            d.add(Box::new(catalog::association(
                ObisCode::new(0, 0, 40, 0, e, 255),
                mechanism,
                ObisCode::new(0, 0, 43, 0, security, 255),
            )));
        }
        d
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
