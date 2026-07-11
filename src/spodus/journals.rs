//! ИВКЭ journals (СТО 34.01-5.1-013-2023, §10.9 and §10.13).
//!
//! * The **data-exchange-status journal** (§10.9, `0.0.94.7.135.255`) records the
//!   outcome of the read/write tasks the ИВКЭ runs against a meter.
//! * The **event journals** (§10.13) log the ИВКЭ's own events; their structure
//!   and codes follow ГОСТ Р 58940-2020 (timestamp + event code).
//!
//! Both are `ProfileGeneric` (IC 7, v1) objects; the typed models here build the
//! buffer and the capture-object column schema.

use std::sync::Arc;

use crate::classes::data::Data;
use crate::types::attrs::SortMethod;
use crate::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;

/// `status` values of an exchange-status record (§10.9, Table 8, column 4).
pub mod exchange_status {
    /// Task completed successfully.
    pub const DONE: u8 = 0;
    /// Waiting to start.
    pub const WAITING: u8 = 1;
    /// Access denied.
    pub const ACCESS_DENIED: u8 = 2;
    /// Not supported.
    pub const NOT_SUPPORTED: u8 = 3;
    /// Partially completed.
    pub const PARTIAL: u8 = 4;
    /// Meter not found.
    pub const NOT_FOUND: u8 = 5;
    /// No response.
    pub const NO_RESPONSE: u8 = 6;
    /// Bad link.
    pub const BAD_LINK: u8 = 7;
}

/// A helper building a capture-object column marker (`Data` at `code`, attr 2).
fn column(code: ObisCode) -> (Arc<dyn InterfaceClass + Send + Sync>, u8) {
    (Arc::new(Data::new(code, CosemDataType::Null)), 2u8)
}

/// One data-exchange-status record (§10.9, Table 8).
#[derive(Clone, Debug, Default)]
pub struct ExchangeRecord {
    /// `task_id` — task identifier.
    pub task_id: u32,
    /// Meter unique identifier.
    pub meter_uid: Vec<u8>,
    /// Task start time, as date-time octets.
    pub start: Vec<u8>,
    /// Task status (see [`exchange_status`]).
    pub status: u8,
    /// Task end time, as date-time octets.
    pub end: Vec<u8>,
    /// Number of attempts.
    pub attempts: u8,
}

impl ExchangeRecord {
    fn to_entry(&self) -> CosemDataType {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(self.task_id as u16),
            CosemDataType::OctetString(self.meter_uid.clone()),
            CosemDataType::DateTime(self.start.clone()),
            CosemDataType::Unsigned(self.status),
            CosemDataType::DateTime(self.end.clone()),
            CosemDataType::Unsigned(self.attempts),
        ])
    }
}

/// The data-exchange-status journal (§10.9, `0.0.94.7.135.255`).
#[derive(Clone, Debug, Default)]
pub struct ExchangeStatusJournal {
    records: Vec<ExchangeRecord>,
}

impl ExchangeStatusJournal {
    /// Creates an empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an exchange-status record.
    pub fn append(&mut self, record: ExchangeRecord) {
        self.records.push(record);
    }

    /// The Table-8 columns as capture-object markers.
    fn columns() -> Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)> {
        vec![
            column(ObisCode::new(0, 0, 94, 7, 135, 1)),  // task_id
            column(ObisCode::new(0, 0, 94, 7, 128, 10)), // meter uid
            column(ObisCode::new(0, 0, 94, 7, 135, 2)),  // start
            column(ObisCode::new(0, 0, 94, 7, 135, 3)),  // status
            column(ObisCode::new(0, 0, 94, 7, 135, 4)),  // end
            column(ObisCode::new(0, 0, 94, 7, 135, 5)),  // attempts
        ]
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) journal object.
    pub fn build(&self) -> ProfileGeneric {
        let buffer: Vec<CosemDataType> = self.records.iter().map(ExchangeRecord::to_entry).collect();
        let entries_in_use = buffer.len() as u32;
        ProfileGeneric::new(ProfileGenericConfig {
            logical_name: obis::exchange_status_journal(),
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

/// An ИВКЭ event journal (§10.13), following ГОСТ Р 58940-2020: each entry is a
/// timestamp and an event code, captured by a Clock and an event register.
#[derive(Clone, Debug)]
pub struct EventJournal {
    logical_name: ObisCode,
    entries: Vec<(Vec<u8>, u16)>,
}

impl EventJournal {
    /// Creates an empty event journal with the given OBIS (one of the §10.13
    /// codes, e.g. [`obis::access_control_log`]).
    pub fn new(logical_name: ObisCode) -> Self {
        EventJournal { logical_name, entries: Vec::new() }
    }

    /// Logs an event: `timestamp` (date-time octets) and its code.
    pub fn log(&mut self, timestamp: Vec<u8>, code: u16) {
        self.entries.push((timestamp, code));
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) journal object.
    pub fn build(&self) -> ProfileGeneric {
        let buffer: Vec<CosemDataType> = self
            .entries
            .iter()
            .map(|(ts, code)| {
                CosemDataType::Structure(vec![CosemDataType::DateTime(ts.clone()), CosemDataType::LongUnsigned(*code)])
            })
            .collect();
        let entries_in_use = buffer.len() as u32;
        let columns = vec![
            column(ObisCode::new(0, 0, 1, 0, 0, 255)), // Clock timestamp
            column(self.logical_name.clone()),         // event code register
        ];
        ProfileGeneric::new(ProfileGenericConfig {
            logical_name: self.logical_name.clone(),
            version: 1,
            buffer,
            capture_objects: columns,
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
    fn exchange_status_journal_builds_profile() {
        let mut journal = ExchangeStatusJournal::new();
        journal.append(ExchangeRecord {
            task_id: 7,
            meter_uid: b"SIT12260004".to_vec(),
            start: vec![0x07, 0xE6, 0x07, 0x04],
            status: exchange_status::DONE,
            end: vec![0x07, 0xE6, 0x07, 0x04],
            attempts: 1,
        });
        let profile = journal.build();
        assert_eq!(profile.class_id(), 7);
        assert_eq!(profile.logical_name(), &obis::exchange_status_journal());

        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 6);
        assert_eq!(cols[0], CosemDataType::LongUnsigned(7));
        assert_eq!(cols[3], CosemDataType::Unsigned(exchange_status::DONE));
        // Six capture columns.
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 6);
    }

    #[test]
    fn event_journal_logs_events() {
        let mut journal = EventJournal::new(obis::access_control_log());
        journal.log(vec![0x07, 0xE6, 0x07, 0x04], 0x0011);
        let profile = journal.build();
        assert_eq!(profile.logical_name(), &obis::access_control_log());

        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[1], CosemDataType::LongUnsigned(0x0011));
        // Two capture columns: clock + event register.
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 2);
    }
}
