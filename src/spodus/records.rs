//! ИВКЭ record journals (СТО 34.01-5.1-013-2023, §10.10 and §10.11).
//!
//! * The **object-correction journal** (§10.10, `0.0.94.7.136.255`) records the
//!   last correction time of the ИВКЭ configuration objects.
//! * The **numeric meter journal** (§10.11, `0.0.94.7.137.255`) holds meter
//!   readings disaggregated one value per row.
//!
//! Both are `ProfileGeneric` (IC 7, v1) objects.

use crate::classes::profile_generic::ProfileGeneric;
use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;
use super::profile::reference_profile;

/// One object-correction record (§10.10, Table 9).
#[derive(Clone, Debug, Default)]
pub struct CorrectionRecord {
    /// OBIS code of the corrected object.
    pub object_obis: Vec<u8>,
    /// Last correction time (date-time octets).
    pub time: Vec<u8>,
}

/// The object-correction journal (§10.10).
#[derive(Clone, Debug, Default)]
pub struct CorrectionJournal {
    records: Vec<CorrectionRecord>,
}

impl CorrectionJournal {
    /// Creates an empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a correction.
    pub fn record(&mut self, record: CorrectionRecord) {
        self.records.push(record);
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object (§10.10).
    pub fn build(&self) -> ProfileGeneric {
        let buffer = self
            .records
            .iter()
            .map(|r| {
                CosemDataType::Structure(vec![
                    CosemDataType::OctetString(r.object_obis.clone()),
                    CosemDataType::DateTime(r.time.clone()),
                ])
            })
            .collect();
        let columns = [ObisCode::new(0, 0, 94, 7, 136, 0), ObisCode::new(0, 0, 94, 7, 136, 1)];
        reference_profile(obis::object_correction_journal(), &columns, buffer)
    }
}

/// One numeric-journal record (§10.11, Table 10). A single disaggregated meter
/// reading with the metadata needed to relate it to its source journal row.
#[derive(Clone, Debug)]
pub struct NumericRecord {
    /// Meter identifier.
    pub meter_id: Vec<u8>,
    /// OBIS of the source journal in the meter.
    pub journal_obis: Vec<u8>,
    /// OBIS of the reading.
    pub reading_obis: Vec<u8>,
    /// Attribute number.
    pub attribute: u8,
    /// Fix time in the meter (date-time octets).
    pub meter_time: Vec<u8>,
    /// The reading value (CHOICE — any type).
    pub value: CosemDataType,
    /// Fix time in the ИВКЭ (date-time octets).
    pub ivke_time: Vec<u8>,
}

/// The numeric meter journal (§10.11).
#[derive(Clone, Debug, Default)]
pub struct NumericJournal {
    records: Vec<NumericRecord>,
}

impl NumericJournal {
    /// Creates an empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a disaggregated meter reading.
    pub fn record(&mut self, record: NumericRecord) {
        self.records.push(record);
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object (§10.11).
    pub fn build(&self) -> ProfileGeneric {
        let buffer = self
            .records
            .iter()
            .map(|r| {
                CosemDataType::Structure(vec![
                    CosemDataType::OctetString(r.meter_id.clone()),
                    CosemDataType::OctetString(r.journal_obis.clone()),
                    CosemDataType::OctetString(r.reading_obis.clone()),
                    CosemDataType::Unsigned(r.attribute),
                    CosemDataType::DateTime(r.meter_time.clone()),
                    r.value.clone(),
                    CosemDataType::DateTime(r.ivke_time.clone()),
                ])
            })
            .collect();
        let columns = [
            ObisCode::new(0, 0, 94, 7, 128, 10),
            ObisCode::new(0, 0, 94, 7, 137, 1),
            ObisCode::new(0, 0, 94, 7, 137, 2),
            ObisCode::new(0, 0, 94, 7, 137, 3),
            ObisCode::new(0, 0, 94, 7, 137, 4),
            ObisCode::new(0, 0, 94, 7, 137, 5),
            ObisCode::new(0, 0, 94, 7, 137, 6),
        ];
        reference_profile(obis::numeric_meter_journal(), &columns, buffer)
    }
}

/// `transmission status` values of an incoming-event row (§8.5.10, Table 4).
pub mod transmission_status {
    /// Waiting to be sent to the head-end.
    pub const WAITING: u8 = 0;
    /// Sent but not confirmed.
    pub const SENT_UNCONFIRMED: u8 = 1;
    /// Sent and confirmed.
    pub const SENT_CONFIRMED: u8 = 2;
    /// Transmission disabled.
    pub const DISABLED: u8 = 3;
}

/// One incoming push-event row (§8.5.10, Table 4).
#[derive(Clone, Debug, Default)]
pub struct IncomingEvent {
    /// Meter identifier.
    pub meter_id: Vec<u8>,
    /// Meter model.
    pub meter_model: Vec<u8>,
    /// Fix time in the ИВКЭ (date-time octets).
    pub ivke_time: Vec<u8>,
    /// Event time in the meter (date-time octets).
    pub meter_time: Vec<u8>,
    /// Field number within the meter's event-journal OBIS.
    pub journal_field: u8,
    /// Event code.
    pub code: u16,
    /// Transmission status (see [`transmission_status`]).
    pub status: u8,
}

/// The incoming push-events table (§8.5.10, `0.0.94.7.140.255`).
#[derive(Clone, Debug, Default)]
pub struct IncomingEventsTable {
    rows: Vec<IncomingEvent>,
}

impl IncomingEventsTable {
    /// Creates an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an incoming event.
    pub fn record(&mut self, event: IncomingEvent) {
        self.rows.push(event);
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object (§8.5.10).
    pub fn build(&self) -> ProfileGeneric {
        let buffer = self
            .rows
            .iter()
            .map(|e| {
                CosemDataType::Structure(vec![
                    CosemDataType::OctetString(e.meter_id.clone()),
                    CosemDataType::OctetString(e.meter_model.clone()),
                    CosemDataType::DateTime(e.ivke_time.clone()),
                    CosemDataType::DateTime(e.meter_time.clone()),
                    CosemDataType::Unsigned(e.journal_field),
                    CosemDataType::LongUnsigned(e.code),
                    CosemDataType::Unsigned(e.status),
                ])
            })
            .collect();
        let columns = [
            ObisCode::new(0, 0, 94, 7, 128, 10),
            ObisCode::new(0, 0, 94, 7, 140, 2),
            ObisCode::new(0, 0, 94, 7, 140, 3),
            ObisCode::new(0, 0, 94, 7, 140, 4),
            ObisCode::new(0, 0, 94, 7, 140, 5),
            ObisCode::new(0, 0, 94, 7, 140, 6),
            ObisCode::new(0, 0, 94, 7, 140, 7),
        ];
        reference_profile(obis::incoming_events_table(), &columns, buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn correction_journal_builds_profile() {
        let mut journal = CorrectionJournal::new();
        journal.record(CorrectionRecord {
            object_obis: obis::meter_list().to_bytes(),
            time: vec![0x07, 0xE6, 0x07, 0x04],
        });
        let profile = journal.build();
        assert_eq!(profile.logical_name(), &obis::object_correction_journal());
        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 2);
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 2);
    }

    #[test]
    fn numeric_journal_builds_profile() {
        let mut journal = NumericJournal::new();
        journal.record(NumericRecord {
            meter_id: b"SIT12260004".to_vec(),
            journal_obis: vec![1, 0, 98, 2, 0, 255],
            reading_obis: vec![1, 0, 1, 8, 1, 255],
            attribute: 2,
            meter_time: vec![0x07, 0xE6, 0x07, 0x04],
            value: CosemDataType::DoubleLongUnsigned(123_456),
            ivke_time: vec![0x07, 0xE6, 0x07, 0x04],
        });
        let profile = journal.build();
        assert_eq!(profile.logical_name(), &obis::numeric_meter_journal());
        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 7);
        assert_eq!(cols[5], CosemDataType::DoubleLongUnsigned(123_456));
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 7);
    }

    #[test]
    fn incoming_events_table_builds_profile() {
        let mut table = IncomingEventsTable::new();
        table.record(IncomingEvent {
            meter_id: b"SIT12260004".to_vec(),
            code: 0x1C,
            status: transmission_status::WAITING,
            ..Default::default()
        });
        let profile = table.build();
        assert_eq!(profile.logical_name(), &obis::incoming_events_table());
        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 7);
        assert_eq!(cols[5], CosemDataType::LongUnsigned(0x1C));
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 7);
    }
}
