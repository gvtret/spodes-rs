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
}
