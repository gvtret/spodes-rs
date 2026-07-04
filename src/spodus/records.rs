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
}
