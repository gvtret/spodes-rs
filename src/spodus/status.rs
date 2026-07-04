//! Meter status table (СТО 34.01-5.1-013-2023, §10.8, `0.0.94.7.134.255`).
//!
//! Per-meter status snapshot, exposed as a `ProfileGeneric` (IC 7, v1) with the
//! Table-7 columns: meter uid, last successful/attempted session times, current
//! relay state/mode and power limit, the last read meter time, the fix times of
//! those values and the load-profile period.

use crate::classes::profile_generic::ProfileGeneric;
use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;
use super::profile::reference_profile;

/// One meter's status row (§10.8, Table 7).
#[derive(Clone, Debug, Default)]
pub struct MeterStatus {
    /// Unique meter identifier.
    pub meter_uid: Vec<u8>,
    /// Time of the last successful session (date-time octets).
    pub last_success: Vec<u8>,
    /// Time of the last session attempt (date-time octets).
    pub last_attempt: Vec<u8>,
    /// Current relay state.
    pub relay_state: u8,
    /// Current relay control mode.
    pub relay_mode: u8,
    /// Current power limit.
    pub power_limit: u8,
    /// Last read meter time (date-time octets).
    pub last_meter_time: Vec<u8>,
    /// Relay-state fix time (date-time octets).
    pub relay_state_time: Vec<u8>,
    /// Relay-mode fix time (date-time octets).
    pub relay_mode_time: Vec<u8>,
    /// Power-limit fix time (date-time octets).
    pub power_limit_time: Vec<u8>,
    /// Current-time fix time (date-time octets).
    pub current_time_fix: Vec<u8>,
    /// Load-profile period.
    pub load_profile_period: u16,
}

impl MeterStatus {
    fn to_row(&self) -> CosemDataType {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(self.meter_uid.clone()),
            CosemDataType::DateTime(self.last_success.clone()),
            CosemDataType::DateTime(self.last_attempt.clone()),
            CosemDataType::Unsigned(self.relay_state),
            CosemDataType::Unsigned(self.relay_mode),
            CosemDataType::Unsigned(self.power_limit),
            CosemDataType::DateTime(self.last_meter_time.clone()),
            CosemDataType::DateTime(self.relay_state_time.clone()),
            CosemDataType::DateTime(self.relay_mode_time.clone()),
            CosemDataType::DateTime(self.power_limit_time.clone()),
            CosemDataType::DateTime(self.current_time_fix.clone()),
            CosemDataType::LongUnsigned(self.load_profile_period),
        ])
    }
}

/// The meter status table (§10.8).
#[derive(Clone, Debug, Default)]
pub struct MeterStatusTable {
    rows: Vec<MeterStatus>,
}

impl MeterStatusTable {
    /// Creates an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a meter status row.
    pub fn add(&mut self, status: MeterStatus) {
        self.rows.push(status);
    }

    /// Builds the COSEM `ProfileGeneric` (IC 7, v1) object (§10.8).
    pub fn build(&self) -> ProfileGeneric {
        let buffer = self.rows.iter().map(MeterStatus::to_row).collect();
        let columns = [
            ObisCode::new(0, 0, 94, 7, 128, 10),
            ObisCode::new(0, 0, 94, 7, 134, 1),
            ObisCode::new(0, 0, 94, 7, 134, 2),
            ObisCode::new(0, 0, 94, 7, 134, 3),
            ObisCode::new(0, 0, 94, 7, 134, 4),
            ObisCode::new(0, 0, 94, 7, 134, 5),
            ObisCode::new(0, 0, 94, 7, 134, 6),
            ObisCode::new(0, 0, 94, 7, 134, 7),
            ObisCode::new(0, 0, 94, 7, 134, 8),
            ObisCode::new(0, 0, 94, 7, 134, 9),
            ObisCode::new(0, 0, 94, 7, 134, 10),
            ObisCode::new(0, 0, 94, 7, 134, 11),
        ];
        reference_profile(obis::meter_status_table(), &columns, buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn meter_status_table_builds_profile() {
        let mut table = MeterStatusTable::new();
        table.add(MeterStatus {
            meter_uid: b"SIT12260004".to_vec(),
            relay_state: 1,
            power_limit: 15,
            load_profile_period: 900,
            ..Default::default()
        });
        let profile = table.build();
        assert_eq!(profile.class_id(), 7);
        assert_eq!(profile.logical_name(), &obis::meter_status_table());

        let attrs = profile.attributes();
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        let CosemDataType::Structure(cols) = &rows[0] else { panic!("row structure") };
        assert_eq!(cols.len(), 12);
        assert_eq!(cols[3], CosemDataType::Unsigned(1));
        assert_eq!(cols[11], CosemDataType::LongUnsigned(900));
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 12);
    }
}
