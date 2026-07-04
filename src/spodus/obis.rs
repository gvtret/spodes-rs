//! OBIS codes of the СПОДУС / ИВКЭ information model (СТО 34.01-5.1-013-2023).
//!
//! Each function returns the [`ObisCode`] of a mandated object. Codes with a
//! channel component (`0.b.…`) take the channel as an argument.

use crate::obis::ObisCode;

/// Management logical device (`0.0.41.0.0.2`).
pub fn management_logical_device() -> ObisCode {
    ObisCode::new(0, 0, 41, 0, 0, 2)
}

/// ИВКЭ logical name (`0.0.42.0.0.255`).
pub fn ivke_logical_name() -> ObisCode {
    ObisCode::new(0, 0, 42, 0, 0, 255)
}

// --- Nameplate / passport data (§10.14, class Data) ------------------------

/// ИВКЭ serial number (`0.0.96.1.0.255`).
pub fn serial_number() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 0, 255)
}

/// ИВКЭ model (`0.0.96.1.1.255`).
pub fn model() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 1, 255)
}

/// Firmware version (`0.0.96.1.2.255`).
pub fn firmware_version() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 2, 255)
}

/// Manufacturer name (`0.0.96.1.3.255`).
pub fn manufacturer() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 3, 255)
}

/// Production year (`0.0.96.1.4.255`).
pub fn production_year() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 4, 255)
}

/// Hardware version (`0.0.0.2.1.255`).
pub fn hardware_version() -> ObisCode {
    ObisCode::new(0, 0, 0, 2, 1, 255)
}

/// СПОДУС specification version (`0.0.96.1.6.255`).
pub fn spodus_version() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 6, 255)
}

/// Last firmware-update date (`0.0.96.1.7.255`).
pub fn last_update_date() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 7, 255)
}

/// Non-metrological firmware identifier (`0.0.96.1.8.255`).
pub fn nonmetrological_firmware_id() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 8, 255)
}

/// Metrological firmware checksum (`0.0.96.1.10.255`).
pub fn metrological_firmware_checksum() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 10, 255)
}

// --- Meter management lists ------------------------------------------------

/// Discovered-meters list (§10.5, `0.0.94.7.131.255`, Profile generic).
pub fn discovered_meters() -> ObisCode {
    ObisCode::new(0, 0, 94, 7, 131, 255)
}

/// Meter access policies (§10.6, `0.0.94.7.132.255`, array of Data structs).
pub fn access_policies() -> ObisCode {
    ObisCode::new(0, 0, 94, 7, 132, 255)
}

// --- Journals (§10.9, §10.13) ----------------------------------------------

/// Parameter-programming event log (§10.13, `0.0.96.11.3.255`).
pub fn parameter_programming_log() -> ObisCode {
    ObisCode::new(0, 0, 96, 11, 3, 255)
}

/// Access-control event log (§10.13, `0.0.96.11.6.255`).
pub fn access_control_log() -> ObisCode {
    ObisCode::new(0, 0, 96, 11, 6, 255)
}

/// Self-diagnostics event log (§10.13, `0.0.96.11.7.255`).
pub fn self_diagnostics_log() -> ObisCode {
    ObisCode::new(0, 0, 96, 11, 7, 255)
}

/// Switching event log for channel `b` (§10.13, `0.b.96.11.5.255`).
pub fn switching_log(channel: u8) -> ObisCode {
    ObisCode::new(0, channel, 96, 11, 5, 255)
}

/// Discrete-I/O event log for channel `b` (§10.13, `0.b.99.98.10.255`).
pub fn discrete_io_log(channel: u8) -> ObisCode {
    ObisCode::new(0, channel, 99, 98, 10, 255)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameplate_codes() {
        assert_eq!(serial_number().to_bytes(), vec![0, 0, 96, 1, 0, 255]);
        assert_eq!(hardware_version().to_bytes(), vec![0, 0, 0, 2, 1, 255]);
        assert_eq!(spodus_version().to_bytes(), vec![0, 0, 96, 1, 6, 255]);
        assert_eq!(metrological_firmware_checksum().to_bytes(), vec![0, 0, 96, 1, 10, 255]);
    }

    #[test]
    fn meter_lists_and_management() {
        assert_eq!(management_logical_device().to_bytes(), vec![0, 0, 41, 0, 0, 2]);
        assert_eq!(ivke_logical_name().to_bytes(), vec![0, 0, 42, 0, 0, 255]);
        assert_eq!(discovered_meters().to_bytes(), vec![0, 0, 94, 7, 131, 255]);
        assert_eq!(access_policies().to_bytes(), vec![0, 0, 94, 7, 132, 255]);
    }

    #[test]
    fn journal_codes() {
        assert_eq!(parameter_programming_log().to_bytes(), vec![0, 0, 96, 11, 3, 255]);
        assert_eq!(access_control_log().to_bytes(), vec![0, 0, 96, 11, 6, 255]);
        assert_eq!(self_diagnostics_log().to_bytes(), vec![0, 0, 96, 11, 7, 255]);
        // Channel-scoped journals.
        assert_eq!(switching_log(1).to_bytes(), vec![0, 1, 96, 11, 5, 255]);
        assert_eq!(discrete_io_log(2).to_bytes(), vec![0, 2, 99, 98, 10, 255]);
    }
}
