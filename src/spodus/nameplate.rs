//! ИВКЭ nameplate / passport data (СТО 34.01-5.1-013-2023, §10.14).
//!
//! The passport parameters are exposed as `Data` (IC 1) objects at fixed OBIS
//! codes. Text identifiers are carried as octet-strings, the production year as
//! a long-unsigned, dates as date-time octet-strings and the firmware checksum
//! as an octet-string.

use crate::classes::data::Data;
use crate::classes::profile_generic::ProfileGeneric;
use crate::interface::InterfaceClass;
use crate::types::CosemDataType;

use super::obis;
use super::profile::reference_profile;

/// The ИВКЭ passport data (§10.14).
#[derive(Clone, Debug, Default)]
pub struct Nameplate {
    /// Serial number.
    pub serial_number: String,
    /// Model designation.
    pub model: String,
    /// Firmware version.
    pub firmware_version: String,
    /// Manufacturer name.
    pub manufacturer: String,
    /// Production year.
    pub production_year: u16,
    /// Hardware version.
    pub hardware_version: String,
    /// СПОДУС specification version.
    pub spodus_version: String,
    /// Last firmware-update date, as date-time octets (empty if unknown).
    pub last_update_date: Vec<u8>,
    /// Identifier of the non-metrological firmware part.
    pub nonmetrological_firmware_id: String,
    /// Checksum of the metrological firmware part.
    pub metrological_firmware_checksum: Vec<u8>,
}

impl Nameplate {
    /// Builds the `Data` objects for every passport parameter.
    pub fn objects(&self) -> Vec<Data> {
        let text = |s: &str| CosemDataType::OctetString(s.as_bytes().to_vec());
        vec![
            Data::new(obis::serial_number(), text(&self.serial_number)),
            Data::new(obis::model(), text(&self.model)),
            Data::new(obis::firmware_version(), text(&self.firmware_version)),
            Data::new(obis::manufacturer(), text(&self.manufacturer)),
            Data::new(obis::production_year(), CosemDataType::LongUnsigned(self.production_year)),
            Data::new(obis::hardware_version(), text(&self.hardware_version)),
            Data::new(obis::spodus_version(), text(&self.spodus_version)),
            Data::new(obis::last_update_date(), CosemDataType::DateTime(self.last_update_date.clone())),
            Data::new(obis::nonmetrological_firmware_id(), text(&self.nonmetrological_firmware_id)),
            Data::new(
                obis::metrological_firmware_checksum(),
                CosemDataType::OctetString(self.metrological_firmware_checksum.clone()),
            ),
        ]
    }

    /// Builds the passport-data reference profile (§10.14, `0.0.94.7.0.255`,
    /// IC 7 v1): one row aggregating every passport parameter, with the
    /// individual passport OBIS codes as the columns.
    pub fn profile(&self) -> ProfileGeneric {
        let objects = self.objects();
        let columns: Vec<_> = objects.iter().map(|o| o.logical_name().clone()).collect();
        let row = objects.iter().map(|o| o.attributes()[1].1.clone()).collect();
        reference_profile(obis::nameplate_profile(), &columns, vec![CosemDataType::Structure(row)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn nameplate_builds_data_objects() {
        let plate = Nameplate {
            serial_number: "IVKE-0001".to_string(),
            model: "GW-100".to_string(),
            firmware_version: "1.2.3".to_string(),
            manufacturer: "Acme".to_string(),
            production_year: 2026,
            hardware_version: "revB".to_string(),
            spodus_version: "СТО 013-2023".to_string(),
            last_update_date: vec![0x07, 0xE6, 0x07, 0x04],
            nonmetrological_firmware_id: "app-42".to_string(),
            metrological_firmware_checksum: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let objects = plate.objects();
        assert_eq!(objects.len(), 10);

        // Every object is a Data (class_id 1) at the right OBIS.
        assert!(objects.iter().all(|o| o.class_id() == 1));
        assert_eq!(objects[0].logical_name(), &obis::serial_number());

        // Serial number is an octet-string of the text.
        assert_eq!(objects[0].attributes()[1].1, CosemDataType::OctetString(b"IVKE-0001".to_vec()));
        // Production year is a long-unsigned.
        let year = objects.iter().find(|o| o.logical_name() == &obis::production_year()).unwrap();
        assert_eq!(year.attributes()[1].1, CosemDataType::LongUnsigned(2026));
    }

    #[test]
    fn nameplate_profile_aggregates_passport() {
        let plate = Nameplate { serial_number: "IVKE-0001".to_string(), production_year: 2026, ..Default::default() };
        let profile = plate.profile();
        assert_eq!(profile.class_id(), 7);
        assert_eq!(profile.version(), 1);
        assert_eq!(profile.logical_name(), &obis::nameplate_profile());

        let attrs = profile.attributes();
        // One row with the ten passport values; ten capture columns.
        let CosemDataType::Array(rows) = &attrs[1].1 else { panic!("buffer array") };
        assert_eq!(rows.len(), 1);
        let CosemDataType::Structure(values) = &rows[0] else { panic!("row structure") };
        assert_eq!(values.len(), 10);
        assert_eq!(values[0], CosemDataType::OctetString(b"IVKE-0001".to_vec()));
        let CosemDataType::Array(caps) = &attrs[2].1 else { panic!("capture array") };
        assert_eq!(caps.len(), 10);
    }
}
