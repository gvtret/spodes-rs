//! ИВКЭ nameplate / passport data (СТО 34.01-5.1-013-2023, §10.14).
//!
//! The passport parameters are exposed as `Data` (IC 1) objects at fixed OBIS
//! codes. Text identifiers are carried as octet-strings, the production year as
//! a long-unsigned, dates as date-time octet-strings and the firmware checksum
//! as an octet-string.

use crate::classes::data::Data;
use crate::types::CosemDataType;

use super::obis;

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
}
