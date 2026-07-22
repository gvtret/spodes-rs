use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{DayProfile, SeasonProfile, WeekProfile};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`ActivityCalendar`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ActivityCalendarConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: name of the active calendar.
    pub calendar_name_active: Vec<u8>,
    /// Attribute 3: active season profile (array of `season` structures).
    pub season_profile_active: Vec<SeasonProfile>,
    /// Attribute 4: active week profile table (array).
    pub week_profile_table_active: Vec<WeekProfile>,
    /// Attribute 5: active day profile table (array).
    pub day_profile_table_active: Vec<DayProfile>,
    /// Attribute 6: name of the passive calendar.
    pub calendar_name_passive: Vec<u8>,
    /// Attribute 7: passive season profile (array).
    pub season_profile_passive: Vec<SeasonProfile>,
    /// Attribute 8: passive week profile table (array).
    pub week_profile_table_passive: Vec<WeekProfile>,
    /// Attribute 9: passive day profile table (array).
    pub day_profile_table_passive: Vec<DayProfile>,
    /// Attribute 10: date-time at which the passive calendar becomes active.
    pub activate_passive_calendar_time: Vec<u8>,
}

/// `Activity calendar` interface class (class_id = 20, version = 0) per
/// IEC 62056-6-2 §4.5.5. Defines the tariff schedule as an active calendar and a
/// passive calendar that replaces it when activated.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ActivityCalendar {
    logical_name: ObisCode,
    calendar_name_active: Vec<u8>,
    season_profile_active: Vec<SeasonProfile>,
    week_profile_table_active: Vec<WeekProfile>,
    day_profile_table_active: Vec<DayProfile>,
    calendar_name_passive: Vec<u8>,
    season_profile_passive: Vec<SeasonProfile>,
    week_profile_table_passive: Vec<WeekProfile>,
    day_profile_table_passive: Vec<DayProfile>,
    activate_passive_calendar_time: Vec<u8>,
}

impl ActivityCalendar {
    /// Builds a new [`ActivityCalendar`] from its configuration.
    pub fn new(config: ActivityCalendarConfig) -> Self {
        ActivityCalendar {
            logical_name: config.logical_name,
            calendar_name_active: config.calendar_name_active,
            season_profile_active: config.season_profile_active,
            week_profile_table_active: config.week_profile_table_active,
            day_profile_table_active: config.day_profile_table_active,
            calendar_name_passive: config.calendar_name_passive,
            season_profile_passive: config.season_profile_passive,
            week_profile_table_passive: config.week_profile_table_passive,
            day_profile_table_passive: config.day_profile_table_passive,
            activate_passive_calendar_time: config.activate_passive_calendar_time,
        }
    }

    /// Method 1: `activate_passive_calendar` — copies the passive calendar over
    /// the active one, making it effective immediately (IEC 62056-6-2 §4.5.5.3).
    fn activate_passive_calendar(&mut self) -> Result<CosemDataType, String> {
        self.calendar_name_active = self.calendar_name_passive.clone();
        self.season_profile_active = self.season_profile_passive.clone();
        self.week_profile_table_active = self.week_profile_table_passive.clone();
        self.day_profile_table_active = self.day_profile_table_passive.clone();
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for ActivityCalendar {
    fn class_id(&self) -> u16 {
        20
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::OctetString(self.calendar_name_active.clone())),
            (3, CosemDataType::Array(self.season_profile_active.iter().map(|s| s.clone().into()).collect())),
            (4, CosemDataType::Array(self.week_profile_table_active.iter().map(|w| w.clone().into()).collect())),
            (5, CosemDataType::Array(self.day_profile_table_active.iter().map(|d| d.clone().into()).collect())),
            (6, CosemDataType::OctetString(self.calendar_name_passive.clone())),
            (7, CosemDataType::Array(self.season_profile_passive.iter().map(|s| s.clone().into()).collect())),
            (8, CosemDataType::Array(self.week_profile_table_passive.iter().map(|w| w.clone().into()).collect())),
            (9, CosemDataType::Array(self.day_profile_table_passive.iter().map(|d| d.clone().into()).collect())),
            (10, CosemDataType::OctetString(self.activate_passive_calendar_time.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "activate_passive_calendar".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?; // length = element count
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
        };
        // class_id + 10 attributes.
        if seq.len() != 11 {
            return Err(BerError::InvalidLength);
        }
        if let CosemDataType::LongUnsigned(class_id) = seq[0] {
            if class_id != self.class_id() {
                return Err(BerError::InvalidValue);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::OctetString(obis) = &seq[1] {
            if obis.len() == 6 {
                self.logical_name = ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
            } else {
                return Err(BerError::InvalidLength);
            }
        } else {
            return Err(BerError::InvalidTag);
        }
        self.calendar_name_active = take_octet_string(&seq[2])?;
        self.season_profile_active = take_typed_array(&seq[3])?;
        self.week_profile_table_active = take_typed_array(&seq[4])?;
        self.day_profile_table_active = take_typed_array(&seq[5])?;
        self.calendar_name_passive = take_octet_string(&seq[6])?;
        self.season_profile_passive = take_typed_array(&seq[7])?;
        self.week_profile_table_passive = take_typed_array(&seq[8])?;
        self.day_profile_table_passive = take_typed_array(&seq[9])?;
        self.activate_passive_calendar_time = take_octet_string(&seq[10])?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.activate_passive_calendar(),
            _ => Err(format!("Method {method_id} not supported for Activity calendar")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_octet_string(value: &CosemDataType) -> Result<Vec<u8>, BerError> {
    match value {
        CosemDataType::OctetString(bytes) => Ok(bytes.clone()),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_typed_array<T: for<'a> TryFrom<&'a CosemDataType, Error = String>>(
    value: &CosemDataType,
) -> Result<Vec<T>, BerError> {
    match value {
        CosemDataType::Array(list) => {
            list.iter().map(|item| T::try_from(item).map_err(|_| BerError::InvalidTag)).collect()
        }
        _ => Err(BerError::InvalidTag),
    }
}

/// Writes a BER length octet (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ActivityCalendar {
        ActivityCalendar::new(ActivityCalendarConfig {
            logical_name: ObisCode::new(0, 0, 13, 0, 0, 255),
            calendar_name_active: b"ACT".to_vec(),
            season_profile_active: vec![SeasonProfile {
                season_profile_name: b"summer".to_vec(),
                season_start: vec![1, 1],
                week_name: b"w1".to_vec(),
            }],
            week_profile_table_active: vec![],
            day_profile_table_active: vec![],
            calendar_name_passive: b"PAS".to_vec(),
            season_profile_passive: vec![SeasonProfile {
                season_profile_name: b"winter".to_vec(),
                season_start: vec![7, 1],
                week_name: b"w2".to_vec(),
            }],
            week_profile_table_passive: vec![],
            day_profile_table_passive: vec![],
            activate_passive_calendar_time: vec![0; 12],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 20);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 10);
        assert_eq!(obj.methods().len(), 1);
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.calendar_name_active = vec![];
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn activate_copies_passive_over_active() {
        let mut obj = sample();
        obj.invoke_method(1, None).unwrap();
        assert_eq!(obj.attributes()[1].1, CosemDataType::OctetString(b"PAS".to_vec()));
        let expected_passive: CosemDataType = SeasonProfile {
            season_profile_name: b"winter".to_vec(),
            season_start: vec![7, 1],
            week_name: b"w2".to_vec(),
        }
        .into();
        assert_eq!(obj.attributes()[2].1, CosemDataType::Array(vec![expected_passive]));
    }
}
