use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration used to build a `DemandRegister` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DemandRegisterConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: the demand value being accumulated in the current period.
    pub current_average_value: CosemDataType,
    /// Attribute 3: the demand value computed for the last completed period.
    pub last_average_value: CosemDataType,
    /// Attribute 4: `scaler_unit` structure { scaler, unit } for both values.
    pub scaler_unit: CosemDataType,
    /// Attribute 5: status of the register at capture time.
    pub status: CosemDataType,
    /// Attribute 6: the time `last_average_value` was captured (date-time).
    pub capture_time: CosemDataType,
    /// Attribute 7: start time of the current demand period (date-time).
    pub start_time_current: CosemDataType,
    /// Attribute 8: the demand-integration period, in seconds (double-long-unsigned).
    pub period: CosemDataType,
    /// Attribute 9: number of periods used for the sliding-demand computation.
    pub number_of_periods: CosemDataType,
}

/// The `DemandRegister` interface class (class_id = 5) managing measured demand
/// quantities such as the maximum power over a period, with support for
/// measurement periods and capture time, per IEC 62056-6-2.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DemandRegister {
    logical_name: ObisCode,
    current_average_value: CosemDataType,
    last_average_value: CosemDataType,
    scaler_unit: CosemDataType,
    status: CosemDataType,
    capture_time: CosemDataType,
    start_time_current: CosemDataType,
    period: CosemDataType,
    number_of_periods: CosemDataType,
}

impl DemandRegister {
    /// Creates a new `DemandRegister` object from its configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration used to build the object.
    ///
    /// # Returns
    /// A new `DemandRegister`.
    pub fn new(config: DemandRegisterConfig) -> Self {
        DemandRegister {
            logical_name: config.logical_name,
            current_average_value: config.current_average_value,
            last_average_value: config.last_average_value,
            scaler_unit: config.scaler_unit,
            status: config.status,
            capture_time: config.capture_time,
            start_time_current: config.start_time_current,
            period: config.period,
            number_of_periods: config.number_of_periods,
        }
    }

    /// Resets `current_average_value` and `last_average_value` to 0, and clears
    /// the status, capture time and current-period start time.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - On successful reset.
    /// * `Err(String)` - If the value type does not support reset.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        match &self.current_average_value {
            CosemDataType::Integer(_) => {
                self.current_average_value = CosemDataType::Integer(0);
                self.last_average_value = CosemDataType::Integer(0);
            }
            CosemDataType::Long(_) => {
                self.current_average_value = CosemDataType::Long(0);
                self.last_average_value = CosemDataType::Long(0);
            }
            CosemDataType::DoubleLong(_) => {
                self.current_average_value = CosemDataType::DoubleLong(0);
                self.last_average_value = CosemDataType::DoubleLong(0);
            }
            CosemDataType::Unsigned(_) => {
                self.current_average_value = CosemDataType::Unsigned(0);
                self.last_average_value = CosemDataType::Unsigned(0);
            }
            CosemDataType::LongUnsigned(_) => {
                self.current_average_value = CosemDataType::LongUnsigned(0);
                self.last_average_value = CosemDataType::LongUnsigned(0);
            }
            CosemDataType::DoubleLongUnsigned(_) => {
                self.current_average_value = CosemDataType::DoubleLongUnsigned(0);
                self.last_average_value = CosemDataType::DoubleLongUnsigned(0);
            }
            _ => return Err("Unsupported value type for reset".to_string()),
        }
        self.status = CosemDataType::Null;
        self.capture_time = CosemDataType::Null;
        self.start_time_current = CosemDataType::Null;
        Ok(CosemDataType::Null)
    }

    /// Advances to the next measurement period, moving `current_average_value`
    /// into `last_average_value`, resetting `current_average_value`, updating the
    /// status and capture time, and setting a new period start time.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - On a successful transition.
    /// * `Err(String)` - If the value type does not support reset.
    fn next_period(&mut self) -> Result<CosemDataType, String> {
        // Move the current value into the last value.
        self.last_average_value = self.current_average_value.clone();
        // Reset the current value.
        match &self.current_average_value {
            CosemDataType::Integer(_) => self.current_average_value = CosemDataType::Integer(0),
            CosemDataType::Long(_) => self.current_average_value = CosemDataType::Long(0),
            CosemDataType::DoubleLong(_) => self.current_average_value = CosemDataType::DoubleLong(0),
            CosemDataType::Unsigned(_) => self.current_average_value = CosemDataType::Unsigned(0),
            CosemDataType::LongUnsigned(_) => self.current_average_value = CosemDataType::LongUnsigned(0),
            CosemDataType::DoubleLongUnsigned(_) => self.current_average_value = CosemDataType::DoubleLongUnsigned(0),
            _ => return Err("Unsupported value type for next_period".to_string()),
        }
        // Update the status (1 means a successful measurement).
        self.status = CosemDataType::Unsigned(1);
        // Update the capture and current-period start time (example: 2025-05-01 00:00:00).
        let new_time = CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // year 2025, month 5, day 1
            0x02, // day of week: Tuesday
            0x00, 0x00, 0x00, // hour 0, minute 0, second 0
            0x00, // hundredths of a second: 0
            0x00, 0x00, 0x00, // deviation from UTC: 0
        ]);
        self.capture_time = new_time.clone();
        self.start_time_current = new_time;
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for DemandRegister {
    fn class_id(&self) -> u16 {
        5
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
            (2, self.current_average_value.clone()),
            (3, self.last_average_value.clone()),
            (4, self.scaler_unit.clone()),
            (5, self.status.clone()),
            (6, self.capture_time.clone()),
            (7, self.start_time_current.clone()),
            (8, self.period.clone()),
            (9, self.number_of_periods.clone()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string()), (2, "next_period".to_string())]
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
        if let CosemDataType::Structure(seq) = tlv {
            if seq.len() == 10 {
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
                self.current_average_value = seq[2].clone();
                self.last_average_value = seq[3].clone();
                self.scaler_unit = seq[4].clone();
                self.status = seq[5].clone();
                self.capture_time = seq[6].clone();
                self.start_time_current = seq[7].clone();
                self.period = seq[8].clone();
                self.number_of_periods = seq[9].clone();
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            2 => self.next_period(),
            _ => Err(format!("Method {} not supported for DemandRegister class", method_id)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a length in BER (short or long form).
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
