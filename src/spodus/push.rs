//! ИВКЭ notification objects (СТО 34.01-5.1-013-2023, §8.5).
//!
//! The event push-message object (§8.5.11, `0.0.96.50.0.255`) describes the
//! aggregated meter events the ИВКЭ pushes upstream; the push-filter mask
//! (`0.0.97.98.10.255`) selects which events are relayed.

use crate::classes::data::Data;
use crate::types::CosemDataType;

use super::obis;

/// One pushed meter event (§8.5.11, `message`).
#[derive(Clone, Debug, Default)]
pub struct EventMessage {
    /// ИВКЭ logical name (16 octets).
    pub uspd_ln: Vec<u8>,
    /// Meter number.
    pub meter_number: Vec<u8>,
    /// Meter model.
    pub meter_model: Vec<u8>,
    /// Event date-time (octets).
    pub date_time: Vec<u8>,
    /// Field number within the meter's event-journal OBIS.
    pub journal_id: u8,
    /// Event code (per СПОДЭС / СПОДУС).
    pub code: u16,
}

impl EventMessage {
    fn to_structure(&self) -> CosemDataType {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(self.uspd_ln.clone()),
            CosemDataType::OctetString(self.meter_number.clone()),
            CosemDataType::OctetString(self.meter_model.clone()),
            CosemDataType::DateTime(self.date_time.clone()),
            CosemDataType::Unsigned(self.journal_id),
            CosemDataType::LongUnsigned(self.code),
        ])
    }
}

/// The event push-message object (§8.5.11, `0.0.96.50.0.255`).
#[derive(Clone, Debug, Default)]
pub struct EventMessages {
    messages: Vec<EventMessage>,
}

impl EventMessages {
    /// Creates an empty event-message list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an event.
    pub fn push(&mut self, message: EventMessage) {
        self.messages.push(message);
    }

    /// Builds the COSEM `Data` (IC 1) object holding the `array message` (§8.5.11).
    pub fn build(&self) -> Data {
        let array = self.messages.iter().map(EventMessage::to_structure).collect();
        Data::new(obis::event_message(), CosemDataType::Array(array))
    }
}

/// Builds the push-filter mask object (`0.0.97.98.10.255`, IC 1). Its value type
/// mirrors the meter's own push-mask object (§8.5.9), so it is supplied by the
/// caller.
pub fn push_mask(value: CosemDataType) -> Data {
    Data::new(obis::push_mask(), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn event_messages_build_data_object() {
        let mut events = EventMessages::new();
        events.push(EventMessage {
            uspd_ln: b"IVKE000000000001".to_vec(),
            meter_number: b"SIT12260004".to_vec(),
            meter_model: b"SiT".to_vec(),
            date_time: vec![0x07, 0xE6, 0x07, 0x04],
            journal_id: 1,
            code: 0x1C,
        });
        let object = events.build();
        assert_eq!(object.class_id(), 1);
        assert_eq!(object.logical_name(), &obis::event_message());
        let CosemDataType::Array(rows) = &object.attributes()[1].1 else { panic!("array") };
        let CosemDataType::Structure(fields) = &rows[0] else { panic!("message structure") };
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[5], CosemDataType::LongUnsigned(0x1C));
    }

    #[test]
    fn push_mask_wraps_value() {
        let mask = push_mask(CosemDataType::DoubleLongUnsigned(0xFF00));
        assert_eq!(mask.logical_name(), &obis::push_mask());
        assert_eq!(mask.attributes()[1].1, CosemDataType::DoubleLongUnsigned(0xFF00));
    }
}
