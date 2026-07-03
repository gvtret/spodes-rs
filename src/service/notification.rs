//! Unsolicited notification services (IEC 62056-5-3): the server-initiated
//! EVENT-NOTIFICATION and DATA-NOTIFICATION APDUs.
//!
//! Both are unconfirmed: the server pushes them to the client without a prior
//! request. EVENT-NOTIFICATION ([194], tag 0xC2) reports a single attribute
//! change; DATA-NOTIFICATION ([15], tag 0x0F) carries an arbitrary push body
//! (see the Push setup class, IC 40).

use crate::types::CosemDataType;

use super::{push_length, read_length, tag, AttributeDescriptor, ServiceError};

/// An EVENT-NOTIFICATION-REQUEST APDU: an unsolicited report that one attribute
/// of one object has taken a new value.
#[derive(Debug, Clone, PartialEq)]
pub struct EventNotificationRequest {
    /// Optional event time, as a date-time octet-string.
    pub time: Option<Vec<u8>>,
    /// The attribute that changed.
    pub attribute: AttributeDescriptor,
    /// The new attribute value.
    pub value: CosemDataType,
}

impl EventNotificationRequest {
    /// Encodes the APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::EVENT_NOTIFICATION_REQUEST];
        match &self.time {
            None => buf.push(0x00),
            Some(t) => {
                buf.push(0x01);
                push_length(t.len(), &mut buf);
                buf.extend_from_slice(t);
            }
        }
        self.attribute.encode(&mut buf);
        self.value.serialize_ber(&mut buf)?;
        Ok(buf)
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<EventNotificationRequest, ServiceError> {
        if bytes.first() != Some(&tag::EVENT_NOTIFICATION_REQUEST) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let (time, mut pos) = match bytes.get(1) {
            Some(0x00) => (None, 2),
            Some(0x01) => {
                let (len, header) = read_length(&bytes[2..])?;
                let start = 2 + header;
                let t = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
                (Some(t), start + len)
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let (attribute, n) = AttributeDescriptor::decode(&bytes[pos..])?;
        pos += n;
        let (value, _) = CosemDataType::deserialize_ber(&bytes[pos..])?;
        Ok(EventNotificationRequest { time, attribute, value })
    }
}

/// A DATA-NOTIFICATION APDU: an unsolicited push carrying an arbitrary body.
#[derive(Debug, Clone, PartialEq)]
pub struct DataNotification {
    /// Long-Invoke-Id-And-Priority (32-bit): identifies this push invocation.
    pub long_invoke_id_and_priority: u32,
    /// Date-time octet-string; empty (zero length) when not transmitted.
    pub date_time: Vec<u8>,
    /// The notification body (the push data).
    pub notification_body: CosemDataType,
}

impl DataNotification {
    /// Encodes the APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceError> {
        let mut buf = vec![tag::DATA_NOTIFICATION];
        buf.extend_from_slice(&self.long_invoke_id_and_priority.to_be_bytes());
        push_length(self.date_time.len(), &mut buf);
        buf.extend_from_slice(&self.date_time);
        self.notification_body.serialize_ber(&mut buf)?;
        Ok(buf)
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<DataNotification, ServiceError> {
        if bytes.first() != Some(&tag::DATA_NOTIFICATION) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let b = bytes.get(1..5).ok_or(ServiceError::Truncated)?;
        let long_invoke_id_and_priority = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let (len, header) = read_length(&bytes[5..])?;
        let start = 5 + header;
        let date_time = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
        let (notification_body, _) = CosemDataType::deserialize_ber(&bytes[start + len..])?;
        Ok(DataNotification { long_invoke_id_and_priority, date_time, notification_body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obis::ObisCode;

    #[test]
    fn event_notification_without_time_round_trips() {
        let ev = EventNotificationRequest {
            time: None,
            attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 96, 11, 0, 255), 2),
            value: CosemDataType::LongUnsigned(0x0007),
        };
        let bytes = ev.encode().unwrap();
        // C2 00 <attr 9> <12 0007>.
        assert_eq!(bytes[..2], [0xC2, 0x00]);
        assert_eq!(bytes[11..], [0x12, 0x00, 0x07]);
        assert_eq!(EventNotificationRequest::decode(&bytes).unwrap(), ev);
    }

    #[test]
    fn event_notification_with_time_round_trips() {
        let ev = EventNotificationRequest {
            time: Some(vec![0x07, 0xE6, 0x07, 0x04, 0x06, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            attribute: AttributeDescriptor::new(8, ObisCode::new(0, 0, 1, 0, 0, 255), 2),
            value: CosemDataType::Unsigned(1),
        };
        let bytes = ev.encode().unwrap();
        assert_eq!(bytes[..2], [0xC2, 0x01]);
        assert_eq!(EventNotificationRequest::decode(&bytes).unwrap(), ev);
    }

    #[test]
    fn data_notification_round_trips() {
        let dn = DataNotification {
            long_invoke_id_and_priority: 0x0000_0001,
            date_time: Vec::new(),
            notification_body: CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(0x1234),
                CosemDataType::Unsigned(9),
            ]),
        };
        let bytes = dn.encode().unwrap();
        // 0F 00000001 00 <02 02 <12 1234> <11 09>>.
        assert_eq!(bytes[..6], [0x0F, 0x00, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(DataNotification::decode(&bytes).unwrap(), dn);
    }
}
