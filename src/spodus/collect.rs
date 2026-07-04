//! Downstream meter polling and aggregation (СТО 34.01-5.1-013-2023, §10).
//!
//! The ИВКЭ, acting as a DLMS client to the meters, reads their attributes and
//! stores the results in its aggregation cache so they can be served upstream
//! without re-polling.

use crate::obis::ObisCode;
use crate::service::get::{GetDataResult, GetResponse};
use crate::session::ClientSession;
use crate::transport::DataLinkLayer;

use super::meter::MeterRegistry;

/// A meter attribute to poll: `(class_id, logical_name, attribute_id)`.
pub type AttributeRef = (u16, ObisCode, i8);

/// Polls `attributes` of a meter over its downstream `session` and stores the
/// successfully read values in the registry's aggregation cache. Returns the
/// number of attributes read successfully.
pub fn poll_meter<L: DataLinkLayer>(
    session: &mut ClientSession<L>,
    registry: &mut MeterRegistry,
    meter_id: &[u8],
    attributes: &[AttributeRef],
) -> usize {
    let mut read = 0;
    for (class_id, obis, attribute) in attributes {
        if let Ok(GetResponse::Normal { result: GetDataResult::Data(value), .. }) =
            session.get(*class_id, obis.clone(), *attribute)
        {
            registry.store(meter_id, obis.clone(), *attribute as u8, value);
            read += 1;
        }
    }
    read
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classes::data::Data;
    use crate::server::RequestDispatcher;
    use crate::spodus::meter::MeterDescriptor;
    use crate::types::CosemDataType;
    use std::io;

    /// A loopback link that dispatches each request to a local "meter" server.
    struct LocalLink {
        server: RequestDispatcher,
        pending: Option<Vec<u8>>,
    }

    impl DataLinkLayer for LocalLink {
        fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
            self.pending = Some(self.server.dispatch(apdu).expect("dispatch"));
            Ok(())
        }
        fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
            Ok(self.pending.take().expect("a response"))
        }
    }

    #[test]
    fn poll_meter_updates_aggregation_cache() {
        // The downstream "meter" exposes an energy register.
        let energy = ObisCode::new(1, 0, 1, 8, 0, 255);
        let mut meter_server = RequestDispatcher::new();
        meter_server.add(Box::new(Data::new(energy.clone(), CosemDataType::DoubleLongUnsigned(123_456))));
        let mut session = ClientSession::new(LocalLink { server: meter_server, pending: None });

        let mut registry = MeterRegistry::new();
        registry.add(MeterDescriptor { meter_id: b"SIT12260004".to_vec(), ..Default::default() });

        let read = poll_meter(&mut session, &mut registry, b"SIT12260004", &[(1, energy.clone(), 2)]);
        assert_eq!(read, 1);
        assert_eq!(registry.cached(b"SIT12260004", &energy, 2), Some(&CosemDataType::DoubleLongUnsigned(123_456)));
    }
}
