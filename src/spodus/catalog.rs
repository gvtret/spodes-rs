//! Builders for the standard catalogue objects of the ИВКЭ (СТО 34.01-5.1-013-2023,
//! Appendix A): Clock, SAP assignment, Security setup and Association LN.
//!
//! These reuse the crate's existing COSEM interface classes, instantiated at the
//! Appendix-A OBIS codes with СТО-013 defaults.

use crate::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AssociationLnVersion, AuthenticationMechanism,
};
use crate::classes::clock::{Clock, ClockConfig};
use crate::classes::sap_assignment::{SapAssignment, SapAssignmentConfig};
use crate::classes::security_setup::{SecuritySetup, SecuritySetupConfig};
use crate::obis::ObisCode;
use crate::types::CosemDataType;

use super::obis;

/// Client-type identifiers of the ИВКЭ server part (§8.4).
pub mod client_id {
    /// Public client — read-only, no security.
    pub const PUBLIC: u8 = 16;
    /// Reading — read + selective + some actions, high security.
    pub const READER: u8 = 32;
    /// Push output — DataNotification within a preset association.
    pub const PUSH: u8 = 34;
    /// Configurator — read/write/selective, high security.
    pub const CONFIGURATOR: u8 = 48;
}

/// The ИВКЭ Clock object (`0.0.1.0.0.255`, IC 8).
pub fn clock() -> Clock {
    use crate::types::attrs::DateTime;
    Clock::new(ClockConfig {
        logical_name: ObisCode::new(0, 0, 1, 0, 0, 255),
        time: DateTime([0u8; 12]),
        time_zone: 0,
        status: 0,
        daylight_savings_begin: DateTime([0u8; 12]),
        daylight_savings_end: DateTime([0u8; 12]),
        daylight_savings_deviation: 0,
        daylight_savings_enabled: false,
        clock_base: 0,
    })
}

/// The SAP-assignment object (§10.1.8, `0.0.41.0.0.255`, IC 17) listing the
/// logical devices of the ИВКЭ.
pub fn sap_assignment(sap_assignment_list: Vec<CosemDataType>) -> SapAssignment {
    SapAssignment::new(SapAssignmentConfig { logical_name: obis::sap_assignment(), sap_assignment_list })
}

/// A Security-setup object (IC 64 v1) at `obis` with the given security policy
/// (§9: 0 for Public, authenticated+encrypted for Reader/Configurator) and
/// suite 0.
pub fn security_setup(obis: ObisCode, security_policy: u8, client_st: Vec<u8>, server_st: Vec<u8>) -> SecuritySetup {
    SecuritySetup::new(SecuritySetupConfig {
        logical_name: obis,
        version: 1,
        security_policy,
        security_suite: 0,
        client_system_title: client_st,
        server_system_title: server_st,
        certificates: vec![],
    })
}

/// An Association LN object (IC 15 v1) at `obis` for a connection type, with the
/// given authentication mechanism and a reference to its Security-setup object.
pub fn association(obis: ObisCode, mechanism: AuthenticationMechanism, security_setup_ref: ObisCode) -> AssociationLn {
    AssociationLn::new(AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: CosemDataType::Null,
        application_context_name: CosemDataType::Null,
        xdlms_context_info: CosemDataType::Null,
        authentication_mechanism: mechanism,
        secret: CosemDataType::OctetString(vec![]),
        association_status: CosemDataType::Enum(0),
        security_setup_reference: CosemDataType::OctetString(security_setup_ref.to_bytes()),
        user_list: vec![],
        current_user: CosemDataType::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn standard_catalogue_objects_have_correct_class_and_obis() {
        assert_eq!(clock().class_id(), 8);
        assert_eq!(clock().logical_name(), &ObisCode::new(0, 0, 1, 0, 0, 255));

        let sap = sap_assignment(vec![]);
        assert_eq!(sap.class_id(), 17);
        assert_eq!(sap.logical_name(), &obis::sap_assignment());

        let ss = security_setup(ObisCode::new(0, 0, 43, 0, 0, 255), 0, vec![], vec![]);
        assert_eq!(ss.class_id(), 64);
        assert_eq!(ss.version(), 1);
        assert_eq!(ss.logical_name(), &ObisCode::new(0, 0, 43, 0, 0, 255));

        let assoc = association(
            ObisCode::new(0, 0, 40, 0, 1, 255),
            AuthenticationMechanism::None,
            ObisCode::new(0, 0, 43, 0, 0, 255),
        );
        assert_eq!(assoc.class_id(), 15);
        assert_eq!(assoc.logical_name(), &ObisCode::new(0, 0, 40, 0, 1, 255));
    }
}
