//! COSEM interface classes (IEC 62056-6-2), each implementing
//! [`InterfaceClass`](crate::interface::InterfaceClass).

/// Activity calendar (class 20).
pub mod activity_calendar;
/// Arbitrator (class 68).
pub mod arbitrator;
/// Association LN (class 15).
pub mod association_ln;
/// Clock (class 8).
pub mod clock;
/// Data (class 1).
pub mod data;
/// Data protection (class 30).
pub mod data_protection;
/// Demand register (class 5).
pub mod demand_register;
/// Disconnect control (class 70).
pub mod disconnect_control;
/// Extended register (class 4).
pub mod extended_register;
/// GPRS modem setup (class 45).
pub mod gprs_modem_setup;
/// GSM diagnostic (class 47).
pub mod gsm_diagnostic;
/// IEC HDLC setup (class 23).
pub mod iec_hdlc_setup;
/// IEC local port setup (class 19).
pub mod iec_local_port_setup;
/// Image transfer (class 18).
pub mod image_transfer;
/// IPv4 setup (class 42).
pub mod ipv4_setup;
/// IPv6 setup (class 48).
pub mod ipv6_setup;
/// Limiter (class 71).
pub mod limiter;
/// MAC address setup (class 43).
pub mod mac_address_setup;
/// M-Bus slave port setup (class 25).
pub mod mbus_slave_port_setup;
/// Profile generic (class 7).
pub mod profile_generic;
/// Push setup (class 40).
pub mod push_setup;
/// Register (class 3).
pub mod register;
/// Register activation (class 6).
pub mod register_activation;
/// Register monitor (class 21).
pub mod register_monitor;
/// SAP assignment (class 17).
pub mod sap_assignment;
/// Schedule (class 10).
pub mod schedule;
/// Script table (class 9).
pub mod script_table;
/// Security setup (class 64).
pub mod security_setup;
/// Single action schedule (class 22).
pub mod single_action_schedule;
/// Special days table (class 11).
pub mod special_days_table;
/// TCP-UDP setup (class 41).
pub mod tcp_udp_setup;
