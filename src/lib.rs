//! `spodes-rs` — a pure-Rust implementation of the DLMS/COSEM stack for
//! electricity metering, following IEC 62056 (the DLMS Green Book) and the
//! Russian companion profiles СТО 34.01-5.1-006-2023 and Р 1323565.1.
//!
//! The crate is organised as a layered stack that can be used piecemeal or as a
//! whole:
//!
//! * [`types`] — the COSEM data types and their A-XDR (BER) serialization.
//! * [`obis`] — OBIS object identification codes.
//! * [`interface`] / [`classes`] — the COSEM interface classes (Data, Register,
//!   Clock, Profile generic, Association LN, Security setup, …).
//! * [`transport`] — the physical-medium abstraction and the HDLC and wrapper
//!   data-link sub-layers (IEC 62056-46 / IEC 62056-47).
//! * [`service`] — the application-layer xDLMS services (GET/SET/ACTION,
//!   notifications, association and ciphering APDUs), using LN referencing.
//! * [`security`] — the security model: suites (0/1/2, and the GOST suite 9),
//!   protection policy, the authentication mechanisms (0..10) and the ECDH/GOST
//!   key-agreement primitives.
//! * [`session`] — a blocking client-side driver, and [`server`] — a
//!   request dispatcher for the server side.
//!
//! # Example
//!
//! ```
//! use spodes_rs::classes::data::Data;
//! use spodes_rs::interface::InterfaceClass;
//! use spodes_rs::obis::ObisCode;
//! use spodes_rs::types::CosemDataType;
//!
//! let object = Data::new(ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), CosemDataType::LongUnsigned(0x1234));
//! assert_eq!(object.class_id(), 1);
//! ```

/// COSEM data types and their BER (A-XDR) serialization.
pub mod types;

/// OBIS object identification codes.
pub mod obis;

/// The [`InterfaceClass`](interface::InterfaceClass) trait shared by all COSEM
/// interface classes.
pub mod interface;

/// Implementations of the COSEM interface classes (Data, Register, Clock, …).
pub mod classes;

/// BER serialization and deserialization helpers.
pub mod serialization;

/// Transport layer: physical-medium abstraction and the HDLC and wrapper
/// data-link sub-layers that carry xDLMS APDUs (IEC 62056-46 / IEC 62056-47).
pub mod transport;

/// Application-layer xDLMS services (GET/SET/ACTION) and association
/// establishment (AARQ/AARE), per IEC 62056-5-3, using LN referencing.
pub mod service;

/// Security model: security suites (0/1/2), security policy (protection level)
/// and the HLS/LLS authentication mechanisms (0..10), including the GOST profile
/// of Р 1323565.1.
pub mod security;

/// Client-side session driver that ties the transport, service and ciphering
/// layers into blocking GET/SET/ACTION/associate/release round trips.
pub mod session;

/// Server-side request dispatcher: routes incoming GET/SET/ACTION APDUs to the
/// addressed COSEM object and returns the response APDU.
pub mod server;
