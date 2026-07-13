//! `spodes-rs` — a pure-Rust implementation of the DLMS/COSEM stack for
//! electricity metering.
//!
//! It follows IEC 62056 (the DLMS Green Book / Blue Book) and the Russian
//! companion profiles **СПОДЭС** (СТО 34.01-5.1-006-2023, the meter model),
//! **Р 1323565.1** (the GOST cryptography profile) and **СПОДУС**
//! (СТО 34.01-5.1-013-2023, the ИВКЭ data-concentrator model). Every wire format
//! and cryptographic primitive is validated byte-for-byte against the reference
//! test vectors of those standards.
//!
//! The crate has no required feature flags and no unsafe code in its own
//! sources; it can be used a layer at a time or as a whole.
//!
//! [![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://gvtret.github.io/spodes-rs/)
//! [![crates.io](https://img.shields.io/crates/v/spodes-rs.svg)](https://crates.io/crates/spodes-rs)
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://gvtret.github.io/spodes-rs/")]
//!
//! # The stack
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │  session (client)     server (dispatcher)     spodus       │  drivers / profile
//! ├────────────────────────────────────────────────────────────┤
//! │  service    GET/SET/ACTION, ACSE, notifications, ciphering │  application layer
//! │  security   suites, policy, HLS mechanisms, ECDH/GOST      │
//! ├────────────────────────────────────────────────────────────┤
//! │  transport  HDLC (62056-46) and wrapper (62056-47)         │  transport layer
//! ├────────────────────────────────────────────────────────────┤
//! │  classes / interface  -  COSEM interface objects           │  object model
//! │  types (A-XDR/BER)  -  obis                                │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! * [`types`] — the COSEM data types ([`CosemDataType`](types::CosemDataType))
//!   and their A-XDR (BER) serialization.
//! * [`obis`] — OBIS object identification codes ([`ObisCode`](obis::ObisCode)).
//! * [`interface`] / [`classes`] — the COSEM interface classes (Data, Register,
//!   Clock, Profile generic, Association LN, Security setup, …), all behind the
//!   [`InterfaceClass`](interface::InterfaceClass) trait.
//! * [`transport`] — the physical-medium abstraction
//!   ([`PhysicalTransport`](transport::PhysicalTransport)) and the HDLC and
//!   wrapper data-link sub-layers (IEC 62056-46 / IEC 62056-47).
//! * [`service`] — the application-layer xDLMS services (GET/SET/ACTION,
//!   notifications, association and ciphering APDUs), using LN referencing.
//! * [`security`] — the security model: suites (0/1/2 and the GOST suite),
//!   protection policy, the authentication mechanisms (0..10) and the ECDH/GOST
//!   key-agreement primitives.
//! * [`session`] — a blocking client-side driver
//!   ([`ClientSession`](session::ClientSession)); [`server`] — a request
//!   dispatcher ([`RequestDispatcher`](server::RequestDispatcher)).
//! * [`spodus`] — the СПОДУС ИВКЭ data-concentrator object model and the
//!   [`Concentrator`](spodus::node::Concentrator) node.
//!
//! # Examples
//!
//! Build a COSEM object and read its attributes:
//!
//! ```
//! use spodes_rs::classes::data::Data;
//! use spodes_rs::interface::InterfaceClass;
//! use spodes_rs::obis::ObisCode;
//! use spodes_rs::types::CosemDataType;
//!
//! let object = Data::new(ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), CosemDataType::LongUnsigned(0x1234));
//! assert_eq!(object.class_id(), 1);
//! assert_eq!(object.attributes()[1].1, CosemDataType::LongUnsigned(0x1234));
//! ```
//!
//! Encode an xDLMS GET-request APDU:
//!
//! ```
//! use spodes_rs::obis::ObisCode;
//! use spodes_rs::service::get::GetRequest;
//! use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};
//!
//! let request = GetRequest::Normal {
//!     invoke_id_and_priority: invoke_id_and_priority(1, true, true),
//!     attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
//!     access_selection: None,
//! };
//! // C0 01 C1 0001 0000800000FF 02 00
//! assert_eq!(request.encode().unwrap()[0], 0xC0);
//! ```
//!
//! Answer a request server-side with a [`RequestDispatcher`](server::RequestDispatcher):
//!
//! ```
//! use spodes_rs::classes::data::Data;
//! use spodes_rs::obis::ObisCode;
//! use spodes_rs::server::RequestDispatcher;
//! use spodes_rs::service::get::{GetRequest, GetResponse};
//! use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};
//! use spodes_rs::types::CosemDataType;
//!
//! let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
//! let mut server = RequestDispatcher::new();
//! server.add(Box::new(Data::new(obis.clone(), CosemDataType::DoubleLongUnsigned(123_456))));
//!
//! let request = GetRequest::Normal {
//!     invoke_id_and_priority: invoke_id_and_priority(1, true, true),
//!     attribute: AttributeDescriptor::new(1, obis, 2),
//!     access_selection: None,
//! };
//! let response = GetResponse::decode(&server.dispatch(&request.encode().unwrap()).unwrap()).unwrap();
//! assert!(matches!(response, GetResponse::Normal { .. }));
//! ```
//!
//! # Standards
//!
//! IEC 62056-5-3 (application layer), IEC 62056-6-2 (interface classes),
//! IEC 62056-46 / -47 (HDLC / wrapper transport), СТО 34.01-5.1-006-2023
//! (СПОДЭС), СТО 34.01-5.1-013-2023 (СПОДУС) and Р 1323565.1 (GOST cryptography).
#![warn(missing_docs)]

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

/// СПОДУС — the ИВКЭ concentrator/gateway information model
/// (СТО 34.01-5.1-013-2023): meter aggregation upstream and pass-through access.
pub mod spodus;
