//! СПОДУС — the ИВКЭ concentrator/gateway profile (СТО 34.01-5.1-013-2023).
//!
//! An ИВКЭ (data concentrator) speaks СПОДЭС as a DLMS client to the meters
//! downstream, aggregates their data, and serves it upstream to the head-end
//! (ИВК) as a DLMS server via the СПОДУС object model, while also allowing
//! transparent pass-through access to an individual meter.
//!
//! This module builds the СПОДУС information model on top of the existing COSEM
//! object classes ([`crate::classes`]), the server dispatcher
//! ([`crate::server`]) and the client session ([`crate::session`]).

pub mod access_policy;
pub mod collect;
pub mod discovered;
pub mod journals;
pub mod meter;
pub mod nameplate;
pub mod node;
pub mod obis;
pub mod proxy;
