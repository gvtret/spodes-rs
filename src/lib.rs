/// Библиотека `spodes-rs` для работы с объектами COSEM (Companion Specification for Energy Metering)
/// в соответствии со стандартами IEC 62056-6-2 и СТО 34.01-5.1-006-2023.
///
/// Предоставляет реализацию интерфейсных классов, типов данных, OBIS-кодов,
/// а также механизмы сериализации/десериализации в формате BER.
pub mod types;

/// Модуль для работы с OBIS-кодами (Object Identification System).
pub mod obis;

/// Модуль, определяющий трейт `InterfaceClass` для интерфейсных классов COSEM.
pub mod interface;

/// Модуль, содержащий реализации интерфейсных классов COSEM (например, `Data`, `Register`).
pub mod classes;

/// Модуль для сериализации и десериализации объектов в формате BER.
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
