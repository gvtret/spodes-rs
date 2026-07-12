# spodes-rs

[![CI](https://github.com/gvtret/spodes-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gvtret/spodes-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](#license)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://gvtret.github.io/spodes-rs/)
[![crates.io](https://img.shields.io/crates/v/spodes-rs.svg)](https://crates.io/crates/spodes-rs)

A pure-Rust implementation of the DLMS/COSEM stack for electricity metering,
following IEC 62056 (the DLMS Green Book) and the Russian companion profiles
**СТО 34.01-5.1-006-2023** and **Р 1323565.1** (GOST cryptography).

The crate covers the whole stack — COSEM object model, A-XDR encoding, HDLC and
TCP/UDP transport, the xDLMS application services, and the full security model
including the GOST suite — and provides blocking client and server drivers on
top. Every wire format and every cryptographic primitive is validated
byte-for-byte against the reference test vectors of the standards.

## Features

- **COSEM object model** — 31 interface classes (Data, Register, Extended /
  Demand register, Register activation, Profile generic, Clock, Script table,
  Schedule, Special days table, Association LN, Security setup, Disconnect
  control, Limiter, Push / TCP-UDP / IPv4 / IPv6 setup, and more), all versions.
- **38 typed attribute structs** — strongly-typed structs for IEC 62056-6-2
  (Blue Book) type definitions, replacing generic `CosemDataType`.
- **A-XDR / BER** serialization of the common COSEM data types.
- **Transport** — an HDLC data-link layer (IEC 62056-46) over any byte medium
  and a wrapper layer (IEC 62056-47) for TCP/UDP.
- **xDLMS services** (LN referencing, IEC 62056-5-3):
  - GET / SET / ACTION — normal, block transfer (with datablocks) and WITH-LIST;
  - ACSE association (AARQ / AARE) and release (RLRQ / RLRE);
  - structured InitiateRequest / InitiateResponse;
  - DataNotification and EventNotification;
  - ExceptionResponse and ConfirmedServiceError;
  - general block transfer (GBT);
  - glo-/ded-ciphering and general-glo-/ded-/general-ciphering / general-signing.
- **Security** (IEC 62056-5-3 §5.3 and Р 1323565.1):
  - security suites 0, 1, 2 and the GOST suite;
  - protection policies (none / authentication / encryption / both);
  - authentication mechanisms 0..10, including the GOST HLS mechanisms
    (Streebog, Kuznyechik-CMAC, GOST 34.10 signatures);
  - AES-GCM APDU protection, ECDSA and GOST 34.10 signatures;
  - ECDH and GOST VKO key agreement with the NIST SP 800-56A and GOST KDFs.
- **Timeouts and retries** — configurable per-request timeouts and automatic
  retries for transient errors in the client session.
- **Optional logging** — `tracing` support behind a feature flag.

## Quick start

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
spodes-rs = { git = "https://github.com/gvtret/spodes-rs" }
# or with optional features:
# spodes-rs = { git = "...", features = ["tracing"] }
```

### Creating a COSEM object

```rust
use spodes_rs::classes::data::Data;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::CosemDataType;

let object = Data::new(
    ObisCode::new(0, 0, 0x80, 0, 0, 0xFF),
    CosemDataType::LongUnsigned(0x1234),
);
assert_eq!(object.class_id(), 1);
assert_eq!(object.attributes()[1].1, CosemDataType::LongUnsigned(0x1234));
```

### Creating a Register with ScalerUnit

```rust
use spodes_rs::classes::register::Register;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::ScalerUnit;
use spodes_rs::types::CosemDataType;

let register = Register::new(
    ObisCode::new(0, 0, 1, 0, 0, 255),
    CosemDataType::DoubleLongUnsigned(1_234_567),
    ScalerUnit::new(-2, 30), // 0.01 kWh
);
// value = 1234567 × 10^(-2) = 12345.67 kWh
```

### BER serialization

```rust
use spodes_rs::types::CosemDataType;

let value = CosemDataType::Structure(vec![
    CosemDataType::LongUnsigned(3),
    CosemDataType::OctetString(vec![0, 0, 1, 0, 0, 255]),
    CosemDataType::Unsigned(2),
]);

let mut buf = Vec::new();
value.serialize_ber(&mut buf).unwrap();
// buf contains the A-XDR encoded bytes

let (decoded, remainder) = CosemDataType::deserialize_ber(&buf).unwrap();
assert!(remainder.is_empty());
assert_eq!(decoded, value);
```

### Typed attributes (IEC 62056-6-2)

The crate provides strongly-typed structs for all COSEM type definitions:

```rust
use spodes_rs::types::attrs::*;
use spodes_rs::obis::ObisCode;

// Action item for script tables and register monitors
let action = ActionItem {
    script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
    script_selector: 1,
};
let cd: CosemDataType = action.into();  // Convert to CosemDataType
let back = ActionItem::try_from(&cd).unwrap();  // Convert back

// Schedule table entry
let entry = ScheduleTableEntry {
    index: 1,
    enable: true,
    script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
    script_selector: 1,
    switch_time: vec![0x10, 0x00, 0x00],  // 16:00:00
    validity_window: 0xFFFF,
    exec_weekdays: vec![0x7F],  // all days
    exec_specdays: vec![0x00],
    begin_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF],
    end_date: vec![0x07, 0xE5, 0x12, 0x31, 0xFF],
};

// Access rights for Association LN
let access = AccessRight {
    attribute_access: vec![
        AttributeAccessItem { attribute_id: 1, access_mode: 1, access_selectors: None },
        AttributeAccessItem { attribute_id: 2, access_mode: 3, access_selectors: None },
    ],
    method_access: vec![
        MethodAccessItem { method_id: 1, access_mode: 1 },
    ],
};
```

### Client session with timeouts and retries

```rust
use spodes_rs::session::ClientSession;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::MemoryTransport;
use std::time::Duration;

let transport = MemoryTransport::new();
let wrapper = Wrapper::new(transport, 1, 1024);

// Configure with timeouts and retries
let mut session = ClientSession::builder(wrapper)
    .request_timeout(Duration::from_secs(5))
    .max_retries(3)
    .retry_delay(Duration::from_millis(200))
    .build();

// GET request
let response = session.get(3, obis(0, 0, 1, 0, 0, 255), 2).unwrap();

// SET request
use spodes_rs::types::CosemDataType;
session.set(3, obis(0, 0, 1, 0, 0, 255), 2, CosemDataType::DoubleLongUnsigned(1000)).unwrap();

// ACTION request
session.action(9, obis(0, 0, 10, 100, 0, 255), 1, Some(CosemDataType::LongUnsigned(1))).unwrap();
```

### Server dispatcher

```rust
use spodes_rs::classes::data::Data;
use spodes_rs::classes::register::Register;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::ScalerUnit;
use spodes_rs::types::CosemDataType;

let mut dispatcher = RequestDispatcher::new();

// Register objects
dispatcher.add(Box::new(Data::new(
    ObisCode::new(0, 0, 96, 1, 0, 255),
    CosemDataType::Unsigned(0),
)));
dispatcher.add(Box::new(Register::new(
    ObisCode::new(0, 0, 1, 0, 0, 255),
    CosemDataType::DoubleLongUnsigned(123_456),
    ScalerUnit::new(-2, 30),
)));

// Dispatch incoming request APDU
let request_apdu = vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0xFF, 0x02, 0x00];
let response_apdu = dispatcher.dispatch(&request_apdu).unwrap();
```

### Clock object

```rust
use spodes_rs::classes::clock::{Clock, ClockConfig};
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::DateTime;

let clock = Clock::new(ClockConfig {
    logical_name: ObisCode::new(0, 0, 1, 0, 0, 255),
    time: DateTime::from_ymdhms(2025, 7, 12, 14, 30, 0),
    time_zone: 180,  // UTC+3
    status: 0,
    daylight_savings_begin: DateTime::from_ymdhms(2025, 3, 30, 3, 0, 0),
    daylight_savings_end: DateTime::from_ymdhms(2025, 10, 26, 4, 0, 0),
    daylight_savings_deviation: 60,
    daylight_savings_enabled: true,
    clock_base: 1,  // internal crystal
});

assert_eq!(clock.time().0[5], 14);  // hour
```

### Activity calendar with typed structs

```rust
use spodes_rs::types::attrs::{SeasonProfile, WeekProfile, DayProfile, DayProfileAction};
use spodes_rs::obis::ObisCode;

let season = SeasonProfile {
    season_profile_name: b"Summer".to_vec(),
    season_start: vec![0x07, 0xE5, 0x04, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    week_name: b"WeekA".to_vec(),
};

let week = WeekProfile {
    week_profile_name: b"WeekA".to_vec(),
    monday: 1, tuesday: 1, wednesday: 1, thursday: 1,
    friday: 1, saturday: 2, sunday: 2,
};

let day = DayProfile {
    day_id: 1,
    day_schedule: vec![
        DayProfileAction {
            start_time: vec![0x08, 0x00, 0x00],
            script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
            script_selector: 1,
        },
    ],
};
```

### Push setup

```rust
use spodes_rs::classes::push_setup::{PushSetup, PushSetupConfig};
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::{CommunicationWindow, DateTime, SendDestinationAndMethod};
use spodes_rs::types::CosemDataType;

let config = PushSetupConfig {
    logical_name: ObisCode::new(0, 0, 25, 1, 0, 255),
    version: 0,
    push_object_list: vec![
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(3),
            CosemDataType::OctetString(vec![0, 0, 1, 0, 0, 255]),
            CosemDataType::Unsigned(2),
        ]),
    ],
    send_destination_and_method: SendDestinationAndMethod {
        transport_service: 0,  // TCP
        destination: b"192.168.1.100:4059".to_vec(),
        message: 2,  // A-XDR
    },
    communication_window: vec![CommunicationWindow {
        begin: DateTime::from_ymdhms(2025, 1, 1, 8, 0, 0),
        end: DateTime::from_ymdhms(2025, 12, 31, 18, 0, 0),
    }],
    randomisation_start_interval: 30,
    number_of_retries: 3,
    repetition_delay: CosemDataType::LongUnsigned(60),
    port_reference: vec![],
    push_client_sap: 0,
    push_protection_parameters: vec![],
    push_operation_method: 0,
    confirmation_parameters: CosemDataType::Null,
    last_confirmation_date_time: CosemDataType::Null,
};

let mut push = PushSetup::new(config);
push.invoke_method(1, Some(CosemDataType::Integer(0))).unwrap();
```

## Examples

Runnable examples live in [`examples/`](examples). Run one with:

```sh
cargo run --example client_session
cargo run --example server_dispatch
cargo run --example hls_handshake
cargo run --example push_listener
cargo run --example push_sender
cargo run --example tcp_client
cargo run --example udp_client
```

The per-class examples show how to build and serialize individual COSEM objects:

```sh
cargo run --example data_usage
cargo run --example register_usage
cargo run --example clock_usage
cargo run --example extended_register_usage
cargo run --example demand_register_usage
cargo run --example profile_generic_usage
cargo run --example register_activation_usage
cargo run --example schedule_usage
cargo run --example script_table_usage
cargo run --example special_days_table_usage
```

## СПОДУС — ИВКЭ concentrator

The [`spodus`](src/spodus) module implements the СПОДУС profile
(СТО 34.01-5.1-013-2023): a data-concentrator (ИВКЭ) that speaks СПОДЭС as a
DLMS client to the meters, aggregates their data, and serves it upstream to the
head-end (ИВК) as a DLMS server, with transparent pass-through to an individual
meter by its `direct_id`.

```sh
cargo run --example spodus_concentrator
```

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `gost` | yes | GOST cryptographic primitives (Kuznyechik, Streebog, GOST 34.10) |
| `nist` | yes | NIST cryptographic primitives (AES-GCM, ECDSA, ECDH) |
| `tracing` | no | Optional `tracing` logging support |

```toml
[dependencies]
spodes-rs = { git = "...", default-features = false, features = ["nist"] }
```

## Standards

- IEC 62056-5-3 (DLMS/COSEM application layer, the "Green Book")
- IEC 62056-6-2 (COSEM interface classes)
- IEC 62056-46 / IEC 62056-47 (HDLC and TCP/UDP transport)
- СТО 34.01-5.1-006-2023 (Rosseti companion profile)
- Р 1323565.1 (GOST cryptographic profile: suites, HLS mechanisms 8/9/10,
  GOST 34.10 / 34.11 / 34.12, VKO / KDF_TREE)

## Testing

```sh
cargo test                    # unit + integration + doc tests
cargo test --features tracing # with tracing enabled
cargo clippy --all-targets --all-features
cargo doc --no-deps --all-features
```

## MSRV

The minimum supported Rust version is **1.85**. This is tested in CI.

## Versioning

This project follows [Semantic Versioning](https://semver.org). Notable changes
are recorded in [CHANGELOG.md](CHANGELOG.md). Releases are cut by pushing a
`vX.Y.Z` tag matching the `Cargo.toml` version, which triggers the release
workflow. While the crate is at `0.x`, minor releases may contain breaking
changes.

## License

Licensed under the [GNU General Public License v3.0](LICENSE-GPL).
