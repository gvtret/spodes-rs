# spodes-rs

[![CI](https://github.com/gvtret/spodes-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gvtret/spodes-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

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
- **Drivers** — a blocking [`ClientSession`](src/session.rs) and a server-side
  [`RequestDispatcher`](src/server.rs).

## Quick start

Add the crate to your `Cargo.toml` (path or git dependency), then:

```rust
use spodes_rs::classes::data::Data;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::CosemDataType;

// Build a COSEM Data object (class_id 1) and read its attributes.
let object = Data::new(
    ObisCode::new(0, 0, 0x80, 0, 0, 0xFF),
    CosemDataType::LongUnsigned(0x1234),
);
assert_eq!(object.class_id(), 1);
assert_eq!(object.attributes()[1].1, CosemDataType::LongUnsigned(0x1234));
```

Encoding an xDLMS GET request:

```rust
use spodes_rs::obis::ObisCode;
use spodes_rs::service::get::GetRequest;
use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};

let request = GetRequest::Normal {
    invoke_id_and_priority: invoke_id_and_priority(1, true, true),
    attribute: AttributeDescriptor::new(1, ObisCode::new(0, 0, 0x80, 0, 0, 0xFF), 2),
    access_selection: None,
};
// C0 01 C1 0001 0000800000FF 02 00
let bytes = request.encode().unwrap();
```

## Examples

Runnable examples live in [`examples/`](examples). Run one with:

```sh
cargo run --example client_session
cargo run --example server_dispatch
cargo run --example hls_handshake
```

The per-class examples (`data_usage`, `register_usage`, `clock_usage`, …) show
how to build and serialize individual COSEM objects.

## СПОДУС — ИВКЭ concentrator

The [`spodus`](src/spodus) module implements the СПОДУС profile
(СТО 34.01-5.1-013-2023): a data-concentrator (ИВКЭ) that speaks СПОДЭС as a
DLMS client to the meters, aggregates their data, and serves it upstream to the
head-end (ИВК) as a DLMS server, with transparent pass-through to an individual
meter by its `direct_id`.

The **complete Appendix-A object model** is provided: the nameplate (§10.14) and
its profile, configured meter list (§10.2), direct-channel table (§10.3),
channel list (§10.4), discovered meters (§10.5), access policies (§10.6),
data-exchange tasks (§10.7), meter status table (§10.8), the exchange-status
(§10.9), correction (§10.10), numeric (§10.11) and event (§10.13) journals, the
incoming-events table (§8.5.10), the notification objects (§8.5), the time-delta
and discrete-inputs objects, the standard Clock / SAP-assignment / Security-setup
/ Association-LN objects, and the two new СПОДУС classes **Table manager (8200)**
and **Profile data filter (8201)**. On top of it: the [`Concentrator`](src/spodus/node.rs)
upstream server (serving the full catalogue), downstream `poll_meter` aggregation
and the `MeterProxy` pass-through. See `cargo run --example spodus_concentrator`
and the `tests/spodus_integration.rs` regression test.

**Scope note:** this is the COSEM object model and its behaviour, exercised over
an in-memory transport. A deployable ИВКЭ additionally needs the physical
transport binding (HDLC/TCP, ports 4059/4065, §8), the operational collection
loop (§6: meter configuration, scheduled polling, task execution, time sync) and
real association/security configuration — these are outside the current scope.

## Standards

- IEC 62056-5-3 (DLMS/COSEM application layer, the "Green Book")
- IEC 62056-6-2 (COSEM interface classes)
- IEC 62056-46 / IEC 62056-47 (HDLC and TCP/UDP transport)
- СТО 34.01-5.1-006-2023 (Rosseti companion profile)
- Р 1323565.1 (GOST cryptographic profile: suites, HLS mechanisms 8/9/10,
  GOST 34.10 / 34.11 / 34.12, VKO / KDF_TREE)

## Testing

```sh
cargo test          # unit + integration + doc tests
cargo clippy --all-targets
cargo doc --no-deps
```

## Versioning

This project follows [Semantic Versioning](https://semver.org). Notable changes
are recorded in [CHANGELOG.md](CHANGELOG.md). Releases are cut by pushing a
`vX.Y.Z` tag matching the `Cargo.toml` version, which triggers the release
workflow. While the crate is at `0.x`, minor releases may contain breaking
changes.

## License

Licensed under the [GNU General Public License v3.0](LICENSE-GPL).
