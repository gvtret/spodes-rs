# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the crate is at `0.x`, minor releases may contain breaking changes.

## [Unreleased]

## [0.4.0] - 2026-07-09

### Added

- **Access Control List (ACL)** — full IEC 62056-5-3, 5.3.7.2.2 implementation:
  - `src/security/access_rights.rs`: `AccessRights`, `ObjectListEntry`, `AttributeAccessMode`, `MethodAccessMode`
  - AssociationLN `object_list` with `can_read`/`can_write`/`can_invoke` methods
  - `RequestDispatcher::set_association()` for access rights enforcement
  - Server validates GET/SET/ACTION against association's access_rights before dispatch
- **80+ integration tests** covering:
  - GOST HLS mechanisms (8: CMAC, 10: GOST 34.10 signature)
  - AES-GCM encryption/decryption
  - ECDSA P-256/P-384 (Suite 1/2)
  - Block transfer, SET/ACTION
  - Association LN with all authentication mechanisms
  - ACL access rights checking

## [0.3.0] - 2026-07-09

### Changed

- **Updated all cryptographic dependencies** to latest versions:
  - aes-gcm 0.10 -> 0.11, aead 0.5 -> 0.6
  - ecdsa 0.16 -> 0.17, p256/p384 0.13 -> 0.14
  - sha2 0.10 -> 0.11, streebog 0.10 -> 0.11
  - hmac 0.12 -> 0.13, cmac 0.7 -> 0.8
  - kuznyechik 0.8 -> 0.9, sha1 0.10 -> 0.11, md-5 0.10 -> 0.11
- **Updated rand** 0.9.1 -> 0.9.4 (fixed RUSTSEC-2026-0097)
- **Updated num-bigint** 0.4.7 -> 0.4.8 (yanked version)

### Added

- **TCP/UDP examples** (`tcp_client`, `tcp_server`, `udp_client`) with IEC 62056-47 wrapper
- **Architecture documentation** (`docs/ARCHITECTURE.md`)
- **Deployment guide** (`docs/DEPLOYMENT.md`)
- **Audit report** (`docs/AUDIT-REPORT.md`)
- **Performance benchmarks** (`benches/crypto.rs`, `benches/serialization.rs`)
- **CI improvements**: cargo audit job, coverage measurement with cargo-tarpaulin

### Security

- Fixed RUSTSEC-2026-0097 (rand unsound with custom logger)
- Removed yanked num-bigint 0.4.7 from dependencies

## [0.2.2] - 2026-07-04

### Documentation

- Fixed the misaligned "stack" diagram on the crate landing page: replaced the
  variable-width em-dash and middle-dot glyphs with ASCII and padded every row
  to a fixed inner width so the box borders line up on docs.rs.

## [0.2.1] - 2026-07-04

### Documentation

- Documented every remaining public item so the API renders in full on docs.rs.
  The added text is anchored to the standards: interface-class fields carry
  their IEC 62056-6-2 attribute numbers and meaning, service APDU variants and
  tags follow IEC 62056-5-3 Table 60, HDLC address/control/frame fields follow
  IEC 62056-46, and the ACSE/ciphering constants name their DLMS mechanisms and
  ciphered-APDU tags. Rewrote the crate landing page with the layer diagram, a
  module guide and three runnable examples. No functional changes.

## [0.2.0] - 2026-07-04

### Added

- **СПОДУС / ИВКЭ concentrator** (`spodus` module, СТО 34.01-5.1-013-2023): the
  complete Appendix-A object model of an ИВКЭ (data concentrator) —
  nameplate (§10.14) and its profile, configured meter list (§10.2),
  direct-channel table (§10.3), channel list (§10.4), discovered meters (§10.5),
  access policies (§10.6), data-exchange tasks (§10.7), meter status table
  (§10.8), data-exchange-status (§10.9), correction (§10.10), numeric (§10.11)
  and event (§10.13) journals, incoming-events table (§8.5.10), notifications
  (§8.5), the time-delta and discrete-inputs objects, the standard Clock /
  SAP-assignment / Security-setup / Association-LN objects, and the two new
  СПОДУС classes **Table manager (8200)** and **Profile data filter (8201)**.
  Plus the `Concentrator` upstream server, downstream `poll_meter` aggregation
  and the `MeterProxy` transparent pass-through by `direct_id`. Example:
  `spodus_concentrator`; regression test: `tests/spodus_integration.rs`.

  Scope: this is the COSEM object model over an in-memory transport. A deployable
  ИВКЭ still needs the physical transport binding (HDLC/TCP, §8), the operational
  collection loop (§6) and real association/security configuration.

## [0.1.0] - 2026-07-04

Initial release: a full DLMS/COSEM stack for IEC 62056 and the Russian
СТО 34.01-5.1-006-2023 / Р 1323565.1 GOST profiles.

### Added

- **COSEM object model** — 31 interface classes (Data, Register, Extended /
  Demand register, Register activation, Profile generic, Clock, Script table,
  Schedule, Special days table, Association LN, Security setup, Disconnect
  control, Limiter, Push / TCP-UDP / IPv4 / IPv6 setup and more), all versions,
  with A-XDR (BER) serialization of the common COSEM data types.
- **Transport** — an HDLC data-link layer (IEC 62056-46) over any byte medium
  and a wrapper layer (IEC 62056-47) for TCP/UDP.
- **xDLMS services** (LN referencing, IEC 62056-5-3): GET / SET / ACTION
  (normal, block transfer and WITH-LIST); ACSE association (AARQ / AARE) and
  release (RLRQ / RLRE); structured InitiateRequest / InitiateResponse;
  DataNotification and EventNotification; ExceptionResponse and
  ConfirmedServiceError; general block transfer (GBT); glo-/ded-ciphering and
  general-glo-/ded-/general-ciphering / general-signing.
- **Security** — suites 0, 1, 2 and the GOST suite; protection policies;
  authentication mechanisms 0..10 including the manufacturer mechanism (2) and
  the GOST HLS mechanisms (Streebog, Kuznyechik-CMAC, GOST 34.10); AES-GCM APDU
  protection; ECDSA and GOST 34.10 signatures; ECDH and GOST VKO key agreement
  with the NIST SP 800-56A and GOST KDFs. All GOST and KDF primitives are
  validated byte-for-byte against the reference vectors of the standards.
- **Drivers** — a blocking client `ClientSession` and a server-side
  `RequestDispatcher` (with GET segmentation and SET reassembly).
- **Tooling** — GitHub Actions CI (fmt, clippy, test, doc, package) and a
  tag-triggered release workflow; dual MIT / Apache-2.0 license.

[Unreleased]: https://github.com/gvtret/spodes-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/gvtret/spodes-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gvtret/spodes-rs/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/gvtret/spodes-rs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/gvtret/spodes-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/gvtret/spodes-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gvtret/spodes-rs/releases/tag/v0.1.0
