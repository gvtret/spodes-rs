# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the crate is at `0.x`, minor releases may contain breaking changes.

## [Unreleased]

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

[Unreleased]: https://github.com/gvtret/spodes-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gvtret/spodes-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gvtret/spodes-rs/releases/tag/v0.1.0
