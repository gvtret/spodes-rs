# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the crate is at `0.x`, minor releases may contain breaking changes.

## [Unreleased]

## [0.7.1] - 2026-07-23

### Changed

- Removed third-party client/vendor name references from source comments,
  test names and the changelog; the underlying behaviour (accepting the
  manufacturer-specific mechanism-2 "HIGH" scheme, Clock's octet-string
  date-time encoding, etc.) is unchanged.

## [0.7.0] - 2026-07-23

### Added (manufacturer HIGH / HLS-GMAC interop, HDLC peer SAP)

- **Manufacturer-specific "HIGH" security accepted against HLS-GMAC
  associations**: the AARQ handler now accepts a client proposing the
  generic mechanism 2 (`HlsManufacturer`) against an association configured
  for mechanism 5 (`HlsGmac`), completing the four-pass handshake with the
  manufacturer-AES scheme that HIGH level actually implements — still gated
  on knowing the correct shared secret. `AssociationLn` tracks the in-flight handshake
  mechanism separately from the configured one, and the AARE's
  responding-AP-title is only echoed for ciphering / title-bound (GMAC+)
  mechanisms, matching the etalon.
- **`Data` (class 1) and `PushSetup` (class 40) gained `set_attribute`**:
  `Data` attribute 2 (value) and `PushSetup` attributes 2–8
  (`push_object_list`, `send_destination_and_method`, `communication_window`,
  `randomisation_start_interval`, `number_of_retries`, `repetition_delay`,
  version-≥1 `port_reference`) are now writable for server-side
  configuration.
- **HDLC client-SAP learning**: the server learns the client's address from
  SNRM and exposes it via the new `DataLinkLayer::client_sap()` (default
  `None`, non-breaking); inbound frames not addressed to this station are
  now filtered before dispatch.

### Fixed (HDLC server state machine: NDM/NRM, FRMR, inter-octet timeout)

- **NDM now only accepts SNRM and DISC** (Yellow Book `HDLC_NDMOP` / C++
  connect-loop parity); any other frame (I, UI, RR/RNR, unknown control) is
  silently ignored instead of being processed as if already associated.
- **FRMR paths added** for an unknown control field (`W`), an oversized
  I-frame `information` beyond the negotiated `max_info_rx` (`Y`), and an
  invalid N(R) on I/RR/RNR frames (`Z`); a wrong N(S) gets an RR carrying
  the current N(R) without advancing the receive sequence. Replying to an
  unknown control field re-parses the raw frame's addresses (`peek_addresses`)
  so the FRMR still reaches the right peer even though the control byte
  itself didn't decode.
- **Inter-octet vs. inactivity timeout semantics now match the C++
  `session_recv_frame` reference**: an inter-octet timeout mid-frame
  discards the incomplete octets and keeps listening for the next frame
  (previously surfaced as an error without disconnecting); an inactivity
  timeout on an empty buffer marks the link NDM and returns `TimedOut`, as
  before. `send_apdu` now refuses to send while the server side is in NDM.

### Fixed (xDLMS AARQ/HLS association etalon parity)

- **HLS pass 3/4 success now actually marks the association associated**
  (`AssociationLn::association_status` was previously left in the "pending"
  state after a successful `reply_to_HLS_authentication`, a genuine gap).
- **GET/SET/ACTION are now gated on association state**: allowed when no
  association is configured or once associated; while an HLS handshake is
  pending, only the `reply_to_HLS_authentication` ACTION on Association LN
  is accepted — everything else yields an EXCEPTION-RESPONSE
  (`service-not-allowed` / `operation-not-possible`).
- **AARQ validation hardened** against the C++/Yellow Book etalon: a
  protocol-version other than `{version1}` is rejected with the
  acse-service-**provider** diagnostic `no-common-acse-version` (previously
  only user diagnostics existed); a `sender-acse-requirements` bit pattern
  other than the authentication bit, or a mechanism-name without a
  calling-authentication-value (or vice versa), is rejected as
  `authentication-failure`.
- **ACSE wire format extended** for `protocol-version` (`[0]`),
  `sender-acse-requirements` (configurable, not hardcoded), the
  acse-service-provider vs. -user diagnostic CHOICE, and the AARE's HLS
  functional unit (`mechanism-name` echoed back alongside the StoC
  challenge) — all with symmetric encode/decode.

### Fixed (COSEM/HDLC server: mass-SET / configurator suite parity)

- **`set_attribute` added** for Register (value, scaler_unit), Clock (time,
  time_zone, daylight-saving fields), Limiter, ProfileGeneric
  (capture_objects, capture_period, sort_method, profile_entries),
  Association LN, Security Setup and several other interface classes needed
  by a mass-SET / configurator test suite.
- **GET/SET datablock state (`PendingBlocks`) can now be persisted across
  APDUs**: `RequestDispatcher::take_pending`/`restore_pending` let a host
  that rebuilds the dispatcher per request stash and restore in-flight
  block transfers.
- **HDLC send-side now waits for the peer's RR when `window_tx <= 1`**
  (server), matching the etalon's non-pipelined behaviour; N(R) validation
  on I/RR/RNR frames was refined to only FRMR when N(R) is genuinely
  *ahead* of V(S), since a *behind* N(R) is a normal lagging cumulative ack
  under windowed sends, not a protocol violation.
- **Role-based AARE conformance negotiation** (public / reader / configurator,
  matching the C++ `aare` fill order) replaces the previous single fixed
  conformance block.
- **Clock dates are now carried as `octet-string` (tag `0x09`)**, not
  `date-time` (tag `0x19`), matching `osp_val_cosem_datetime` / common client
  expectations; method IDs renumbered to the Blue Book layout
  (`adjust_to_measuring_period` inserted at 2, `shift_time` added at 6); and
  `PushSetup::reset` now sets `last_confirmation_date_time` to 1900-01-01
  rather than all-zero.

### Changed (full rust-idiomatic refactor: pedantic + nursery clippy)

- Every category of a full `clippy::pedantic` + `clippy::nursery` sweep the
  project explicitly opted into, including the two risky ones (numeric
  casts and trait/method signatures), is now applied: inlined `format!`
  args, `let…else`, dropped redundant `continue`s and clones, merged
  identical match arms, idiomatic `Option` handling (`map_or`/`map_or_else`/
  `is_none_or`), `From`/`.into()` over lossless `as` casts, and simplified
  method signatures (borrowed parameters instead of owned, `#[must_use]` on
  consuming builders, bare return values instead of always-`Ok`/`Some`
  wrappers).
- **Two real bugs surfaced and fixed while auditing the numeric casts**,
  not just style: several `TryFrom<&CosemDataType>` impls silently
  truncated an out-of-range `Long`/`LongUnsigned` wire value (attribute_id,
  method_id, scaler, version, client_SAP, quality_of_service, and others)
  into a different, valid-looking in-range value instead of rejecting it —
  now validated with `try_from` and covered by regression tests; HDLC's
  `XidParams::decode` similarly wrapped an out-of-range peer-proposed
  window size instead of rejecting it — now clamped to `u8::MAX`.
- Every other cast left in place is backed by either a provable invariant
  (a guard, a bitmask, a fixed-shape encoding) or a `debug_assert!` on a
  genuine protocol-level bound (the HDLC wrapper's 16-bit length field, the
  GOST KDF's one-octet block counter, HDLC's version-0 `unsigned` max-info
  field) — documented inline at each site rather than blanket-suppressed.

## [0.6.0] - 2026-07-22

### Added (HDLC XID negotiation and outbound I-frame segmentation)

- **XID parameter negotiation during SNRM/UA** (IEC 62056-46 §6.4.4.4.3.2,
  ported from openspodes `hdlc_session.c`): new `transport::hdlc::XidParams`
  (max information field length and window size, per direction).
  `HdlcLayer::set_xid_ceiling`/`xid()` configure the proposed ceiling and
  read back the negotiated values (tightened to the smaller of the two
  sides; a zero/absent field from the peer leaves that direction
  unchanged, and a ceiling is only ever narrowed, never widened). The
  client encodes its ceiling into SNRM and negotiates against UA's reply;
  the server resets to its own ceiling on every fresh SNRM, negotiates
  against the client's proposal, and echoes the result in UA. Defaults:
  1280/1280/1/1 (client), 512/512/1/1 (server), matching the reference.
- **Outbound I-frame segmentation**: `HdlcLayer::send_apdu` now splits an
  APDU whose LLC-prefixed payload exceeds the negotiated `max_info_tx` into
  consecutive I-frames with the format field's segmentation bit set on
  every frame but the last — the send-side mirror of the segmented-frame
  reassembly `receive_apdu` already performed. (The openspodes C reference
  does not actually implement this despite modelling the segmentation bit
  on receive: its own `send_apdu` just rejects an oversized APDU outright;
  this is a genuine addition, not a straight port, verified by feeding one
  `HdlcLayer`'s segmented output directly into a second, independent
  `HdlcLayer`'s `receive_apdu` and confirming it reassembles correctly.)

### Added (general block transfer, ported from openspodes gbt.c / client.c)

- **`service::gbt::send`/`receive`**: drive the general-block-transfer codec
  (IEC 62056-5-3 §9.3) over any `DataLinkLayer`, segmenting an oversized
  APDU into blocks and reassembling them on the other end. Supports
  unconfirmed transfer (no acks) and confirmed transfer with a window: the
  sender waits for an ack-only GBT frame every `window` blocks and
  retransmits from the first block the peer reports missing on a gap; the
  receiver requests retransmission on out-of-order blocks and
  acks-and-discards duplicates. `applies_to_apdu` identifies the services
  GBT covers: GET/SET/ACTION and, unlike the older service-specific
  WITH-DATABLOCK mechanism, DataNotification and EventNotificationRequest
  too.
- **`ClientSession`/`ClientSessionBuilder` GBT integration**: `with_gbt`/
  `enable_gbt(block_size)`, `gbt_window`/`set_gbt_window`,
  `gbt_streaming`/`set_gbt_streaming`. When enabled, a request or response
  whose service qualifies and exceeds the configured block size is
  transparently segmented/reassembled instead of sent as a single frame.
  Verified end-to-end over real threads and channels (unconfirmed,
  confirmed-window, and below-threshold round trips) — the single-call
  `LoopbackLink` mock used by other session tests cannot exercise GBT's
  multi-round-trip block/ack exchange.
- Server-side reassembly/segmentation is provided by the same `gbt::send`/
  `receive` functions, usable directly by any code driving a
  `RequestDispatcher` over a `DataLinkLayer` (see `tests/gbt_integration.rs`
  for the pattern); `RequestDispatcher::set_max_pdu` should be raised when
  GBT is meant to handle wire segmentation, so the service layer doesn't
  also segment via WITH-DATABLOCK.

### Added (HDLC inter-octet and inactivity timeouts, ported from openspodes hdlc_session.c)

- **`PhysicalTransport::set_read_timeout`**: an optional, non-breaking
  trait method (default no-op) mirroring `TcpStream::set_read_timeout`,
  letting a transport bound how long a `receive` call may block.
- **`HdlcLayer::set_inter_octet_timeout_ms`/`set_inactivity_timeout_s`**:
  configure the IEC 62056-46 "межсимвольный" (20..6000 ms, default 25) and
  "межкадровый" (0..120 s, 0 = disabled) timeouts, clamped to the standard's
  ranges. `receive_apdu` now waits under the inactivity timeout for a *new*
  frame to start and switches to the tighter inter-octet timeout for the
  rest of that frame; either one elapsing aborts the read with an
  `io::ErrorKind::TimedOut` error (already treated as transient/retryable by
  `ClientSession`'s existing retry logic). An inactivity timeout also drops
  `HdlcLayer::is_connected()` to `false` (NDM must be assumed on a silent
  peer), matching the reference; an inter-octet timeout does not by itself
  drop the connection.

### Security (re-audit against openspodes security.c 1.10.0)

- **Replay protection**: `SecurityContext` now tracks the last invocation
  counter (IC) accepted from each peer. `unprotect`/`gost_unprotect`/
  `gost_gmac_unprotect` reject a received IC that does not exceed the last
  one accepted — a replayed or reordered-backward ciphered APDU — *before*
  attempting decryption, and leave the context state unchanged on
  rejection. This closes a gap where a captured ciphered APDU could
  previously be replayed and would decrypt/process successfully. New
  `CipherError::ReplayDetected`.
- **Invocation-counter exhaustion guard**: `protect`/`gost_protect`/
  `gost_gmac_protect` refuse to protect another APDU once the IC has
  reached `u32::MAX` (re-keying is required), instead of wrapping the
  counter back to a reusable value. New `CipherError::InvocationCounterExhausted`
  and an advisory `SecurityContext::key_rotation_needed()` (true once the IC
  is within 1000 of overflow).
- **HLS authentication rate limiting**: `AssociationLn` now locks out the
  `reply_to_HLS_authentication` ACTION after 5 consecutive failed attempts
  (reset on a successful authentication), mitigating brute-force guessing
  of the challenge response — previously every attempt was checked with no
  limit.

### Added (Push delivery, ported from openspodes push_delivery.c)

- **`RequestDispatcher::build_push_delivery_request`**: reads each object
  listed in a `PushSetup`'s `push_object_list` from the dispatcher's
  registry, assembles the values into a DataNotification body (a single
  value, or an Array when more than one object is pushed), and pairs it with
  the destination/transport/client-SAP from the Push setup object, returning
  a `PushDeliveryRequest` for the host to send over the configured
  transport. `PushSetup` itself does not hold a registry reference (unlike
  the C implementation's back-pointer to the server), so the dispatcher —
  which already owns the object registry — is the natural place for this in
  the Rust API. New `PushSetup::push_object_list`/`send_destination_and_method`/
  `push_client_sap` getters.

### Added (server-side association, ported from openspodes 2.2.0)

- **Server-side AARQ handling** (`RequestDispatcher::handle_aarq`, also wired
  into `dispatch`): validates the application context, the calling-AP-title
  (8 octets required for ciphering and title-bound HLS), the InitiateRequest
  (DLMS version / conformance / client PDU size — rejected with an
  `initiateError` ConfirmedServiceError in the user-information), and the
  authentication against the configured Association LN. Structured ACSE
  diagnostics are returned in the AARE (`application-context-name-not-supported`,
  `calling-AP-title-not-recognized`, `authentication-required`,
  `authentication-mechanism-name-not-recognised`, `authentication-failure`).
  LLS checks the secret; HLS pass 1/2 stores CtoS, returns a random 16-octet
  StoC and leaves the association pending until the
  `reply_to_HLS_authentication` ACTION. The negotiated InitiateResponse ANDs
  the conformance and caps the PDU size by the client's maximum.
- New `acse_diagnostic` constants module and the missing mechanism-id
  constants (6..10) in `service::acse`.

### Added (HDLC session hardening, ported from openspodes 2.2.0)

- `HdlcLayer::connect`/`disconnect`: SNRM/UA establishment (with sequence
  reset) and DISC/UA-DM release for the client side.
- Server-side data-link lifecycle in `receive_apdu`: SNRM → UA with sequence
  reset (fresh association), DISC → UA in NRM / DM in NDM, FRMR on invalid
  frames, RR/RNR handling.
- I-frame segmentation reassembly: frames with the segmentation bit set are
  accumulated and acknowledged with RR until the final segment arrives.
- Frames with a bad FCS/HCS are silently dropped (up to 8 in a row) instead
  of aborting the exchange.

### Security

- Key material is now zeroized on drop (`zeroize`): `HlsContext` keys
  (EK/AK/GOST/signing), `SecurityContext` keys, and the old Association LN
  secret replaced by `change_HLS_secret`.

### Added (ported from the openspodes C implementation)

- **Six new interface classes** (IEC 62056-6-2): Compact data (62) with
  `reset`/`capture` methods, Register table (61), Status mapping (63),
  Utility tables (26), Parameter monitor (65) and the M-Bus slave device
  descriptor (76).
- **Server-side selective access** for the ProfileGeneric buffer (class 7,
  attribute 2): `entry_descriptor` (selector 2) filters the returned rows by
  the 1-based entry window in GET-REQUEST-NORMAL and WITH-LIST;
  `range_descriptor` (selector 1) returns the buffer unfiltered, matching the
  reference implementation.

### Fixed (Blue Book compliance, per openspodes 2.4.0)

- **Data (class 1) method 1** is now `reset`: sets the value to null-data per
  IEC 62056-6-2 §4.3.1.3.1 (previously rejected as unsupported).
- **Schedule (class 10) methods** now follow §4.5.3: method 1
  `enable_disable` toggles the entry's enable flag by index, method 2
  `insert` appends a `schedule_table_entry`, method 3 `delete` removes an
  entry by index (previously methods 1/2 enabled/disabled the whole
  schedule).
- **Malformed GET/SET requests** from an associated client are now answered
  with a `other-reason` data-access-result response instead of an error that
  drops the session.

### Security (per openspodes 1.10.0 audit)

- **BER length decoding hardened**: long-form lengths are limited to
  4 octets (previously up to 127 octets shifted into a `usize`, overflowing
  on crafted input) and a declared length beyond the remaining buffer is
  rejected before any allocation.

## [0.5.0] - 2026-07-12

### Added

- **38 typed COSEM attribute structs** for IEC 62056-6-2 (Blue Book):
  - Access rights: `AccessRight`, `AttributeAccessItem`, `MethodAccessItem`
  - Association LN: `ObjectListElement`, `AssociatedPartnersId`, `ContextName`, `XDLMSContextInfo`
  - Register Monitor / Limiter: `ValueDefinition`, `ActionItem`, `ActionSet`, `EmergencyProfile`, `LimiterAction`
  - Script Table: `Script`, `ActionSpecification`
  - Schedule: `ScheduleTableEntry`
  - Special Days: `SpecialDayEntry`
  - Activity Calendar: `SeasonProfile`, `WeekProfile`, `DayProfile`, `DayProfileAction`
  - Push Setup: `SendDestinationAndMethod`, `CommunicationWindow`
  - Register Activation: `ObjectDefinition`, `RegisterActMask`
  - Image Transfer: `ImageToActivateInfo`
  - Single Action Schedule: `ExecutedScript`
  - SAP Assignment: `SapAssignmentEntry`
  - GSM Diagnostic: `GsmAdjacentCell`
  - Data Protection: `ProtectionObject`
  - IPv4: `IpOption`
  - IPv6: `NeighborDiscoverySetup`
- **63 unit tests** for all typed attribute conversions (round-trip, BER, error cases)
- **Push examples**: `push_listener.rs`, `push_sender.rs`
- **GitHub Pages** deployment workflow for rustdoc
- **Version bump** workflow with dry-run support

### Security

- Fixed timing attack vulnerability in constant-time comparison for authentication tags.
- Removed potentially panicking `unwrap()` calls in favour of explicit error handling.

### Changed

- All 15 class files updated to use typed structs instead of generic `CosemDataType`:
  - AssociationLN, Limiter, PushSetup, ActivityCalendar, ScriptTable, Schedule
  - SpecialDaysTable, RegisterActivation, RegisterMonitor, SingleActionSchedule
  - ImageTransfer, GsmDiagnostic, ExtendedRegister, SapAssignment, IPv4/IPv6 Setup

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

[Unreleased]: https://github.com/gvtret/spodes-rs/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/gvtret/spodes-rs/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/gvtret/spodes-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/gvtret/spodes-rs/compare/v0.4.0...v0.6.0
[0.4.0]: https://github.com/gvtret/spodes-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gvtret/spodes-rs/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/gvtret/spodes-rs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/gvtret/spodes-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/gvtret/spodes-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gvtret/spodes-rs/releases/tag/v0.1.0
