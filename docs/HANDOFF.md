# Handoff — spodes-rs working context

Progress log. Latest entry at the bottom is the live state.

## 2026-07-13 (approx, session resumed) — Typed COSEM attributes refactor, in progress toward 0.5.0

**Done (found on resume; this file did not exist before — created now):**
- Since the earlier 0.2.x docs work, the project shipped **0.3.0** (crypto deps
  update, benchmarks, English docs) and **0.4.0** (ACL: `access_rights` in
  AssociationLN + server-side access checking, 287 tests) — both tagged and
  released. Git history was rewritten at some point (rebase/filter — commit
  hashes for the 0.2.x work no longer match what's in the old chat log, but
  content is equivalent: `b439102` = stack-diagram fix, etc.).
  Also completed since 0.2.x: security audit fixes (AUDIT-REPORT.md — timing-
  attack fix in constant-time comparison, removed panicking `unwrap()`s),
  deployment guide (`docs/DEPLOYMENT.md`), GitHub Pages rustdoc deploy,
  version-bump workflow.
- **Current work (0.5.0, unreleased):** a large typed-attributes refactor per
  `docs/TYPED-ATTRS-PLAN.md` — replacing loosely-typed `CosemDataType`/`Choice`
  attribute fields with proper Rust structs in `src/types/attrs.rs` (now 75
  structs/enums, 3891 lines). Latest commit `c2ca8ad` "refactor: type 20 more
  fields per IEC 62056-6-2 Blue Book" added: `User`, `ExecutionTime`,
  `QualityOfService`, `GsmServiceParameter`, `CellInfo`,
  `PushProtectionParameter`, `ConfirmationParameters`, `Certificate`; and wired
  them into DemandRegister, AssociationLN, Limiter, Arbitrator, PushSetup,
  SecuritySetup, GprsModemSetup, GsmDiagnostic, SingleActionSchedule.
  CHANGELOG's `[0.5.0] - 2026-07-12` section already lists 38 typed structs +
  63 unit tests + push examples (`push_listener.rs`/`push_sender.rs`) + GitHub
  Pages workflow — the just-committed 20 more structs are additional work not
  yet reflected in the CHANGELOG `[0.5.0]` entry.

**State:**
- Branch `main`, clean tree, `Cargo.toml` version `0.5.0` — **not yet tagged/released** (`git tag` shows up to `v0.4.0` only).
- `cargo build --lib` clean. `cargo test --lib` → **309 passed, 0 failed**.
- Per `docs/TYPED-ATTRS-PLAN.md` "Фаза 3" priority list, several classes are typed (Data, Register-family via earlier commits, plus the ones listed above); the plan's own "Риски" note ~30+ interface classes and 288 tests total to update — so this is likely still mid-way, not complete. Phase 2 (`InterfaceClass` trait gaining `typed_attributes()`) and Phase 4 (server/client typed dispatch) status not verified this session — check the trait definition and `attrs.rs` coverage against the plan's class list before assuming done.

**Next:**
1. Diff `docs/TYPED-ATTRS-PLAN.md`'s class list against what's actually typed in `src/classes/*.rs` to find which classes still use raw `CosemDataType`/`Choice` for attributes that should be typed structs.
2. Update `CHANGELOG.md` `[0.5.0]` entry to include the 20 additional structs from commit `c2ca8ad` (currently only lists the original 38).
3. Once typed-attrs work is judged complete: bump nothing further (already `0.5.0`), run full quality gate (`cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test`, `cargo doc --no-deps`), then tag `v0.5.0` and push (triggers `.github/workflows/release.yml` → crates.io publish + docs.rs rebuild), per the `release` skill.

**Notes:**
- Author email in commits here is `trgv@tavrida.com` (not the `mtistudent@yandex.ru` default in the handoff skill template — this project's actual convention). No `Co-Authored-By: Claude` trailer (guard hook blocks it).
- crates.io token was rotated and verified working in an earlier session (old leaked token revoked, new one confirmed via `cargo owner --list`) — no outstanding security action there.
- `docs/` is excluded from the crates.io package (`exclude = ["/docs"]` in Cargo.toml per earlier session), so this HANDOFF.md and the other docs/ files never ship in the crate.

## 2026-07-22 — Port from openspodes C implementation (gaps + fixes)

**Done:**
- Compared against `/mnt/e/work/opendlms/openspodes` (C, v2.4.0) and ported:
  - Blue Book fixes: Data method 1 = reset (`src/classes/data.rs`); Schedule
    methods 1-3 = enable_disable/insert/delete per §4.5.3
    (`src/classes/schedule.rs`, test updated in `tests/integration.rs`).
  - Malformed GET/SET → DAR `other-reason` response instead of session drop
    (`src/server.rs` dispatch_get/dispatch_set).
  - Server-side selective access for ProfileGeneric buffer: selector 2
    (entry_descriptor) filters rows, selector 1 passes through
    (`apply_selective_access` in `src/server.rs`).
  - BER length hardening: long-form limited to 4 octets + declared length must
    fit the remaining buffer (`read_length` in `src/types/mod.rs`, test
    `crafted_ber_length_is_rejected`).
  - Six new IC classes with tests: compact_data(62), register_table(61),
    status_mapping(63), utility_tables(26), parameter_monitor(65),
    mbus_slave(76) — registered in `src/classes/mod.rs`.
- Verified already present in Rust (no port needed): ALN method 2
  change_HLS_secret; HLS-GMAC uses EK as GCM key with AK in AAD; glo IV
  TX-local/RX-peer titles (split tx/rx SecurityContext in session.rs);
  ExceptionResponse for unknown APDU tags; mechanism 2 = password AES
  (C reverted its GMAC mapping to identity).
- CHANGELOG `[Unreleased]` updated. Quality gate green: fmt, clippy
  (-D warnings), doc (-D warnings), 327 lib + 87 integration/doc tests.

**State:** branch `main`, changes uncommitted at entry-write time (commit
follows immediately after). Version still 0.5.0 unreleased.

**Next:** Consider porting the remaining C-side items (see below), then release.

**Notes — NOT ported (larger subsystems, decide separately):**
- AARQ centralized validation + ACSE diagnostics (C server.c has a full
  server-side association state machine; Rust RequestDispatcher has no AARQ
  handling at all — architectural gap).
- HDLC session hardening (inter-octet/inactivity timeouts, RX pending buffer,
  I-frame segmentation reassembly, DISC lifecycle NRM→UA+NDM, FRMR W/X/Y/Z,
  XID renegotiation) — Rust hdlc.rs is codec + thin layer.
- Key zeroization (`zeroize` crate) for all key material.
- Data HAL (C 2.3.0) — not applicable: Rust's InterfaceClass trait is the
  abstraction; a HAL-backed impl can be written by users.
- Push delivery service internals (C service/push_delivery.c) vs existing
  spodus/push.rs — not compared in depth.
- C parameter_monitor/mbus_slave attribute sets follow the C project (which
  deviates from the Blue Book for class 65); ported as-is per user request.

## 2026-07-22 — C-port round 2: server AARQ, HDLC hardening, zeroize

**Done:**
- Server-side AARQ/AARE: `RequestDispatcher::handle_aarq` (src/server.rs) with
  full validation chain and ACSE diagnostics per C aarq_validate; new
  `acse_diagnostic` module + mechanisms 6..10 constants in service/acse.rs;
  `AssociationLn` gained `authentication_mechanism()`, `secret()`,
  `set_association_status()` getters. 7 new tests.
- HDLC hardening (src/transport/hdlc.rs): `connect()`/`disconnect()`
  (SNRM/UA, DISC/UA-DM), server lifecycle in `receive_apdu` (SNRM→UA+reset,
  DISC→UA/DM, FRMR, RR/RNR), segmented I-frame reassembly with RR acks,
  bad-FCS frames dropped (MAX_BAD_FRAMES=8). 5 new tests.
- Zeroize: new dep `zeroize = "1.8"`; Drop impls for `HlsContext` and
  `SecurityContext`; old secret zeroized in `change_hls_secret`. Test FRU
  (`..Default::default()`) sites rewritten (Drop types forbid FRU).

**State:** branch `main`, all quality gates green (351 lib+unit tests total,
7 suites; fmt/clippy/doc -D warnings). Committed after this entry.

**Next:** Remaining from the C comparison, still not ported: HDLC inter-octet
and inactivity timeouts (needs deadline support in PhysicalTransport), XID
parameter negotiation, outbound I-frame segmentation, push_delivery deep
comparison vs spodus/push.rs. Then release (0.5.0 or 0.6.0 given the new
public API).

## 2026-07-22 — C-port round 3: push delivery wiring

**Done:**
- `PushSetup` (src/classes/push_setup.rs): added `push_object_list()`,
  `send_destination_and_method()`, `push_client_sap()` getters; new
  `PushDeliveryRequest` struct; updated docs to point at the dispatcher-side
  assembly (PushSetup itself has no registry back-reference, unlike C's
  `p->server->dispatcher`).
- `RequestDispatcher::build_push_delivery_request` (src/server.rs): reads
  each `push_object_list` entry from the registry, builds a DataNotification
  body (single value or Array), encodes it, returns a `PushDeliveryRequest`
  with destination/transport/client_sap. Mirrors C's
  `push_build_notification_body`/`push_try_schedule_delivery`, but returns
  the request instead of using a global function-pointer hook (idiomatic
  Rust: caller owns transmission, no `unsafe`/global state needed). 2 new
  tests (reads registered object; rejects missing object).
- Full quality gate green: 341 lib tests + 4 integration suites, fmt/clippy/
  doc -D warnings all clean.

**State:** branch `main`, uncommitted at entry-write time (commit follows
immediately). This closes the last item from the C-comparison round ("push
delivery internals ... not compared in depth" from the first 2026-07-22
entry) except the two items below.

**Remaining from the full C comparison (deliberately deferred, minor):**
- HDLC inter-octet / inactivity timeouts (needs a deadline/clock abstraction
  in PhysicalTransport — larger API change, not done).
- XID parameter negotiation and outbound I-frame segmentation (C splits long
  I-frames across multiple HDLC frames; Rust send_apdu sends one frame today
  — acceptable since APDUs already fit under typical HDLC info-field limits
  via the xDLMS block-transfer layer instead).

**Next:** consider these two remaining items only if a concrete need arises;
otherwise the C-parity port is functionally complete. Ready for release
(0.5.0 or bump to 0.6.0 given the new public API surface: handle_aarq,
build_push_delivery_request, HdlcLayer::connect/disconnect, 6 new IC
classes).

## 2026-07-22 — Re-audit round: found and fixed 2 real security gaps

**User asked to re-verify sync with openspodes.** Did a deeper pass this
time: compared C test suites (test_errors.c 37 tests, test_core.c 108 tests,
test_gost_crypto.c 16, test_spodus_concentrator.c 8, GBT/general_ciphering
headers) against Rust, not just source files. Found two real, previously
unported security behaviors (both confirmed present in C via
`test_glo_unprotect_replay_ic` and `ctx->hls_failures >= 5` in security.c)
and fixed them:

**Done:**
1. **Replay protection (IC monotonicity)** — `SecurityContext` gained
   `last_peer_ic`/`ic_valid` private fields (init in `for_suite`).
   `unprotect`/`gost_unprotect`/`gost_gmac_unprotect` in
   `src/service/ciphering.rs` now call `check_replay(ic)` before touching
   ciphertext and `accept_peer_ic(ic)` only after successful decrypt. New
   `CipherError::ReplayDetected`. 3 new tests (one per cipher family) proving
   replay/reorder rejection and that acceptance still advances the baseline.
   Verified this doesn't break `ClientSession`: the one call site that
   matters (`session.rs:747`, `&mut c.rx` inside `send`/`get`/`set`/`action`)
   uses a persistent context across the session's lifetime — correct. A
   second call site (`send_raw`, line ~543) uses `c.rx.clone()` and so never
   accumulates replay state — a pre-existing wart, left alone (not a
   regression, just ineffective there; noted for later if `send_raw` gets
   revisited).
2. **IC-overflow guard** — `protect`/`gost_protect`/`gost_gmac_protect`
   reject via `check_send_ic()` when `invocation_counter == u32::MAX`
   (`CipherError::InvocationCounterExhausted`); added advisory
   `SecurityContext::key_rotation_needed()` (IC within 1000 of overflow),
   mirroring C's `osp_sec_key_rotation_needed`. 2 new tests.
3. **HLS failure rate limiting** — `AssociationLn` gained a `hls_failures: u8`
   transient field (`#[serde(skip)]`) and `MAX_HLS_FAILURES = 5` const.
   `reply_to_hls_authentication_checked` (now the sole dispatch target for
   method 1) rejects outright once `hls_failures >= 5`, increments on every
   failure, resets to 0 on success — exactly mirrors C's per-mechanism
   `ctx->hls_failures` bookkeeping. 1 new test (5 wrong attempts, then even
   the correct response is rejected).

Full quality gate green: 347 lib tests (was 341) + 87 across 6 integration
suites, fmt/clippy/doc -D warnings clean.

**Also checked, found already in sync (no action needed):**
- GOST/Streebog/Kuznyechik/VKO/KDF reference vectors (test_gost_crypto.c,
  16 tests) — already ported with byte-for-byte vectors in earlier sessions.
- SPODUS concentrator tests (test_spodus_concentrator.c, 8 tests) — already
  covered by the feature/spodus work (merged at 0.2.0).
- General ciphering / general signing codec — comparable API surface.

**Known, deliberately NOT ported (architecture-level, flagged before, still
true — not touched this round):**
- GBT (General Block Transfer): Rust has the codec (`service/gbt.rs`
  encode/decode) but it is not wired into `session.rs`/`server.rs` — no
  actual general-block-transfer flow uses it. C has transport-level
  streaming helpers (`osp_gbt_transport_send_streaming*`). This is a bigger
  integration task, not a bug — GET/SET already have their own block
  transfer (WithDataBlock) which is wired and tested.
- HDLC inter-octet/inactivity timeouts, XID negotiation, outbound I-frame
  segmentation (needs a deadline/clock abstraction in `PhysicalTransport`).

**State:** branch `main`, uncommitted at entry-write time (commit follows
immediately). All changes are additive/hardening — no breaking API removal,
though `SecurityContext` gained private fields (transparent to callers using
`for_suite`) and `CipherError` gained two new variants (non-exhaustive
matches would need updating — check any external `match CipherError {}` if
this crate gets consumers outside the workspace).

**Next:** GBT wiring and HDLC timeouts remain optional future work — ask
before doing either, they're larger architectural changes. Otherwise ready
for release; likely 0.6.0 given the accumulated public API additions across
today's four rounds (handle_aarq, build_push_delivery_request,
HdlcLayer::connect/disconnect, 6 new IC classes, CipherError variants,
key_rotation_needed).

## 2026-07-22 — GBT wiring + HDLC inter-octet/inactivity timeouts

**Done (both items the user explicitly asked to take up):**

1. **GBT (General Block Transfer) wiring** — was previously codec-only
   (`service/gbt.rs` encode/decode), now fully wired:
   - `gbt::applies_to_apdu`, `gbt::send`, `gbt::receive` (src/service/gbt.rs)
     drive the codec over any `DataLinkLayer`. Confirmed mode: sender waits
     for an ack every `window` blocks, retransmits on a reported gap;
     receiver requests retransmission on out-of-order blocks, acks/discards
     duplicates. **Found and fixed a real ack-cadence bug during testing**:
     initial `receive()` acked every accepted block regardless of window
     size, desyncing from `send()` (which only checks for an ack once per
     window) — caused spurious retransmit storms with window>1. Fixed by
     tracking `blocks_since_ack` and only acking every `window` blocks,
     matching the sender's batching exactly.
   - `ClientSession`/`ClientSessionBuilder` gained `with_gbt`/`enable_gbt`/
     `gbt_window`/`gbt_streaming` (mirrors C's `osp_client_enable_gbt` etc.)
     wired into `transact_once`: request segmented via GBT when it qualifies
     and exceeds the block size (checked on the *plain* pre-cipher tag, so
     ciphering doesn't change whether GBT applies — a deliberate improvement
     over the C reference, which checks the tag post-ciphering and so can
     never actually engage GBT together with ciphering); response
     reassembled via `gbt::receive` when the first byte is the GBT tag.
   - New `impl From<ServiceError> for io::Error` (src/service/mod.rs) so GBT
     codec errors compose with `io::Result` the same way `HdlcError` already
     does.
   - New `tests/gbt_integration.rs`: 3 end-to-end tests over **real OS
     threads + mpsc channels** (client session + a small GBT-aware server
     loop) — unconfirmed large GET, confirmed-window (2) large GET, and a
     small response that stays unsegmented. Note: `RequestDispatcher` is not
     `Send` (holds `Box<dyn InterfaceClass>` without a Send bound), so the
     dispatcher must be *built inside* the spawned server thread, not moved
     in — and the dispatcher's `max_pdu` must be raised (`usize::MAX` in the
     test) so it emits one full response for GBT to segment, instead of
     pre-segmenting via its own WITH-DATABLOCK mechanism first.
   - 11 gbt.rs unit tests (was 3) using a `ScriptedLink` `DataLinkLayer` mock
     that scripts exact ack sequences — covers unconfirmed/confirmed send,
     gap-retransmit, non-ack-reply rejection, single/multi-block receive,
     gap/duplicate handling on receive.

2. **HDLC inter-octet and inactivity timeouts** (src/transport/hdlc.rs,
   src/transport/mod.rs):
   - `PhysicalTransport::set_read_timeout(Option<Duration>) -> io::Result<()>`
     — new trait method, **default no-op body so fully non-breaking** for
     existing implementors (`MemoryTransport`, example `TcpTransport`s).
     Mirrors `TcpStream::set_read_timeout` exactly so a real TCP transport
     can just forward to it.
   - `HdlcLayer` gained `inter_octet_timeout: Duration` (default 25ms,
     `set_inter_octet_timeout_ms` clamps 20..6000) and
     `inactivity_timeout: Option<Duration>` (default `None`/disabled,
     `set_inactivity_timeout_s` clamps 0..120, 0→None) — exact limits from
     IEC 62056-46 / the C reference's `OSP_HDLC_INTER_OCTET_MIN/MAX_MS` and
     `OSP_HDLC_INACTIVITY_MAX_S`.
   - `read_frame` split into flag-search (bounded by inactivity timeout) and
     `read_frame_body` (bounded by inter-octet timeout once the flag is
     found); timeout restored to inactivity before returning either way.
     Both timeout kinds surface as `io::ErrorKind::TimedOut` (already
     classified transient/retryable by `ClientSession`'s `is_transient_io`,
     so no new retry plumbing needed) with a distinguishing message
     ("inactivity" vs "inter-octet"). Only the inactivity timeout sets
     `connected = false` (assume NDM on a silent peer, matching the C
     doc comment "drop to NDM without closing transport"); an inter-octet
     timeout (a single garbled/interrupted frame) does not.
   - 5 new tests incl. a `TimeoutTransport` mock that logs every
     `set_read_timeout` call and can simulate the peer going silent —
     verifies the exact inactivity→inter-octet→inactivity phase sequence,
     the TimedOut+disconnect behavior on inactivity, and the
     TimedOut+no-disconnect behavior on inter-octet silence.
   - **Not wired into an example**: no example in this crate drives
     `HdlcLayer` directly (only `Wrapper`/IEC 62056-47) — adding one was out
     of scope for "add HDLC timeouts" and would be its own task if wanted.

**State:** branch `main`, all quality gates green — 360 lib tests (was 347)
+ 90 across 7 integration suites (gbt_integration.rs is new); fmt/clippy/doc
`-D warnings` clean. Uncommitted at entry-write time (commit follows
immediately).

**This closes both items from the previous session's "deliberately NOT
ported" list.** Per that entry's closing note, the remaining un-ported items
(XID parameter negotiation, outbound I-frame segmentation) were NOT part of
this request and remain open if wanted later — HDLC already does inbound
segmented-I-frame *reassembly* (from the 2026-07-22 round-2 HDLC hardening),
just not outbound segmentation of a single large `send_apdu` call (GBT is
the mechanism this crate offers for large payloads instead).

**Next:** release. Given the accumulated public API growth across all of
today's rounds (handle_aarq, build_push_delivery_request, GBT send/receive +
session integration, PhysicalTransport::set_read_timeout, HdlcLayer
connect/disconnect + timeouts, 6 new IC classes, new CipherError variants,
key_rotation_needed), 0.6.0 is the right next version per semver (still 0.x,
so technically optional, but the surface added is substantial). Not
released yet — awaiting user go-ahead per the `release` skill's normal flow.

## 2026-07-22 — Closed the last two HDLC tails: XID negotiation + outbound segmentation

**User: "outbound I-frame segmentation - тоже надо реализовать. Вообще надо
закрыть все хвосты!!!"** (also asked "Согласование XID при SNRM
реализовано?" first — answer was no; user asked to implement it too). Both
now done.

**Done:**
1. **XID negotiation** (src/transport/hdlc.rs): new `pub struct XidParams
   { max_info_tx, max_info_rx: u16, window_tx, window_rx: u8 }` with
   `encode`/`decode` (wire format `81 80 <grouplen> 05 02 <tx:u16> 06 02
   <rx:u16> 07 04 <tx:u32> 08 04 <rx:u32>`, matching openspodes exactly) and
   `negotiate(&mut self, peer)` (tighten-only, zero-from-peer = no
   opinion). `HdlcLayer` gained `xid_configured`/`xid` fields,
   `set_xid_ceiling()`/`xid()` public API, `client_default()` =
   1280/1280/1/1, `server_default()` = 512/512/1/1. `connect()` sends
   `xid_configured.encode()` in SNRM's info field, negotiates against UA's
   reply. Server's SNRM branch in `receive_apdu` resets `xid =
   xid_configured` then negotiates against the SNRM's info field, answers
   UA via new `send_unnumbered_with_info` (added; `send_unnumbered` now
   delegates to it with empty info). 7 new tests incl. full
   client-sends/server-answers round trips using `MemoryTransport` loopback
   tricks (feed UA first, then read back what SNRM the client actually
   sent from the still-buffered tail).

2. **Outbound I-frame segmentation** (same file): `send_apdu` now chunks
   the LLC-prefixed payload by `self.xid.max_info_tx` (falls back
   sensibly since defaults are always positive), setting
   `frame.segmented = !last` per chunk and consuming one N(S) slot per
   segment; sent back-to-back with no per-segment ack wait (this
   implementation has no true windowed flow control beyond stop-and-wait
   per whole APDU, and a stray RR is harmlessly skipped by the *next*
   `receive_apdu` call's existing `ReceiveReady => continue` branch
   regardless). **Important finding, now in CHANGELOG**: re-checked the C
   reference's own `osp_hdlc_session_send_apdu` and it does NOT segment —
   it only rejects an oversized APDU (`OSP_ERR_NOMEM`). Only the *receive*
   path models the segmentation bit in C. So this is a genuine Rust-side
   addition beyond parity, not a straight port — flagged as such rather
   than silently claiming C parity. 4 new tests, including a true two-party
   proof: send from one independent `HdlcLayer`, feed the raw bytes into a
   *second, separate* `HdlcLayer`, confirm `receive_apdu` reassembles
   correctly — plus a test confirming `send_apdu` uses the *negotiated*
   ceiling (not just the configured default) after `connect()`.

**State:** branch `main`, all quality gates green — 371 lib tests (was 360)
+ 90 across 7 integration suites; fmt/clippy/doc `-D warnings` clean.
Committed after this entry.

**This closes the HDLC "remaining un-ported items" list from the prior
2026-07-22 entries in full: inter-octet/inactivity timeouts (done earlier
today), XID negotiation (done), outbound I-frame segmentation (done).** No
known gaps remain in the HDLC layer relative to either the C reference or
the standard's documented mechanisms, modulo the deliberate non-parity note
above (Rust now does MORE than the C reference here, not less).

**Next:** release. Public API surface added across all of today's five
rounds is now large enough that 0.6.0 is clearly the right next version
(handle_aarq, build_push_delivery_request, GBT send/receive + session
integration, PhysicalTransport::set_read_timeout, HdlcLayer
connect/disconnect/XID/timeouts, XidParams, 6 new IC classes, new
CipherError variants, key_rotation_needed, HLS rate limiting). Still
awaiting user go-ahead to actually cut the release.

## 2026-07-22 — Released v0.6.0

**Done:** Cargo.toml → 0.6.0; CHANGELOG `[Unreleased]` closed into
`## [0.6.0] - 2026-07-22` (folding in the never-separately-tagged 0.5.0
work-in-progress entry too, since crates.io's latest published version was
still 0.4.0 — 0.5.0 was committed to CHANGELOG but never tagged/released).
Fixed the changelog compare links accordingly: `[0.6.0]` compares
`v0.4.0...v0.6.0`, dropped the dead `[0.5.0]` link.

Full quality gate re-run clean at the new version: `cargo build`, `fmt
--check`, `clippy --all-targets -D warnings`, `cargo test` (371 lib + 90
across 7 integration suites), `cargo doc --no-deps -D warnings`, `cargo
package`.

Commit `8805902` "Release v0.6.0" pushed to `main`. Tag `v0.6.0` pushed →
GitHub Actions Release workflow run `29905139631`: both jobs green (GitHub
Release + Publish to crates.io). Confirmed live on crates.io
(`0.6.0` in the versions list, jumping from `0.4.0` — the last actually
published version). CI run on `main` (`29905132764`) also green.

**State:** fully released and clean. `main` at `8805902` = `v0.6.0`, nothing
uncommitted, nothing unpushed.

**Next:** none pending from this work block. docs.rs will rebuild
automatically from the new publish (usually within a few minutes) —
https://docs.rs/spodes-rs/0.6.0/spodes_rs/. If further work resumes, start
fresh from a clean `main`.
