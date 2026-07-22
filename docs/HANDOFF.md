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
