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
