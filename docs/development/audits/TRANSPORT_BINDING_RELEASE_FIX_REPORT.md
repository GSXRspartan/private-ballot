# Transport-binding Release fix — root cause, classification, and minimum safe fix

Status: **Phase 1 (source proof) · Phase 2 (fix) · Phase 3 (tests) COMPLETE.**
No archive, verifier, anchor-eligibility, transport, path-security, or Tor
integrity gate was weakened. The preserved forensic directory
`C:\50 voter anchor\try 3` was **not** touched.

---

## 1. Root cause (source-proven)

The finalized-archive → live-anchor workflow requires a verified
`transport/archive-binding-v1.cbor` in the archive. A standard Release GUI build
cannot produce one, for three independent, source-proven reasons:

1. **No production transport authority exists.**
   [`production_transport_authority_root_v1()`](crates/gui-core/src/transport.rs:199)
   returns `TransportAuthorityRootV1::ProductionNotProvisioned { .. }` — an
   explicit fail-closed placeholder. The voter coordinator's production
   constructor
   ([`PrivateSubmissionCoordinatorV1::production_unprovisioned`](crates/transport-gateway/src/lib.rs:112))
   installs exactly that root, so no production build has a usable transport
   authority.

2. **The only working binding source is a controlled-test harness.**
   The organizer in-process Tor intake — the sole code that produces a
   `TransportArchiveBindingV1` from real accepted-transport history — is compiled
   only under `#[cfg(feature = "managed-tor-test")]`
   ([`gui/src-tauri/src/lib.rs:83`](gui/src-tauri/src/lib.rs:83),
   module [`organizer_tor_intake.rs`](gui/src-tauri/src/organizer_tor_intake.rs)).
   Its provisioning self-generates an ed25519 authority via
   [`generate_test_authority_material_v1("test-root")`](gui/src-tauri/src/organizer_tor_intake.rs:853).
   In the default build (`gui/src-tauri/Cargo.toml` `default = []`),
   [`finalized_transport_binding_for_active_intake`](gui/src-tauri/src/lib.rs:2144)
   compiles to `Ok(None)`.

3. **The binding is ephemeral even under the feature.**
   Each intake start builds a fresh, empty gateway
   ([`TransportGatewaySimulatorV1::default()`](gui/src-tauri/src/organizer_tor_intake.rs:1068))
   with no durable persistence path. The transport-batch history that
   [`transport_archive_binding`](crates/transport-gateway/src/lib.rs:1051) seals
   lives only in the running collector worker's memory. After an election is
   finalized and the app is restarted, that history is gone; a later
   archive-write (even under the feature) finds `organizer_intake == None` and
   writes an **unbound** archive.

### Why the historical failure looked like corruption

In the default build, [`write_finalized_archive`](gui/src-tauri/src/lib.rs:2126)
silently selected the unbound writer. The frontend then re-verified the archive,
found no binding, and reported
`GUI_FINAL_ARCHIVE_VERIFY_FAILED / ARCHIVE_INTEGRITY / archive-directory`
([`ManageElection.tsx`](gui/src/screens/ManageElection.tsx)). The archive was
actually valid — it simply was not, and could not be, transport-bound. The
`ARCHIVE_INTEGRITY` label conflated "archive is corrupt" with "archive is valid
but not anchor-eligible in this build."

## 2. Classification

- **B — Feature coupling** (primary): the production-shaped GUI exposes a
  finalized-archive/anchor workflow whose only binding provenance is behind a
  test feature.
- **D — Product workflow** (primary): the archive button succeeds writing an
  unbound archive that cannot satisfy its own required anchor verification, and
  reports the shortfall as an integrity failure.
- **C — Legacy limitation** (the specific 381-package election): its transport
  history was ephemeral and is unrecoverable; it cannot be retro-bound without
  inventing historical evidence.
- **Not A**: enabling `managed-tor-test` in Release is **not** a safe fix — it
  ships a self-generated `test-root` authority and the entire controlled-test
  intake/provisioning harness. The absolute no-ship-test-behavior rule forbids
  it.

## 3. Minimum safe production fix (implemented)

The backend anchor gates were already fail-closed and were left untouched:
[`write_live_anchor_config_from_verification_v1`](crates/gui-core/src/live_anchor_config.rs:189)
and [`verify_transport_archive_anchor`](crates/gui-core/src/transport_anchor.rs:76)
already refuse any archive lacking a verified transport binding. The defect was
that the write path produced a misleading artifact and the UI mislabeled the
result. The fix, all additive:

1. **Fail closed before writing** — [`write_finalized_archive`](gui/src-tauri/src/lib.rs:2126)
   now takes an explicit `require_transport_binding: bool` and, via the pure
   [`require_finalized_transport_binding`](gui/src-tauri/src/lib.rs) helper,
   returns `GUI_TRANSPORT_ARCHIVE_BINDING_REQUIRED` (category `UNAVAILABLE`, **not**
   `ARCHIVE_INTEGRITY`) **before any file is created** when an anchor-eligible
   archive is required but no authoritative binding is available. No archive is
   written; the existing election record is unchanged. The binding is never
   fabricated.

2. **Build-capability signal** — new read-only command
   `anchor_deployment_capabilities` returns
   `transport_binding_provenance_available = cfg!(feature = "managed-tor-test")`.
   The organizer screen reads it once and, when false, shows a plain readiness
   notice explaining that this build cannot produce an anchor-eligible archive
   and that live anchoring is unavailable — instead of offering a doomed action.

3. **Honest frontend** — `onWriteArchive` passes `requireTransportBinding = true`
   (this GUI's finalized archive is the anchor-eligible published record). The
   backend now refuses up front, so the misleading post-write `ARCHIVE_INTEGRITY`
   path is no longer reached for the no-binding case. The genuine-integrity
   branch (`!verified || !finalized`) is retained as defense-in-depth.

### Legacy 381-package election

It **cannot** be made transport-bound. Its transport-batch history was never
persisted (reason 3 above), so a binding can only be produced by inventing
historical evidence, which is prohibited. Live-anchor qualification therefore
requires a **fresh current-format election** produced while a bound intake
worker is continuously live through archive-write. The existing finalized record
remains fully valid for offline verification.

## 4. Tests (added / run)

New shell-crate unit tests (default Release features), all passing:

- `finalized_archive_binding_required_fails_closed_without_binding` — refuses
  with `GUI_TRANSPORT_ARCHIVE_BINDING_REQUIRED`, category `UNAVAILABLE` (never
  `ARCHIVE_INTEGRITY`).
- `finalized_archive_binding_present_is_written` — present binding proceeds; an
  unbound archive is written only when the caller explicitly does not require
  anchor eligibility.
- `transport_binding_provenance_absent_in_standard_release` — provenance is
  absent unless `managed-tor-test`.
- `finalized_archive_command_requires_binding_flag_and_registration` — the
  fail-closed gate runs *before* any archive writer, the command takes the
  explicit flag, and the capability command is registered.

Suites run green under the MSVC/vcpkg toolchain:

| suite | result |
|---|---|
| shell crate lib unit tests (default features) | 31 passed |
| shell crate `cargo check --features managed-tor-test` | clean |
| archive crate lib (transport binding fail-closed) | 47 passed |
| gui-core `archive_verify` | 12 passed |
| gui-core `live_anchor_publish` | 8 passed |
| gui-core `live_driver_archive` | 4 passed |
| frontend `tsc --noEmit` | clean |
| frontend `node --test` | 706/711 (5 pre-existing migration drift; none from this change) |

The 5 frontend failures pre-date this change (first unexpected surface is
`api.walletdReadiness(`, added by the Ootle/Tor migration; the acknowledgement
row-count and ExternalWalletd-default asserts describe pre-migration UI). This
change added its one new surface (`api.anchorDeploymentCapabilities`) to the
guard allowlist.

## 5. Known unrelated blockers (migration-owned; not fixed here)

- `crates/gui-core/tests/archive_writer.rs` (~L910) — `&str`/`String` mismatch;
  blocks building all gui-core test targets at once (run per-`--test`).
- `crates/ootle-anchor-app/tests/publish_security.rs:308` — E0609
  `phase_is_terminal_success`; blocks only that target.
- 5 frontend guard tests drifted during the migration (see §4).
