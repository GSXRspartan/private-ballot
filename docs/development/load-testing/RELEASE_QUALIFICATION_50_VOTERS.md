# Release qualification: 50 voters

Status: **PASS** for the corrected archive/anchor workflow (backend, current
format). The prior `GUI_FINAL_ARCHIVE_VERIFY_FAILED` blocker is resolved by a
minimum-safe, fail-closed production fix; no verification, transport, anchor,
integrity, path, or Tor gate was weakened. Full root-cause detail:
[`TRANSPORT_BINDING_RELEASE_FIX_REPORT.md`](TRANSPORT_BINDING_RELEASE_FIX_REPORT.md).

The preserved forensic directory `C:\50 voter anchor\try 3` was **not** touched.

## 50-voter release gate

| gate | result |
|---|---|
| performance / responsiveness | **PASS** |
| archive write (transport-bound) | **PASS** |
| transport-bound independent archive verification | **PASS** |
| anchor preparation (non-network) | **PASS** |
| security fail-closed cases | **PASS** |
| **overall 50-voter release qualification** | **PASS** |

### Requalification evidence (corrected code, MSVC/vcpkg, `--release`)

`release_qualification_50_voters` — 1 passed, through the SAME writer/verifier/
anchor functions the Tauri commands call:

- election creation 11.1 ms; proof generation 1.557 s (44 real proofs)
- intake median 5.925 ms; p95 7.161 ms; max 8.149 ms
- cold resume 65.9 ms; warm resume 6.9 ms (0 historical Triptych, cache hit)
- post-mutation resume: 0 replay, 0 Triptych
- private intake: index hits 47, linear scans 0
- tally 42 µs; accepted 47
- **archive write (bound) 231.6 ms**
- **archive first verify 324.1 ms** → `verified`, `finalized`,
  `transport_binding_present`, `transport_binding_verified`; 1 replay, 49
  Triptych verifies
- **archive memo verify 13.8 ms** → 0 Triptych verifies
- **anchor preparation** → accepted_ballot_count 47 (non-network)
- workspace bytes 53 841

Supporting suites (all green): shell-crate lib 31 (incl. 4 new fail-closed
tests); shell `cargo check --features managed-tor-test` clean; archive lib 47;
gui-core `archive_verify` 12, `live_anchor_publish` 8, `live_driver_archive` 4;
frontend `tsc` clean.

## What was fixed

Standard Release (`default = []`) has no transport-binding provenance: the
production transport authority is `ProductionNotProvisioned` and the only binding
source (organizer Tor intake, self-generated `test-root` authority) is behind the
`managed-tor-test` controlled-test feature — and even there the binding is
ephemeral. The old GUI wrote a valid-but-unbound archive and mislabeled it as an
`ARCHIVE_INTEGRITY` failure.

Fix (additive, fail-closed): `write_finalized_archive` now takes an explicit
`require_transport_binding` flag and refuses **before writing** with
`GUI_TRANSPORT_ARCHIVE_BINDING_REQUIRED` (category `UNAVAILABLE`, not
`ARCHIVE_INTEGRITY`) when an anchor-eligible archive is required but no
authoritative binding exists. A new `anchor_deployment_capabilities` command lets
the organizer screen explain readiness instead of offering a doomed action. The
backend anchor gates were already fail-closed and were left untouched.

## Legacy 381-package election

The existing finalized Release-GUI election (381 stored / 50 accepted / 331
rejected; ~3 s resume, no freeze) **cannot** be made transport-bound: its
transport-batch history was never persisted (the intake gateway is rebuilt empty
each start), so a binding could only be produced by inventing historical
evidence, which is prohibited. It remains valid for offline verification;
live-anchor qualification requires a fresh current-format election produced while
a bound intake worker stays live through archive-write.

## Next scale stage

The generic scale harness is READY — see
[`SCALE_QUALIFICATION_HARNESS.md`](SCALE_QUALIFICATION_HARNESS.md). Validated at
100 voters through `tools/load-test/RUN_SCALE_QUALIFICATION.ps1` (PASS). Remaining scales
(500 / 1000 / 2048 / 4096) are user-run:

```powershell
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 500
```
