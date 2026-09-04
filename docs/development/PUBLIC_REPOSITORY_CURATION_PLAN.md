# Public Repository Curation Plan

Status: living document for the maintainer. Records the intentional
classification of the tree, the decisions that are still human-owned, and
the exact next steps before public release.

## Source / release / dev / never-publish matrix

| Artifact                                                        | Source (Git) | Release asset | Dev-only | Never publish |
| ---                                                             | ---          | ---           | ---      | ---            |
| Rust crates under `crates/`                                     | yes          | no            | no       | no             |
| Tauri desktop shell under `gui/`                                | yes          | no            | no       | no             |
| Front-end tests under `gui/test/`                               | yes          | no            | no       | no             |
| V2 event template source (`templates/ootle-anchor-event-template-v2/`) | yes | no       | no       | no             |
| Guide PNGs under `gui/src/assets/guide/`                        | yes          | no            | no       | no             |
| App icons under `gui/src-tauri/icons/`                          | yes (after brand review) | no | no       | no             |
| Public test vectors under `test-vectors/`                       | yes          | no            | no       | no             |
| Vendored `third_party/tari-triptych/` + its BSD-3-Clause LICENSE| yes          | no            | no       | no             |
| Public docs under `docs/` (curated)                             | yes          | no            | no       | no             |
| Load-test docs under `docs/development/load-testing/`           | yes          | no            | yes      | no             |
| Load-test harness `tools/load-test/RUN_SCALE_QUALIFICATION.ps1` | yes          | no            | yes      | no             |
| Load-test Rust harness (`crates/gui-core/tests/release_scale_qualification.rs`, `release_qualification_50_voters.rs`) | yes | no | yes | no |
| Historical review/audit/performance docs under `docs/development/` | yes       | no            | yes      | no             |
| Windows `.exe` / `.msi` / `.wasm`                               | no           | yes           | no       | no             |
| Compiled V2 event-template WASM                                 | no           | optional, with hashes | no  | no             |
| walletd binary                                                  | no           | no (Option A — see WALLETD_DISTRIBUTION_RECOMMENDATION.md) | no | never with wallet state |
| Preserved 500-voter archive                                     | no           | no            | no       | yes            |
| LocalAppData V2 anchor evidence sidecar / any real run's sidecar| no           | no            | no       | yes            |
| Real voter credential, wallet DB, wallet API key, Tor onion key, private transport-authority key | no | no | no | yes |
| Generated `target/`, `gui/dist/`, `gui/node_modules/`, `gui/src-tauri/target/`, `gui/src-tauri/gen/`, `templates/*/target/`, `scale-qualification-results/` | no | no | no (local) | no |

## What was moved in the current curation pass

- `AUDIT_*` and `TRANSPORT_BINDING_RELEASE_FIX_REPORT.md` → `docs/development/audits/`.
- `PERFORMANCE_REMEDIATION_*` and `PRODUCTION_RELEASE_CRYPTO_PERFORMANCE*` → `docs/development/performance/`.
- `RELEASE_QUALIFICATION_50_VOTERS.md` and `SCALE_QUALIFICATION_HARNESS.md` → `docs/development/load-testing/`.
- `RUN_SCALE_QUALIFICATION.ps1` → `tools/load-test/` (harness updated to resolve repo root two levels up).
- `HANDOFF_*`, `SLICE4D_OPUS_IMPLEMENTATION_PLAN.md`,
  `CONTROLLED_ALPHA_GIT_STATUS_20260831.txt`, and the temporary curation
  handoff/report files were removed after classification as scratch/status
  artifacts with no unique source or test material.

## Human decisions still required

1. **Project license.** No `LICENSE` file exists. Options that are compatible
   with the current dependency graph and would signal the same posture the
   README and SECURITY docs already imply:
   - MIT
   - Apache-2.0
   - MIT OR Apache-2.0 (permissive dual-license — matches the common Rust
     ecosystem convention and the license already used by many direct
     dependencies).
   Do NOT create `LICENSE` until the maintainer explicitly chooses.
2. **Brand / trademark.** RESOLVED (2026-09-03): the public product name is
   **Private Ballot** and the status label is **Independent Open-Source
   Project**; "Tari" has been removed from the current public product
   identity. Icon/brand-mark items and the frozen protocol identifiers are
   captured in `docs/release/BRAND_TRADEMARK_REVIEW.md`.
3. **walletd distribution.** Confirm Option A (user installs walletd
   separately) for the initial public source. See
   `docs/development/WALLETD_DISTRIBUTION_RECOMMENDATION.md`.
4. **Third-party attribution.** Run a real `cargo license`-style report and
   an npm `license-checker`-style report and attach both to
   `THIRD_PARTY_NOTICES.md` before public release.
5. **Git history secret audit conclusion.** The working tree is clean of
   secret-shaped content (see this pass's report). The Git history has not
   been proven clean end-to-end; a targeted commit-level audit is a
   publication gate.
6. **Linux / macOS builds.** Windows is currently the only qualified build
   target. Cross-platform builds are a follow-on phase.

## Next exact phase (after this pass)

1. Maintainer chooses the project license and adds `LICENSE`.
2. Run the transitive `cargo license` and npm `license-checker` reports and
   fold them into `THIRD_PARTY_NOTICES.md`.
3. Run the targeted Git history secret audit (see report) and record its
   conclusion.
4. Cross-platform Linux/macOS builds.
5. First public GitHub push and Release with signed Windows binaries.
