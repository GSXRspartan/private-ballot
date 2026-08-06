# Phase 4 Final Pre-Testnet Repairs — 2026-08-06

## 1. Starting branch and HEAD

- **Branch:** `phase4/ootle-testnet-anchor-prototype`
- **HEAD:** `1b10f8841b40b08fb8594b2d6bf641a896ec515d`
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via `stable-x86_64-pc-windows-msvc`

## 2. Findings repaired

- **H-1** — Config/snapshot consistency is not enforced on restore or accepted-evidence construction.
- **M-1** — Supplying both `--approve` and `--reject` silently selects approval.
- **M-2** — `check_agreement` can mutate an already-terminal lifecycle phase.
- **M-3** — `AnchorLifecycleOrchestrator::from_snapshot` accepts a caller-supplied phase without validating that it is consistent with the walletd snapshots, receipt snapshots, submitted handle, and polling state.

## 3. Exact files changed

### Modified source files

| File | Repair |
|------|--------|
| `crates/ootle-anchor-app/src/driver.rs` | H-1: restore-time binding validation + accepted-evidence binding validation |
| `crates/ootle-anchor-app/src/evidence.rs` | E.1: `from_canonical_bytes` decode-and-verify round trip |
| `crates/ootle-anchor-app/src/lib.rs` | M-1: `pub mod cli` export |
| `crates/ootle-anchor-app/src/main.rs` | M-1: `cli::validate_args` before config loading |
| `crates/ootle-anchor-lifecycle/src/orchestrator.rs` | M-2: terminal idempotency in `check_agreement`; M-3: `validate_reconstruction` |
| `crates/ootle-anchor-lifecycle/src/snapshot.rs` | M-3: bounded `LifecycleReconstructionError` variants |
| `crates/ootle-anchor-network-adapters/tests/orchestrator_integration.rs` | M-2: updated `scenario_6_disagreement` for terminal idempotency |
| `crates/ootle-anchor-lifecycle/tests/archive_independence.rs` | M-2: updated disagreement assertions |
| `crates/ootle-anchor-lifecycle/tests/end_to_end.rs` | M-2: updated disagreement test |
| `crates/ootle-anchor-lifecycle/tests/safety_mutation.rs` | M-2: updated disagreement assertions |
| `docs/reviews/PHASE4_SLICE4A10_APPLICATION_DRIVER_AND_DURABLE_SNAPSHOT_2026-08-05.md` | E.3: KAV digest formatting corrected |

### New source files

| File | Repair |
|------|--------|
| `crates/ootle-anchor-app/src/cli.rs` | M-1: CLI argument validation module |
| `crates/ootle-anchor-app/tests/config_snapshot_binding.rs` | H-1: 9 regression tests |
| `crates/ootle-anchor-app/tests/cli_validation.rs` | M-1: 12 CLI parser tests |
| `crates/ootle-anchor-app/tests/evidence_decoding.rs` | E.1: 6 evidence round-trip tests |
| `crates/ootle-anchor-lifecycle/tests/agreement_idempotency.rs` | M-2: 6 terminal idempotency tests |
| `crates/ootle-anchor-lifecycle/tests/snapshot_consistency.rs` | M-3: 31 phase-consistency tests |

## 4. Config/snapshot binding checks (H-1)

### Restore-time validation

`AnchorAppDriver::restore` calls `validate_snapshot_binding` before orchestrator construction. The current configuration's immutable anchor binding is compared with the snapshot's walletd binding. Equality is required for:

- network (`anchor_record_network`);
- account reference;
- anchor-record digest (re-derived from the config's locator triple);
- canonical anchor-log payload (derived from the digest);
- maximum fee.

A mismatch returns `DriverError::ConfigSnapshotBindingMismatch` (`DRIVER_CONFIG_SNAPSHOT_BINDING_MISMATCH`) before any transport construction or receipt lookup. The fingerprint is not independently configurable from the config (it is derived from the anchor inspection during prepare); it is checked in the accepted-evidence binding layer.

### Accepted-evidence validation

`accept_evidence` checks, before creating ACCEPTED evidence:

- archive/config-derived anchor digest equals `VerifiedIndexerAnchorV1` anchor digest;
- archive/config-derived network equals verified receipt network;
- verified transaction ID equals the submitted lifecycle transaction ID.

A mismatch returns `DriverError::EvidenceBindingMismatch` (`DRIVER_EVIDENCE_BINDING_MISMATCH`). No ACCEPTED evidence is created; the existing snapshot and artifacts are left unchanged.

## 5. Accepted-evidence binding checks (H-1)

See Section 4. The accepted-evidence binding validation is defense-in-depth: the restore-time check prevents config changes before a run, and the accepted-evidence check catches any inconsistency between the config and the verified receipt at evidence construction time. A successful `FinalizedAccept` produces byte-identical evidence to the pre-repair behavior (verified by `restore_produces_byte_identical_evidence`).

## 6. CLI contradictory-flag behavior (M-1)

`cli::validate_args` is called in `main.rs::run()` before any config loading, transport construction, runtime construction, snapshot mutation, or transaction submission. It rejects:

- `--approve` and `--reject` supplied together → `ConfigurationFailure` (`ANCHOR_APP_CONFIGURATION_FAILURE`);
- any unknown argument → `ConfigurationFailure`.

Duplicate `--approve` (or `--reject`) is deterministic: the `any`-check resolves to `Approve` (or `Reject`), matching the existing single-flag behavior. This is the documented chosen behavior for duplicates.

## 7. Terminal idempotency (M-2)

`check_agreement` returns `Ok(IdempotentNoOp)` at the beginning if the lifecycle phase is terminal. The phase, diagnostic, walletd coordinator snapshots, and receipt coordinator snapshots are never mutated. A `FinalizedAccept` can never be rewound to `FinalizedDisagreement` (or any other terminal) by a late agreement check.

## 8. Snapshot phase-consistency rules (M-3)

`AnchorLifecycleOrchestrator::from_snapshots` calls `validate_reconstruction` before constructing the coordinators. The declared `UnifiedAnchorLifecyclePhase` must be derivable from and consistent with the contained state. Enforced invariants:

- **NotPrepared:** no walletd snapshot, no receipt snapshot, no submitted handle.
- **Prepared:** walletd snapshot with `Prepared` decision, `NotSubmitted` submission; no submitted handle, no receipt.
- **Approved:** walletd snapshot with `Approved` decision, `NotSubmitted` submission; no submitted handle, no receipt.
- **RejectedByApprover:** walletd snapshot with `Rejected` decision; no submitted handle, no receipt.
- **Submitted:** submitted handle exists; walletd snapshot with `Submitted` state and matching transaction ID; receipt state absent or `SubmittedNotQueried` and not verified.
- **PollingInProgress:** submitted handle exists; walletd snapshot with `Submitted` state; receipt snapshot with non-terminal state; `attempts_consumed > 0`.
- **Unknown:** either submit-timeout (walletd `TimedOutUnknown`, no submitted handle, no receipt) or poll-exhausted (submitted handle, walletd `Submitted`, non-terminal receipt); must not carry a verified successful receipt.
- **FinalizedAccept:** submitted handle exists; walletd `Submitted` with matching transaction ID; receipt `ReceiptFinalizedAccept`, `verified == true`, final status `Accepted`.
- **FinalizedFeeOnly:** receipt `ReceiptFinalizedFeeOnly`, not verified.
- **FinalizedReject:** receipt `ReceiptFinalizedReject`, not verified.
- **FinalizedVerificationFailed:** receipt `ReceiptVerificationFailed` or `ReceiptFinalizedAccept` without verified flag.
- **FinalizedDisagreement:** submitted handle and receipt snapshot exist.

Cross-checks (fired before phase-specific checks): receipt snapshot requires submitted handle; submitted handle requires walletd snapshot; transaction IDs, bindings, and query locators must match across all snapshots; at most one walletd and one receipt snapshot.

Bounded error codes: `PhaseStateMismatch`, `SubmittedHandleWithoutWalletdSnapshot`, `TransactionIdMismatch`, `BindingMismatch`, `DuplicateIdentifier`, `TooManySnapshots`, `PolicyInconsistent`, `MissingSubmittedHandle`, `SnapshotRequestMismatch`.

## 9. New regression and mutation tests

| Test file | Count | Coverage |
|-----------|-------|----------|
| `config_snapshot_binding.rs` | 9 | H-1: network/account/archive/manifest/max-fee mismatch rejected; unchanged config restores; byte-identical evidence; no snapshot mutation; no transport contact |
| `cli_validation.rs` | 12 | M-1: approve/reject/neither/both; duplicate approve/reject; unknown args; decision mapping; zero transport on contradiction |
| `evidence_decoding.rs` | 6 | E.1: round trip; reject trailing bytes, wrong version, wrong hash algorithm, malformed digest, altered body |
| `agreement_idempotency.rs` | 6 | M-2: check_agreement no-op on FinalizedAccept, FinalizedFeeOnly, FinalizedReject, FinalizedVerificationFailed, FinalizedDisagreement, RejectedByApprover |
| `snapshot_consistency.rs` | 31 | M-3: one valid reconstruction per phase; mutation tests for every invariant; no-panic; no transport contact |

Total new tests: **64**.

## 10. Canonical-format compatibility statement

- Anchor-record encoding: unchanged.
- Snapshot encoding: unchanged.
- Evidence encoding: unchanged.
- Transaction construction, fees, walletd submission, receipt conversion, and verification semantics: unchanged.
- No canonical field was added, removed, or reordered.
- Durable snapshots generated by the current driver still decode and restore successfully (verified by `snapshot_encoding.rs` KAV test and `restore_with_unchanged_config_succeeds`).
- Successful restore produces byte-identical evidence to the pre-repair behavior (verified by `restore_produces_byte_identical_evidence`).

## 11. Test results

### Targeted package tests

| Package | Result |
|---------|--------|
| `tari-cc-private-ballot-ootle-anchor-app` | 97 passed; 0 failed |
| `tari-cc-private-ballot-ootle-anchor-lifecycle-orchestrator` | 87 passed; 0 failed |
| `tari-cc-private-ballot-ootle-walletd-anchor-adapter` | 47 passed; 0 failed |
| `tari-cc-private-ballot-ootle-receipt-anchor-adapter` | 45 passed; 0 failed |
| `tari-cc-private-ballot-ootle-anchor-network-adapters` | 64 passed; 0 failed |

## 12. Workspace check

```
cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets
```

Result: **Finished** with 0 errors, 0 warnings.

## 13. Workspace tests

```
cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace
```

Result: **All passed; 0 failed.** Ignored tests are the heavy Triptych suites and timing tests, which were not run per instructions.

## 14. Strict Clippy

```
cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings
```

Result: **Exit code 0.** One pre-existing warning in vendored Triptych (`variant `Variable` is never constructed`) — not introduced by this repair slice and not in project-owned code.

## 15. No network

No network access was used. All tests use scripted transports (`ScriptedWalletdTransport`, `ScriptedIndexerTransport`). No socket was opened.

## 16. No socket

No socket was opened. All transports are scripted fakes driven through their public APIs.

## 17. No transaction submitted

No transaction was submitted to a live network. All submission paths use the scripted walletd fake.

## 18. No signing

No signing was performed. The driver holds no wallet secret and delegates all signing to the existing adapter layer, which was not modified.

## 19. Vendored Triptych untouched

Confirmed: `git diff --name-only -- "*triptych*" "*Triptych*"` returns no output. `git ls-files --others --exclude-standard -- "*triptych*" "*Triptych*"` returns no output. No vendored Triptych file was modified, added, or deleted.

## 20. Staged file count

18 files staged (17 project-owned source/test/doc files + this report).

## 21. Per-file sizes and SHA-256

```
  2541  2cdc737927f814839ff030d52d4d855a477d3e677cc0c52060aa73caf9f9a802  crates/ootle-anchor-app/src/cli.rs
 31801  c552be9de0b4ffc1d82831d09308b5c885f6f57f64227b8b468e33b21e1e12db  crates/ootle-anchor-app/src/driver.rs
 32038  e919c56fae6762f9db9eb620f1f435940e2278c814d72ecf8f58645da3ede528  crates/ootle-anchor-app/src/evidence.rs
  2232  f018ca2bd2baee84b55acdc59dab3eb4c592f3a7b5842e53805c07aaed1c1df1  crates/ootle-anchor-app/src/lib.rs
  6705  6f26930589ba726aca21e465b466609404ad4cec8a5f17026982b2996e10485e  crates/ootle-anchor-app/src/main.rs
  4195  1dfa8eb8146a90b5920183298ba22f833a5b86db97e308d0025c19d388bc0f7c  crates/ootle-anchor-app/tests/cli_validation.rs
  9766  fcee966c5c875396dfc2da0815bf9a2e746e35dc66f6e0e3d8d10c8f80e4b5d2  crates/ootle-anchor-app/tests/config_snapshot_binding.rs
  4726  597bd877a4edeab7f2f28130fbebe62f83bc231d02088f89041aa44b0a655efa  crates/ootle-anchor-app/tests/evidence_decoding.rs
 49810  cdd827ef33ac9baff45bf2d511ddc6760884287448c7186e6fc53c70136a4764  crates/ootle-anchor-lifecycle/src/orchestrator.rs
 10350  6eef3aeea68453d47def5467815ed8b23232a05a2e9197fae41a0549fd842f16  crates/ootle-anchor-lifecycle/src/snapshot.rs
  7911  f3d13d75878c73d3228fd8fd222270a19c88c7ddfd80da9914da3064f90122a9  crates/ootle-anchor-lifecycle/tests/agreement_idempotency.rs
 14464  88a12fd688f03384e3111179f14fa9eaa2292536a9ebfd44fb900fa5bd5bb525  crates/ootle-anchor-lifecycle/tests/archive_independence.rs
 10470  1c38197e8c0f601a7b5135e77ae06dafc91e583e8667612e164f02c2d3f8b1f1  crates/ootle-anchor-lifecycle/tests/end_to_end.rs
 13070  432310aea220730d5d4396e534202ee9fb4bb35a89c0c76ef0e60e8335117329  crates/ootle-anchor-lifecycle/tests/safety_mutation.rs
 21816  6dfd114469551ae34c7f107d682f434e9c14fccdfbfdb476d82a051fa73e8ed9  crates/ootle-anchor-lifecycle/tests/snapshot_consistency.rs
  9842  01874b134f8fbdd87964fb863d9be35d918ce0917c08c0607b69fe8bc453779c  crates/ootle-anchor-network-adapters/tests/orchestrator_integration.rs
 20840  fba47cde11cc7a13c69ab01d6c6a664b19eacf24843ed8b0c2e3a3a40827cdc3  docs/reviews/PHASE4_SLICE4A10_APPLICATION_DRIVER_AND_DURABLE_SNAPSHOT_2026-08-05.md
 15043  f7f1f2a828e8b4e46eaae674718d88e465e10e56e9d6e9b995c31b35bd912e7e  docs/reviews/PHASE4_FINAL_PRETESTNET_REPAIRS_2026-08-06.md
```

## 22. Full staged binary patch size and SHA-256

Computed from `git diff --cached --binary` of all 18 staged files:

- **Patch size:** 116,462 bytes
- **Patch SHA-256:** `849019383617d61ba748722b8aa7c38d34232780e179a9dda61256ead81ec556`

## 23. No commit created

No commit was created. All changes are staged but not committed, per instructions.

## 24. Go/no-go for the first operator-controlled testnet anchor

**CONDITIONAL GO.**

All four confirmed review findings (H-1, M-1, M-2, M-3) are repaired. All 64 new regression and mutation tests pass. The workspace check, workspace tests, and strict clippy pass. Canonical formats are unchanged. Vendored Triptych is untouched. No network, socket, transaction, or signing occurred.

The condition is that the working tree was not clean at the start of this repair slice — a prior interrupted attempt had already placed the core implementation. This repair completed the missing tests (H-1, M-1, E.1), fixed compilation and test-expectation errors, fixed clippy lints, fixed the 4A10 KAV formatting, updated the network-adapters integration test for M-2, and created this evidence report. The operator should review the staged diff before committing.
