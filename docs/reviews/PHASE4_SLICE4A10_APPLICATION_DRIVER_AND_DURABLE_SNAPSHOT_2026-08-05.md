# Phase 4 Slice 4A10 — Application Driver, Durable Snapshot, and Anchor Evidence

Date: 2026-08-05
Mode: Implement, validate, and stage. No commit created. No network contact. No transaction submitted. No signing performed.

## 1. Repository preconditions

- Branch: `phase4/ootle-testnet-anchor-prototype`
- Starting HEAD: `bc357c326b74884b8cad0651e74f39705e88e55c`
- Working tree: clean before work (`git status --porcelain` empty)
- Rust toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` via `+stable-x86_64-pc-windows-msvc`
- No rebase, fast-forward, amend, branch switch, or commit performed. HEAD unchanged.

## 2. Files changed

- `Cargo.toml` — added `crates/ootle-anchor-app` as a workspace member.
- `Cargo.lock` — added the `tari-cc-private-ballot-ootle-anchor-app` package entry (no existing version drift; Tokio resolved to the already-present 1.53.1).
- `crates/ootle-walletd-anchor-adapter/src/results.rs` — widened `SubmittedWalletdAnchorRequestV1::new` from `pub(crate)` to `pub` with a documentation note (the only existing Phase 4 source change outside the new crate).
- `crates/ootle-anchor-app/**` — new crate (library + binary + 6 integration test files).
- `docs/reviews/PHASE4_SLICE4A10_APPLICATION_DRIVER_AND_DURABLE_SNAPSHOT_2026-08-05.md` — this report (staged last).

## 3. Reused components

Every coordinator, adapter, orchestrator, and encoder is reused verbatim. No logic is duplicated.

- `AnchorLifecycleOrchestrator` (`crates/ootle-anchor-lifecycle/src/orchestrator.rs:120`) — `prepare_fee_bearing`, `approve`, `reject`, `submit`, `recover`, `advance_one_poll`, `from_snapshot`, `snapshot`, `phase`, `submitted`, `query`.
- `WalletdAnchorCoordinator` (`crates/ootle-walletd-anchor-adapter/src/coordinator.rs:160`) via the orchestrator.
- `AnchorReceiptCoordinator` (`crates/ootle-receipt-anchor-adapter/src/retrieve.rs:249`) — used by the driver to re-query the verified indexer anchor after `FinalizedAccept` (the orchestrator's `advance_one_poll` drops the report it builds; `receipt_coordinator()` exposes only `&`, so the driver builds a fresh coordinator for the re-query, which is a pure transform of frozen commitments).
- `NetworkAdapterConfig` (`crates/ootle-anchor-network-adapters/src/config.rs:56`) — network, endpoint, fee, and receipt-query validation.
- `RealWalletdTransport` / `RealIndexerTransport` (`crates/ootle-anchor-network-adapters/src/{walletd,indexer}.rs`) — the Slice 4A9 real transports, driven by `TokioBlockingExecutor`.
- `ScriptedWalletdTransport` / `ScriptedIndexerTransport` — reused for offline tests.
- `CanonicalCborWriter` / `CanonicalCborReader` (`crates/protocol/src/cbor.rs`) — the only CBOR encoder/decoder.
- `Blake3HashProviderV1` (`crates/protocol/src/hashing.rs:50`) — the only hash provider.
- `OotleAnchorRecordV1::canonical_hash` (`crates/anchor/src/digest.rs:76`) — anchor-record digest re-derivation.
- `AnchorLogPayloadV1::from_digest` (`crates/anchor-transport/src/payload.rs:69`) — payload construction.
- `AnchorReceiptQueryV1::from_submitted` (`crates/ootle-receipt-anchor-adapter/src/query.rs:44`) — receipt query derivation.
- `WalletdAnchorBindingV1::new` (`crates/ootle-walletd-anchor-adapter/src/binding.rs:32`) — binding reconstruction (already `pub`).
- `WalletdAnchorSnapshotV1::new` (`crates/ootle-walletd-anchor-adapter/src/registry.rs:108`) — walletd snapshot reconstruction (already `pub`).
- `AnchorReceiptQuerySnapshotV1::new` (`crates/ootle-receipt-anchor-adapter/src/state.rs:111`) — receipt snapshot reconstruction (already `pub`).
- `SubmittedWalletdAnchorRequestV1::new` (`crates/ootle-walletd-anchor-adapter/src/results.rs:255`) — submitted handle reconstruction (widened from `pub(crate)` to `pub` in this slice).
- `receipt_scenarios` (`crates/ootle-receipt-anchor-adapter/src/scenarios.rs`) — deterministic receipt builders for tests.

## 4. Tokio executor and runtime ownership

`TokioBlockingExecutor` (`crates/ootle-anchor-app/src/executor.rs`) implements `BlockingExecutor` (defined in `crates/ootle-anchor-network-adapters/src/executor.rs:71`).

- Owns one current-thread Tokio runtime wrapped in `Arc<std::sync::Arc<tokio::runtime::Runtime>>` so it is `Clone` (the driver hands one clone to the walletd transport and one to the indexer transport — no second runtime).
- `new_current_thread()` builds via `tokio::runtime::Builder::new_current_thread().build()` (only the `rt` feature; no `rt-multi-thread`, `time`, or `net`).
- `block_on` checks `tokio::runtime::Handle::try_current()` first; if the calling thread is already inside an active Tokio runtime, it returns `BlockingExecutorError::AlreadyInsideAsyncRuntime` without panicking.
- Stores no secret material, performs no I/O, starts no background task.

## 5. Wall-clock backoff

`WallClockBackoff` (`crates/ootle-anchor-app/src/backoff.rs`) maps the Slice 4A8 abstract attempt index to a bounded `Duration`:

- `delay_for(0) = Duration::ZERO`
- `delay_for(1) = base`
- `delay_for(i) = min(cap, base * 2^(i-1))` with saturating arithmetic.
- Rejects zero base (`BackoffError::ZeroBase`) and cap below base (`BackoffError::CapBelowBase`).
- No randomness, no jitter, no `tokio::time`, no `net`. The driver sleeps via `std::thread::sleep` between polls; never before the first attempt, after a terminal state, or after policy exhaustion.

## 6. Canonical durable snapshot format

`crates/ootle-anchor-app/src/snapshot_store.rs` owns the canonical encoding of `AnchorLifecycleRecoverySnapshot`.

**Envelope**: canonical CBOR definite-length 4-element array:
1. `SNAPSHOT_RECORD_TYPE_ID_V1` = `"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_LIFECYCLE_SNAPSHOT_V1"`
2. `SNAPSHOT_HASH_ALGORITHM_ID_V1` = `"BLAKE3-256/tari-cc-private-ballot/v1"`
3. body digest (32 bytes, BLAKE3)
4. canonical body bytes

**Body**: canonical CBOR definite-length 6-element array:
1. walletd snapshots (array of 10-element arrays)
2. receipt snapshots (array of 6-element arrays)
3. optional submitted handle (0/1-element array; `null` is not in the protocol CBOR subset)
4. polling policy (2-element array: max attempts, attempts consumed)
5. unified phase (text)
6. optional diagnostic (0/1-element array)

**Walletd snapshot** (10-element array): project request id, walletd request id, binding (6-element array: network, account, anchor digest, payload, max fee, fingerprint), decision, submission state, optional transaction id, optional effective status, retry count, sequence, optional diagnostic.

**Receipt snapshot** (6-element array): query (8-element array), query state, optional final status, verified bool, sequence, optional diagnostic.

**Submitted handle** (4-element array): project request id, walletd request id, transaction id, binding. State is implied as `Submitted`.

**Domain separation**: `SNAPSHOT_FRAME_PREFIX_V1` = `b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_LIFECYCLE_SNAPSHOT_FRAME_V1"`, `SNAPSHOT_DOMAIN_LABEL_V1` = `"tari-cc-private-ballot/ootle-anchor-lifecycle-snapshot/v1"`. Frame layout: `prefix || 0x00 || label || 0x00 || body`. Distinct from the protocol, anchor-record, transaction-inspection, and evidence frames.

**Size limit**: `MAX_SNAPSHOT_FILE_BYTES = 65_536`, enforced before write and before decode.

**Identifier validation**: every identifier is re-validated through its existing constructor (`AnchorRequestId::new`, `AnchorTransactionId::new`, `OotleNetworkIdV1::new`, `AnchorAccountReference::new`). Transaction IDs are validated as canonical lowercase 64-character hexadecimal. Every vocabulary field (phase, decision, submission state, effective status, query state, final status, diagnostic) is validated against the closed `as_str()` vocabulary of the existing enums.

## 7. Snapshot known-answer vector

The reference snapshot (`known_answer_snapshot` in `tests/common/mod.rs`) contains:
- network: `esmeralda`
- manifest hash: `0x11` repeated 32 bytes
- archive hash: `0x22` repeated 32 bytes
- anchor digest: `0x33` repeated 32 bytes (the canonical hash of the anchor record built from the above three)
- transaction ID: `0x44` repeated 32 bytes (64 lowercase hex chars)
- phase: `FINALIZED_ACCEPT`
- one walletd snapshot (Approved, Submitted, tx present, status Submitted, retry 0, sequence 1)
- one receipt snapshot (ReceiptFinalizedAccept, final status Accepted, verified true, sequence 1)
- submitted handle present
- polling policy `[8, 5]`
- no diagnostic

**Pinned digest** (BLAKE3, domain-separated):
```
d4a9d17742c47c71cd08848d41fc6fa33f925daad6200d087f1340 6710d86275
```
(hex: `212, 169, 209, 119, 66, 196, 124, 113, 205, 8, 132, 141, 65, 252, 111, 163, 63, 146, 93, 170, 214, 32, 13, 8, 127, 19, 64, 103, 16, 216, 98, 117`)

The `snapshot_known_answer_vector` test (`tests/snapshot_encoding.rs`) asserts both the canonical bytes determinism and the exact digest.

## 8. Atomic-write behavior

`write_snapshot_atomic` writes to `<path>.tmp`, flushes, `sync_all`s, and atomically renames to the target on the same filesystem. A failure before rename leaves the previous target intact. The temp path is deterministic (no randomness). The `atomic_write_safety` test verifies a second write replaces the first and the temp file does not linger.

## 9. Anchor evidence record format

`crates/ootle-anchor-app/src/evidence.rs` defines `AnchorEvidenceRecordV1`.

**Envelope**: canonical CBOR definite-length 4-element array:
1. `EVIDENCE_RECORD_TYPE_ID_V1` = `"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_EVIDENCE_V1"`
2. `EVIDENCE_HASH_ALGORITHM_ID_V1` = `"BLAKE3-256/tari-cc-private-ballot/v1"`
3. body digest (32 bytes)
4. canonical body bytes

**Body**: canonical CBOR definite-length 12-element array:
1. purpose (`NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR`)
2. network
3. election manifest hash (32 bytes)
4. archive hash (32 bytes)
5. anchor-record digest (32 bytes)
6. optional transaction id
7. optional ledger position
8. final status (ACCEPTED / FEE_ONLY_ACCEPTED / REJECTED / VERIFICATION_FAILED / DISAGREEMENT / POLL_EXHAUSTED_UNKNOWN / REJECTED_BY_APPROVER)
9. receipt source (INDEPENDENT_INDEXER / WALLETD_AND_INDEXER / NONE)
10. lifecycle phase
11. snapshot digest (32 bytes)
12. evidence digest algorithm

**Domain separation**: `EVIDENCE_FRAME_PREFIX_V1` = `b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_EVIDENCE_FRAME_V1"`, `EVIDENCE_DOMAIN_LABEL_V1` = `"tari-cc-private-ballot/ootle-anchor-evidence/v1"`. Distinct from all other frames.

**Size limit**: `MAX_EVIDENCE_FILE_BYTES = 8_192`.

**Constructors**:
- `from_verified_indexer_accept` — the only constructor that may produce `ACCEPTED`.
- `from_terminal_outcome` — produces all other terminal incident records.

The record holds no ballot, proof, nullifier, registry key, voter identity, organizer identity, tally, archive contents, private key, auth secret, or seal signer.

`ArchiveProofInputs` and `TerminalEvidenceInputs` are defined in the application leaf because no lower-level crate bundles these public locators together; they carry no secrets.

## 10. Driver lifecycle

`AnchorAppDriver` (`crates/ootle-anchor-app/src/driver.rs`) is generic over the wire transport (`W: WalletdWireTransport`, `I: IndexerReceiptWireTransport`), so the same code path serves offline scripted tests and online real transports.

The `run` loop:
1. `NotPrepared` → build `OotleAnchorRecordV1`, compute production digest, build `AnchorLogPayloadV1`, build `AnchorBindingV1`, build `AnchorPreparationRequest`, wrap in `OotleAnchorTransactionBuildRequestV1`, call `prepare_fee_bearing`, persist snapshot, continue.
2. `Prepared` + `Reject` → call `reject`, persist snapshot, write terminal evidence, return `RejectedByApprover`.
3. `Prepared` + `Approve` → call `approve`, persist snapshot, continue.
4. `Prepared` + `NoDecision` → persist snapshot, return `NotYetFinalized`.
5. `Approved` → call `submit`, persist snapshot, continue.
6. `Unknown` → call `recover`, persist snapshot, continue.
7. `Submitted` / `PollingInProgress` → call `advance_one_poll`, persist snapshot, write evidence on terminal, return; otherwise sleep via `std::thread::sleep(backoff.delay_for(attempts))` and continue.
8. Terminal phases → build evidence (re-query the indexer for `FinalizedAccept` to obtain `VerifiedIndexerAnchorV1`), write evidence atomically, return.

Never auto-approves. Never blind-resubmits. Never claims finality before verified `FinalizedAccept`.

## 11. Explicit operator-decision gate

The driver takes `OperatorDecision { Approve, Reject, NoDecision }`. `NoDecision` stops at `Prepared` and returns `NotYetFinalized`. The binary maps `--approve` / `--reject` flags to the decision; absent both, `NoDecision`.

## 12. Restart and recovery

`AnchorAppDriver::restore` reads the snapshot file (if present; absent is equivalent to `new`), reconstructs the orchestrator via `AnchorLifecycleOrchestrator::from_snapshot`, and continues. The `restart_after_submission_before_first_poll`, `restart_mid_poll`, and `restart_after_finalized_accept_is_idempotent` tests verify the restart path.

## 13. No-blind-resubmit rule

The orchestrator's `submit` is idempotent once `Submitted`. The `no_duplicate_transaction_on_restart` test verifies the restored driver does not resubmit (the scripted walletd's `submit_calls` counter does not increase).

## 14. No-finality-before-verified-accept rule

`FinalizedAccept` is only set by the orchestrator when `report.is_verified_success()` is true (`orchestrator.rs:730-731`). The driver's `accept_evidence` re-queries the indexer via a fresh `AnchorReceiptCoordinator` to obtain the `VerifiedIndexerAnchorV1` and builds the `ACCEPTED` evidence record from it. Fee-only acceptance is a distinct non-success terminal.

## 15. Configuration format

`crates/ootle-anchor-app/src/config.rs` defines `AnchorAppConfig` with a canonical CBOR envelope (digest-bearing, dedicated config hash domain `CONFIG_FRAME_PREFIX_V1` / `CONFIG_DOMAIN_LABEL_V1`). The config carries only public locator data and bounded policy values. Walletd auth is never persisted in the canonical config; it is loaded separately from an environment variable via `with_walletd_auth`. Validation: supported testnet, anchor-record network equals adapter network, non-zero max fee, non-zero receipt-query attempts, non-zero backoff base, cap at least base, absolute bounded paths, endpoint validation delegated to `NetworkAdapterConfig`.

## 16. Binary behavior

`tari-cc-private-ballot-anchor` (`src/main.rs`) parses `--config`, `--auth-env`, `--approve`, `--reject`, `--dry-run` via a small manual parser (no CLI framework). It loads the canonical config, optionally loads walletd auth from the named environment variable, constructs one current-thread Tokio runtime, builds the real transports, creates or restores the driver, runs it, and prints the human-review summary, machine code, snapshot path, evidence path, phase, and transaction id. Exit 0 only for finalized acceptance; non-zero for every non-success or incomplete outcome. Dry-run constructs no transport, submits nothing, signs nothing, prints only the deterministic anchor/build evidence. The binary accepts no private key, mnemonic, seed, wallet password, raw KeyId, or signer secret.

## 17. Dependency and feature audit

Direct dependencies (from `cargo tree --depth 1`):
- 9 project path crates (`anchor`, `anchor-transport`, `archive`, `ootle-anchor-adapter`, `ootle-anchor-lifecycle-orchestrator`, `ootle-anchor-network-adapters`, `ootle-receipt-anchor-adapter`, `ootle-walletd-anchor-adapter`, `protocol`)
- `tokio v1.53.1` with `default-features = false, features = ["rt"]`

Transitive:
- `reqwest v0.13.4` remains transitive through Slice 4A9 (`tari_indexer_client` / `tari_ootle_walletd_client` / `tari_ootle_wallet_sdk`), all pinned to rev `92023e0b`.
- Exactly one Tokio version (1.53.1).
- No second runtime, no second HTTP stack, no version drift, no security-sensitive pin changed.

## 18. Mutation tests

The snapshot rejection tests (`tests/snapshot_encoding.rs`) verify the codec rejects: wrong record type, test-only hash algorithm, trailing bytes, non-shortest CBOR, wrong CBOR type, wrong field count, truncation, malformed digest length, oversized body, digest mismatch, invalid identifiers, unknown phase, unknown decision, unknown submission state, unknown query state, and unknown diagnostic.

## 19. Archive independence

`tests/archive_independence.rs` proves byte-identical `OotleAnchorRecordV1` canonical bytes, `ArchiveHashV1`, `ManifestHash`, recomputed anchor digest, stable transaction id, and stable fingerprint across the happy path. It asserts the snapshot and evidence files contain no archive content, ballot, proof, nullifier, registry key, voter identity, organizer identity, auth secret, seal signer, or private key.

## 20. Toolchain and validation

- `cargo +stable-x86_64-pc-windows-msvc fmt -p tari-cc-private-ballot-ootle-anchor-app -- --check` — clean.
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-ootle-anchor-app` — 69 tests, 0 failures.
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-ootle-walletd-anchor-adapter` — 47 tests, 0 failures (constructor widening does not alter any existing test result).
- Per-crate regressions (network-adapters, lifecycle-orchestrator, receipt-anchor-adapter, anchor-adapter, anchor-transport, anchor, protocol) — all pass.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets` — exit 0.
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace` — all pass, 0 failures.
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings` — exit 0 (no warnings in project-owned code; the single `triptych` warning is in the excluded `third_party/tari-triptych`).
- Dependency audits (`cargo tree --depth 1`, `-i reqwest`, `-i tokio`) — confirmed above.

## 21. Staged file count and hashes

Staged files (computed after `git add`):

(See the final session output for the per-file SHA-256 hashes and the final binary patch hash.)

## 22. No commit

No `git commit` was run. All work remains staged in the index only.

## 23. No network

No network contact. All Cargo commands used `--locked --offline`. No `cargo update`, `cargo search`, crates.io query, live walletd request, live indexer request, or real testnet submission.

## 24. No socket

No socket was opened. All tests use scripted transports. The real transports are constructed only in the binary's `main.rs` and are not exercised by any test.

## 25. No transaction submitted

No real transaction was submitted. The scripted walletd transport returns deterministic responses.

## 26. No signing

No signing was performed. The driver and binary never hold a private key, mnemonic, seed, or signer secret.

## 27. Vendored Triptych untouched

`third_party/tari-triptych` was not modified.

## 28. No Phase 1–3 source changed

No Phase 1–3 crate source was modified.

## 29. No existing Phase 4 semantics changed other than the one-line constructor visibility widening

The only existing Phase 4 source change is `SubmittedWalletdAnchorRequestV1::new` from `pub(crate)` to `pub` in `crates/ootle-walletd-anchor-adapter/src/results.rs`, with a documentation note. No behavior changes.

## 30. Evidence file path

`docs/reviews/PHASE4_SLICE4A10_APPLICATION_DRIVER_AND_DURABLE_SNAPSHOT_2026-08-05.md` (this file).

## 31. Go/no-go for Phase 4 code closeout

**GO.** The harmless, non-binding Ootle testnet anchor prototype is code-complete.

- An operator can run `tari-cc-private-ballot-anchor` against testnet walletd and indexer.
- The operator must explicitly approve (`--approve`) or reject (`--reject`); absent both, the run stops at `Prepared`.
- The tool persists recovery state to a canonical, versioned, digest-bearing snapshot file.
- The tool restarts safely from the snapshot (`--config` + existing snapshot).
- The tool produces canonical, versioned evidence for every terminal outcome.

Restated non-claims:
- Binding governance use remains unauthorized.
- The prototype is non-binding.
- The offline archive and the independent verifier remain authoritative.
- The anchor proves only that a specific commitment was submitted or finalized on the named ledger.
- It does not prove ballot validity, tally correctness, organizer honesty, voter anonymity, or archive availability.
- Independent cryptographic and implementation review remains required before binding use.
- Testnet reset requires transparent re-anchoring of the unchanged `ArchiveHashV1`, not rebuilding the historical election package.

Remaining follow-ups:
- Operator runbook.
- Real testnet run.
- Observed live receipts.
- macOS validation.
- GNU raw-dylib toolchain provisioning.
- Final independent review.
- Phase 5 work.
