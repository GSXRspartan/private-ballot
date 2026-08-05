# Phase 4 Slice 4A8 â€” Anchor Lifecycle Orchestration

**Date:** 2026-08-05
**Branch:** `phase4/ootle-testnet-anchor-prototype`
**Toolchain:** Rust 1.97.1 MSVC (`stable-x86_64-pc-windows-msvc`)
**Slice:** 4A8 â€” Lifecycle Orchestration

---

## 1. Starting Branch and HEAD

The committed 4A7 tip was absent at start: Slice 4A7 was staged in the index
but never committed, leaving HEAD at the 4A6B tip (`503afb1`). After user
authorization, the staged 4A7 work was committed as
`6436856 feat: add Ootle receipt retrieval and anchor verification`, making
HEAD the committed 4A7 tip with a clean working tree. Slice 4A8 was then
implemented on that baseline.

**Starting HEAD (4A7 tip):** `64368568807701657a9ad1c5cbe416eab8c0c63f`
**Starting tree:** clean (no unstaged or untracked changes)

---

## 2. Files Changed

**15 files staged** (1 new crate with 13 files, 2 workspace files, 1 narrow
walletd-adapter re-export):

| File | Status |
|---|---|
| `Cargo.toml` | Modified (1 workspace member line added) |
| `Cargo.lock` | Modified (1 new package entry, no version drift) |
| `crates/ootle-anchor-lifecycle/Cargo.toml` | New |
| `crates/ootle-anchor-lifecycle/src/lib.rs` | New |
| `crates/ootle-anchor-lifecycle/src/orchestrator.rs` | New |
| `crates/ootle-anchor-lifecycle/src/policy.rs` | New |
| `crates/ootle-anchor-lifecycle/src/report.rs` | New |
| `crates/ootle-anchor-lifecycle/src/snapshot.rs` | New |
| `crates/ootle-anchor-lifecycle/src/state.rs` | New |
| `crates/ootle-anchor-lifecycle/tests/common/mod.rs` | New |
| `crates/ootle-anchor-lifecycle/tests/end_to_end.rs` | New |
| `crates/ootle-anchor-lifecycle/tests/recovery.rs` | New |
| `crates/ootle-anchor-lifecycle/tests/safety_mutation.rs` | New |
| `crates/ootle-anchor-lifecycle/tests/archive_independence.rs` | New |
| `crates/ootle-walletd-anchor-adapter/src/lib.rs` | Modified (1-line re-export) |

No Phase 1â€“3 source changed. No vendored Triptych changed
(`third_party/tari-triptych` untouched). No anchor-record,
transaction-construction, walletd, or receipt semantics changed.

---

## 3. Reused Coordinators / Components (Exact APIs, Unchanged)

The orchestrator drives every existing coordinator method exactly as
designed, forwarding the exact request DTOs:

- `WalletdAnchorCoordinator::{new, from_snapshots, registry, prepare_fee_bearing, approve, reject, submit, recover}` â€” called verbatim.
- `WalletdDecisionRequestV1::for_prepared` â€” used for approve/reject.
- `WalletdSubmitRequestV1::for_approved` â€” used for submit/recover.
- `AnchorReceiptCoordinator::{new, from_snapshots, registry, register, query}` â€” called verbatim.
- `AnchorReceiptQueryV1::from_submitted` â€” used to build the receipt query.
- `compare_walletd_and_indexer` â€” called verbatim for agreement.
- `FakeWalletdAnchorClient`, `FakeIndexerReceiptClient`, `FakeReceiptStep`, `receipt_scenarios` â€” reused unchanged.
- `AnchorLifecycleState` â€” reused as the reporting mapping target (not redefined).
- `OotleAnchorTransactionBuildRequestV1`, `OotleAnchorRecordV1`, `ArchiveHashV1`, `ManifestHash`, `Blake3HashProviderV1` â€” reused in tests.

**One narrow interface fix** (proven defect, no semantics change):
`crates/ootle-walletd-anchor-adapter/src/lib.rs` gained a one-line
`pub use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;`
re-export. The type was already part of the walletd adapter's public API
surface (a parameter to the public `prepare_fee_bearing` method) but was not
previously re-exported, making it impossible for a downstream crate that
depends only on the walletd adapter to name the type. The re-export changes
no semantics, no method signature, and no behavior.

---

## 4. New Crate + Dependency / Feature Audit

**Package:** `tari-cc-private-ballot-ootle-anchor-lifecycle-orchestrator`
**Crate path:** `crates/ootle-anchor-lifecycle`
**`#![forbid(unsafe_code)]`** and **`[lints] workspace = true`** set, matching
sibling crates.

### Direct dependencies (library, `cargo tree --depth 1`)

```
tari-cc-private-ballot-anchor
tari-cc-private-ballot-anchor-transport
tari-cc-private-ballot-ootle-receipt-anchor-adapter
tari-cc-private-ballot-ootle-walletd-anchor-adapter
```

Exactly the four permitted project crates. No new pinned Ootle, HTTP, RPC,
async-runtime, TLS, WebSocket, database, GUI, or signing dependency added.

### Dev-only dependencies (test-only, as permitted)

```
tari-cc-private-ballot-anchor
tari-cc-private-ballot-anchor-transport
tari-cc-private-ballot-ootle-anchor-adapter
tari-cc-private-ballot-ootle-walletd-anchor-adapter
tari-cc-private-ballot-ootle-receipt-anchor-adapter
tari-cc-private-ballot-protocol
tari-cc-private-ballot-archive
```

### Lockfile audit

The only `Cargo.lock` change is the new package entry
(`tari-cc-private-ballot-ootle-anchor-lifecycle-orchestrator v0.1.0`).
No version drift; no new external dependency added by this crate.

### Private-key / signing audit

No private-key, secret-key, mnemonic, signing, sealing, or wallet-secret
type appears in any public API of the new crate. The `WalletdSealSignerRef`
is only a key *handle* (branch + index), never key material.

### Network audit

No network call occurred. No `async`, `tokio`, `reqwest`, `hyper`, `std::time`,
`sleep`, or `Duration` appears in any source file (only doc-comment mentions of
what the crate *never* does).

---

## 5. Orchestrator Driver Responsibilities

`AnchorLifecycleOrchestrator` owns:
- one `WalletdAnchorCoordinator`;
- one `AnchorReceiptCoordinator`;
- the bounded `PollingPolicy`;
- the unified per-anchor lifecycle record and state.

It exposes explicit, caller-advanced steps only (no loops, no sleeping, no
async):

- `prepare_fee_bearing` â€” calls `WalletdAnchorCoordinator::prepare_fee_bearing`;
- `approve` / `reject` â€” calls `approve`/`reject` with `WalletdDecisionRequestV1::for_prepared`;
- `submit` â€” calls `submit` with `WalletdSubmitRequestV1::for_approved`, then builds the receipt query via `AnchorReceiptQueryV1::from_submitted` and registers it via `AnchorReceiptCoordinator::register`;
- `recover` â€” calls `recover` verbatim; on a discovered sealed id, calls `submit` **idempotently** (no second client call, no second transaction) to obtain the `SubmittedWalletdAnchorRequestV1` handle;
- `advance_one_poll` â€” calls `AnchorReceiptCoordinator::query` exactly once and consumes exactly one attempt from the policy;
- `check_agreement` â€” calls `compare_walletd_and_indexer` verbatim when a walletd finalize observation is available.

It never re-implements binding checks, receipt conversion, verification, or
agreement; never constructs, mutates, signs, or resubmits a transaction; never
holds key custody.

---

## 6. Bounded Polling / Retry Policy and Its Limits

`PollingPolicy` carries `max_query_attempts` and an abstract
`BackoffSchedule` expressed as attempt indices (unitless, 1-based). It uses
no `std::time`, no sleeping, no async, no randomness. It is advanced
explicitly by the caller through `consume_one()`, which consumes exactly one
attempt per `advance_one_poll` step.

- `is_exhausted()` â€” whether the bound is exhausted.
- `attempts_remaining()` â€” remaining budget.
- `attempts_consumed()` â€” consumed count.
- `from_consumed()` â€” restart reconstruction (clamped to `max`).

The policy decides only *how many* times to re-query and *whether* the bound
is exhausted; it never decides finality. On exhaustion the lifecycle
transitions to a resumable `Unknown`, never a permanent failure.

---

## 7. Unified Lifecycle State and Its Mapping to `AnchorLifecycleState`

`UnifiedAnchorLifecyclePhase` is a project-owned enum that extends the merged
`AnchorLifecycleState` (not redefined) with:

- `NotPrepared` (maps to `None` â€” no `AnchorLifecycleState` variant);
- `PollingInProgress` (maps to `Submitted`);
- `FinalizedVerificationFailed` (maps to `Unknown` â€” never `FinalizedAccept`);
- `FinalizedDisagreement` (maps to `Unknown` â€” never `FinalizedAccept`);
- all merged variants (`Prepared`, `Approved`, `RejectedByApprover`,
  `Submitted`, `FinalizedAccept`, `FinalizedFeeOnly`, `FinalizedReject`,
  `Unknown`) map to their `AnchorLifecycleState` counterparts.

`is_terminal_success()` is `true` only for `FinalizedAccept`. Verification
failure and disagreement are never reported as success.

---

## 8. Required State-Machine Transitions and Safety Rules

Exactly these transitions are implemented:

- `Prepared â†’ Approved` (approve) | `Prepared â†’ RejectedByApprover` (reject; terminal).
- `Approved â†’ Submitted` (submit) | `Approved â†’ Unknown` (submit timeout/lost response).
- `Unknown(submit) â†’ Submitted` (recover finds sealed id; `submit` idempotent) | `Unknown(submit) â†’ Approved` (recover proves never sealed; retryable) | `Unknown(submit) â†’ RejectedByApprover`/`Unknown` (recover terminal/in-flight), using `WalletdRecoveryStateV1` exactly.
- `Submitted â†’ poll`:
  - `ReceiptNotFound` / `ReceiptPending` / `ReceiptUnknown` â†’ remain polling until `max_query_attempts` reached, then `Unknown` (resumable);
  - full acceptance + verified â†’ `FinalizedAccept`;
  - fee-only â†’ `FinalizedFeeOnly`;
  - rejected â†’ `FinalizedReject`;
  - verification-failed â†’ `FinalizedVerificationFailed`.
- Any terminal re-driven is idempotent: no rewind, no second submit, no second distinct transaction.

An ambiguous submit state is always resolved by `recover`, never by a blind
resubmit. `submit` on `Unknown` is refused (`NotRecoverable` error).

---

## 9. Unified Recovery Snapshot Composition and Restart Proof

`AnchorLifecycleRecoverySnapshot` composes:
- walletd snapshots (`Vec<WalletdAnchorSnapshotV1>`);
- receipt-query snapshots (`Vec<AnchorReceiptQuerySnapshotV1>`);
- the cached `SubmittedWalletdAnchorRequestV1` (needed because its
  constructor is crate-private to the walletd adapter);
- the `PollingPolicy` (max + consumed);
- the unified phase and diagnostic.

`from_snapshot` / `from_snapshots` rebuilds both coordinators via their
existing `from_snapshots` constructors and resumes at the correct stage. The
resumed lifecycle does not re-submit, does not rewind a terminal, and
continues polling within the *remaining* attempt bound.

Restart is proven for every stage (12 dedicated tests in `recovery.rs`):
prepared-not-approved, approved-not-submitted, rejected-by-approver,
submitted-not-queried, mid-poll (partial attempts), poll-exhausted unknown,
submit-timeout pending recovery, finalized accept/fee-only/reject,
verification-failed.

---

## 10. Walletd / Indexer Agreement Handling

`check_agreement` calls `compare_walletd_and_indexer` verbatim. A
disagreement:
- is surfaced as `FinalizedDisagreement` (distinct terminal);
- does not mutate the archive, anchor record, submitted transaction id,
  unsigned-transaction fingerprint, or any prior verified receipt evidence;
- does not convert a verified acceptance into a failure of the underlying
  artifacts (the cached receipt evidence is preserved unchanged).

The agreement logic is not duplicated or re-implemented.

---

## 11. Deterministic End-to-End Fake Harness Behavior

`LifecycleHarness` (in `tests/common/mod.rs`) scripts both fakes together:
- a walletd outcome (via `FakeWalletdAnchorClient` injection methods) and a
  receipt-query step sequence (`FakeReceiptStep`, `receipt_scenarios`) keyed
  by the sealed transaction id;
- drives the polling policy through an explicit attempt counter (no
  wall-clock, no sleeping, no async, no randomness);
- exposes captured call counts on both fakes and the attempts consumed;
- supports the full matrix (11 tests in `end_to_end.rs`): happy path,
  fee-only, rejected, verification-failure, poll-until-found,
  poll-exhausted â†’ unknown, submit-timeout â†’ recover â†’ resume,
  submit-timeout â†’ recover â†’ retry, approver reject, disagreement, agreement-ok.

---

## 12. Safety, Mutation, and Archive/Transaction-Independence Tests

**Safety/mutation (10 tests, `safety_mutation.rs`):**
- never blind-resubmits an ambiguous submit (always routes through `recover`);
- never creates a second distinct transaction under duplicate drive, restart, or retry;
- treats fee-only, rejected, and verification-failure as distinct non-success terminals, never `FinalizedAccept`;
- treats not-found/pending/timeout as resumable, never permanent failure;
- exhausts the attempt bound to resumable `Unknown`, never success;
- surfaces disagreement without mutating any artifact;
- disagreement does not convert a verified acceptance into failure of artifacts;
- no invalid case panics or mutates any artifact.

**Archive/transaction independence (2 tests, `archive_independence.rs`):**
- byte-identical `OotleAnchorRecordV1` canonical CBOR, `ArchiveHashV1`,
  `ManifestHash`, recomputed anchor-record digest, submitted transaction id,
  and unsigned-transaction fingerprint across every outcome: happy path,
  fee-only, rejected, verification-failure, not-found, pending, timeout,
  poll-exhausted unknown, submit-timeout â†’ recover, disagreement, and
  eventual finality after restart;
- driving, polling, recovering, or restarting cannot change the submitted
  transaction id or fingerprint.

---

## 13. Toolchain Result

- **Toolchain:** `stable-x86_64-pc-windows-msvc` (Rust 1.97.1)
- **rustfmt:** clean (`cargo fmt -- --check` passes)
- **`cargo check --locked --offline --workspace`:** passes
- **`cargo clippy --locked --offline --workspace --all-targets -- -D warnings`:** passes (zero warnings)
- **`cargo test --locked --offline --workspace`:** passes (exit code 0)

---

## 14. Targeted and Workspace Validation Results

| Step | Command | Result |
|---|---|---|
| 1 | `cargo fmt -p ... -- --check` | clean |
| 2 | new orchestrator crate tests | 49 passed (14 lib + 2 archive + 11 e2e + 12 recovery + 10 safety) |
| 3 | 4A7 receipt-adapter regression | all passed |
| 4 | 4A6B walletd regression | all passed |
| 5 | 4A6A prepare/approval regression | all passed |
| 6 | 4A5 transaction-adapter regression | all passed |
| 7 | 4A4 anchor-transport regression | all passed |
| 8 | anchor regression | all passed |
| 9 | protocol regression | all passed |
| 10 | `cargo check --locked --offline --workspace` | passes |
| 11 | `cargo test --locked --offline --workspace` | passes (exit code 0) |
| 12 | `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` | passes (zero warnings) |
| 13 | `cargo tree --locked --offline` audit | direct deps = 4 project crates only; no new Ootle/HTTP/RPC/async/TLS/DB/signing |

---

## 15. Staged File Count and Hashes

**Staged file count:** 15

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `Cargo.lock` | 115055 | CA7A901F7BCCF97983B6D939E7D1D810CFB5E8A8D48303D5831ABD524BD95991 |
| `Cargo.toml` | 693 | 4AC5245DECE167DCD3AC74A242F00F8E31670DAD722348CD5F9DEB5E6C4F2B4B |
| `crates/ootle-anchor-lifecycle/Cargo.toml` | 2366 | D8F8117F955B4551C1137A81E98F7A634AA26682435FA7FF7DAD42ACB2FE19FD |
| `crates/ootle-anchor-lifecycle/src/lib.rs` | 3090 | E64ACBC8513BA06BED3482A35F4A34A3F609E1627E6505A1791414C3DDF9296E |
| `crates/ootle-anchor-lifecycle/src/orchestrator.rs` | 34110 | 491D86633D907C7D41ED7727054CD5FAE8E46CAC24E1B4E10AF8C68B91ACFC3E |
| `crates/ootle-anchor-lifecycle/src/policy.rs` | 9720 | 95896AC8F68CFFA4208490E95E0DC6AB17A01047E82D338B8CD51298507C275F |
| `crates/ootle-anchor-lifecycle/src/report.rs` | 7311 | 50BAC6FCBB1189D6A49F1BE05493015A48ADA94103C16654B921853E3734E970 |
| `crates/ootle-anchor-lifecycle/src/snapshot.rs` | 8255 | 5CACB341FAD33920DA54F01C185E20A79C0AFF00F94C821FBAFD9AFE47A1EF48 |
| `crates/ootle-anchor-lifecycle/src/state.rs` | 10420 | 84832F58642564D443D42994478D169CF811837F1A266CA715228A38641FC5C6 |
| `crates/ootle-anchor-lifecycle/tests/archive_independence.rs` | 14317 | 95349E9E0ADEC0B3E8D06A3D4F5FB50543E5C7B636D03959F2D4DEBEB6B1602B |
| `crates/ootle-anchor-lifecycle/tests/common/mod.rs` | 11871 | ECD06CEFB773F5F37CDD96C55B2AC8B5362FAAF8D2E6AA98D6ACE01B1115F76C |
| `crates/ootle-anchor-lifecycle/tests/end_to_end.rs` | 10234 | A5E634E5FDB523C0497DB90734C3E87E2CDD0719A2A30E478FD3415B0E25C5A4 |
| `crates/ootle-anchor-lifecycle/tests/recovery.rs` | 13871 | 7ACA6F7E4B20E236B3FFCD4DDB0B47658AEBBA47E9B28A7F71B291362FDFDF01 |
| `crates/ootle-anchor-lifecycle/tests/safety_mutation.rs` | 12763 | A50C898F065F4CF648B6380B51BD1572ED6E6CA9BE27D142422F30AE1006595C |
| `crates/ootle-walletd-anchor-adapter/src/lib.rs` | 5601 | 3AFE3125DEA5AAD41A7D7DEE844605CE7106AA48CEE256C5B2678BCCF081E55A |

**Binary patch size:** 150699 bytes
**Binary patch SHA-256:** 964BCDB52B2E35E511AD1B229BE76330BF3EC4717F8722E14D8C5F8861814AD2

`git diff --cached --check`: clean (no whitespace errors).

---

## 16. No Commit Created

No commit was created. All changes are staged in the index, ready for
review.

---

## 17. No Network Contact

No network call occurred. All `cargo` commands used `--locked --offline`.
No `reqwest`, `hyper`, `tokio`, or async-runtime code was compiled or executed.
The `tari_indexer_client` `client` feature remains disabled.

---

## 18. No Transaction Submitted

No transaction was submitted. No testnet funds were spent. The
`FakeWalletdAnchorClient` and `FakeIndexerReceiptClient` are offline in-memory
fakes; no real walletd or indexer was contacted.

---

## 19. Vendored Triptych Untouched

`third_party/tari-triptych` was not modified. `git diff --stat HEAD` shows
zero changes under `third_party/`.

---

## 20. Evidence-File Path

`docs/reviews/PHASE4_SLICE4A8_LIFECYCLE_ORCHESTRATION_2026-08-05.md`

---

## 21. Go / No-Go Recommendation for Slice 4A9

**Go.** The lifecycle orchestrator composes the walletd and receipt
coordinators end-to-end with a bounded, wall-clock-free polling policy, a
unified lifecycle state, a deterministic recovery snapshot, and the walletd/
indexer agreement hook â€” all offline, deterministic, and proven by 49 tests
including archive/transaction independence across every outcome. The design
introduces no wall-clock timing, no async runtime, no key custody, and no
transaction construction or mutation. Slice 4A9 (real network adapters) can
now bridge the synchronous `WalletdAnchorClient` and
`IndexerAnchorReceiptClient` traits to the confirmed async walletd/indexer
REST clients, mapping the abstract attempt indices to concrete wall-clock
backoff delays, without changing any orchestrator, coordinator, DTO, or
safety semantics established here.
