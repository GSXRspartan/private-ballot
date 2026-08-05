# Phase 4 Slice 4A7 — Independent Ootle Receipt Retrieval and Anchor Verification

**Date:** 2026-08-05
**Branch:** `phase4/ootle-testnet-anchor-prototype`
**Starting HEAD:** `503afb1dcbcc49320fde1cb13e6fda77d2a3ec24`
**Toolchain:** Rust 1.97.1 (`stable-x86_64-pc-windows-msvc`)
**Mode:** Implement, validate, stage. **No commit created.** No network contact. No transaction submitted.

---

## 1. Starting branch and HEAD

- Branch `phase4/ootle-testnet-anchor-prototype`, HEAD `503afb1dcbcc49320fde1cb13e6fda77d2a3ec24`, clean working tree confirmed before edits.
- `rustc +stable-x86_64-pc-windows-msvc --version` → `rustc 1.97.1 (8bab26f4f 2026-07-14)`.

## 2. Files changed

New leaf crate `crates/ootle-receipt-anchor-adapter` (package
`tari-cc-private-ballot-ootle-receipt-anchor-adapter`) plus the workspace member
line and lockfile package entry. No Phase 1–3 source, no vendored Triptych, no
anchor-record, anchor-log, transaction-construction, walletd prepare/approve/
submit/recover, or verifier/tally/election source changed.

| File | Role |
| --- | --- |
| `Cargo.toml` | add workspace member |
| `Cargo.lock` | new package entry only (no version drift) |
| `crates/ootle-receipt-anchor-adapter/Cargo.toml` | pinned deps (Section: Dependency pinning) |
| `src/lib.rs` | crate contract + confirmed-API citations |
| `src/errors.rs` | bounded, stable error enums |
| `src/query.rs` | Section A — receipt query identifier |
| `src/convert.rs` | Section B/E — transaction-id + receipt conversion (pinned seams) |
| `src/address.rs` | Section C — receipt-address derivation evidence |
| `src/client.rs` | Section D — narrow fakeable client boundary |
| `src/retrieve.rs` | Section G/H — retrieval, verification, agreement |
| `src/state.rs` | Section I — query/recovery state + snapshots |
| `src/fake.rs` | Section J — deterministic offline fake client |
| `src/scenarios.rs` | Section J — deterministic receipt builders |
| `tests/common/mod.rs` | shared real-flow submitted-request builders |
| `tests/retrieval_verification.rs` | Sections F, G, K |
| `tests/agreement.rs` | Section H |
| `tests/recovery_state.rs` | Section I |
| `tests/archive_independence.rs` | Section L |

## 3. Exact pinned indexer/receipt APIs (rev `92023e0`, checkout `…/tari-ootle-fb4571cb31b11274/92023e0`)

- **Receipt retrieval:** `tari_indexer_client::rest_api_client::IndexerRestApiClient::get_transaction_receipt(address: TransactionReceiptAddress) -> Result<GetTransactionReceiptResponse, IndexerRestClientError>` — `clients/tari_indexer_client/src/rest_api_client.rs:260`. `GetTransactionReceiptResponse { receipt: TransactionReceipt }` — `clients/tari_indexer_client/src/types.rs:818`.
- **Result read (pending/rejected):** `get_transaction_result(GetTransactionResultRequest{ transaction_id }) -> GetTransactionResultResponse { result: IndexerTransactionFinalizedResult }` — `rest_api_client.rs:152`, `types.rs:259/276`. `IndexerTransactionFinalizedResult::{ Pending, Finalized{ final_decision: Decision, execution_result: Option<Box<ExecuteResult>>, execution_time, finalized_time, abort_details }, Rejected{ details, rejected_time } }` — `types.rs:393`.
- **Receipt address derivation:** `tari_ootle_transaction::TransactionId::into_receipt_address(self) -> TransactionReceiptAddress` — `crates/transaction/src/transaction_id.rs:73` — places the 32 transaction-id bytes verbatim into the receipt `ObjectKey` (`self.into_array().into()`). Reversible via `TransactionId::from_receipt_address` (`:65`). `TransactionReceiptAddress` — `crates/template_lib_types/src/substates/tx_reciept.rs:17`; `ObjectKey::LENGTH == 32`.
- **Persisted receipt:** `tari_engine_types::transaction_receipt::TransactionReceipt { outcome: FinalizeOutcome, diff_summary, fee_withdrawals, events, logs: Box<[LogEntry]>, fee_receipt, epoch: Epoch }` — `crates/engine_types/src/transaction_receipt.rs:22`.
- **Full vs fee-only:** `FinalizeOutcome::{ Commit, FeeIntentCommit }` — `transaction_receipt.rs:84`. A persisted receipt substate exists only for a committed transaction (there is no `Reject` outcome); a fully-rejected transaction has no receipt substate.
- **Logs:** `tari_engine_types::logs::LogEntry { message: String, level: LogLevel }` — `crates/engine_types/src/logs.rs:42`; `LogLevel::{ Error, Warn, Info, Debug }` — `crates/template_lib_types/src/log_level.rs:17` (`tari_template_lib::types` re-exports `tari_template_lib_types`, so the field type is `tari_template_lib_types::LogLevel`). The anchor payload lives in `LogEntry.message` verbatim; `LogEntry`'s `Display` prepends the level and is **not** used.
- **Ledger position:** `Epoch(pub u64)` via `Epoch::as_u64()` — `crates/engine_types/src/epoch.rs:65`.
- **Result-path full/fee-only/reject:** `ExecuteResult.finalize.result: TransactionResult::{ Accept, AcceptFeeRejectRest, Reject }` — `crates/engine_types/src/commit_result.rs:283`.

## 4. Dependency and feature audit (Section M)

Direct pinned dependencies (all git rev `92023e0`, same as Slices 4A5/4A6, no drift):
`tari_ootle_transaction 0.37.0`, `tari_template_lib_types 0.29.0`,
`tari_engine_types 0.37.0`, and `tari_indexer_client 0.36.0`
(**`default-features = false`** → the reqwest/HTTP/TLS `client` feature is *not*
enabled). Project deps: `anchor-transport`, `ootle-walletd-anchor-adapter`,
`ootle-anchor-adapter`, `anchor`.

- **`--locked --offline` build/test succeed.** Lockfile change is the single new package entry (16 lines) — no version drift, no new transitive crate.
- `cargo tree -p …-ootle-receipt-anchor-adapter -i reqwest` → reqwest is reached **only** through the pre-existing `ootle-walletd-anchor-adapter → tari_ootle_walletd_client` chain. `tari_indexer_client` resolves with the `client` feature **off** (lock deps: no `reqwest`/`hyper`/`thiserror`/`bytes`/`serde_urlencoded`). **No new HTTP/TLS/runtime stack is introduced; no duplicate HTTP client stack.**
- No WebSocket, database (`sqlx`/`diesel`/`rocksdb`/`libsqlite`), `axum`, or `tonic` crate is added by this crate.
- **No signing/private-key crate is used by project code:** no `KeyId`, `to_key_id`, `sign`, `secret`, `mnemonic`, or `private_key` symbol appears in `src/` or `tests/`; no private-key type appears in any public API.
- **No network call occurs:** no `reqwest`, `.await`, `async fn`, `tokio::`, or `IndexerRestApiClient` call site exists in source (only descriptive doc comments name the confirmed async API). Every test uses the offline `FakeIndexerReceiptClient`.

## 5. Transaction-ID conversion (Section B) — `src/convert.rs`

- One representation only: the project `AnchorTransactionId` (bounded lowercase hex). `transaction_id_from_ootle` delegates to Slice 4A6B `canonicalize_transaction_id` (Ootle→project). `transaction_id_to_ootle` is the exact inverse (project→Ootle): strict 64-char, lowercase `[0-9a-f]` only, decoding to exactly 32 bytes; rejects empty, wrong length, uppercase, non-hex.
- Deterministic round trip and a known-answer vector (`0x00..1f → "0001…1f"`) are unit-tested; uppercase, wrong-length, and non-hex inputs are rejected. No second encoding is invented.

## 6. Receipt-address derivation (Section C) — `src/address.rs`

- `derive_receipt_address_evidence` parses the project id to a pinned `TransactionId`, calls the typed `into_receipt_address()`, and records `AnchorReceiptAddressEvidenceV1` (project tx id, typed Ootle id hex, `txreceipt_…` display, object-key hex, network) with **no finality claim**. No debug-string parsing is used.
- Tests prove determinism (same id → same evidence), that the receipt object-key hex **equals** the transaction-id hex, that different ids derive different addresses, and that a malformed id is rejected.

## 7. Query-client boundary (Section D) — `src/client.rs`

- `trait IndexerAnchorReceiptClient { fn fetch_anchor_receipt(&mut self, &AnchorReceiptQueryV1) -> Result<IndexerReceiptFetchV1, IndexerReceiptTransportError>; }` — one confirmed operation, synchronous, fakeable, no pinned type or key crossing it.
- Outcomes: `IndexerReceiptFetchV1::{ Finalized(AnchorReceiptV1), Pending, NotFound }`; transport errors `IndexerReceiptTransportError::{ Unavailable, Timeout, MalformedResponse, UnsupportedApi }`. The doc traces how a real adapter composes `get_transaction_receipt` (committed receipt) and `get_transaction_result` (pending/rejected) into these outcomes.

## 8. Receipt conversion (Section E) — `src/convert.rs`

- `convert_transaction_receipt(&TransactionReceipt, &AnchorTransactionId, &OotleNetworkIdV1) -> Result<AnchorReceiptV1, ReceiptConversionError>` and `convert_receipt_response(&GetTransactionReceiptResponse, …)` are the only seams naming the pinned receipt types.
- Maps only confirmed fields: `FinalizeOutcome::Commit → Accepted`, `FeeIntentCommit → FeeOnlyAccepted`; ordered logs preserved with exact UTF-8 `message` (level mapped `Error/Warn/Info/Debug`); `epoch → ledger_position`; source `IndependentIndexer`. No organizer identity, block timestamp, archive/tally validity, or acceptance beyond the outcome is invented. Bounds: `MAX_RECEIPT_LOG_ENTRIES = 256`, `MAX_RECEIPT_LOG_MESSAGE_BYTES = 4096`; over-count and over-length are rejected before any DTO is built (exact-max accepted).

## 9. Final-status mapping (Section F) — `src/retrieve.rs`

Finalized receipts flow through the **existing** Slice 4A4 `verify_query_outcome`,
whose ordered rules discriminate the state:

| Observation | Query state | Query outcome |
| --- | --- | --- |
| Full acceptance, valid anchor log | `ReceiptFinalizedAccept` (verified) | `Finalized` |
| Fee-only (`FeeOnlyAcceptance`) | `ReceiptFinalizedFeeOnly` | `Finalized` |
| Rejected (`RejectedTransaction`) | `ReceiptFinalizedReject` | `Finalized` |
| Full acceptance, bad/missing/dup/conflicting/wrong-tx/wrong-net log | `ReceiptVerificationFailed` | `Finalized` |
| Pending | `ReceiptPending` | `NotFinalized` |
| Not found | `ReceiptNotFound` | `NotFound` |
| Timeout / transport failure | `ReceiptUnknown` | `Unknown` |

A fee-only result is a distinct, non-success terminal state — never collapsed into
rejection nor counted as an anchor. Not-found is never collapsed into rejection.
Source evidence: `FinalizeOutcome` (`transaction_receipt.rs:84`) and
`TransactionResult` (`commit_result.rs:283`).

## 10. Anchor verification behavior (Section G)

`AnchorReceiptCoordinator::query` reuses `verify_query_outcome`/`verify_anchor_receipt`
verbatim (no re-implementation). A `ReceiptFinalizedAccept` requires: matching
transaction id and network; a full finalized acceptance; exactly one strictly
parseable project anchor log; digest equal to the expected digest; no duplicate or
conflicting anchor log; malformed project-looking logs rejected; unrelated logs may
coexist. Success yields `VerifiedIndexerAnchorV1 { evidence (tx, network, digest,
ledger position, source=indexer), payload, address evidence, final_status }` — no
archive/ballot/secret data. Fee-only and rejected receipts fail (as distinct
states); the receipt source is recorded as indexer.

## 11. Walletd/indexer agreement (Section H)

`compare_walletd_and_indexer` confirms each observation's source
(walletd vs independent indexer), that both name the expected transaction and
network (an indexer receipt for another transaction is refused), then defers to the
Slice 4A4 `compare_receipt_observations`. The **stricter existing rule — full
ordered log-sequence equality — is retained unchanged** (source `agreement.rs`
confirms both observations derive from the same consensus-committed log vector).
Refused: walletd-accept vs indexer-reject; walletd-fee-only vs indexer-full;
missing anchor in one source; different digest/tx/network; swapped sources.

## 12. Query and recovery state (Section I)

`AnchorReceiptQueryStateV1::{ SubmittedNotQueried, ReceiptNotFound, ReceiptPending,
ReceiptUnknown, ReceiptFinalizedAccept, ReceiptFinalizedFeeOnly,
ReceiptFinalizedReject, ReceiptVerificationFailed }`. `LocalReceiptQueryRegistry`
preserves the frozen query binding (project/walletd request ids, tx id, network,
account, digest, payload, fingerprint), last final status, verified flag,
deterministic sequence, and bounded diagnostic. `AnchorReceiptQuerySnapshotV1` +
`from_snapshots` provide deterministic restart/import; registration is idempotent
and never rewinds. A missing/pending/timeout state is resumable (not terminal); only
fee-only and rejection are terminal.

## 13. Fake behavior (Section J)

`FakeIndexerReceiptClient` scripts per-transaction-id sequences of `FakeReceiptStep`
(`Fetch(Finalized/Pending/NotFound)` or `Transport(error)`); the final step repeats
so a terminal outcome is stable (supports stale-then-final and restart replay). No
randomness, no network, no transaction creation/modification, no signing. It exposes
`queried_transaction_ids()`, `call_count()`, `query_count_for()`, and a global
`set_unavailable`. `scenarios.rs` builds every receipt shape (accept, fee-only,
reject, missing/malformed/wrong/duplicate/conflicting/unrelated logs, walletd-source
variant) from the anchor-transport API only.

## 14. Mutation and archive-independence tests (Sections K, L)

- **Mutation/safety:** malformed/uppercase/wrong-length/non-hex transaction id; wrong receipt/transaction/network; oversized and too-many logs; full acceptance without/with-malformed/wrong-digest/duplicate/conflicting anchor log; fee-only; rejected; walletd/indexer disagreement; stale-then-final; and query/submitted binding mismatch are all covered. No invalid case panics; each returns a bounded report or error.
- **Archive/transaction independence:** `archive_independence.rs` builds a real `OotleAnchorRecordV1`/`ArchiveHashV1`, drives receipt queries across success, not-found, pending, timeout, malformed, fee-only, rejected, malformed-log, duplicate-log, disagreement, and restart, and asserts the record's canonical CBOR bytes, `ArchiveHashV1`, `ManifestHash`, and recomputed digest are byte-identical, and that the submitted transaction id and unsigned-transaction fingerprint are unchanged.

## 15. Toolchain result

All build/test/clippy/tree commands ran under `stable-x86_64-pc-windows-msvc`
(Rust 1.97.1) with `--locked --offline`.

## 16. Targeted and workspace validation

- `cargo fmt -p …-ootle-receipt-anchor-adapter -- --check` → clean.
- Receipt-adapter tests: **45 passed** (13 lib unit + 17 retrieval/verification + 8 agreement + 6 recovery/state + 1 archive-independence), 0 failed.
- 4A6B / 4A6A / 4A5 / 4A4 / anchor / protocol regressions and the full workspace test run: **all suites 0 failed**; the manual long suites (`1 ignored` per suite) were skipped by default.
- `cargo check --locked --offline --workspace` → success (only the pre-existing vendored `triptych` dead-code warning, outside the workspace).
- `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` → **clean** for all project crates.
- Offline `cargo tree` feature audit → see Section 4.

## 17. Staged file count and hashes

**Staged files: 18.** `git diff --cached --check` → clean.

| bytes | sha256 | path |
| --- | --- | --- |
| 114628 | `1b47e46bc1788d8aaf0b87071783ba9ec42c19e481b2ebe74f0b0e0ea2cc2849` | `Cargo.lock` |
| 656 | `da4d19686953ec3a5ac03667f80e426da012c2b0229836098c7a4a3ed94c8c70` | `Cargo.toml` |
| 4258 | `207ccff14ea29b729608984e2f4bcb468d3c9f1c4ccd16d68500fba377f6faf5` | `crates/ootle-receipt-anchor-adapter/Cargo.toml` |
| 5990 | `490a216e00ec73be3e4a1a505b2100f7288b42e148ac4dba8477d82700b4c514` | `src/address.rs` |
| 4213 | `a2f91f917e5ce5269ec69bf2767a266c4310f29d7a7a778bdec8afde74d46783` | `src/client.rs` |
| 15883 | `6ee555e4fa10a6995a1ec3f4abf86a727512d4c51ab3e6867124509b5942ad7d` | `src/convert.rs` |
| 5054 | `3b176ffcd88b00fe7470a8a8ce913a9bbfbf2ec4ad0159bdcfe0399255388c79` | `src/errors.rs` |
| 6092 | `1457738c86d1d995e2d310bbaa7c96b0244ac2698772de3d8bd6d43f43011488` | `src/fake.rs` |
| 5259 | `bbadc7e9cb09bd6d90cc2e5de3a828b94b4ca04c746862779a5dd88f93d63b7f` | `src/lib.rs` |
| 6166 | `6ca2aa7adc1663ec77a129a6f0335e729cfad0ac2e7f6cd6d76d2869c91fffa7` | `src/query.rs` |
| 16777 | `573a4a23949e5d1e3524368a2c49af3b7dcefbcbc69c7653c54162ce850fe15d` | `src/retrieve.rs` |
| 7779 | `440e0c73dc478c96a7f536c4c7ff47cbd4210fc762134b480d792d21dd6955d0` | `src/scenarios.rs` |
| 12063 | `b9c94a6e9645c3cc1628bb514172291d569b9d32e0c78972649c5f1c00609724` | `src/state.rs` |
| 5722 | `6c9271684f00d9020beaf44e500fe704b9c596bc6310891caba6511071d47b51` | `tests/agreement.rs` |
| 5466 | `979ddf3ce3b415a14d9277211d20c79bbe488aeb1c9eb6deb3debd64b8d7b7d0` | `tests/archive_independence.rs` |
| 6461 | `91900592bb2f356d4fb936fc2d1bcbaa022efd1bc9dfdc3ab12f0e9b5ff1cf01` | `tests/common/mod.rs` |
| 8069 | `796cdf0598210ff57cf7fad081396da8a53a67380af3b0e3d2a3731e9423cb1d` | `tests/recovery_state.rs` |
| 15045 | `cfaf996f73d384d9b2698b2b577bc11ca1c689ed21fdee66502bcd04857264b6` | `tests/retrieval_verification.rs` |

(Paths under the last rows are relative to `crates/ootle-receipt-anchor-adapter/`.)

**Binary patch** (`git diff --cached --binary`): **138876 bytes**, sha256
`7fadd52a811030f35606b59aa52150fbd21693d25284637cf5b33301e189c11a`. *(Excludes this
evidence file, which is staged separately after hashing.)*

## 18. No commit created

No `git commit` was run. Changes are staged only.

## 19. No network contact

No indexer, walletd, or any network was contacted. `tari_indexer_client` is built
with the `client` (reqwest) feature disabled; every test uses the offline fake.

## 20. No transaction submitted

No transaction was constructed, signed, sealed, or submitted; no testnet funds were
spent. The slice is read-only over an already-submitted transaction id.

## 21. Evidence-file path

`docs/reviews/PHASE4_SLICE4A7_RECEIPT_RETRIEVAL_VERIFICATION_2026-08-05.md`.

## 22. Go/no-go recommendation for Slice 4A8 lifecycle orchestration

**GO.** The receipt-retrieval boundary is complete, offline-verified, and cleanly
layered on the confirmed pinned APIs: transaction-id ↔ receipt-address derivation is
deterministic and reversible; the persisted receipt converts losslessly into the
Slice 4A4 receipt DTO with a first-class fee-only distinction; verification reuses
the 4A4 verifier verbatim; and the query/recovery state machine plus deterministic
snapshots give 4A8 a safe, resumable substrate. Recommended 4A8 scope notes:
(a) 4A8 should own the polling cadence/backoff and the retry-bound around
`ReceiptUnknown`/`ReceiptPending`, which this slice deliberately leaves to the
caller; (b) the real indexer adapter (async→sync bridge over
`get_transaction_receipt` + `get_transaction_result`) remains unimplemented by
design and should land behind this crate's narrow trait; (c) durable on-disk
snapshot encoding is still deferred and should be pinned in 4A8.
