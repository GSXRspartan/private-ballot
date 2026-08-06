# Phase 4 Slice 4A9: Real Walletd and Indexer Client Adapters — Evidence Report

## 1. Starting Branch and HEAD

- **Branch**: `phase4/ootle-testnet-anchor-prototype`
- **Starting HEAD**: `1c7684af9a8d1a3930be138a93b73deff8f28b28`
- **Date**: 2026-08-05
- **Toolchain**: Rust 1.97.1, `1.97.1-x86_64-pc-windows-msvc`

## 2. Files Changed

| File | Status |
|------|--------|
| `Cargo.toml` | Modified (one line: workspace member added) |
| `Cargo.lock` | Modified (new crate's dependencies resolved) |
| `crates/ootle-anchor-network-adapters/Cargo.toml` | New |
| `crates/ootle-anchor-network-adapters/src/lib.rs` | New |
| `crates/ootle-anchor-network-adapters/src/endpoint.rs` | New |
| `crates/ootle-anchor-network-adapters/src/executor.rs` | New |
| `crates/ootle-anchor-network-adapters/src/error.rs` | New |
| `crates/ootle-anchor-network-adapters/src/auth.rs` | New |
| `crates/ootle-anchor-network-adapters/src/walletd.rs` | New |
| `crates/ootle-anchor-network-adapters/src/indexer.rs` | New |
| `crates/ootle-anchor-network-adapters/src/config.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/common/mod.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/endpoint_shape.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/parity.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/malformed.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/orchestrator_integration.rs` | New |
| `crates/ootle-anchor-network-adapters/tests/archive_independence.rs` | New |

No Phase 1–3 source changed. No vendored Triptych changed. No existing anchor, transaction, walletd, receipt, or lifecycle source changed.

## 3. Exact Pinned Walletd/Indexer APIs

### Walletd (`tari_ootle_walletd_client`, rev `92023e0`)

- **Struct**: `WalletDaemonClient` (`clients/wallet_daemon_client/src/lib.rs:209`)
- **Constructor**: `connect<T: IntoUrl>(endpoint: T, token: Option<EncodedJwtString>) -> Result<Self, WalletDaemonClientError>` (line 217, synchronous, no connection opened)
- **Protocol**: JSON-RPC 2.0 over HTTP POST (line 939, `jrpc_call`)
- **Auth**: Optional bearer JWT (`EncodedJwtString = Zeroizing<String>`, `types.rs:997`)
- **Methods** (all `async fn`, take `&mut self`):
  - `create_transaction_request<T: Borrow<TransactionRequestCreateRequest>>` (line 355) — method `"transaction_requests.create"`
  - `get_transaction_request<T: Borrow<TransactionRequestGetRequest>>` (line 362) — method `"transaction_requests.get"`
  - `approve_transaction_request<T: Borrow<TransactionRequestDecisionRequest>>` (line 376) — method `"transaction_requests.approve"`
  - `reject_transaction_request<T: Borrow<TransactionRequestDecisionRequest>>` (line 384) — method `"transaction_requests.reject"`
  - `submit_transaction_request<T: Borrow<TransactionRequestSubmitRequest>>` (line 391) — method `"transaction_requests.submit"`
- **Request types**: `TransactionRequestCreateRequest` (`types.rs:142`), `TransactionRequestDecisionRequest` (`types.rs:275`), `TransactionRequestSubmitRequest` (`types.rs:288`), `TransactionRequestGetRequest` (`types.rs:249`)
- **Response types**: `TransactionRequestCreateResponse` (`types.rs:199`), `TransactionRequestDecisionResponse` (`types.rs:281`), `TransactionRequestSubmitResponse` (`types.rs:294`), `TransactionRequestGetResponse` (`types.rs:255`), `TransactionRequestInfo` (`types.rs:225`)
- **`TransactionRequestId = i32`** (`crates/wallet/sdk/src/models/transaction_request.rs:13`)
- **`EffectiveStatus`**: `Pending, Approved, Rejected, Submitting, Submitted, Expired` (`crates/wallet/sdk/src/models/transaction_request.rs:69`)
- **`KeyId`**: enum `Derived{key_branch, index}` / `Imported{local_key_id}` (`crates/wallet/sdk/src/models/key.rs:346`)
- **Error**: `WalletDaemonClientError` (`clients/wallet_daemon_client/src/error.rs:27`)
- **reqwest**: mandatory dependency (no feature to disable)

### Indexer (`tari_indexer_client`, rev `92023e0`)

- **Struct**: `IndexerRestApiClient` (`clients/tari_indexer_client/src/rest_api_client.rs:65`)
- **Constructor**: `connect<T: IntoUrl>(endpoint: T) -> Result<Self, IndexerRestClientError>` (line 71, synchronous, no connection opened)
- **Protocol**: REST (HTTP GET with JSON)
- **Auth**: None
- **Methods** (all `async fn`, take `&self`):
  - `get_transaction_receipt(address: TransactionReceiptAddress)` (line 260) — `GET transaction-receipts/{object_key}`
  - `get_transaction_result(req: GetTransactionResultRequest)` (line 152) — `GET transactions/{transaction_id}/result`
- **Response types**: `GetTransactionReceiptResponse { receipt: TransactionReceipt }` (`types.rs:815`), `GetTransactionResultResponse { result: IndexerTransactionFinalizedResult }` (`types.rs:270`)
- **`IndexerTransactionFinalizedResult`**: `Pending`, `Finalized{final_decision, ...}`, `Rejected{details, rejected_time}` (`types.rs:390`)
- **`Decision`**: `Commit`, `Abort(AbortReason)` (`crates/consensus_types/src/decision.rs:16`)
- **`TransactionReceipt`**: `outcome: FinalizeOutcome`, `logs: Box<[LogEntry]>`, `epoch: Epoch` (`crates/engine_types/src/transaction_receipt.rs:18`)
- **`FinalizeOutcome`**: `Commit`, `FeeIntentCommit` (`crates/engine_types/src/transaction_receipt.rs:72`)
- **`TransactionId`**: `Copy`, 32 bytes, `into_receipt_address(self) -> TransactionReceiptAddress` (`crates/transaction/src/transaction_id.rs:73`)
- **Error**: `IndexerRestClientError` (`clients/tari_indexer_client/src/error.rs:56`)
- **`client` feature**: default, enables reqwest

## 4. Crate and Dependency Layout

### New crate: `crates/ootle-anchor-network-adapters`

Package name: `tari-cc-private-ballot-ootle-anchor-network-adapters`

**Dependencies**:
- `tari-cc-private-ballot-ootle-walletd-anchor-adapter` (path)
- `tari-cc-private-ballot-ootle-receipt-anchor-adapter` (path)
- `tari-cc-private-ballot-ootle-anchor-adapter` (path)
- `tari-cc-private-ballot-anchor-transport` (path)
- `tari-cc-private-ballot-anchor` (path)
- `tari_ootle_walletd_client` (git rev `92023e0`) — reqwest mandatory
- `tari_ootle_wallet_sdk` (git rev `92023e0`)
- `tari_ootle_transaction` (git rev `92023e0`, features=["serde"])
- `tari_template_lib_types` (git rev `92023e0`)
- `tari_engine_types` (git rev `92023e0`)
- `tari_indexer_client` (git rev `92023e0`, default features enable client/reqwest)
- `tari_consensus_types` (git rev `92023e0`)
- `url = "2"`
- `serde_json = "1"`
- `time = "0.3"`

**Dev-dependencies**:
- `tari-cc-private-ballot-ootle-anchor-lifecycle-orchestrator` (path)
- `tari-cc-private-ballot-archive` (path)
- `tari-cc-private-ballot-protocol` (path)
- Plus the adapter/anchor/transport crates for test helpers

**Dependency direction**: core protocol/election → anchor → anchor-transport → transaction adapter → walletd domain adapter → receipt domain adapter → lifecycle orchestrator → **real network adapters** (this crate, application layer leaf)

**No lower-level project crate depends on this crate.**

## 5. Runtime Ownership

Selected strategy: **option 2** (application-owned executor trait) combined with **option 3** (caller-owned runtime handle wrapper).

- `BlockingExecutor` trait: `fn block_on<F: Future<Output = T>, T>(&self, future: F) -> Result<T, BlockingExecutorError>`
- `RealWalletdTransport<E: BlockingExecutor>`: holds a `WalletDaemonClient` and an executor; calls `self.executor.block_on(self.client.method(...))` to bridge async to sync
- `RealIndexerTransport<E: BlockingExecutor>`: same pattern with `IndexerRestApiClient`
- `SimpleBlockingExecutor`: test-only executor that polls once using `Waker::noop()`; never exercised by offline tests (scripted transports are synchronous)
- The crate creates no process-global runtime, starts no background task, and never calls `block_on` inside conversion or verification functions
- A future application command supplies a tokio-based executor; the lifecycle orchestrator remains synchronous and deterministic

## 6. Endpoint Configuration

- `WalletdEndpoint` and `IndexerEndpoint`: bounded, validated endpoint URLs
- Validation: rejects empty, unsupported scheme, empty host, embedded credentials, query strings, fragments, over-length paths, control characters, whitespace, port zero
- Supports `http` and `https` only
- Allows loopback for local testnet prototype
- No DNS or connectivity checks in constructors
- Network is never inferred from the endpoint
- `Debug` output contains no credentials

## 7. Walletd Real Adapter

- `WalletdAnchorNetworkAdapter<T: WalletdWireTransport>` implements `WalletdAnchorClient`
- Consumes `WalletdCreateAnchorRequestV1`, forwards `wire_request()` to the transport
- Converts `TransactionRequestCreateResponse` → `WalletdCreateOutcomeV1`
- Converts `TransactionRequestDecisionResponse` → `WalletdDecisionOutcomeV1` via `WalletdEffectiveStatusV1::from_wire`
- Converts `TransactionRequestSubmitResponse` → `WalletdSubmitOutcomeV1` via `canonicalize_transaction_id`
- Converts `TransactionRequestGetResponse` → `WalletdRequestStatusV1` with cached fingerprint
- Caches the inspection fingerprint at creation time (same approach as the 4A6 fake) since `fingerprint_unsigned` is private to the 4A5 crate
- Network safety: rejects mismatched network before any transport call
- No private key, mnemonic, or signing API exposed; never locally signs
- The real adapter is transport only

## 8. Indexer Real Adapter

- `IndexerReceiptNetworkAdapter<T: IndexerReceiptWireTransport>` implements `IndexerAnchorReceiptClient`
- Converts `AnchorReceiptQueryV1` → `TransactionId` via `transaction_id_to_ootle`, derives receipt address via `TransactionId::into_receipt_address`
- Composes two confirmed reads: `get_transaction_receipt` then `get_transaction_result` if not found
- Maps: receipt found → `Finalized(convert_receipt_response(...))`; `Pending` → `Pending`; `Finalized{Commit}` (receipt missing) → `Pending` (timing); `Finalized{Abort}` / `Rejected` → `Finalized(rejected_receipt)`; 404 on both → `NotFound`
- Bounded rejection reason: truncated to 4096 bytes preserving UTF-8 boundaries
- Uses the 4A7 coordinator and verifier unchanged; never duplicates receipt-verification logic

## 9. Transport Error Mapping

- `TransportError`: bounded, carries `TransportErrorCategory` + optional `u16` HTTP status
- Categories: `ConnectionRefused`, `Timeout`, `TlsFailure`, `AuthenticationFailure`, `HttpStatusError`, `MalformedResponse`, `UnsupportedApi`, `NotFound`, `ServiceUnavailable`, `ExecutorUnavailable`, `Unknown`
- `from_walletd_client`: maps `WalletDaemonClientError` variants by `is_timeout()`, `is_connect()`, status code (401/404/503)
- `from_indexer_client`: maps `IndexerRestClientError` variants similarly, checking `source.status().as_u16()` for HTTP status
- No third-party error text, credentials, account references, key handles, or wallet identifiers preserved
- Adapter maps `TransportError` → `WalletdAnchorAdapterError` / `IndexerReceiptTransportError`

## 10. Async-to-Sync Bridge

- `BlockingExecutor` trait with `block_on`
- Real transports hold the pinned client and an executor
- Scripted transports are fully synchronous; no executor needed for tests
- No nested runtime execution; no automatic retry; no sleeping
- Cancellation and timeout outcomes are distinct (Timeout vs ExecutorUnavailable)
- Polling policy remains at the orchestration layer (4A8 `PollingPolicy`), not inside the transport

## 11. Offline Endpoint-Shape Validation

- **Walletd outbound**: tests capture `TransactionRequestCreateRequest`, `TransactionRequestDecisionRequest`, `TransactionRequestGetRequest`, `TransactionRequestSubmitRequest` and verify field-level correctness
- **Walletd JSON-RPC methods**: documented from pinned source (`transaction_requests.create/approve/reject/get/submit`)
- **Indexer outbound**: test captures `TransactionReceiptAddress` and verifies it matches `derive_receipt_address_evidence`
- **Indexer REST paths**: documented from pinned source (`transaction-receipts/{object_key}`, `transactions/{id}/result`)
- **Inbound shapes**: successful create, approval, rejection, submitted tx ID, status, receipt not found, pending, full acceptance, fee-only, finalized rejection, malformed, service error — all tested
- No socket opened; no network contacted

## 12. Authentication and Secret Boundary

- Walletd: optional `WalletdAuthSecret` (bounded JWT/API key reference)
  - `Debug` redacted: `WalletdAuthSecret(<redacted>)`
  - Not persisted in lifecycle snapshots
  - Not included in evidence logs
  - Not in equality/hash types (no `PartialEq`/`Hash` derived)
  - `pub(crate) fn as_jwt_string()` — raw credential never crosses public API
- Indexer: no authentication support confirmed in the pinned API; none invented
- No wallet private key, mnemonic, seed, signer secret, or password in any adapter API
- `KeyId` remains an opaque non-secret walletd handle

## 13. Network Safety

- Every real operation requires the project-bound network, the adapter's configured network, and the operation binding's network to agree exactly
- `WalletdAnchorNetworkAdapter::ensure_network_matches` checks before any transport call
- No mainnet, no preproduction networks, no case-insensitive aliases, no fallback, no endpoint-derived network
- Reuses 4A5 `map_ootle_network` and project-owned `OotleNetworkIdV1`

## 14. Real/Fake Parity

- **Walletd**: create (request_id, expires_at), fingerprint cache, approve (status), reject (status), submit (transaction_id), get (status, transaction_id) — all verified to agree
- **Indexer**: full acceptance, pending, not found, fee-only — all verified to produce identical `IndexerReceiptFetchV1`
- 10 parity tests, all passing

## 15. Malformed and Mutation Tests

- 12 malformed/mutation tests covering: wrong network, walletd not found, service unavailable, malformed submit, indexer malformed, indexer unavailable, indexer timeout, endpoint embedded credentials, endpoint query, endpoint fragment, all error categories without panic, transport error text sanitization
- No malformed case panics; no case mutates any artifact

## 16. Orchestrator Integration

- 8 scenarios driving the existing 4A8 `AnchorLifecycleOrchestrator` through real adapters with scripted transports:
  1. Prepare → approve → submit → receipt not found → final acceptance ✓
  2. Submit response lost → status recovery → final acceptance ✓
  3. Fee-only receipt ✓
  4. Rejected receipt ✓
  5. Verification failure ✓
  6. Walletd/indexer disagreement ✓
  7. Malformed response (no panic) ✓
  8. Restart between submission and receipt finalization ✓
- The lifecycle orchestrator required no modification
- No socket, no network

## 17. Archive/Artifact Independence

- Tests prove byte-identical anchor digest, fingerprint, network, and transaction ID across: not found, pending, timeout, malformed, unavailable, walletd failure
- Fingerprint unchanged after walletd failure
- Transaction ID stable across recovery

## 18. Dependency and Feature Audit

- **Same Ootle revision**: all git deps at `92023e0` — no drift
- **New direct dependencies**: `url 2.5.8`, `serde_json 1.0.151`, `time 0.3.55` — all already in the lock from other crates
- **Async runtime**: no direct tokio dependency; tokio is transitive via reqwest. No second async runtime.
- **HTTP client**: reqwest 0.13.4 (unified features: `json`, `cookies`, `stream`). No second HTTP stack.
- **TLS**: via reqwest's default (rustls). No second TLS implementation.
- **JSON codec**: serde_json. No second JSON codec.
- **URL parser**: `url 2.5.8`.
- **Auth**: no auth crate added (JWT is `Zeroizing<String>` from the pinned walletd client).
- **WebSocket**: none.
- **Database**: none.
- **Signing/key crates**: `tari_ootle_wallet_sdk` present (for `KeyId`/`EffectiveStatus` types only); no signing or key-derivation API called.
- **Private-key public type**: none in the adapter's public API.
- **Mainnet submission code**: none.
- **Lockfile changed**: yes — new crate's dependencies resolved (7 packages added: `curve25519-dalek`, `js-sys`, `rand_core 0.6.4`, `wasm-bindgen` and related — all platform/target-specific transitive deps of reqwest, not new downloads)
- **No wildcard dependencies**: all versions are exact or caret with lock pinning
- **No floating Git dependency**: all at exact rev `92023e0`

## 19. Toolchain and Validation Results

- **Toolchain**: `1.97.1-x86_64-pc-windows-msvc`
- **rustfmt**: passed on all changed project-owned Rust files
- **New crate tests**: 64 tests, all passing (16 unit + 48 integration)
- **4A8 lifecycle-orchestrator regression**: all tests passing (workspace test suite)
- **4A7 receipt-adapter regression**: all tests passing
- **4A6B walletd submission/recovery regression**: all tests passing
- **4A6A prepare/approval regression**: all tests passing
- **4A5 transaction-adapter regression**: all tests passing
- **4A4 anchor-transport regression**: all tests passing
- **Anchor regression**: all tests passing
- **Protocol regression**: all tests passing
- **Workspace `cargo check --all-targets`**: passed
- **Default workspace tests**: all passing (0 failures across all crates)
- **Strict workspace Clippy with `-D warnings`**: passed
- **Offline dependency and feature audit**: completed; no new downloads; no version drift

All Cargo commands used `--locked --offline` with the MSVC toolchain.

## 20. Staged File Count and Hashes

**Staged file count**: 18

**Per-file staged blob byte count and SHA-256**:

| File | Bytes | SHA-256 |
|------|-------|---------|
| `Cargo.lock` | 116653 | `10daf2925693b0eb4ad7fc39626ab3a691862e3bc1f60f45f4f6313f670c2f1a` |
| `Cargo.toml` | 771 | `56226151758e86d4eda3648f6da62ca23a52093f7dd6042cc2f62edf13ffaae2` |
| `crates/ootle-anchor-network-adapters/Cargo.toml` | 5147 | `8358de820ce09c33a9fafae939a021517852be8160c8324c49835d4f2fd916e1` |
| `crates/ootle-anchor-network-adapters/src/auth.rs` | 3577 | `f9c847465734273cfc5cc1c09ca7e74a73a6299477df6759e8faeb598edbb75e` |
| `crates/ootle-anchor-network-adapters/src/config.rs` | 8724 | `a890dc537b12e10ad404e34acdb0ed04a189b9d48af21d23cccb11e38bb197d4` |
| `crates/ootle-anchor-network-adapters/src/endpoint.rs` | 11932 | `34ebc6d55d7129b00c207fc9cb8d082e435c2ba59cfefb060bbd323abd3b5380` |
| `crates/ootle-anchor-network-adapters/src/error.rs` | 9290 | `30cc03712e36a9bdd2b17ba8d83a6bdb41c959f39fbc8a01bb6cb0a2ba8dc2db` |
| `crates/ootle-anchor-network-adapters/src/executor.rs` | 4220 | `0b7adfd0bd3b8ce7308f898d98ebe2d0898c27ef0bff0588425004e197854881` |
| `crates/ootle-anchor-network-adapters/src/indexer.rs` | 17490 | `46382cdb0f6377038ccc2765e7c89b0f9283a01b3725a2e815cfc9c71740b270` |
| `crates/ootle-anchor-network-adapters/src/lib.rs` | 3084 | `829f4478f319ebe0dc7f25538a8ebc0ddaca92b000feae3468ed8b2480eea072` |
| `crates/ootle-anchor-network-adapters/src/walletd.rs` | 29767 | `27ee91c294d0e53b0a9ce7d3e803c7969d845d10cf2af84b8926579a2d549838` |
| `crates/ootle-anchor-network-adapters/tests/archive_independence.rs` | 4508 | `536af81684450f4614e8c1aebb9bbba94506eef151474d3206668d72a2d4f5e7` |
| `crates/ootle-anchor-network-adapters/tests/common/mod.rs` | 5422 | `fa44f986247cac4c9ca147dc1922a22d79229437af2a61b8e606e0025c6989f8` |
| `crates/ootle-anchor-network-adapters/tests/endpoint_shape.rs` | 11324 | `434f2be996d8592c285f562e229d08fddd802a7d4a533ef24d54e87ac6bdfbdb` |
| `crates/ootle-anchor-network-adapters/tests/malformed.rs` | 7220 | `b23f25ce46d99a3c75d2c763f57c8290ac06c44e4ef6a8d980076a948582d10f` |
| `crates/ootle-anchor-network-adapters/tests/orchestrator_integration.rs` | 9655 | `8285c055e138ccf86e3b5b15c75d695647c721208053fde23c36f54703239b08` |
| `crates/ootle-anchor-network-adapters/tests/parity.rs` | 9719 | `253115a3303fde7edca8acdbd7d62dd37f2b47c43d66bd20682b4c15e6739c48` |
| `docs/reviews/PHASE4_SLICE4A9_REAL_NETWORK_ADAPTERS_2026-08-05.md` | 18581 | `3edd12b0f7c730feae30e18098251e261947d2d9890dde88395604438984eb2a` |

**Full staged binary patch**: 171792 bytes
**Full staged binary patch SHA-256**: `0d622179b98721f57fc8e06e22d5fb76aeca0d242c645a9e7fa8729f0f131f87`

## 21. No Commit Created

No commit was created. Changes are staged only.

## 22. No Network Contact

No network contact occurred during implementation or validation.

## 23. No Socket Opened

No socket was opened during implementation or validation. All tests use scripted transports.

## 24. No Transaction Submitted

No transaction was submitted. The real transports were never invoked with a live client.

## 25. No Signing Performed

No signing, sealing, or key derivation was performed. No private key, mnemonic, or signing secret was stored or processed.

## 26. Evidence File Path

`docs/reviews/PHASE4_SLICE4A9_REAL_NETWORK_ADAPTERS_2026-08-05.md`

## 27. Go/No-Go Recommendation for Phase 4A10

**Go.** The real walletd and indexer client adapters are implemented behind the existing narrow traits, validated offline with 64 passing tests, and the lifecycle orchestrator required no modification. The dependency audit confirms no version drift, no second HTTP stack, no second async runtime, and no private-key custody. The adapters are ready for a future application command to supply a tokio-based executor and drive a real testnet transaction.
