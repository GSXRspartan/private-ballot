# Phase 4 Slice 4A6B — Walletd Submission, Transaction-ID Recovery, and Fee Strategy

Date: 2026-08-05
Mode: implement, validate, and stage (no commit)

## 1. Starting branch and HEAD

- Branch: `phase4/ootle-testnet-anchor-prototype`
- Starting HEAD: `2cc1d6077c1114bee94bda0993899223426683d1`
- Repository clean before beginning: yes (`git status --porcelain` empty).
- Toolchain: Rust 1.97.1, MSVC host `stable-x86_64-pc-windows-msvc` (`rustc 1.97.1 (8bab26f4f 2026-07-14)`), used for all Ootle-dependent build/test/clippy commands. All Cargo commands run `--locked --offline`.
- Pinned Ootle checkout inspected: `C:\Users\pdark\.cargo\git\checkouts\tari-ootle-fb4571cb31b11274\92023e0`, HEAD `92023e0b7c2fabf7df2f8ee23a2cc252d3c34f9f`.

## 2. Files changed

Slice 4A5 construction adapter (`crates/ootle-anchor-adapter/`) — narrow fee-aware extension:

- `src/errors.rs` — added `MissingFeeInstruction`, `MalformedFeeInstruction`, `FeeAccountMismatch`, `FeeAmountMismatch`; clarified `UnexpectedFeeInstruction`.
- `src/inspect.rs` — refactored the inspector into a shared core with an internal `FeeExpectation`; added `inspect_fee_bearing_anchor_transaction`; the fee-less `inspect_unsigned_anchor_transaction` behaviour is byte-for-byte unchanged.
- `src/build.rs` — added `build_fee_bearing_anchor_transaction`.
- `src/evidence.rs` — documented that `fee_instructions_present()` is now true on the fee-bearing path (no struct change).
- `src/lib.rs` — re-exported the two new fee-bearing functions.
- `tests/fee_construction.rs` — new: fee-bearing construction/inspection + mutation coverage.

Slice 4A6B walletd adapter (`crates/ootle-walletd-anchor-adapter/`):

- `Cargo.toml` — added `tari_template_lib_types` and `tari_ootle_transaction` (same rev `92023e0`) to `[dependencies]` (for `ComponentAddress` resolution and `TransactionId` canonicalization); removed the now-redundant `[dev-dependencies]` duplicates. **Cargo.lock unchanged.**
- `src/identifiers.rs` — added `WalletdFeeComponentRef` (parses the resolved fee account component address) and `canonicalize_transaction_id`.
- `src/errors.rs` — added submission/recovery variants (`FeeComponentInvalid`, `RequestNotApproved`, `SubmitTimeout`, `MalformedSubmitResponse`, `SubmittedButTransactionIdMissing`, `AlreadySubmitted`, `SubmissionStateUnknown`, `ConflictingTransactionId`, `StatusUnavailable`, `CallerSuppliedTransactionId`).
- `src/client.rs` — enriched `WalletdRequestStatusV1` with `transaction_id` + `observed_fingerprint`; added `WalletdSubmitCommandV1`, `WalletdSubmitOutcomeV1`, and the `submit_transaction_request` trait method.
- `src/convert.rs` — added `build_fee_bearing_walletd_create_request` (fee-aware re-inspection).
- `src/registry.rs` — added `WalletdSubmissionStateV1` and per-record submission state, transaction id, last effective status, and retry count, threaded through the snapshot.
- `src/results.rs` — added `SubmittedWalletdAnchorRequestV1`, `RecoveredWalletdAnchorRequestV1`, `WalletdRecoveryStateV1`; extended the human-review summary with the fee instruction.
- `src/coordinator.rs` — added `WalletdSubmitRequestV1`, `prepare_fee_bearing`, `submit`, `recover`, and `verify_bound_record`.
- `src/fake.rs` — implemented `submit_transaction_request`, enriched `get`, added deterministic fake-only transaction-id derivation and submission failure injectors.
- `src/lib.rs` — updated the module doc for the submit/recover scope; re-exported the new items.
- `tests/prepare_approve_reject.rs` — updated the exact human-review-summary vector for the new `fee_instruction=` field.
- `tests/common/mod.rs` — added fee-bearing helpers.
- `tests/archive_independence.rs` — added a submission/recovery archive-independence case.
- `tests/submit_recover.rs` — new: the submission, binding, timeout/unknown, duplicate, and recovery suite.

No Phase 1–3 source, no vendored Triptych, and no anchor/archive/protocol/tally/election/anchor-record/anchor-log code was modified.

## 3. Confirmed fee strategy — **Strategy 2** (fees embedded before freeze)

Traced the walletd **server**, not only client types:

- `applications/tari_walletd/src/handlers/transaction_requests.rs::handle_submit` (lines 246–318): claims the request with a conditional `Approved -> Submitting` transition, then builds a `TransactionSubmitRequest` from `model.unsigned_transaction` **verbatim** with `detect_inputs: false` ("Everything was resolved at creation. Detecting again here would change the transaction the approver saw."), calls `submit_inner_for_request`, then records the returned `transaction_id`.
- `applications/tari_walletd/src/handlers/transaction.rs::submit_inner_for_request` (127–135) → `submit_inner` (137–236): does `.with_unsigned_transaction(req.transaction)`, attaches out-of-band signatures, signs with `seal_signer` (line 211), and submits (229–233). **It injects no fee.**
- The `pay_fee`-when-empty injection exists only on the immediate `handle_submit_instruction` path (`transaction.rs:87`, `pay_fee_from_component`) and `handle_submit_manifest` (`transaction.rs:508–522`), neither of which creates an approvable frozen request.
- A fee of zero is never valid (`transaction.rs:505–506`, `max_fee.max(1)`), so a fee-less frozen transaction submitted through the request path would be rejected by validators.

Therefore a submittable anchor transaction must embed its fee **before** `transaction_requests.create` — Strategy 2.

Answers to the required documentation points:

- **Fee account resolution**: the opaque project `AnchorAccountReference` is a validated string and cannot be resolved offline. The exact Ootle `ComponentAddress` is supplied by a human operator and parsed **only** at the walletd leaf, in `WalletdFeeComponentRef::parse` (`identifiers.rs`), via `ComponentAddress::from_str`. Resolution never leaks past this leaf.
- **Maximum fee enforcement**: `pay_fee_from_component(component, max_fee)` (builder `builder/mod.rs:122–124` → FeeIntent `270–272`) expands to `CallMethod { call: Address(component), method: "pay_fee", args: [Literal(Amount(max_fee))] }` in the separate `fee_instructions` list; the `pay_fee` call locks up to `max_fee`.
- **Immutability**: the fee instruction is fixed at construction and frozen at `create`; submit seals it verbatim.
- **Approval includes the fee**: yes — the approver views exactly what will be sealed, including the fee instruction.
- **Fee change ⇒ fingerprint change**: yes — the BLAKE3 inspection fingerprint is taken over the whole unsigned transaction (including `fee_instructions`), so changing the fee account or amount changes the fingerprint (proved by `fee_construction.rs::fee_account_change_changes_the_fingerprint` / `fee_amount_change_changes_the_fingerprint`).
- **Spends only the configured fee account**: the fee-bearing inspection proves exactly one `pay_fee` `CallMethod` naming the bound component, with no other fee instruction, no inputs, and exactly one anchor `EmitLog` in the normal list; nothing else is touched.
- **No unrelated account/resource touched**: inputs are intentionally empty (built without auto-fill; `add_inputs_for_instruction` only runs when `fill_inputs`, `builder/mod.rs:870–873`), and the normal list is still exactly the one anchor log.

The change does not weaken the Slice 4A5 rule that the normal instruction list holds exactly one anchor `EmitLog`. No private-key custody is required at any point.

## 4. Exact walletd submit/status APIs (pinned rev `92023e0`, `tari_ootle_walletd_client` v0.37.0)

- `submit_transaction_request` — `clients/wallet_daemon_client/src/lib.rs:392–397` (`transaction_requests.submit`). Request `TransactionRequestSubmitRequest { request_id }` (`types.rs:288–292`); response `TransactionRequestSubmitResponse { transaction_id: TransactionId }` (`types.rs:294–298`).
- `get_transaction_request` — `lib.rs:362–367` (`transaction_requests.get`). Response `TransactionRequestGetResponse { request: TransactionRequestInfo }` with `status: EffectiveStatus` and `transaction_id: Option<TransactionId>` (`types.rs:227–247`).
- `TransactionId` is `[u8; 32]` (`crates/transaction/src/transaction_id.rs:35`), `Display` = 64 lowercase hex (`100–104`) → safely canonicalized to `AnchorTransactionId`.
- `EffectiveStatus` = `{ Pending, Approved, Rejected, Submitting, Submitted, Expired }` (`crates/wallet/sdk/src/models/transaction_request.rs:73–85`); a `Submitted`/`Rejected` request stays terminal, others derive `Expired` past the window (`effective_status`, 124–133).

## 5. Submission input/output

- Input: `WalletdSubmitRequestV1 { project_request_id, walletd_request_id, binding }` — carries **no** transaction id (structurally prevents a caller-supplied id, Section E). Before the client is touched, `submit` requires: the request exists, is approved (not prepared/rejected/expired), the submission state is not unknown, and every binding field (network, account, digest, payload, max fee, fingerprint) and both identifiers match.
- Output: `SubmittedWalletdAnchorRequestV1 { project_request_id, walletd_request_id, transaction_id, binding, state: Submitted }`. It claims no acceptance, finalization, receipt, or finality. The account reference and walletd request id redact their own `Debug`.

## 6. Transaction-ID binding

The transaction id is obtained only from the submit response (walletd sealed it) or recovered from the status API; it is never computed from unsigned bytes. Proven by `submit_recover.rs`: exactly one id in `Submitted` state, the id stays bound to the approved request, wrong network/account/digest/fee/fingerprint reject before submit, an id from another request cannot be attached (`ConflictingTransactionId`), the id cannot be caller-supplied (no field), and the id survives restart/recovery. The fake derives a fake id under a separate `.../transaction-id/v1` domain.

## 7. Timeout / unknown behaviour

A submit timeout (or malformed response) marks the request `TimedOutUnknown`, never `Rejected`, preserving the walletd request id and all bindings. No automatic resubmission occurs: a submit in the unknown state returns `SubmissionStateUnknown`, so retry must begin with `recover`. `recover` maps the observed status: `Submitted` (+id) ⇒ `Unknown → Submitted`; `Approved` ⇒ safe controlled retry (`NotSubmittedRetryable`); `Submitting` ⇒ still in flight; `Pending`/`Rejected`/`Expired` mapped accordingly. `WalletdUnavailable` never marks unknown (nothing was sealed), so the approval survives. Defined outcomes: submit timeout, walletd unavailable, malformed submit response, unknown request, status unavailable, submitted-but-id-missing, conflicting id, duplicate/already-submitted, rejected/expired.

## 8. Duplicate-submission behaviour

Confirmed from source: `handle_submit`'s conditional `Approved -> Submitting` transition lets exactly one caller through; a repeat (now `Submitting`/`Submitted`) fails the transition and produces neither the same id nor a second transaction. The adapter therefore: (a) returns the bound id **idempotently** and skips the client entirely when the request is already locally `Submitted`; (b) refuses a blind resubmit in the unknown state and requires recovery; (c) recovers the original id through the status API. The fake seals at most one transaction per request and exposes `submit_calls`, proving no second anchor transaction is created (`duplicate_submit_*`, `conflicting_recovered_transaction_id_is_rejected`).

## 9. Recovery / status mapping

`recover` re-verifies the full binding before the client is touched (a mismatched binding is a security error — `FingerprintMismatch`, caught with `get_calls == 0`), re-checks the returned frozen transaction's fingerprint against the bound one, records the last effective status, and maps status → `WalletdRecoveryStateV1`. A recovered id that conflicts with a locally bound one is rejected (`ConflictingTransactionId`); a `Submitted` status without an id is `SubmittedButTransactionIdMissing`.

## 10. Registry / snapshot changes

Each record now stores submission state (`NotSubmitted`/`TimedOutUnknown`/`Submitted`), the transaction id if known, the last confirmed effective status, and a recovery-gated retry count, all threaded through `WalletdAnchorSnapshotV1` and `from_snapshots`. No secret material and no signed transaction bytes are stored. Canonical disk persistence remains deferred (the deterministic snapshot + import proves restart safety offline).

## 11. Fake behaviour

The deterministic fake now covers: submit success, submit timeout before processing (untouched request), submit timeout after processing (sealed but response lost), malformed response, duplicate submission (already-submitted), transaction-id recovery, conflicting id (`force_transaction_id`), walletd unavailable, request not found, rejected, expired, and restart/import. It uses no randomness, derives fake ids under a fake-only domain, creates at most one fake transaction per request, exposes call counts/captured calls, never signs with real keys, never produces a real Ootle transaction, and never claims finality.

## 12. Mutation and archive-independence tests

`submit_recover.rs` rejects — before any client call — a wrong project/walletd request id, wrong network/account/digest/payload/max-fee/fingerprint, an unapproved/rejected/expired request, a caller-supplied id (structural), and a conflicting recovered id; no invalid case panics. `archive_independence.rs::submission_and_recovery_never_mutate_archive_artifacts` proves byte-identical `OotleAnchorRecordV1`, `ArchiveHashV1`, and `ManifestHash` across successful submission, idempotent duplicate, timeout+recovery, walletd-unavailable, conflicting-id rejection, and restart import.

## 13. Dependency / feature audit

- Walletd client: `tari_ootle_walletd_client v0.37.0`, git rev `92023e0` (`92023e0b7c2fabf7df2f8ee23a2cc252d3c34f9f`). Same exact revision reused; no branch/tag/floating HEAD.
- New direct dependencies at this leaf: `tari_template_lib_types` and `tari_ootle_transaction`, both git rev `92023e0` (already present transitively/as dev-deps). **Cargo.lock is unchanged** — no new crate entered the graph, so no network resolution was needed.
- Runtime/HTTP/TLS graph: `reqwest v0.13.4`, `tokio v1.53.1`, `rustls v0.23.43` (+ `hyper-rustls`, `tokio-rustls`, `openssl` on some transitive edges) enter **only** through `tari_ootle_walletd_client` (the real async client), exactly as in Slice 4A6A. This slice owns no runtime, starts no task, and every test uses the offline fake.
- Signing crates transitively present: `tari_crypto v0.23.2` (via the walletd client). This project calls **no** signing or key-derivation API: the seal signer only produces a `KeyId` handle, and `canonicalize_transaction_id` only hex-encodes 32 bytes. No private-key type appears in the public API.
- No network call occurred during tests (offline fake only; `--offline` throughout).

## 14. Toolchain result

All Ootle-dependent commands ran on Rust 1.97.1 MSVC (`+stable-x86_64-pc-windows-msvc`), `--locked --offline`. Clean.

## 15. Targeted / workspace validation (all pass)

- rustfmt: clean on both changed crates (`--check` produced no diff).
- 4A6B walletd suite (`submit_recover` 19, `mutation_safety` 16, `prepare_approve_reject` 7, `archive_independence` 2, `parity` 1, `reinspection_gate` 2, lib 0).
- 4A5 suite incl. new `fee_construction` (9) and regressions (`construction` 7, `inspection_mutations` 15, `network_mapping` 6, `archive_independence` 1, `dependency_audit` 2, `fake_real_parity` 2).
- 4A4 anchor-transport, anchor, protocol regressions: pass.
- Workspace `cargo check --workspace`: clean (only a pre-existing dead-code warning in vendored `triptych`).
- Workspace tests excluding the heavy `cli` real-Triptych/padding/timing suites: pass.
- Strict Clippy `-D warnings` on both changed crates (`--all-targets`): clean.
- Offline `cargo tree` feature audit: as recorded in §13.

Deliberately not run (per the task): any real walletd call, transaction submission, indexer query, the large election suite, the long padding suite, timing tests, fuzz campaigns, or any network test.

## 16. Staged file count and hashes

21 files staged; `git diff --cached --check` reports no whitespace errors. Cargo.lock is **not** staged (unchanged).

Staged blob size (bytes) and SHA-256:

```
    9405  1624d68e33270afe3cbe0288fe5ae72938033f5de2949ab77bacc56d95759048  crates/ootle-anchor-adapter/src/build.rs
    7775  c96a1e61d3e788a44b67da442b023ecb2116dbe9040aee9dc9cd3834fa9d59a6  crates/ootle-anchor-adapter/src/errors.rs
    4449  31a6bbc8151efbb0d352b92bfe668295f2182803f1f1e7f0da25c8044c94f5c0  crates/ootle-anchor-adapter/src/evidence.rs
   16709  e41a0e86c256af5a3542118d88f61fce7940948da52cdf6a10ba1900dfe74456  crates/ootle-anchor-adapter/src/inspect.rs
    2355  16b8b1a03b16d10bab4eae55f11cbbbf50d88a4929e92d9938d0ced26a4f36e9  crates/ootle-anchor-adapter/src/lib.rs
    6881  9a0838038084b1f796e0fa6c908d721c6ccddc991772df84184fd9bde776370d  crates/ootle-anchor-adapter/tests/fee_construction.rs
    3271  959fee82716c0ecef1910a4ceed8529efd76f7bf765f961adaa69e6081a0e07c  crates/ootle-walletd-anchor-adapter/Cargo.toml
   11416  da6f5f245581fa9b86c4eb8eca37415d1a192691c440734d9153a86973a014c9  crates/ootle-walletd-anchor-adapter/src/client.rs
   11789  96c2298a893190cb571a7447cf0a20b25dc5fa2e09a70c7d14f0a82709f886bd  crates/ootle-walletd-anchor-adapter/src/convert.rs
   32861  a90facf48d9ce569a1267ef0fafe65372eaa21098f12f859b6dc660316b30e4c  crates/ootle-walletd-anchor-adapter/src/coordinator.rs
    6991  86c178ee60c666b3a593e7e188fce6f3281b3c56cdfb18647e91d106433f84bc  crates/ootle-walletd-anchor-adapter/src/errors.rs
   17310  a0aa814d29f67003f743cff9e9370ccde97c36389fac5a08505115a8257d0a54  crates/ootle-walletd-anchor-adapter/src/fake.rs
    6582  d0258ef55a503865cbb1d0e72b4e0ca44f3442c1c2538335d251549e9462445f  crates/ootle-walletd-anchor-adapter/src/identifiers.rs
    5156  6c8784b67974ec043890ccd1409bc9f6ca9f892fedb9a6e1414b9ca75a1fc7cb  crates/ootle-walletd-anchor-adapter/src/lib.rs
   14321  369f1654f19b064aa29a17e9dbfd7de125c90186fc038507f5f6339a56808834  crates/ootle-walletd-anchor-adapter/src/registry.rs
   13955  7b77f1f3ed92ceb717539bf50d170d7b104aaa59d00334c0cac67cd1043e4211  crates/ootle-walletd-anchor-adapter/src/results.rs
   10308  7b2e1c0db1fc586d996fec814a35bf381382248a3cb71c5311c0129e65339c39  crates/ootle-walletd-anchor-adapter/tests/archive_independence.rs
    4679  74e52e281aca907b59d06dddb247ee7a90f4167a530d23562f01500c1fe2f087  crates/ootle-walletd-anchor-adapter/tests/common/mod.rs
    7199  5676fa5d8fef72dfda8d80fa849682b197ab2cd2391415c9dc7a8b430f30250e  crates/ootle-walletd-anchor-adapter/tests/prepare_approve_reject.rs
   22373  9a1bccad2d6b00c28138748e78b9bbbe082d234936d1ffd91468d24fa9daafa3  crates/ootle-walletd-anchor-adapter/tests/submit_recover.rs
   17688  56c0c19af9cec8544511657991c6fc5de5b38442f9fa803958748cd82235513b  docs/reviews/PHASE4_SLICE4A6B_WALLETD_SUBMISSION_RECOVERY_2026-08-05.md
```

Binary staged patch (`git diff --cached --binary`): size 153027 bytes, SHA-256 `9dc99d9ca5ac6f025cc34fbcfbbf3a5dd3b6247b302a2889870ac245b85358fe`.

(The `docs/reviews` blob hash above is for the copy at staging time, before this staging table was appended.)

## 17. No commit created

No commit was created. The change is staged only.

## 18. No network contact

No network contact occurred. All Cargo operations used `--locked --offline`; Cargo.lock was unchanged; every test used the offline fake.

## 19. No transaction submitted

No transaction was submitted. No walletd, indexer, or network endpoint was contacted; no testnet funds were spent.

## 20. Evidence-file path

`docs/reviews/PHASE4_SLICE4A6B_WALLETD_SUBMISSION_RECOVERY_2026-08-05.md` (this file).

## 21. Go / no-go for Slice 4A7 (receipt retrieval and verification)

**Go.** The fee strategy is settled from source (Strategy 2), submission and transaction-id recovery are modelled safely and offline, and the transaction id now reaches a project-owned `Submitted` result and survives restart. Slice 4A7 can build on `SubmittedWalletdAnchorRequestV1`/`RecoveredWalletdAnchorRequestV1.transaction_id()` to retrieve and verify a finalized receipt. Open follow-ups for 4A7: a real async walletd client bridging to this synchronous boundary (using `canonicalize_transaction_id`); the confirmed receipt/indexer retrieval API; and receipt-log verification against the anchor `EmitLog`. This slice deliberately stops at submission and transaction-id recovery and makes no finality claim.
