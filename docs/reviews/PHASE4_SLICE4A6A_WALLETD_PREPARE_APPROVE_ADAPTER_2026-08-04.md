# Phase 4 — Slice 4A6A: Pinned Walletd Prepare and Approval Adapter

**Date:** 2026-08-04
**Mode:** Implement, validate, and stage (no commit).

---

## 1. Starting branch and HEAD

- **Branch:** `phase4/ootle-testnet-anchor-prototype`
- **Required starting HEAD:** `131b901948e8420432c47fca1069de3c13d7c509` (confirmed clean before work).
- **Toolchain:** Rust `1.97.1`. Ootle-dependent build/test/Clippy ran under the installed
  **MSVC** toolchain `stable-x86_64-pc-windows-msvc` (`rustc 1.97.1 (8bab26f4f 2026-07-14)`).
  The repository's `rust-toolchain.toml` pins channel `1.97.1`, whose default host on this
  machine is `x86_64-pc-windows-gnu`; the GNU toolchain lacks the MinGW `as.exe` that
  `getrandom`'s raw-dylib code generation requires, so every Ootle-dependent Cargo command was
  invoked with `+stable-x86_64-pc-windows-msvc`.

All Cargo operations used `--offline` and (after the initial lockfile resolution) `--locked`.
No network was contacted.

---

## 2. Files changed

New leaf crate `crates/ootle-walletd-anchor-adapter` (package
`tari-cc-private-ballot-ootle-walletd-anchor-adapter`):

| File | Purpose |
|------|---------|
| `Cargo.toml` | Crate manifest and pinned dependencies. |
| `src/lib.rs` | Crate docs, module wiring, public re-exports. |
| `src/errors.rs` | Section H — narrow, bounded `WalletdAnchorAdapterError`. |
| `src/identifiers.rs` | `WalletdRequestId` (redacted), `WalletdSealSignerRef` → `KeyId`. |
| `src/status.rs` | `WalletdEffectiveStatusV1` project mirror of `EffectiveStatus`. |
| `src/binding.rs` | `WalletdAnchorBindingV1` + field-by-field `ensure_matches`. |
| `src/convert.rs` | Section B — build result → `TransactionRequestCreateRequest`. |
| `src/client.rs` | Section A — narrow `WalletdAnchorClient` boundary + DTOs. |
| `src/results.rs` | Sections C/D/E/F — prepared/approved/rejected results + summary. |
| `src/registry.rs` | Section G — in-memory registry + `WalletdAnchorSnapshotV1`. |
| `src/coordinator.rs` | Sections C/E/F/G — prepare/approve/reject orchestration. |
| `src/fake.rs` | Section I — deterministic offline `FakeWalletdAnchorClient`. |
| `tests/common/mod.rs` | Shared deterministic constructors. |
| `tests/prepare_approve_reject.rs` | Happy path, summary vector, registry, restart. |
| `tests/mutation_safety.rs` | Sections E/F/H/K binding, state, client-failure rejections. |
| `tests/parity.rs` | Section J real/fake conversion parity. |
| `tests/reinspection_gate.rs` | Section K — the re-run 4A5 safety gate is live. |
| `tests/archive_independence.rs` | Section M — archive/anchor artifacts never mutated. |

Root workspace edits:

- `Cargo.toml` — added `crates/ootle-walletd-anchor-adapter` to `members`.
- `Cargo.lock` — new locked entries for the walletd client dependency closure.

**No Phase 1–3 source changed. No vendored Triptych changed. No anchor / anchor-transport /
Slice 4A5 semantics changed.**

---

## 3. Exact walletd API / version / revision

- **Package:** `tari_ootle_walletd_client` **v0.37.0**
- **Source:** git `https://github.com/tari-project/tari-ootle`, **rev `92023e0`**
  (full: `92023e0b7c2fabf7df2f8ee23a2cc252d3c34f9f`) — the exact revision used by Slice 4A5.
- **Local checkout inspected:**
  `<local cargo git checkout of tari-ootle @ 92023e0>`
  (`git rev-parse HEAD` = `92023e0b7c2fabf7df2f8ee23a2cc252d3c34f9f`).

Confirmed method signatures (`clients/wallet_daemon_client/src/lib.rs`), all `async fn` on
`&mut WalletDaemonClient`, generic over `Borrow<T>`:

| Method (line) | RPC | Request | Response |
|---|---|---|---|
| `create_transaction_request` (355) | `transaction_requests.create` | `TransactionRequestCreateRequest` | `TransactionRequestCreateResponse` |
| `get_transaction_request` (362) | `transaction_requests.get` | `TransactionRequestGetRequest` | `TransactionRequestGetResponse` |
| `list_transaction_requests` (369) | `transaction_requests.list` | `TransactionRequestListRequest` | `TransactionRequestListResponse` |
| `approve_transaction_request` (376) | `transaction_requests.approve` | `TransactionRequestDecisionRequest` | `TransactionRequestDecisionResponse` |
| `reject_transaction_request` (384) | `transaction_requests.reject` | `TransactionRequestDecisionRequest` | `TransactionRequestDecisionResponse` |
| `submit_transaction_request` (392) | `transaction_requests.submit` | `TransactionRequestSubmitRequest` | `TransactionRequestSubmitResponse` *(4A6B, not used here)* |

Confirmed request/response structures (`clients/wallet_daemon_client/src/types.rs`):

- `TransactionRequestCreateRequest` (line 144): `transaction: UnsignedTransaction`,
  `seal_signer: KeyId`, `other_signers: Vec<KeyId>`, `signatures: Vec<TransactionSignature>`,
  `lock_ids: Vec<WalletLockId>`, `ttl_secs: Option<u64>`. The doc comment states the transaction
  is **stored verbatim and frozen**; walletd does not alter it.
- `TransactionRequestCreateResponse` (line 201): `request_id: TransactionRequestId`,
  `expires_at: i64`.
- `TransactionRequestDecisionRequest` (line 277): `request_id: TransactionRequestId`.
- `TransactionRequestDecisionResponse` (line 283): `request_id: TransactionRequestId`,
  `status: EffectiveStatus` — **no transaction identifier** (approval never seals).
- `TransactionRequestGetResponse` (line 257): `request: TransactionRequestInfo` whose
  `transaction_id: Option<TransactionId>` is `None` until submit.

Supporting types (`crates/wallet/sdk/src/models/`):

- `TransactionRequestId = i32` (`transaction_request.rs:13`) — treated as an opaque, bounded handle.
- `EffectiveStatus` (`transaction_request.rs:73`): `Pending | Approved | Rejected | Submitting |
  Submitted | Expired`.
- `KeyId` (`key.rs:348`): `Derived { key_branch: KeyBranch, index: u64 } | Imported { local_key_id: u64 }`
  — a **reference only**, no key material.

### Material-difference assessment (precondition step 11 / stop condition)

The confirmed **create → freeze → approve/reject → submit** lifecycle matches the inventory
exactly (method names, the "stored verbatim/frozen" semantics, the opaque request id, the
status enum, and the fact that only submit produces a transaction id).

One nuance was recorded and handled rather than treated as a blocking material difference:
`TransactionRequestCreateRequest` carries **no `fee_account`/`max_fee` fields**. Those fields
belong to `CallInstructionRequest` (line 111), which is the immediate
`transactions.submit_instruction` path — a path that submits at once and does **not** create an
approvable frozen request, so it cannot support this slice's approve/reject gate. The frozen
create path instead stores a complete `UnsignedTransaction` plus a `seal_signer` key handle.

Because the Slice 4A5 transaction is deliberately fee-less, this adapter preserves the project's
fee account and maximum fee as **project-owned binding metadata** (surfaced in the human-review
summary and enforced at approval), and does **not** invent fee instructions or inject them into
the wire request. How the fee is actually paid at submit is a Slice 4A6B question — see §22.

---

## 4. Dependency / feature audit

Established offline from the existing local Cargo cache (`cargo generate-lockfile --offline`
locked **443 packages** with no network access; every required crate version was already
extracted under `~/.cargo/registry`). All subsequent commands used `--locked --offline`.

**Direct dependencies of the new crate** (`cargo tree --depth 1 --edges normal`):

- `tari-cc-private-ballot-anchor`, `tari-cc-private-ballot-anchor-transport`,
  `tari-cc-private-ballot-ootle-anchor-adapter`, `tari-cc-private-ballot-protocol` (project paths)
- `tari_ootle_walletd_client v0.37.0` (git rev `92023e0`) — the confirmed wire types
- `tari_ootle_wallet_sdk v0.37.0` (git rev `92023e0`) — **type-only**, to name `KeyId` /
  `EffectiveStatus` / `TransactionRequestId`; no signing or key-derivation API is called.

Dev-only: the project path crates + `tari-cc-private-ballot-archive` (archive-independence) and
`tari_ootle_transaction` / `tari_template_lib_types` (mutation gate), all pinned to rev `92023e0`.

**Async / transport / TLS — introduced transitively only** (via `tari_ootle_walletd_client`;
`cargo tree --invert` confirms none is a direct project dependency):

| Crate | Version | Reached via |
|---|---|---|
| `tokio` | 1.53.1 | `reqwest`→`hyper`→`h2`/`hyper-util` |
| `reqwest` | 0.13.4 | `tari_ootle_walletd_client` |
| `hyper` | 1.11.0 | `reqwest` |
| `hyper-rustls` | 0.27.9 | `reqwest` |
| `rustls` | 0.23.43 | `hyper-rustls` (+ `native-tls`/`schannel` present) |
| `h2` | 0.4.15 | `reqwest` |

**Key / signing crates — present transitively only** (via `tari_ootle_wallet_sdk` /
`tari_ootle_walletd_client`; none is a direct project dependency):
`tari_ootle_wallet_crypto 0.38.0`, `tari_crypto 0.23.2`, `curve25519-dalek`, `argon2`,
`password-hash`, `keyring-core 1.0.0`, `webauthn-rs 0.5.5`. `tari_indexer_client 0.36.0` is pulled
transitively by the wallet SDK and is **not** a direct dependency (no indexer client was added).

**Feature graph note:** the walletd client is used with default features (no `ts`/`ts-rs`
codegen). No database crate is a direct dependency. No project dependency requires local signing
or private-key custody to prepare or approve a request (`seal_signer` is a `KeyId` handle).

**Confirmations:** this project calls no signing API, and no private-key/wallet-SDK type appears
in the public adapter API (`KeyId` is produced internally from the project-owned
`WalletdSealSignerRef` only when assembling the wire request).

---

## 5. Preparation conversion (Section B)

`build_walletd_create_request(build_result, seal_signer, ttl_secs)`:

1. Re-runs the **exact Slice 4A5 inspector** (`inspect_unsigned_anchor_transaction`) over
   `build_result.unsigned_transaction()` with an expectation rebuilt from the build result's own
   walletd-preparation DTO; any rejection maps to `UnsafeUnsignedTransaction(<bounded 4A5 error>)`.
2. Asserts the fresh inspection fingerprint equals the build result's recorded fingerprint.
3. Builds the exact `TransactionRequestCreateRequest` from the **preconstructed unsigned
   transaction** (cloned verbatim), a `seal_signer` `KeyId` derived from the project seal-signer
   reference, and empty `other_signers`/`signatures`/`lock_ids`. No anchor hashing or payload
   formatting is duplicated; the single `EmitLog` from 4A5 is preserved byte-for-byte.
4. Derives a deterministic project request id (BLAKE3 under a dedicated domain frame over the
   network, account, digest, and fingerprint).

The wire request is reachable only through this leaf crate (`WalletdCreateAnchorRequestV1::wire_request`),
mirroring how Slice 4A5 exposes its unsigned transaction. No core project crate depends on it.

---

## 6. Fee / account / network binding (Sections B, E)

`WalletdAnchorBindingV1` fixes `{ network, account, anchor_digest, payload, max_fee, fingerprint }`.
`ensure_matches` compares every field and returns a distinct bounded error (network → account →
payload → digest → fee → fingerprint). No private key or mnemonic is present anywhere in the
binding, request, or public API; `KeyId` never appears in the public surface (it is produced
internally from `WalletdSealSignerRef` only when assembling the wire request).

---

## 7. Human-review summary (Section D)

`PreparedWalletdAnchorRequestV1::human_review_summary()` derives entirely from the inspected
binding: fixed pilot purpose, network, fee account, maximum fee, exact 64-hex anchor digest, the
exact tagged `EmitLog` payload, and the instruction count, plus explicit
`transaction_id=NONE_YET` and `voter_or_ballot_data=NONE`. It contains no caller prose. An exact
stable vector is asserted in `tests/prepare_approve_reject.rs::human_review_summary_is_an_exact_stable_vector`.

---

## 8. Approval behavior (Section E)

`WalletdAnchorCoordinator::approve` binds the walletd request id, project request id, network,
account, digest, payload, maximum fee, and fingerprint (via `WalletdDecisionRequestV1`). It
rejects: unknown request, id mismatch, any binding-field mismatch, already-approved,
already-rejected, and expired — all **before** the client call. The approved result claims no
signature bytes, no transaction id, no submission, and no finality (state `Approved`).

## 9. Rejection behavior (Section F)

`WalletdAnchorCoordinator::reject` distinguishes user rejection from API failure, preserves the
binding, is terminal (a rejected request can never be approved — enforced and tested), makes
repeated rejection deterministic without a second wire call, produces no transaction id, and
mutates no archive/anchor artifact.

## 10. Local request registry (Section G)

`LocalWalletdAnchorRegistry` keeps, per project request: walletd request id, frozen binding,
decision state, a deterministic registration sequence, and the last bounded diagnostic code — no
wallet secret, no archive content. `WalletdAnchorSnapshotV1` + `from_snapshots` provide a
deterministic in-memory restart/import (durable disk persistence deferred). Restart of prepared
and approved state is tested.

## 11. Error mapping (Section H)

`WalletdAnchorAdapterError` covers every required category (walletd unavailable, transport
failure, malformed response, request-creation rejected, request not found, approval rejected,
already approved, already rejected, expired, binding/network/account/payload/fee mismatch,
unsafe unsigned transaction, unsupported walletd API) plus `FingerprintMismatch` and
`RequestIdMismatch`. Every variant is bounded; the only embedded value is the already-bounded,
project-owned Slice 4A5 error. No third-party/reqwest text and no secret is ever exposed.

## 12. Offline fake behavior (Section I)

`FakeWalletdAnchorClient` implements the narrow boundary with no randomness (BLAKE3-derived,
deterministic request ids under a fake-specific frame + counter), never produces a transaction
id, never signs/submits, stores no key material, and exposes call counts and captured requests.
It supports scripted create rejection/timeout/malformed/unavailable, approve/reject success and
failure injection, forced expiry, unknown request, and transport errors.

## 13. Real / fake parity (Section J)

`tests/parity.rs` proves the real conversion (`build_walletd_create_request`) and the
fake-captured request agree on the exact `EmitLog` payload, network, fee account, maximum fee,
instruction count (1), anchor digest, and unsigned fingerprint, and that neither carries a
transaction id or finality state.

## 14. Mutation and archive-independence tests (Sections K, M)

- `tests/mutation_safety.rs` (16 tests): every binding/state/client-failure rejection; no panic.
- `tests/reinspection_gate.rs` (2 tests): the exact 4A5 inspector convert re-runs rejects a
  duplicate-anchor transaction and passes a valid one. (The pinned build result exposes no public
  mutator, so an unsafe transaction cannot reach the convert path through the public API; the full
  mutation matrix is proven by the Slice 4A5 inspection suite, regression-run below.)
- `tests/archive_independence.rs` (1 test): prepare + approve + reject + client failure + restart
  leave `OotleAnchorRecordV1` canonical bytes, `ArchiveHashV1`, `ManifestHash`, and the anchor
  digest byte-identical.

---

## 15. Toolchain result

- MSVC `stable-x86_64-pc-windows-msvc` (Rust 1.97.1) used for all Ootle-dependent operations.
- GNU limitation confirmed: missing MinGW `as.exe` for `getrandom` raw-dylib codegen.
- Async runtime introduced (transitively): `tokio` (via `reqwest`/`hyper`).
- HTTP/TLS introduced (transitively): `reqwest 0.13.x` → `hyper` → `hyper-rustls`/`rustls`
  (+ `native-tls`/`schannel` present). See §4.
- Key/signing crates present **transitively only**: `tari_ootle_wallet_crypto`, `tari_crypto`,
  `curve25519-dalek`, `argon2`, `password-hash`, `keyring-core`, `webauthn-rs`. This project
  **calls no signing API** and **no private-key type appears in the public adapter API** (the
  only wallet-SDK type touched is `KeyId`, a non-secret handle, produced internally).

## 16. Targeted / workspace validation

All under `+stable-x86_64-pc-windows-msvc`, `--offline --locked`:

| Step | Command scope | Result |
|---|---|---|
| rustfmt | new crate `--check` | clean (after auto-format) |
| new crate tests | `-p …-ootle-walletd-anchor-adapter` | **27 passed, 0 failed** |
| Slice 4A5 regression | `-p …-ootle-anchor-adapter` | 33 passed, 0 failed |
| Slice 4A4 regression | `-p …-anchor-transport` | 72 passed, 0 failed |
| anchor regression | `-p …-anchor` | 43 passed, 0 failed |
| protocol regression | `-p …-protocol` | 30 passed, 0 failed |
| workspace check | `check --workspace` | clean (1 pre-existing warning in vendored `triptych`) |
| workspace tests | `test --workspace` | **460 passed, 0 failed, 7 ignored** (long/manual suites skipped) |
| strict Clippy | `clippy -p …-ootle-walletd-anchor-adapter --all-targets -- -D warnings` | clean, exit 0 |
| dependency/feature audit | offline `cargo tree` / `--invert` | see §4 |

Not run (per instructions): real walletd calls, transaction submission, indexer queries, the
large election suite, the long padding suite, timing tests, fuzz campaigns, any network test.

New-crate test breakdown: `prepare_approve_reject` (7), `mutation_safety` (16), `parity` (1),
`reinspection_gate` (2), `archive_independence` (1) = 27.

---

## 17. Staged file count and hashes

**21 files staged**, no commit. `git diff --cached --check` is clean. No Phase 1–3 source, no
vendored Triptych, and no anchor / anchor-transport / Slice 4A5 source is among them. The
`Cargo.lock` change is additive: the walletd closure is added and existing security-sensitive
pins are preserved (e.g. `curve25519-dalek 4.1.3` unchanged, `getrandom 0.2.17` kept with a
coexisting `0.3.4` added for the closure); the Ootle git rev `92023e0` is unchanged.

Blob size (bytes) and SHA-256 of each staged file (evidence doc omitted — self-referential):

| File | Bytes | SHA-256 |
|------|------:|---------|
| `Cargo.lock` | 114163 | `406f4c6319f4ee38fafe5a8bae56b3cdff27ed664411716687d09a0c16caffd6` |
| `Cargo.toml` | 613 | `3c8c37ba9cb3d23f48f8886414a46418e952263e7f3d929177a83d600921529e` |
| `crates/ootle-walletd-anchor-adapter/Cargo.toml` | 2774 | `b0a96b87e139b7a515ca4bb45d8d05b233a8269a2cefd32e580c2b728fa7e5f0` |
| `…/src/binding.rs` | 4078 | `52923a9803ee091db79cb57bb7ba47f84c9bd25277414ce1da6686c5e8f1e862` |
| `…/src/client.rs` | 7376 | `98c8f7e61d72ac4243f47ab2ecf8bb57fbe35d91d7054f7350a0a61cdd20494a` |
| `…/src/convert.rs` | 8329 | `a3df9b6b51e450ceb681f75907834c5941910ed8e89169bd348b388059efb52c` |
| `…/src/coordinator.rs` | 15628 | `79e5b3cfa95631aae1f1b2e6f2258d1ab99ea9b78626eb7fa4cf98fd97803673` |
| `…/src/errors.rs` | 4775 | `f64a62e5dcdce04c019c15160ca28334d43839985d527257de64a173cb2d25e3` |
| `…/src/fake.rs` | 10158 | `ab06c84d2d06877a68b0f964a0811404d3006add3e88367ff26304fe8276e545` |
| `…/src/identifiers.rs` | 3176 | `af531718e655bf5d21a4b744fddc5f21a708d72639e093e7482e8840193165a1` |
| `…/src/lib.rs` | 3595 | `2d130fb785dffec4d5b7abf2feab5b9c779a60c49c5903569face47b3e6d66e7` |
| `…/src/registry.rs` | 8941 | `c8d8936fab4222e48e8281c6a668a4cb0894b7b7586c5e1c40954d0b81ff7272` |
| `…/src/results.rs` | 7073 | `8d22067b72898a50ffd66e9e4828e7a7b60fd869b6ce824d10737c57d0a4cbee` |
| `…/src/status.rs` | 2559 | `42e1f9bd22d196b30b741874dae5e046c08069763b78a2a447e0d3e6b0bb9492` |
| `…/tests/archive_independence.rs` | 5302 | `96c375eca95f7f645fb2ff9df9c84e3d403dbcaf619603ff8792689cd289a0c1` |
| `…/tests/common/mod.rs` | 3457 | `6124ecc471c4b3a9089842a5bc8854f1e525a391f7c9e86cd75282266389c6ad` |
| `…/tests/mutation_safety.rs` | 11252 | `dff5cf34cdd0041c470a643e232af006916b826e2f1852b8a699de7044abb193` |
| `…/tests/parity.rs` | 3679 | `2fc216954ddbedb0121b3173d92c1c9b341177d116d6639f965eb150202876a0` |
| `…/tests/prepare_approve_reject.rs` | 6979 | `d7a7ff83a1e05f96b094f147614498608f09c59b85bac5f4d52454666c24b4b0` |
| `…/tests/reinspection_gate.rs` | 2433 | `04f17285ac3ea0c8a60014c790beac6b20503bc7da4a27a638aec7c26fef43ad` |

**Binary patch** (`git diff --cached --binary`, before this staging section was added to the
evidence doc): size **277045 bytes**, SHA-256
`109793f385a263003d2c91facb5909152280d3eb530d5dd05478060d3d8a8bc6`. The final patch size/SHA-256
including the completed evidence doc is recomputed after the last re-stage and reported with the
run output.

---

## 18–21. Guarantees

- **18. No commit created** — work is staged only.
- **19. No network contact** — all Cargo commands used `--offline`; no walletd/indexer call.
- **20. No transaction submitted** — no signing, sealing, submission, or transaction id anywhere.
- **21. Evidence file** — this document:
  `docs/reviews/PHASE4_SLICE4A6A_WALLETD_PREPARE_APPROVE_ADAPTER_2026-08-04.md`.

---

## 22. Go / no-go recommendation for Slice 4A6B (submission and recovery)

**GO, with one design item to resolve first.**

The prepare/approve/reject lifecycle is implemented, offline-tested, and clean under strict
Clippy. The confirmed `submit_transaction_request` path (`TransactionRequestSubmitRequest{request_id}`
→ `TransactionRequestSubmitResponse{transaction_id}`) is a natural continuation of the registry and
coordinator built here.

**Blocking design item for 4A6B — fee payment on the frozen-request path.** The confirmed
`transaction_requests.create` request stores a complete `UnsignedTransaction` verbatim and does
**not** inject fees (unlike the immediate `CallInstructionRequest` path). The Slice 4A5
transaction is deliberately fee-less, so as currently frozen it would not pay a fee at submit.
Before 4A6B submits, the fee strategy must be settled — most likely a `pay_fee_from_component`
instruction added to the transaction *before* it is frozen (which requires resolving the opaque
project account to an Ootle `ComponentAddress` and re-running the 4A5 inspector with a fee-aware
expectation), or a confirmation that the walletd submit path applies `max_fee` itself. This
adapter deliberately did not invent that behavior. Everything else needed for 4A6B — opaque id
handling, request-status reads, and a deterministic restart model — is in place.
