# Ootle Coupling Inventory (Stage 1 audit)

**Baseline:** `origin/main 47f7760` (`chore: update Private Ballot for v0.42 Esmeralda deployment` `de61cd7`).
**Method:** `rg` over `Cargo.toml`/`*.rs`/`*.ts`/`*.json`/`*.md`, excluding `target/` build outputs and `templates/**/target/`. File:line cites every claim. The developer prompt categories A–I are used below.

## Dependency pins (E — deployment configuration)

| Location | Current | Target (Stage 1) |
|---|---|---|
| `crates/ootle-anchor-adapter/Cargo.toml:22-28,45-46` | git rev `a43773e600b9503ed3fadcd3f0048f86131e3644` (v0.42 cohort), `tari_ootle_transaction` + `tari_template_lib_types`, `minicbor = 2.2` | git rev `9f03f90b9a8803b66a3fa63a29fb905d2ba20178` (v0.51.0 tag), `minicbor 2.3` |
| `crates/ootle-walletd-anchor-adapter/Cargo.toml:24-41` | same rev: `tari_ootle_walletd_client`, `tari_ootle_wallet_sdk`, `tari_template_lib_types`, `tari_ootle_transaction` | same rev bump |
| `crates/ootle-receipt-anchor-adapter/Cargo.toml:28-47,62-65` | same rev: `tari_ootle_transaction`, `tari_template_lib_types`, `tari_engine_types`, `tari_indexer_client` (default-features=false) | same rev bump |
| `crates/ootle-anchor-network-adapters/Cargo.toml:30-56` | same rev: `tari_ootle_walletd_client`, `tari_ootle_wallet_sdk`, `tari_ootle_transaction` (serde), `tari_template_lib_types`, `tari_engine_types`, `tari_indexer_client`, `tari_consensus_types` | same rev bump |
| `templates/ootle-anchor-event-template-v2/Cargo.toml:16` | `tari_template_lib = "=0.33.0"` (v0.42 cohort) | `"=0.39.0"` |
| `templates/ootle-anchor-event-template/Cargo.toml:12` | `tari_template_lib = "=0.31.1"` (v0.39.2) | **Frozen historical baseline — do not bump.** Retained only as V1 compatibility evidence. |

## What already exists (proof, not rewriting)

- **No GraphQL (C/D — indexer/wallet adapter).** `rg -i graphql` across the repo (excluding `target/`, `.git/`) returns **zero hits**. Production indexer access is REST via `tari_indexer_client::IndexerRestApiClient` (`crates/ootle-anchor-network-adapters/src/indexer.rs`) + the offline `GetTransactionReceiptResponse` conversion seam (`crates/ootle-receipt-anchor-adapter/src/convert.rs`). The v0.46 “GraphQL removed” migration is therefore **already satisfied** — prove by keeping this grep in CI.
- **No transaction return values (B — network adapter).** The anchor is a fire-and-forget `publish_anchor_v2` event emitter (`templates/ootle-anchor-event-template-v2/src/lib.rs`: four `String` args, no return). Reads go through receipts/events (`crates/ootle-receipt-anchor-adapter/src/{convert,retrieve,query}.rs`), not return values. Matches the v0.46 removal rule.
- **CBOR event metadata already handled (D).** `crates/ootle-receipt-anchor-adapter/src/convert.rs:150,428-449` implements the v0.42 PR #2679 CBOR (`RawCbor`) model: metadata values are CBOR text strings, decoded centrally. The v0.50 Protocol V1 CBOR-hash change lands in the same central seam — no domain code parses wire CBOR.
- **Verified-read posture (B/D).** `crates/ootle-anchor-network-adapters/src/indexer.rs` maps `tari_consensus_types::Decision` (Commit/Abort) to full acceptance vs rejection, and `crates/ootle-receipt-anchor-adapter` compares walletd vs indexer observations (`compare_walletd_and_indexer`). The adapter must name the v0.50 `IndexerTrust::Verify` equivalent explicitly after the bump (compile will surface it).
- **Walletd JSON-RPC (C).** `crates/ootle-walletd-anchor-adapter/src/{client,convert,coordinator}.rs` + `crates/ootle-anchor-network-adapters/src/walletd.rs` use `tari_ootle_walletd_client::WalletDaemonClient` for `transaction_requests.create/approve/reject` + status poll. **No** `nfts.list` and **no** `signing_requests:approve` (the two v0.51 walletd permission breakers) — grep confirms; the bump does not force a permission change.
- **Circuit breakers already present:** `crates/ootle-anchor-adapter/src/{build.rs,inspect.rs,event_instruction.rs}` enforce the fee-less unsigned-transaction inspection fingerprint, template-binding parse (`template_` prefix strip, `event_instruction.rs:13-26`), epoch/network binding, and the re-inspection gate before any walletd request (`crates/ootle-walletd-anchor-adapter/src/coordinator.rs:281` + `convert.rs:125`). These are the “centralized decoding/validation” the prompt asks for — Phase 4 documents them as the adapter rather than re-creating them.

## Classification by file (A–I)

**A — protocol logic** (must not change ABI/digest semantics):
- `templates/ootle-anchor-event-template-v2/src/lib.rs` — `publish_anchor_v2(anchor_digest, network, election_id, public_summary)`, `ANCHOR_EVENT_TOPIC_V2 = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2"`, keys `anchor_digest_v2`/`network`/`election_id`/`public_summary`, `MAX_PUBLIC_SUMMARY_LEN = 256*1024`. **Frozen except `tari_template_lib` version.**
- `crates/anchor`, `crates/anchor-transport`, `crates/ballot`, `crates/crypto`, `crates/protocol`, `crates/tally`, `crates/verifier`, `crates/archive` — no `tari_*` deps (verify: `rg "tari_" crates/<c>/Cargo.toml` empty). Portable domain core (see `docs/architecture/PORTABLE_CORE.md`).

**B — network adapter:** `crates/ootle-anchor-network-adapters/src/{indexer.rs,walletd.rs,endpoint.rs,config.rs,executor.rs,auth.rs}`, `crates/ootle-anchor-app` (async runtime bridge; `Cargo.toml:20` — `net` feature → Tokio I/O for reqwest; this crate **creates** the runtime, the adapters do not).

**C — wallet adapter:** `crates/ootle-walletd-anchor-adapter/src/{binding.rs,client.rs,convert.rs,coordinator.rs,registry.rs,status.rs,identifiers.rs}`.

**D — indexer adapter:** `crates/ootle-receipt-anchor-adapter/src/{convert.rs,client.rs,retrieve.rs,query.rs,state.rs,address.rs}` + `crates/ootle-anchor-network-adapters/src/indexer.rs`.

**E — deployment configuration:**
- `templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md` + `template_metadata.{cbor,json}` + `Cargo.lock`
- `gui/src/api/types.ts:505` — “Published v0.39.2 event-template address for the selected network” (stale comment; type is a string, not hard-coded — must track the registry)
- `crates/gui-core/tests/trusted_anchor_deployment.rs` (schema `TARI_CC_PRIVATE_BALLOT_TRUSTED_OOTLE_DEPLOYMENT_V2`, sample `template_2222...`, `template_6666...`) — **test fixture (I)** for the trusted lock, to be migrated (not rewritten) by the deployment registry
- `crates/gui-core/tests/live_v2_anchor_esmeralda.rs:170` — `PRIVATE_BALLOT_V2_TEMPLATE_ADDRESS` env or `DEFAULT_TEMPLATE_ADDRESS` — the one place a reset today requires a source/constant edit; Phase 6 replaces it with registry resolution
- `README.md:140`, `docs/OPERATOR_SETUP.md:32,125`, `THIRD_PARTY_NOTICES.md:127` — docs say “walletd v0.42.0 on Esmeralda”; Phase 18 updates these to the v0.51.0 cohort

**F — desktop-only concern:** `gui/src-tauri/` (`walletd_credential_store.rs` OS keyring, `walletd_probe.rs:8` `/json_rpc` note), `crates/transport-network`, `crates/transport-gateway`, `crates/cli` — no Ootle template logic; must not be imported by the portable core or the hosted backend.

**G — portable/browser-safe logic:** `crates/{anchor,anchor-transport,archive,ballot,crypto,protocol,registry,tally,verifier}` + `crates/ootle-anchor-adapter`'s pure build/inspect (it depends on `tari_ootle_transaction` for the `UnsignedTransaction` type — the only non-portable part of the “core” adapter; Phase 14 assesses WASM portability).

**H — historical documentation:** `docs/reviews/PHASE4_SLICE4A*_*.md` (v0.37.0/`92023e0`, v0.39.2), `docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md` (v0.42 artifact 61479 bytes, v0.39.2 60714 bytes), `templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md:169` (v0.39.2 artifact). **Do not edit historical evidence.** The registry keeps them as `HISTORICAL`/`SUPERSEDED`.

**I — test fixtures:** `crates/{ootle-anchor-adapter,ootle-walletd-anchor-adapter,ootle-receipt-anchor-adapter,ootle-anchor-network-adapters,ootle-anchor-lifecycle}/tests/common/mod.rs`, `crates/ootle-receipt-anchor-adapter/src/scenarios.rs`, `tests/trusted_anchor_deployment.rs`, `tests/live_*.rs`. They use synthetic `template_1111...`/`template_2222...`/`template_4444...`/`template_6666...` — **not** real deployments. They survive the pin bump unchanged in spirit; only the git rev line changes.

## Where a future reset would require source edits today (to be fixed by Phases 4–6)

1. **Git rev lines** in 4 `crates/ootle-*/Cargo.toml` files + 1 template `Cargo.toml` — a cohort bump is a 5-line edit today; Phase 3 centralizes the rev in one `Cargo.toml` workspace `[patch]`/workspace-dependency table so the registry + runbook can name the cohort without archaeology. (Accepted: still a build-time constant; the *runtime* deployment identity moves to the registry.)
2. **`DEFAULT_TEMPLATE_ADDRESS` in `crates/gui-core/tests/live_v2_anchor_esmeralda.rs`** — runtime default; Phase 6 replaces resolution with the registry (fail-closed on missing/multiple `CURRENT`).
3. **Doc constants** (`README`, `OPERATOR_SETUP`, `ManageElection.tsx:224` fee comment) — Phase 18.
4. **`minicbor 2.2` pin** in `crates/ootle-anchor-adapter/Cargo.toml` vs upstream `2.3.1` — Phase 3 alignment (compile-enforced).

## Verdict

The repo is already architecturally close to the prompt's target: REST-not-GraphQL, no return values, CBOR event metadata via a central converter, fee-less inspection + re-inspection gates, walletd/indexer comparison. The missing pieces are (a) the v0.51.0 cohort bump, (b) a first-class deployment registry replacing the trusted-lock singletons, (c) an explicit codec/version-detection boundary for CBOR/base64-CBOR, and (d) the hosted-mode skeleton/docs. Phases 3–8 deliver exactly those, without touching the frozen protocol semantics.
