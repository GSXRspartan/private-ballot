# Ootle Current State (Stage 1 reconnaissance)

**Date:** 2026-11-09
**Private Ballot baseline:** `origin/main` = `47f77606070a65845a5116a69c4525423af4d46e` (`fix: make V2 anchor fees resilient...`, after `chore: update Private Ballot for v0.42 Esmeralda deployment` `de61cd7`).
**Method:** `tari-project/tari-ootle` releases page + tagged `Cargo.toml` + crates.io. Commit/tag/PR cited. No guessing. Working tree clean at start; new branch `hosted-v2-stage1` from `origin/main`.

## Latest released version

| Release | Date (UTC) | Commit | Status |
|---|---|---|---|
| `v0.51.0` | 2026-11-09 13:02 | `9f03f90b9a8803b66a3fa63a29fb905d2ba20178` | Latest published (GitHub marks Pre-release) |
| `v0.50.1` | 2026-11-07 04:28 | `0b3f364dd0eaff9997b08d722948619981b62ce7` | Prior |
| `v0.50.0` | 2026-11-07 03:27 | `d3252ef11de0a4100fe0eb6c0dc6c47b2502f5cb` | Protocol V1 activation |
| `v0.47.0` | 2026-10-20 | — | Last version referenced by the original Stage 1 prompt (now superseded) |

The prompt's “v0.47 baseline / upcoming reset / CBOR unreleased” framing is **stale**. The current reality is v0.50–v0.51 with Protocol V1 already live and **no reset**.

## Dependency cohort selected for Stage 1 (v0.51.0, tagged)

From `https://github.com/tari-project/tari-ootle/blob/v0.51.0/Cargo.toml`:

| Crate | v0.51.0 workspace version | crates.io observed |
|---|---|---|
| `tari_template_lib` | `0.39.0` | `0.39.0` published 2026-11-09 |
| `tari_template_lib_types` | `0.38.0` | `0.38.0` |
| `tari_engine_types` | `0.51.0` | `0.52.0` (newer crate, treated as unreleased — see below) |
| `tari_consensus_types` | `0.51.0` | `0.52.0` (unreleased) |
| `tari_ootle_transaction` | `0.51.0` | `0.52.0` (unreleased) |
| `tari_indexer_client` | `0.52` (workspace path version; crates.io `0.51.0` line) | `0.53.0` (unreleased) |
| `tari_ootle_walletd_client` | `0.53.0` (workspace; crates.io `0.51.0` published 2026-11-02) | `0.51.0` |
| `tari_ootle_wallet_sdk` | `0.53.0` (workspace; crates.io `0.51.0`) | `0.54.0` (unreleased) |
| `tari_template_test_tooling` | `0.51.0` | `0.52.0` (unreleased) |
| `tari_template_abi` | `0.23.0` | — |

**Decision:** pin the **git cohort `9f03f90...` (v0.51.0 tag)** in Stage 1, exactly mirroring the existing `a43773e...` (v0.42) exact-revision pin pattern. Do **not** pin crates.io `0.52`/`0.53`/`0.54` — those are ahead of the tagged workspace and are treated as UNRELEASED DEVELOPMENT until a tagged release confirms them. Template `tari_template_lib = "=0.39.0"`.

## RELEASED AND REQUIRED (must handle in Stage 1)

1. **Protocol V1 live since Esmeralda epoch 12951 (2026-11-08).** v0.50.0: substate hashes commit to each value's CBOR encoding. No reset, data directories kept; a 0.49 node missing the epoch forks and must delete data + resync. PRs #3327, #3309. *Implication: CBOR hashing is live, not “upcoming.” Our CBOR codec must match the live model; fixture tests are required, not speculative.*
2. **Template definitions move to V2; rebuild + republish mandatory.** v0.50.0 (#3281, #3398): a template built against earlier `tari_template_lib` fails to load. v0.51.0 note confirms: “templates on `tari_template_lib` 0.38 keep working; 0.39 removes `Amount::is_negative`/`non_negative_checked`/`negative_checked`” (#3623). *Our template `=0.33.0` → `=0.39.0`, and the deployed v0.42 artifact is invalid on the live network.*
3. **`CallFunction` reaches only static functions; `CallMethod` only methods.** v0.50.0 (#3273): `MethodCalledAsFunction` / `FunctionCalledAsMethod`. *Our `publish_anchor_v2` is a static function — call-site must stay `call_function`.*
4. **Arithmetic/fee/call metering tightened; InputLoadTooLarge caps.** v0.50.0 (#3213, #3261, #3328, #3381, #3309): literals/blobs metered, table slot 24 pts, 4 MiB/tx + 16 MiB/block input caps, spend-script per-module fee.
5. **ootle-rs trusts indexer by default.** v0.50.0 (#3369): pass `IndexerTrust::Verify` to keep verifying receipts/substate reads. *Private Ballot never uses ootle-rs directly, but the adapter must assert verified finalization semantics — see inventory.*
6. **walletd hardening.** v0.51.0 (#3473, #3545): `nfts.list` needs `accounts:read`; API key can no longer be granted `signing_requests:approve`; refresh tokens bounded; WebRTC JSON-RPC reaches `/json_rpc` (#3593). v0.51.0 also: transaction with `min_epoch > max_epoch` is rejected (not held) (#3475). *Our walletd adapter uses `transaction_requests.create/approve/reject` + status polling; no `nfts.list` / `signing_requests:approve` usage found — prove by grep, then keep.*
7. **Validator startup constraint.** v0.51.0 (#3386): `validator_node.fee_claim_public_key` must be a wallet account key; default key fails. *Not a client concern, but documented for operator runbook.*
8. **Host SDKs must decode V2 template definition + `InputLoadTooLarge`.** v0.50.0 (#3281, #3381, #3398). *Browser/hosted assessment must note TS SDK (`@tari-project/ootle` 0.11.0) dependency.*

## RELEASED BUT OPTIONAL

- Validator seed phrase recovery (`--seed-words`, #3386), epoch-oracle configurable validator set (#3603), committee presync (#3324), weighted consensus (#3272/#3329), `ConfidentialResourceBuilder::update_metadata` (#3354), MainNet settings shipped in binary (#3269/#3322/#3374/#3383). None required for the anchor client.

## UNRELEASED DEVELOPMENT (do not pin)

- crates.io `tari_engine_types`/`tari_ootle_transaction`/`tari_consensus_types`/`tari_template_test_tooling` `0.52.0`, `tari_indexer_client` `0.53.0`, `tari_ootle_wallet_sdk` `0.54.0` — ahead of the v0.51.0 tagged workspace. Treat as development until a tagged release confirms.
- `development` branch commits after `9f03f90` (e.g. the Oct 22 2026 commits in search results predate the Nov tags — recheck the branch tip at implementation time). Do not pin development HEAD.
- The prompt's “unreleased CBOR/base64 for receipts/events/resources/dry-run/UTXOs” — now **partially released**: CBOR substate hashing is live (Protocol V1). Base64-CBOR wire variants for indexer result types remain a compatibility boundary in our adapter (see `OOTLE_RESET_COMPATIBILITY.md`), not a reason to switch production code.

## EXPECTED RESET BEHAVIOR (corrected)

- **No testnet reset in v0.50.0/v0.50.1/v0.51.0.** Explicit: “No testnet reset. Data directories are kept.” Wallet DBs migrate on first start (v0.50.1); validator DB migrates on first start (v0.51.0, #3519). The prompt's “next reset invalidates accounts/balances/template addresses” does **not** apply to the current releases.
- **But** the template **must** still be rebuilt (`0.39.0`) and republished, because V2 template definitions are the only ones the engine loads. Historical deployment identities (v0.42 artifact, addresses) are evidence, not permanent config — hence the deployment registry (Phase 6).
- A future reset remains possible and is handled by the registry + `docs/operations/OOTLE_RESET_RUNBOOK.md`, not by hard-coded addresses.

## UNKNOWN / NEEDS REVALIDATION AFTER RESET (or after live epoch)

- Whether any deployed component/template addresses from the v0.42 era are still reachable post-Protocol-V1 (requires a live read-only check; Stage 1 does **not** publish or spend).
- The exact JSON→CBOR/base64-CBOR rendering of each indexer REST result field on the live network (fixture capture required; the adapter centralizes decoding so the domain never sees raw wire forms).
- `minicbor` 2.2 vs 2.3.1 skew: upstream workspace uses `minicbor 2.3.1` (v0.51.0 Cargo.toml); Private Ballot's adapter pins `minicbor 2.2` — must be aligned during the pin bump (see Phase 3).

## Sources

- `https://github.com/tari-project/tari-ootle/releases` — v0.51.0 (`9f03f90`), v0.50.1 (`0b3f364`), v0.50.0 (`d3252ef`), v0.47.0
- `https://github.com/tari-project/tari-ootle/blob/v0.51.0/Cargo.toml` and `.../v0.50.1/Cargo.toml`
- `https://crates.io/api/v1/crates/tari_template_lib/0.39.0` (published 2026-11-09, `0b60d7c4...`)
- Key PRs cited inline: #2679 (event metadata CBOR, v0.42 already in our code), #3213/#3261/#3273/#3281/#3309/#3327/#3369/#3381/#3398 (v0.50), #3386/#3473/#3475/#3545/#3623 (v0.51)
