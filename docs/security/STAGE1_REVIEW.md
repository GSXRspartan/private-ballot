# Stage 1 Security Review (Phase 15)

Targeted architecture/security review of the Stage 1 branch (`hosted-v2-stage1`). Findings are BLOCKER / HIGH / MEDIUM / LOW / INFO. “Open” means accepted for Stage 2 with tracking; “Closed” means verified in Stage 1.

## BLOCKER

| # | Finding | Status |
|---|---|---|
| B1 | Server needs ballot plaintext | **Closed.** No API route in the skeleton accepts plaintext; `HostedStorage` stores envelopes only; the design (`HOSTED_API_V1.md`) requires browser-side cryptography. |
| B2 | Private keys leave the browser | **Closed.** No key-handling code in the hosted crate; `BROWSER_PORTABILITY.md` forbids secret export. |
| B3 | Hosted backend can silently alter voter intent | **Closed by design.** Envelopes are browser-signed; alteration breaks verification/receipt binding. Backend verification is required (Stage 2). |
| B4 | Reset binds election to wrong template | **Closed.** `DeploymentRegistry::resolve_current` fails closed on network/ABI/hash mismatch. |
| B5 | Stale deployment address accepted | **Closed.** Exactly-one-CURRENT rule; `MultipleCurrentDeployments` / `NoCurrentDeployment` are hard errors. |
| B6 | Old GraphQL path remains authoritative | **Closed.** `rg -i graphql` is empty; production uses `IndexerRestApiClient` (REST) + central CBOR converter. |
| B7 | Fail-open Ootle verification | **Closed.** `Encoded::decode` exact + bounded; `MalformedEncodedReceipt` fails closed; no random decoders. |

## HIGH

| # | Finding | Status |
|---|---|---|
| H1 | Unbounded public requests | **Closed.** `MAX_BODY_BYTES = 64 KiB` (`DefaultBodyLimit`) in the skeleton; per-route limits are Stage 2. |
| H2 | Sensitive logs | **Closed.** No request-body logging; `eprintln!` carries only service name/version; tripwire in tests. |
| H3 | Replay ambiguity / duplicate ambiguity / non-idempotent retry | **Open (Stage 2).** API design defines `receipt_id` idempotency + nullifier uniqueness; implementation is Stage 2. |
| H4 | Network mismatch | **Closed.** `observed_network_epoch` + registry network check. |
| H5 | CORS wildcard around sensitive APIs | **Closed.** No CORS layer in the skeleton (same-origin default). Stage 2 must keep it that way. |
| H6 | Backend exposed on public interface by default | **Closed.** `HostedConfig::validate` rejects non-loopback (`HOSTED_CONFIG_NON_LOOPBACK_BIND`); default `127.0.0.1:8788`. |

## MEDIUM

| # | Finding | Status |
|---|---|---|
| M1 | Missing structured error taxonomy | **Closed.** Hosted API design + `ConfigError`/`RegistryError`/`ReceiptConversionError` fixed codes. |
| M2 | Weak operational health checks | **Closed.** `/health` + `/api/v1/status` in the skeleton. |
| M3 | Stale documentation | **Closed** for the load-bearing docs (new `docs/modernization/*`, `docs/architecture/*`, `docs/hosted/*`, `docs/operations/*`); README/OPERATOR_SETUP version refs updated to the v0.51.0 cohort. |
| M4 | Missing reset migration instructions | **Closed.** `docs/operations/OOTLE_RESET_RUNBOOK.md`. |

## LOW

| # | Finding | Status |
|---|---|---|
| L1 | `tari_indexer_client` / `tari_ootle_wallet_sdk` crates.io versions (0.52/0.53/0.54) ahead of the tagged workspace | **Accepted.** Stage 1 pins the tagged git cohort `9f03f90`, not crates.io “latest,” per the “do not pin unreleased” rule. Documented in `OOTLE_CURRENT_STATE.md`. |
| L2 | Pre-existing warnings (`triptych` dead variant, `gui-core` `write_array_len` must-use, `transport-gateway` unused import) | **Accepted.** Unrelated to Stage 1; not introduced by the migration. |

## INFO

- The v0.42→v0.51 migration is unusually clean: one `Encoded` wire-type change + field additions (`receipt`, `include_proof`, `value_summaries`, `component_upgrades`, `main_signer`, `external_signers`) + two new error variants. No protocol-semantic change was required.
- Protocol V1 activation (epoch 12951) was coordinatively cleaner than a testnet reset: no accounts/balances wiped, no template addresses invalidated by a wipe — but template *binaries* must still be rebuilt against `tari_template_lib 0.39.0` because V2 template definitions are now the only ones the engine loads.

## Review verdict

No BLOCKER or HIGH finding blocks Stage 2. The single open item is H3 (idempotency/duplicate implementation), which by design belongs to Stage 2 ballot ingestion, not the skeleton.
