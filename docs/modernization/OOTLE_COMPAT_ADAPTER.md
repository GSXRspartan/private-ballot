# Ootle Compatibility Adapter (Phase 4)

## Boundary

```
Private Ballot domain/core (anchor, ballot, protocol, tally, verifier, archive)
        |
        v
OotleAnchorPort  (semantic operations — project DTOs only)
        |
        +-- ootle-anchor-adapter        (transaction build + inspection fingerprint)
        +-- ootle-walletd-anchor-adapter (walletd create/approve/reject/submit)
        +-- ootle-receipt-anchor-adapter (indexer receipt conversion)
        +-- ootle-anchor-network-adapters (real IndexerRestApiClient / WalletDaemonClient transports)
        +-- ootle-anchor-lifecycle       (polling orchestrator)
```

**No new crate was created for this boundary.** The existing five `ootle-*` crates *are* the adapter; this document names the seams so the domain layer's contract is explicit. Names follow the repository's existing conventions (`Anchor*V1`, `*AnchorAdapterError`, `*AnchorClient`, `TransportError`).

## Semantic operations (domain view)

| Domain operation | Seam | Wire hidden |
|---|---|---|
| `get_template` (binding) | `AnchorTemplateBindingV1/V2` + `parse_anchor_template_address` (`crates/ootle-anchor-adapter/src/event_instruction.rs`) | `template_` prefix, `TemplateAddress` hex |
| `dry_run_anchor` (fee-less build) | `build_*` + `inspect` (`crates/ootle-anchor-adapter/src/build.rs`, `inspect.rs`) | `TransactionBuilder`, `UnsignedTransaction`, CBOR fingerprint |
| `submit_anchor` | `WalletdAnchorCoordinator::{prepare,approve,submit}` + `WalletdAnchorClient` | walletd JSON-RPC (`transaction_requests.create/approve/reject`) |
| `get_transaction_status` | `WalletdAnchorCoordinator::query_status` / scripted `TransactionRequestInfo` | `EffectiveStatus`, `TransactionRequestInfo` (incl. v0.51 `value_summaries`, `component_upgrades`, `main_signer`) |
| `get_receipt` | `convert_receipt_response` → `AnchorReceiptV1` | `Encoded<TransactionReceipt>` (CBOR, base64 in JSON), `GetTransactionReceiptResponse` |
| `find_anchor_event` | `AnchorEventProofV2` + `verify_anchor_receipt` (`crates/anchor-transport`) | `Event` topic, `RawCbor` metadata, `template_` rendering |
| `get_finalized_substate` | Receipt `FinalizeOutcome` → `AnchorFinalStatusV1` | `Commit` / `FeeIntentCommit`, `IndexerTransactionFinalizedResult` |
| `verify_network_identity` | `observed_network_epoch` + `map_ootle_network` | `Network` byte, `GetNetworkInfoResponse` |

The domain layer never imports `tari_*` types. `rg "tari_" crates/<domain>/Cargo.toml` is empty for `anchor`, `ballot`, `crypto`, `protocol`, `registry`, `tally`, `verifier`, `archive`.

## Decoding centralization

- **CBOR receipts:** `crates/ootle-receipt-anchor-adapter/src/convert.rs::convert_receipt_response` is the *only* place that calls `Encoded::decode`. `MalformedEncodedReceipt` fails closed.
- **CBOR event metadata:** `convert_transaction_receipt` is the *only* place that reads `payload.get_str` / `raw.as_bytes()`.
- **Template addresses:** `parse_anchor_template_address` is the *only* place that strips `template_`.
- **Walletd/indexer errors:** `crates/ootle-anchor-network-adapters/src/error.rs::from_walletd_client` / `from_indexer_client` are the *only* mappings to bounded `TransportError`.

## Version detection (explicit, no random decoders)

Capability is the pinned git cohort (currently `9f03f90` = v0.51.0). The adapter does not sniff wire bytes to choose a decoder: `Encoded::decode` is the single capability, bounded by `MAX_CBOR_NESTING_DEPTH` and exact-decode (trailing bytes rejected). A future cohort bump changes the pin (one rev in four `Cargo.toml` files), rebuilds the central converters, and re-runs the fixture suite — it does not add parallel decoders to the domain layer.

## Verified-read / finalization posture

- The real transport forwards `IndexerRestApiClient::get_transaction_receipt` verbatim to `convert_receipt_response`; no `include_proof` shortcut is taken (we pass `include_proof: false` in `GetTransactionResultRequest` and use the dedicated receipt endpoint).
- `Decision::Commit` vs `Decision::Abort(_)` distinguishes full acceptance from rejection; `FeeIntentCommit` maps to `FeeOnlyAccepted`, never to `Accepted`.
- `compare_walletd_and_indexer` refuses disagreeing observations. Finalization is never claimed from a single unverified read.

## What did not change

- `publish_anchor_v2` ABI (four args, static function), topic, metadata keys, digest framing, `public_summary` cap — frozen by the template-compiles-unchanged test against `tari_template_lib 0.39.0` (see `templates/ootle-anchor-event-template-v2/Cargo.toml`).
