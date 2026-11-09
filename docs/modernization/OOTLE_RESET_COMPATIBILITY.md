# CBOR / Reset Compatibility (Phase 5)

## What is live (not future)

Protocol V1 (v0.50.0, Esmeralda epoch 12951, 2026-11-08) commits substate hashes to CBOR encodings. `Encoded<T>` (`tari_engine_types::encoded`) is the live wire model: CBOR bytes, base64 in JSON. The indexer already returns receipts as `Encoded<TransactionReceipt>` (`GetTransactionReceiptResponse.receipt`) and `Encoded<SubstateValue>` (resource/ProvenTransactionReceipt). Event metadata has been CBOR (`RawCbor`) since the v0.42 cohort (PR #2679).

Therefore Stage 1 does **not** design a speculative dual codec. It does three things:

1. Pins the live `Encoded` capability and decodes it in one central seam.
2. Adds fail-closed fixtures for malformed inputs.
3. Documents the capability/version contract so a future base64-CBOR variant (or a reset generation) is a new capability, not a silent fallback.

## Codec contract (`crates/ootle-receipt-anchor-adapter/src/convert.rs`)

- `convert_receipt_response(&GetTransactionReceiptResponse, ...)` calls `Encoded::decode()` exactly once.
- `Encoded::decode` uses `tari_bor::decode_exact_with_max_depth(..., MAX_CBOR_NESTING_DEPTH)`: every byte must belong to the value, no trailing bytes, bounded nesting.
- Any failure maps to `ReceiptConversionError::MalformedEncodedReceipt` (`RECEIPT_CONVERSION_MALFORMED_ENCODED_RECEIPT`). No error text, key material, or receipt bytes are preserved.
- Event metadata: `payload.get_str(key)` for CBOR strings; lossless lowercase-hex fallback for non-string engine values (never a bogus string decode).

## Fixture matrix (all must pass; see `convert.rs` tests)

| Input | Behavior |
|---|---|
| Well-formed `Encoded<TransactionReceipt>` | Decodes; `ledger_position` preserved |
| Malformed CBOR (`0xff 0xff 0xff`) | `MalformedEncodedReceipt` |
| Valid CBOR + trailing `0x00` | Rejected (exact decode) |
| Empty payload | Rejected |
| Oversized event count (> 256) | `TooManyLogs` before any DTO |
| Non-string CBOR metadata (int `123` → `187b`, bool `true` → `f5`) | Lossless hex, no panic |

## Version / capability detection

- Capability = pinned git cohort `9f03f90` (v0.51.0 tag). There is no runtime sniffing of `is_json` vs `is_cbor` vs `is_base64`.
- A future wire variant (e.g. base64-CBOR JSON fields, dry-run/result `Encoded` types) is handled by bumping the cohort pin, updating the central converters, and adding fixtures — never by `try_decode_json_else_cbor_else_base64` in the domain layer.
- `GetTransactionResultRequest.include_proof: false` and `GetTransactionResultResponse.receipt: None` (v0.51 additions) are handled explicitly; the adapter never expects a `ProvenTransactionReceipt` unless it opts in.

## Fail-closed list (verified by tests)

Malformed base64 (serde layer), malformed CBOR, wrong semantic type, oversized payload (`MAX_RECEIPT_LOG_ENTRIES`, `MAX_RECEIPT_LOG_MESSAGE_BYTES`, `MAX_BODY_BYTES` in hosted), missing required fields (`AnchorEventProofV2::new` validation), unexpected network (`observed_network_epoch` + `resolve_current` network check), digest mismatch (`verify_anchor_receipt`, registry hash check).

## Not implemented (explicitly)

- No production switch to unreleased development wire formats.
- No “try random decoders until something works.”
- No dry-run/UTXO/resource result adaptation beyond receipts until fixture captures of those result types exist.
