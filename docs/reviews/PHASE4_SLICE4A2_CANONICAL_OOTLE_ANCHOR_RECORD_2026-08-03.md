# Phase 4 Slice 4A2 — Canonical Ootle Anchor Record and Test Vectors

**Repository:** `C:path	o	ari-private-ballot`
**Branch:** `phase4/ootle-testnet-anchor-prototype`
**Starting HEAD:** `114f96a9c24c226578db896519c1d2b17268acb1` (clean working tree at start)
**Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`
**Mode:** offline implementation; staged, **not** committed. No network contact.
**Date:** 2026-08-03

---

## 1. Summary

Slice 4A2 adds one new leaf crate, `tari-cc-private-ballot-anchor`, containing a
project-owned, versioned, canonical **Ootle anchor record** that binds one
completed Phase 3 `ArchiveHashV1` to a future Tari Ootle testnet transaction.
The record is offline-only: it has a deterministic canonical CBOR encoding, a
production BLAKE3 domain-separated digest, and deterministic vectors. No Ootle,
walletd, indexer, HTTP, RPC, async-runtime, or networking dependency was added,
and no existing Phase 1–3 crate source was modified.

**Architecture note.** The record references `ArchiveHashV1`, which lives in the
`archive` crate, and `archive` already depends on `protocol`. Hosting the record
in `protocol` would create a `protocol → archive` dependency cycle. A dedicated
leaf crate depending on both `protocol` and `archive` is therefore architecturally
required, not optional complexity. This matches the Slice 4A1 recommendation.

---

## 2. Canonical record schema

The record is a fixed six-element, definite-length CBOR array in fixed field
order. Three fields are fixed protocol constants (written by the encoder, checked
by the decoder); only three fields are caller-supplied.

| # | Field | CBOR type | Source | Value / bound |
|---|---|---|---|---|
| 0 | record-type / version | text | fixed constant | `TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1` (38 bytes) |
| 1 | network identifier | text | caller | bounded: non-empty, ≤ 32 bytes, `[A-Za-z0-9_-]` only |
| 2 | election manifest hash | byte string(32) | caller (`ManifestHash`) | opaque 32 bytes |
| 3 | archive hash | byte string(32) | caller (`ArchiveHashV1`) | opaque 32 bytes |
| 4 | hash-algorithm identifier | text | fixed constant | `BLAKE3-256/tari-cc-private-ballot/v1` (36 bytes) |
| 5 | purpose identifier | text | fixed constant | `NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR` (41 bytes) |

Public type: `OotleAnchorRecordV1` — `crates/anchor/src/record.rs`.
The struct stores only `{ network, election_manifest_hash, archive_hash }`; the
three constant fields are not stored (they are implied), so the type has no field
capable of holding arbitrary caller data.

### Field rationale

- **Field 0 (record-type/version).** Single string that both marks the object as
  this project's anchor record (preventing confusion with unrelated ledger logs)
  and pins the version (preventing confusion with a future anchor version). One
  string serves both roles, so no separate numeric version field is used.
- **Field 1 (network).** Binds the intended Ootle network so a receipt on one
  network cannot be mistaken for a commitment intended for another. Kept as a
  bounded, character-restricted identifier rather than an enum so it is not
  hardcoded to one current network name (per the 4A1 brief).
- **Field 2 (election manifest hash).** Lets an independent verifier identify
  which election archive the record belongs to without placing any election
  metadata on-chain. It is the existing `ManifestHash`.
- **Field 3 (archive hash).** The primary commitment being anchored — the
  existing completed `ArchiveHashV1`, which already transitively commits to the
  election manifest hash, registry commitment, candidate-set commitment, and
  archive file digests.
- **Field 4 (hash-algorithm identifier).** Declares the production suite so the
  record is self-describing and so the decoder can reject the test-only
  deterministic hash identifier. Fixed to the production constant.
- **Field 5 (purpose).** Makes the harmless, non-binding pilot scope legible from
  the ledger. Fixed constant, never caller text, so it cannot carry prose,
  titles, timestamps, counts, or arbitrary memo.

### Rejected / not-added fields (smaller design kept)

- **Separate numeric version** — redundant with the versioned record-type string
  (field 0). Not added.
- **Previous-anchor reference** — useful for re-anchoring after a testnet reset,
  but not needed to encode or verify a single completed archive commitment. It is
  a later-slice concern and was deliberately excluded from V1 to avoid adding a
  field "future versions might use." Documented here rather than implemented.
- **Timestamp / epoch / submitter** — these are ledger-authenticated facts that
  belong to the future receipt evidence, not to the offline record. Excluded.
- **Registry commitment / candidate-set commitment as standalone fields** —
  already transitively committed by field 3; adding them would duplicate
  commitments without adding binding. Excluded.

---

## 3. Canonical encoding rules

Implemented in `crates/anchor/src/canonical.rs`, reusing the existing
`CanonicalCborWriter` / `CanonicalCborReader` from `protocol` unchanged.

- Fixed six-element definite-length array; fixed field order.
- Definite lengths only; shortest integer/length encodings (inherited from the
  protocol reader, which rejects non-shortest and indefinite forms).
- Strict UTF-8 for text (inherited from the protocol reader).
- Exact 32-byte digests for fields 2 and 3.
- Terminal `reader.finish()` rejects trailing bytes.
- Maximum encoded-size limit enforced on both encode and decode.
- No maps, no optional fields, no extension points in V1.
- Decoder requires the exact record-type, hash-algorithm, and purpose constants.

### Reused validation codes (no new `ValidationCode` variant added)

| Condition | Code |
|---|---|
| wrong record-type / version | `UnsupportedProtocolVersion` |
| wrong hash-algorithm id (incl. test-only) | `UnsupportedHashAlgorithm` |
| wrong purpose / empty or bad-charset network | `InvalidData` |
| network too long / record too large | `ProtocolLimitExceeded` |
| wrong field count / malformed digest length / truncation | `InvalidCbor` |
| non-shortest length | `NonCanonicalCbor` |
| wrong field type | `UnexpectedCborType` |
| trailing bytes | `TrailingCborData` |
| digest mismatch (`verify_hash`) | `ArchiveManifestHashMismatch` |

---

## 4. Sizes

| Quantity | Value |
|---|---|
| Normal encoded size (network `esmeralda`) | **200 bytes** |
| Maximum encoded size (32-byte network) | **224 bytes** |
| Enforced `MAX_OOTLE_ANCHOR_RECORD_BYTES` | 512 bytes |
| `MAX_OOTLE_NETWORK_ID_BYTES` | 32 bytes |
| Anchor-record digest size | 32 bytes (`OotleAnchorRecordHashV1`) |
| Locally confirmed Ootle `EmitLog` budget | 32 KiB = 32,768 bytes |

The 224-byte maximum is ~0.68% of the `EmitLog` budget.

**Locally confirmed Ootle `EmitLog` and receipt references** (read from the
Slice 4A1 source checkout, *not* a dependency of this crate):

- Source checkout: `<local cargo git checkout of tari-ootle @ 92023e0>` (workspace `0.37.0`, commit `92023e0`).
- `Instruction::EmitLog { level, message: MaxString<{ ENGINE_LIMITS.max_log_size_bytes }> }` — `crates/transaction/src/v1/instruction.rs:74-81`.
- `max_log_size_bytes: 32 * 1024` — `crates/engine_types/src/limits.rs:110`.
- Engine execution of `EmitLog` — `crates/engine/src/transaction/processor.rs:375-378`.
- Receipt log storage: `TransactionReceipt.logs: Box<[LogEntry]>` — `crates/engine_types/src/transaction_receipt.rs:33-35`.
- Receipt is a persisted substate: `SubstateValue::TransactionReceipt` — `crates/engine_types/src/substate.rs:659-660`.

This crate imports **none** of the above; the constant is documented, not
depended upon.

---

## 5. Domain separator and production hashing

Implemented in `crates/anchor/src/digest.rs`.

- Frame prefix: `TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_FRAME_V1` — distinct from the
  protocol frame prefix `TARI_CC_PRIVATE_BALLOT_HASH_FRAME_V1`.
- Domain label: `tari-cc-private-ballot/ootle-anchor-record/v1` — distinct from
  every protocol domain (archive, manifest, registry, candidate-set, ballot,
  scope, proof-statement).
- Frame: `prefix || 0x00 || domain-label || 0x00 || canonical-record-bytes`.
- Provider: production `Blake3HashProviderV1`. `canonical_hash` validates the
  provider's `algorithm_id` equals the production identifier and rejects any
  other (including the test-only hasher) with `UnsupportedHashAlgorithm`.

The distinct frame prefix guarantees an anchor-record digest can never collide
with any protocol object digest, even independently of the label. The
anchor-record digest commits to the wrapper record and does **not** replace or
reinterpret `ArchiveHashV1`, which remains the commitment to the completed archive
(verified distinct by test `anchor_digest_differs_from_wrapped_archive_hash`).

---

## 6. Production vectors (exact)

Reference record: network `esmeralda`, manifest hash `0x11 × 32`, archive hash
`0x22 × 32`. All digests use production `Blake3HashProviderV1`.

**Vector 12 — exact canonical bytes (200 bytes, hex):**

```
867826544152495f43435f505249564154455f42414c4c4f545f4f4f544c455f414e43484f52
5f56316965736d6572616c646158201111111111111111111111111111111111111111111111
11111111111111111111582022222222222222222222222222222222222222222222222222222
2222222222222227824424c414b45332d3235362f746172692d63632d707269766174652d6261
6c6c6f742f763178294e4f4e5f42494e44494e475f415050524f56414c5f50494c4f545f41524
3484956455f414e43484f52
```
(single contiguous string in the test; wrapped here for readability)

**Vector 13 — exact production anchor-record digest:**

```
90568acd3af4646b07c375a562a392140cb7776550465b6bf2937d2043093b1d
```

**Vectors 2–4 — field sensitivity (production digests):**

| Vector | Change from reference | Digest |
|---|---|---|
| 2 | network `igor` | `05ea8c28970114cb60c707438011b931d6e8c20dd19b3ba4b9a88ad80c5d3d62` |
| 3 | manifest hash `0x12 × 32` | `88c6cef036980555d0adb32e0d9349436e6a5e8205d6d5985cbcdad1224af756` |
| 4 | archive hash `0x23 × 32` | `9c1c985495918c313222a03de3597db5aaa5185982f1aa2609e679d2c2151101` |

**Rejection / boundary vectors:**

| Vector | Case | Result |
|---|---|---|
| 6 | record-type `...V2` | `UnsupportedProtocolVersion` |
| 7 | test-only hash id | `UnsupportedHashAlgorithm` |
| 8 | trailing byte appended | `TrailingCborData` |
| 9 | single-byte mutation | canonical bytes and digest both change |
| 10 | 32-byte network id | accepted; encodes to 224 bytes; round-trips |
| 11 | 33-byte network id | `ProtocolLimitExceeded` |

Additional decoder rejections covered by unit tests in `canonical.rs`: wrong
field count (`InvalidCbor`), wrong field type (`UnexpectedCborType`),
non-shortest array length (`NonCanonicalCbor`), truncation (`InvalidCbor`),
malformed 31/33-byte digest lengths (`InvalidCbor`), empty network in bytes
(`InvalidData`), unsupported purpose (`InvalidData`), oversized encoded record
(`ProtocolLimitExceeded`).

---

## 7. Forbidden-content structural analysis

The guard is **structural**, not runtime keyword scanning.

- The struct `OotleAnchorRecordV1` has exactly three fields: a bounded
  `OotleNetworkIdV1` (≤ 32 bytes, `[A-Za-z0-9_-]`) and two fixed-size 32-byte
  commitment wrappers. There is no variable-length, caller-controlled field.
- Record-type, hash-algorithm, and purpose are fixed constants, so no free-form
  text field exists that could carry a memo, title, or description.
- Test `record_serialized_shape_has_only_approved_fields` decodes the canonical
  bytes at the CBOR layer and asserts exactly six elements in the exact approved
  shape (two constants, one bounded ≤ 32-byte identifier, two 32-byte digests, two
  more constants), with `finish()` confirming no further fields.

Consequently the record cannot contain ballot package bytes, Triptych proof
bytes, nullifiers/linking tags, registry public keys, voter identifiers, voter
count, vote selections, tally counts, election title/description, organizer
personal information, arbitrary memo text, wallet/account private keys, or
archive file contents. The bounded 32-byte, character-restricted network field is
too small and too constrained to carry binary secrets and is semantically the
network name.

---

## 8. Independent reconstruction result

Test `independent_reconstruction_matches_bytes_and_digest` rebuilds the record
from only the documented inputs (record-type identifier, network identifier,
election manifest hash, archive hash, production hash-algorithm identifier via
`for_provider`, purpose identifier), constructing the hashes in a different order,
and confirms the canonical bytes **and** the digest exactly match the original,
including the exact Vector 13 digest. No filesystem path, timestamp, insertion
order, machine state, wallet identity, transaction ID, or receipt affects the
canonical bytes. **Result: pass.**

---

## 9. Offline failure-independence result

Test `anchor_construction_does_not_modify_archive_artifacts` builds a production
`ArchiveHashV1` from a real `ArchiveManifestV1`, snapshots the archive manifest's
canonical bytes and archive hash, constructs an anchor record and computes its
digest (the operations a later slice would attempt), then recomputes the archive
artifacts and asserts they are byte-identical before and after. Anchor-record
construction is a pure deterministic read of already-frozen values and cannot
mutate any election artifact. **Result: pass.** This satisfies the first half of
the Phase 4 condition that the offline election output remains authoritative
regardless of anchoring success or failure.

---

## 10. Roadmap / ADR correction

- Added `docs/decisions/ADR-0006-phase4-ootle-anchor-prototype-scope.md` as the
  single narrow decision note reconciling the phase numbering: Phase 4 now covers
  the harmless, non-binding Ootle testnet anchor prototype; the anchor prototype
  is renumbered out of Phase 5; binding governance use remains unauthorized;
  independent cryptographic and implementation review remains required before any
  binding use. ADR-0006 extends, and does not replace, ADR-0001.
- `ROADMAP.md`: two minimal notes (one under Phase 4, one under Phase 5) pointing
  to ADR-0006. The roadmap was not otherwise rewritten.

---

## 11. Test and validation results

| Command (Rust 1.97.1) | Result |
|---|---|
| `cargo test --locked --offline -p tari-cc-private-ballot-protocol` | 30 passed, 0 failed |
| `cargo test --locked --offline -p tari-cc-private-ballot-anchor` | 27 (lib) + 16 (vectors) passed, 0 failed |
| `cargo check --locked --offline --workspace --all-targets` | clean (only pre-existing vendored Triptych dead-code warning) |
| `cargo test --locked --offline --workspace` | 34 test binaries, all `ok`, 0 failures |
| `cargo clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings` | clean (only pre-existing vendored Triptych warning) |

The long governance-scale suite, the long padding-boundary suite, timing smoke
tests, fuzz campaigns, and network tests were not run per the slice restrictions.
`rustfmt` (edition 2024) was run only on the five new project-owned files;
`cargo fmt --all` was not used, so no vendored Triptych formatting changed.

---

## 12. Dependency and isolation confirmation

- No Ootle, walletd, indexer, HTTP, RPC, async-runtime, or networking dependency
  was added. `crates/anchor/Cargo.toml` depends only on the workspace `protocol`
  and `archive` path crates.
- `Cargo.lock` diff adds exactly one package entry
  (`tari-cc-private-ballot-anchor`) with two path dependencies and **no** new
  crates.io dependency.
- No vendored Tari Triptych file under `third_party/tari-triptych` was staged or
  changed.
- No existing Phase 1–3 crate source was modified. Only the workspace
  `Cargo.toml` members list, `Cargo.lock`, `ROADMAP.md`, and the new ADR were
  touched outside the new crate.
- No `unsafe`, `unwrap()`, `expect()`, `todo!()`, or `unimplemented!()` in the new
  code; no warnings suppressed.

---

## 13. Staged evidence

Whitespace check `git diff --cached --check`: **clean**.

Staged files (10):

| File | SHA-256 | Bytes |
|---|---|---|
| `Cargo.lock` | `5c2041df2c2d24cefabf815fbd393ec4631e35433606b3a725969afd7e2dcc84` | 11375 |
| `Cargo.toml` | `53c20edd2c5a9ef06a6d6d7db2ce05cb38cb9f87136f7c7d8ad93301b84a8e06` | 504 |
| `ROADMAP.md` | `489bf8b58c50d4b2fd76cf4b7c88e40d5b40d6d12f40e661b1689a0f17def087` | 5816 |
| `crates/anchor/Cargo.toml` | `b30e05371e5b68b740a392a597cc1309d4f974227effcb41bcb930aff9cdfc0b` | 296 |
| `crates/anchor/src/canonical.rs` | `e24b6be9879d7e7a730a0c181dbd830ce629d2daef88ff327a87084f098bf223` | 14380 |
| `crates/anchor/src/digest.rs` | `758da45ebe33785e6b73935891cb471f67915b77f47ab3a0ce173b72bfcfed89` | 8055 |
| `crates/anchor/src/lib.rs` | `8dfd78ee24a8b76a17335cfa2d01c22018608a90964af0bcc8b956f59960c91d` | 1332 |
| `crates/anchor/src/record.rs` | `1387bc0c21f40322e473e202490c25217765e7faa76dcf81b6ff4fef8de5d927` | 8476 |
| `crates/anchor/tests/canonical_ootle_anchor_vectors.rs` | `79fe8c9e9bed02da0feba0a4dde8d86f00e9fcb2e975a526ac417093083caf7a` | 16225 |
| `docs/decisions/ADR-0006-phase4-ootle-anchor-prototype-scope.md` | `f51bcabae0760dfab0f55672e8101195674ec3b26aa448cb05fcee2f7f1e0b4e` | 3004 |

Staged binary patch (`git diff --cached --binary`, before this report was staged):
- bytes: **56508**
- SHA-256: `7e6aff6297c1eb716135882eaf87199e30c416321630201dab9e93b1062d33c1`

This evidence report is staged in addition to the ten files above, bringing the
final staged count to 11. Its inclusion does not affect the patch hash recorded
above, which was computed over the implementation change set.

**No commit was created. No network contact was made.**

---

## 14. Limitations and non-goals

- Offline only. No transaction construction, signing, submission, receipt
  parsing, signer interface, or network I/O — those are later Phase 4 slices.
- The record proves nothing on its own about ballot validity, tally correctness,
  organizer honesty, voter anonymity, or archive availability. The offline archive
  and independent verifier remain authoritative.
- No custom Ootle template or component; no CLI submission command.
- No previous-anchor / re-anchoring field in V1 (documented, deferred).
- No Phase 1–3 canonical format, hashing, or Triptych semantics were changed.
- Binding governance use remains unauthorized; independent review remains required
  before any binding use.
