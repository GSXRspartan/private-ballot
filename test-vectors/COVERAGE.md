# Phase 2 test-vector coverage

## Implemented in Slice 12A1

The dependency-free hostile CBOR corpus covers:

- truncated input;
- trailing data;
- indefinite-length arrays;
- non-shortest unsigned integers;
- invalid UTF-8;
- unexpected CBOR types;
- empty registries;
- duplicate registry public keys;
- noncanonical registry ordering;
- empty candidate sets;
- duplicate candidate identifiers;
- noncanonical candidate ordering;
- unknown approval selections;
- duplicate approval selections;
- too few approval selections;
- too many approval selections.

Every case records and tests an exact stable rejection code.

## Implemented in Slice 12A2

The semantic rejection corpus covers:

- unsupported manifest and ballot-package versions;
- wrong manifest binding;
- unsupported proof-suite binding;
- empty and malformed test-only proofs;
- proofs replayed against another ballot payload;
- duplicate election-scoped nullifiers;
- election-not-open rejection;
- lifecycle manifest and registry mismatches;
- replay decisions without submissions;
- skipped and duplicate replay decisions;
- replay package-digest mismatches;
- incomplete replay transcripts;
- archive file-digest mismatches;
- archive-manifest hash mismatches;
- archive hash-provider mismatches;
- archive-manifest self-reference rejection.

These are constructed public-API scenarios rather than canonical CBOR vectors
when the affected object family has no canonical encoding yet.

## Implemented in Slice 12C2A

The valid canonical corpus now publishes and checks:

- registry snapshots;
- selectable-option candidate sets;
- approval ballot payloads;
- election manifests;
- version-two election manifests with a hash-bound proposal question;
- proof-bearing ballot packages;
- archive manifests.

Decision vectors explicitly cover both candidate elections and ballot measures.
Every valid case includes authoritative canonical CBOR, lowercase hexadecimal,
decode metadata, and exact domain-separated test-hash metadata.

## Implemented in Slice 12C2B

A dependency-free Python standard-library verifier now independently:

- parses every checked-in valid vector without importing project Rust APIs;
- validates the supported deterministic CBOR subset and object schema shapes;
- enforces version-two proposal-question bounds without rewriting text;
- re-encodes every parsed object byte-for-byte;
- reproduces every published domain-separated test hash;
- verifies both candidate-election and ballot-measure examples;
- emits the deterministic `independent-verification-v1.json` report.

## Implemented in Slice 12C2C

The hostile CBOR corpus now includes a small checked-in
`ElectionManifestV2::from_canonical_cbor` rejection set for:

- non-NFC proposal questions;
- leading whitespace in proposal questions;
- C1 control U+0085 in proposal questions;
- nine-field V1-shaped manifest payloads presented to the V2 decoder;
- non-canonical indefinite-length V2 arrays.

The independent Python verifier exercises these original malformed bytes
directly and compares their expected rejection categories.

## Implemented in Slice 12D

The standalone cargo-fuzz workspace now publishes seven real libFuzzer
targets covering:

- deterministic CBOR primitives;
- registry snapshots;
- selectable-option candidate sets;
- approval ballot payloads;
- election manifests;
- proof-bearing ballot packages;
- archive manifests.

Successful object decodes must re-encode byte-for-byte identically and retain
deterministic canonical hashes or commitments. Checked-in valid and hostile
CBOR vectors provide deterministic local seed corpora.

## Not yet representable

The following required families do not yet have version-one schemas in the Rust
workspace and therefore cannot honestly have canonical vectors:

- governance-source records;
- relay receipts;
- submission batch manifests;
- approval tally transcripts;
- election result objects;
- Ootle anchor records.

Duplicate map-key and unknown closed-map-field vectors also remain inapplicable
while the implemented version-one objects use fixed-position CBOR arrays.

All-zero identifier rejection remains deferred until the protocol defines which
identifiers forbid the all-zero value.

## Later gates

Still required:

- sustained fuzz campaigns and preserved minimized regressions;
- canonical schemas and vectors for the remaining unimplemented object families;
- Phase 2 closeout documentation;
- a production anonymous-membership construction selected by a later phase.

The reserved proof suite
`TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS` remains test-only and does
not establish anonymity or authorization for binding elections.
