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

## Planned for Slice 12A2

Semantic hostile vectors will cover:

- unsupported protocol versions;
- wrong manifest hashes;
- wrong registry commitments;
- unsupported proof suites;
- malformed test-only proofs;
- duplicate election-scoped nullifiers;
- replay transcript omissions and digest mismatches;
- archive file and archive-manifest digest mismatches;
- lifecycle-state rejection.

## Not yet representable

The following required families do not yet have version-one schemas in the Rust
workspace and therefore cannot honestly have canonical vectors:

- governance-source records;
- ballot-package canonical encoding;
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

Still required after the Rust corpus exists:

- independent parsing and re-encoding;
- property and structured mutation tests;
- real fuzz targets;
- synthetic election cohorts;
- complete offline archive replay;
- cross-implementation hash agreement.

The reserved proof suite
`TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS` remains test-only and does
not establish anonymity or authorization for binding elections.
