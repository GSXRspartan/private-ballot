# Canonical Data Format and Test Vector Plan

## Status

Phase 1 draft.

This document defines the deterministic serialization and cross-implementation
test evidence required before Phase 2 protocol objects may be considered stable.

It does not select a production anonymous-membership construction.

## Purpose

Election manifests, registry snapshots, candidate manifests, ballots, receipts,
verification transcripts, tally transcripts, results, and archive manifests
must produce identical protocol bytes in every conforming implementation.

A signature or hash authenticates bytes, not an abstract Rust structure.
Therefore, equivalent-looking data must not have multiple accepted protocol
encodings.

## Serialization profile

### 1. Format

Protocol objects use CBOR following the core deterministic encoding
requirements of RFC 8949 Section 4.2.1.

Human-readable JSON may accompany an object for inspection, but JSON is not
signed, hashed as the protocol object, or treated as authoritative.

### 2. Deterministic encoding requirements

Protocol encoders must:

- use preferred shortest-length serialization;
- use only definite-length byte strings, text strings, arrays, and maps;
- order map keys according to the selected RFC 8949 deterministic profile;
- reject duplicate map keys;
- encode every protocol object as exactly one complete CBOR data item;
- emit no trailing data after the complete object.

Protocol verifiers must reject noncanonical encodings rather than decoding and
silently accepting an alternate byte representation.

### 3. Restricted data model

The Phase 2 protocol profile permits:

- unsigned integers;
- signed integers where explicitly required;
- byte strings;
- UTF-8 text strings for presentation metadata only;
- arrays;
- maps;
- booleans;
- null only where a schema explicitly permits it.

The Phase 2 protocol profile forbids unless a later ADR explicitly adds them:

- floating-point values;
- NaN and infinity;
- indefinite-length items;
- arbitrary semantic tags;
- bignums;
- decimal fractions;
- embedded executable or script content.

### 4. Map keys

Protocol maps use assigned unsigned-integer field labels.

Field labels are part of the versioned protocol schema and must not be reused
for a different meaning.

Unknown fields are rejected in version 1 unless the containing schema
explicitly defines an extension map.

### 5. Identifiers

Protocol identifiers use fixed or bounded byte strings defined by their schema.

Display names are separate UTF-8 presentation fields and are not identifiers.

Candidate, election, registry, relay, schema, suite, and algorithm identifiers
must define:

- exact byte length or maximum byte length;
- generation or assignment rule;
- whether all-zero values are forbidden;
- canonical display representation, if any.

Hexadecimal and base encodings are presentation forms only. Protocol objects
contain the underlying bytes.

### 6. Hashes

Hash fields contain raw digest bytes, not hexadecimal text.

Every hashed object defines:

- a hash-suite identifier;
- a domain-separation label;
- the exact canonical CBOR bytes covered by the hash;
- whether the domain label is inside or outside the CBOR object;
- the expected digest length.

The archive may include hexadecimal digest files for human and tool
compatibility, but those files are derived presentation artifacts.

### 7. Domain separation

Every signature, nullifier, object hash, Merkle leaf, Merkle node, receipt,
batch commitment, tally commitment, result commitment, and archive commitment
uses a distinct versioned domain-separation label.

A domain label must identify at least:

- project protocol;
- protocol version;
- object or operation type;
- suite version where applicable.

### 8. Timestamps

Protocol timestamps use signed integer seconds since the Unix epoch in UTC.

Sub-second precision is not included in signed election objects unless a later
schema explicitly requires it.

Human-readable ISO 8601 timestamps may be included in JSON renderings.

### 9. Ordered and unordered collections

Arrays preserve semantic order.

Collections that are logically unordered must define a canonical ordering
before encoding.

Examples:

- ranked ballot choices preserve voter-selected order;
- registry entries are ordered by their canonical registry key;
- candidate manifests are ordered by candidate identifier;
- approval selections are ordered by candidate identifier before encoding;
- digest lists are ordered by canonical archive path.

A set or hash-map iteration order must never determine protocol bytes.

## Version 1 object families

The initial test-vector suite covers:

1. `GovernanceSource`
2. `ElectionManifest`
3. `RegistryEntry`
4. `RegistrySnapshot`
5. `CandidateEntry`
6. `CandidateManifest`
7. `ApprovalBallotPayload`
8. `BallotPackage` using a reserved test-only proof suite
9. `RelayReceipt`
10. `SubmissionBatchManifest`
11. `BallotDecision`
12. `VerificationTranscript`
13. `ApprovalTallyTranscript`
14. `ElectionResult`
15. `ArchiveFileEntry`
16. `ArchiveManifest`
17. `OotleAnchorRecord`

Each object family receives a separate version identifier and field-label
registry.

## Test vector directory

Vectors are stored under:

```text
test-vectors/
  README.md
  schema/
  valid/
  invalid/
  hashes/
  round-trip/
```

Each vector case contains:

```text
<vector-id>/
  description.md
  input.json
  canonical.cbor
  canonical.hex
  expected.json
  expected-hashes.json
```

Invalid cases may replace `canonical.cbor` with `invalid.cbor` and must include
the exact expected rejection code.

## Required valid vectors

At minimum, Phase 2 publishes valid vectors for:

- smallest valid governance source record;
- smallest valid synthetic registry;
- multi-member registry in noncanonical input order producing canonical order;
- candidate manifest with stable machine IDs and separate display names;
- approval ballot selecting one candidate;
- approval ballot selecting multiple candidates in canonical order;
- permitted empty approval ballot representing abstention;
- first valid ballot acceptance;
- duplicate-nullifier rejection transcript;
- tied approval tally reported as a tie;
- unique approval winner;
- empty accepted-ballot set;
- archive manifest containing every required artifact;
- Ootle anchor record matching an offline archive hash.

## Required invalid vectors

At minimum, Phase 2 publishes invalid vectors for:

- truncated CBOR;
- valid object followed by trailing bytes;
- indefinite-length map;
- indefinite-length array;
- non-shortest integer encoding;
- duplicate map key;
- unknown required-version field;
- unsupported protocol version;
- unknown object field in a closed version 1 map;
- wrong field type;
- oversized byte or text string;
- invalid UTF-8 text;
- all-zero forbidden identifier;
- wrong identifier length;
- duplicate registry public key;
- empty electorate where forbidden;
- duplicate candidate identifier;
- unknown approval selection;
- duplicate approval selection;
- too few selections;
- too many selections;
- wrong manifest hash;
- wrong registry hash;
- unsupported proof-suite identifier;
- malformed test-only proof;
- duplicate election-scoped nullifier;
- mismatched tally transcript;
- mismatched result hash;
- mismatched archive file digest;
- anchor record referencing the wrong archive hash.

## Cross-implementation requirements

A single implementation generating and consuming its own vectors is not
sufficient evidence.

Before Phase 2 serialization is considered stable:

1. The Rust implementation must generate every canonical byte vector.
2. An independent decoder or implementation must parse every valid vector.
3. Both implementations must reject every invalid vector with compatible
   classifications.
4. Re-encoding a valid parsed object must reproduce identical bytes.
5. Hashes must match byte-for-byte across implementations.
6. At least one implementation must be written independently from the primary
   Rust serialization code.

## Property and fuzz testing

Property tests must cover:

- encode-decode-encode byte identity;
- input-order independence for logically unordered collections;
- rejection of duplicate fields and choices;
- deterministic rejection codes;
- mutation of every committed field changing the expected object hash;
- preservation of ranked order where order is meaningful.

Fuzz targets must cover:

- generic CBOR decoding;
- every version 1 protocol object decoder;
- canonicality checking;
- archive path validation;
- ballot validation;
- tally transcript verification.

Fuzzing must enforce memory, nesting-depth, collection-size, and input-size
limits.

## Test-only proof suite

Protocol plumbing may use a reserved test-only anonymous-membership provider
before ADR-0005 selects an accepted production construction.

The reserved provider must never claim cryptographic anonymity.

Its encoded suite identifier and every generated archive must clearly state:

`TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS`

Production-mode verifiers must reject that suite.

## Acceptance gate

Phase 2 protocol implementation may begin after this plan is accepted.

Protocol serialization may be called stable only when:

- field labels and object schemas are documented;
- deterministic CBOR rules are implemented;
- valid and invalid vectors exist;
- independent parsing and re-encoding agree;
- property tests pass;
- fuzz targets run without known crashes;
- archive and Ootle commitment bytes reproduce exactly.

## References

- RFC 8949, Concise Binary Object Representation:
  https://www.rfc-editor.org/rfc/rfc8949.html
- ADR-0003, governance source pinning and MVP scope
- ADR-0004, MVP ballot validation and tally policy
- ADR-0005, anonymous membership construction direction
