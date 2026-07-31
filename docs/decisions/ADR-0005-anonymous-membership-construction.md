# ADR-0005: Anonymous membership construction direction

## Status

Proposed for Phase 1 technical and cryptographic review.

This ADR does not approve a production cryptographic construction and does
not authorize binding elections.

## Context

The voting protocol requires a voter to prove membership in a frozen
electorate without revealing which member created the ballot.

It also requires:

- one accepted ballot per eligible voter per election;
- an election-scoped nullifier or equivalent duplicate-detection value;
- no stable public identifier linking different elections;
- offline public verification;
- canonical parsing and deterministic rejection;
- practical operation for an electorate of roughly dozens rather than
  millions of members.

The existing Python LSAG proof of concept demonstrates basic algebra and
workflow only. It is not audited, has known validation and encoding defects,
and uses a modified scope-oriented key-image construction whose security
properties have not been established for this project.

## Candidate A: Scope-linkable ring signature

A linkable ring signature proves that one member of a public-key ring signed
a message while hiding which member signed it.

The published LSAG family provides anonymity, linkability, and spontaneous
ring formation without a shared group secret.

For this project, ordinary global linkability is insufficient. Duplicate
detection must apply within one election while avoiding a stable public tag
across different elections.

A candidate construction therefore needs a reviewed event-scoped or
context-scoped linkability design. Merely adding an election string to a
home-grown key-image formula is not accepted as a security argument.

If this family is selected, Ristretto255 is the preferred group abstraction
for evaluation because it presents a prime-order group with canonical point
encodings and avoids exposing Edwards cofactor behavior to the protocol.

Advantages:

- direct use of a frozen public-key registry;
- no credential issuer after registry publication;
- no trusted circuit setup;
- simple offline verification model;
- linear proof size is likely acceptable for a small CC electorate;
- natural fit for a Rust implementation.

Risks:

- the exact scope-linkable construction still requires selection and review;
- proof size and verification time grow with the ring;
- custom transcript or key-image changes can invalidate published security
  arguments;
- signer-side constant-time behavior and key handling require careful review.

## Candidate B: Zero-knowledge Merkle membership with nullifiers

A Semaphore-style construction stores identity commitments in a Merkle tree.
A voter proves membership in the tree and publishes a context-derived
nullifier that prevents duplicate signaling within the election.

Advantages:

- group membership and nullifier behavior closely match the voting problem;
- proof size need not grow linearly with electorate size;
- existing protocol specifications, audits, and implementations can inform
  the design;
- explicit separation between identity commitment, group root, signal, and
  external nullifier.

Risks:

- substantially larger proving-system and circuit surface;
- Merkle-tree and circuit compatibility become consensus-like protocol data;
- current ecosystems are commonly oriented toward Circom, JavaScript,
  Ethereum, and SNARK tooling rather than a small native Rust application;
- proving keys, circuit versions, field encodings, and verifier dependencies
  require strict preservation and review.

## Candidate C: Anonymous credentials with contextual pseudonyms

An authority could issue an anonymous credential to each eligible voter.
The voter would prove possession without revealing the credential and derive
an election-specific pseudonym or nullifier.

BBS-family credentials provide unlinkable proofs and selective disclosure.
Context-dependent pseudonym proposals may supply controlled linkability.

Advantages:

- separates eligibility issuance from later anonymous ballot presentation;
- supports richer credentials and future attributes;
- may avoid publishing a complete public-key ring in every proof.

Risks:

- requires an issuer and credential lifecycle beyond the existing registry;
- revocation, reissuance, and duplicate credential prevention become major
  operational concerns;
- pairing-based cryptography adds a different implementation stack;
- contextual pseudonym specifications and implementation maturity require
  specialist review.

## Decision

### 1. No production construction is selected yet

The production `crypto_suite_id` remains unresolved during Phase 1.

No election may enter the `FROZEN` state with an unresolved cryptographic
suite.

### 2. The protocol remains cryptography-agnostic

Phase 2 defines a narrow anonymous-membership interface separating:

- governance key generation;
- public registry entries;
- proof creation;
- proof verification;
- election-scoped nullifier extraction;
- canonical proof serialization;
- suite-specific validation errors.

The election manifest identifies the exact cryptographic suite and version.

### 3. Initial research priority

The first research candidate is a reviewed scope-linkable ring-signature
construction evaluated over Ristretto255.

This is a research priority, not a production approval.

The reason is the small expected electorate, direct compatibility with the
published governance-key registry, relatively simple offline verification,
and absence of a separate credential issuer or zero-knowledge circuit stack.

### 4. Primary fallback

If no suitable reviewed scope-linkable ring-signature construction can be
identified and implemented safely, the project will evaluate a
Semaphore-style Merkle membership and nullifier construction.

### 5. Deferred credential approach

BBS-family anonymous credentials remain a future option but are not selected
for the MVP because they add issuer, credential, revocation, pairing, and
context-pseudonym design requirements.

### 6. Python proof of concept

The Python LSAG implementation is reference material only.

Its source code, serialization, key-image formula, tests, and security claims
must not be copied into the production Rust backend.

### 7. Test-only protocol plumbing

Before production cryptography is selected, Phase 2 may use a clearly marked
test-only proof provider for protocol, archive, and tally plumbing.

A test-only provider must:

- be unavailable in release builds;
- use a reserved non-production suite identifier;
- place an explicit non-production marker in generated archives;
- be rejected by any verifier operating in production mode.

## Construction acceptance gates

A cryptographic construction cannot be accepted until all of the following
are satisfied:

1. The exact named construction and source publication are recorded.
2. The security rationale applies to the exact scoped-linkability design.
3. Protocol version, manifest hash, registry commitment, ballot bytes,
   election scope, proof commitments, and nullifier are domain-separated.
4. Point and scalar encodings are canonical.
5. Identity, malformed, noncanonical, and invalid-group values are rejected.
6. Secret-dependent operations are implemented with appropriate side-channel
   protections.
7. Private key material is zeroized where practical.
8. Deterministic positive and negative test vectors are published.
9. Property tests and malformed-input fuzzing are included.
10. Proof-size and verification-time limits are recorded.
11. At least one independent reviewer evaluates the construction and code.
12. An independently implemented verifier or equivalent cross-check exists
    before binding use.

## Ootle boundary

The initial Ootle anchor does not need to verify anonymous-membership proofs.

The offline verifier validates ballots and produces committed verification,
tally, result, and archive hashes. Ootle records those commitments and
append-only lifecycle transitions.

Moving proof verification into an Ootle template would require a separate ADR,
cost analysis, template support review, and consensus-safety assessment.

## Consequences

- Phase 2 can build canonical protocol structures without prematurely locking
  the project to one cryptographic backend.
- The easiest prototype is not mistaken for reviewed production security.
- A ring-signature path receives first evaluation because it fits the small
  electorate and registry model.
- A mature zero-knowledge membership pattern remains available as a fallback.
- Binding use remains blocked until the exact construction and implementation
  receive independent review.

## Primary references

- LSAG publication:
  https://link.springer.com/chapter/10.1007/978-3-540-27800-9_28
- Ristretto implementation documentation:
  https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/
- Semaphore documentation:
  https://docs.semaphore.pse.dev/
- BBS signatures draft:
  https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- BBS contextual pseudonym draft:
  https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-per-verifier-linkability/
