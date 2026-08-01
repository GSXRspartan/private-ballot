# Phase 3 scope-linkable construction gate

**Date:** 2026-08-01

## Decision status

No production anonymous-membership construction is selected.

Implementation of a signer, prover, proof verifier, transcript, hash-to-point
function, election-scoped key image, nullifier derivation, production suite
identifier, or proof serialization remains blocked.

This gate exists to prevent an ordinary linkable ring signature from being
modified into an election-scoped scheme without a security argument for the
exact modified construction.

## Current implementation baseline

Phase 3 Slice 1, commit `af791d2`, provides only:

- `curve25519-dalek` 5.0.0;
- canonical 32-byte Ristretto public-key parsing;
- malformed-encoding rejection;
- identity-point rejection;
- recompression agreement;
- a byte-oriented public API.

It provides no private-key handling and no anonymous-membership proof.

The sealed `ProofVerifierV1` boundary remains authoritative. Only a verifier
implemented inside the crypto crate may create `VerifiedProofV1` and
`VerifiedNullifier`.

## Primary construction candidate

The current research lead is:

**Patrick P. Tsang, Victor K. Wei, Tony K. Chan, Man Ho Au, Joseph K. Liu, and
Duncan S. Wong, "Separable Linkable Threshold Ring Signatures," Cryptology
ePrint Archive, Paper 2004/267, INDOCRYPT 2004.**

Primary record:

https://eprint.iacr.org/2004/267

DOI:

https://doi.org/10.1007/978-3-540-30556-9_30

The public abstract and metadata establish that the paper:

- presents a separable linkable ring-signature construction;
- defines and analyzes event-oriented linking;
- gives a security model and reductions to stated hardness assumptions;
- introduces accusatory linkability and non-slanderability notions;
- includes a threshold extension.

Those facts make it relevant to election-scoped duplicate detection.

They do not, by themselves, establish that a direct Ristretto255 port is
correct or that the threshold construction is appropriate for this project's
one-voter-per-proof use.

## Required exact construction decision

Before implementation begins, a reviewed decision record must identify:

1. the exact paper, section, algorithms, and security theorem being
   instantiated;
2. whether the project uses the paper's non-threshold or threshold variant;
3. every algebraic group and hardness assumption;
4. the exact adaptation from the paper's group notation to Ristretto255;
5. the exact event or scope input;
6. the exact link tag, key image, or nullifier equation;
7. the exact message and ring encoding;
8. all hash-to-scalar and hash-to-group functions;
9. the Fiat-Shamir transcript order and labels;
10. the proof byte encoding;
11. signer randomness requirements;
12. verifier rejection rules;
13. the anonymity, unforgeability, linkability, non-slanderability, and
    cross-scope unlinkability claims actually supported;
14. maximum ring size and denial-of-service limits;
15. deterministic positive and negative test vectors;
16. an independent review plan.

## Election-scope requirement

The event identifier must derive from the canonical election scope already
bound to the complete manifest hash.

Required behavior:

- two valid proofs from the same governance key in the same election scope
  produce linkable duplicate-detection material;
- proofs from the same governance key in different election scopes are not
  publicly linkable;
- changing the ballot payload changes the authenticated proof statement but
  does not create a second voting identity inside the same scope;
- changing the registry or manifest changes the scope;
- a malicious party cannot frame an honest registry member by manufacturing
  the member's link tag.

A formula such as ordinary LSAG key-image derivation with an election string
prepended or appended is not authorized merely because tests appear to work.

## Transcript candidate

Merlin 3.0.0 is a transcript candidate, not a selected dependency.

Primary package record:

https://docs.rs/crate/merlin/3.0.0

Its documented properties are relevant:

- Fiat-Shamir transcript automation;
- domain separation;
- framed message appends;
- protocol composition;
- transcript-bound synthetic randomness support.

Merlin must not be added until the selected construction's transcript is
specified field by field. A transcript framework cannot repair an incorrect
protocol equation.

## Hash-to-group candidate

`curve25519-dalek` 5.0.0 exposes Ristretto hash-to-group APIs behind its
optional `digest` feature.

Primary API record:

https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/ristretto/struct.RistrettoPoint.html

The `digest` feature is not enabled in Slice 1.

It must remain disabled until the construction decision specifies:

- the digest algorithm;
- input framing and domain separation;
- whether the operation hashes a public key, election scope, both, or another
  protocol value;
- interoperability vectors;
- the security rationale for the resulting link tag.

## Registry and ring rules to resolve

The implementation decision must also state:

- whether the proof ring is the complete canonical registry snapshot;
- whether smaller signer-selected rings are forbidden;
- how duplicate public keys are rejected;
- whether ring order is canonical and statement-bound;
- the minimum electorate size required before anonymity is claimed;
- the maximum supported ring size;
- whether verification cost is linear in registry size;
- how registry replacement and revocation affect election scope.

For the first pilot, using the complete frozen canonical registry is the
default research assumption. It is not yet an approved production decision.

## Proof-boundary requirements

Any future implementation must preserve these existing properties:

- `ProofVerifierV1` remains sealed;
- the application reconstructs the complete `ProofStatementV1`;
- the proof suite receives that exact statement;
- callers cannot construct `VerifiedNullifier`;
- successful verification returns the exact authenticated statement;
- ballot packages do not carry a trusted external nullifier;
- first-valid-nullifier acceptance remains outside the cryptographic suite;
- the test-only verifier remains visibly non-production.

## Explicit no-go conditions

Do not begin signer or verifier implementation while any of these are true:

- only the abstract or a secondary summary has been reviewed;
- the exact event-oriented equation has not been transcribed and checked;
- the Ristretto adaptation has no written security rationale;
- the nullifier or key-image formula is being invented locally;
- transcript fields or ordering are unspecified;
- hash-to-group or hash-to-scalar domains are unspecified;
- proof serialization is unspecified;
- ring membership and ordering rules are unspecified;
- cross-scope unlinkability has no test plan;
- non-slanderability has no adversarial test plan;
- a production suite identifier would overstate review status.

## Exit gate for Slice 2A

Slice 2A is complete when this document is preserved.

It authorizes research and exact construction review only.

It does not authorize:

- enabling the `digest` feature;
- adding SHA-2, SHA-3, Merlin, or randomness dependencies;
- adding private scalars;
- generating governance keys;
- deriving a nullifier;
- implementing a prover;
- implementing `ProofVerifierV1` for a real suite;
- changing ballot or archive formats;
- claiming production anonymity.

## Next research packet

The next packet must contain the exact equations from the selected primary
paper, a symbol-by-symbol mapping to existing protocol fields and
Ristretto255 types, and a written list of any deviations.

If the exact construction cannot be justified, the project must evaluate the
documented Semaphore fallback rather than invent a new ring-signature variant.
