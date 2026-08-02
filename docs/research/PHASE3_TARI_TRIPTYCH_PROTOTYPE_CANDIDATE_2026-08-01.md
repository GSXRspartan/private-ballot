# Phase 3 Tari Triptych Prototype Candidate Selection

## Decision metadata

- Decision date: 2026-08-01
- Repository branch: `phase3/anonymous-membership-prototype`
- Parent commit: `0df49e8`
- Slice: Phase 3 Slice 2C
- Status: `SELECTED_FOR_PHASE3_PROTOTYPE_ONLY`
- Production status: `BLOCKED_PENDING_SECURITY_ARGUMENT_AND_INDEPENDENT_REVIEW`
- Binding-election authorization: `NO`
- Production dependency authorization: `NO`
- Ootle-native proof-verification authorization: `NO`

## Decision

The official Tari Triptych implementation is selected as the primary
anonymous-membership candidate for the Phase 3 prototype.

This selection authorizes documentation, isolated adapters, deterministic test
vectors, and non-binding local prototype experiments. It does not approve the
construction for production, binding elections, native Ootle verification, or
security claims beyond the exact source audit and behavioral probes recorded
below.

Semaphore remains the principal fallback if the scoped-generator construction
cannot receive an adequate security argument or the upstream implementation
cannot be production-hardened.

The Tsang et al. construction remains a security-model reference. Chirotonia
remains a prime-order equation reference. Neither is selected as the Phase 3
prototype implementation.

## Exact upstream identity

The audited source is the official Tari repository:

- Repository: `https://github.com/tari-project/triptych.git`
- Commit: `bf0cb42fff55636a8bb037020411fb3a050af23f`
- Tree: `6825e30904a7815f16987e9fb891ca197e415d08`
- Commit date: `2025-07-14T11:55:04-05:00`
- Commit subject: `Increase weight entropy (#114)`
- Package: `triptych`
- Package version: `0.1.1`
- License: `BSD-3-Clause`
- Tracked files: `29`
- Tracked-source SHA-256:
  `ADAEC1AD96596ECD4466F993D5C08FC36C05E696A566C860F0AC705904972FE8`

The implementation uses Ristretto, Merlin 3.0.0, BLAKE3, canonical proof
encoding, witness zeroization, batch verification, and a `no_std`-friendly
crate structure.

The upstream crate explicitly describes itself as experimental and unsuitable
for production use. This warning is inherited unchanged by this decision.

## Upstream validation evidence

The exact committed source was copied by Git archive into a native Linux
filesystem and validated against 85 offline-vendored dependency manifests and
85 checksum files.

The following native Linux gates passed with Rust 1.97.1:

- `cargo check --locked --offline --all-targets --all-features`
- Clippy with all warnings denied except the named Rust 1.97
  `clippy::manual_is_multiple_of` style drift in two unchanged upstream lines
- 38 library tests
- 1 RingCT example test
- 2 documentation tests

The upstream validation total was 41 passing tests and zero failures.

A dependent-crate build also emitted one upstream `dead_code` warning for
`OperationTiming::Variable`. Cargo's dependency lint cap prevented that
upstream warning from becoming a failure. A production integration must decide
whether to patch, configure, or otherwise account for this warning rather than
silently losing strict lint coverage.

## Exact Triptych relation

For fixed independent Ristretto generators `G` and `U`, Triptych proves the
relation:

```text
{ M, J ; (l, r) : M[l] = r * G, r * J = U }
```

The audited implementation therefore defines:

```text
verification key M[l] = r * G
linking tag     J    = r^-1 * U
```

The verification key depends on the governance private scalar `r` and the
stable generator `G`. The linking tag depends on the same scalar and the
linking generator `U`.

`TriptychParameters::new_with_generators(n, m, G, U)` accepts caller-supplied
generators. The implementation binds `n`, `m`, `G`, `U`, commitment
generators, and the commitment blinding generator into the parameter hash.

`TriptychStatement` binds the parameter hash, input-set hash, and linking tag
`J`. The input-set hash binds the ordered verification-key vector and the
original unpadded size.

## Why election-scoped `U` is operationally desirable

The prototype keeps `G` stable and proposes a deterministic
election-specific `U_election`.

This gives the intended behavior:

- the same governance private key produces the same public verification key
  across elections;
- the same key produces the same linking tag within one election;
- the same key produces a different linking tag in a different election;
- duplicate ballots can be detected within the election;
- the public archive does not expose a stable cross-election linking tag.

This is operationally compatible with a long-lived voter-created governance
key and election-scoped first-valid-ballot handling.

Behavioral compatibility is not a proof that changing `U` per election
preserves Triptych's anonymity, unforgeability, linkability, exculpability, or
non-frameability assumptions. That security argument remains the main
construction gate.

## Provisional `U_election` derivation

The following derivation is recorded for prototype vectors and review. It is
not production-approved.

```text
generator_domain =
  UTF8("tari-cc-private-ballot-triptych-scope-generator-v1")

generator_input =
  generator_domain
  || LE64(protocol_version)
  || LE32(byte_length(proof_suite_id))
  || UTF8(proof_suite_id)
  || LE32(byte_length(election_scope))
  || election_scope

uniform_bytes =
  BLAKE3-XOF(generator_input, 64 bytes)

U_election =
  RistrettoPoint::from_uniform_bytes(uniform_bytes)
```

Prototype constraints:

1. `protocol_version` is the exact version reconstructed in
   `ProofStatementV1`.
2. `proof_suite_id` is the exact suite identifier reconstructed in
   `ProofStatementV1`.
3. `election_scope` is the exact canonical election scope derived from the
   canonical election-manifest hash.
4. Length fields are unsigned little-endian integers with the widths shown
   above.
5. The ballot payload, voter key, ballot choice, and proof randomness are not
   inputs. `U_election` must be identical for every ballot in the election.
6. The derived point must not be the Ristretto identity.
7. The derived point must not equal `G`.
8. Any derivation-version change requires a new proof-suite identifier,
   vectors, compatibility decision, and archive metadata.
9. The authority must not be allowed to provide an arbitrary unvalidated
   `U`; verifiers derive it independently from canonical protocol data.
10. Production use remains blocked until an independent reviewer confirms
    that this derivation provides generators with the independence properties
    required by the Triptych security model.

## Behavioral scope-probe result

An isolated native Linux probe used:

- `G`: the Ristretto basepoint
- `n = 2`
- `m = 3`
- ring size `N = n^m = 8`
- the same private scalar and signer index in two election scopes
- deterministic BLAKE3-XOF-to-Ristretto derivation for each `U_election`
- a caller-supplied Merlin transcript for protocol-statement binding

The probe established:

- deterministic scope-generator derivation;
- nonidentity scope generators;
- distinct generators for distinct election scopes;
- scope generators unequal to `G`;
- same key and same scope produce the same linking tag;
- same key and different scopes produce different linking tags;
- the public verification key is stable across scopes;
- a changed protocol message fails verification;
- changed scope parameters fail verification;
- a proof created under the second scope verifies under that scope;
- canonical proof serialization round-trips exactly.

The observed ring-eight proof was 520 bytes. One optimized local run measured:

- proving: 5,198 microseconds;
- verification: 2,543 microseconds.

These timings are a single-machine observation, not a benchmark,
service-level objective, capacity claim, or side-channel analysis.

## Protocol transcript mapping

The prototype transcript label is:

```text
tari-cc-private-ballot-triptych-v1
```

The verifier reconstructs the exact `ProofStatementV1`, obtains its canonical
protocol encoding, and appends those bytes under the Merlin label:

```text
proof_statement_v1
```

The canonical statement binds:

- protocol version;
- proof-suite identifier;
- canonical election-manifest hash;
- canonical election scope;
- registry commitment;
- canonical ballot-payload hash;
- ballot-kind identifier;
- ballot-confidentiality identifier.

Triptych additionally binds its parameters, ordered input set, original
unpadded size, and linking tag internally.

The prover and verifier must use byte-identical transcript labels and
canonical statement bytes. Field-by-field ad hoc transcripts, display text,
JSON, platform-native integer encodings, or partially reconstructed statements
are not authorized.

The existing verifier boundary must continue to reject a verified result if
the returned statement differs from the exact statement reconstructed by the
caller.

## Registry ordering, sizing, and prototype padding

The prototype registry policy is:

1. Parse every governance verification key from its canonical 32-byte
   compressed Ristretto encoding.
2. Reject malformed, noncanonical, and identity encodings.
3. Reject duplicate real verification keys before any padding.
4. Sort real verification keys lexicographically by their canonical 32-byte
   encoding.
5. Record the real, unpadded registry size in the canonical registry object.
6. Use `n = 2`.
7. Select the smallest integer `m >= 2` such that `2^m` is at least the real
   registry size.
8. Set `N = 2^m`.
9. For a non-power-of-two registry, use the audited upstream
   `TriptychInputSet::new_with_padding` behavior: repeat the final sorted real
   verification key until the vector length is `N`.
10. The signer index refers only to the real sorted registry and must be less
    than the unpadded size. A padded duplicate position is never an eligible
    signer index.
11. The verifier reconstructs the same sorted real registry, the same
    parameters, and the same upstream padding result.
12. Any disagreement in ordering, real size, parameters, padding, or
    canonical key bytes is a verification failure.

For the six-member Tari Council, this policy produces `m = 3`, `N = 8`, and
two repeated trailing entries.

Upstream explicitly warns callers to decide whether repeated-last-key padding
is safe for their use case. Before production, independent review must analyze
duplicate positions, anonymity-set accounting, malicious key placement,
non-frameability, and whether a different padding construction is required.

## Nullifier interpretation

For this prototype, the canonical compressed linking tag `J` is the
election-scoped duplicate-ballot identifier returned only after successful
proof verification.

The archive-level nullifier representation must be a versioned canonical
encoding of that verified tag. No separate home-grown formula may combine the
private key, public key, election scope, or registry commitment outside the
reviewed Triptych construction.

A nullifier is accepted only after:

1. canonical proof parsing;
2. exact parameter and registry reconstruction;
3. exact transcript reconstruction;
4. successful Triptych verification;
5. successful binding to the exact `ProofStatementV1`;
6. canonical linking-tag encoding;
7. first-valid-ballot duplicate handling.

## `curve25519-dalek` integration choices

The ballot workspace currently uses `curve25519-dalek` 5.0.0. The audited
Triptych crate uses 4.1.3.

This document does not authorize a dependency change. The compile-first
prototype slice must select and record one of these approaches:

### Option A: isolated adapter crate

Keep the audited Triptych dependency on 4.1.3 in a private adapter crate.
Exchange only canonical 32-byte Ristretto encodings across the crate boundary.
Do not expose either version's `RistrettoPoint` in the public protocol API.

Advantages:

- smallest change to the audited source;
- preserves the existing 5.0.0 ballot parser;
- makes the version boundary explicit.

Costs:

- two curve-library versions in the dependency graph;
- duplicate code and audit surface;
- canonical conversion and identity checks must be tested at both sides.

### Option B: reviewed Triptych update to 5.0.0

Maintain a narrowly reviewed fork or upstream contribution that updates
Triptych to `curve25519-dalek` 5.0.0.

Advantages:

- one curve-library version;
- simpler internal types and dependency graph.

Costs:

- no longer byte-for-byte identical to audited upstream commit `bf0cb42`;
- requires a focused source diff, full upstream tests, canonical-proof checks,
  fuzzing, and independent review.

### Rejected integration shortcut

Downgrading the existing ballot substrate from 5.0.0 solely to match Triptych
is not authorized by this packet.

The first code slice should prefer a private adapter boundary and compile
before deciding whether a maintained 5.0.0 port is justified.

## Verification placement and Ootle boundary

The first Triptych verifier remains local and offline-capable.

The offline archive remains independently authoritative and verifiable. Ootle
continues to provide append-only lifecycle and commitment anchoring only.

The initial Ootle data may commit to:

- election-manifest hash;
- registry commitment;
- election lifecycle state;
- ballot-package or archive commitment;
- final archive commitment.

This packet does not claim that an Ootle template verifies Triptych proofs. It
does not authorize embedding Triptych, Merlin, BLAKE3-to-Ristretto derivation,
registry reconstruction, or proof parsing in a template.

Any native Ootle verifier requires a separate architecture decision,
deterministic execution analysis, dependency and resource review, consensus
compatibility analysis, test vectors, and security review.

## Required security argument

Before production use, an independent cryptographic review must address at
least:

1. Whether replacing fixed global `U` with independently derived
   `U_election` preserves Triptych's stated security properties.
2. Whether an authority choosing manifest inputs can bias `U_election`,
   create related generators, frame a voter, or weaken anonymity.
3. Whether the BLAKE3-XOF-to-Ristretto derivation provides the required
   generator independence from `G` and from generators in other elections.
4. Whether cross-election linking remains infeasible when public
   verification keys are stable and election tags are published.
5. Whether repeated-last-key padding changes anonymity, witness ambiguity,
   batch verification, or non-frameability.
6. Whether duplicate, rogue, small-subgroup-equivalent, malformed, or
   adversarially ordered public keys create attacks.
7. Whether the exact transcript mapping prevents replay across elections,
   registries, ballot kinds, confidentiality modes, and payloads.
8. Whether canonical parsing and serialization reject malleable proofs,
   points, scalars, and trailing bytes.
9. Whether prover randomness, witness handling, zeroization, and timing
   behavior are suitable for supported desktop platforms.
10. Whether batch verification reports and handles invalid proofs safely.
11. Whether the selected ring-size policy provides meaningful anonymity for
    a six-member council.
12. Whether the implementation and dependency versions are maintained and
    production-suitable.

## Prototype implementation gates

No production dependency or code is authorized until a later slice records:

- the chosen dalek integration approach;
- a private adapter API that does not expose third-party point types;
- canonical key, tag, and proof byte encodings;
- exact proof-suite and transcript identifiers;
- deterministic generator vectors for multiple elections;
- registry ordering and six-to-eight padding vectors;
- same-election duplicate detection;
- cross-election unlinkability behavior tests;
- wrong-manifest, wrong-registry, wrong-payload, wrong-kind, and
  wrong-confidentiality rejection tests;
- malformed proof and trailing-byte rejection;
- proof-size and bounded-input limits;
- native Windows, Linux, and macOS validation status;
- fuzzing of all untrusted parsers;
- an explicit non-binding pilot marker.

## Current decision state

```text
primary_phase3_prototype_candidate=TARI_TRIPTYCH
official_upstream_commit=bf0cb42fff55636a8bb037020411fb3a050af23f
scoped_generator_mechanism=BEHAVIORALLY_COMPATIBLE
scoped_generator_security_argument=NOT_YET_ESTABLISHED
production_construction_selected=NO
binding_election_authorized=NO
ootle_native_verification_authorized=NO
semaphore_fallback=RETAINED
```

The next implementation work is a small private adapter prototype. It must not
be described as production anonymous voting, and it must preserve the existing
sealed proof-verifier boundary.
