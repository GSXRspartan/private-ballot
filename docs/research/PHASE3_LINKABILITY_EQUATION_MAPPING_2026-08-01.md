# Phase 3 linkability equation mapping

**Date:** 2026-08-01

## Decision status

No production anonymous-membership construction is selected.

This packet maps two primary-source constructions to the private-ballot
requirements and records why neither may be copied directly into the Rust
implementation.

The result is a compatibility decision, not a cryptographic implementation
authorization.

## Required private-ballot properties

The intended proof suite must provide all of the following:

1. membership in the complete frozen canonical governance registry;
2. signer anonymity within that registry;
3. one stable duplicate-detection value per governance key and election scope;
4. unlinkability of the same governance key across different election scopes;
5. non-frameability or non-slanderability;
6. no public recovery of the signer's registry public key;
7. proof binding to the complete canonical `ProofStatementV1`;
8. deterministic verification and canonical proof encoding;
9. no trusted external nullifier;
10. compatibility with the sealed `ProofVerifierV1` boundary.

A construction that identifies the double-signer is not a privacy-preserving
substitute for an anonymous election-scoped nullifier.

## Source A: Tsang et al. 2004/267

Primary source:

Patrick P. Tsang, Victor K. Wei, Tony K. Chan, Man Ho Au, Joseph K. Liu, and
Duncan S. Wong, "Separable Linkable Threshold Ring Signatures," Cryptology
ePrint Archive, Paper 2004/267.

https://eprint.iacr.org/2004/267

### Algebra and assumptions

The concrete construction in Section 5 uses a distinct RSA-style group for
each member:

`G_i = QR(N_i)`

where `N_i` is a safe-prime product and the group order is not publicly known.

Each public key contains:

`pk_i = (ell_i, N_i, g_i, y_i, H_i)`

with:

`y_i = g_i ^ x_i`

The secret key contains the factorization and exponent:

`sk_i = (p_i, q_i, x_i)`

The paper's stated security arguments rely on:

- the Strong RSA assumption;
- DDH over `QR(N)`;
- the random-oracle model.

These assumptions and proof techniques are not the Ristretto255 prime-order
group model.

### Event-oriented tag equation

For event identifier `e`, each member-specific event base is:

`h_(i,e) = H_i(param, pk_i, e)`

For an actual signer, the corresponding tag is:

`tag_(i,e) = h_(i,e) ^ x_i`

The signature proves equality of the secret exponent in:

`y_i = g_i ^ x_i`

and:

`tag_(i,e) = h_(i,e) ^ x_i`

The threshold construction also creates simulated tags for non-signers and
uses two proof-of-knowledge components.

### Link algorithm

For two valid signatures under the same event, the paper searches for a public
key appearing in both rings whose event tag is equal.

When found, the algorithm returns linked and additionally outputs that public
key as the suspected double-signer.

This is accusatory linkability by design.

### Private-ballot mapping

| Paper symbol | Meaning | Existing project field |
| --- | --- | --- |
| `e` | linkability event | `ElectionScope` derived from the complete manifest hash |
| `M` | signed message | canonical `ProofStatementV1` transcript bytes |
| `Y` | ring public-key set | complete frozen canonical governance registry |
| `x_i` | signer secret exponent | voter-held governance private key |
| `y_i` | member public key | canonical registered governance public key |
| `tag_(i,e)` | event tag | desired election-scoped nullifier role |
| `Verify` | signature verification | sealed `ProofVerifierV1::verify` implementation |
| linked result | repeated signer | first-valid-nullifier duplicate policy |

### Direct-port verdict

**Rejected as a direct Ristretto255 production candidate.**

Reasons:

1. The construction is built over per-user RSA groups of unknown order.
2. Its security reductions rely on Strong RSA and DDH over `QR(N)`.
3. Ristretto255 is one shared prime-order group.
4. Replacing exponentiation in unknown-order groups with Ristretto scalar
   multiplication changes the proof system and invalidates direct reliance on
   the paper's theorems.
5. The construction is threshold-oriented and includes one tag per ring member.
6. Its link algorithm identifies the suspected public key.
7. Public identification of the repeated signer conflicts with the desired
   non-accusatory anonymous-nullifier behavior.

The paper remains useful for its event-oriented security model and
non-slanderability definitions. Its concrete Section 5 construction must not
be ported by notation substitution.

## Source B: Russo et al. 2021 Chirotonia ECC scheme

Primary source:

Antonio Russo, Antonio FernÃ¡ndez Anta, MarÃ­a Isabel GonzÃ¡lez Vasco, and Simon
Pietro Romano, "Chirotonia: A Scalable and Secure e-Voting Framework based on
Blockchains and Linkable Ring Signatures," arXiv:2111.02257.

https://arxiv.org/abs/2111.02257

### Algebra and assumptions

The scheme operates in one public cyclic elliptic-curve group `E` with
generator `G`.

Key generation is:

`pk_i = sk_i * G`

The paper defines:

- `H`, a challenge hash;
- `H2P`, a hash-to-point function;
- `HPK`, an ordered recursive hash of the ring public-key tuple.

For ring `PK_n`, the link base and tag are:

`L = H2P(HPK(PK_n))`

`T = sk_pi * L`

The ring response chain uses:

`A_i = s_i * G + c_(i-1) * pk_i`

`B_i = s_i * L + c_(i-1) * T`

`c_i = H(m || T || A_i || B_i)`

Verification reconstructs the same challenge cycle. Two signatures are linked
exactly when their tags `T` are equal.

The paper states unforgeability, anonymity, linkability, and non-framability
in the random-oracle model under DDH in the selected cyclic group.

### Private-ballot mapping

| Paper symbol | Meaning | Existing project field |
| --- | --- | --- |
| `PK_n` | ordered ring | complete canonical registry public-key order |
| `HPK(PK_n)` | ring digest | registry commitment or canonical registry bytes |
| `m` | signed message | canonical `ProofStatementV1` transcript bytes |
| `sk_pi` | signer scalar | voter-held governance private key |
| `pk_pi` | signer public key | registered Ristretto governance public key |
| `T` | linkability tag | desired authenticated nullifier role |
| `c_i` | Fiat-Shamir challenges | future transcript-derived scalars |
| `s_i` | ring responses | future canonical scalar response array |

### Compatibility advantages

This construction is structurally closer to the project because:

- it uses one prime-order elliptic-curve group;
- the public key is a scalar multiple of one generator;
- the tag is a group element that does not directly name a public key;
- linkability is a simple equality check on the tag;
- the proof size and verification work are linear in ring size;
- it has an e-voting-oriented security analysis including non-framability.

### Scope failure

The published tag base depends on the ring:

`L = H2P(HPK(PK_n))`

It does not include an independent election identifier.

Therefore, if all of the following remain the same:

- governance secret key;
- ordered canonical registry;
- `HPK` encoding;
- hash-to-point function;

then `L` is the same and:

`T = sk_pi * L`

is also the same across elections.

That creates cross-election linkability when a registry and governance key are
reused.

The project explicitly requires the opposite behavior.

### Unauthorized tempting modification

A tempting replacement would be:

`L_scope = H2P(domain || election_scope || registry_commitment)`

`T_scope = sk_pi * L_scope`

This would make the base vary by election scope and appears to produce the
desired operational behavior.

It is **not authorized** by the Chirotonia paper as reviewed here.

Its anonymity, linkability, and non-framability proofs were written for the
paper's exact ring-derived base. A scoped-base modification requires an exact
security argument and independent review.

Tests demonstrating same-scope equality and cross-scope inequality would not
replace that argument.

### Direct-copy verdict

**Rejected as an unmodified production candidate.**

Reason: its tag is ring-scoped rather than election-scoped.

**Retained as a prime-order implementation reference only.**

Reason: its challenge cycle and non-accusatory tag structure are materially
closer to the desired system than the accusatory RSA construction.

## Construction comparison

| Requirement | Tsang 2004 | Chirotonia 2021 | Project need |
| --- | --- | --- | --- |
| Prime-order ECC group | No | Yes | Yes |
| Event or election scope | Yes | No, ring-scoped | Yes |
| Cross-scope unlinkability | Modeled by event | Not when ring is unchanged | Yes |
| Non-accusatory duplicate tag | No | Yes | Yes |
| Identifies suspected public key | Yes | No | No |
| Non-frameability model | Non-slanderability | Yes | Yes |
| One tag per signature | No, tag vector | Yes | Yes |
| Direct Ristretto instantiation justified | No | No | Not yet |
| Existing theorem applies unchanged | No | No for scoped modification | Required before production |

## Current decision

The primary Tsang 2004 concrete construction is demoted from implementation
candidate to security-model reference.

The Chirotonia ECC scheme is promoted to equation-level implementation
reference, but not to production construction.

No signer, verifier, transcript, hash-to-point function, scalar parser,
randomness source, proof encoding, suite identifier, or nullifier derivation
is authorized.

## Next candidate class

The next literature review must focus on a construction that is all of:

- explicitly scoped or event-oriented;
- non-accusatory;
- prime-order elliptic-curve based;
- proven anonymous, linkable, unforgeable, and non-frameable;
- compatible with one signer out of a complete canonical ring;
- free of mandatory opener or deanonymization behavior;
- precise enough to instantiate over Ristretto255 without inventing equations.

A recent scoped construction with optional or mandatory deanonymization may be
studied for its scope mechanism, but its deanonymization components must not be
silently removed.

If no suitable reviewed construction is found, the project must move to the
documented Semaphore-style membership-proof fallback.

## Implementation gate after Slice 2B

The following remain forbidden:

- adding Merlin;
- enabling the `curve25519-dalek` `digest` feature;
- adding SHA-2, SHA-3, or randomness dependencies;
- introducing `Scalar` into the public API;
- generating or importing private governance keys;
- implementing the challenge cycle;
- defining an election-scoped tag locally;
- implementing `ProofVerifierV1` for a real suite;
- assigning a production proof-suite identifier;
- changing ballot packages or archives.

The next approved work is another research packet or a documented fallback
decision, not proof code.
