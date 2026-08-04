# Phase 3 Slice 3C16: Triptych padding-boundary assurance

## Status banner

- **The full long suite has not yet been executed.** Only the harness and the
  inexpensive planning smoke test have been run.
- **The suite is ignored/manual.** It never runs in a default `cargo test`
  invocation.
- **Expected runtime may be several hours**, and on an unoptimized profile the
  extrapolation below is well beyond that.
- **Passing functional tests cannot formally prove the anonymity theorem for
  the repeated-final-key padding construction.** Everything recorded here is
  behavioural evidence about the existing construction.

## Starting state

- Branch: `phase3/anonymous-membership-prototype`
- HEAD: `50319fdc1ad56796607fb350d50b10aa47ae59d7`
- Working tree: clean before the slice began.
- Rust toolchain: `1.97.1`.
- Network access: none; all Cargo commands used `--locked --offline`.

## Scope

This slice adds one test file and this evidence file. No production source, no
vendored Triptych source, no manifest, and no lockfile was changed. The slice
adds no batch verification, no unsafe code, no `unwrap()`, `expect()`, `todo!()`
or `unimplemented!()`, and no warning suppression.

The suite is deliberately **not** another complete archive/tally election
replay. It performs no archive transcript, no tally, and no relay-receipt work.
Its subject is cryptographic membership, padding, nullifier semantics,
serialization shape, and signer-position behaviour at the 256-member ring
boundary.

## Files changed

- `crates/cli/tests/triptych_padding_boundary_assurance.rs` (new)
- `docs/reviews/PHASE3_SLICE3C16_TRIPTYCH_PADDING_BOUNDARY_ASSURANCE_2026-08-03.md` (new)

## Test target and names

- Package: `tari-cc-private-ballot-cli`
- Target: `--test triptych_padding_boundary_assurance`
- Ignored/manual test:
  `manual_triptych_padding_boundary_assurance_covers_every_signer_position`
- Non-ignored smoke test:
  `boundary_planning_table_and_key_fixture_are_consistent`

Manual invocation:

```bash
cargo test --locked --offline --release -p tari-cc-private-ballot-cli --test triptych_padding_boundary_assurance -- --ignored --nocapture
```

## Registry sizes and derived padded capacities

| Members | Triptych base `n` | Exponent `m` | Padded capacity `N = n**m` | Final-key repeats |
| ------- | ----------------- | ------------ | -------------------------- | ----------------- |
| 249     | 2                 | 8            | 256                        | 7                 |
| 250     | 2                 | 8            | 256                        | 6                 |
| 255     | 2                 | 8            | 256                        | 1                 |
| 256     | 2                 | 8            | 256                        | 0                 |
| 257     | 2                 | 9            | **512**                    | 255               |

### How the 257 capacity was derived, not guessed

Two independent derivations must agree, for every proof of every size:

1. **Planned.** `plan_triptych_ring_v1` reproduces the upstream
   `TriptychParameters` constraints (`n > 1`, `m > 1`, ring size `N = n**m`,
   `n**m` must not overflow `u32`) and selects the smallest exponent whose
   capacity holds the registry. For 257 members the smallest valid exponent is
   `m = 9`, giving `N = 512`.
2. **Observed.** The upstream Triptych serializer writes `n - 1` and `m` as
   leading little-endian `u32` values
   (`third_party/tari-triptych/src/proof.rs`, `TriptychProof::to_bytes`). The
   suite reads those two fields back out of the canonical proof bytes produced
   by the real project prover and recomputes `N`. This is the parameter set the
   real construction actually used, not a restatement of the plan.

Every signer of every size must report the planned base, exponent, and capacity,
and the observed inner-proof length must equal the length implied by the plan.

The observation path was validated end to end against real proofs at known small
capacities during harness validation (see *Harness validation*), where the
observed `(n, m)` and the predicted serialized lengths matched exactly.

## Properties covered

### Registry construction and verifier configuration

- One deterministic canonical registry per size, built from the existing
  `crates/cli/tests/fixtures/triptych_large_election_keys_2048.bin` fixture,
  whose chunk `index` is the public key of signing scalar `index + 1`.
- Registry uniqueness is asserted directly, and again structurally by
  `RegistrySnapshot::from_canonical_cbor`, which rejects duplicates and
  non-canonical ordering.
- The verifier is constructed only through
  `build_tari_triptych_verifier_from_registry_v1`, so the commitment and the key
  bytes always come from the same frozen snapshot.
- Recorded per size: true member count, padded ring capacity, Triptych base and
  exponent, padding repeat count, registry commitment, and proof-suite
  identifier.

### Every real voter position

For every registry position of every size the suite constructs the real secret,
generates a real Triptych proof, accepts it through the project-owned
manifest-bound ingestion boundary, and then confirms:

- the authenticated nullifier is nonempty, exactly 32 bytes, not the identity
  encoding, and equal to the envelope linking tag. Canonical, non-identity
  point encoding is enforced by `TariTriptychProofEnvelopeV1`, which is the
  project-owned gate the verifier itself uses;
- the envelope re-encodes to exactly the submitted bytes;
- the proof does **not** verify against another ballot statement in the same
  election, nor against the same ballot in a different election;
- the canonical package region outside the opaque proof byte string is
  byte-identical to every other signer's, so no project-owned package field
  varies with signer position.

### Nullifier behaviour

Per voter, four real proofs are generated:

| Case                                            | Required outcome                |
| ----------------------------------------------- | ------------------------------- |
| same voter, same election, same ballot          | identical nullifier             |
| same voter, same election, different valid choice | identical nullifier           |
| same voter, different election                  | different nullifier             |
| adjacent voters, same election                  | different nullifiers            |

The per-size unique nullifier count must equal the member count, and the
acceptance ledger must hold exactly one ballot per member.

For the final real registry key — the key the padding repeats — the suite
additionally requires that a second valid ballot from that voter is rejected as
`DUPLICATE_NULLIFIER` through `ingest_approval_ballot_package_v1`, with the
ledger length unchanged. Together with the unique-nullifier count this is the
evidence that repeated-final-key padding does not create extra usable voter
identities: the repeated slots contribute no additional accepted ballot and no
additional nullifier.

### Proof-size invariant

Within each registry size, and with ballot content length held constant, the
suite records the inner Triptych proof length, the complete envelope length, and
the complete canonical ballot-package length as ordered sets. It reports minimum,
maximum, and unique length counts, and fails if any of the three has more than
one unique value. A signer-position-dependent length difference therefore fails
the test rather than being reported as a note.

### Padding-boundary binding

- The padded verification-key vector is compared across sizes using a read-only
  model of the documented repeated-final-key rule. The model is asserted to
  contain every real key followed only by repeats of the final real key, and the
  five padded vectors are asserted pairwise distinct. The model never feeds a
  proof or a verification.
- Each transition (249→250, 250→255, 255→256, 256→257) is asserted to change the
  registry commitment and the complete canonical proof statement.
- A valid proof is verified against a verifier that pairs the *original*
  registry commitment with a *foreign* padded key vector, using the public
  `TariTriptychPrototypeVerifierV1::new` constructor. This bypasses the
  commitment gate and forces the failure to come from the Triptych statement
  itself. Cases: each of the four other boundary sizes, one real member removed,
  and one real member added. All must fail with `MALFORMED_PROOF`. The 256↔257
  case is specifically a proof generated under one padded capacity verified
  under another.
- The same foreign registries are also tried through the normal
  registry-bound factory, where they must fail earlier with `INVALID_DATA`
  because the commitment does not match.

**Upstream unpadded-size binding.** `TriptychInputSet::new_with_padding` passes
the *unpadded* length into `new_internal`, which appends `unpadded_size` to the
input-set transcript before the padded key vector
(`third_party/tari-triptych/src/statement.rs`). That binding is therefore
present in the input-set hash, and through it in the statement hash. This slice
records that as a source-level property of the vendored implementation, and
deliberately does **not** claim to have tested it directly: it is not reachable
through project-owned APIs. Constructing two project registries whose padded
vectors coincide but whose unpadded sizes differ would require a registry whose
last two keys are equal, and `RegistrySnapshot::from_canonical_cbor` rejects
duplicate governance keys. The suite asserts the reachable consequence instead —
that all five padded key vectors are distinct, so padded-vector binding alone
already separates every boundary registry.

### Unauthorized and padding-related attempts

Each must be rejected cleanly, and the acceptance-ledger length is asserted
unchanged across the whole rejection matrix:

| Attempt                                                        | Expected code              |
| -------------------------------------------------------------- | -------------------------- |
| unregistered secret                                             | `INVALID_DATA`             |
| zero secret scalar                                              | `INVALID_DATA`             |
| noncanonical secret scalar                                      | `INVALID_DATA`             |
| duplicate real public key in the canonical registry             | `DUPLICATE_GOVERNANCE_KEY` |
| identity public key in the canonical registry                   | `MALFORMED_PROOF`          |
| final real key signing against a registry that excludes it      | `INVALID_DATA`             |
| proof verified under a different padded capacity or key vector  | `MALFORMED_PROOF`          |
| proof verified under a foreign registry commitment              | `INVALID_DATA`             |
| valid inner proof paired with another voter's linking tag       | `MALFORMED_PROOF`          |
| the same swapped-nullifier package through normal ingestion     | `MALFORMED_PROOF`          |

The swapped-nullifier case is constructible because
`TariTriptychProofEnvelopeV1::new` accepts any canonical non-identity tag; the
project API permits building that malformed input, and it must not verify.

Capacity mismatch does not panic upstream: `TriptychProof::verify` checks that
the proof `f` matrix has `m` rows and `n - 1` columns and returns an error, which
the project verifier maps to `MALFORMED_PROOF`.

### Package inspection

For the first, middle, penultimate, and final voters of each size the suite
inspects the canonical package bytes and requires:

- identical total package length;
- a byte-identical prefix covering every project-owned field outside the proof
  byte string, i.e. protocol version, manifest hash, proof-suite identifier, the
  canonical payload byte string, and the proof byte-string header;
- distinct proof regions of identical length.

Because the prefix is byte-identical across signer positions, no project-owned
package field can encode a signer index or voter position, and no
variable-length serialization was observed. **This is not a proof of zero
knowledge.** The only claim made is that no explicit application-level signer
index and no variable-length serialization was observed in project-owned package
fields.

## Progress and evidence output

`--nocapture` is required to see progress. Emitted at least:

- one `begin` line per registry size, with `members`, `padded_capacity`,
  `triptych_base`, `triptych_exponent`, `padding_repeats`,
  `registry_commitment`, and `proof_suite`;
- one `progress` line every 25 completed signers, with the signer counter,
  cumulative proof count, accepted count, and cumulative prove/verify
  milliseconds;
- one `package_inspection` line per size;
- one `complete` line per size carrying every required field: `members`,
  `padded_capacity`, `proof_count`, `prove_ms_total`, `prove_ms_average`,
  `verify_ms_total`, `proof_bytes_min`, `proof_bytes_max`,
  `envelope_bytes_min`, `envelope_bytes_max`, `package_bytes_min`,
  `package_bytes_max`, `unique_nullifier_count`, and `duplicate_rejection`;
- one `transition` line per adjacent size pair.

`proof_bytes` is the inner canonical Triptych proof, `envelope_bytes` is the
complete project proof envelope, and `package_bytes` is the complete canonical
ballot package.

## Harness validation

The long suite was **not** run. To avoid staging an unexercised multi-hundred-line
harness, the complete per-size code path was validated once with the size list
temporarily reduced to `[5, 6, 7, 8, 9]`, which reproduces the same structure
(four sizes at or below a power-of-two capacity plus one size just above it).
That temporary edit was reverted before staging; the staged file carries the
required `[249, 250, 255, 256, 257]` list, and the restored file was re-checked
with `rustfmt --check`, `cargo check`, `cargo clippy`, and the default test run.

Every assertion in the suite executed and passed in that reduced run, including
the rejection matrix, duplicate rejection, package inspection, and all four
boundary transitions. Measured there, on the unoptimized `test` profile:

| Capacity | Exponent | Inner proof bytes | Envelope bytes | Package bytes | Identical prefix bytes | Prove ms/proof |
| -------- | -------- | ----------------- | -------------- | ------------- | ---------------------- | -------------- |
| 8        | 3        | 520               | 554            | 635           | 81                     | 341–437        |
| 16       | 4        | 616               | 650            | 731           | 81                     | 626            |

Those observed lengths match the planned serialization formula exactly, which is
the same formula that predicts 1,000 inner bytes at capacity 256 and 1,096 at
capacity 512. The corresponding predicted envelope lengths are 1,034 and 1,130,
and the predicted package lengths are 1,115 and 1,211. These are predictions to
be confirmed by the long run, not measurements.

### Runtime expectation

Extrapolating linearly in ring size from the two measured points above, one
proof on the unoptimized profile costs roughly 7.5 s at capacity 256 and roughly
15 s at capacity 512. The suite generates four real proofs per voter, i.e.
`4 x (249 + 250 + 255 + 256 + 257) = 5,068` proofs, so the unoptimized profile
extrapolates to well over ten hours before verification cost. Verification adds
roughly a quarter again.

The long run should therefore use `--release`. This is a rough extrapolation
from a small-ring measurement, not a measurement of the real suite.

## Validation performed

All commands completed successfully with Rust `1.97.1`, `--locked`, and
`--offline`:

```powershell
rustup.exe run 1.97.1 rustfmt --edition 2024 --check crates/cli/tests/triptych_padding_boundary_assurance.rs
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test triptych_padding_boundary_assurance
rustup.exe run 1.97.1 cargo check --manifest-path Cargo.toml --locked --offline --workspace --all-targets
rustup.exe run 1.97.1 cargo clippy --manifest-path Cargo.toml --locked --offline --workspace --all-targets --no-deps -- -D warnings
```

The default test invocation reports exactly one ignored test:

```
running 2 tests
test manual_triptych_padding_boundary_assurance_covers_every_signer_position ... ignored, manual real Triptych padding-boundary assurance for 249/250/255/256/257 members
test boundary_planning_table_and_key_fixture_are_consistent ... ok

test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.68s
```

The only clippy/rustc warning in the workspace build is the pre-existing
`OperationTiming::Variable` dead-code warning inside the vendored Triptych
crate, which is unchanged by this slice.

Not run: the full 249/250/255/256/257 suite, the existing 128/250/256 complete
election suite, the 4,096-member protocol-limit test, the performance harness,
fuzz campaigns, and timing experiments.

## Vendored Triptych

`third_party/tari-triptych/` is unchanged: no staged entry, no working-tree
diff, and no untracked file under that path. The vendored crate is read for
evidence only — the leading `n - 1` and `m` serialization fields, the padding
rule, the input-set `unpadded_size` binding, and the `verify` dimension checks
are all cited, never modified.

## Limitations

- The full long suite has not been executed. Every per-size number in this file
  other than the reduced-run table is a plan or a prediction.
- Passing this suite would be functional evidence only. It cannot formally prove
  the anonymity theorem for the repeated-final-key padding construction, and it
  makes no claim about proof indistinguishability, side channels, or timing.
- The upstream `unpadded_size` binding is recorded from vendored source, not
  demonstrated by a project-level test, because project registry uniqueness makes
  the distinguishing case unreachable.
- No machine-learning or timing-leakage classification was performed in this
  slice.

## Staging evidence

The final staged-file count, per-blob byte counts and SHA-256 values, and the
complete staged binary-patch byte count and SHA-256 are recorded in the task
handoff after this evidence file itself is staged. This avoids claiming a
self-referential checksum inside the file being hashed.

No commit was created.
