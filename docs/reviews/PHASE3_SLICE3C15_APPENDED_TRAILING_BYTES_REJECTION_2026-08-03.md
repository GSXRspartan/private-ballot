# Phase 3 Slice 3C15: appended trailing-byte rejection

## Starting state

- Branch: `phase3/anonymous-membership-prototype`
- HEAD: `1c5f59ad33cb97d1a4ada1d04f385d9b7fed8d55`
- Working tree: clean before the slice began.
- Rust toolchain: `1.97.1`.
- Network access: none; all Cargo commands used `--locked --offline`.

## Outcome

No production defect was found at the normal untrusted acceptance boundaries,
so this slice adds regression tests only. Canonical ballot-package decoding
consumes the entire CBOR input and returns `TRAILING_CBOR_DATA` for an appended
suffix. The real Triptych verifier parses the entire inner proof before
verification and returns `MALFORMED_PROOF` for an appended suffix.

`TariTriptychProofEnvelopeV1::from_bytes` remains the documented structural
transport decoder: its fixed header has no inner-proof length field, and it
preserves every remaining byte rather than interpreting a valid prefix. The
normal verifier immediately applies canonical Triptych parsing to that complete
payload, so a suffix cannot produce a verified proof or an accepted ballot.

## Coverage added

- `crates/crypto/src/triptych_verifier.rs`
  - Starts from real canonical Triptych proof bytes and a real envelope.
  - Confirms the unmodified proof parses and verifies.
  - Appends each suffix below and repeats canonical parsing plus verifier
    invocation three times, requiring `MALFORMED_PROOF` each time.
  - Confirms structural envelope decoding retains the complete altered byte
    sequence, ruling out prefix-only interpretation.

- `crates/verifier/tests/real_triptych_ballot.rs`
  - Starts from a real canonical `BallotPackageV1` and verifies its exact
    decode/re-encode round trip.
  - Exercises direct package decoding and the normal
    `ingest_approval_ballot_package_v1` path.
  - Repeats every failed ingestion three times with the same expected code and
    an empty acceptance ledger.
  - After every failed mutation, accepts the original unmodified package and
    then confirms a second original submission returns `DUPLICATE_NULLIFIER`.

## Suffix families

The inner Triptych proof and envelope path cover:

- one zero byte;
- one nonzero byte;
- eight arbitrary bytes;
- 32 arbitrary bytes;
- the serialized first point from another valid proof;
- the version-and-linking-tag header from another valid envelope; and
- a complete second valid envelope.

The outer canonical ballot-package path covers:

- one zero byte;
- one nonzero byte;
- eight arbitrary bytes;
- 32 arbitrary bytes; and
- canonical approval-payload CBOR bytes.

## Acceptance-path result

The normal ingestion sequence exercised by the regression is:

`untrusted package bytes -> canonical package decoding -> manifest and suite
binding -> authoritative candidate-set validation -> approval-limit validation
-> Triptych envelope parsing -> canonical proof parsing and verification ->
lifecycle validation -> nullifier-ledger acceptance`.

Outer package suffixes stop at canonical decoding with
`TRAILING_CBOR_DATA`; inner proof-envelope suffixes stop during proof handling
with `MALFORMED_PROOF`. In both cases the ledger stays empty, the original
package remains acceptable afterward, and only the subsequent original
submission is rejected as `DUPLICATE_NULLIFIER`.

## Validation

All commands completed successfully with Rust `1.97.1`, `--locked`, and
`--offline`:

```powershell
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-crypto --features test-only-suites
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-verifier
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-verifier --test real_triptych_ballot
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test hostile_cbor_corpus
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test deterministic_mutation_matrix
rustup.exe run 1.97.1 cargo check --manifest-path Cargo.toml --locked --offline --workspace --all-targets
rustup.exe run 1.97.1 cargo clippy --manifest-path Cargo.toml --locked --offline --workspace --all-targets --no-deps -- -D warnings
```

The excluded long election and all-signer suites, fuzz campaigns, and timing
experiments were not run. Rustfmt was run only on the two changed project-owned
Rust files. No vendored Triptych source was changed.

## Staging evidence

The final staged-file count, per-blob byte counts and SHA-256 values, and the
complete staged binary-patch byte count and SHA-256 are recorded in the task
handoff after this evidence file itself is staged. This avoids claiming a
self-referential checksum inside the file being hashed.

No commit was created.
