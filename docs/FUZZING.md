# Parser Fuzzing

## Purpose

The standalone `fuzz/` workspace exercises every public version-one
canonical decoder currently published by the project.

The targets test parser safety and canonical invariants. They do not establish
anonymous eligibility, cryptographic security, authorization, or suitability
for binding elections.

## Pinned environment

The validated Slice 12D environment uses:

- `cargo-fuzz 0.13.2`;
- `libfuzzer-sys 0.4.13`;
- `nightly-2026-07-31`;
- Linux x86_64;
- a C++11 compiler;
- `llvm-symbolizer`.

The fuzz workspace is separate from the production Cargo workspace. Fuzz-only
dependencies therefore do not enter the production dependency graph.

## Targets

The seven targets are:

1. `canonical_cbor_reader`;
2. `registry_snapshot`;
3. `candidate_set`;
4. `approval_ballot_payload`;
5. `election_manifest`;
6. `ballot_package`;
7. `archive_manifest`.

Each object decoder target enforces:

- arbitrary input never panics before an invariant violation;
- successful decoding consumes a canonical object;
- successful decoding re-encodes byte-for-byte identically;
- the re-encoded object decodes and re-encodes identically again;
- canonical hashes or commitments are deterministic.

Payload and package targets use a fixed three-option approval context. This
preserves the decoder API's required candidate-set and approval-limit inputs
without deriving semantic context from fuzzer-controlled bytes.

## Seed corpora

Run from the repository root:

```text
python3 fuzz/import_seeds.py --root .
```

The importer copies:

- all nine checked-in valid canonical vectors to relevant targets;
- all 16 hostile CBOR cases to every target;
- one empty seed per target.

Generated corpora remain local under `fuzz/corpus/` and are not committed.

## Build offline

From the repository root:

```text
CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=nightly-2026-07-31 CXX=g++ \
  cargo fuzz build canonical_cbor_reader
```

Replace the target name to build another target.

## Bounded smoke run

```text
CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=nightly-2026-07-31 CXX=g++ \
  cargo fuzz run registry_snapshot fuzz/corpus/registry_snapshot -- \
  -runs=64 -max_len=4096 -timeout=5 -rss_limit_mb=2048
```

A bounded smoke run proves the harness builds and executes. It is not a
substitute for a sustained campaign.

## Sustained campaign

A longer campaign should:

- run each target independently;
- retain newly discovered corpus entries;
- preserve crash and timeout artifacts;
- record toolchain and commit identifiers;
- reproduce failures with `cargo fuzz run <target> <artifact>`;
- minimize stable failures before opening an issue.

No target performs network, walletd, Ootle, indexer, or filesystem mutation
outside cargo-fuzz's local corpus and artifact directories.
