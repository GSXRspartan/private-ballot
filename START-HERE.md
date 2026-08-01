# Start Here

This repository contains the non-production protocol foundation for a private
Tari governance ballot system.

## Current position

- Phase 1 specification foundation: complete.
- Phase 2 offline Rust foundation: complete at `d9e46e1`.
- Phase 3 anonymous-membership prototype and cross-platform CI: next.
- Harmless non-binding pilot: not started.
- Ootle anchoring: not implemented.
- Binding election use: prohibited.

The current test proof and hash providers are deterministic, forgeable, and
non-anonymous. The repository does not yet provide production anonymous
eligibility.

## Read in this order

1. `README.md`
2. `PHASE_STATUS.md`
3. `ROADMAP.md`
4. `docs/reviews/PHASE2_CLOSEOUT_2026-08-01.md`
5. `docs/PHASE1_PROTOCOL_SPEC_v0.1.md`
6. `docs/OPEN_QUESTIONS.md`
7. `docs/decisions/ADR-0001-offline-authority-ootle-anchor.md`
8. `docs/decisions/ADR-0002-governance-keys.md`
9. `docs/decisions/ADR-0003-governance-source-and-mvp-scope.md`
10. `docs/decisions/ADR-0004-ballot-and-tally-policy.md`
11. `docs/decisions/ADR-0005-anonymous-membership-construction.md`
12. `docs/DATA_FORMAT_TEST_VECTOR_PLAN.md`
13. `docs/INDEPENDENT_VECTOR_VERIFIER.md`
14. `docs/FUZZING.md`
15. `test-vectors/COVERAGE.md`

## Reproduce the Phase 2 workspace gates

From the repository root with Rust 1.97:

```text
cargo fmt --all -- --check
cargo check --locked --offline --workspace --all-targets
cargo check --locked --offline --release --workspace --lib --bins
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace
python -B tools/independent_vector_verifier.py --root . --check-report test-vectors/valid/independent-verification-v1.json
```

The root workspace currently registers 220 Rust tests.

Parser fuzzing uses the separate `fuzz/` workspace and requires a supported
Unix-like host, nightly Rust, cargo-fuzz, LLVM sanitizer support, and a C++
compiler. See `docs/FUZZING.md`.

## Platform status

- Windows: validated.
- Linux x86_64: validated, including bounded cargo-fuzz execution.
- macOS: intended but not yet natively validated.

A future CI matrix must exercise Windows, Linux, and macOS before release
claims are made.

## Safety boundary

Nothing in this repository is approved Tari governance policy.

Do not use it for a binding Core Contributor, Council, treasury, charter, or
other consequential election. Do not place real voter secrets in test
fixtures, logs, archives, issues, or commits.
