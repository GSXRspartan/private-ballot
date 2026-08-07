# Phase 5 Slice 5A2 — GUI-Core Application Facade (2026-08-07)

## 1. Starting point

- **Starting branch:** `phase4/ootle-testnet-anchor-prototype`
- **Starting HEAD:** `05d923da1e552b7fdf2abf1129bf53334620d6f1`
- **Starting tag:** `phase4-release-build-2026-08-06` (points at starting HEAD)
- **Working tree at start:** clean
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via `stable-x86_64-pc-windows-msvc`
- **New Phase 5 branch:** `phase5/gui-core-foundation`, created at exactly the
  starting commit. The Phase 4 branch and tags are untouched.
- **No commit was created.** All changes are staged only.

## 2. Purpose

Slice 5A2 creates the application-facing Rust facade the future GUI will
call: `crates/gui-core` (`tari-cc-private-ballot-gui-core`). It is not the
GUI. It composes existing public backend APIs into typed, application-facing
operations and contains no Tauri types, no HTTP server, no async runtime, and
no knowledge that React/TypeScript exists.

## 3. Files changed

- `Cargo.toml` — one line: workspace member `crates/gui-core`.
- `Cargo.lock` — exactly one new `[[package]]` entry for
  `tari-cc-private-ballot-gui-core` (path dependencies only).
- `crates/gui-core/Cargo.toml` — new.
- `crates/gui-core/src/lib.rs` — crate documentation and re-exports.
- `crates/gui-core/src/error.rs` — `GuiCoreError` / `GuiErrorCategory`.
- `crates/gui-core/src/hex.rs` — bounded lowercase-hex rendering.
- `crates/gui-core/src/artifacts.rs` — `GuiElectionArtifactsV1` loader.
- `crates/gui-core/src/summary.rs` — election/candidate view models.
- `crates/gui-core/src/intake.rs` — intake result view model.
- `crates/gui-core/src/session.rs` — `GuiElectionSessionV1` facade.
- `crates/gui-core/src/tally.rs` — tally summary rendering.
- `crates/gui-core/src/archive_writer.rs` — archive-directory writer.
- `crates/gui-core/src/archive_verify.rs` — full offline replay verifier.
- `crates/gui-core/src/inspect.rs` — anchor config/snapshot/evidence
  inspectors.
- `crates/gui-core/tests/common/mod.rs` — shared deterministic fixtures.
- `crates/gui-core/tests/artifacts.rs` — loader tests.
- `crates/gui-core/tests/intake.rs` — intake tests.
- `crates/gui-core/tests/tally.rs` — tally tests.
- `crates/gui-core/tests/archive_writer.rs` — writer tests.
- `crates/gui-core/tests/archive_verify.rs` — replay verifier tests.
- `crates/gui-core/tests/inspect.rs` — inspector tests.
- `crates/gui-core/tests/security.rs` — security/error-model tests.
- `docs/decisions/ADR-0007-phase5-gui-stack-and-rust-boundary.md` — new.
- `docs/reviews/PHASE5_SLICE5A2_GUI_CORE_FOUNDATION_2026-08-07.md` — this
  report.
- `PHASE_STATUS.md` — narrow factual header/current-state update.

No existing crate source file was modified. No vendored Triptych change. No
Phase 1-4 behavior change.

## 4. Crate dependency graph

Direction (unchanged, extended by one leaf):

```
protocol / registry / ballot / crypto / verifier / tally / archive
anchor / anchor-transport / ootle-anchor-* / ootle-anchor-app
                          ↓
                       gui-core
                          ↓
                 future Tauri shell
```

gui-core direct dependencies (all workspace path crates): protocol,
registry, ballot, crypto, verifier, tally, archive, anchor, anchor-transport,
ootle-anchor-adapter, ootle-walletd-anchor-adapter,
ootle-receipt-anchor-adapter, ootle-anchor-lifecycle-orchestrator,
ootle-anchor-app.

Dev-only dependencies: `curve25519-dalek v4.1.3` (already in the lockfile
via `crypto`; used to derive fixture public keys from fixed scalars, exactly
as the existing crypto/CLI tests do) and
`ootle-anchor-network-adapters` (config fixture construction).

**Zero new external runtime dependencies.** No serde, Tauri, tokio, HTTP,
database, keyring, or GUI framework.

## 5. Facade APIs

### 5.1 Election artifact loading (`artifacts.rs`)

`GuiElectionArtifactsV1::from_bytes(manifest, registry, candidates)` and
`from_paths(manifest_path, registry_path, candidate_path)`:

1. canonical-decode each artifact via the existing decoders;
2. reject files larger than `MAX_CANONICAL_OBJECT_BYTES` before reading;
3. recompute the registry commitment and require it to equal the manifest's;
4. recompute the candidate-set commitment and require equality;
5. recompute the manifest hash with `Blake3HashProviderV1`;
6. enforce `ProductionProofSuitePolicyV1` (test-only suite rejected);
7. return the validated triple only when every check passes.

Filenames are never trusted; election identity is never inferred from
directory names.

### 5.2 Election session (`session.rs`)

`GuiElectionSessionV1::new(artifacts)` builds the registry-bound Triptych
verifier (validating every governance key as a canonical Ristretto point) and
freezes the lifecycle. `open`, `close`, `mark_verified`, and `finalize`
delegate verbatim to `ElectionLifecycleV1`. The session owns the
`BallotAcceptanceLedger`, the `VerificationTranscriptV1`, and the canonical
bytes of every ingested package (public data needed for archive
construction). The session itself is not persisted; no new canonical format
was created.

### 5.3 Ballot intake (`intake.rs`)

`intake_ballot(package_bytes)`:

- refuses intake while the election is not open (`ELECTION_NOT_OPEN`, nothing
  recorded), matching the lifecycle's own acceptance rule;
- records the submission digest in the transcript with
  `received_before_close = true`;
- delegates decode/binding/suite-policy/payload/proof/ledger acceptance to
  `ingest_approval_ballot_package_v1` verbatim;
- records the deterministic decision (Accepted or the existing rejection
  code) in the transcript;
- returns `GuiBallotIntakeResultV1` with accepted flag, stable code, coarse
  category, package digest, sequence, and — only after successful proof
  verification — the nullifier; for duplicates, the nullifier (already public
  through the first accepted ballot) and the first accepted ballot's sequence
  are resolved via a read-only re-verification.

A rejected ballot never mutates the acceptance ledger; the transcript records
the rejection exactly as the existing replay composition does.

### 5.4 Tally (`tally.rs`)

`session.tally()` calls `ApprovalTally::from_ballots` over ledger-accepted
payloads and renders `GuiTallySummaryV1` (per-candidate counts with display
names, accepted/abstention counts, leading result). `NoApprovals`,
`SingleLeader`, and `Tie` mirror `LeadingResult` exactly; no winner is
invented for a tie. Tests prove facade output equals the direct backend
tally rendered by the same summarizer, and that an independent replay's
tally is identical.

### 5.5 Archive writer (`archive_writer.rs`)

`write_archive_directory_v1(session, target_dir)` promotes the tested archive
assembly pattern:

- layout: `election-manifest.cbor`, `candidate-set.cbor`,
  `voter-registry.cbor`, `submissions/NNNNNNNN.cbor` (intake order), and
  `archive-manifest.cbor` (never a catalog member);
- the verification transcript is derived during replay and is never
  serialized, preserving the existing protocol design;
- the target directory is created when absent; an existing target must be an
  empty directory (non-directory or non-empty targets are rejected);
- every file is written atomically (temporary file, flush, sync, rename);
  no file is ever silently overwritten;
- catalog entries and digests use `ArchiveFileEntryV1::for_bytes` /
  `ArchiveFileCatalogV1` / `ArchiveManifestV1::for_provider` with the
  production BLAKE3 provider; the final `ArchiveHashV1` is returned with a
  per-file summary.

### 5.6 Full offline archive verifier (`archive_verify.rs`)

`verify_archive_directory_v1(dir)` promotes the strongest CLI replay-gate
composition, running five stages in order:

1. `ARCHIVE_MANIFEST` — presence, canonical decode, hash-provider match;
2. `CATALOG_FILES` — strict catalog membership (missing **and** unexpected
   files rejected; detached-signature prefix excluded) and per-file digest
   verification;
3. `ELECTION_ARTIFACTS` — required artifact presence plus the full loader
   cross-binding and production suite policy;
4. `BALLOT_REPLAY` — deterministic replay of every archived package through
   `ingest_approval_ballot_package_v1` against an opened lifecycle,
   reproducing acceptance, duplicate-nullifier, and rejection decisions, and
   validating transcript completeness; the tally is recomputed;
5. `ARCHIVE_HASH` — the catalog and archive manifest are rebuilt from the
   on-disk bytes and must equal the archived manifest and its hash.

`verified` is true only when every stage passes. Integrity failures are
reported in the structured result with stage and stable code; only
filesystem-level impossibilities return `Err`. Organizer state is never
consulted; the offline archive remains authoritative.

### 5.7 Structured anchor inspectors (`inspect.rs`)

- `inspect_anchor_config_v1(path)` — decodes via the existing config loader
  (envelope + digest validation) and derives the anchor-record digest from
  the configured locator triple exactly as the driver's dry-run path does.
  The config never carries walletd auth.
- `inspect_anchor_snapshot_v1(path)` — size/regular-file guard,
  `read_snapshot`, `snapshot_digest`, then semantic reconstruction through
  `AnchorLifecycleOrchestrator::from_snapshot`, exactly matching the CLI
  `--inspect-snapshot` stages; returns phase, polling counters, transaction
  id, and per-record walletd/receipt summaries.
- `inspect_anchor_evidence_v1(path)` — size guard plus the digest-verifying
  `AnchorEvidenceRecordV1::from_canonical_bytes`; returns final status,
  receipt source, phase, network, all digests, transaction id, ledger
  position, snapshot digest, and the fixed non-binding human-review summary.

None of the inspectors prints, writes, or contacts any network, and none
parses CLI text.

## 6. Error model

`GuiCoreError` carries a stable machine code, a `GuiErrorCategory`, an
optional static context label, and a bounded static message. Existing
identifiers are preserved: protocol `ValidationCode` strings,
`ConfigFileError`, `SnapshotFileError`, `EvidenceError`, and
`LifecycleReconstructionError` codes flow through verbatim. New codes are
introduced only where no existing code exists
(`GUI_REGISTRY_COMMITMENT_MISMATCH`, `GUI_FILE_NOT_FOUND`, `GUI_IO_ERROR`,
`GUI_ARCHIVE_TARGET_NOT_EMPTY`, `GUI_ARCHIVE_TARGET_INVALID`,
`GUI_ARCHIVE_MISSING_FILE`, `GUI_ARCHIVE_UNEXPECTED_FILE`,
`GUI_ARCHIVE_MISSING_ARTIFACT`). No error contains a path, a secret, or raw
third-party text.

## 7. Security boundary

No gui-core view model contains a secret-bearing field: no
`TariTriptychSecretKeyV1`, no private scalar bytes, no walletd auth token, no
wallet password, no wallet seed, no mnemonic, no signing or raw signer
secret. Enforced by a source-policy test scanning `src/` for the
code-level identifiers of secret-bearing APIs, plus a manifest test
forbidding GUI/network/database dependency names. Allowed non-secret values
match the architecture review: governance public keys, commitments, package
digests, post-verification nullifiers, archive/anchor/snapshot/evidence
digests, transaction fingerprint/id, request ids, fee account label, fee
component, max fee, network.

## 8. Deferred voter key generation — design note

The architecture review found no production voter governance-key generation
API; `crypto/src/triptych_prover.rs` states it "does not provide key
generation, persistence, import UX". Per ADR-0005, key generation is part of
the cryptographic construction surface and must not be smuggled into a GUI
facade. gui-core therefore does not generate voter keys.

A later reviewed slice (before 5A6) should add, in the **crypto** crate:

- `TariTriptychSecretKeyV1::generate()` (name TBD): sample a canonical
  nonzero Ristretto scalar using `rand_core::OsRng` (already a crypto
  dependency), with rejection or wide-reduce sampling decided by the
  cryptographic reviewer; return the existing zeroizing wrapper;
- `TariTriptychSecretKeyV1::public_key()` (name TBD): derive
  `RistrettoPublicKeyV1` via basepoint multiplication with the existing
  canonical compressed encoding;
- zeroization: already implemented (`Drop` zeroizes; `Debug` redacts);
  the generator adds no persistence and no export besides the caller's
  explicit choice;
- no-wallet-seed guard: the registration/display path must surface the
  existing `GOVERNANCE_KEY_WARNING` verbatim; the API accepts and returns no
  wallet-derived material;
- test strategy: generated keys are canonical nonzero scalars; public key
  matches scalar multiplication; registry round-trip; proof/verify with a
  generated key; deterministic test vectors unchanged (fixtures keep fixed
  scalars); side-channel and acceptance-gate review per ADR-0005 §"Construction
  acceptance gates" before any binding use.

The GUI MVP imports an existing voter credential per session and never
persists it.

## 9. Anchor progress API — deferred

`AnchorAppDriver::run` remains monolithic/blocking and unchanged. Future
options, without changing lifecycle semantics:

A. run the driver on a dedicated worker thread and watch the durable
   snapshot file (rewritten after every step) for progress;
B. later add a step-wise or event-callback driving API as an additive
   change to `ootle-anchor-app`.

5A2 ships only the structured read-only inspectors.

## 10. Tests

56 gui-core integration tests, all deterministic and offline, using real
Triptych proofs from fixed scalar fixtures (the same approach as the
existing CLI integration tests):

- **artifacts.rs (11):** valid load from bytes/paths, missing file, wrong
  registry commitment, wrong candidate commitment, wrong artifact slot,
  malformed CBOR, non-canonical CBOR, unsupported version, test-only suite
  rejection, summary fields.
- **intake.rs (8):** real Triptych acceptance, duplicate nullifier with
  first-valid reference, wrong manifest, unknown candidate, malformed proof,
  no accepted-state mutation on rejection, deterministic
  sequence/transcript, intake refusal while not open.
- **tally.rs (4):** no approvals, single leader, tie, facade-equals-backend.
- **archive_writer.rs (5):** deterministic layout/order/hashes, identical
  bytes → identical archive hash, non-empty target rejected without
  overwrite, file target rejected, zero-ballot archive writes and verifies.
- **archive_verify.rs (12):** valid archive verifies; tampered ballot,
  manifest, registry, candidate set, and catalog digest detected; missing
  file; unexpected extra file; duplicate/tally/hash reproduction; two
  independent runs identical; missing directory; missing archive manifest.
- **inspect.rs (9):** valid config, tampered config, Prepared snapshot,
  FinalizedAccept snapshot, semantically impossible snapshot rejected, valid
  evidence, tampered evidence, missing targets, fee-only evidence with
  transaction id.
- **security.rs (7):** no secret-bearing API identifiers in sources, no
  network/async usage in sources, bounded ASCII error strings, no credential
  or path leakage in errors, paths with spaces, oversized input rejection,
  forbidden-dependency manifest policy.

Required-case mapping: cases 1-8 → artifacts; 9-15 → intake; 16-19 → tally;
20-26 → archive_writer; 27-38 → archive_verify; 39-45 → inspect + security
source policy; 46-50 → security. Note on case 22/23 phrasing: Triptych
proofs intentionally use fresh OS randomness, so "same inputs" means the
same canonical package bytes; the test asserts byte-identical archives from
two sessions that ingested identical bytes.

## 11. Validation

All with `cargo +stable-x86_64-pc-windows-msvc`, `--locked --offline`:

- `fmt -p tari-cc-private-ballot-gui-core -- --check` — pass.
- `test -p tari-cc-private-ballot-gui-core` — 56 passed, 0 failed.
- Regression packages protocol, registry, ballot, crypto, verifier, tally,
  archive, anchor, anchor-transport, ootle-anchor-app — all pass.
- `check --workspace --all-targets` — pass.
- `test --workspace` — 106 suites ok, 954 passed, 0 failed, 7 ignored
  (pre-existing ignored/manual long Triptych suites remain skipped).
- `clippy --workspace --all-targets --no-deps -- -D warnings` — pass.

No network, walletd, indexer, signing, or transaction activity occurred.
The only external output note: the pre-existing `triptych` dead-code warning
in `third_party` is unchanged and untouched.

## 12. Canonical-format compatibility

No canonical format was created, modified, or re-encoded. gui-core reads and
writes only the existing canonical objects through their existing encoders.
Archives written by the facade verify byte-identically through the promoted
replay verifier, and two writes of identical package bytes produce identical
archive hashes.

## 13. Hashes

Staged file count, per-file byte counts and SHA-256, full staged patch byte
count and SHA-256: see the staging transcript in the 5A2 final task output
(computed at staging time after this document was written).

## 14. Go / no-go for 5A3

**READY FOR 5A3** (Tauri shell, navigation, design system), with the noted
deferrals: voter key generation requires its own reviewed slice before 5A6,
and anchor progress reporting uses the snapshot-watch approach unless a
step-wise driver API is added later.
