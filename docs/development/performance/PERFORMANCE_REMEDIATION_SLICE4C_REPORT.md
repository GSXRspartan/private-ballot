# Performance Remediation — Slice 4C

## Verdict

**PASS.** The required validation was completed on 2026-08-30 using the supplied
Windows MSVC/vcpkg environment. The earlier `dlltool.exe` error was isolated to
the agent's incomplete toolchain environment; it does not occur with the
documented MSVC environment.

Slice 4B was inspected after the five-minute read-only handoff observation. Its report, matrix, implementation, and isolated tests were present; no relevant Cargo/Rust process ran and no Slice 4B artifact changed. Slice 4B is verified complete and idle.

## Private-intake reconciliation

Before this slice, every inbox package calculated its digest and searched transcript.decisions().iter().find(...). For K inbox files and N transcript decisions, this is O(K×N): at K=N=4,096, up to 16,777,216 digest comparisons per sync pass.

GuiElectionSessionV1 now has a non-durable HashMap<BallotPackageDigestV1, TranscriptDecisionIndexEntryV1>. An entry holds the **first** decision's sequence and outcome, preserving the legacy find semantics. It is populated after every transcript decision, including Slice 4B's ordered parallel application; rebuilt by durable reconstruction; transactionally cloned; and never encoded as authority.

Every index hit rereads the authoritative transcript row and compares its sequence, digest, and outcome. Any disagreement fails closed with GUI_PRIVATE_INTAKE_DIGEST_INDEX_INCONSISTENT.

Normal reconciliations are now O(K) expected time: K map probes and K constant-time transcript-row checks. At 4,096 files, that is 4,096 probes and zero linear scans. New/unseen files retain the full validation/intake path.

Instrumentation added:

- private_intake_digest_index_hits
- private_intake_digest_index_misses
- private_intake_linear_transcript_scans
- private_inbox_files_read
- private_inbox_files_hashed
- private_inbox_files_skipped_unchanged

## Private inbox re-read / re-hash behavior

The audit confirmed every previous sync opened, read, and BLAKE3-hashed each content-addressed .package file. Filenames are canonical lowercase hex digests computed with HashDomain::BallotPackageV1; full validation still compares filename commitment with a freshly calculated content digest.

The new process-local cache skips only a file fully read and digest-validated during the same process, with a matching authoritative transcript digest and unchanged regular-file byte length and modification time. Metadata is an invalidation signal, not an integrity substitute. Missing timestamp, changed metadata, reparse point, oversize file, read-time identity change, restart, new file, or cache/index inconsistency takes the full read/hash path. The cache is not durable.

The full path takes metadata before and after the read and rejects a change-during-read with GUI_PRIVATE_INTAKE_INBOX_FILE_CHANGED_DURING_READ. A normal same-name mutation invalidates the cache, is rehashed, and fails closed on a filename/content-digest mismatch. Counters do not log package, nullifier, voter, or receipt data.

## Tauri event-thread work

Material filesystem, durable-state, hashing, archive, and proof-verification commands now use async fn plus run_blocking_command. This includes package intake, inbox sync, durable draft writes/freeze/export, archive writes, anchor inspections/configuration, governance document hashing, credential-directory operations, irreversible ballot export, and private voter-bundle export.

The static regression checks high-risk commands specifically, including intake_ballot_package and sync_private_intake. Commands intentionally synchronous are bounded in-memory lifecycle/view/selection operations only: shell info, unload, summaries, authority, IDs, tally, participation, draft creation/preview, status, selection, and reset. The complete classification is in AUDIT_TAURI_BLOCKING_MATRIX.POST_SLICE4C.csv.

export_prepared_voter_ballot retains its session/voter locks across the atomic cast-lock and no-overwrite write boundary. It now runs off the event thread; releasing the locks earlier would weaken that irreversible transaction's atomicity.

## Tests and checks

New isolated gui-core regression binary:

cargo test -p tari-cc-private-ballot-gui-core --test slice4c_private_intake -- --nocapture

It covers index/legacy equivalence, short circuiting, canonical ordering, new decisions, transactional cloning, durable rebuild, same-name mutation fail-closed behavior, unchanged-file skip behavior, and a 4,096 decision/package operation-count fixture. Exact global counters are serialized within this test binary.

rustfmt --check (with skip_children=true for the dirty Tauri tree) and git diff --check passed.

Completed validation used `--features test-support` and passed:

- `slice4c_private_intake` (7 tests), including the 4,096 lookup fixture,
  no-linear-scan assertion, unchanged-file skip, and same-name mutation refusal.
- `workspace` (38), `verified_session_cache` (6),
  `reconstruction_instrumentation` (5), `durable_append_fast_path` (14),
  `parallel_historical_replay` (7), `slice4b_instrumentation` (1), `intake`
  (13), `private_intake_inbox` (16), `security` (7), `participation` (18),
  `election_status` (11), `serialization` (3), `tally` (10), and
  `voter_cast_lock` (22).
- gui-core unit tests (116).
- `cargo check -p tari-cc-private-ballot-gui-core` and
  `cargo check --manifest-path gui/src-tauri/Cargo.toml`.

The checks and tests emitted only existing warnings: the vendored Triptych
`OperationTiming::Variable` dead-code warning, two Tauri dead-code warnings,
and two existing gui-core unit-test `unused_must_use` warnings. No test or
check failure occurred.

## Security and behavior preserved

- New-ballot Triptych verification remains on every full intake path.
- Nullifier and first-valid behavior remain in the serial authoritative ledger application.
- Transcript/durable ordering is unchanged.
- Index and inbox cache are transient accelerators, not durable authority.
- Inbox path confinement, reparse rejection, size limits, digest validation, and rollback remain.
- Workspace listing stays on the verified-session-cache path with zero historical replay.
- Slice 3B append and Slice 4B replay behavior are unchanged except for recording the derived index alongside their existing canonical decisions.
- No physical-device-I/O claim is made.

## Remaining UI-thread risks

No known material filesystem, hashing, archive, or Triptych-verification command remains synchronously on the Tauri event thread. Normal session/voter lock contention remains by design; only the irreversible cast path retains locks while executing its atomic file operation.

## Next slice

Slice 4D: same-run archive-verification memoization.
