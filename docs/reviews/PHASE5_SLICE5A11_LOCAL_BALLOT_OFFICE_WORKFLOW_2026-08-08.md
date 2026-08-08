# Phase 5 Slice 5A11: local ballot office workflow

Starting branch and HEAD: `phase5/gui-core-foundation` at
`efd5957a280a12f3d5ed1e3f501d30d4e2686f79`.

## Local voter to office flow

The desktop workflow keeps the same transport-independent artifact all the way
through the local pilot: voter selection, real `TARI_TRIPTYCH_PROTOTYPE_V1`
proof, self-verification, canonical `BallotPackageV1`, local `.cbor` export,
native organizer import, strict decode, existing proof verification, lifecycle
validation, nullifier duplicate detection, and accepted/rejected result.

The explicit shared boundary is
`GuiElectionSessionV1::intake_ballot_package_bytes(&[u8])`. The older
`intake_ballot` name remains as a compatibility alias. The source of bytes is
outside validity: local file today, future privacy transport or test harness
later.

## Organizer UI

Manage Election now has a Ballot office section with a native
`Import ballot package` picker. The frontend never decodes CBOR. Rust reads
exact bytes and delegates to gui-core. Operator messages are bounded:
`Ballot accepted.`, `Duplicate ballot for this election.`, wrong-election,
not-open, malformed/invalid proof, invalid selection, unsupported suite, and
canonical-byte failures.

The UI does not display voter identity, registry/member index, raw proof bytes,
raw nullifier, duplicate-of sequence, or global accepted count. The selected
path is transient session UX only.

## Lifecycle, Duplicate, And Mutation Behavior

Backend authority remains OPEN-only. Targeted tests cover FROZEN, OPEN, CLOSED,
VERIFIED, and FINALIZED, with non-OPEN intake rejected before transcript
recording.

Targeted gui-core tests prove valid import, exact replay rejection,
fresh same-voter/same-election regenerated proof rejection by the same
election-scoped nullifier, second eligible voter acceptance, wrong-election
rejection, trailing-byte rejection, malformed-proof rejection, and accepted
state preservation after rejected ballots.

The package-level governance-revision test preserves a valid package generated
under revision A, loads otherwise matching artifacts under revision B, opens the
office, and rejects the preserved package as `WRONG_MANIFEST_HASH`. This closes
the 5A10B F4 gap through the binding chain:
proof -> manifest hash -> governance_source_revision.

## Privacy Boundary

No transport metadata was added to `BallotPackageV1`, accepted ballot records,
tally, transcript, public archive, or cryptographic commitment. Future 5A12 can
replace only `read exact bytes from a local file` with `receive exact bytes from
a privacy transport` and still call
`GuiElectionSessionV1::intake_ballot_package_bytes`.

Sealed results remain sealed while voting is open. The organizer may see the
result of the package just imported, but the UI no longer displays intake
sequence numbers and the existing participation summary keeps numeric fields
sealed under the 5A5 policy.

## F2 And F3

F2 lock result: Tauri `prepare_voter_ballot` now clones only public immutable
election artifacts and lifecycle state while holding the organizer session
mutex, releases that mutex, then locks the voter session for real proof
generation. The credential secret is still only borrowed by
`GuiVoterSessionV1::prepare_ballot`; it is not cloned, moved, serialized, or
returned.

F3 collision UX result: Rust still uses `create_new(true)`. The bounded backend
message now says: `For safety, ballot exports never overwrite an existing file.
Choose a new filename.`

## Release Performance

No prover redesign was made. Existing 5A10B local performance characterization
is carried forward: 16-member proof 11,416 ms / replay 1,652 ms /
12,427-byte package; 32-member proof 37,750 ms / replay 6,917 ms /
27,291-byte package; 64-member proof 137,567 ms / replay 17,499 ms /
59,995-byte package. The largest measured ring remains 64 members. The
requested 250-member representative release measurement remains a pre-pilot
follow-up and was not rerun in this cost-controlled pass.

## Validation

Completed:

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-gui-core --test intake`
  passed: 13 tests.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline -p tari-cc-private-ballot-gui-core`
  passed.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --manifest-path gui/src-tauri/Cargo.toml`
  passed.
- `npm test` passed: 77 frontend tests.
- `npm run build` passed.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets`
  passed.
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings`
  passed.
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --manifest-path gui/src-tauri/Cargo.toml --all-targets --no-deps -- -D warnings`
  passed.

`cargo fmt --all --check` still reports pre-existing workspace/vendored
formatting and newline-style issues outside this slice. The Rust files touched
by this slice were formatted directly.

`cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace`
ran until the known Windows-hostile filename fixture:
`crates/gui-core/tests/governance.rs::t24_hostile_filename_cannot_control_archive_path`
failed while creating the hostile local filename with `Access is denied. (os
error 5)`. This is the same current-state Windows fixture noted in the request;
no unrelated archive behavior was changed to make it pass.

`npx tauri build` reran the frontend production build successfully, then failed
in Rust release compilation before bundling because `dlltool.exe` was not
available for the `getrandom` build script. No WiX/MSI/NSIS stage was reached.

No walletd, indexer, Ootle submission, HTTP, Tor, relay, upload, or Internet
vote submission was added or contacted.

## Manual Smoke Checklist

Not claimed as human-completed: launch app; organizer loads OPEN election;
separate voter flow loads same election; eligible credential; voter selects
choice; generate real proof; local verification passes; export ballot;
organizer imports exact exported file; ballot accepted; import exact file
again; duplicate rejected; second eligible voter package accepted; close
election; results become available only when permitted; deterministic tally
matches accepted ballots; invalid and wrong-election packages reject; no voter
identity shown; no network traffic required; light/dark; keyboard navigation.

## Recommendation

Conditional ready pending the known Windows hostile-filename fixture,
environment repair for `dlltool.exe` before Tauri release packaging, and
independent Opus review of the local byte-intake boundary and sealed-result UI.
