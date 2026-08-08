# Phase 5 Slice 5A10B: real Triptych ballot preparation

Starting branch and HEAD: `phase5/gui-core-foundation` at
`be57d1c987887f1aa26398c43e0287619059561b`.

## Implemented local path

`GuiVoterSessionV1::prepare_ballot` uses ownership model A. The Tauri command
holds the Rust voter-session mutex for the whole operation; the session borrows
the `TariTriptychSecretKeyV1` from `GuiVoterCredentialSessionV1` and neither
moves nor clones it. The secret remains a zeroizing Rust value, is never
serialized, converted to text, logged, or retained in prepared state.

The exact prover call chain is:

1. reconstruct the verifier-owned statement with
   `reconstruct_approval_proof_statement` from the manifest and Rust-owned
   `ApprovalBallotPayload`;
2. build the frozen-registry verifier with
   `build_tari_triptych_verifier_from_registry_v1`;
3. call `prove_tari_triptych_prototype_v1(statement, verifier, secret)`;
4. construct `BallotPackageV1`, encode canonical CBOR, strictly decode it, and
   call `verify_approval_proof` through the independent verifier path;
5. install `Ready` only after that verification succeeds.

The prover derives the signer verification key from the secret, finds its
canonical sorted registry position internally using exact key equality, and
keeps that index Rust-only. It obtains fresh proof randomness through the
existing `OsRng` path. The proof envelope carries the authenticated Triptych
linking tag; successful verification exposes it as the election-scoped
nullifier. Same secret and election therefore produce the same authenticated
linkability value for duplicate detection; the manifest-derived election scope
changes for a different election, yielding a different linking tag.

The reconstructed statement binds protocol version, suite, manifest hash,
manifest-derived election scope, registry commitment, canonical payload hash,
ballot kind, and ballot confidentiality. Candidate-set commitment and
`governance_source_revision` are committed by the manifest hash; no proposal,
question, or V2 semantic field was added.

The existing `BallotPackageV1` canonical schema is unchanged: version,
manifest hash, suite ID, canonical approval-payload bytes, and proof bytes.
It contains no secret, witness, randomness, wallet material, member index, or
nullifier. The package digest shown to the UI is the existing domain-separated
`HashDomain::BallotPackageV1` BLAKE3-256 digest of its exact canonical bytes.

## Prepared state and export

`Ready` holds only canonical bytes and a safe summary: election/manifest IDs,
canonical selected IDs and labels, abstention, suite, public linking value,
byte count, digest, and local-verification result. Raw proof bytes remain
Rust-side. Selection changes, credential reset/replacement, workflow reset,
and election replacement remove the ready package. When lifecycle leaves
`OPEN`, the package remains inspectable but is no longer exportable; new proof
construction is also rejected.

The frontend shows indeterminate “Generating privacy proof…” state and blocks
duplicate generation. It uses a native save dialog only to select a path. Rust
uses create-new semantics (never overwrite), writes and syncs the canonical
bytes, reads them back, strictly decodes them, re-verifies them through the
existing verifier, and compares the read-back bytes before reporting success.
There is no network, walletd, indexer, relay, upload, or vote submission.

## Validation and remaining work

`cargo +stable-x86_64-pc-windows-msvc check --locked --offline -p
tari-cc-private-ballot-gui-core` passed (only the pre-existing vendored
Triptych dead-code warning). `npm run build` passed. The new focused real-proof
test was started twice but each invocation timed out while compiling the
gui-core test binary; it produced no test result. Full workspace tests,
clippy, Tauri build, vector regression, organizer-intake integration, mutation
matrix, performance timing, and large-ring testing were not run in this
cost-controlled pass. Canonical vectors and vendored Triptych were not changed.

Manual smoke checklist (not claimed complete): load an OPEN election; load an
eligible controlled credential; select valid options; generate; confirm the
summary and no secret display; export; confirm read-back verification; intake
through organizer test harness; verify duplicate/mutation/election-change
rejection; reset credential/selection; close lifecycle; check light/dark and
keyboard navigation.

Recommendation: **CONDITIONAL READY FOR OPUS REVIEW** after the targeted test
binary, organizer-intake/mutation tests, large-ring measurements, and the
requested full offline validation matrix complete.

## Validation completion

The initial conditional verdict was solely a test-binary compilation timeout,
not a prover failure. With compilation allowed to complete, the original
focused real-proof test passed: compilation took 307 seconds and test runtime
was 0.51 seconds. The new generated-credential bridge/export test compiled in
156 seconds and ran in 0.72 seconds. It generates a real Rust credential,
derives and enrolls its governance key into a `RegistrySnapshot`, proves with
that same credential, verifies the canonical package, exports/read-backs it,
accepts it through `GuiElectionSessionV1` exactly once, rejects the replay as
`DUPLICATE_NULLIFIER`, and rejects an independently changed final proof byte.

The exact suite is `TARI_TRIPTYCH_PROTOTYPE_V1`; no `TEST_ONLY_SUITE_ID` or
mock proof is used in either GUI path. `real_triptych_ballot` passed all 10
real-proof cases, including changed selection/payload, changed manifest,
changed registry, foreign election, canonical round-trip, trailing bytes,
same-election duplicate nullifier, and cross-election differing nullifier.
The gui-core intake suite passed 8 tests and its security suite passed 7.
The complete voter-session suite passed 20 tests, covering selection/reset/
lifecycle invalidation and stale operation tokens.

Performance harness results (real Triptych proof path; proof total over all
members, replay is verifier/intake total): 16 members: 11,416 ms prove, 1,652
ms replay, 11,050-byte proof and 12,427-byte package; 32: 37,750 ms, 6,917 ms,
24,618 / 27,291 bytes; 64: 137,567 ms, 17,499 ms, 54,730 / 59,995 bytes.
The 7-member and 11-member governance regressions also passed (3,590/578 ms
and 7,621/1,193 ms respectively). The ignored 249–257 and 128–256 complete
election regressions were not run: their all-member workload is not reasonable
for this interactive pass given the measured 64-member total; no parameters or
fixtures were weakened.

Offline workspace check and `clippy -- -D warnings` passed (apart from the
pre-existing vendored Triptych dead-code warning). Full workspace tests ran to
one unrelated known Windows failure: governance test
`t24_hostile_filename_cannot_control_archive_path` cannot create its hostile
filename (`Access is denied`, OS error 5). No 5A10B test failed. No source
repair was required beyond adding the bridge/export validation test. Canonical
formats and vendored Triptych remain unchanged; no network, walletd, indexer,
or relay was contacted.

Final recommendation: **READY FOR OPUS REVIEW**, subject to the documented
Windows hostile-filename fixture and deferred impractical complete large-ring
regressions.
