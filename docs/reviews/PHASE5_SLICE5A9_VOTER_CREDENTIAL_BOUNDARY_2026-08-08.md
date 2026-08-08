# Phase 5 Slice 5A9 - Voter Governance Credential Boundary

- **Date:** 2026-08-08
- **Branch:** `phase5/gui-core-foundation`
- **Starting HEAD:** `b05545bd3fd194b5377a61f93abd8ae5c3b7c8ac`
- **Mode:** Implement, validate, document, and stage. **No commit.**

## 1. Discovered Credential Model

The exact secret proving registry membership is the existing
`TariTriptychSecretKeyV1`: a canonical, nonzero Ristretto scalar used by the
Triptych prototype witness. The corresponding governance public key is
`Ristretto basepoint * scalar`, compressed to the 32-byte canonical Ristretto
encoding stored in `RegistrySnapshot` entries.

No wallet key is involved. No Tari/Ootle wallet seed, account key, mnemonic, or
spending key is imported or derived. The existing `VoterGovernanceKeyRegistrationV1`
is public-only enrollment metadata.

## 2. Private Credential Format Finding

No reviewed private credential serialization/persistence format exists in the
repository. `TariTriptychSecretKeyV1::from_canonical_bytes` validates a raw
scalar encoding for protocol/test use, but it is not a versioned, domain-marked,
wallet-distinguishable, user-facing credential file format. Therefore this
slice implements session-only generation and explicitly does **not** expose
import or export commands.

## 3. Generation And RNG

Generation is Rust-side only via `TariTriptychSecretKeyV1::generate_os_rng()`.
The call chain is:

`gui/src-tauri` command -> `GuiVoterCredentialSessionV1::generate_for` ->
`VoterGovernanceCredentialV1::generate` ->
`TariTriptychSecretKeyV1::generate_os_rng` ->
`curve25519_dalek_v4::Scalar::random(&mut rand_core::OsRng)`.

`OsRng` is the existing `rand_core` OS-backed randomness primitive already used
by the Triptych prover for proof randomness.

## 4. Secret Ownership And Zeroization

`VoterGovernanceCredentialV1` owns exactly one `TariTriptychSecretKeyV1`.
It does not implement `Serialize`, `Display`, `Clone`, or `Copy`; `Debug` is
redacted. The underlying `TariTriptychSecretKeyV1` zeroizes its canonical
32-byte scalar array on drop. Temporary `Scalar` values are wrapped with
`Zeroizing` where the existing primitive reconstructs them.

Limit: this does not claim whole-process memory erasure for compiler/register
temporaries or copies inside third-party curve arithmetic.

## 5. Rust Session Design

The Tauri `AppState` now owns `Mutex<Option<GuiVoterCredentialSessionV1>>`.
Only one credential is loaded at a time; generating a new one replaces and
drops the previous session. `load_election`, `freeze_election`, and
`unload_election` clear the voter credential. `reset_voter_governance_credential`
explicitly clears it.

Poisoned locks map to bounded `GUI_STATE_UNAVAILABLE` and do not panic with
secret-bearing state.

## 6. TypeScript Boundary

The frontend receives only `GuiVoterCredentialStatusV1`: loaded flag, origin,
derived public key hex/abbreviation, eligibility, and fixed notices. No scalar,
credential bytes, mnemonic, seed, private key, proof, nullifier, ballot package,
or registry index is present. Eligibility is computed in Rust.

## 7. Eligibility And Privacy

Eligibility is an exact byte comparison between the derived 32-byte governance
public key and the frozen `RegistrySnapshot` public keys. The public DTO does
not include registry position/index. If later proving needs an index, it should
remain Rust-side.

## 8. Enrollment Workflow

The actual enrollment sequence remains:

1. Voter creates a dedicated governance credential.
2. Voter gives only the public governance key to the organizer.
3. Organizer includes the public key in the frozen registry.
4. Voter later loads/uses the same private credential.
5. Rust derives the public key and confirms membership.

Because there is no approved persistence format, session-only generation after
an election is already frozen will normally show **Not eligible** unless that
new public key was already enrolled.

## 9. UI Behavior

The Vote screen now advances from review confirmation into a real Governance
Credential stage. It shows the wallet-seed warning, session-only status,
generation action, explicit import/export deferral, public key abbreviation,
and Rust-returned eligibility. The next stage remains disabled unless
eligibility is `Eligible`; proof generation and ballot/export/confirmation are
deferred.

## 10. Prohibitions Preserved

No Triptych proof generation is called by the voter workflow. No nullifier,
ballot payload, ballot package, vote submission, walletd/indexer contact,
network request, telemetry, or signing outside credential generation occurs.

## 11. Validation

Passed:

- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline -p tari-cc-private-ballot-crypto -p tari-cc-private-ballot-gui-core --all-targets`
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --manifest-path gui\src-tauri\Cargo.toml --all-targets`
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-crypto --lib` - 50 passed
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-gui-core --lib` - 43 passed
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-gui-core --test security --test serialization` - 9 passed
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline -p tari-cc-private-ballot-crypto -p tari-cc-private-ballot-gui-core --all-targets --no-deps -- -D warnings`
- `npm test` - 71 passed
- `npm run build`

Notes:

- `cargo fmt --check --all` was not usable as a final signal because it reports
  pre-existing formatting/newline drift in third-party and older workspace
  files. Touched Rust files were formatted directly.
- `npx tauri build` compiled the release executable successfully at
  `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe`, then failed
  during MSI bundling when WiX `light.exe` returned failure. The captured output
  did not include a more specific WiX diagnostic. The executable build itself
  succeeded; installer bundling remains unproven for this run.
- Full workspace `cargo test` / full workspace `clippy` were not rerun to avoid
  repeated broad validation loops after focused checks passed.

## 12. Manual Smoke Checklist

Documented, not human-completed:

1. Launch app.
2. Load valid election.
3. Review cryptographically bound details.
4. Confirm review.
5. Open Governance Credential stage.
6. Verify wallet-seed warning.
7. Generate credential.
8. Verify only public governance key is shown.
9. Verify no secret is shown.
10. Confirm Not eligible for unrelated frozen registry.
11. Load an election containing the generated public key if a fixture supports it.
12. Confirm Eligible.
13. Unload election.
14. Confirm credential state cleared.
15. Load another election.
16. Confirm credential not silently carried over.
17. Clear credential.
18. Inspect frontend diagnostics for no secret fields.
19. Light/dark.
20. Keyboard navigation.

## 13. Staging

Staged hashes and patch hash are computed at final staging time. No commit is
created.

## 14. Go / No-Go For 5A10

**CONDITIONAL READY.** The secret boundary, generation, public-key derivation,
eligibility matching, and UI gate are in place. 5A10 may proceed only after the
reviewer accepts that import/export persistence remains deferred pending an
explicit credential-file design, and after the WiX bundling failure is either
reproduced with diagnostics or accepted as installer-only risk.
