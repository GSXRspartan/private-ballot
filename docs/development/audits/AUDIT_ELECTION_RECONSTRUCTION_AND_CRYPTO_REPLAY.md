# Audit — Durable election reconstruction, cryptographic replay, and UI latency

**Repository:** `tari-ballot-organizer-anchor-deployment-gui` (worktree of `tari-cc-private-ballot`)
**Branch:** `feature/organizer-anchor-deployment-gui` @ `b6da1b3`
**Date:** 2026-08-29
**Scope:** investigation and architecture only. **No production source was modified.** No verification was removed, weakened, or bypassed. No durable format, protocol behaviour, tally semantics, nullifier handling, or security boundary was changed.

**Evidence classes used throughout:**

- **CONFIRMED** — read directly from repository source, or measured on this machine.
- **MEASURED** — produced by a scratchpad-only benchmark that links the vendored `third_party/tari-triptych` crate through its public API and mirrors the repository's own statement construction. The benchmark lives outside the repository (`%TEMP%/claude/.../scratchpad/tripbench`) and changed nothing in-tree.
- **STRONGLY INFERRED** — follows necessarily from confirmed code plus a documented arithmetic model.
- **ESTIMATE** — depends on a size assumption that is stated explicitly.
- **NOT FOUND** — searched for and absent.

---

## 1. Executive summary

The confirmed Windows hang is not an isolated defect. It is one instance of a systemic architectural pattern: **the durable workspace layer treats "show me the list of elections" and "rebuild the cryptographically authoritative election" as the same operation**, and it performs that operation synchronously on the Tauri main thread.

Five findings dominate.

**F-1 (SEVERE, confirmed).** `list_election_workspaces` — a *display* command — performs a complete cryptographic reconstruction of **every** durable election workspace on disk: it rebuilds the Triptych verifier from the registry and re-verifies **every stored ballot proof**, for **every** workspace, on the **main thread**. This is the exact stack WinDbg captured. [`gui/src-tauri/src/lib.rs:1406`](gui/src-tauri/src/lib.rs:1406) → [`crates/gui-core/src/workspace.rs:302`](crates/gui-core/src/workspace.rs:302) → [`crates/gui-core/src/workspace.rs:1085`](crates/gui-core/src/workspace.rs:1085) → [`crates/gui-core/src/session.rs:142`](crates/gui-core/src/session.rs:142).

**F-2 (SEVERE, confirmed).** That command is reached from **eleven distinct UI actions**, including every ordinary lifecycle button (Open voting, Close voting, Mark verified, Finalize), every election load, resume, unload, freeze, and delete — because `AppState.refreshWorkspaces()` is called after each of them ([`gui/src/state/AppState.tsx:226`](gui/src/state/AppState.tsx:226), and its call sites at lines 298, 322, 358, 394, 426). Pressing "Close voting" on a 4100-voter election with 1000 stored ballots would, by the measured model, freeze the UI for roughly five minutes *after* the close itself already completed off-thread.

**F-3 (SEVERE, confirmed, independent of cryptography).** `load_committed_history` reads and decodes **every revision file from revision 1 to head** on **every** load ([`crates/gui-core/src/workspace.rs:822-840`](crates/gui-core/src/workspace.rs:822)), and each session revision file embeds the **entire registry plus every ballot package accepted so far** ([`crates/gui-core/src/workspace.rs:1290-1304`](crates/gui-core/src/workspace.rs:1290)). Worse, `write_workspace_revision` calls `load_committed_history` **before every write** ([`crates/gui-core/src/workspace.rs:684`](crates/gui-core/src/workspace.rs:684)). Cumulative disk traffic over an election therefore scales as **O(revisions² × registry + revisions³ × package)**. At 4100 voters this is not slow — it is arithmetically impossible to complete.

**F-4 (HIGH, measured).** Inside a single ballot verification, **44 % of the CPU at 4100 voters is spent recomputing a per-election constant**. `TariTriptychPrototypeVerifierV1::verify` rebuilds the entire Triptych statement from scratch for every ballot: it re-derives the scope generator, regenerates the commitment-matrix generators, re-decompresses all *R* registry keys, and re-compresses all *N* padded ring keys into a fresh transcript — none of which depends on the ballot ([`crates/crypto/src/triptych_verifier.rs:102-108`](crates/crypto/src/triptych_verifier.rs:102), [`crates/crypto/src/triptych_prototype.rs:29-60`](crates/crypto/src/triptych_prototype.rs:29), [`third_party/tari-triptych/src/statement.rs:72-74`](third_party/tari-triptych/src/statement.rs:72)). Measured: **131.9 ms of the 298.2 ms per ballot at R=4100 is redundant**.

**F-5 (HIGH, confirmed).** `resume_election_workspace` performs the **same full replay twice in one call** — once in `summarize_workspace` ([`crates/gui-core/src/workspace.rs:346`](crates/gui-core/src/workspace.rs:346)) and again in `from_durable_snapshot` ([`crates/gui-core/src/workspace.rs:353`](crates/gui-core/src/workspace.rs:353)).

**What is *not* wrong.** The design already contains the right instinct in two places, and both must be preserved:

- `transactional_clone` deliberately avoids replay for same-process mutations, with an explicit rationale comment ([`crates/gui-core/src/session.rs:204-214`](crates/gui-core/src/session.rs:204)) and a dedicated test (`transactional_clone_preserves_validated_state_without_durable_replay`, [`crates/gui-core/tests/workspace.rs:1666`](crates/gui-core/tests/workspace.rs:1666)). So ballot intake does **not** re-verify history.
- Most genuinely expensive commands already use `run_blocking_command` → `tauri::async_runtime::spawn_blocking` ([`gui/src-tauri/src/lib.rs:233`](gui/src-tauri/src/lib.rs:233)): archive verification, resume, close/verify/finalize, ballot preparation, Tor lifecycle. The gap is that the *listing* path was never classified as expensive.

**Headline recommendation.** Split the concept. A durable workspace has (A) cheap display metadata, (B) loaded-but-unverified durable state, and (C) a cryptographically verified authoritative session. Today `GuiElectionWorkspaceSummaryV1` is produced by building (C) and then throwing it away. Listing must be served from (A). Resume must build (C) exactly once, off-thread, and cache it under a hash-chained identity.

---

## 2. Confirmed WinDbg root cause

The supplied stack matches the current source **line for line**. Every frame was verified:

| Frame | Source | Verified content |
|---|---|---|
| `list_election_workspaces` | [`gui/src-tauri/src/lib.rs:1406-1411`](gui/src-tauri/src/lib.rs:1406) | `fn list_election_workspaces(app: AppHandle) -> …` — **synchronous** `#[tauri::command]` |
| `list_election_workspaces_v1` | [`crates/gui-core/src/workspace.rs:262`](crates/gui-core/src/workspace.rs:262) | iterates every directory under the workspaces root |
| `summarize_workspace` | [`crates/gui-core/src/workspace.rs:1055`](crates/gui-core/src/workspace.rs:1055), called at [`:302`](crates/gui-core/src/workspace.rs:302) | line **1085**: `GuiElectionSessionV1::from_durable_snapshot(snapshot.clone())?` |
| `GuiElectionSessionV1::from_durable_snapshot` | [`crates/gui-core/src/session.rs:109`](crates/gui-core/src/session.rs:109) | line **142**: `let _ = session.intake_ballot_package_bytes(package)?;` inside `for package in &snapshot.packages` |
| `intake_ballot_package_bytes` | [`crates/gui-core/src/session.rs:286`](crates/gui-core/src/session.rs:286) | line **298**: `self.process_intake_package(package_bytes)` |
| `process_intake_package` | [`crates/gui-core/src/session.rs:362`](crates/gui-core/src/session.rs:362) | line **374**: `ingest_approval_ballot_package_v1(...)` |
| `ingest_approval_ballot_package_v1` | [`crates/verifier/src/approval_ingestion.rs:17`](crates/verifier/src/approval_ingestion.rs:17) | line **45**: `verify_approval_proof(...)` |
| `verify_approval_proof` | [`crates/verifier/src/proof_verification.rs:55`](crates/verifier/src/proof_verification.rs:55) | line **90**: `proof_verifier.verify(&statement, proof_bytes)?` |
| `TariTriptychPrototypeVerifierV1::verify` | [`crates/crypto/src/triptych_verifier.rs:82`](crates/crypto/src/triptych_verifier.rs:82) | lines **113-114**: `proof.verify(&triptych_statement, &mut transcript)` |
| `TriptychProof::verify` | [`third_party/tari-triptych/src/proof.rs:410`](third_party/tari-triptych/src/proof.rs:410) | line **412**: delegates to `verify_batch` with a batch of one |
| `TriptychProof::verify_batch` | [`third_party/tari-triptych/src/proof.rs:547`](third_party/tari-triptych/src/proof.rs:547) | line **807**: `RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points)` — the AVX2 MSM |

**Why it blocks the UI (CONFIRMED).** In Tauri 2 (`tauri = "2"`, [`gui/src-tauri/Cargo.toml:23`](gui/src-tauri/Cargo.toml:23)), a `#[tauri::command]` declared without `async` executes on the main/event-loop thread. `list_election_workspaces` is declared `fn`, not `async fn`. The dump's profile — one thread with ~5.187 s of user CPU, every other thread at effectively zero — is exactly what a synchronous scalar-heavy MSM loop on the event thread produces, and it satisfies Windows' `APPLICATION_HANG_BusyHang` criteria.

**Why it fired ~16 s after startup (CONFIRMED).** There is no Rust `.setup()` hook; `run()` only registers state and the invoke handler ([`gui/src-tauri/src/lib.rs:4913-5024`](gui/src-tauri/src/lib.rs:4913)). The first `list_election_workspaces` comes from the frontend: `AppStateProvider`'s mount effect ([`gui/src/state/AppState.tsx:273-279`](gui/src/state/AppState.tsx:273)) calls `refreshWorkspaces()`, which invokes it. That fires once the WebView2 host, Vite bundle, and React tree have loaded — a plausible ~10 s after process start on a cold Windows launch, with the ~5.2 s of replay following.

**Election size consistency band (STRONGLY INFERRED, not a claim about the user's data).** Using the measured per-ballot cost in §10, 5.187 s of Triptych work corresponds to roughly: R=4100 → ~17 packages; R=1000 → ~89; R=500 → ~245; R=100 → ~749; R=50 → ~953 — **summed across all workspaces present in app-data**, and before adding the revision-history decode of §11.3. The audit cannot determine which pair applies without the user's app-data directory.

---

## 3. Complete frontend trigger inventory

### 3.1 Boundary shape (CONFIRMED)

Every backend call in the frontend goes through one wrapper. `grep -rn "invoke(" gui/src` outside [`gui/src/api/client.ts`](gui/src/api/client.ts) returns **zero** hits — there are no ad-hoc invokes. All calls funnel through `call<T>()` at [`gui/src/api/client.ts:107-116`](gui/src/api/client.ts:107).

Navigation is whole-screen conditional rendering with a keyed error boundary ([`gui/src/App.tsx:81-92`](gui/src/App.tsx:81)). **Consequence: every navigation to a screen unmounts the previous screen and fully remounts the new one, re-running all of its mount effects.** `AppStateProvider` sits above `App` ([`gui/src/main.tsx:26-34`](gui/src/main.tsx:26)) and therefore **never** unmounts.

`React.StrictMode` is enabled ([`gui/src/main.tsx:27`](gui/src/main.tsx:27)). In a development build this double-invokes effects, so every mount-effect command below fires **twice in dev**. In a production build (`vite build`) StrictMode does not double-invoke. The confirmed hang is reproducible in either build; StrictMode doubles the cost in dev only.

### 3.2 Screen-by-screen effect inventory (CONFIRMED)

| Screen | `useEffect` count | Mount-effect backend calls | Timers |
|---|---|---|---|
| `AppStateProvider` (never unmounts) | 2 | **`list_election_workspaces`**, `active_workspace_ids`, `election_summary`, `active_election_authority`, `participation_summary` ([`AppState.tsx:273-279`](gui/src/state/AppState.tsx:273)) | none |
| `Home` | **0** | **none** — renders `AppState.workspaces` | none |
| `Guide` | 0 | none | none |
| `Settings` | 0 | none | none |
| `Evidence` | 0 | none (button only) | none |
| `Archive` | 0 | none (button only) | none |
| `Anchor` | 0 | none (button only) | none |
| `About` | 2 | `shell_info` ([`About.tsx:31`](gui/src/screens/About.tsx:31)) | none |
| `CreateElection` | 4 | `get_or_create_election_draft` ([`CreateElection.tsx:213-215`](gui/src/screens/CreateElection.tsx:213)); `preview_draft` when `step === "review"` ([`:514-516`](gui/src/screens/CreateElection.tsx:514)) | none |
| `ManageElection` | 7 | `walletd_credential_status`, `walletd_readiness` ([`:476-502`](gui/src/screens/ManageElection.tsx:476)); `current_tally` ([`:503-521`](gui/src/screens/ManageElection.tsx:503)); `organizer_tor_status` + `trusted_ootle_deployment_status` ([`:585-593`](gui/src/screens/ManageElection.tsx:585)); **`sync_private_intake`** when OPEN ([`:602-624`](gui/src/screens/ManageElection.tsx:602)) | **4 s** auto-sync ([`:677-684`](gui/src/screens/ManageElection.tsx:677)) |
| `Vote` | 13 | `voter_confirmation` ([`:463-466`](gui/src/screens/Vote.tsx:463)); credential status ([`:468-471`](gui/src/screens/Vote.tsx:468)); `voter_workflow_status` ([`:490-493`](gui/src/screens/Vote.tsx:490)); `managed_tor_test_status` ([`:499-502`](gui/src/screens/Vote.tsx:499)); `voter_tor_status` ([`:507-510`](gui/src/screens/Vote.tsx:507)) | **5 s** Tor status ([`:519-528`](gui/src/screens/Vote.tsx:519)); **20 s + jitter** authenticated lifecycle refresh ([`lifecycleAutoRefresh.ts:33`](gui/src/lifecycleAutoRefresh.ts:33)) |
| `VoterCredentialCard` | 3 | credential listing/status | none |

### 3.3 The `refreshWorkspaces` fan-in — the core defect (CONFIRMED)

`refreshWorkspaces()` ([`gui/src/state/AppState.tsx:226-244`](gui/src/state/AppState.tsx:226)) calls `api.listElectionWorkspaces()`. It is invoked from **eleven** places:

| # | Trigger | Call site |
|---|---|---|
| 1 | Application startup | [`AppState.tsx:277`](gui/src/state/AppState.tsx:277) |
| 2 | `loadElection` (three-file) | [`AppState.tsx:298`](gui/src/state/AppState.tsx:298) |
| 3 | `loadElectionFolder` | [`AppState.tsx:322`](gui/src/state/AppState.tsx:322) |
| 4 | `resumeElectionWorkspace` | [`AppState.tsx:358`](gui/src/state/AppState.tsx:358) |
| 5 | `unloadElection` | [`AppState.tsx:394`](gui/src/state/AppState.tsx:394) |
| 6 | `runLifecycle("open")` | [`AppState.tsx:426`](gui/src/state/AppState.tsx:426) |
| 7 | `runLifecycle("close")` | same |
| 8 | `runLifecycle("verify")` | same |
| 9 | `runLifecycle("finalize")` | same |
| 10 | `CreateElection` freeze | [`CreateElection.tsx:525`](gui/src/screens/CreateElection.tsx:525), [`:546`](gui/src/screens/CreateElection.tsx:546) |
| 11 | `deleteElectionWorkspace` | via `delete_election_workspace`, which re-lists **in Rust** at [`lib.rs:1556`](gui/src-tauri/src/lib.rs:1556) |

**Important nuance, stated because it contradicts a natural assumption:** navigating to Home does **not** trigger a listing. `Home` has zero effects and reads the provider's cached array. The listing is triggered by *lifecycle actions*, not by *navigation*. This matters for the fix — the frontend does not need a listing after `runLifecycle`; it only needs the updated summary for the one active workspace.

---

## 4. Complete Tauri command classification

**92 distinct commands** are registered ([`gui/src-tauri/src/lib.rs:4918-5024`](gui/src-tauri/src/lib.rs:4918)); 93 `#[tauri::command]` attribute sites exist because `submit_prepared_voter_ballot_privately` has two `cfg` variants ([`lib.rs:3409`](gui/src-tauri/src/lib.rs:3409) sync, [`lib.rs:3424`](gui/src-tauri/src/lib.rs:3424) async). The complete per-command classification is in **`AUDIT_TAURI_COMMAND_BLOCKING_MATRIX.csv`**.

Summary of main-thread risk:

| Risk | Count | Commands |
|---|---|---|
| **SEVERE** | 2 | `list_election_workspaces`, `delete_election_workspace` |
| **HIGH** | 5 | `open_voting`, `intake_ballot_package`, `sync_private_intake`, `freeze_election`, `write_archive_with_governance_document` |
| **MEDIUM-HIGH** | 1 | `set_draft_governance_document` |
| **MEDIUM** | 17 | all `set_draft_*`, `import_registry_to_draft`, `export_election_artifacts`, `compute_governance_document_digest`, `match_governance_document`, `voter_confirmation`, `export_prepared_voter_ballot`, `inspect_template_wasm`, `configure_managed_tor_test`, `submit_prepared_voter_ballot_privately` (non-managed-tor build) |
| **LOW** | 16 | small file/keyring reads |
| **NONE** | 51 | already `async` + `spawn_blocking`, or demonstrably trivial |

**25 synchronous commands can perform unbounded or size-scaling work on the main thread.**

Commands capable of the specific heavy operations the brief asked about:

- **Triptych proof verification:** `list_election_workspaces` (SEVERE, sync), `delete_election_workspace` (SEVERE, sync), `intake_ballot_package` (HIGH, sync — one *new* ballot), `sync_private_intake` (HIGH, sync — new ballots only), `resume_election_workspace` (async), `verify_archive` / `verify_transport_archive_anchor` / `write_live_anchor_config_from_verified_archive` (async).
- **Signature verification:** `import_election_status_artifact`, `fetch_election_status_private`, `export_election_status_artifact` (all async, one Ed25519 op each — [`election_status.rs:352`](crates/gui-core/src/election_status.rs:352)); `configure_managed_tor_test` (sync, root + descriptor Ed25519).
- **Durable snapshot reconstruction:** `list_election_workspaces`, `delete_election_workspace`, `resume_election_workspace`.
- **Hashing over large state:** `set_draft_governance_document`, `compute_governance_document_digest`, `match_governance_document`, `voter_confirmation` — all read and blake3 a user-chosen file up to **`MAX_GOVERNANCE_DOCUMENT_BYTES` = 50 MiB** ([`crates/gui-core/src/governance.rs:67`](crates/gui-core/src/governance.rs:67)); the first is synchronous **and** embeds those 50 MiB into every subsequent draft revision.
- **Large filesystem reads:** the whole `load_committed_history` family (§5.2).
- **Indexer / wallet operations:** `run_live_anchor_lifecycle_step`, `walletd_readiness`, `connect_walletd`, `reconnect_walletd` — all async. Correct.
- **Anchor/receipt verification:** inside `run_live_anchor_lifecycle_step` (async) — [`crates/anchor-transport/src/verification.rs:71/127/154`](crates/anchor-transport/src/verification.rs:71).

---

## 5. Complete durable reconstruction call graph

### 5.1 The replay chain (CONFIRMED)

```
list_election_workspaces                    lib.rs:1406        [SYNC — MAIN THREAD]
 └─ list_election_workspaces_v1             workspace.rs:262
     ├─ for every directory under the workspaces root:
     │   ├─ load_newest_workspace           workspace.rs:745
     │   │   └─ load_committed_history      workspace.rs:754
     │   │       ├─ load_commit_markers     workspace.rs:845     (reads every .commit)
     │   │       ├─ load_committed_revision_files workspace.rs:892 (reads + blake3 + DECODES every .workspace)
     │   │       └─ for rev in 1..=head: decode_workspace + validate_predecessor  workspace.rs:822-840
     │   ├─ draft_superseding_session_v1    workspace.rs:654
     │   │   └─ load_newest_workspace(successor)  ← a SECOND full history load per superseded draft
     │   └─ summarize_workspace             workspace.rs:1055
     │       ├─ workspace_has_organizer_authority_v1  workspace.rs:604  (cheap sidecar read)
     │       └─ GuiElectionSessionV1::from_durable_snapshot  workspace.rs:1085 → session.rs:109
     │           ├─ GuiElectionArtifactsV1::from_bytes         (CBOR decode of manifest/registry/candidates)
     │           ├─ Self::new                       session.rs:78
     │           │   └─ build_tari_triptych_verifier_from_registry_v1  verifier/triptych_registry.rs:21
     │           │       └─ TariTriptychPrototypeVerifierV1::new  crypto/triptych_verifier.rs:50
     │           │           └─ validate_triptych_registry_keys_v1 → parse_sorted_registry_keys_v1
     │           │               └─ R Ristretto DECOMPRESSIONS      crypto/triptych_prototype.rs:166-185
     │           ├─ session.open()                  session.rs:140
     │           └─ for package in snapshot.packages:   session.rs:141-143
     │               └─ intake_ballot_package_bytes  session.rs:286 → process_intake_package session.rs:362
     │                   ├─ blake3 package digest             session.rs:396
     │                   ├─ transcript.record_submission      archive/replay.rs:179  (O(1))
     │                   └─ ingest_approval_ballot_package_v1 verifier/approval_ingestion.rs:17
     │                       ├─ BallotPackageEnvelopeV1::from_canonical_cbor
     │                       ├─ manifest.canonical_hash (blake3)
     │                       ├─ validate_manifest_binding + ProductionProofSuitePolicyV1
     │                       ├─ candidates.canonical_commitment (blake3)
     │                       ├─ verify_approval_proof            verifier/proof_verification.rs:55
     │                       │   ├─ reconstruct_approval_proof_statement
     │                       │   └─ TariTriptychPrototypeVerifierV1::verify  crypto/triptych_verifier.rs:82
     │                       │       ├─ derive_scope_generator_v1     ← per-election CONSTANT, recomputed
     │                       │       ├─ TriptychParameters::new_with_generators ← CONSTANT, recomputed
     │                       │       ├─ parse_sorted_registry_keys_v1 ← R DECOMPRESSIONS, recomputed
     │                       │       ├─ TriptychInputSet::new_with_padding ← N COMPRESSIONS, recomputed
     │                       │       ├─ TriptychStatement::new        ← per-ballot (cheap)
     │                       │       └─ TriptychProof::verify → verify_batch → vartime_multiscalar_mul
     │                       └─ ledger.accept_verified             verifier/lib.rs:74  (O(1) nullifier set)
     └─ sort summaries                      workspace.rs:310
```

### 5.2 Every call site of every named function (CONFIRMED — exhaustive)

**`GuiElectionSessionV1::from_durable_snapshot`** ([`session.rs:109`](crates/gui-core/src/session.rs:109)) — 3 non-test call sites:
1. [`workspace.rs:1085`](crates/gui-core/src/workspace.rs:1085) in `summarize_workspace` — reached from **listing** and **resume**.
2. [`workspace.rs:353`](crates/gui-core/src/workspace.rs:353) in `resume_election_workspace_v1` — reached from **resume**.
3. [`session.rs:223`](crates/gui-core/src/session.rs:223) in `replayed_clone` — **no production caller for the session type**; documented as reserved for hostile-disk-resume tests and diagnostics. (`GuiElectionDraftV1::replayed_clone` at [`creation.rs:402`](crates/gui-core/src/creation.rs:402) *is* used in production, but performs no cryptography.)

**`summarize_workspace`** ([`workspace.rs:1055`](crates/gui-core/src/workspace.rs:1055)) — 2 call sites: [`:302`](crates/gui-core/src/workspace.rs:302) (listing, per workspace) and [`:346`](crates/gui-core/src/workspace.rs:346) (resume).

**`list_election_workspaces_v1`** ([`workspace.rs:262`](crates/gui-core/src/workspace.rs:262)) — 2 production call sites, both **synchronous Tauri commands**: [`lib.rs:1410`](gui/src-tauri/src/lib.rs:1410) and [`lib.rs:1556`](gui/src-tauri/src/lib.rs:1556).

**`intake_ballot_package_bytes`** ([`session.rs:286`](crates/gui-core/src/session.rs:286)) — from `from_durable_snapshot` ([`:142`](crates/gui-core/src/session.rs:142)), from `intake_ballot` ([`:413`](crates/gui-core/src/session.rs:413)), and from `intake_ballot_package` ([`lib.rs:1796`](gui/src-tauri/src/lib.rs:1796)).

**`process_intake_package`** ([`session.rs:362`](crates/gui-core/src/session.rs:362)) — from `intake_ballot_package_bytes` ([`:298`](crates/gui-core/src/session.rs:298)) and `reconcile_accepted_package_bytes_from_inbox` ([`:357`](crates/gui-core/src/session.rs:357)).

**`ingest_approval_ballot_package_v1`** — one production call site ([`session.rs:374`](crates/gui-core/src/session.rs:374)) plus the archive replay session ([`crates/archive/src/verifier.rs:443`](crates/archive/src/verifier.rs:443)).

**`verify_approval_proof`** — [`approval_ingestion.rs:45`](crates/verifier/src/approval_ingestion.rs:45).

**`TariTriptychPrototypeVerifierV1::verify`** — via the `ProofVerifierV1` trait at [`proof_verification.rs:90`](crates/verifier/src/proof_verification.rs:90).

**`TriptychProof::verify` / `verify_batch`** — [`triptych_verifier.rs:114`](crates/crypto/src/triptych_verifier.rs:114); `verify` is a batch of one ([`proof.rs:410-417`](third_party/tari-triptych/src/proof.rs:410)).

**Semantically equivalent reconstruction functions found by inspection (not by name):**

- `load_committed_history` ([`workspace.rs:754`](crates/gui-core/src/workspace.rs:754)) — full durable-history reconstruction, **no cryptography but O(history) I/O + decode**. Call sites: `load_newest_workspace` ([`:749`](crates/gui-core/src/workspace.rs:749)) and **`write_workspace_revision` ([`:684`](crates/gui-core/src/workspace.rs:684))**. Transitively reached by *every* durable write: `intake_ballot_package`, `sync_private_intake`, `open_voting`, `close_voting`, `mark_verified`, `finalize_election`, `freeze_election`, and all eight `set_draft_*` commands.
- `ArchiveReplaySessionV1` ([`crates/archive/src/verifier.rs:435-446`](crates/archive/src/verifier.rs:435)) — the archive-authoritative equivalent of `from_durable_snapshot`. Reached by `verify_archive`, `verify_transport_archive_anchor`, and `write_live_anchor_config_from_verified_archive` (all async).
- `ingest_private_intake_inbox_into_session_v1` ([`private_intake_inbox.rs:237`](crates/gui-core/src/private_intake_inbox.rs:237)) — partial reconstruction: re-reads and re-hashes every inbox file each pass; already-decided packages short-circuit at [`session.rs:336-341`](crates/gui-core/src/session.rs:336) via a **linear scan of the transcript**, so a pass is O(files × decisions) even with no new work.

---

## 6. Complete cryptographic verification inventory

| # | Operation | Where | Security property | Input | Input immutable? | Already verified earlier? | Result persisted? | Repeated? | Required on every access? | Safe to cache? | Cache invalidated by |
|---|---|---|---|---|---|---|---|---|---|---|---|
| V1 | Triptych proof verification | [`crypto/triptych_verifier.rs:82-120`](crates/crypto/src/triptych_verifier.rs:82) | Anonymous membership in the frozen registry + binding to this exact ballot payload/manifest/scope | canonical proof bytes + reconstructed statement | YES (package bytes are content-addressed and frozen) | YES, at original intake | **NO** | YES — on every listing/resume | **NO** — only when the package set or the artifacts change | **YES** | change of workspace head-revision digest, manifest, registry, candidate set, protocol/suite id, or verifier build epoch |
| V2 | Registry-key canonicality | [`crypto/triptych_prototype.rs:62-69`](crates/crypto/src/triptych_prototype.rs:62), via [`triptych_verifier.rs:54`](crates/crypto/src/triptych_verifier.rs:54) | Every governance key is a canonical non-identity Ristretto point, strictly sorted and unique | registry key list | YES (registry is frozen at freeze time) | YES | NO | YES — once per session build, i.e. once per workspace per listing | NO | **YES** — key on the registry commitment | registry commitment change |
| V3 | Manifest binding of a package | [`approval_ingestion.rs:34`](crates/verifier/src/approval_ingestion.rs:34) | The ballot names this election's manifest hash and proof suite | envelope + manifest hash | YES | YES | NO | YES | NO | YES (with V1) | same as V1 |
| V4 | Production proof-suite policy | [`approval_ingestion.rs:35`](crates/verifier/src/approval_ingestion.rs:35) | Test-only suites are refused in production | suite id string | YES | YES | NO | YES | NO | YES | protocol/suite id change |
| V5 | Candidate-set commitment | [`approval_ingestion.rs:37-42`](crates/verifier/src/approval_ingestion.rs:37) | The authoritative candidate set matches the manifest | candidate bytes + manifest | YES | YES | NO | YES | NO | YES | candidate/manifest change |
| V6 | Statement-echo check | [`proof_verification.rs:92-97`](crates/verifier/src/proof_verification.rs:92) | The verifier cannot return a result for a different statement | verifier output | YES | YES | NO | YES | NO | YES (with V1) | same as V1 |
| V7 | First-valid-nullifier acceptance | [`verifier/lib.rs:74-97`](crates/verifier/src/lib.rs:74) | One acceptance per registry-scoped nullifier; first valid ballot wins | verified nullifier | YES | YES | **NO** — the ledger is never serialized | YES | NO | YES — but only as part of a whole verified session | same as V1 |
| V8 | Package content-address digest | [`session.rs:396`](crates/gui-core/src/session.rs:396), [`private_intake_inbox.rs:123`](crates/gui-core/src/private_intake_inbox.rs:123) | The package bytes are exactly the ones decided/handed off | package bytes | YES | YES | file name only | YES (every inbox pass) | for a *new* file: yes | YES — a decided-digest set | inbox file added/removed |
| V9 | Workspace revision digest + predecessor chain | [`workspace.rs:1506`](crates/gui-core/src/workspace.rs:1506), [`:989-1013`](crates/gui-core/src/workspace.rs:989) | The durable history is an unbroken, untampered blake3 chain | revision payloads | YES | YES | commit markers on disk | YES — full chain re-walked on every read *and every write* | **the head must be authenticated; the whole chain need not be re-walked in-process** | YES — head `(revision, digest)` | any new revision |
| V10 | Organizer-authority marker | [`workspace.rs:604-632`](crates/gui-core/src/workspace.rs:604) | Ballot-office provenance (fail-closed) | sidecar file | NO — a separate file, not covered by V9 | n/a | file presence | cheap | YES — must be re-read | **NO** (re-read; it is ~1 file, microseconds) | n/a |
| V11 | Supersession marker | [`workspace.rs:494-548`](crates/gui-core/src/workspace.rs:494) | A frozen draft is retired from discovery | sidecar file + successor kind | NO | n/a | file presence | costs a **full successor history load** per superseded draft | YES | successor *kind* is cacheable under V9's key | successor head change |
| V12 | Election-status statement signature | [`election_status.rs:352-376`](crates/gui-core/src/election_status.rs:352) | Signed lifecycle truth from a pinned transport root | statement CBOR | NO — new statement each time | NO | accepted record persisted | per fetch/import | YES | **NO** | n/a |
| V13 | Archive file digests + archive-hash rebuild | [`archive/verifier.rs:326`](crates/archive/src/verifier.rs:326), [`:460+`](crates/archive/src/verifier.rs:460) | The published archive is internally consistent | archive files | YES while unchanged on disk | not in this process | NO | per click | **YES on demand — this is the independent verifier** | Only as a same-run memo keyed by `(dir, archive hash)`; never across restarts | any file change |
| V14 | Archive ballot replay | [`archive/verifier.rs:435-446`](crates/archive/src/verifier.rs:435) | The published result is reproducible from published data | archived packages | YES | not in this process | NO | per click | **YES on demand** | same-run memo only | any file change |
| V15 | Transport descriptor / receipt Ed25519 | [`gui-core/transport.rs:159-192`](crates/gui-core/src/transport.rs:159), [`transport-gateway/lib.rs:446`](crates/transport-gateway/src/lib.rs:446) | Ballot office identity, receipt authenticity | descriptor / receipt | per-message | NO | descriptor cached in state | per message | YES | NO | n/a |
| V16 | Anchor receipt / finality verification | [`anchor-transport/verification.rs:71/127/154`](crates/anchor-transport/src/verification.rs:71) | On-chain anchor evidence is genuine and final | receipts | NO — live chain state | NO | evidence file | per step | YES | NO | n/a |
| V17 | Governance-document digest | [`governance.rs`](crates/gui-core/src/governance.rs), used at [`lib.rs:2746`](gui/src-tauri/src/lib.rs:2746) etc. | The archived document matches the pinned revision | user file up to 50 MiB | user-controlled | NO | in the draft/archive | per call | YES | NO (user file may change) | n/a |

**Nothing in the current implementation persists a verification verdict.** V1–V7 are recomputed from scratch on every reconstruction, and V9 is re-walked on every read *and* write.

---

## 7. UI action matrix

The full matrix is **`AUDIT_CRYPTO_TRIGGER_MATRIX.csv`** (44 rows). Condensed answer to the brief's direct question — *"does pressing ordinary buttons or switching tabs cause the same expensive cryptographic reconstruction again?"*:

| UI action | Reconstructs session? | Verifies Triptych? | Historical ballots touched | Main-thread risk | Necessary? |
|---|---|---|---|---|---|
| **Navigate to Home** | **NO** | **NO** | 0 | none | — |
| Navigate to Guide / Settings / About / Archive / Anchor / Evidence | NO | NO | 0 | none | — |
| Navigate to **Manage Election** | NO | NO | 0 (but `sync_private_intake` re-reads every inbox file, sync) | HIGH | partly |
| Navigate to **Vote** | NO | NO | 0 | LOW | yes |
| Navigate to **Create Election** | NO | NO | 0 | none | yes |
| **Application startup** | **YES — every workspace** | **YES** | **ALL, ×workspaces** | **SEVERE** | **NO** |
| **Open voting** | NO for the action; **YES for the follow-up refresh** | **YES (refresh)** | **ALL, ×workspaces** | **SEVERE** (refresh) + HIGH (`open_voting` itself) | **NO** |
| **Close voting / Mark verified / Finalize** | NO for the action; **YES for the follow-up refresh** | **YES (refresh)** | **ALL, ×workspaces** | **SEVERE** (refresh) | **NO** |
| **Resume election** | **YES — TWICE** | **YES — TWICE** | 2× that workspace, then ALL ×workspaces for the refresh | SEVERE (the refresh; the resume itself is off-thread) | one replay yes, the second no, the refresh no |
| **Delete workspace** | **YES — every remaining** | **YES** | ALL ×workspaces | **SEVERE** | **NO** |
| **Freeze election** | NO ballots; validates R registry keys | NO | 0 ballots, R keys | HIGH + SEVERE (refresh) | key check yes, refresh no |
| **Load election / folder** | NO ballots | NO | 0 ballots, R keys | SEVERE (refresh only) | refresh no |
| **Import ballot package** | NO | **YES — one new ballot** | 1 + full revision-history decode | HIGH | verification yes, history decode no |
| **Sync accepted ballots / 4 s auto-sync** | PARTIAL | **YES — new ballots only** | all inbox files, O(N²) scan | HIGH | new-ballot verification yes, re-reading known files no |
| **Verify archive** (Archive screen) | **YES — archive replay** | **YES** | all archived packages | none (async) | **YES — this is the point of the button** |
| **Verify transport anchor** | **YES — archive replay again** | **YES** | all archived packages | none | verification yes, *re-running* the archive replay it just ran, no |
| **Write live anchor config** | **YES — archive replay again** | **YES** | all archived packages | none | derivation from a verified archive yes, third replay no |
| **Prepare ballot** (voter) | NO | NO (proves, not verifies) | 0 | none | yes |
| **Submit privately** (voter) | NO | NO | 0 | MEDIUM in non-managed-tor builds | yes |

---

## 8. Repeated verification findings

**15 confirmed triggers can re-verify already-verified ballots.** Twelve go through the durable-workspace replay; three go through the archive verifier.

**R-1 — Listing is reconstruction (SEVERE).** `summarize_workspace` needs six fields. Five of them come from data already in hand:

| Summary field | Actual source | Needs a verified session? |
|---|---|---|
| `workspace_id` | `record.workspace_id` | **NO** |
| `last_revision` | `record.revision` | **NO** |
| `updated_at_unix_secs` | `record.updated_at_unix_secs` | **NO** |
| `election_manifest_hash_hex` | `session.summary()` — but derivable by hashing `snapshot.manifest_bytes` directly | **NO** |
| `question_preview` | `session.summary().proposal_question` — decodable from `snapshot.manifest_bytes` alone | **NO** |
| `lifecycle_state` | `session.lifecycle_state()` — but `snapshot.lifecycle_state` is *already the stored field* the replay reproduces | **NO** |
| `finalized` | derived from `lifecycle_state` | **NO** |
| `organizer_workspace` | sidecar marker read | **NO** |
| **`accepted_ballot_count`** | `session.accepted_count()` = `ledger.len()` | **YES — this is the only field that requires the ledger** |

So **one integer** is forcing a full cryptographic replay of every election on disk. §13 covers how to supply it safely.

**R-2 — Double replay on resume (HIGH).** [`workspace.rs:346`](crates/gui-core/src/workspace.rs:346) and [`:353`](crates/gui-core/src/workspace.rs:353) reconstruct the identical snapshot twice. Exactly 50 % of resume CPU is waste.

**R-3 — Per-ballot recomputation of per-election constants (HIGH, MEASURED).** See §10.2. Four sub-operations inside `verify` depend only on `(protocol_version, suite_id, election_scope, registry_keys)` — all frozen for the life of the election — yet are recomputed per ballot.

**R-4 — Full history re-walk on every durable write (SEVERE).** [`workspace.rs:684`](crates/gui-core/src/workspace.rs:684).

**R-5 — Supersession successor loads (MEDIUM).** Each superseded draft in the listing costs an extra full `load_committed_history` of its successor session ([`workspace.rs:668`](crates/gui-core/src/workspace.rs:668)).

**R-6 — Inbox re-read on a 4-second timer (MEDIUM).** Every pass reads and blake3-hashes every inbox file and performs a linear transcript scan per file ([`private_intake_inbox.rs:280-298`](crates/gui-core/src/private_intake_inbox.rs:280), [`session.rs:336-341`](crates/gui-core/src/session.rs:336)) — O(files × decisions) with **zero** new work.

**R-7 — Triple archive replay in the anchor flow (MEDIUM).** Verify archive → verify transport anchor → write live anchor config each independently re-run `verify_archive_directory_v1` over the same unchanged directory.

**R-8 — StrictMode dev doubling (LOW, dev only).** Mount effects double-invoke in development builds ([`main.tsx:27`](gui/src/main.tsx:27)), so startup performs the listing replay twice in `npm run dev`.

**What is *not* repeated (verified, for the record):** ballot intake does **not** replay history — `mutate_session_transactionally` uses `transactional_clone` ([`lib.rs:1012`](gui/src-tauri/src/lib.rs:1012)), which is a structural clone with an explicit rationale comment at [`session.rs:204-214`](crates/gui-core/src/session.rs:204).

---

## 9. Main-thread blocking findings

25 synchronous commands can perform unbounded work on the Tauri event thread (§4). The ones that can plausibly cross Windows' 5-second hang threshold:

1. **`list_election_workspaces`** — proven by the dump. Unbounded in (ballots × workspaces).
2. **`delete_election_workspace`** — same body, same unbounded cost, plus a recursive directory removal.
3. **`sync_private_intake`** — fires from a 4-second timer while OPEN; O(inbox files) I/O + O(files × decisions) scanning + per-new-ballot verification + full history re-walk + fsync.
4. **`intake_ballot_package`** — one required proof verification (up to 298 ms at R=4100) plus a full history re-walk.
5. **`open_voting`** — the only lifecycle transition that was *not* converted to `spawn_blocking`; still pays a full history re-walk.
6. **`freeze_election`** — R registry-key decompressions (measured 38.8 ms at R=4100) plus history re-walk and three durable writes.
7. **`set_draft_governance_document`** — reads up to 50 MiB, hashes it, and writes it into a revision that every subsequent draft edit will re-read.
8. **`write_archive_with_governance_document`** — writes an entire archive synchronously. **No frontend caller was found**; the wrapper exists at [`client.ts:400`](gui/src/api/client.ts:400) but nothing calls it.

The `run_blocking_command` helper ([`lib.rs:233-246`](gui/src-tauri/src/lib.rs:233)) already exists and is used correctly by 30+ commands. The listing path simply never adopted it.

---

## 10. 50-voter scaling analysis

### 10.1 Measurement method (MEASURED)

A standalone crate outside the repository was built against `third_party/tari-triptych` through its public API, reproducing exactly what [`crates/crypto/src/triptych_prototype.rs:29-60`](crates/crypto/src/triptych_prototype.rs:29) does per ballot. Release profile, `-C target-cpu=native`, Windows 11, this machine. Ring exponent chosen by the repository's own rule ([`triptych_prototype.rs:140-164`](crates/crypto/src/triptych_prototype.rs:140)). Numbers are microseconds per ballot; run-to-run variance of ±15 % was observed between the two benchmark passes, so treat these as *magnitudes*, not precision figures.

| Registry R | ring m | padded N | decompress R keys | params | input set | statement | **Σ statement rebuild** | **MSM verify** | **Σ per ballot** |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 3 | 8 | 85 | 217 | 81 | 16 | **397** | **867** | **1 264 µs** |
| **50** | **6** | **64** | **475** | **386** | **631** | **47** | **1 824** | **3 617** | **5 441 µs** |
| 100 | 7 | 128 | 1 132 | 483 | 1 233 | 84 | **2 783** | **4 142** | **6 926 µs** |
| 500 | 9 | 512 | 4 712 | 570 | 4 875 | 302 | **10 508** | **10 620** | **21 128 µs** |
| 1 000 | 10 | 1 024 | 11 741 | 963 | 15 500 | 989 | **32 427** | **25 705** | **58 132 µs** |
| 4 100 | 13 | 8 192 | 38 776 | 839 | 80 403 | 5 079 | **131 898** | **166 259** | **298 157 µs** |

Plus a one-off **verifier construction** cost per `GuiElectionSessionV1::new` equal to the "decompress R keys" column (V2 above): 0.5 ms at R=50, **38.8 ms at R=4100**. This is paid for **every workspace on every listing**, even a FROZEN workspace holding zero ballots.

### 10.2 Redundant fraction (MEASURED)

"Σ statement rebuild" is per-election-constant work recomputed for every ballot:

| R | redundant per ballot | share of total |
|---:|---:|---:|
| 50 | 1.82 ms | **33.5 %** |
| 500 | 10.5 ms | **49.7 %** |
| 1 000 | 32.4 ms | **55.8 %** |
| 4 100 | 131.9 ms | **44.2 %** |

### 10.3 Full-replay time, one workspace (STRONGLY INFERRED from §10.1)

`t = decompress_R + N × per_ballot`, where N is the number of **stored packages** (`snapshot.packages`) — note this includes **rejected** packages too, because `process_intake_package` pushes every package it processes ([`session.rs:391`](crates/gui-core/src/session.rs:391)).

**A 50-voter election (R = 50):**

| Stored packages N | One full replay |
|---:|---:|
| 2 | **11 ms** |
| 10 | 55 ms |
| **50** | **272 ms** |
| 100 (50 accepted + 50 duplicates/rejects) | 545 ms |

**Verdict for 50 voters:** the current architecture is *survivable*. A 272 ms main-thread stall per listing is a perceptible but not fatal hitch — and it is multiplied by the number of workspaces on disk and by the eleven triggers of §3.3. Three 50-voter workspaces already cost ~0.8 s per lifecycle button press.

### 10.4 Cross-size table (STRONGLY INFERRED)

Realistic pairings where R ≥ electorate:

| Election | R | N | One full replay | Comment |
|---|---:|---:|---:|---|
| tiny pilot | 8 | 2 | 0.09 s | fine |
| small | 50 | 50 | **0.27 s** | perceptible hitch |
| medium | 100 | 100 | **0.69 s** | clearly laggy |
| large | 500 | 500 | **10.6 s** | **hangs Windows** |
| very large | 1 000 | 1 000 | **58 s** | unusable |
| target | 4 100 | 4 100 | **20.4 min** | impossible |

Windows raises "Not Responding" at ~5 s of an unpumped message queue. **A single-workspace replay crosses that threshold at roughly N ≈ 950 for R = 50, N ≈ 245 for R = 500, N ≈ 89 for R = 1000, and N ≈ 17 for R = 4100.**

---

## 11. 4100-voter scaling implications

### 11.1 Cryptographic cost (MEASURED + INFERRED)

| N stored packages | One replay at R = 4100 |
|---:|---:|
| 2 | 0.64 s |
| **17** | **~5.1 s — crosses the Windows hang threshold** |
| 50 | 14.9 s |
| 100 | 29.9 s |
| 500 | 2.5 min |
| 1 000 | 5.0 min |
| **4 100** | **20.4 min** |

Every one of the eleven `refreshWorkspaces` triggers pays this, **per workspace on disk**, **on the main thread**.

### 11.2 What optimisation can recover (MEASURED)

**Hoisting the per-election constants** (F-4) removes 131.9 ms/ballot → 166.3 ms/ballot; a 4100-ballot replay drops from 20.4 min to **11.4 min**.

**Batch verification.** The vendored crate already supports batching proofs that share one `TriptychInputSet` and `TriptychParameters` but carry distinct linking tags ([`proof.rs:537-551`](third_party/tari-triptych/src/proof.rs:537)) — exactly the ballot case. Measured amortisation:

| R | batch 1 | batch 2 | batch 5 | batch 10 | batch 20 |
|---:|---:|---:|---:|---:|---:|
| 50 | 2 429 µs | 1 455 | 1 381 | 1 157 | **821 µs** |
| 500 | 9 866 µs | 5 539 | 2 856 | 1 977 | **1 723 µs** |
| 4 100 | 152 483 µs | 113 900 | 34 958 | 20 438 | **16 278 µs** |

At R=4100 a batch of 20 is **9.4× cheaper per proof** than one-at-a-time. (The batch-2 figure at R=4100 is noisy — only 3 repetitions — but the trend across 5/10/20 is unambiguous.)

**Combined ceiling:** constants hoisted + batches of 20 → 4100 ballots in **≈ 67 s** instead of 20.4 min: an 18× improvement. Two conclusions follow. First, batching is genuinely valuable. Second, **67 seconds is still not a UI operation** — a full 4100-ballot replay must be a background job with progress reporting and cancellation, never something a button press implies. This is precisely why the *verified-session cache* (§14) matters more than the crypto optimisation: after the first replay, the correct cost of a repeat open is **zero**.

**Note on `verify_batch` semantics:** batching changes *failure attribution*, not *acceptance*. The library provides `verify_batch_with_single_blame` / `verify_batch_with_full_blame` ([`proof.rs:433`](third_party/tari-triptych/src/proof.rs:433), [`:516`](third_party/tari-triptych/src/proof.rs:516)) which re-verify individually on failure. Adopting batching would require using a blame variant so that per-ballot accept/reject decisions and the transcript remain byte-identical. That is a design constraint for the later implementation pass, not something this audit changes.

### 11.3 The non-cryptographic wall (STRONGLY INFERRED, ESTIMATE inputs)

Size assumptions, stated explicitly:
- Registry CBOR ≈ R × 36 B (a 32-byte key plus framing) → **~148 KB at R = 4100**, ~1.8 KB at R = 50. *(ESTIMATE.)*
- Triptych proof = `8 + 32 × (7 + 3m)` bytes ([`proof.rs:816-828`](third_party/tari-triptych/src/proof.rs:816)) → **1 480 B at m = 13**; a full package with envelope and payload ≈ **1.6 KB**. *(CONFIRMED formula; ESTIMATE for the envelope overhead.)*
- Revision file *k* ≈ 148 KB + k × 1.6 KB ([`workspace.rs:1290-1304`](crates/gui-core/src/workspace.rs:1290)).

**One listing/resume** reads and decodes revisions 1..Rv:

| Head revision Rv (R = 4100) | Bytes read + decoded per listing |
|---:|---:|
| 100 | **23 MB** |
| 500 | **274 MB** |
| 4 100 | **14 GB** |

**Cumulative over the whole election**, because `write_workspace_revision` re-reads the history before every write:

| Rv | Total durable I/O over the election |
|---:|---:|
| 100 | ~1 GB |
| 500 | ~52 GB |
| 4 100 | **~19.7 PB** |

**This is the real 4100-voter blocker.** Even if Triptych verification were free, the durable format — full registry plus the full package set copied into every revision, with the entire chain re-read on every read and every write — makes a 4100-voter election arithmetically impossible to run. **This is an independent finding and would need its own remediation slice; it is out of scope for the cache work but must not be forgotten.**

### 11.4 Also flagged for 4100 voters

- `MAX_REGISTRY_MEMBERS = 4_096` ([`crates/protocol/src/limits.rs:15`](crates/protocol/src/limits.rs:15)). **A 4100-voter election exceeds the protocol's own registry limit.** The stated target is not currently representable. (CONFIRMED.)
- `MAX_WORKSPACE_REVISION_BYTES_V1 = 512 MB` ([`workspace.rs:35`](crates/gui-core/src/workspace.rs:35)) is not the binding constraint (revision 4100 is ~6.7 MB); the *count* of revisions is.
- `sync_private_intake`'s duplicate short-circuit is a linear transcript scan ([`session.rs:336-341`](crates/gui-core/src/session.rs:336)) → O(N²) per 4-second tick: ~16.8 M 32-byte comparisons at N = 4100, on the main thread, every 4 seconds.

---

## 12. Security-required versus redundant verification

### 12.1 Required, keep exactly as-is

- **First verification of any newly-arrived package** — file import ([`lib.rs:1787`](gui/src-tauri/src/lib.rs:1787)), inbox reconciliation of a package not yet in the transcript ([`session.rs:357`](crates/gui-core/src/session.rs:357)), collector acceptance ([`organizer_tor_intake.rs`](gui/src-tauri/src/organizer_tor_intake.rs) worker thread). **Never cache, never skip.**
- **Archive verification** (`verify_archive` and friends) — this *is* the independent verifier. It must remain a real, complete replay of the archive on disk. A same-run memo keyed by `(directory, archive hash)` is defensible; anything persisted across restarts is not.
- **Every signature check** — election-status statements, transport descriptors, receipts, anchor evidence. Each is a fresh message; caching is meaningless and unsafe.
- **Registry-key canonicality (V2)** — required once per distinct registry, not once per workspace per listing.
- **Revision-chain integrity (V9)** — the *head* revision digest must be authenticated against its commit marker on every read. What is redundant is re-walking revisions 1..head-1 in-process when the head digest already hash-chains over them.

### 12.2 Redundant — safe to eliminate without weakening any rule

| Redundancy | Why it is safe to remove |
|---|---|
| Full replay to render a workspace **list** | Eight of nine summary fields need no ledger; the ninth (`accepted_ballot_count`) can be supplied as authenticated durable metadata or as explicitly-untrusted display data (§13) |
| **Second** replay inside `resume_election_workspace` | Identical input, identical code path, identical result — pure duplication |
| Per-ballot rebuild of scope generator, Triptych parameters, registry decompression, input-set compression | All four are pure functions of frozen per-election inputs; the values are identical for every ballot in the election |
| Re-walking revisions 1..head-1 on every read/write | The head digest is a blake3 hash chain: `payload(k)` embeds `digest(k-1)` via `encode_predecessor` ([`workspace.rs:1124-1140`](crates/gui-core/src/workspace.rs:1124)) and `digest(k) = H(domain ‖ 0x00 ‖ payload(k))` ([`workspace.rs:1506-1513`](crates/gui-core/src/workspace.rs:1506)). Authenticating the head therefore authenticates the whole chain. A **full** chain walk remains valuable as an explicit integrity-check operation, but it must not be the price of opening a menu. |
| Re-reading and re-hashing already-decided inbox files every 4 s | Content-addressed names plus a decided-digest set give the same answer |
| Second and third archive replays in the anchor flow | Same directory, same archive hash, same process run |

### 12.3 Why `from_durable_snapshot` replays — history check (§15 of the brief)

**Searched:** `git log -S` on `from_durable_snapshot` and `transactional_clone`; all 12 ADRs; `docs/reviews/*`; `docs/threat-model/` (empty); `PHASE_STATUS.md`; `SECURITY*` (**NOT FOUND** — no SECURITY file exists); all comments in `session.rs` and `workspace.rs`.

**Result.** The replay was introduced in `260cc6c "feat: add durable election workspace recovery"` (2026-08-14) together with the whole workspace layer. Commit messages are one-line; **no ADR or review document explains the replay decision** (NOT FOUND). But the source itself makes the reason unambiguous, and it is **structural, not merely defensive**:

> "This is intentionally made from canonical public artifacts plus the exact canonical ballot-package bytes that already feed archive replay. **It does not serialize the verifier, nullifier set, or accepted-ledger internals.**" — [`session.rs:54-58`](crates/gui-core/src/session.rs:54)

The durable snapshot stores **only** `lifecycle_state`, `manifest_bytes`, `registry_bytes`, `candidate_bytes`, and `packages` ([`session.rs:59-66`](crates/gui-core/src/session.rs:59), encoder at [`workspace.rs:1290`](crates/gui-core/src/workspace.rs:1290)). The `BallotAcceptanceLedger` — nullifier set, accepted payloads, accepted count — is a **derived** quantity that exists nowhere on disk. Replay is the only way to reconstruct it, and it is also the only way to reproduce the transcript in intake order.

The complementary decision is equally deliberate and equally documented:

> "This intentionally does not call `from_durable_snapshot`: **disk resume still replays persisted packages through proof verification**, but ordinary same-process mutations preserve the already-validated verifier, ledger, transcript, lifecycle, and package bytes directly." — [`session.rs:204-214`](crates/gui-core/src/session.rs:204), with the test at [`tests/workspace.rs:1666`](crates/gui-core/tests/workspace.rs:1666)

And the hostile-resume intent is pinned by tests: `tampered_committed_newest_revision_fails_closed_without_rollback` ([`tests/workspace.rs:1160`](crates/gui-core/tests/workspace.rs:1160)), `resume_replays_accepted_packages_and_rejects_duplicate_nullifier` ([`:1707`](crates/gui-core/tests/workspace.rs:1707)), `revision_copied_into_different_workspace_id_is_rejected` ([`:1448`](crates/gui-core/tests/workspace.rs:1448)).

**Conclusion.** The security objective is: *a session reconstructed from disk must never be trusted unless every ballot in it has passed real proof verification and the first-valid-nullifier rule in this process.* That objective is correct and must be preserved exactly. What is **not** required by that objective is (a) applying it to a *display listing*, and (b) re-applying it to *byte-identical, already-verified* durable state within one process run. The cache in §14 preserves the objective while removing both.

---

## 13. Recommended lightweight workspace listing design

**Principle.** Listing produces **display metadata**. It must never construct, return, or imply a verified session.

**Proposed shape (design only — not implemented):**

1. Add `summarize_workspace_metadata_only(...)` alongside the existing function. It uses the head `DurableElectionWorkspaceV1` record that `load_newest_workspace` already returns and performs **no** cryptography beyond what it already did for the revision digest:
   - `lifecycle_state` ← `snapshot.lifecycle_state` (already a stored, chain-authenticated field)
   - `election_manifest_hash_hex` ← blake3 over `snapshot.manifest_bytes` (one hash — no verifier, no ring)
   - `question_preview` ← decode `snapshot.manifest_bytes` only (CBOR decode; V2 manifests carry `proposal_question`)
   - `finalized`, `last_revision`, `updated_at_unix_secs`, `workspace_id` ← record fields
   - `organizer_workspace` ← existing sidecar read ([`workspace.rs:604`](crates/gui-core/src/workspace.rs:604))
2. **`accepted_ballot_count` — two options; recommend Option A.**
   - **Option A (recommended, no format change): report `stored_package_count = snapshot.packages.len()` as an explicitly *unverified* display field, renamed accordingly.** Rename the field to something that cannot be mistaken for the authoritative accepted count (e.g. `stored_ballot_count`), mark it in the type as display-only, and have the UI label it "ballots stored" rather than "accepted". The authoritative accepted count continues to come only from a verified session (`participation_summary`, `current_tally`). This changes **no durable format** and adds **no new trust**.
   - **Option B (needs a format change — defer): add an authenticated `accepted_ballot_count` to the revision body.** It would be covered by the revision digest and hence by the chain, so it is not forgeable without breaking the chain. But it introduces a durable-format version bump and a new class of "the count says 5, the replay says 4" divergence, which must fail closed. Out of scope for this pass, and explicitly disallowed by the constraints.
3. `list_election_workspaces_v1` calls the metadata-only summariser. `resume_election_workspace_v1` continues to call the verifying path — **once** (see §14).
4. Make `list_election_workspaces` and `delete_election_workspace` `async fn` and wrap the body in `run_blocking_command`, because even metadata-only listing does filesystem I/O.

**Security rule satisfied.** A metadata listing never becomes trusted election state because the metadata type is distinct from the verified-session type (§16 below), the count is renamed to remove the false authority, and no command consumes listing output as election state. Grep confirms today's `GuiElectionWorkspaceSummaryV1` is consumed **only** by the frontend for display and by `resume_election_workspace`'s role decision — and that role decision reads `organizer_workspace`, which comes from the sidecar marker, not from the replay.

**Additional listing fix.** `draft_superseding_session_v1` ([`workspace.rs:654`](crates/gui-core/src/workspace.rs:654)) should learn the successor's *kind* from the head record it already decodes, rather than triggering an extra full-history load per superseded draft.

---

## 14. Recommended verified-session cache architecture

**Recommendation: memory-only, per-process, no persistence.** Persisting a "this was verified" verdict across restarts creates a trust artifact that an attacker with filesystem access could plant — the exact confusion the fail-closed resume was built to prevent. A process-local cache adds no new trust: it only avoids *re-deriving, within one process run, a value this process already derived from bytes it can prove are unchanged*.

**Proposed type (design only):**

```
VerifiedElectionSessionCacheV1
  entries: LruMap<VerifiedSessionKeyV1, Arc<VerifiedElectionSessionV1>>   // capacity ~4
  inflight: Map<VerifiedSessionKeyV1, Weak<Barrier>>                       // stampede control
```

`VerifiedElectionSessionV1` is a **new wrapper type with no public constructor** other than "a real replay just succeeded" — see §16.

**Where it lives.** In `gui-core`, owned by the Tauri `AppState` (`Mutex<VerifiedElectionSessionCacheV1>`), not a global static. That keeps it process-scoped, test-injectable, and dropped on shutdown.

**What it caches.** Two independent layers, because they have different keys and different lifetimes:

| Layer | Key | Value | Why separate |
|---|---|---|---|
| **L1 — verifier** | `registry_commitment` + `suite_id` + `protocol_version` + `verifier_epoch` | the built `TariTriptychPrototypeVerifierV1` **and** the derived per-election Triptych constants (scope generator, parameters, decompressed keys, input set) | shared by every session of the same election; removes F-4 and V2's per-workspace cost |
| **L2 — verified session** | see §15 | `Arc<VerifiedElectionSessionV1>` | removes R-1, R-2, and repeat opens |

---

## 15. Exact cache keys

Derived from the repository's actual identity design, not invented.

### L2 — verified session key

```
VerifiedSessionKeyV1 {
    workspace_id:            String,   // validate_workspace_id_v1-checked, workspace.rs:224
    head_revision:           u64,      // CommittedRevision.revision, workspace.rs:148
    head_revision_digest_hex:String,   // CommittedRevision.digest_hex — see below
    verifier_epoch:          u32,      // build-time constant, bumped on any crypto/verifier/protocol change
}
```

**Why the head digest alone is sufficient (CONFIRMED).** `revision_digest_hex(payload) = blake3("tari-cc-private-ballot/durable-election-workspace-revision/v1" ‖ 0x00 ‖ payload)` ([`workspace.rs:1506-1513`](crates/gui-core/src/workspace.rs:1506)). `encode_workspace` writes the predecessor into the payload, and `encode_predecessor` writes the *previous revision's digest hex* ([`workspace.rs:1124-1140`](crates/gui-core/src/workspace.rs:1124)). Therefore `digest(k)` commits to `digest(k-1)` commits to … `digest(1)`, and the payload of the head commits to the manifest, registry, candidate set, lifecycle state, **and the exact ordered package list**. **The head digest is a collision-resistant commitment to the entire durable state and its whole history.** No separate manifest digest, snapshot digest, or package-set digest is needed — adding them would be redundant, not safer.

**Why `workspace_id` is still in the key.** `read_valid_revision_file` already rejects a revision whose embedded `workspace_id` differs ([`workspace.rs:954`](crates/gui-core/src/workspace.rs:954)), and `revision_copied_into_different_workspace_id_is_rejected` pins that. Including the id keeps the key self-evidently non-transferable between elections even if that check ever changed.

**Why `verifier_epoch` is in the key.** Nothing on disk changes when the verifier implementation changes. A constant bumped by developers on any change to `crates/crypto`, `crates/verifier`, `crates/protocol`, or the vendored `triptych` crate makes stale entries structurally unreachable after an upgrade. A cheap enforcement mechanism: derive it from `PROTOCOL_VERSION_V1`, `TARI_TRIPTYCH_PROOF_SUITE_ID_V1`, and a manually maintained `VERIFIED_SESSION_CACHE_EPOCH: u32` with a doc comment requiring a bump.

**What is deliberately NOT in the key, and how it is handled instead:**

| Not in the key | Why | Handling |
|---|---|---|
| organizer-authority marker | a sidecar file, not covered by the revision digest ([`workspace.rs:604`](crates/gui-core/src/workspace.rs:604)) | **re-read on every cache hit** — it is one small file, microseconds. Never cached. |
| supersession marker | same | re-read on every listing |
| persisted election-status record | applied *after* reconstruction ([`lib.rs:1467`](gui/src-tauri/src/lib.rs:1467)) and can advance the lifecycle | **the cached value is the pre-status session; re-apply the persisted status to a clone on every hit.** Never cache the post-status session. |
| process-local intake fence / transport state | not durable session state | unchanged |

### L1 — verifier key

```
VerifierCacheKeyV1 { registry_commitment: RegistryCommitment, suite_id: &'static str, protocol_version: u16, verifier_epoch: u32 }
```

`registry_commitment` is derived from the registry snapshot by `canonical_commitment` ([`verifier/triptych_registry.rs:25`](crates/verifier/src/triptych_registry.rs:25)) and is exactly the value the verifier binds proofs against ([`triptych_verifier.rs:93-97`](crates/crypto/src/triptych_verifier.rs:93)). Reusing an L1 entry across two elections that share a registry is safe *because the proof statement itself carries the registry commitment and is checked against the verifier's on every `verify` call*.

## 16. Exact invalidation rules

| Event | Mechanism | Result |
|---|---|---|
| **New ballot accepted** (file import, inbox reconciliation) | a new revision is written → new head revision + new digest | key miss — automatic |
| **New ballot rejected** | still pushed to `packages` ([`session.rs:391`](crates/gui-core/src/session.rs:391)) → new revision | key miss — automatic |
| **Import of election artifacts** | creates no workspace ([`lib.rs:1331-1333`](gui/src-tauri/src/lib.rs:1331)) | nothing to invalidate |
| **Recovery / crash resume** | reads the head from disk; if the head moved, key miss | automatic |
| **Snapshot replacement / rollback / file swap** | digest of head changes, or the commit-marker check fails and `load_committed_history` errors before any cache lookup | miss or hard failure — **never a hit** |
| **Manifest / registry / candidate mutation** | those bytes are inside the revision payload → digest changes | automatic |
| **Election status change** (open/close/verify/finalize) | a revision is written by `mutate_session_transactionally` | automatic |
| **Finalization** | same | automatic |
| **Tally state mutation** | tally is derived from the ledger; no independent state | n/a |
| **Transport intake** | writes to the inbox, then `sync_private_intake` writes a revision only when something was newly accepted ([`lib.rs:1914-1918`](gui/src-tauri/src/lib.rs:1914)) | automatic; an inbox-only change with no acceptance correctly does **not** invalidate |
| **Arbitrary filesystem change under the workspace** | the key is computed **from freshly-read commit markers and revision digests on every lookup**, never from a remembered value | automatic |
| **Application restart** | memory-only cache; nothing survives | full re-verification, by design |
| **Protocol / suite version change** | in the key | automatic |
| **Verifier implementation change** | `verifier_epoch` in the key | manual bump — enforce with a test that fails when crypto-crate files change without an epoch bump |
| **Corruption detected** | `load_committed_history` returns `corrupt_workspace()` before any lookup; on a *failed replay*, **store nothing** | fail closed |
| **Organizer-authority marker added/removed** | not in the key — re-read every time | correct by construction |

**Non-negotiable ordering rule.** The key must be computed from **freshly read** commit markers and revision-file digests **on every single lookup**. The cache must never remember "workspace X is at revision 7" and skip the disk read — that would reintroduce exactly the TOCTOU the design is meant to avoid.

---

## 17. Concurrency / cache-stampede design

**Threats introduced by a cache, and the mitigation for each:**

| Risk | Mitigation |
|---|---|
| **Stampede** — ten UI invokes trigger ten simultaneous replays of the same workspace | Single-flight: an `inflight: Map<Key, Weak<Barrier>>` guarded by a short-lived mutex. The first caller inserts a barrier and performs the replay; subsequent callers with the same key clone the barrier, **release the map lock**, and await it. Exactly one Triptych replay per key. |
| **Lock held during cryptography** | **Never hold the cache mutex across a replay.** The sequence is: lock → look up / claim inflight → **unlock** → replay on a blocking worker → lock → insert → unlock. |
| **Deadlock** | The cache mutex must be a leaf: it may not be acquired while holding `AppState.session`, `AppState.voter`, or `preparation_slot`. Document the ordering next to `AppState` and pin it with a test in the style of the existing `preparation_slot` concurrency tests ([`lib.rs:4895-4910`](gui/src-tauri/src/lib.rs:4895)). |
| **TOCTOU between digest computation and load** | The digest is computed **from the payload bytes actually read** (`read_valid_revision_file` reads, hashes, and compares against the filename and the commit marker — [`workspace.rs:948-956`](crates/gui-core/src/workspace.rs:948)). The cached value must be keyed by *that* digest, not by one read separately. Write the API so the key can only be produced by the loader that returned the bytes. |
| **Mutation during verification** | The replay operates on `Vec<u8>` payloads already read into memory. A concurrent writer produces a new revision with a new digest; the completed replay is inserted under the *old* key, which is simply never looked up again. Safe. |
| **Stale read** | Impossible while the key is recomputed from disk each lookup (§16). |
| **Cache replacement / multiple elections open** | A small LRU (capacity ~4) bounds memory. Entries are `Arc`, so eviction never invalidates a session a command is currently using. |
| **Failed verification** | **Never insert.** A replay that errors removes the inflight entry and propagates the error to every waiter. There must be **no negative caching** — a corrupt-file error must be re-derived each time. |
| **Cancellation / shutdown** | Waiters await a barrier, not a task handle; if the worker panics, `spawn_blocking` returns `JoinError` and `run_blocking_command` already maps it to `GUI_COMMAND_TASK_FAILED` ([`lib.rs:240-244`](gui/src-tauri/src/lib.rs:240)). Waiters must observe the same failure, not hang. |
| **Duplicate proof verification within one replay** | Not applicable — each package is verified once per replay. |

---

## 18. Recommended worker/thread model

**Rule:** `async` alone is not enough. `tauri::async_runtime::spawn_blocking` moves work to a blocking thread pool and is correct for I/O and for short CPU bursts; a multi-minute Triptych replay would monopolise a pool thread. Recommendation by cost class:

| Class | Mechanism | Applies to |
|---|---|---|
| Demonstrably trivial (in-memory reads, microseconds) | **remain synchronous** | `election_summary`, `participation_summary`, `active_workspace_ids`, `preview_draft`, selection getters/setters, credential-status getters |
| Small file I/O (single small file, keyring) | `async` + `spawn_blocking` | `trusted_ootle_deployment_status`, `inspect_anchor_*`, `walletd_credential_status`, `list_saved_voter_credentials`, `voter_tor_status`, `export_voter_transport_bundle` |
| Bounded but size-scaling I/O + hashing | `async` + `spawn_blocking` | all `set_draft_*`, `import_registry_to_draft`, `open_voting`, `freeze_election`, `export_election_artifacts`, `export_prepared_voter_ballot`, `compute_governance_document_digest`, `match_governance_document`, `voter_confirmation`, `inspect_template_wasm`, `configure_managed_tor_test`, `write_archive_with_governance_document` |
| Metadata listing (I/O only, no crypto) | `async` + `spawn_blocking` | `list_election_workspaces`, `delete_election_workspace` — **after** §13 removes the replay |
| One-ballot verification (≤ 300 ms) | `async` + `spawn_blocking` | `intake_ballot_package`, `sync_private_intake` |
| **Full election replay (seconds to minutes)** | **dedicated single CPU worker thread, one job at a time, with progress events and cancellation** — not the shared blocking pool | `resume_election_workspace`, and any future explicit "re-verify this workspace" action |
| Full archive verification | keep on `spawn_blocking` today; migrate to the dedicated CPU worker if archives grow | `verify_archive` and friends |
| Network | `async` + `spawn_blocking` (already correct) | walletd, indexer, Tor |

**Why a dedicated worker rather than a pool for replay:** the work is single-job-at-a-time by nature (one election is being opened), it must be cancellable when the user navigates away, and it must emit progress (`ballots_verified / total`) so the UI can show a determinate bar instead of "Resuming and verifying election…" ([`Home.tsx:400-402`](gui/src/screens/Home.tsx:400)). A bounded pool would let several replays run concurrently and starve the machine.

---

## 19. Instrumentation plan

**Purpose: prove the frequency claims before optimising, and prove they are gone afterwards.**

Design (behind a `dev-instrumentation` cargo feature, off by default in release):

```
struct ReconstructionMetricsV1 {   // all AtomicU64
    workspace_list_calls, workspace_summarize_calls,
    from_durable_snapshot_calls, historical_ballots_replayed,
    triptych_verify_calls, triptych_verify_batch_calls,
    verifier_builds, registry_keys_decompressed,
    revision_files_decoded, revision_bytes_decoded,
    session_cache_hits, session_cache_misses,
    session_cache_invalidations, session_cache_inflight_joins,
    reconstruction_duration_micros_total, reconstruction_duration_micros_max,
    proof_verification_duration_micros_total,
}
```

- **Placement:** counters increment at [`workspace.rs:262`](crates/gui-core/src/workspace.rs:262), [`:1055`](crates/gui-core/src/workspace.rs:1055), [`session.rs:109`](crates/gui-core/src/session.rs:109), [`session.rs:374`](crates/gui-core/src/session.rs:374), [`triptych_verifier.rs:82`](crates/crypto/src/triptych_verifier.rs:82), [`workspace.rs:934`](crates/gui-core/src/workspace.rs:934), and the cache entry points.
- **Exposure:** one new dev-only Tauri command `reconstruction_metrics` returning the snapshot, rendered on the Settings screen when `settings.devDiagnostics` is on (the flag already exists — [`AppState.tsx:33`](gui/src/state/AppState.tsx:33)). Plus a one-line `eprintln!` summary on process exit under the feature.
- **Privacy constraints (mandatory).** Counters and durations **only**. Never log: nullifiers, linking tags, proof bytes, payloads, package digests, credential material, passphrases, member indices, registry keys, voter public keys, election ids, manifest hashes, workspace ids, or file paths. Ballot counts are already disclosed through `participation_summary` under its existing visibility policy, so aggregate counts add no new disclosure — but a *per-workspace* breakdown would leak cross-election correlation and must not be produced. The existing test `workspace_revision_is_versioned_and_has_no_secret_type_markers` ([`tests/workspace.rs:1743`](crates/gui-core/tests/workspace.rs:1743)) and the serializable-struct scan at [`lib.rs:4148-4160`](gui/src-tauri/src/lib.rs:4148) establish the house style; the metrics struct must pass the same scan.
- **First use:** run the app against the user's real app-data with instrumentation on, and record the actual `(workspaces, ballots_replayed, duration)` at startup. That converts §2's consistency band into a measurement.

---

## 20. Regression test plan

Every existing protocol and security test must keep passing unchanged — in particular `crates/gui-core/tests/workspace.rs` (all 40 tests, especially the hostile-resume family at lines 1117–1495), `crates/gui-core/tests/private_intake_inbox.rs`, `crates/verifier/`, `crates/crypto/`, and `crates/archive/`.

**New tests, grouped by claim:**

*Cost / no-replay claims (need the §19 counters):*
1. Startup with **no** elections → `from_durable_snapshot_calls == 0`.
2. Startup with a **2-ballot** election → `historical_ballots_replayed == 0` (listing must not replay).
3. Startup with **50 accepted ballots** → `historical_ballots_replayed == 0`; listing wall time bounded.
4. `list_election_workspaces` twice → `triptych_verify_calls` unchanged between calls.
5. Navigate Home → Manage → Vote → Home → `triptych_verify_calls` unchanged (frontend test asserting no `list_election_workspaces` invoke on navigation).
6. Any metadata refresh → `from_durable_snapshot_calls` unchanged.
7. `runLifecycle` for each of open/close/verify/finalize → **no** workspace listing replay.

*Correct verification claims:*
8. Opening an election performs exactly **one** replay of exactly `packages.len()` proofs — asserts R-2 is fixed.
9. Re-opening the **same unchanged** workspace → `session_cache_hits == 1`, `historical_ballots_replayed` unchanged.
10. Accepting a new ballot then re-opening → cache **miss**, replay count equals the new `packages.len()`.
11. Rejecting a ballot then re-opening → cache **miss** (rejected packages are stored too).
12. **Tampered snapshot cannot reuse a verification:** replay, then rewrite the head revision file's bytes and its commit marker consistently → key differs → miss → and the tamper must still be caught by the existing chain checks.
13. **Tampered manifest cannot reuse a verification:** mutate `manifest_bytes` inside the head revision → digest changes → miss.
14. **Rollback cannot reuse a verification:** delete the head revision so the workspace reverts to revision k-1 → the key differs from the cached one → miss; and `deleted_committed_newest_revision_fails_closed_without_rollback` still fails closed.
15. **Cross-election reuse impossible:** two workspaces whose bodies are byte-identical except for `workspace_id` → two distinct keys, two replays.
16. **Import forces validation:** a ballot package arriving by file import or inbox is always fully verified, cache or no cache.
17. **Failed verification is never cached:** inject a corrupt package → replay fails → `session_cache_hits == 0` on the retry, and the same error is returned.
18. **Verifier-epoch bump invalidates:** bumping `VERIFIED_SESSION_CACHE_EPOCH` makes a previously cached key a miss.
19. **No negative caching:** two consecutive failing loads both perform real work.

*Concurrency claims:*
20. Ten concurrent `resume_election_workspace` calls for the same workspace → `from_durable_snapshot_calls == 1`, `session_cache_inflight_joins == 9`.
21. Concurrent resume of **different** workspaces → both complete; no deadlock; assert the cache mutex is acquirable from a third thread during a replay (mirroring the existing `preparation_slot` invariant test at [`lib.rs:4895`](gui/src-tauri/src/lib.rs:4895)).
22. A replay that panics releases the inflight slot and fails all waiters.

*Responsiveness claims:*
23. **GUI event thread stays responsive:** a shell-level test asserting that no registered command whose matrix row is SEVERE/HIGH is declared without `async` — implementable as a source-scanning test in the style of the existing `AppState`/serializable-struct scans at [`lib.rs:4141-4160`](gui/src-tauri/src/lib.rs:4141).
24. **4100-voter architecture:** with a synthetic large workspace, assert that an ordinary UI action (listing, lifecycle refresh) performs **zero** proof verifications — the count assertion, not a wall-clock assertion, so it is deterministic in CI.
25. **Anchor operations receive authoritative verified state:** `write_live_anchor_config_from_verified_archive` must still derive from a real archive verification; assert it refuses a directory whose archive verification fails, cache or no cache.
26. **Voter-only workflows do not initialise organizer-only functionality:** assert that a voter-authority session performs no walletd/indexer/Ootle initialisation and no organizer workspace write (extends the existing organizer-authority tests).

---

## 21. Files and functions a later implementation pass would touch

**Nothing below was modified in this pass.**

| File | Function / region | Change |
|---|---|---|
| [`crates/gui-core/src/workspace.rs`](crates/gui-core/src/workspace.rs) | `summarize_workspace` :1055 | add a metadata-only sibling; keep the verifying path for resume |
| | `list_election_workspaces_v1` :262 | call the metadata-only summariser |
| | `resume_election_workspace_v1` :320 | build the session **once**; derive the summary from it |
| | `draft_superseding_session_v1` :654 | avoid the extra successor history load |
| | `load_committed_history` :754 | add a head-only fast path; keep the full walk as an explicit integrity operation |
| | `write_workspace_revision` :684 | use the head-only path instead of a full walk |
| [`crates/gui-core/src/session.rs`](crates/gui-core/src/session.rs) | `from_durable_snapshot` :109 | accept an injected cached verifier; optionally batch-verify |
| [`crates/crypto/src/triptych_verifier.rs`](crates/crypto/src/triptych_verifier.rs) | `TariTriptychPrototypeVerifierV1` :39, `verify` :82 | hoist the per-election Triptych constants into the struct (built once in `new`) |
| [`crates/crypto/src/triptych_prototype.rs`](crates/crypto/src/triptych_prototype.rs) | `build_triptych_statement_v1` :29 | split into "build per-election context" + "bind this ballot's linking tag" |
| **new** `crates/gui-core/src/verified_session_cache.rs` | — | `VerifiedElectionSessionCacheV1`, `VerifiedSessionKeyV1`, single-flight |
| **new** `crates/gui-core/src/verified_session.rs` | — | `VerifiedElectionSessionV1` provenance wrapper (§22) |
| [`crates/gui-core/src/private_intake_inbox.rs`](crates/gui-core/src/private_intake_inbox.rs) | `ingest_private_intake_inbox_into_session_v1` :237 | skip files whose digest is already decided |
| [`crates/gui-core/src/session.rs`](crates/gui-core/src/session.rs) | `reconcile_accepted_package_bytes_from_inbox` :317 | replace the linear transcript scan with a digest set |
| [`gui/src-tauri/src/lib.rs`](gui/src-tauri/src/lib.rs) | `list_election_workspaces` :1406, `delete_election_workspace` :1527, `open_voting` :1564, `intake_ballot_package` :1787, `sync_private_intake` :1865, `freeze_election` :2609, all `set_draft_*` :2505-2745, `write_archive_with_governance_document` :3481, `configure_managed_tor_test`, `voter_confirmation`, `compute_governance_document_digest`, `match_governance_document`, `export_prepared_voter_ballot`, `inspect_*` | convert to `async` + `run_blocking_command` |
| | `AppState` :367 | add the cache field + lock-ordering documentation |
| | `resume_election_workspace` :1449 | route through the dedicated CPU worker; emit progress |
| [`gui/src/state/AppState.tsx`](gui/src/state/AppState.tsx) | `runLifecycle` :400 | stop calling `refreshWorkspaces()` after lifecycle actions; update the one active row locally |
| [`gui/src/api/types.ts`](gui/src/api/types.ts) | `GuiElectionWorkspaceSummaryV1` | rename `accepted_ballot_count` → `stored_ballot_count`; label it as unverified |
| [`gui/src/screens/Home.tsx`](gui/src/screens/Home.tsx) | workspace table | relabel the count column; add determinate resume progress |
| [`gui/src/screens/ManageElection.tsx`](gui/src/screens/ManageElection.tsx) | :677-684 | back off the 4 s auto-sync when the inbox is unchanged |

---

## 22. Separating the three concepts (brief §9), risks, and unresolved questions

### 22.1 Does the current implementation conflate A / B / C?

**Yes, in one specific and consequential place, and no elsewhere.**

- **Conflation (confirmed).** `summarize_workspace` builds **(C) a fully verified authoritative session** in order to produce **(A) cheap display metadata**, then discards C. That is the single defect. The cost is real; the *trust* direction is conservative (it over-verifies), which is why it never produced a security bug — only a hang.
- **Correct separation already present (worth preserving).** `SessionAuthorityV1` ([`lib.rs:268-273`](gui/src-tauri/src/lib.rs:268)) deliberately keeps *role* outside `GuiElectionSessionV1`, with the rationale "a session is reconstructible by anyone from public artifacts, so the session object alone must never imply ballot-office authority." `VerifiedApprovalBallotV1` ([`proof_verification.rs:16-19`](crates/verifier/src/proof_verification.rs:16)) has **no public constructor**, so a caller cannot pair a verified proof with a different payload. `VerifiedProofV1` and `VerifiedNullifier` follow the same pattern. **The codebase already knows how to do this** — the technique simply was not applied at the workspace layer.

### 22.2 Recommended types (design only)

```
// (A) display metadata — cheap, explicitly untrusted
struct GuiElectionWorkspaceMetadataV1 { … stored_ballot_count: usize … }   // NOT accepted_ballot_count

// (B) loaded durable state — decoded, chain-checked, NOT proof-verified
struct LoadedDurableWorkspaceV1 { record: DurableElectionWorkspaceV1, head: HeadRevisionIdentityV1 }

// (C) verified authoritative state — no public constructor
struct VerifiedElectionSessionV1 {
    session: GuiElectionSessionV1,
    provenance: VerificationProvenanceV1 { key: VerifiedSessionKeyV1, verified_at: Instant, ballots_verified: usize },
}
impl VerifiedElectionSessionV1 { /* constructible ONLY by the replay path */ }
```

Every command that today takes `&GuiElectionSessionV1` for an authoritative operation — `current_tally`, `write_archive*`, `finalize_election`, `write_live_anchor_config_*` — should take `&VerifiedElectionSessionV1`. Making the constructor private to the replay module makes "use display metadata where verified state is required" a **compile error** rather than a review question. `HeadRevisionIdentityV1` should likewise be constructible only by the loader that read and hashed the bytes, which is what closes the TOCTOU in §17.

### 22.3 Security analysis of the proposed optimisations

| Question from the brief | Answer |
|---|---|
| Could tampered durable data bypass verification? | **No.** The cache key is recomputed from freshly-read commit markers and revision digests on every lookup; tampering changes the digest, producing a miss, and the existing chain checks still fail closed. |
| Could a maliciously modified snapshot receive a stale "verified" result? | **No** — same mechanism. The head digest hash-chains the entire history. |
| Could imported ballot packages bypass proof verification? | **No.** Import and inbox reconciliation are unconditional first-verification paths; the cache is consulted only when loading a workspace from disk, never when admitting a package. |
| Could a manifest change preserve a valid cache entry? | **No.** `manifest_bytes` is inside the revision payload, so the head digest changes. |
| Could a previously verified ballot be modified on disk? | It can be modified, but not *used*: any change to `packages` changes the revision payload and therefore the head digest. |
| Could file replacement or rollback cause cache confusion? | **No.** Rollback lowers the head revision and/or changes the digest → miss. The existing rollback tests still apply. |
| Could one election's verification be reused for another? | **No.** `workspace_id` + head digest + registry commitment are all in the keys, and `read_valid_revision_file` already rejects a revision carrying a foreign workspace id. |
| Could an attacker manipulate metadata while preserving cache identity? | Only sidecar markers are outside the digest — and those are **re-read on every hit**, never cached. |
| Could restart semantics create trust in unverified data? | **No** — the cache is memory-only. A restart re-verifies from scratch. This is the decisive argument against persistence. |
| Does the metadata-only listing weaken anything? | Only if a caller treats listing output as election state. The type split in §22.2 makes that a compile error; the count is renamed to remove the false authority. |

### 22.4 Risks and unresolved questions

1. **`MAX_REGISTRY_MEMBERS = 4_096` < 4 100.** The stated target electorate is not representable by the current protocol limits ([`limits.rs:15`](crates/protocol/src/limits.rs:15)). This needs a product decision before any 4100-voter work.
2. **The durable-format quadratic (F-3) is the real 4100-voter blocker** and is *not* solved by the cache. It needs its own slice (out-of-line package storage, or a snapshot+delta revision format). Both are durable-format changes, explicitly forbidden in this pass.
3. **Batch verification changes failure attribution.** Adopting it requires a blame variant so per-ballot decisions and the transcript stay byte-identical. Needs its own careful slice with differential tests against the current one-at-a-time path.
4. **`accepted_ballot_count` semantics.** Option A (rename to a stored-package count) is honest and needs no format change, but it *does* change what the Home screen shows. A product decision is required; if the true accepted count must be shown before opening the election, only Option B satisfies that, and Option B is a durable-format change.
5. **The 4-second auto-sync interval** may be too aggressive at scale even after the sync command moves off-thread — worth revisiting once instrumentation exists.
6. **Measurement scope.** All timings are from the vendored Triptych crate through its public API on one Windows machine. They model `TariTriptychPrototypeVerifierV1::verify` faithfully but exclude CBOR decode, manifest hashing, and statement reconstruction (all small relative to the MSM). They were **not** obtained by running the shipping application, because doing so would have required building the Tauri shell and using real election data. Instrumenting the real app (§19) remains the authoritative next measurement.
7. **`write_archive_with_governance_document` has no frontend caller** (NOT FOUND). Either wire it up or remove it; leaving a synchronous whole-archive writer registered is an avoidable hazard.
8. **Not verified in this pass:** whether Tauri 2's `spawn_blocking` pool size is adequate under the 4 s + 5 s + 20 s timer load once more commands migrate onto it. Worth checking before the migration lands.

---

## 23. Recommended implementation sequence

Ordered by *risk-adjusted value*: each step is independently shippable, independently testable, and does not depend on the next.

**Step 0 — Instrumentation (§19).** Counters behind a dev feature. No behaviour change. Establishes the baseline and makes every later claim falsifiable. **Do this first.**

**Step 1 — Stop the bleeding, no crypto changes.** Two edits, both trivially safe:
   - (a) make `list_election_workspaces` and `delete_election_workspace` `async` + `run_blocking_command` — the hang becomes a slow spinner instead of a Windows "Not Responding";
   - (b) remove `refreshWorkspaces()` from `runLifecycle` in [`AppState.tsx:426`](gui/src/state/AppState.tsx:426) and update the single active row locally. This alone eliminates **4 of the 15** repeated-crypto triggers.

**Step 2 — Metadata-only listing (§13).** The single highest-value change: removes replay from the listing path entirely, which kills **11 of the 15** repeated triggers. Requires the type split (§22.2) so the count cannot be mistaken for authoritative.

**Step 3 — Collapse the double replay on resume (F-5).** One-line-shaped change at [`workspace.rs:346`](crates/gui-core/src/workspace.rs:346)/[`:353`](crates/gui-core/src/workspace.rs:353); halves resume cost.

**Step 4 — Hoist the per-election Triptych constants (F-4).** Contained entirely inside `crates/crypto`; measurable 33–56 % reduction in per-ballot cost; provable by existing crypto tests plus a differential test that the verdict for every fixture is unchanged.

**Step 5 — Head-only revision load for the write path (F-3, partial).** Use the authenticated head instead of re-walking the chain in `write_workspace_revision`, keeping the full walk available as an explicit integrity operation. Removes the worst amplification without touching the durable format.

**Step 6 — Verified-session cache (§14–17).** Memory-only, single-flight, LRU(4). By this point the listing no longer needs it, so its job is narrowed to "opening the same election twice is free" — a much smaller, much safer surface than if it had been built first.

**Step 7 — Convert the remaining sync commands** per the §18 table, in risk order.

**Step 8 — Dedicated CPU replay worker with progress and cancellation** for `resume_election_workspace`.

**Step 9 (separate initiative, not part of this work) — Durable-format redesign** for the O(revisions²·registry) problem, and a decision on `MAX_REGISTRY_MEMBERS` vs. the 4100-voter target.

Steps 0–3 are low-risk and would, together, remove every confirmed main-thread hang path reachable from ordinary UI use. Steps 4–6 are the performance work. Step 9 is the one that decides whether a 4100-voter election is possible at all.
