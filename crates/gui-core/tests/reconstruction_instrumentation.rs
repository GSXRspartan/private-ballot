//! Performance-remediation Slice 1 regression tests.
//!
//! These prove — through the development reconstruction counters — the two
//! central claims of the slice:
//!
//!   1. Listing workspaces performs ZERO durable session reconstruction and
//!      ZERO Triptych proof verification, however many ballots are stored.
//!   2. Opening/resuming an election still performs the full required
//!      verification (one Triptych verify per stored package, exactly once —
//!      the audit's F-5 double-replay is gone).
//!
//! Fixture note: the shared test registry has three voters (`SECRET_SCALARS`),
//! and Triptych proving uses `OsRng`, so distinct *accepted* ballots are capped
//! at three, but any number of distinct *stored* packages can be produced by
//! re-submitting a used voter (rejected as a duplicate nullifier, still stored
//! and still replayed on resume). The zero-replay-on-listing invariant is
//! independent of the stored count, so the count only needs to be > 0 to make
//! the regression bite; a larger STORED count exercises the replay loop harder.
//!
//! The counters are process-global, so the tests in this dedicated binary
//! serialize on a shared lock and measure a freshly reset baseline.

mod common;

use std::sync::Mutex;

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, LoadedElectionWorkspaceV1, ensure_election_workspaces_directory_v1,
    instrumentation, list_election_workspaces_v1, resume_election_workspace_v1,
    workspace_id_for_session_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

/// Serializes the counting tests within this binary so a freshly reset counter
/// baseline is never perturbed by a sibling test running in parallel.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, msg: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{msg}: {error}"),
    }
}

/// Builds an OPEN session workspace and returns `(TestDir, root, id, stored)`.
///
/// It intakes `accepted` distinct accepted ballots (0..=3) and then
/// `duplicates` further packages from voter 0 — each rejected as a duplicate
/// nullifier but durably stored — so the total stored-package count is
/// `accepted + duplicates`.
fn build_workspace(
    label: &str,
    accepted: usize,
    duplicates: usize,
) -> (TestDir, std::path::PathBuf, String, usize) {
    assert!(
        accepted <= 3,
        "the shared fixture registry has three voters"
    );
    let dir = TestDir::new(label);
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    for index in 0..accepted {
        let package = triptych_package_bytes(index, &[b"candidate-a"]);
        assert!(
            ok(session.intake_ballot(&package), "intake accepted").accepted,
            "fixture ballot {index} must be accepted",
        );
    }
    for _ in 0..duplicates {
        // Voter 0 again: a fresh proof (OsRng) but the same nullifier, so it is
        // rejected as a duplicate yet still stored in the durable package list.
        let package = triptych_package_bytes(0, &[b"candidate-b"]);
        let result = ok(session.intake_ballot(&package), "intake duplicate");
        assert!(!result.accepted, "duplicate must be rejected");
    }
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write session revision",
    );
    (dir, root, workspace_id, accepted + duplicates)
}

#[test]
fn listing_a_workspace_with_no_ballots_replays_nothing() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, _id, stored) = build_workspace("instr-empty", 0, 0);

    instrumentation::reset();
    let summaries = ok(list_election_workspaces_v1(&root), "list");
    let counters = instrumentation::snapshot();

    assert_eq!(summaries.len(), 1, "one workspace listed");
    assert_eq!(counters.workspace_list_calls, 1);
    assert_eq!(
        counters.from_durable_snapshot_calls, 0,
        "listing must not reconstruct a durable session",
    );
    assert_eq!(counters.historical_ballots_replayed, 0);
    assert_eq!(
        counters.triptych_verify_calls, 0,
        "listing must perform zero Triptych verification",
    );
    assert_eq!(
        counters.triptych_adapter_verify_calls, 0,
        "listing must make zero calls to the Triptych verifier adapter",
    );
    assert_eq!(summaries[0].stored_ballot_count, stored);
}

#[test]
fn listing_a_workspace_with_many_stored_ballots_replays_nothing() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    // 3 accepted + 12 duplicates = 15 durably stored ballot packages.
    let (_dir, root, _id, stored) = build_workspace("instr-many", 3, 12);
    assert_eq!(stored, 15);

    instrumentation::reset();
    let summaries = ok(list_election_workspaces_v1(&root), "list");
    let counters = instrumentation::snapshot();

    assert_eq!(summaries.len(), 1);
    assert_eq!(
        counters.from_durable_snapshot_calls, 0,
        "listing many stored ballots still constructs no session",
    );
    assert_eq!(
        counters.historical_ballots_replayed, 0,
        "listing many stored ballots replays zero ballots",
    );
    assert_eq!(
        counters.triptych_verify_calls, 0,
        "listing many stored ballots performs zero Triptych verification",
    );
    assert_eq!(
        counters.triptych_adapter_verify_calls, 0,
        "listing many stored ballots makes zero verifier-adapter calls",
    );
    // The display-only stored count is available without any replay.
    assert_eq!(summaries[0].stored_ballot_count, 15);
}

#[test]
fn repeated_startup_style_discovery_replays_no_ballots() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, _id, _stored) = build_workspace("instr-startup", 3, 5);

    instrumentation::reset();
    // Startup + a redundant refresh: two list passes back to back.
    let _ = ok(list_election_workspaces_v1(&root), "list 1");
    let _ = ok(list_election_workspaces_v1(&root), "list 2");
    let counters = instrumentation::snapshot();

    assert_eq!(counters.workspace_list_calls, 2);
    assert_eq!(
        counters.from_durable_snapshot_calls, 0,
        "repeated discovery reconstructs nothing",
    );
    assert_eq!(counters.historical_ballots_replayed, 0);
    assert_eq!(counters.triptych_verify_calls, 0);
    assert_eq!(counters.triptych_adapter_verify_calls, 0);
}

#[test]
fn resuming_an_election_replays_every_stored_ballot_exactly_once() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    // 3 accepted + 2 duplicates = 5 stored packages, all replayed on resume.
    let (_dir, root, workspace_id, stored) = build_workspace("instr-resume", 3, 2);

    instrumentation::reset();
    let loaded = ok(resume_election_workspace_v1(&root, &workspace_id), "resume");
    let counters = instrumentation::snapshot();

    match loaded {
        LoadedElectionWorkspaceV1::Session { session, .. } => {
            assert_eq!(
                session.accepted_count(),
                3,
                "three unique nullifiers accepted"
            );
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    }

    // Exactly ONE reconstruction: the audit's F-5 double-replay (summary +
    // load) is gone now that the summary is metadata-only.
    assert_eq!(
        counters.from_durable_snapshot_calls, 1,
        "resume reconstructs the durable session exactly once",
    );
    assert_eq!(
        counters.historical_ballots_replayed, stored as u64,
        "resume replays every stored package",
    );
    assert_eq!(
        counters.triptych_verify_calls, stored as u64,
        "resume verifies every stored package's proof exactly once",
    );
    // The adapter boundary independently confirms the same number of real
    // verifier calls (all fixture proofs are valid, so both counts agree).
    assert_eq!(
        counters.triptych_adapter_verify_calls, stored as u64,
        "resume makes exactly one verifier-adapter call per stored package",
    );
}

#[test]
fn new_ballot_intake_still_verifies_its_proof() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let mut session: GuiElectionSessionV1 = open_session();

    instrumentation::reset();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    assert!(ok(session.intake_ballot(&package), "intake").accepted);
    let counters = instrumentation::snapshot();

    assert_eq!(
        counters.triptych_verify_calls, 1,
        "a newly intaken ballot must still be proof-verified exactly once",
    );
    assert_eq!(
        counters.triptych_adapter_verify_calls, 1,
        "a newly intaken ballot reaches the verifier adapter exactly once",
    );
}
