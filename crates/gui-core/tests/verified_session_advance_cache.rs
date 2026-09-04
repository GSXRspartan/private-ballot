//! Slice 4E: incremental verified-session advancement — cache integration.
//!
//! These prove the runtime behavior on top of the equivalence invariant
//! (`tests/verified_session_advancement.rs`): a successful advance followed by
//! an immediate resume of the new head is a cache hit with ZERO historical
//! replay, and every write→trust safety check (revision/body confirmation,
//! external drift) fails closed to cold reconstruction.
//!
//! Counters are process-global; this binary serializes counter windows.

mod common;

use std::sync::Mutex;

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, LoadedElectionWorkspaceV1, VerifiedElectionSessionCacheV1,
    advance_verified_session_after_commit_v1, ensure_election_workspaces_directory_v1,
    instrumentation, resume_election_workspace_with_verified_session_cache_v1,
    workspace_id_for_session_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{message}: {error}"),
    }
}

fn resume(
    root: &std::path::Path,
    workspace_id: &str,
    cache: &VerifiedElectionSessionCacheV1,
) -> GuiElectionSessionV1 {
    match ok(
        resume_election_workspace_with_verified_session_cache_v1(root, workspace_id, cache),
        "resume",
    ) {
        LoadedElectionWorkspaceV1::Session { session, .. } => session,
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    }
}

/// Applies a mutation, commits revision N+1, and advances the cache.
fn mutate_write_advance(
    root: &std::path::Path,
    workspace_id: &str,
    session: &mut GuiElectionSessionV1,
    cache: &VerifiedElectionSessionCacheV1,
    package: &[u8],
) -> bool {
    let _ = session.intake_ballot(package);
    let new_revision = ok(
        write_session_workspace_revision_v1(root, workspace_id, session),
        "write revision",
    );
    ok(
        advance_verified_session_after_commit_v1(root, workspace_id, new_revision, session, cache),
        "advance",
    )
}

#[test]
fn advance_then_immediate_resume_has_zero_historical_replay() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("advance-zero-replay");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let cache = VerifiedElectionSessionCacheV1::default();

    // Genesis: one accepted ballot committed as revision 1.
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write rev1",
    );

    // First resume: a cold miss that reconstructs and replays.
    let _ = resume(&root, &workspace_id, &cache);

    // Mutate + commit revision 2 + advance the cache.
    instrumentation::reset();
    let advanced = mutate_write_advance(
        &root,
        &workspace_id,
        &mut session,
        &cache,
        &triptych_package_bytes(1, &[b"candidate-b"]),
    );
    assert!(advanced, "the advance is confirmed and installed");

    // Immediate resume of the new head: a cache HIT with zero replay.
    let before = instrumentation::snapshot();
    let resumed = resume(&root, &workspace_id, &cache);
    let after = instrumentation::snapshot();
    assert_eq!(
        after.from_durable_snapshot_calls - before.from_durable_snapshot_calls,
        0,
        "an advanced resume reconstructs nothing",
    );
    assert_eq!(
        after.historical_ballots_replayed - before.historical_ballots_replayed,
        0,
        "an advanced resume replays no historical ballot",
    );
    assert_eq!(
        after.triptych_adapter_verify_calls - before.triptych_adapter_verify_calls,
        0,
        "an advanced resume performs zero Triptych verification",
    );
    assert_eq!(
        after.verified_session_cache_hits - before.verified_session_cache_hits,
        1,
        "the advanced head is served from the cache",
    );

    // Authoritative equivalence: the resumed (advanced) session equals a fresh
    // reconstruction of the committed head.
    let snapshot = ok(resumed.to_durable_snapshot(), "resumed snapshot");
    let fresh = ok(
        GuiElectionSessionV1::from_durable_snapshot(snapshot),
        "fresh reconstruct",
    );
    assert_eq!(resumed.accepted_count(), fresh.accepted_count());
    assert!(resumed.transcript() == fresh.transcript());
    assert_eq!(resumed.lifecycle_state(), fresh.lifecycle_state());
}

#[test]
fn sequential_advances_have_zero_replay_between_them() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("advance-sequential");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let cache = VerifiedElectionSessionCacheV1::default();

    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write genesis",
    );
    let _ = resume(&root, &workspace_id, &cache); // warm the first head

    let packages = [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-c"]), // duplicate
        triptych_package_bytes(2, &[b"candidate-c"]),
    ];
    for package in &packages {
        assert!(mutate_write_advance(
            &root,
            &workspace_id,
            &mut session,
            &cache,
            package
        ));
        instrumentation::reset();
        let _ = resume(&root, &workspace_id, &cache);
        let after = instrumentation::snapshot();
        assert_eq!(
            after.historical_ballots_replayed, 0,
            "each advanced resume in the chain replays nothing",
        );
        assert_eq!(after.from_durable_snapshot_calls, 0);
        assert_eq!(after.verified_session_cache_hits, 1);
    }
}

#[test]
fn revision_drift_refuses_to_advance_and_falls_back() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("advance-revision-drift");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let cache = VerifiedElectionSessionCacheV1::default();

    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write genesis",
    );
    let _ = resume(&root, &workspace_id, &cache);

    // Commit revision 2 but claim a WRONG expected revision to the advance.
    let _ = session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]));
    let real_revision = ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write rev2",
    );
    instrumentation::reset();
    let advanced = ok(
        advance_verified_session_after_commit_v1(
            &root,
            &workspace_id,
            real_revision + 5, // wrong expected head revision
            &session,
            &cache,
        ),
        "advance with wrong revision",
    );
    let counters = instrumentation::snapshot();
    assert!(!advanced, "a revision mismatch refuses to advance");
    assert_eq!(counters.verified_session_cache_advances, 0);
    assert!(counters.verified_session_cache_advance_identity_drift >= 1);
    assert!(counters.verified_session_cache_advance_fallback_replays >= 1);

    // The cache was invalidated, so the next resume is a cold reconstruction.
    instrumentation::reset();
    let _ = resume(&root, &workspace_id, &cache);
    let after = instrumentation::snapshot();
    assert_eq!(
        after.from_durable_snapshot_calls, 1,
        "fallback forces cold replay"
    );
}

#[test]
fn external_head_change_after_write_is_not_advanced() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("advance-external-drift");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let cache = VerifiedElectionSessionCacheV1::default();

    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write genesis",
    );

    // Our mutation commits revision 2 ...
    let mut ours = session.transactional_clone();
    let _ = ours.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]));
    let our_revision = ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &ours),
        "write our rev2",
    );

    // ... but before we advance, a DIFFERENT committed head is written (rev 3).
    let _ = session.intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]));
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "external rev3",
    );

    instrumentation::reset();
    let advanced = ok(
        advance_verified_session_after_commit_v1(&root, &workspace_id, our_revision, &ours, &cache),
        "advance under external drift",
    );
    let counters = instrumentation::snapshot();
    assert!(!advanced, "an external head change is never advanced over");
    assert_eq!(counters.verified_session_cache_advances, 0);
    assert!(counters.verified_session_cache_advance_identity_drift >= 1);
}
