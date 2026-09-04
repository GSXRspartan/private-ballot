//! Slice 2 verified-session cache regression tests.
//!
//! The counters are process-global, so this binary serializes tests that reset
//! them. Every successful cache entry is created through the durable replay
//! path; no test manufactures a trusted session directly.

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use tari_cc_private_ballot_gui_core::{
    GuiCoreError, GuiElectionSessionV1, GuiErrorCategory, LoadedElectionWorkspaceV1,
    VerifiedElectionSessionCacheV1, VerifiedSessionKeyV1, ensure_election_workspaces_directory_v1,
    instrumentation, resume_election_workspace_with_verified_session_cache_v1,
    workspace_id_for_session_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, open_session_with_revision, triptych_package_bytes};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{message}: {error}"),
    }
}

fn write_workspace(root: &std::path::Path, session: &GuiElectionSessionV1) -> String {
    let workspace_id = workspace_id_for_session_v1(session);
    ok(
        write_session_workspace_revision_v1(root, &workspace_id, session),
        "write session workspace",
    );
    workspace_id
}

fn build_workspace(
    label: &str,
    accepted: usize,
    duplicates: usize,
) -> (
    TestDir,
    std::path::PathBuf,
    String,
    GuiElectionSessionV1,
    usize,
) {
    assert!(accepted <= 3, "fixture registry has three voters");
    let dir = TestDir::new(label);
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    for index in 0..accepted {
        assert!(
            ok(
                session.intake_ballot(&triptych_package_bytes(index, &[b"candidate-a"])),
                "accepted fixture ballot",
            )
            .accepted
        );
    }
    for _ in 0..duplicates {
        assert!(
            !ok(
                session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-b"])),
                "duplicate fixture ballot",
            )
            .accepted
        );
    }
    let workspace_id = write_workspace(&root, &session);
    (dir, root, workspace_id, session, accepted + duplicates)
}

fn resumed_session(
    root: &std::path::Path,
    workspace_id: &str,
    cache: &VerifiedElectionSessionCacheV1,
) -> GuiElectionSessionV1 {
    match ok(
        resume_election_workspace_with_verified_session_cache_v1(root, workspace_id, cache),
        "cached resume",
    ) {
        LoadedElectionWorkspaceV1::Session { session, .. } => session,
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    }
}

#[test]
fn first_and_second_unchanged_resume_have_the_required_replay_profile() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, workspace_id, _session, stored) = build_workspace("cache-first-second", 3, 2);
    let cache = VerifiedElectionSessionCacheV1::default();

    instrumentation::reset();
    let first = resumed_session(&root, &workspace_id, &cache);
    let first_counts = instrumentation::snapshot();
    assert_eq!(first.accepted_count(), 3);
    assert_eq!(first_counts.verified_session_cache_misses, 1);
    assert_eq!(first_counts.verified_session_cache_insertions, 1);
    assert_eq!(first_counts.from_durable_snapshot_calls, 1);
    assert_eq!(first_counts.historical_ballots_replayed, stored as u64);
    assert_eq!(first_counts.triptych_adapter_verify_calls, stored as u64);

    instrumentation::reset();
    let second = resumed_session(&root, &workspace_id, &cache);
    let second_counts = instrumentation::snapshot();
    assert_eq!(second.accepted_count(), 3);
    assert_eq!(second_counts.verified_session_cache_hits, 1);
    assert_eq!(second_counts.from_durable_snapshot_calls, 0);
    assert_eq!(second_counts.historical_ballots_replayed, 0);
    assert_eq!(second_counts.triptych_verify_calls, 0);
    assert_eq!(second_counts.triptych_adapter_verify_calls, 0);
    assert_eq!(cache.snapshot().entries, 1);
}

#[test]
fn durable_revision_change_cannot_reuse_the_old_verified_session() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, workspace_id, mut session, _stored) = build_workspace("cache-revision", 1, 0);
    let cache = VerifiedElectionSessionCacheV1::default();
    let _ = resumed_session(&root, &workspace_id, &cache);

    ok(session.close(), "close session");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write changed durable revision",
    );

    instrumentation::reset();
    let resumed = resumed_session(&root, &workspace_id, &cache);
    let counts = instrumentation::snapshot();
    assert_eq!(resumed.lifecycle_state(), "CLOSED");
    assert_eq!(counts.verified_session_cache_hits, 0);
    assert_eq!(counts.verified_session_cache_misses, 1);
    assert_eq!(counts.from_durable_snapshot_calls, 1);
    assert_eq!(counts.historical_ballots_replayed, 1);
}

#[test]
fn new_ballot_still_verifies_once_and_forces_a_fresh_verified_head() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, workspace_id, mut session, _stored) =
        build_workspace("cache-new-ballot", 0, 0);
    let cache = VerifiedElectionSessionCacheV1::default();
    let _ = resumed_session(&root, &workspace_id, &cache);

    instrumentation::reset();
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "new ballot intake",
        )
        .accepted
    );
    let intake_counts = instrumentation::snapshot();
    assert_eq!(intake_counts.triptych_verify_calls, 1);
    assert_eq!(intake_counts.triptych_adapter_verify_calls, 1);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write post-intake revision",
    );
    cache.invalidate_workspace(&workspace_id);

    instrumentation::reset();
    let resumed = resumed_session(&root, &workspace_id, &cache);
    let replay_counts = instrumentation::snapshot();
    assert_eq!(resumed.accepted_count(), 1);
    assert_eq!(replay_counts.verified_session_cache_hits, 0);
    assert_eq!(replay_counts.from_durable_snapshot_calls, 1);
    assert_eq!(replay_counts.historical_ballots_replayed, 1);
    assert_eq!(replay_counts.triptych_adapter_verify_calls, 1);
}

#[test]
fn concurrent_identical_resumes_single_flight_the_historical_replay() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let (_dir, root, workspace_id, _session, stored) = build_workspace("cache-concurrent", 3, 12);
    let cache = Arc::new(VerifiedElectionSessionCacheV1::default());
    let barrier = Arc::new(Barrier::new(8));

    instrumentation::reset();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            let workspace_id = workspace_id.clone();
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                match resume_election_workspace_with_verified_session_cache_v1(
                    &root,
                    &workspace_id,
                    &cache,
                ) {
                    Ok(LoadedElectionWorkspaceV1::Session { session, .. }) => {
                        assert_eq!(session.accepted_count(), 3)
                    }
                    Ok(LoadedElectionWorkspaceV1::Draft { .. }) => {
                        panic!("expected session workspace")
                    }
                    Err(error) => panic!("concurrent cached resume failed: {error}"),
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("resume worker must not panic");
    }
    let counts = instrumentation::snapshot();
    assert_eq!(counts.from_durable_snapshot_calls, 1);
    assert_eq!(counts.historical_ballots_replayed, stored as u64);
    assert_eq!(counts.triptych_adapter_verify_calls, stored as u64);
    assert_eq!(counts.verified_session_single_flight_owners, 1);
    assert_eq!(
        counts.verified_session_single_flight_waiters + counts.verified_session_cache_hits,
        7,
        "every non-owner must either wait for the owner or observe its completed entry",
    );
}

#[test]
fn failed_reconstruction_is_not_trusted_or_negative_cached() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let cache = VerifiedElectionSessionCacheV1::default();
    let key = VerifiedSessionKeyV1::new("test-workspace".to_owned(), 1, "a".repeat(64));

    instrumentation::reset();
    for _ in 0..2 {
        let error = cache
            .get_or_reconstruct(key.clone(), || {
                Err(GuiCoreError::new(
                    "GUI_TEST_RECONSTRUCTION_FAILED",
                    GuiErrorCategory::ArchiveIntegrity,
                    Some("test"),
                    "test reconstruction failed",
                ))
            })
            .err()
            .expect("a failed reconstruction must not be cached");
        assert_eq!(error.code(), "GUI_TEST_RECONSTRUCTION_FAILED");
    }
    let counts = instrumentation::snapshot();
    assert_eq!(cache.snapshot().entries, 0);
    assert_eq!(cache.snapshot().in_flight, 0);
    assert_eq!(counts.verified_session_cache_hits, 0);
    assert_eq!(counts.verified_session_single_flight_owners, 2);
    assert_eq!(counts.verified_session_single_flight_failures, 2);
}

#[test]
fn bounded_lru_evicts_and_an_evicted_workspace_reverifies() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("cache-eviction");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let first_session = open_session();
    let first_id = write_workspace(&root, &first_session);
    let second_session = open_session_with_revision("cache-eviction-second-election");
    let second_id = write_workspace(&root, &second_session);
    let cache = VerifiedElectionSessionCacheV1::new(1);

    let _ = resumed_session(&root, &first_id, &cache);
    let _ = resumed_session(&root, &second_id, &cache);
    assert_eq!(cache.snapshot().entries, 1);

    instrumentation::reset();
    let _ = resumed_session(&root, &first_id, &cache);
    let counts = instrumentation::snapshot();
    assert_eq!(counts.verified_session_cache_hits, 0);
    assert_eq!(counts.verified_session_cache_misses, 1);
    assert_eq!(counts.from_durable_snapshot_calls, 1);
}
