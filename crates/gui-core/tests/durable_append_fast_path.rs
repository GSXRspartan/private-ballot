//! Slice 3B — process-local validated-head fast-append tests.
//!
//! These prove the fast path removes the per-append full-history re-read while
//! preserving every fail-closed durability and tamper guarantee. They read only
//! the aggregate development counters in `instrumentation` and manipulate only
//! OS-temporary workspaces; no application data is touched. The existing
//! `workspace.rs`, `verified_session_cache.rs`, and `reconstruction_instrumentation.rs`
//! suites cover the wrong-predecessor, divergent-same-generation, and
//! copied-workspace cold-load fail-closed cases and remain green unchanged.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, LoadedElectionWorkspaceV1, VerifiedElectionSessionCacheV1,
    clear_workspace_append_trusted_heads_v1, delete_election_workspace_v1, instrumentation,
    list_election_workspaces_v1, resume_election_workspace_with_verified_session_cache_v1,
    workspace_id_for_session_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

/// The `instrumentation` counters are process-global, so tests that `reset()`
/// and read them must not run concurrently with any other append in this
/// binary. Every test acquires this guard, serializing the whole file.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, msg: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{msg}: {error}"),
    }
}

/// Distinct, valid canonical package for one of the three fixture voters.
fn distinct_package(voter_index: usize) -> Vec<u8> {
    triptych_package_bytes(voter_index, &[b"candidate-a"])
}

/// Intakes `package` (accepted or duplicate — both grow the durable package
/// list) and writes the next durable revision, returning its number.
fn intake_and_write(
    root: &Path,
    workspace_id: &str,
    session: &mut GuiElectionSessionV1,
    package: &[u8],
) -> u64 {
    let _ = ok(
        session.intake_ballot_package_bytes(package),
        "fixture package must pass the intake boundary",
    );
    ok(
        write_session_workspace_revision_v1(root, workspace_id, session),
        "durable revision must write",
    )
}

/// Writes the genesis (revision 1) open snapshot with zero packages.
fn write_genesis(root: &Path, workspace_id: &str, session: &GuiElectionSessionV1) -> u64 {
    ok(
        write_session_workspace_revision_v1(root, workspace_id, session),
        "genesis revision must write",
    )
}

fn revision_files(root: &Path, workspace_id: &str) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = ok(
        fs::read_dir(root.join(workspace_id).join("revisions")),
        "revisions dir",
    )
    .map(|entry| ok(entry, "revision entry").path())
    .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("workspace"))
    .collect();
    paths.sort();
    paths
}

// 1 + 12: a fresh process (empty validated-head map, i.e. a restart) performs a
// full committed-history validation before it can take any fast path.
#[test]
fn fresh_process_append_performs_full_history_validation() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-fresh-full");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    assert_eq!(write_genesis(root, &workspace_id, &session), 1);
    assert_eq!(
        intake_and_write(root, &workspace_id, &mut session, &distinct_package(0)),
        2
    );
    assert_eq!(
        intake_and_write(root, &workspace_id, &mut session, &distinct_package(1)),
        3
    );
    assert_eq!(revision_files(root, &workspace_id).len(), 3);

    // Simulate a process restart: no persisted trust survives.
    clear_workspace_append_trusted_heads_v1();
    instrumentation::reset();

    let revision = intake_and_write(root, &workspace_id, &mut session, &distinct_package(2));
    assert_eq!(revision, 4);

    let counters = instrumentation::snapshot();
    assert_eq!(counters.workspace_append_calls, 1);
    assert_eq!(counters.workspace_append_full_history_validations, 1);
    assert_eq!(counters.workspace_append_fast_path_hits, 0);
    // The full walk read all three committed revisions to choose the head.
    assert_eq!(counters.workspace_append_revision_files_read, 3);
}

// 2: after a validated head exists, the next append takes the fast path and
// reads only the single head revision file — never the whole chain.
#[test]
fn warm_append_reads_only_head_not_whole_chain() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-warm-head-only");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));
    // Trusted head is now warm (revision 3).

    instrumentation::reset();
    let revision = intake_and_write(root, &workspace_id, &mut session, &distinct_package(2));
    assert_eq!(revision, 4);

    let counters = instrumentation::snapshot();
    assert_eq!(counters.workspace_append_calls, 1);
    assert_eq!(counters.workspace_append_fast_path_hits, 1);
    assert_eq!(counters.workspace_append_full_history_validations, 0);
    // Exactly one prior revision file (the head) was read, independent of the
    // three-revision history behind it.
    assert_eq!(counters.workspace_append_revision_files_read, 1);
}

// The scaling property: append head-loading work is independent of history
// depth once warm. A deeper history still reads exactly one head file.
#[test]
fn warm_append_head_read_is_constant_across_history_depth() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-constant-head");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    // Grow a deeper history using duplicate-entry appends (each still grows the
    // durable package list and therefore the revision chain).
    let dup = distinct_package(0);
    for _ in 0..12 {
        intake_and_write(root, &workspace_id, &mut session, &dup);
    }

    instrumentation::reset();
    intake_and_write(root, &workspace_id, &mut session, &dup);
    let counters = instrumentation::snapshot();
    assert_eq!(counters.workspace_append_fast_path_hits, 1);
    assert_eq!(counters.workspace_append_revision_files_read, 1);
}

// 3 + 18: a fast-appended revision is real and authoritative — it passes the
// full cold-load validation on resume, and the reconstructed head matches.
#[test]
fn fast_appended_revision_is_authoritative_on_resume() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-authoritative");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    let head = intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));
    assert_eq!(head, 3);

    let cache = VerifiedElectionSessionCacheV1::default();
    match ok(
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache),
        "resume must reconstruct the fast-appended workspace",
    ) {
        LoadedElectionWorkspaceV1::Session { workspace, .. } => {
            assert_eq!(workspace.last_revision, 3);
            // Two distinct accepted ballots were stored.
            assert_eq!(workspace.stored_ballot_count, 2);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    }
}

// 4: a tampered OLD (non-head) revision cannot be silently accepted — the cold
// full walk on resume fails closed.
#[test]
fn tampered_old_revision_fails_closed_on_cold_load() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-tamper-old");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));

    // Flip a byte inside an OLD revision file (revision 2, not the head).
    let files = revision_files(root, &workspace_id);
    let old = &files[1];
    let mut bytes = ok(fs::read(old), "read old revision");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    ok(fs::write(old, &bytes), "overwrite old revision");

    clear_workspace_append_trusted_heads_v1();
    let cache = VerifiedElectionSessionCacheV1::default();
    let result =
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache);
    assert!(
        result.is_err(),
        "a tampered historical revision must fail closed"
    );
}

// 5: a missing middle revision fails closed on the cold full walk.
#[test]
fn missing_middle_revision_fails_closed_on_cold_load() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-missing-middle");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));

    let files = revision_files(root, &workspace_id);
    ok(fs::remove_file(&files[1]), "remove middle revision");

    clear_workspace_append_trusted_heads_v1();
    let cache = VerifiedElectionSessionCacheV1::default();
    let result =
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache);
    assert!(
        result.is_err(),
        "a missing middle revision must fail closed"
    );
}

// 9 + 10: external mutation of the confirmed head invalidates fast-path
// authority and fails closed rather than chaining onto corrupt state.
#[test]
fn head_corruption_invalidates_fast_path_and_fails_closed() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-head-corrupt");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    let head = intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));
    assert_eq!(head, 3);
    // Trusted head is warm at revision 3.

    // Corrupt the head revision file's content in place (name still encodes the
    // old digest, so it no longer re-hashes to the marker's digest).
    let files = revision_files(root, &workspace_id);
    let head_file = files.last().expect("head revision file");
    let mut bytes = ok(fs::read(head_file), "read head revision");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    ok(fs::write(head_file, &bytes), "overwrite head revision");

    instrumentation::reset();
    // A further append must NOT silently chain onto the corrupt head.
    let _ = session.intake_ballot_package_bytes(&distinct_package(2));
    let result = write_session_workspace_revision_v1(root, &workspace_id, &session);
    assert!(result.is_err(), "corrupt head must fail the append closed");

    let counters = instrumentation::snapshot();
    // The fast path detected the anomaly and discarded the trusted head.
    assert_eq!(counters.workspace_append_trusted_head_invalidations, 1);
}

// 11: two concurrent in-process appenders cannot silently fork the workspace.
#[test]
fn concurrent_appends_do_not_fork() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-concurrent");
    let root = Arc::new(dir.path().to_path_buf());

    let base = open_session();
    let workspace_id = workspace_id_for_session_v1(&base);
    write_genesis(&root, &workspace_id, &base);

    let workspace_id = Arc::new(workspace_id);
    let mut handles = Vec::new();
    for voter_index in 0..2usize {
        let root = Arc::clone(&root);
        let workspace_id = Arc::clone(&workspace_id);
        handles.push(std::thread::spawn(move || {
            let mut session = open_session();
            let package = distinct_package(voter_index);
            let _ = session.intake_ballot_package_bytes(&package);
            write_session_workspace_revision_v1(root.as_path(), workspace_id.as_str(), &session)
        }));
    }
    let mut revisions: Vec<u64> = handles
        .into_iter()
        .map(|handle| {
            ok(
                handle.join().expect("thread must not panic"),
                "concurrent append",
            )
        })
        .collect();
    revisions.sort_unstable();
    // Distinct, contiguous revision numbers — no two writers produced the same
    // generation, so no conflicting fork exists.
    assert_eq!(revisions, vec![2, 3]);

    // The chain remains contiguous and fully resumable (no conflicting_workspace).
    clear_workspace_append_trusted_heads_v1();
    let cache = VerifiedElectionSessionCacheV1::default();
    let resumed =
        resume_election_workspace_with_verified_session_cache_v1(&root, &workspace_id, &cache);
    assert!(
        resumed.is_ok(),
        "the serialized concurrent history must resume cleanly"
    );
}

// 13: resume/import does NOT inherit fast-path trust. After a restart, resuming
// warms nothing for the writer, so the next append is a full validation.
#[test]
fn resume_does_not_grant_fast_path_trust() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-no-inherit");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));

    clear_workspace_append_trusted_heads_v1(); // restart
    let cache = VerifiedElectionSessionCacheV1::default();
    let _ = ok(
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache),
        "resume must succeed",
    );

    instrumentation::reset();
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));
    let counters = instrumentation::snapshot();
    // The first append after a restart still fully validates, even though a
    // resume already ran — resume never warms the writer's validated head.
    assert_eq!(counters.workspace_append_full_history_validations, 1);
    assert_eq!(counters.workspace_append_fast_path_hits, 0);
}

// 14: deleting a workspace clears its validated head; a re-created workspace of
// the same id starts at genesis.
#[test]
fn delete_clears_trusted_head() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-delete-clears");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));

    instrumentation::reset();
    ok(
        delete_election_workspace_v1(root, &workspace_id),
        "delete must succeed",
    );
    let counters = instrumentation::snapshot();
    assert_eq!(counters.workspace_append_trusted_head_invalidations, 1);

    // A fresh session for the same id writes genesis again (no stale head).
    let fresh = open_session();
    assert_eq!(write_genesis(root, &workspace_id, &fresh), 1);
}

// 15: intaking a brand-new distinct ballot still performs a Triptych proof
// verification (the fast path only changes durable reads, never verification).
#[test]
fn new_ballot_still_verifies_cryptographically() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-verify-preserved");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    write_genesis(root, &workspace_id, &session);

    instrumentation::reset();
    let before = instrumentation::snapshot().triptych_adapter_verify_calls;
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    let after = instrumentation::snapshot().triptych_adapter_verify_calls;
    assert!(after > before, "a new ballot must be proof-verified");
}

// 16: the Slice 2 verified-session cache still behaves — a second resume of an
// unchanged head is a cache hit and does not reconstruct again.
#[test]
fn slice2_cache_hit_preserved_under_fast_path() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-cache-hit");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));

    let cache = VerifiedElectionSessionCacheV1::default();
    instrumentation::reset();
    let _ = ok(
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache),
        "first resume",
    );
    let _ = ok(
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache),
        "second resume",
    );
    let counters = instrumentation::snapshot();
    assert_eq!(counters.verified_session_cache_hits, 1);
    // Exactly one reconstruction across two resumes of the same head.
    assert_eq!(counters.from_durable_snapshot_calls, 1);
}

// 17: workspace listing performs zero historical ballot replay, regardless of
// the fast-path state.
#[test]
fn workspace_listing_replays_nothing() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-listing");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);
    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(1));

    instrumentation::reset();
    let summaries = ok(list_election_workspaces_v1(root), "listing must succeed");
    assert!(
        summaries
            .iter()
            .any(|summary| summary.workspace_id == *workspace_id)
    );
    let counters = instrumentation::snapshot();
    assert_eq!(counters.historical_ballots_replayed, 0);
    assert_eq!(counters.from_durable_snapshot_calls, 0);
}

// 19: lifecycle progression through finalization stays deterministic and
// durable across fast appends, and resumes as Finalized.
#[test]
fn lifecycle_finalization_is_deterministic_under_fast_path() {
    let _serial = serial_guard();
    let dir = TestDir::new("slice3b-finalize");
    let root = dir.path();
    let mut session = open_session();
    let workspace_id = workspace_id_for_session_v1(&session);

    write_genesis(root, &workspace_id, &session);
    intake_and_write(root, &workspace_id, &mut session, &distinct_package(0));
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(root, &workspace_id, &session),
        "closed revision",
    );
    ok(session.mark_verified(), "verify");
    ok(
        write_session_workspace_revision_v1(root, &workspace_id, &session),
        "verified revision",
    );
    ok(session.finalize(), "finalize");
    ok(
        write_session_workspace_revision_v1(root, &workspace_id, &session),
        "finalized revision",
    );

    clear_workspace_append_trusted_heads_v1();
    let cache = VerifiedElectionSessionCacheV1::default();
    match ok(
        resume_election_workspace_with_verified_session_cache_v1(root, &workspace_id, &cache),
        "finalized workspace must resume",
    ) {
        LoadedElectionWorkspaceV1::Session { workspace, .. } => {
            assert!(workspace.finalized, "resumed workspace must be finalized");
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    }
}
