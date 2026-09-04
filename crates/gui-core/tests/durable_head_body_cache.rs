//! Slice 4F: warm durable-head body cache.
//!
//! Proves that a warm append reuses the decoded head body (eliminating the
//! repeated CBOR decode) WHILE still reading and re-hashing the head file every
//! time (the Slice 3B tamper check is never skipped), and that every
//! identity/tamper/eviction path fails closed or drops the cache.
//!
//! Counters and the cache are process-global; this binary serializes tests and
//! clears the cache at the start of each.

mod common;

use std::sync::Mutex;

use tari_cc_private_ballot_gui_core::{
    DURABLE_HEAD_BODY_CACHE_MAX_BYTES_V1, GuiElectionSessionV1,
    clear_workspace_append_trusted_heads_v1, delete_election_workspace_v1,
    ensure_election_workspaces_directory_v1, instrumentation,
    set_durable_head_body_cache_max_bytes_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{message}: {error}"),
    }
}

/// Resets the global warm-head cache and counters to a known baseline.
fn reset_all() {
    clear_workspace_append_trusted_heads_v1();
    set_durable_head_body_cache_max_bytes_v1(DURABLE_HEAD_BODY_CACHE_MAX_BYTES_V1);
    instrumentation::reset();
}

fn write(root: &std::path::Path, workspace_id: &str, session: &GuiElectionSessionV1) -> u64 {
    ok(
        write_session_workspace_revision_v1(root, workspace_id, session),
        "write revision",
    )
}

#[test]
fn warm_append_reads_and_rehashes_but_reuses_the_decoded_body() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-reuse");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();
    let workspace_id = "wsa";

    reset_all();
    // Genesis commit seeds the cache with the just-written head body.
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, workspace_id, &session);

    // A warm append (advancing the head) reads and re-hashes the current head
    // file (integrity), but reuses the cached decoded body (no re-decode).
    instrumentation::reset();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, workspace_id, &session);
    let counters = instrumentation::snapshot();

    assert_eq!(
        counters.durable_head_body_disk_reads, 1,
        "the head file is still read and re-hashed on the warm append",
    );
    assert_eq!(
        counters.durable_head_body_cache_hits, 1,
        "the decoded head body is reused from the cache",
    );
    assert_eq!(
        counters.durable_head_body_decodes, 0,
        "the warm append does not re-decode the head body",
    );
    // Slice 3B fast-path integrity is preserved: exactly the head file was read.
    assert_eq!(counters.workspace_append_fast_path_hits, 1);
    assert_eq!(counters.workspace_append_revision_files_read, 1);
}

#[test]
fn tampered_head_fails_closed_and_never_serves_a_cached_body() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-tamper");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();
    let workspace_id = "wsb";

    reset_all();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    let rev1 = write(&root, workspace_id, &session);
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]))
            .unwrap()
            .accepted
    );
    let rev2 = write(&root, workspace_id, &session);
    assert!(rev2 > rev1);

    // Externally tamper the current head revision file bytes (leaving the commit
    // marker intact). The warm append re-hashes the file, detects the mismatch,
    // and must fail closed — never reuse the cached body for the trusted digest.
    let revisions = root.join(workspace_id).join("revisions");
    let head_file = std::fs::read_dir(&revisions)
        .expect("revisions dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".workspace"))
        })
        .max()
        .expect("head revision file");
    let mut bytes = std::fs::read(&head_file).expect("read head");
    bytes[0] ^= 0x01;
    std::fs::write(&head_file, bytes).expect("write tampered head");

    assert!(
        session
            .intake_ballot(&triptych_package_bytes(2, &[b"candidate-c"]))
            .unwrap()
            .accepted
    );
    let result = write_session_workspace_revision_v1(&root, workspace_id, &session);
    assert!(
        result.is_err(),
        "a tampered head must fail closed, not be served from the body cache",
    );
}

#[test]
fn delete_clears_the_cached_head_body() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-delete");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();
    let workspace_id = "wsc";

    reset_all();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, workspace_id, &session);
    assert!(
        instrumentation::snapshot().durable_head_body_cache_bytes > 0,
        "head body cached"
    );

    ok(
        delete_election_workspace_v1(&root, workspace_id),
        "delete workspace",
    );
    assert_eq!(
        instrumentation::snapshot().durable_head_body_cache_bytes,
        0,
        "deleting the workspace clears its cached head body",
    );
}

#[test]
fn different_workspaces_do_not_cross_hit() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-distinct");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();

    reset_all();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    // Same body, two distinct workspace ids: each caches its own head.
    let _ = write(&root, "wsd1", &session);
    let _ = write(&root, "wsd2", &session);

    // A warm append to wsd1 reads wsd1's head and hits wsd1's cached body only.
    instrumentation::reset();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, "wsd1", &session);
    let counters = instrumentation::snapshot();
    assert_eq!(counters.durable_head_body_cache_hits, 1);
    assert_eq!(
        counters.durable_head_body_decodes, 0,
        "wsd1 reused its own cached body"
    );
}

#[test]
fn bounded_byte_eviction_and_a_too_large_body_is_not_cached() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-eviction");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );

    // A cap smaller than one head body: nothing is cached (single body > cap).
    reset_all();
    set_durable_head_body_cache_max_bytes_v1(64);
    let _ = write(&root, "wse1", &session);
    assert_eq!(
        instrumentation::snapshot().durable_head_body_cache_bytes,
        0,
        "a body larger than the cap is not cached",
    );

    // A cap that holds roughly one body forces LRU eviction as more workspaces
    // are written.
    reset_all();
    set_durable_head_body_cache_max_bytes_v1(2500);
    for workspace_id in ["wse2", "wse3", "wse4", "wse5"] {
        let _ = write(&root, workspace_id, &session);
    }
    let counters = instrumentation::snapshot();
    assert!(
        counters.durable_head_body_cache_bytes <= 2500,
        "cached bytes stay within the byte cap",
    );
    assert!(
        counters.durable_head_body_cache_evictions >= 1,
        "exceeding the byte cap evicts the least-recently-used head body",
    );
}

#[test]
fn restart_starts_with_an_empty_cache() {
    let _guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = TestDir::new("warm-body-restart");
    let root = ok(ensure_election_workspaces_directory_v1(dir.path()), "root");
    let mut session = open_session();
    let workspace_id = "wsf";

    reset_all();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, workspace_id, &session);

    // Simulate a process restart: both the trusted head and the body cache clear.
    clear_workspace_append_trusted_heads_v1();
    assert_eq!(
        instrumentation::snapshot().durable_head_body_cache_bytes,
        0,
        "restart empties the cache"
    );

    // The next append re-establishes trust via the full walk (no fast-path hit),
    // decoding the head from disk anew — never trusting a stale cached body.
    instrumentation::reset();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]))
            .unwrap()
            .accepted
    );
    let _ = write(&root, workspace_id, &session);
    let counters = instrumentation::snapshot();
    assert_eq!(
        counters.workspace_append_fast_path_hits, 0,
        "the first append after restart takes the full-walk path",
    );
    assert_eq!(counters.workspace_append_full_history_validations, 1);
}
