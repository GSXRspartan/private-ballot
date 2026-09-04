//! Slice 4C private-intake indexing and immutable-inbox cache regressions.
//!
//! Kept in its own integration-test binary because instrumentation is
//! process-global and these tests assert exact operation counts.

mod common;

use std::{fs, sync::Mutex};

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, append_accepted_ballot_package_to_inbox_v1, ballot_package_digest_hex_v1,
    ingest_private_intake_inbox_into_session_v1, instrumentation,
};

use common::{TestDir, open_session, triptych_package_bytes};

// These tests intentionally assert exact process-global instrumentation counts.
// Keep their measurement windows serial while leaving unrelated integration-test
// binaries free to run in parallel.
static INSTRUMENTATION_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn indexed_reconciliation_matches_the_legacy_first_decision_lookup() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-index-equivalence");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    let mut session = open_session();
    let first = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first");
    assert_eq!(first.newly_accepted, 1);
    let legacy_first = session
        .transcript()
        .decisions()
        .iter()
        .find(|decision| decision.sequence().value() == 0)
        .expect("the test fixture must retain the legacy first decision");
    assert!(legacy_first.outcome().is_accepted());

    let transcript_before = session.transcript().clone();
    instrumentation::reset();
    let repeat = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("repeat");
    let counters = instrumentation::snapshot();

    assert_eq!(repeat.newly_accepted, 0);
    assert_eq!(repeat.duplicates, 1);
    assert_eq!(counters.private_intake_digest_index_hits, 1);
    assert_eq!(counters.private_intake_digest_index_misses, 0);
    assert_eq!(counters.private_intake_linear_transcript_scans, 0);
    assert_eq!(
        session.transcript(),
        &transcript_before,
        "the indexed result must preserve the legacy no-new-transcript-row behavior",
    );
}

#[test]
fn unchanged_inbox_file_skips_read_hash_after_its_first_full_validation() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-unchanged-skip");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    let mut session = open_session();
    instrumentation::reset();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first");
    let first = instrumentation::snapshot();
    assert_eq!(first.private_inbox_files_read, 1);
    assert_eq!(first.private_inbox_files_hashed, 1);
    assert_eq!(first.private_inbox_files_skipped_unchanged, 0);

    instrumentation::reset();
    let repeat = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("repeat");
    let second = instrumentation::snapshot();
    assert_eq!(repeat.duplicates, 1);
    assert_eq!(second.private_inbox_files_read, 0);
    assert_eq!(second.private_inbox_files_hashed, 0);
    assert_eq!(second.private_inbox_files_skipped_unchanged, 1);
    assert_eq!(second.private_intake_digest_index_hits, 1);
    assert_eq!(second.private_intake_linear_transcript_scans, 0);
}

#[test]
fn changed_same_name_file_invalidates_the_skip_and_fails_closed() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-same-name-tamper");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    let mut session = open_session();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first");
    let digest_hex = ballot_package_digest_hex_v1(&package);
    fs::write(
        inbox.join(format!("{digest_hex}.package")),
        b"changed-same-name",
    )
    .expect("tamper");

    instrumentation::reset();
    let result = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session);
    let counters = instrumentation::snapshot();
    assert!(
        result.is_err(),
        "a same-name mutation must be fully revalidated"
    );
    assert_eq!(counters.private_inbox_files_skipped_unchanged, 0);
    assert_eq!(counters.private_inbox_files_read, 1);
    assert_eq!(counters.private_inbox_files_hashed, 1);
}

#[test]
fn transactional_clone_preserves_the_derived_index_and_validation_cache() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-transactional-clone");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    let mut session = open_session();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first");
    let mut cloned = session.transactional_clone();

    instrumentation::reset();
    let summary =
        ingest_private_intake_inbox_into_session_v1(&inbox, &mut cloned).expect("clone sync");
    let counters = instrumentation::snapshot();
    assert_eq!(summary.duplicates, 1);
    assert_eq!(counters.private_intake_digest_index_hits, 1);
    assert_eq!(counters.private_inbox_files_skipped_unchanged, 1);
    assert_eq!(counters.private_intake_linear_transcript_scans, 0);
}

#[test]
fn durable_reconstruction_rebuilds_the_derived_index_before_reconciliation() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-durable-rebuild");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    let mut session = open_session();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first");
    let snapshot = session.to_durable_snapshot().expect("snapshot");
    let mut resumed = GuiElectionSessionV1::from_durable_snapshot(snapshot).expect("resume");

    instrumentation::reset();
    let summary =
        ingest_private_intake_inbox_into_session_v1(&inbox, &mut resumed).expect("reconcile");
    let counters = instrumentation::snapshot();
    assert_eq!(summary.duplicates, 1);
    assert_eq!(counters.private_intake_digest_index_hits, 1);
    assert_eq!(counters.private_intake_digest_index_misses, 0);
    assert_eq!(
        counters.private_inbox_files_read, 1,
        "restart has no transient file cache"
    );
    assert_eq!(counters.private_inbox_files_hashed, 1);
    assert_eq!(counters.private_intake_linear_transcript_scans, 0);
}

#[test]
fn new_decisions_update_the_index_without_changing_canonical_transcript_order() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let dir = TestDir::new("slice4c-index-update");
    let inbox = dir.join("inbox");
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let second = triptych_package_bytes(1, &[b"candidate-b"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &first).expect("append first");

    let mut session = open_session();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("first sync");
    append_accepted_ballot_package_to_inbox_v1(&inbox, &second).expect("append second");
    let second_sync =
        ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("second sync");
    assert_eq!(second_sync.newly_accepted, 1);
    assert_eq!(session.transcript().decisions().len(), 2);
    assert!(session.transcript().decisions()[0].outcome().is_accepted());
    assert!(session.transcript().decisions()[1].outcome().is_accepted());

    instrumentation::reset();
    let repeat = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("repeat");
    let counters = instrumentation::snapshot();
    assert_eq!(repeat.duplicates, 2);
    assert_eq!(counters.private_intake_digest_index_hits, 2);
    assert_eq!(counters.private_inbox_files_skipped_unchanged, 2);
    assert_eq!(counters.private_intake_linear_transcript_scans, 0);
}

#[test]
fn synthetic_4096_lookup_workload_has_no_linear_transcript_scans() {
    let _instrumentation_guard = INSTRUMENTATION_LOCK.lock().expect("lock");
    let mut session = open_session();
    let packages: Vec<Vec<u8>> = (0_u32..4096)
        .map(|index| format!("not-a-canonical-ballot-{index}").into_bytes())
        .collect();

    for package in &packages {
        let result = session
            .intake_ballot_package_bytes(package)
            .expect("malformed package is recorded as a canonical rejection");
        assert!(!result.accepted);
    }
    let legacy_linear_comparisons = packages
        .len()
        .checked_mul(session.transcript().decisions().len())
        .expect("bounded synthetic fixture multiplication");
    assert_eq!(legacy_linear_comparisons, 16_777_216);
    let indexed_lookups = u64::try_from(packages.len()).expect("fixture count fits u64");
    let legacy_linear_comparisons =
        u64::try_from(legacy_linear_comparisons).expect("fixture count fits u64");

    instrumentation::reset();
    for package in &packages {
        let result = session
            .reconcile_accepted_package_bytes_from_inbox(package)
            .expect("indexed rejected-package reconciliation");
        assert!(!result.accepted);
    }
    let counters = instrumentation::snapshot();
    assert_eq!(counters.private_intake_digest_index_hits, indexed_lookups);
    assert_eq!(counters.private_intake_digest_index_misses, 0);
    assert_eq!(counters.private_intake_linear_transcript_scans, 0);
    assert!(
        counters.private_intake_digest_index_hits < legacy_linear_comparisons,
        "the indexed pass must use one lookup per package rather than one scan per decision",
    );
}
