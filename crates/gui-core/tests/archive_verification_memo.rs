//! Slice 4D: same-run archive-verification memoization.
//!
//! These prove the load-bearing property: reusing an unchanged archive in the
//! same process performs ZERO repeated historical Triptych proof replay, while
//! the mandatory current-content catalog revalidation still runs on every
//! request, and every tamper/replacement/mutation path fails closed and is
//! never served from a stale cache.
//!
//! The archive-verification counters are process-global, so every test here
//! holds a shared lock across its reset/measure window.

mod common;

use std::sync::{Arc, Mutex};

use tari_cc_private_ballot_archive::{
    ArchiveVerificationCountersSnapshotV1, ArchiveVerificationMemoV1,
    archive_verification_snapshot, reset_archive_verification_counters,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiLiveAnchorConfigRequestV1, verify_archive_directory_v1,
    verify_archive_directory_with_memo_v1, verify_transport_archive_anchor_v1,
    verify_transport_archive_anchor_with_memo_v1,
    write_live_anchor_config_from_verified_archive_v1,
    write_live_anchor_config_from_verified_archive_with_memo_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn closed_session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = open_session();
    let packages = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b", b"candidate-c"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate nullifier
        triptych_package_bytes(2, &[b"candidate-c"]),
    ];
    for package in &packages {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    session
}

fn write_archive(target: &std::path::Path, session: &GuiElectionSessionV1) {
    if let Err(error) =
        tari_cc_private_ballot_gui_core::archive_writer::write_archive_directory_v1(session, target)
    {
        panic!("archive write must succeed: {error}");
    }
}

fn write_test_archive(dir: &TestDir, name: &str) -> std::path::PathBuf {
    let target = dir.join(name);
    write_archive(&target, &closed_session_with_ballots());
    target
}

fn delta(
    before: ArchiveVerificationCountersSnapshotV1,
    after: ArchiveVerificationCountersSnapshotV1,
) -> ArchiveVerificationCountersSnapshotV1 {
    ArchiveVerificationCountersSnapshotV1 {
        archive_verification_cache_hits: after.archive_verification_cache_hits
            - before.archive_verification_cache_hits,
        archive_verification_cache_misses: after.archive_verification_cache_misses
            - before.archive_verification_cache_misses,
        archive_full_verification_count: after.archive_full_verification_count
            - before.archive_full_verification_count,
        archive_catalog_revalidations: after.archive_catalog_revalidations
            - before.archive_catalog_revalidations,
        archive_historical_replay_count: after.archive_historical_replay_count
            - before.archive_historical_replay_count,
        archive_historical_triptych_verifies: after.archive_historical_triptych_verifies
            - before.archive_historical_triptych_verifies,
        archive_cache_evictions: after.archive_cache_evictions - before.archive_cache_evictions,
        archive_cache_identity_drift: after.archive_cache_identity_drift
            - before.archive_cache_identity_drift,
        archive_single_flight_waits: after.archive_single_flight_waits
            - before.archive_single_flight_waits,
    }
}

fn tamper_first_byte(path: &std::path::Path) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => panic!("target file must be readable"),
    };
    let Some(first) = bytes.first() else {
        panic!("target file must not be empty");
    };
    let mut tampered = bytes.clone();
    tampered[0] = first ^ 0x01;
    assert!(std::fs::write(path, tampered).is_ok());
}

#[test]
fn first_verification_is_full_then_unchanged_reuse_skips_replay() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-first-second");
    let target = write_test_archive(&dir, "archive");
    let memo = ArchiveVerificationMemoV1::default();

    // 1. First verification: one miss, one full verification, four Triptych
    //    verifies (one per archived submission), and one catalog revalidation.
    reset_archive_verification_counters();
    let first = verify_archive_directory_with_memo_v1(&memo, &target).expect("first memo verify");
    let first_delta = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(first.verified, "valid archive verifies");
    assert_eq!(first_delta.archive_verification_cache_misses, 1);
    assert_eq!(first_delta.archive_full_verification_count, 1);
    assert_eq!(first_delta.archive_historical_replay_count, 1);
    assert_eq!(first_delta.archive_historical_triptych_verifies, 4);
    assert_eq!(first_delta.archive_catalog_revalidations, 1);
    assert_eq!(first_delta.archive_verification_cache_hits, 0);

    // 2/3. Second unchanged verification: a hit with ZERO repeated replay and
    //      ZERO Triptych verifies, but the catalog is still revalidated.
    let before = archive_verification_snapshot();
    let second = verify_archive_directory_with_memo_v1(&memo, &target).expect("second memo verify");
    let second_delta = delta(before, archive_verification_snapshot());
    assert_eq!(second_delta.archive_verification_cache_hits, 1);
    assert_eq!(second_delta.archive_full_verification_count, 0);
    assert_eq!(
        second_delta.archive_historical_replay_count, 0,
        "a hit performs no repeated historical replay",
    );
    assert_eq!(
        second_delta.archive_historical_triptych_verifies, 0,
        "a hit performs no repeated Triptych proof verification",
    );
    assert_eq!(
        second_delta.archive_catalog_revalidations, 1,
        "a hit still re-reads and re-digests the full catalog",
    );

    // Result equality: the memo output equals a fresh non-memo verification.
    let fresh = verify_archive_directory_v1(&target).expect("non-memo verify");
    assert_eq!(second, fresh, "memo hit output equals fresh verification");
}

#[test]
fn mutated_manifest_never_returns_a_stale_hit() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-mutated-manifest");
    let target = write_test_archive(&dir, "archive");
    let memo = ArchiveVerificationMemoV1::default();
    assert!(
        verify_archive_directory_with_memo_v1(&memo, &target)
            .unwrap()
            .verified
    );

    // Tamper the archive manifest itself. The freshly decoded manifest either
    // changes the archive hash (new key -> miss) or fails to decode.
    tamper_first_byte(&target.join("archive-manifest.cbor"));
    let after = verify_archive_directory_with_memo_v1(&memo, &target).expect("verify after tamper");
    assert!(!after.verified, "a tampered manifest is never a stale hit");
}

#[test]
fn mutated_ballot_fails_closed_before_replay() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-mutated-ballot");
    let target = write_test_archive(&dir, "archive");
    let memo = ArchiveVerificationMemoV1::default();
    assert!(
        verify_archive_directory_with_memo_v1(&memo, &target)
            .unwrap()
            .verified
    );

    // Tamper one archived submission's bytes. The catalog rehash detects it.
    let submissions = target.join("submissions");
    let first_submission = std::fs::read_dir(&submissions)
        .expect("submissions dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .min()
        .expect("at least one submission");
    reset_archive_verification_counters();
    tamper_first_byte(&first_submission);
    let after = verify_archive_directory_with_memo_v1(&memo, &target).expect("verify after tamper");
    let after_delta = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(!after.verified, "a mutated submission is never a stale hit");
    assert_eq!(after.failure_stage, Some("CATALOG_FILES"));
    assert_eq!(
        after_delta.archive_historical_triptych_verifies, 0,
        "catalog rehash fails closed before any replay",
    );
    assert_eq!(after_delta.archive_verification_cache_hits, 0);
}

#[test]
fn same_path_replaced_with_a_different_archive_is_not_a_cross_hit() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-replace-path");
    let target = write_test_archive(&dir, "archive");
    let memo = ArchiveVerificationMemoV1::default();
    let original = verify_archive_directory_with_memo_v1(&memo, &target).expect("original verify");

    // Replace the SAME path with a different final archive (different ballots).
    assert!(std::fs::remove_dir_all(&target).is_ok());
    let mut other = open_session();
    for package in [
        triptych_package_bytes(1, &[b"candidate-a"]),
        triptych_package_bytes(2, &[b"candidate-b"]),
    ] {
        assert!(other.intake_ballot(&package).is_ok());
    }
    assert!(other.close().is_ok());
    write_archive(&target, &other);

    reset_archive_verification_counters();
    let replaced = verify_archive_directory_with_memo_v1(&memo, &target).expect("replaced verify");
    let replaced_delta = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(replaced.verified);
    assert_ne!(
        replaced.archive_hash_hex, original.archive_hash_hex,
        "the replacement archive has a different identity",
    );
    assert_eq!(
        replaced_delta.archive_verification_cache_hits, 0,
        "no cross-hit"
    );
    assert_eq!(
        replaced_delta.archive_full_verification_count, 1,
        "full re-verify"
    );
    assert_eq!(
        replaced_delta.archive_cache_identity_drift, 1,
        "same-path content change is recorded as identity drift",
    );
}

#[test]
fn delete_and_recreate_identical_archive_reuses_only_after_full_rehash() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-delete-recreate");
    let session = closed_session_with_ballots();
    let target = dir.join("archive");
    write_archive(&target, &session);
    let memo = ArchiveVerificationMemoV1::default();
    let before = verify_archive_directory_with_memo_v1(&memo, &target).expect("before verify");

    // Delete and recreate byte-identical content (deterministic archive write).
    assert!(std::fs::remove_dir_all(&target).is_ok());
    write_archive(&target, &session);

    reset_archive_verification_counters();
    let after = verify_archive_directory_with_memo_v1(&memo, &target).expect("after verify");
    let after_delta = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert_eq!(
        after, before,
        "identical recreated content verifies identically"
    );
    // Identity is re-established by a full catalog rehash; only then is the
    // prior verified result reused, so no replay recurs.
    assert_eq!(after_delta.archive_catalog_revalidations, 1);
    assert_eq!(after_delta.archive_verification_cache_hits, 1);
    assert_eq!(after_delta.archive_historical_triptych_verifies, 0);
}

#[test]
fn different_archives_do_not_cross_hit() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-different");
    let first = write_test_archive(&dir, "first");
    let second = write_test_archive(&dir, "second"); // same content, different path
    let memo = ArchiveVerificationMemoV1::default();

    reset_archive_verification_counters();
    let a = verify_archive_directory_with_memo_v1(&memo, &first).expect("first verify");
    let b = verify_archive_directory_with_memo_v1(&memo, &second).expect("second verify");
    let both = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(a.verified && b.verified);
    assert_eq!(
        both.archive_verification_cache_hits, 0,
        "distinct directories never cross-hit"
    );
    assert_eq!(
        both.archive_full_verification_count, 2,
        "each verifies independently"
    );
}

#[test]
fn failed_verification_is_never_cached() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-failure-not-cached");
    let target = write_test_archive(&dir, "archive");
    let memo = ArchiveVerificationMemoV1::default();

    // Break the archive so verification fails, then repair it.
    let manifest_hex_path = target.join("submissions");
    let broken = std::fs::read_dir(&manifest_hex_path)
        .expect("submissions dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .min()
        .expect("submission");
    let original = std::fs::read(&broken).expect("read submission");
    tamper_first_byte(&broken);
    let failed = verify_archive_directory_with_memo_v1(&memo, &target).expect("failed verify");
    assert!(!failed.verified);
    assert_eq!(
        memo.entry_count(),
        0,
        "a failed verification is never cached"
    );

    // Repair: the next verification is a full miss (nothing stale was cached).
    assert!(std::fs::write(&broken, original).is_ok());
    reset_archive_verification_counters();
    let repaired = verify_archive_directory_with_memo_v1(&memo, &target).expect("repaired verify");
    let repaired_delta = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(repaired.verified);
    assert_eq!(repaired_delta.archive_verification_cache_hits, 0);
    assert_eq!(repaired_delta.archive_full_verification_count, 1);
}

#[test]
fn bounded_eviction_forces_a_full_reverification() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-eviction");
    let memo = ArchiveVerificationMemoV1::new(2);
    // Two distinct-content archives fill the capacity-2 memo; a third evicts the
    // least-recently-used (the first).
    let a = dir.join("a");
    write_archive(&a, &closed_session_with_ballots());
    let mut second = open_session();
    assert!(
        second
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-a"]))
            .is_ok()
    );
    assert!(second.close().is_ok());
    let b = dir.join("b");
    write_archive(&b, &second);
    let mut third = open_session();
    assert!(
        third
            .intake_ballot(&triptych_package_bytes(2, &[b"candidate-c"]))
            .is_ok()
    );
    assert!(third.close().is_ok());
    let c = dir.join("c");
    write_archive(&c, &third);

    assert!(
        verify_archive_directory_with_memo_v1(&memo, &a)
            .unwrap()
            .verified
    );
    assert!(
        verify_archive_directory_with_memo_v1(&memo, &b)
            .unwrap()
            .verified
    );
    reset_archive_verification_counters();
    assert!(
        verify_archive_directory_with_memo_v1(&memo, &c)
            .unwrap()
            .verified
    ); // evicts a
    let insert_c = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(
        insert_c.archive_cache_evictions >= 1,
        "inserting c evicts the LRU entry"
    );

    // a was evicted: verifying it again is a full miss, not a hit.
    reset_archive_verification_counters();
    assert!(
        verify_archive_directory_with_memo_v1(&memo, &a)
            .unwrap()
            .verified
    );
    let reverify_a = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert_eq!(reverify_a.archive_verification_cache_hits, 0);
    assert_eq!(reverify_a.archive_full_verification_count, 1);
}

#[test]
fn concurrent_same_archive_uses_one_full_replay() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-concurrent");
    let target = write_test_archive(&dir, "archive");
    let memo = Arc::new(ArchiveVerificationMemoV1::default());

    reset_archive_verification_counters();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let memo = Arc::clone(&memo);
                let target = target.clone();
                scope.spawn(move || {
                    verify_archive_directory_with_memo_v1(&memo, &target)
                        .expect("concurrent verify")
                        .verified
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.join().expect("thread joined"));
        }
    });
    let both = delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert_eq!(
        both.archive_full_verification_count, 1,
        "single-flight yields exactly one full replay for concurrent identical callers",
    );
    assert_eq!(
        both.archive_historical_triptych_verifies, 4,
        "the historical replay runs once for the whole concurrent set",
    );
}

#[test]
fn transport_anchor_output_is_identical_with_and_without_the_memo() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-transport-anchor");
    let target = write_test_archive(&dir, "archive");
    let evidence = dir.join("anchor-evidence.bin"); // deliberately absent
    let memo = ArchiveVerificationMemoV1::default();

    let plain = verify_transport_archive_anchor_v1(&target, &evidence).expect("plain transport");
    let memoized = verify_transport_archive_anchor_with_memo_v1(&memo, &target, &evidence)
        .expect("memo transport");
    // A verified non-finalized archive with absent evidence is INCLUDED either
    // way; the memo does not change the conclusion.
    assert_eq!(plain, memoized);
    assert_eq!(memoized.state, "INCLUDED");
}

#[test]
fn live_config_reaches_the_same_gate_with_and_without_the_memo() {
    let _guard = COUNTER_LOCK.lock().expect("counter lock");
    let dir = TestDir::new("memo-live-config");
    let target = write_test_archive(&dir, "archive"); // non-finalized, no binding
    let memo = ArchiveVerificationMemoV1::default();
    let request = minimal_live_config_request(&target, &dir);

    let plain = write_live_anchor_config_from_verified_archive_v1(&request);
    let memoized = write_live_anchor_config_from_verified_archive_with_memo_v1(&memo, &request);
    // The archive is not finalized, so both paths reject at the identical gate.
    match (plain, memoized) {
        (Err(plain_error), Err(memo_error)) => {
            assert_eq!(
                plain_error.code(),
                memo_error.code(),
                "memo and non-memo config paths reject at the identical gate",
            );
        }
        other => panic!("both paths must reject a non-finalized archive identically: {other:?}"),
    }
}

fn minimal_live_config_request(
    archive_dir: &std::path::Path,
    dir: &TestDir,
) -> GuiLiveAnchorConfigRequestV1 {
    GuiLiveAnchorConfigRequestV1 {
        archive_directory: archive_dir.to_string_lossy().into_owned(),
        output_config_path: dir.join("config.cbor").to_string_lossy().into_owned(),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:9000".to_owned(),
        indexer_endpoint: "http://127.0.0.1:9010".to_owned(),
        template_address: "0".repeat(64),
        template_module: "anchor".to_owned(),
        template_event_topic: "anchor.event".to_owned(),
        template_artifact_digest_hex: "0".repeat(64),
        max_epoch_delta: 10,
        account_reference: "account".to_owned(),
        fee_component: "component_0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        declared_seal_public_key: "deadbeef".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1000,
        required_accepted_ballot_floor: 1,
        reduced_anonymity_acknowledged: false,
        snapshot_path: dir.join("snapshot.cbor").to_string_lossy().into_owned(),
        evidence_path: dir.join("evidence.bin").to_string_lossy().into_owned(),
        backoff_base_secs: 1,
        backoff_cap_secs: 2,
        receipt_query_attempts: 3,
        request_timeout_secs: Some(30),
        ttl_secs: None,
    }
}
