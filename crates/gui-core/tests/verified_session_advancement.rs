//! Slice 4E: incremental verified-session advancement.
//!
//! # Load-bearing equivalence proof
//!
//! The advancement optimization is sound ONLY IF an incrementally-mutated,
//! already-verified session is semantically identical to a fresh authoritative
//! reconstruction of the exact durable state it just committed. Because the
//! committed durable body IS `session.to_durable_snapshot()`, the invariant is:
//!
//!   session  ≡  from_durable_snapshot(session.to_durable_snapshot())
//!            =  session.replayed_clone()
//!
//! for every durable mutation category. These tests PROVE that invariant across
//! authoritative state (durable snapshot bytes, verification transcript,
//! accepted count, and tally) before any production advancement path is trusted.
//! If any category failed here, incremental advancement would be UNSOUND and
//! must not be implemented.

mod common;

use tari_cc_private_ballot_gui_core::{GuiElectionSessionV1, HistoricalReplayConfigV1};

use common::{open_session, triptych_package_bytes};

/// Asserts an incrementally-built session equals a fresh reconstruction of its
/// own committed durable snapshot, across every authoritative dimension.
fn assert_equals_fresh_reconstruction(session: &GuiElectionSessionV1) {
    let snapshot = match session.to_durable_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("durable snapshot must encode: {error}"),
    };
    let reconstructed = match GuiElectionSessionV1::from_durable_snapshot(snapshot.clone()) {
        Ok(session) => session,
        Err(error) => panic!("fresh reconstruction must succeed: {error}"),
    };

    // 1. Durable snapshot bytes (lifecycle + artifacts + package list).
    let reconstructed_snapshot = match reconstructed.to_durable_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("reconstructed snapshot must encode: {error}"),
    };
    assert_eq!(
        snapshot, reconstructed_snapshot,
        "durable snapshot must round-trip identically",
    );
    // 2. Lifecycle state.
    assert_eq!(
        session.lifecycle_state(),
        reconstructed.lifecycle_state(),
        "lifecycle state must match a fresh reconstruction",
    );
    // 3. Accepted count.
    assert_eq!(
        session.accepted_count(),
        reconstructed.accepted_count(),
        "accepted count must match a fresh reconstruction",
    );
    // 4. Full verification transcript (submissions + ordered decisions).
    assert!(
        session.transcript() == reconstructed.transcript(),
        "verification transcript must match a fresh reconstruction",
    );
    // 5. Deterministic tally over the accepted set.
    assert_eq!(
        format!("{:?}", session.direct_tally().ok()),
        format!("{:?}", reconstructed.direct_tally().ok()),
        "tally must match a fresh reconstruction",
    );
    // 6. Also equal via the also-parallel reconstruction path (Slice 4B), so the
    //    invariant holds regardless of which reconstruction path a resume uses.
    let parallel = match GuiElectionSessionV1::from_durable_snapshot_parallel(
        snapshot,
        &HistoricalReplayConfigV1 {
            worker_count: Some(3),
            batch_size: 4,
            parallel_threshold: 0,
        },
    ) {
        Ok(session) => session,
        Err(error) => panic!("parallel reconstruction must succeed: {error}"),
    };
    assert!(
        session.transcript() == parallel.transcript(),
        "transcript must match a parallel reconstruction",
    );
    assert_eq!(session.accepted_count(), parallel.accepted_count());
}

#[test]
fn accepted_ballot_mutation_equals_fresh_reconstruction() {
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn rejected_malformed_ballot_mutation_equals_fresh_reconstruction() {
    let mut session = open_session();
    // A malformed (appended-byte) package is durably stored but rejected.
    let mut malformed = triptych_package_bytes(0, &[b"candidate-a"]);
    malformed.push(0x5a);
    let result = session
        .intake_ballot(&malformed)
        .expect("intake returns a result");
    assert!(!result.accepted, "malformed ballot is rejected");
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn duplicate_nullifier_mutation_equals_fresh_reconstruction() {
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    // Same voter again: valid proof, duplicate nullifier -> rejected, stored.
    let duplicate = session
        .intake_ballot(&triptych_package_bytes(0, &[b"candidate-b"]))
        .unwrap();
    assert!(!duplicate.accepted, "duplicate nullifier is rejected");
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn close_transition_equals_fresh_reconstruction() {
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"]))
            .unwrap()
            .accepted
    );
    session.close().expect("close");
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn verified_transition_equals_fresh_reconstruction() {
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    session.close().expect("close");
    session.mark_verified().expect("mark verified");
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn finalized_transition_equals_fresh_reconstruction() {
    let mut session = open_session();
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"]))
            .unwrap()
            .accepted
    );
    assert!(
        session
            .intake_ballot(&triptych_package_bytes(2, &[b"candidate-c"]))
            .unwrap()
            .accepted
    );
    session.close().expect("close");
    session.mark_verified().expect("mark verified");
    session.finalize().expect("finalize");
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn inbox_reconciliation_mutation_equals_fresh_reconstruction() {
    let mut session = open_session();
    // Reconcile an accepted package from the durable inbox path; identical
    // pipeline to live intake, exercised through its dedicated entry point.
    let package = triptych_package_bytes(1, &[b"candidate-b"]);
    let result = session
        .reconcile_accepted_package_bytes_from_inbox(&package)
        .expect("reconcile returns a result");
    assert!(result.accepted);
    assert_equals_fresh_reconstruction(&session);
}

#[test]
fn many_sequential_mutations_each_equal_fresh_reconstruction() {
    // The invariant must hold at EVERY intermediate committed state, so a chain
    // of same-process advances never drifts from cold reconstruction.
    let mut session = open_session();
    let sequence: Vec<Vec<u8>> = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-c"]), // duplicate
        triptych_package_bytes(2, &[b"candidate-c"]),
    ];
    for package in &sequence {
        let _ = session.intake_ballot(package);
        assert_equals_fresh_reconstruction(&session);
    }
    session.close().expect("close");
    assert_equals_fresh_reconstruction(&session);
}
