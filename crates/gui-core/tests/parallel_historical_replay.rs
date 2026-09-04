//! Performance-remediation Slice 4B: bounded multicore historical verification.
//!
//! These tests prove the load-bearing security property of the slice: the
//! bounded-parallel reconstruction produces an authoritative session that is
//! identical, ballot-for-ballot, to the serial reconstruction — for every
//! ballot mix, worker count, batch size, and (by construction) worker
//! completion order. Cryptographic validity is computed in parallel; the
//! nullifier ledger, first-valid-wins, transcript sequencing, and tally are
//! applied serially in canonical order.

mod common;

use tari_cc_private_ballot_ballot::{ApprovalBallotPayload, BallotPackageV1, BallotPackageV1Input};
use tari_cc_private_ballot_crypto::{TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionSnapshotV1, GuiElectionSessionV1, HistoricalReplayConfigV1,
    global_crypto_worker_budget_v1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, PROTOCOL_VERSION_V1};
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};

use common::{
    candidate_id, candidate_set, manifest, open_session, registry, triptych_package_bytes, voters,
};

/// One terminal lifecycle state to drive a reconstructed snapshot to.
#[derive(Debug, Clone, Copy)]
enum Terminal {
    Open,
    Closed,
    Finalized,
}

fn parallel_config(workers: usize, batch_size: usize) -> HistoricalReplayConfigV1 {
    HistoricalReplayConfigV1 {
        worker_count: Some(workers),
        batch_size,
        parallel_threshold: 0,
    }
}

/// A structurally valid package whose proof authenticates candidate-a for voter
/// 0, but which declares candidate-b: it parses and enters the shared batch, yet
/// is cryptographically invalid for its reconstructed statement (exercises the
/// full-blame fallback end-to-end).
fn crypto_invalid_package_bytes() -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let manifest = manifest();
    let candidates = candidate_set();
    let registry = registry();

    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider) else {
        panic!("fixture verifier must construct");
    };
    let Ok(proved_payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        &candidates,
        manifest.approval_limits(),
    ) else {
        panic!("proved payload must be valid");
    };
    let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &proved_payload, &provider)
    else {
        panic!("statement must reconstruct");
    };
    let Ok(secret) = TariTriptychSecretKeyV1::from_canonical_bytes(voters()[0].secret_bytes) else {
        panic!("fixture secret must be canonical");
    };
    let Ok(proof) = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) else {
        panic!("proof must construct");
    };
    let Ok(declared_payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-b")],
        &candidates,
        manifest.approval_limits(),
    ) else {
        panic!("declared payload must be valid");
    };
    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("manifest hash must derive");
    };
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload: declared_payload,
    }) else {
        panic!("crypto-invalid package must be structurally valid");
    };
    match package.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("crypto-invalid package must encode"),
    }
}

/// A malformed package: valid canonical bytes with an appended trailing byte,
/// rejected at decode (before any crypto), but still durably stored.
fn malformed_package_bytes(voter_index: usize) -> Vec<u8> {
    let mut bytes = triptych_package_bytes(voter_index, &[b"candidate-a"]);
    bytes.push(0x5a);
    bytes
}

/// A rich, deterministic mixed package list exceeding the parallel threshold:
/// three unique accepted voters, a crypto-invalid ballot, a malformed ballot,
/// and many duplicate-nullifier re-votes (valid proofs, ledger-rejected).
fn mixed_packages() -> Vec<Vec<u8>> {
    let mut packages = Vec::new();
    packages.push(triptych_package_bytes(0, &[b"candidate-a"]));
    packages.push(triptych_package_bytes(1, &[b"candidate-b"]));
    packages.push(crypto_invalid_package_bytes());
    packages.push(triptych_package_bytes(2, &[b"candidate-c"]));
    packages.push(malformed_package_bytes(1));
    // Interleave duplicate re-votes from voter 0 (valid proof, duplicate
    // nullifier) with more malformed packages, well past the threshold.
    for index in 0..28 {
        packages.push(triptych_package_bytes(0, &[b"candidate-b"]));
        if index % 7 == 3 {
            packages.push(malformed_package_bytes(2));
        }
    }
    packages
}

fn snapshot_from_packages(
    packages: &[Vec<u8>],
    terminal: Terminal,
) -> GuiElectionSessionSnapshotV1 {
    let mut session = open_session();
    for package in packages {
        let _ = session.intake_ballot(package);
    }
    match terminal {
        Terminal::Open => {}
        Terminal::Closed => {
            if let Err(error) = session.close() {
                panic!("fixture close must succeed: {error}");
            }
        }
        Terminal::Finalized => {
            if session.close().is_err() || session.mark_verified().is_err() {
                panic!("fixture close/verify must succeed");
            }
            if let Err(error) = session.finalize() {
                panic!("fixture finalize must succeed: {error}");
            }
        }
    }
    match session.to_durable_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("fixture snapshot must encode: {error}"),
    }
}

fn reconstruct_serial(snapshot: &GuiElectionSessionSnapshotV1) -> GuiElectionSessionV1 {
    match GuiElectionSessionV1::from_durable_snapshot(snapshot.clone()) {
        Ok(session) => session,
        Err(error) => panic!("serial reconstruction must succeed: {error}"),
    }
}

fn reconstruct_parallel(
    snapshot: &GuiElectionSessionSnapshotV1,
    config: &HistoricalReplayConfigV1,
) -> GuiElectionSessionV1 {
    match GuiElectionSessionV1::from_durable_snapshot_parallel(snapshot.clone(), config) {
        Ok(session) => session,
        Err(error) => panic!("parallel reconstruction must succeed: {error}"),
    }
}

/// Asserts two reconstructed sessions are authoritatively identical: same
/// accepted count, lifecycle, stored packages, full verification transcript
/// (submissions + ordered decisions), and tally.
fn assert_equivalent(expected: &GuiElectionSessionV1, actual: &GuiElectionSessionV1) {
    assert_eq!(
        actual.accepted_count(),
        expected.accepted_count(),
        "accepted count must match serial replay",
    );
    assert_eq!(
        actual.lifecycle_state(),
        expected.lifecycle_state(),
        "lifecycle state must match serial replay",
    );
    assert_eq!(
        actual.packages(),
        expected.packages(),
        "stored package bytes must match serial replay",
    );
    assert!(
        actual.transcript() == expected.transcript(),
        "verification transcript (submissions + ordered decisions) must match serial replay",
    );
    assert_eq!(
        format!("{:?}", actual.direct_tally().ok()),
        format!("{:?}", expected.direct_tally().ok()),
        "tally over the accepted set must match serial replay",
    );
}

#[test]
fn parallel_matches_serial_for_every_worker_count_and_batch_size() {
    let packages = mixed_packages();
    for terminal in [Terminal::Open, Terminal::Closed, Terminal::Finalized] {
        let snapshot = snapshot_from_packages(&packages, terminal);
        let serial = reconstruct_serial(&snapshot);
        // Sanity: the fixture actually accepts the three unique voters.
        assert_eq!(
            serial.accepted_count(),
            3,
            "three unique nullifiers accepted"
        );

        for workers in [1_usize, 2, 3, 4] {
            for batch_size in [1_usize, 4, 16, 64] {
                let config = parallel_config(workers, batch_size);
                let parallel = reconstruct_parallel(&snapshot, &config);
                assert_equivalent(&serial, &parallel);
            }
        }
    }
}

#[test]
fn worker_count_one_reproduces_legacy_serial_semantics() {
    let packages = mixed_packages();
    let snapshot = snapshot_from_packages(&packages, Terminal::Finalized);
    let serial = reconstruct_serial(&snapshot);
    let single_worker = reconstruct_parallel(&snapshot, &parallel_config(1, 8));
    assert_equivalent(&serial, &single_worker);
}

#[test]
fn invalid_proof_does_not_suppress_valid_neighbours() {
    // A crypto-invalid ballot sits between valid ballots; only it is rejected.
    let packages = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        crypto_invalid_package_bytes(),
        triptych_package_bytes(1, &[b"candidate-b"]),
        malformed_package_bytes(2),
        triptych_package_bytes(2, &[b"candidate-c"]),
    ];
    let snapshot = snapshot_from_packages(&packages, Terminal::Closed);
    let serial = reconstruct_serial(&snapshot);

    // Force a single batch containing the invalid proof, across worker counts.
    for workers in [1_usize, 2, 3] {
        let parallel = reconstruct_parallel(&snapshot, &parallel_config(workers, 64));
        assert_equivalent(&serial, &parallel);
        assert_eq!(
            parallel.accepted_count(),
            3,
            "the three distinct valid voters are accepted; neighbours are not suppressed",
        );
        let decisions = parallel.transcript().decisions();
        assert!(decisions[0].outcome().is_accepted(), "voter 0 accepted");
        assert!(
            !decisions[1].outcome().is_accepted(),
            "crypto-invalid rejected"
        );
        assert!(decisions[2].outcome().is_accepted(), "voter 1 accepted");
        assert!(!decisions[3].outcome().is_accepted(), "malformed rejected");
        assert!(decisions[4].outcome().is_accepted(), "voter 2 accepted");
    }
}

#[test]
fn duplicate_nullifier_first_valid_wins_under_parallel() {
    // Voter 0 votes twice (distinct payloads, same nullifier). The FIRST is
    // authoritative regardless of parallelism.
    let packages = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-c"]),
    ];
    let snapshot = snapshot_from_packages(&packages, Terminal::Closed);
    let serial = reconstruct_serial(&snapshot);

    for workers in [1_usize, 2, 4] {
        let parallel = reconstruct_parallel(&snapshot, &parallel_config(workers, 1));
        assert_equivalent(&serial, &parallel);
        let decisions = parallel.transcript().decisions();
        assert!(
            decisions[0].outcome().is_accepted(),
            "first voter-0 ballot wins"
        );
        assert!(
            decisions[1].outcome().is_accepted(),
            "distinct voter-1 ballot accepted"
        );
        assert!(
            !decisions[2].outcome().is_accepted(),
            "second voter-0 ballot is a duplicate and loses",
        );
        assert_eq!(parallel.accepted_count(), 2);
    }
}

#[test]
fn parallel_reconstruction_of_a_draft_snapshot_fails_closed() {
    let packages = mixed_packages();
    let mut snapshot = snapshot_from_packages(&packages, Terminal::Open);
    // Corrupt the lifecycle to an impossible durable state.
    snapshot.lifecycle_state = tari_cc_private_ballot_ballot::ElectionLifecycleStateV1::Draft;
    let result =
        GuiElectionSessionV1::from_durable_snapshot_parallel(snapshot, &parallel_config(4, 8));
    assert!(result.is_err(), "a draft durable snapshot must fail closed");
}

#[test]
fn policy_mode_reconstruction_stays_correct_and_within_the_global_budget() {
    // The production policy (worker_count = None) draws from the shared CPU
    // budget and must still reconstruct identically to serial.
    let packages = mixed_packages();
    let snapshot = snapshot_from_packages(&packages, Terminal::Finalized);
    let serial = reconstruct_serial(&snapshot);

    let policy = HistoricalReplayConfigV1 {
        worker_count: None,
        batch_size: 8,
        parallel_threshold: 0,
    };
    let parallel = reconstruct_parallel(&snapshot, &policy);
    assert_equivalent(&serial, &parallel);
    assert!(
        global_crypto_worker_budget_v1() >= 1,
        "budget reserves at least one worker"
    );
}

#[test]
fn concurrent_reconstructions_of_distinct_elections_are_correct() {
    // Different elections may reconstruct concurrently within the global CPU
    // budget; each must match its own serial replay.
    let packages = mixed_packages();
    let snapshot = snapshot_from_packages(&packages, Terminal::Closed);
    let serial = reconstruct_serial(&snapshot);
    let expected_accepted = serial.accepted_count();
    let expected_transcript = serial.transcript().clone();

    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let snapshot = snapshot.clone();
                let expected_transcript = &expected_transcript;
                scope.spawn(move || {
                    let policy = HistoricalReplayConfigV1 {
                        worker_count: None,
                        batch_size: 4,
                        parallel_threshold: 0,
                    };
                    let session = reconstruct_parallel(&snapshot, &policy);
                    assert_eq!(session.accepted_count(), expected_accepted);
                    assert!(session.transcript() == expected_transcript);
                })
            })
            .collect();
        for handle in handles {
            if handle.join().is_err() {
                panic!("a concurrent reconstruction panicked");
            }
        }
    });
}
