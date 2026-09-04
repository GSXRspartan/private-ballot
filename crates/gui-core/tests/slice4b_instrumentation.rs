//! Slice 4B instrumentation regression, isolated in its own binary so the
//! process-global reconstruction counters are read without a sibling test
//! mutating them concurrently.

mod common;

use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, HistoricalReplayConfigV1, instrumentation,
};

use common::{open_session, triptych_package_bytes};

fn malformed_package_bytes(voter_index: usize) -> Vec<u8> {
    let mut bytes = triptych_package_bytes(voter_index, &[b"candidate-a"]);
    bytes.push(0x5a);
    bytes
}

#[test]
fn parallel_reconstruction_instrumentation_counts_are_exact() {
    // 3 unique accepted + 1 malformed (never reaches crypto) + 26 duplicate
    // re-votes (valid proofs, ledger-rejected) = 30 stored packages.
    let mut packages = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(2, &[b"candidate-c"]),
        malformed_package_bytes(1),
    ];
    for _ in 0..26 {
        packages.push(triptych_package_bytes(0, &[b"candidate-b"]));
    }
    let package_count = packages.len() as u64;

    let mut session = open_session();
    for package in &packages {
        let _ = session.intake_ballot(package);
    }
    if let Err(error) = session.close() {
        panic!("fixture close must succeed: {error}");
    }
    let snapshot = match session.to_durable_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("fixture snapshot must encode: {error}"),
    };

    let config = HistoricalReplayConfigV1 {
        worker_count: Some(3),
        batch_size: 8,
        parallel_threshold: 0,
    };

    instrumentation::reset();
    let reconstructed =
        match GuiElectionSessionV1::from_durable_snapshot_parallel(snapshot, &config) {
            Ok(session) => session,
            Err(error) => panic!("parallel reconstruction must succeed: {error}"),
        };
    let counters = instrumentation::snapshot();

    assert_eq!(
        reconstructed.accepted_count(),
        3,
        "three unique nullifiers accepted"
    );
    assert_eq!(
        counters.from_durable_snapshot_calls, 1,
        "one reconstruction ran"
    );
    assert_eq!(
        counters.historical_parallel_reconstruction_count, 1,
        "the parallel path engaged exactly once",
    );
    assert_eq!(
        counters.historical_ballots_replayed, package_count,
        "every stored package is replayed once",
    );
    assert_eq!(
        counters.triptych_verify_calls, package_count,
        "the intake pipeline counts one verification per package",
    );
    assert_eq!(
        counters.historical_serial_order_apply_count, package_count,
        "every package is applied to the authoritative session in canonical order",
    );
    assert!(
        counters.historical_crypto_workers_used >= 1
            && counters.historical_crypto_workers_used <= 3,
        "workers are bounded by the forced count of 3",
    );
    assert!(
        counters.historical_crypto_batches >= 1,
        "at least one shared verification batch ran",
    );
    assert_eq!(
        counters.historical_crypto_proofs,
        package_count - 1,
        "every well-formed package's proof enters a shared batch",
    );
    assert!(
        counters.verifier_context_build_count >= 1,
        "the immutable election context was built",
    );
    assert!(
        counters.verifier_context_reuse_count >= 1,
        "the immutable election context was reused across ballots",
    );
    assert_eq!(
        counters.triptych_adapter_verify_calls,
        package_count - 1,
        "exactly the well-formed packages reach the Triptych verifier adapter",
    );
}
