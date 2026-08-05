//! Query and recovery state, snapshots, and restart/import (Section I).
//!
//! Each case drives the coordinator to a state, snapshots it, rebuilds a fresh
//! coordinator from the snapshots, and asserts the state survives and that a
//! subsequent query resumes correctly. No case contacts a network.

mod common;

use common::{canonical_network, canonical_payload, canonical_submitted, query_of};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptCoordinator, AnchorReceiptQueryStateV1, FakeIndexerReceiptClient, FakeReceiptStep,
    IndexerReceiptTransportError, receipt_scenarios,
};

#[test]
fn registration_records_submitted_not_queried() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(()) = coordinator.register(&query, &submitted) else {
        panic!("registration must succeed");
    };
    assert_eq!(
        coordinator.registry().state(query.project_request_id()),
        Some(AnchorReceiptQueryStateV1::SubmittedNotQueried)
    );
}

#[test]
fn snapshots_round_trip_through_restart() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
            &tx,
            &canonical_network(),
            &canonical_payload(),
        )),
    );
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(
        report.state(),
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
    );

    let snapshots = coordinator.registry().snapshots();
    assert_eq!(snapshots.len(), 1);
    assert!(snapshots[0].verified());

    let restored = AnchorReceiptCoordinator::from_snapshots(snapshots.clone());
    assert_eq!(
        restored.registry().state(query.project_request_id()),
        Some(AnchorReceiptQueryStateV1::ReceiptFinalizedAccept)
    );
    // The rebuilt snapshots equal the originals (deterministic, comparable).
    assert_eq!(restored.registry().snapshots(), snapshots);
}

#[test]
fn not_found_then_finalized_after_restart_resumes() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    // Before restart: no receipt yet.
    let mut client = FakeIndexerReceiptClient::new();
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(first) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("first query must succeed");
    };
    assert_eq!(first.state(), AnchorReceiptQueryStateV1::ReceiptNotFound);

    // Restart from the snapshot.
    let mut restored = AnchorReceiptCoordinator::from_snapshots(coordinator.registry().snapshots());
    assert_eq!(
        restored.registry().state(query.project_request_id()),
        Some(AnchorReceiptQueryStateV1::ReceiptNotFound)
    );

    // After restart the receipt is now finalized; the query resumes to accept.
    let mut client_after = FakeIndexerReceiptClient::new();
    client_after.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
            &tx,
            &canonical_network(),
            &canonical_payload(),
        )),
    );
    let Ok(second) = restored.query(&mut client_after, &query, &submitted) else {
        panic!("second query must succeed");
    };
    assert_eq!(
        second.state(),
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
    );
    assert!(second.is_verified_success());
}

#[test]
fn timeout_state_survives_restart_and_stays_resumable() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::transport(IndexerReceiptTransportError::Timeout),
    );
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(report.state(), AnchorReceiptQueryStateV1::ReceiptUnknown);

    let restored = AnchorReceiptCoordinator::from_snapshots(coordinator.registry().snapshots());
    let Some(snapshot) = restored.registry().snapshot(query.project_request_id()) else {
        panic!("restored snapshot must exist");
    };
    assert_eq!(snapshot.state(), AnchorReceiptQueryStateV1::ReceiptUnknown);
    assert!(!snapshot.state().is_terminal());
    assert_eq!(
        snapshot.last_diagnostic(),
        Some(IndexerReceiptTransportError::Timeout.as_str())
    );
}

#[test]
fn rejected_and_verification_failed_states_survive_restart() {
    // Rejected.
    {
        let submitted = canonical_submitted();
        let query = query_of(&submitted);
        let tx = submitted.transaction_id().clone();
        let mut client = FakeIndexerReceiptClient::new();
        client.script(
            &tx,
            FakeReceiptStep::finalized(receipt_scenarios::rejected_receipt(
                &tx,
                &canonical_network(),
            )),
        );
        let mut coordinator = AnchorReceiptCoordinator::new();
        let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
            panic!("query must succeed");
        };
        assert_eq!(
            report.state(),
            AnchorReceiptQueryStateV1::ReceiptFinalizedReject
        );
        let restored = AnchorReceiptCoordinator::from_snapshots(coordinator.registry().snapshots());
        assert_eq!(
            restored.registry().state(query.project_request_id()),
            Some(AnchorReceiptQueryStateV1::ReceiptFinalizedReject)
        );
    }

    // Verification failure (missing anchor log on a full acceptance).
    {
        let submitted = canonical_submitted();
        let query = query_of(&submitted);
        let tx = submitted.transaction_id().clone();
        let mut client = FakeIndexerReceiptClient::new();
        client.script(
            &tx,
            FakeReceiptStep::finalized(receipt_scenarios::accepted_missing_anchor_log(
                &tx,
                &canonical_network(),
            )),
        );
        let mut coordinator = AnchorReceiptCoordinator::new();
        let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
            panic!("query must succeed");
        };
        assert_eq!(
            report.state(),
            AnchorReceiptQueryStateV1::ReceiptVerificationFailed
        );
        let restored = AnchorReceiptCoordinator::from_snapshots(coordinator.registry().snapshots());
        assert_eq!(
            restored.registry().state(query.project_request_id()),
            Some(AnchorReceiptQueryStateV1::ReceiptVerificationFailed)
        );
    }
}

#[test]
fn registration_is_idempotent_and_never_rewinds() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
            &tx,
            &canonical_network(),
            &canonical_payload(),
        )),
    );
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(_report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    // Re-registering after a finalized query must not rewind to submitted.
    let Ok(()) = coordinator.register(&query, &submitted) else {
        panic!("re-registration must succeed");
    };
    assert_eq!(
        coordinator.registry().state(query.project_request_id()),
        Some(AnchorReceiptQueryStateV1::ReceiptFinalizedAccept)
    );
}
