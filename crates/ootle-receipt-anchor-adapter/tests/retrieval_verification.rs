//! Receipt retrieval, final-status mapping, and anchor verification
//! (Sections F, G, K).
//!
//! Every case drives the real submitted-request flow, scripts the deterministic
//! offline fake indexer, and asserts the exact project-owned query state and
//! verification outcome. No case contacts a network and no invalid case panics.

mod common;

use common::{
    canonical_network, canonical_payload, canonical_submitted, payload, query_of, submit,
};
use tari_cc_private_ballot_anchor_transport::{AnchorFinalStatusV1, AnchorQueryOutcomeV1};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptCoordinator, AnchorReceiptQueryStateV1, FakeIndexerReceiptClient, FakeReceiptStep,
    IndexerReceiptTransportError, receipt_scenarios,
};

// ---------------------------------------------------------------------------
// Section G: a full acceptance carrying exactly one valid anchor log verifies.
// ---------------------------------------------------------------------------

#[test]
fn full_acceptance_with_valid_anchor_log_verifies() {
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
    assert!(report.is_verified_success());
    let Some(verified) = report.verified() else {
        panic!("a verified anchor must be present");
    };
    assert_eq!(verified.final_status(), AnchorFinalStatusV1::Accepted);
    assert_eq!(verified.evidence().anchor_digest(), query.anchor_digest());
    assert_eq!(verified.evidence().transaction_id(), &tx);
    // The receipt-query evidence records the derived address, no finality claim.
    assert_eq!(
        verified.address_evidence().receipt_object_key_hex(),
        tx.as_str()
    );
    assert!(matches!(
        report.outcome(),
        AnchorQueryOutcomeV1::Finalized(_)
    ));
}

#[test]
fn full_acceptance_with_unrelated_logs_still_verifies() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_with_unrelated_logs(
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
    assert!(report.is_verified_success());
}

// ---------------------------------------------------------------------------
// Section F: final-status mapping distinguishes accept, fee-only, reject,
// not-found, pending, and timeout-unknown.
// ---------------------------------------------------------------------------

#[test]
fn fee_only_acceptance_never_counts_as_success() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::fee_only_receipt(
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
        AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly
    );
    assert!(!report.is_verified_success());
    assert_eq!(
        report.final_status(),
        Some(AnchorFinalStatusV1::FeeOnlyAccepted)
    );
}

#[test]
fn rejected_receipt_is_terminal_reject_not_not_found() {
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
    assert_ne!(report.state(), AnchorReceiptQueryStateV1::ReceiptNotFound);
    assert!(!report.is_verified_success());
}

#[test]
fn absent_receipt_is_not_found_not_a_failure() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);

    // No script: the fake defaults to not-found.
    let mut client = FakeIndexerReceiptClient::new();
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(report.state(), AnchorReceiptQueryStateV1::ReceiptNotFound);
    assert!(matches!(report.outcome(), AnchorQueryOutcomeV1::NotFound));
    assert!(!report.state().is_terminal());
}

#[test]
fn pending_is_distinct_from_not_found() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(&tx, FakeReceiptStep::pending());
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(report.state(), AnchorReceiptQueryStateV1::ReceiptPending);
    assert!(matches!(
        report.outcome(),
        AnchorQueryOutcomeV1::NotFinalized
    ));
}

#[test]
fn timeout_is_unknown_with_diagnostic() {
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
    assert!(matches!(report.outcome(), AnchorQueryOutcomeV1::Unknown));
    assert_eq!(
        report.diagnostic(),
        Some(IndexerReceiptTransportError::Timeout.as_str())
    );
}

#[test]
fn unavailable_indexer_is_unknown_not_permanent_failure() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);

    let mut client = FakeIndexerReceiptClient::new();
    client.set_unavailable(true);
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(report.state(), AnchorReceiptQueryStateV1::ReceiptUnknown);
    assert!(!report.state().is_terminal());
}

// ---------------------------------------------------------------------------
// Section G/K: malformed / missing / wrong / duplicate / conflicting anchor
// logs on a full acceptance all fail verification (never panic).
// ---------------------------------------------------------------------------

fn assert_verification_failed(receipt: tari_cc_private_ballot_anchor_transport::AnchorReceiptV1) {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();
    assert_eq!(receipt.transaction_id(), &tx, "test receipt must target tx");

    let mut client = FakeIndexerReceiptClient::new();
    client.script(&tx, FakeReceiptStep::finalized(receipt));
    let mut coordinator = AnchorReceiptCoordinator::new();
    let Ok(report) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("query must succeed");
    };
    assert_eq!(
        report.state(),
        AnchorReceiptQueryStateV1::ReceiptVerificationFailed
    );
    assert!(!report.is_verified_success());
    assert!(report.diagnostic().is_some());
}

#[test]
fn missing_anchor_log_fails_verification() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    assert_verification_failed(receipt_scenarios::accepted_missing_anchor_log(
        &tx,
        &canonical_network(),
    ));
}

#[test]
fn malformed_anchor_log_fails_verification() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    assert_verification_failed(receipt_scenarios::accepted_malformed_anchor_log(
        &tx,
        &canonical_network(),
    ));
}

#[test]
fn wrong_digest_anchor_log_fails_verification() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    // A well-formed anchor log for a different digest.
    assert_verification_failed(receipt_scenarios::accepted_wrong_anchor_log(
        &tx,
        &canonical_network(),
        &payload(0x99),
    ));
}

#[test]
fn duplicate_anchor_logs_fail_verification() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    assert_verification_failed(receipt_scenarios::accepted_duplicate_anchor_logs(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    ));
}

#[test]
fn conflicting_anchor_logs_fail_verification() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    assert_verification_failed(receipt_scenarios::accepted_conflicting_anchor_logs(
        &tx,
        &canonical_network(),
        &canonical_payload(),
        &payload(0x99),
    ));
}

#[test]
fn receipt_for_another_transaction_fails_verification() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();
    // Build a receipt whose own transaction id is a different, unrelated one.
    let other = submit("esmeralda", "fee-account", 0x77);
    let other_tx = other.transaction_id().clone();
    assert_ne!(other_tx, tx);

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
            &other_tx,
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
        AnchorReceiptQueryStateV1::ReceiptVerificationFailed
    );
}

#[test]
fn receipt_for_wrong_network_fails_verification() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script(
        &tx,
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
            &tx,
            &common::network("igor"),
            &canonical_payload(),
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
}

// ---------------------------------------------------------------------------
// Section J: a stale result followed by an eventual finalization.
// ---------------------------------------------------------------------------

#[test]
fn stale_pending_then_finalized_progresses_deterministically() {
    let submitted = canonical_submitted();
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();

    let mut client = FakeIndexerReceiptClient::new();
    client.script_sequence(
        &tx,
        vec![
            FakeReceiptStep::not_found(),
            FakeReceiptStep::pending(),
            FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(
                &tx,
                &canonical_network(),
                &canonical_payload(),
            )),
        ],
    );
    let mut coordinator = AnchorReceiptCoordinator::new();

    let Ok(first) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("first query must succeed");
    };
    assert_eq!(first.state(), AnchorReceiptQueryStateV1::ReceiptNotFound);

    let Ok(second) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("second query must succeed");
    };
    assert_eq!(second.state(), AnchorReceiptQueryStateV1::ReceiptPending);

    let Ok(third) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("third query must succeed");
    };
    assert_eq!(
        third.state(),
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
    );
    assert!(third.is_verified_success());

    // A fourth query keeps the terminal finalized outcome (last step repeats).
    let Ok(fourth) = coordinator.query(&mut client, &query, &submitted) else {
        panic!("fourth query must succeed");
    };
    assert_eq!(
        fourth.state(),
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
    );
    assert_eq!(client.call_count(), 4);
    assert_eq!(client.query_count_for(&tx), 4);
}

// ---------------------------------------------------------------------------
// Section A/K: a query paired with the wrong submitted request is refused.
// ---------------------------------------------------------------------------

#[test]
fn query_bound_to_a_different_submitted_request_is_refused() {
    let submitted_a = canonical_submitted();
    let submitted_b = submit("esmeralda", "fee-account", 0x55);
    assert_ne!(submitted_a.transaction_id(), submitted_b.transaction_id());

    let query_a = query_of(&submitted_a);
    let mut client = FakeIndexerReceiptClient::new();
    let mut coordinator = AnchorReceiptCoordinator::new();
    // Revalidating query A against submitted B must fail before any fetch.
    let result = coordinator.query(&mut client, &query_a, &submitted_b);
    assert!(result.is_err());
    assert_eq!(client.call_count(), 0);
}
