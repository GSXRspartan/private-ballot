//! Safety and mutation tests (Section I).
//!
//! These tests prove the orchestrator:
//! * never blind-resubmits an ambiguous submit (always routes through
//!   `recover`);
//! * never creates a second distinct transaction under duplicate drive,
//!   restart, or retry;
//! * treats fee-only, rejected, and verification-failure as distinct
//!   non-success terminals, never as `FinalizedAccept`;
//! * treats not-found/pending/timeout as resumable, never as permanent
//!   failure;
//! * exhausts the attempt bound to a resumable `Unknown`, never to success;
//! * surfaces walletd/indexer disagreement without mutating any artifact.
//!
//! No invalid case may panic. No invalid case may mutate the archive, anchor
//! record, `ArchiveHashV1`, `ManifestHash`, submitted transaction id,
//! unsigned-transaction fingerprint, or any prior verified receipt evidence.

mod common;

use common::{
    LifecycleHarness, accepted_receipt, fee_only_receipt, missing_anchor_log_receipt,
    rejected_receipt, walletd_accepted_receipt,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, LifecycleStepOutcome, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::FakeReceiptStep;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError;

#[test]
fn ambiguous_submit_always_routes_through_recover_never_blind_resubmit() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();

    // Inject a submit timeout after processing (the request is sealed but the
    // response is lost).
    harness
        .walletd_client
        .inject_submit_timeout_after_processing();
    let result = harness.orchestrator.submit(&mut harness.walletd_client);
    assert!(result.is_err());
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    let submit_calls_after_timeout = harness.submit_calls();
    assert_eq!(submit_calls_after_timeout, 1);

    // Calling submit again on Unknown is NOT allowed — the orchestrator
    // requires recover first.
    let second = harness.orchestrator.submit(&mut harness.walletd_client);
    assert!(second.is_err());
    // No additional submit call was made.
    assert_eq!(harness.submit_calls(), submit_calls_after_timeout);

    // Recover resolves it and calls submit idempotently (no second client
    // call).
    let report = harness.recover();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    assert_eq!(harness.submit_calls(), submit_calls_after_timeout);
}

#[test]
fn duplicate_drive_never_creates_second_distinct_transaction() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    let submit_calls = harness.submit_calls();
    assert_eq!(submit_calls, 1);

    // Driving submit again is an idempotent no-op (already submitted).
    let Ok(report) = harness
        .orchestrator
        .submit(&mut harness.walletd_client)
    else {
        panic!("idempotent")
    };
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    assert!(matches!(
        report.outcome(),
        LifecycleStepOutcome::IdempotentNoOp
    ));
    assert_eq!(harness.submit_calls(), submit_calls);

    // The transaction id is unchanged.
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx);
}

#[test]
fn restart_never_creates_second_distinct_transaction() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };

    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    new_harness.walletd_client = std::mem::take(&mut harness.walletd_client);

    // Polling after restart does not re-submit.
    new_harness.script_receipt(FakeReceiptStep::not_found());
    let _poll = new_harness.poll_once();
    assert_eq!(new_harness.submit_calls(), 1);
    let Some(submitted) = new_harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx);
}

#[test]
fn retry_after_recover_never_submitted_uses_same_transaction() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();

    // Submit fails before processing (never sealed).
    harness
        .walletd_client
        .inject_submit_error(WalletdAnchorAdapterError::SubmitTimeout);
    let _ = harness.orchestrator.submit(&mut harness.walletd_client);
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);

    // Recover proves never sealed → back to Approved.
    let report = harness.recover();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Approved);

    // Submit again — this creates the transaction now.
    let tx = harness.submit();
    assert_eq!(harness.submit_calls(), 2);

    // A second submit is idempotent.
    let Ok(_idempotent) = harness
        .orchestrator
        .submit(&mut harness.walletd_client)
    else {
        panic!("idempotent")
    };
    assert_eq!(harness.submit_calls(), 2);
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx);
}

#[test]
fn fee_only_rejected_verification_failure_are_never_finalized_accept() {
    let cases: &[(&str, common::ReceiptBuilder, UnifiedAnchorLifecyclePhase)] = &[
        (
            "fee-only",
            fee_only_receipt,
            UnifiedAnchorLifecyclePhase::FinalizedFeeOnly,
        ),
        (
            "rejected",
            rejected_receipt,
            UnifiedAnchorLifecyclePhase::FinalizedReject,
        ),
        (
            "verification-failure",
            missing_anchor_log_receipt,
            UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed,
        ),
    ];

    for (label, builder, expected) in cases {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        harness.script_receipt(FakeReceiptStep::finalized(builder(&tx)));
        let report = harness.poll_once();
        assert_eq!(report.phase(), *expected, "case {label}");
        assert!(!report.phase().is_terminal_success(), "case {label}");
        assert!(report.phase().is_terminal(), "case {label}");
        assert_ne!(
            report.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedAccept,
            "case {label}"
        );
    }
}

#[test]
fn not_found_pending_timeout_are_resumable_never_permanent_failure() {
    let mut harness = LifecycleHarness::new(5);
    let _tx = harness.prepare_approve_submit();

    // Not-found.
    harness.script_receipt(FakeReceiptStep::not_found());
    let report = harness.poll_once();
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert!(!report.phase().is_terminal());

    // Pending.
    harness.script_receipt(FakeReceiptStep::pending());
    let report = harness.poll_once();
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert!(!report.phase().is_terminal());

    // Timeout (transport error).
    harness.script_receipt(FakeReceiptStep::transport(
        tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerReceiptTransportError::Timeout,
    ));
    let report = harness.poll_once();
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert!(!report.phase().is_terminal());
}

#[test]
fn poll_exhausted_is_resumable_unknown_never_success() {
    let mut harness = LifecycleHarness::new(1);
    let _tx = harness.prepare_approve_submit();

    let report = harness.poll_once();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(!report.phase().is_terminal());
    assert!(!report.phase().is_terminal_success());

    // Further polls are blocked by the policy.
    let blocked = harness.poll_once();
    assert_eq!(blocked.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(matches!(
        blocked.outcome(),
        LifecycleStepOutcome::PolicyExhausted
    ));
}

#[test]
fn disagreement_does_not_mutate_artifacts() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();

    // Capture the state before disagreement.
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    let tx_before = submitted.transaction_id().clone();
    let fingerprint_before = submitted.binding().fingerprint();
    let walletd_snapshots_before = harness
        .orchestrator
        .walletd_coordinator()
        .registry()
        .snapshots();
    let receipt_snapshots_before = harness
        .orchestrator
        .receipt_coordinator()
        .registry()
        .snapshots();

    // Walletd disagrees (rejects while indexer accepted).
    let walletd = rejected_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_err());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement
    );

    // The submitted transaction id and fingerprint are unchanged.
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);

    // The coordinator snapshots are unchanged (no mutation).
    assert_eq!(
        harness
            .orchestrator
            .walletd_coordinator()
            .registry()
            .snapshots(),
        walletd_snapshots_before
    );
    assert_eq!(
        harness
            .orchestrator
            .receipt_coordinator()
            .registry()
            .snapshots(),
        receipt_snapshots_before
    );
}

#[test]
fn disagreement_does_not_convert_verified_acceptance_into_failure_of_artifacts() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    // The receipt coordinator's verified evidence is still recorded.
    let Some(receipt_snapshot) = harness
        .orchestrator
        .receipt_coordinator()
        .registry()
        .snapshots()
        .into_iter()
        .next()
    else {
        panic!("receipt snapshot must exist")
    };
    assert!(receipt_snapshot.verified());

    // Disagreement surfaces but the verified evidence is preserved.
    let walletd = rejected_receipt(&tx);
    let _ = harness.orchestrator.check_agreement(&walletd);
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement
    );

    let Some(receipt_snapshot_after) = harness
        .orchestrator
        .receipt_coordinator()
        .registry()
        .snapshots()
        .into_iter()
        .next()
    else {
        panic!("receipt snapshot must still exist")
    };
    assert!(receipt_snapshot_after.verified());
    assert_eq!(receipt_snapshot, receipt_snapshot_after);
}

#[test]
fn no_panic_on_invalid_cases() {
    // approve before prepare.
    let mut harness = LifecycleHarness::new(5);
    let result = harness.orchestrator.approve(&mut harness.walletd_client);
    assert!(result.is_err());

    // submit before approve.
    let result = harness.orchestrator.submit(&mut harness.walletd_client);
    assert!(result.is_err());

    // poll before submit.
    let result = harness
        .orchestrator
        .advance_one_poll(&mut harness.indexer_client);
    assert!(result.is_err());

    // recover before any submit-unknown.
    let result = harness.orchestrator.recover(&mut harness.walletd_client);
    assert!(result.is_err());

    // agreement before any receipt.
    let Ok(valid_id) = tari_cc_private_ballot_anchor_transport::AnchorTransactionId::new(
        "0".repeat(64),
    ) else {
        panic!("valid id")
    };
    let result = harness
        .orchestrator
        .check_agreement(&walletd_accepted_receipt(&valid_id));
    assert!(result.is_err());
}
