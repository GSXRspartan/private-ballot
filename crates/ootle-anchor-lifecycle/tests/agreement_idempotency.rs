//! M-2 regression: check_agreement terminal idempotency.
//!
//! Calling `check_agreement` after any terminal phase must be an idempotent
//! no-op: the phase, diagnostic, and coordinator snapshots never change, and
//! repeated calls remain no-ops. A `FinalizedAccept` can never be rewound to
//! `FinalizedDisagreement` (or any other terminal) by a late agreement check.

mod common;

use common::{
    LifecycleHarness, accepted_receipt, fee_only_receipt, missing_anchor_log_receipt,
    rejected_receipt,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, AnchorLifecycleRecoverySnapshot, LifecycleStepOutcome,
    UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::FakeReceiptStep;

/// Builds a disagreeing walletd receipt for the given transaction id.
fn disagreeing_walletd_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1 {
    rejected_receipt(tx)
}

#[test]
fn check_agreement_on_finalized_accept_is_noop() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    let diagnostic_before = harness.orchestrator.diagnostic();
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

    let walletd = disagreeing_walletd_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        report_outcome(result.as_ref().ok()),
        LifecycleStepOutcome::IdempotentNoOp
    );
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    assert_eq!(harness.orchestrator.diagnostic(), diagnostic_before);
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

    // Repeated call remains a no-op.
    let result2 = harness.orchestrator.check_agreement(&walletd);
    assert!(result2.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
}

#[test]
fn check_agreement_on_finalized_fee_only_is_noop() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(fee_only_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
    );

    let walletd = disagreeing_walletd_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
    );
}

#[test]
fn check_agreement_on_finalized_reject_is_noop() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(rejected_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedReject
    );

    let walletd = disagreeing_walletd_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedReject
    );
}

#[test]
fn check_agreement_on_finalized_verification_failed_is_noop() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(missing_anchor_log_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );

    let walletd = disagreeing_walletd_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
}

#[test]
fn check_agreement_on_finalized_disagreement_is_noop() {
    // FinalizedDisagreement is not reachable via the live flow (check_agreement
    // is now a no-op on terminals). Construct it via from_snapshots: drive to
    // FinalizedAccept, snapshot, rebuild with FinalizedDisagreement phase.
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    let snapshot = harness.snapshot();
    let disagreement_snapshot = AnchorLifecycleRecoverySnapshot::new(
        snapshot.walletd_snapshots().to_vec(),
        snapshot.receipt_snapshots().to_vec(),
        snapshot.submitted().cloned(),
        snapshot.policy(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement,
        Some("ANCHOR_AGREEMENT_FINAL_STATUS_MISMATCH"),
    );
    let Ok(mut restored) = AnchorLifecycleOrchestrator::from_snapshot(disagreement_snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement
    );

    let walletd = disagreeing_walletd_receipt(&tx);
    let result = restored.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement
    );
}

#[test]
fn check_agreement_on_rejected_by_approver_is_noop() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    let Ok(_) = harness.orchestrator.reject(&mut harness.walletd_client) else {
        panic!("reject must succeed");
    };
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );

    // check_agreement requires a cached receipt, which RejectedByApprover does
    // not have. It returns NotSubmitted — but it must NOT mutate the phase.
    let Ok(valid_id) =
        tari_cc_private_ballot_anchor_transport::AnchorTransactionId::new("0".repeat(64))
    else {
        panic!("valid id")
    };
    let walletd = disagreeing_walletd_receipt(&valid_id);
    let result = restored_check_agreement(&mut harness, &walletd);
    // The result may be Err(NotSubmitted) because there is no cached receipt,
    // but the phase must not change.
    let _ = result;
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
}

fn restored_check_agreement(
    harness: &mut LifecycleHarness,
    walletd: &tari_cc_private_ballot_anchor_transport::AnchorReceiptV1,
) -> Result<
    tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleStepReport,
    tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleError,
> {
    harness.orchestrator.check_agreement(walletd)
}

fn report_outcome(
    report: Option<
        &tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleStepReport,
    >,
) -> LifecycleStepOutcome {
    report
        .map(|r| r.outcome().clone())
        .unwrap_or(LifecycleStepOutcome::IdempotentNoOp)
}
