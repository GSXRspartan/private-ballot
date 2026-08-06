//! M-3 regression: snapshot phase-consistency invariants.
//!
//! Tests that `AnchorLifecycleOrchestrator::from_snapshot` (and
//! `from_snapshots`) reject inconsistent combinations: a declared phase that
//! cannot be derived from the contained walletd snapshots, receipt snapshots,
//! submitted handle, and polling policy state.
//!
//! Every valid phase is reconstructed successfully from a live harness
//! snapshot. Every mutation below is rejected with a bounded
//! `LifecycleReconstructionError` and never panics.

mod common;

use common::{
    LifecycleHarness, accepted_receipt, account, canonical_network, digest, fee_only_receipt,
    missing_anchor_log_receipt, payload, rejected_receipt,
};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorFinalStatusV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorRequestId, AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, AnchorLifecycleRecoverySnapshot, LifecycleReconstructionError,
    PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::FakeReceiptStep;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, AnchorReceiptQueryV1,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdAnchorBindingV1, WalletdAnchorSnapshotV1,
    WalletdEffectiveStatusV1, WalletdRequestDecisionV1, WalletdRequestId, WalletdSubmissionStateV1,
};

// -- Helpers for building snapshots directly --

fn proj_id() -> AnchorRequestId {
    AnchorRequestId::new("test-request-001".to_owned())
        .unwrap_or_else(|_| panic!("valid request id"))
}

fn walletd_id() -> WalletdRequestId {
    WalletdRequestId::from_walletd(1)
}

fn tx_id(byte: u8) -> AnchorTransactionId {
    let hex: String = std::iter::repeat_n(
        char::from_digit(u32::from(byte >> 4), 16).unwrap_or_else(|| panic!("valid hex digit")),
        64,
    )
    .collect();
    AnchorTransactionId::new(hex).unwrap_or_else(|_| panic!("valid tx id"))
}

fn canonical_tx() -> AnchorTransactionId {
    tx_id(0x44)
}

fn fingerprint() -> OotleAnchorInspectionFingerprintV1 {
    OotleAnchorInspectionFingerprintV1::new([0x55; 32])
}

fn canonical_digest() -> OotleAnchorRecordHashV1 {
    digest(0x22)
}

fn canonical_payload() -> AnchorLogPayloadV1 {
    payload(0x22)
}

fn canonical_account() -> AnchorAccountReference {
    account("fee-account")
}

fn max_fee() -> AnchorMaxFeeV1 {
    AnchorMaxFeeV1::from_units(1_000)
}

fn canonical_binding() -> WalletdAnchorBindingV1 {
    WalletdAnchorBindingV1::new(
        canonical_network(),
        canonical_account(),
        canonical_digest(),
        canonical_payload(),
        max_fee(),
        fingerprint(),
    )
}

fn canonical_submitted() -> SubmittedWalletdAnchorRequestV1 {
    SubmittedWalletdAnchorRequestV1::new(
        proj_id(),
        walletd_id(),
        canonical_tx(),
        canonical_binding(),
    )
}

fn canonical_query() -> AnchorReceiptQueryV1 {
    AnchorReceiptQueryV1::from_submitted(&canonical_submitted())
}

fn walletd_snap(
    decision: WalletdRequestDecisionV1,
    submission: WalletdSubmissionStateV1,
    tx: Option<AnchorTransactionId>,
) -> WalletdAnchorSnapshotV1 {
    let status = tx.is_some().then_some(WalletdEffectiveStatusV1::Submitted);
    WalletdAnchorSnapshotV1::new(
        proj_id(),
        walletd_id(),
        canonical_binding(),
        decision,
        submission,
        tx,
        status,
        0,
        1,
        None,
    )
}

fn receipt_snap(
    state: AnchorReceiptQueryStateV1,
    final_status: Option<AnchorFinalStatusV1>,
    verified: bool,
) -> AnchorReceiptQuerySnapshotV1 {
    AnchorReceiptQuerySnapshotV1::new(canonical_query(), state, final_status, verified, 1, None)
}

// ====================================================================
// Valid reconstruction: one test for every phase
// ====================================================================

#[test]
fn valid_not_prepared() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::NotPrepared,
        None,
    );
    assert!(AnchorLifecycleOrchestrator::from_snapshot(snap).is_ok());
}

#[test]
fn valid_prepared() {
    let mut h = LifecycleHarness::new(5);
    h.prepare();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_approved() {
    let mut h = LifecycleHarness::new(5);
    h.prepare();
    h.approve();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_rejected_by_approver() {
    let mut h = LifecycleHarness::new(5);
    h.prepare();
    let _ = h.orchestrator.reject(&mut h.walletd_client);
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_submitted() {
    let mut h = LifecycleHarness::new(5);
    let _tx = h.prepare_approve_submit();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_polling_in_progress() {
    let mut h = LifecycleHarness::new(5);
    let _tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::not_found());
    let _ = h.poll_once();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_unknown_poll_exhausted() {
    let mut h = LifecycleHarness::new(1);
    let _tx = h.prepare_approve_submit();
    let _ = h.poll_once();
    assert_eq!(h.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_unknown_submit_timeout() {
    let mut h = LifecycleHarness::new(5);
    h.prepare();
    h.approve();
    h.walletd_client.inject_submit_timeout_after_processing();
    let _ = h.orchestrator.submit(&mut h.walletd_client);
    assert_eq!(h.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_finalized_accept() {
    let mut h = LifecycleHarness::new(5);
    let tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _ = h.poll_once();
    assert_eq!(h.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_finalized_fee_only() {
    let mut h = LifecycleHarness::new(5);
    let tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::finalized(fee_only_receipt(&tx)));
    let _ = h.poll_once();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_finalized_reject() {
    let mut h = LifecycleHarness::new(5);
    let tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::finalized(rejected_receipt(&tx)));
    let _ = h.poll_once();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_finalized_verification_failed() {
    let mut h = LifecycleHarness::new(5);
    let tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::finalized(missing_anchor_log_receipt(&tx)));
    let _ = h.poll_once();
    assert!(AnchorLifecycleOrchestrator::from_snapshot(h.snapshot()).is_ok());
}

#[test]
fn valid_finalized_disagreement() {
    let mut h = LifecycleHarness::new(5);
    let tx = h.prepare_approve_submit();
    h.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _ = h.poll_once();
    let snap = h.snapshot();
    let disagreement = AnchorLifecycleRecoverySnapshot::new(
        snap.walletd_snapshots().to_vec(),
        snap.receipt_snapshots().to_vec(),
        snap.submitted().cloned(),
        snap.policy(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement,
        Some("ANCHOR_AGREEMENT_FINAL_STATUS_MISMATCH"),
    );
    assert!(AnchorLifecycleOrchestrator::from_snapshot(disagreement).is_ok());
}

// ====================================================================
// Mutation tests: inconsistent combinations must be rejected
// ====================================================================

#[test]
fn finalized_accept_with_empty_registries_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn finalized_accept_without_submitted_handle_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
            Some(AnchorFinalStatusV1::Accepted),
            true,
        )],
        None,
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    // from_snapshots checks `!receipt_snapshots.is_empty() && submitted.is_none()`
    // before validate_reconstruction, returning MissingSubmittedHandle.
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::MissingSubmittedHandle)
    ));
}

#[test]
fn finalized_accept_with_fee_only_receipt_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly,
            Some(AnchorFinalStatusV1::FeeOnlyAccepted),
            false,
        )],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn finalized_accept_with_unverified_receipt_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
            Some(AnchorFinalStatusV1::Accepted),
            false,
        )],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn submitted_without_submitted_handle_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn submitted_handle_without_walletd_snapshot_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        Some(canonical_submitted()),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    // A submitted handle without a walletd snapshot is rejected with
    // SubmittedHandleWithoutWalletdSnapshot by validate_reconstruction.
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot)
    ));
}

#[test]
fn transaction_id_mismatch_rejected() {
    let wrong_tx = tx_id(0x99);
    let submitted = SubmittedWalletdAnchorRequestV1::new(
        proj_id(),
        walletd_id(),
        wrong_tx,
        canonical_binding(),
    );
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        Vec::new(),
        Some(submitted),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::TransactionIdMismatch)
    ));
}

#[test]
fn binding_mismatch_rejected() {
    let wrong_binding = WalletdAnchorBindingV1::new(
        OotleNetworkIdV1::new("igor".to_owned()).unwrap_or_else(|_| panic!("valid net")),
        canonical_account(),
        canonical_digest(),
        canonical_payload(),
        max_fee(),
        fingerprint(),
    );
    let submitted = SubmittedWalletdAnchorRequestV1::new(
        proj_id(),
        walletd_id(),
        canonical_tx(),
        wrong_binding,
    );
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        Vec::new(),
        Some(submitted),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::BindingMismatch)
    ));
}

#[test]
fn too_many_walletd_snapshots_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![
            walletd_snap(
                WalletdRequestDecisionV1::Prepared,
                WalletdSubmissionStateV1::NotSubmitted,
                None,
            ),
            walletd_snap(
                WalletdRequestDecisionV1::Prepared,
                WalletdSubmissionStateV1::NotSubmitted,
                None,
            ),
        ],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Prepared,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::TooManySnapshots)
    ));
}

#[test]
fn not_prepared_with_walletd_snapshot_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Prepared,
            WalletdSubmissionStateV1::NotSubmitted,
            None,
        )],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::NotPrepared,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn prepared_with_wrong_decision_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::NotSubmitted,
            None,
        )],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Prepared,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn approved_with_receipt_snapshot_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::NotSubmitted,
            None,
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::SubmittedNotQueried,
            None,
            false,
        )],
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Approved,
        None,
    );
    // receipt_snap without submitted handle → MissingSubmittedHandle.
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::MissingSubmittedHandle)
    ));
}

#[test]
fn polling_in_progress_with_zero_attempts_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptNotFound,
            None,
            false,
        )],
        Some(canonical_submitted()),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::PollingInProgress,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PolicyInconsistent)
    ));
}

#[test]
fn polling_in_progress_with_verified_receipt_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
            Some(AnchorFinalStatusV1::Accepted),
            true,
        )],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 2),
        UnifiedAnchorLifecyclePhase::PollingInProgress,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn unknown_with_verified_receipt_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
            Some(AnchorFinalStatusV1::Accepted),
            true,
        )],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 8),
        UnifiedAnchorLifecyclePhase::Unknown,
        Some("POLL_EXHAUSTED"),
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn finalized_fee_only_with_verified_receipt_rejected() {
    let snap = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snap(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(canonical_tx()),
        )],
        vec![receipt_snap(
            AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly,
            Some(AnchorFinalStatusV1::FeeOnlyAccepted),
            true,
        )],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 3),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly,
        None,
    );
    assert!(matches!(
        AnchorLifecycleOrchestrator::from_snapshot(snap),
        Err(LifecycleReconstructionError::PhaseStateMismatch)
    ));
}

#[test]
fn no_panic_on_malformed_combinations() {
    // A batch of impossible combinations; none may panic.
    let cases = vec![
        // FinalizedReject without receipt.
        AnchorLifecycleRecoverySnapshot::new(
            Vec::new(),
            Vec::new(),
            None,
            PollingPolicy::new(8),
            UnifiedAnchorLifecyclePhase::FinalizedReject,
            None,
        ),
        // FinalizedDisagreement without submitted.
        AnchorLifecycleRecoverySnapshot::new(
            Vec::new(),
            Vec::new(),
            None,
            PollingPolicy::new(8),
            UnifiedAnchorLifecyclePhase::FinalizedDisagreement,
            None,
        ),
        // RejectedByApprover with submitted handle.
        AnchorLifecycleRecoverySnapshot::new(
            vec![walletd_snap(
                WalletdRequestDecisionV1::Rejected,
                WalletdSubmissionStateV1::NotSubmitted,
                None,
            )],
            Vec::new(),
            Some(canonical_submitted()),
            PollingPolicy::new(8),
            UnifiedAnchorLifecyclePhase::RejectedByApprover,
            None,
        ),
    ];
    for snap in cases {
        let _ = AnchorLifecycleOrchestrator::from_snapshot(snap);
    }
}

#[test]
fn failed_reconstruction_does_not_contact_transport() {
    // from_snapshot is a pure function of the snapshot fields; it never
    // constructs a client or contacts a transport. This test verifies it
    // returns an error without needing any client.
    let snap = AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    let result = AnchorLifecycleOrchestrator::from_snapshot(snap);
    assert!(result.is_err());
}
