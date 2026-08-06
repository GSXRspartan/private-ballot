//! Deterministic end-to-end scenarios across the full lifecycle (Section H).
//!
//! Each test scripts both the walletd fake and the indexer receipt fake
//! together, drives the polling policy through an explicit attempt counter
//! (no wall-clock, no sleeping, no async, no randomness), and asserts the
//! resulting unified phase, call counts, and attempts consumed.

mod common;

use common::{
    LifecycleHarness, accepted_receipt, fee_only_receipt, missing_anchor_log_receipt,
    rejected_receipt, walletd_accepted_receipt,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    LifecycleRecoveryOutcome, LifecycleStepOutcome, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{FakeReceiptStep, receipt_scenarios};

#[test]
fn happy_path_prepared_approved_submitted_finalized_accept() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Prepared);

    harness.approve();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Approved);

    let tx = harness.submit();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Submitted);

    // Script an accepted receipt for the sealed transaction id.
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));

    let report = harness.poll_once();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    assert!(report.phase().is_terminal_success());
    assert_eq!(harness.attempts_consumed(), 1);
    assert_eq!(harness.receipt_queries(), 1);
    assert_eq!(harness.submit_calls(), 1);
}

#[test]
fn fee_only_is_distinct_non_success_terminal() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(fee_only_receipt(&tx)));

    let report = harness.poll_once();
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
    );
    assert!(report.phase().is_terminal());
    assert!(!report.phase().is_terminal_success());
}

#[test]
fn rejected_is_distinct_non_success_terminal() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(rejected_receipt(&tx)));

    let report = harness.poll_once();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::FinalizedReject);
    assert!(report.phase().is_terminal());
    assert!(!report.phase().is_terminal_success());
}

#[test]
fn verification_failure_is_distinct_non_success_terminal() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(missing_anchor_log_receipt(&tx)));

    let report = harness.poll_once();
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
    assert!(report.phase().is_terminal());
    assert!(!report.phase().is_terminal_success());
}

#[test]
fn poll_until_found_stale_then_eventual_finalization() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();

    // Sequence: not-found, pending, then finalized-accept.
    harness.script_receipt_sequence(vec![
        FakeReceiptStep::not_found(),
        FakeReceiptStep::pending(),
        FakeReceiptStep::finalized(accepted_receipt(&tx)),
    ]);

    let first = harness.poll_once();
    assert_eq!(
        first.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert_eq!(harness.attempts_consumed(), 1);

    let second = harness.poll_once();
    assert_eq!(
        second.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert_eq!(harness.attempts_consumed(), 2);

    let third = harness.poll_once();
    assert_eq!(third.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    assert_eq!(harness.attempts_consumed(), 3);
    assert_eq!(harness.receipt_queries(), 3);
}

#[test]
fn poll_exhausted_transitions_to_resumable_unknown() {
    let mut harness = LifecycleHarness::new(2);
    let _tx = harness.prepare_approve_submit();
    // Default script is not-found.

    let first = harness.poll_once();
    assert_eq!(
        first.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert_eq!(harness.attempts_consumed(), 1);

    let second = harness.poll_once();
    // Second query consumes the last attempt; the policy is now exhausted.
    assert_eq!(second.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(!second.phase().is_terminal());
    assert_eq!(harness.attempts_consumed(), 2);

    // A third poll is blocked by the exhausted policy.
    let third = harness.poll_once();
    assert_eq!(third.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(matches!(
        third.outcome(),
        LifecycleStepOutcome::PolicyExhausted
    ));
    // No additional query was issued.
    assert_eq!(harness.receipt_queries(), 2);
}

#[test]
fn submit_timeout_then_recover_finds_submitted_id() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();

    // Arm a submit that processes fully (seals a transaction id) but then
    // reports a timeout.
    harness
        .walletd_client
        .inject_submit_timeout_after_processing();

    let result = harness.orchestrator.submit(&mut harness.walletd_client);
    assert!(result.is_err());
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    // The fake sealed internally; the coordinator marked the request
    // timed-out-unknown. Exactly one submit call was made.
    assert_eq!(harness.submit_calls(), 1);

    // Recover resolves the lost result: the status API shows the request
    // was submitted with a sealed transaction id. The driver then calls
    // submit idempotently (no second client call) to obtain the submitted
    // handle.
    let report = harness.recover();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    assert!(matches!(
        report.outcome(),
        LifecycleStepOutcome::Recovered(_)
    ));
    // Still only one submit call to the fake — the idempotent submit after
    // recover does not make a second client call.
    assert_eq!(harness.submit_calls(), 1);

    // The lifecycle can now poll.
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be cached after recover")
    };
    let tx = submitted.transaction_id().clone();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let poll_report = harness.poll_once();
    assert_eq!(
        poll_report.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
}

#[test]
fn submit_timeout_then_recover_proves_never_sealed() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();

    // Arm a submit failure *before* processing (the request is never sealed).
    harness
        .walletd_client
        .inject_submit_error(tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError::SubmitTimeout);

    let result = harness.orchestrator.submit(&mut harness.walletd_client);
    assert!(result.is_err());
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);

    // Recover: the status API shows the request still approved (never sealed).
    let report = harness.recover();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Approved);
    assert!(matches!(
        report.outcome(),
        LifecycleStepOutcome::Recovered(LifecycleRecoveryOutcome::NotSubmittedRetryable)
    ));

    // The caller can now submit again safely.
    let tx = harness.submit();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let poll = harness.poll_once();
    assert_eq!(poll.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn approver_reject_is_terminal() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    let Ok(report) = harness.orchestrator.reject(&mut harness.walletd_client) else {
        panic!("reject must succeed");
    };
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
    assert!(report.phase().is_terminal());

    // Re-driving reject is idempotent.
    let again = harness.orchestrator.reject(&mut harness.walletd_client);
    assert!(again.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
}

#[test]
fn disagreement_check_on_terminal_is_idempotent_noop() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    // Indexer sees a full acceptance.
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    // Walletd disagrees (rejects while indexer accepted). Because the
    // lifecycle is already terminal (FinalizedAccept), check_agreement is
    // an idempotent no-op: the phase never rewinds to FinalizedDisagreement,
    // and the cached receipt evidence is preserved unchanged.
    let walletd = receipt_scenarios::rejected_receipt(&tx, &common::canonical_network());
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    assert!(harness.phase().is_terminal());
    assert!(harness.phase().is_terminal_success());
}

#[test]
fn agreement_ok_when_sources_match() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    let walletd = walletd_accepted_receipt(&tx);
    let result = harness.orchestrator.check_agreement(&walletd);
    assert!(result.is_ok());
    // Agreement OK does not change the phase.
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
}
