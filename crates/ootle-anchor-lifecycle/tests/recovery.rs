//! Recovery and restart/import at every stage (Section F).
//!
//! Each case drives the orchestrator to a stage, snapshots it, rebuilds a
//! fresh orchestrator from the snapshot, and asserts the phase survives and
//! that a subsequent step resumes correctly. After restart the resumed
//! lifecycle must not re-submit, must not rewind a terminal, and must
//! continue polling within the remaining attempt bound.

mod common;

use common::{LifecycleHarness, accepted_receipt};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::FakeReceiptStep;

#[test]
fn restart_at_prepared_not_approved() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    let snapshot = harness.snapshot();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Prepared);

    // Restart from the snapshot.
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Prepared);

    // The restored walletd coordinator has the record in its registry, even
    // though the live fake walletd_client does not (the registry is what
    // `from_snapshots` rebuilt). Verify the phase and registry state.
    assert_eq!(
        restored.walletd_coordinator().registry().snapshots().len(),
        1
    );
}

#[test]
fn restart_at_approved_not_submitted() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();
    let snapshot = harness.snapshot();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Approved);

    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Approved);
    // The restored orchestrator can build a submit request from the
    // walletd snapshot.
    assert!(restored.submitted().is_none());
}

#[test]
fn restart_at_rejected_by_approver() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    let Ok(_) = harness.orchestrator.reject(&mut harness.walletd_client) else {
        panic!("reject must succeed");
    };
    let snapshot = harness.snapshot();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );

    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
    assert!(restored.phase().is_terminal());

    // Re-driving a terminal is idempotent.
    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    let Ok(report) = new_harness
        .orchestrator
        .reject(&mut new_harness.walletd_client)
    else {
        panic!("reject idempotent")
    };
    assert_eq!(
        report.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
}

#[test]
fn restart_at_submitted_receipt_not_yet_queried() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    let snapshot = harness.snapshot();
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Submitted);

    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    assert!(restored.submitted().is_some());
    let Some(submitted) = restored.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx);

    // The restored orchestrator can poll immediately.
    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    new_harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let report = new_harness.poll_once();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn restart_mid_poll_resumes_within_remaining_attempt_bound() {
    let mut harness = LifecycleHarness::new(4);
    let _tx = harness.prepare_approve_submit();
    // Consume two attempts with not-found.
    let first = harness.poll_once();
    assert_eq!(
        first.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    let second = harness.poll_once();
    assert_eq!(
        second.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert_eq!(harness.attempts_consumed(), 2);

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    // The restored policy preserves the consumed attempts.
    assert_eq!(restored.policy().attempts_consumed(), 2);
    assert_eq!(restored.policy().attempts_remaining(), 2);
    assert!(!restored.policy().is_exhausted());

    // Resume polling: two more attempts before exhaustion.
    let mut new_harness = LifecycleHarness::new(4);
    new_harness.orchestrator = restored;
    new_harness.script_receipt(FakeReceiptStep::not_found());
    let third = new_harness.poll_once();
    assert_eq!(
        third.phase(),
        UnifiedAnchorLifecyclePhase::PollingInProgress
    );
    assert_eq!(new_harness.attempts_consumed(), 3);

    let fourth = new_harness.poll_once();
    assert_eq!(fourth.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert_eq!(new_harness.attempts_consumed(), 4);
    // No re-submit occurred.
    assert_eq!(new_harness.submit_calls(), 0);
}

#[test]
fn restart_at_poll_exhausted_unknown_stays_resumable() {
    let mut harness = LifecycleHarness::new(1);
    let _tx = harness.prepare_approve_submit();
    let first = harness.poll_once();
    assert_eq!(first.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(harness.policy().is_exhausted());

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    assert!(restored.policy().is_exhausted());
    assert!(!restored.phase().is_terminal());

    // A further poll is blocked by the exhausted policy.
    let mut new_harness = LifecycleHarness::new(1);
    new_harness.orchestrator = restored;
    let report = new_harness.poll_once();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Unknown);
}

#[test]
fn restart_at_submit_timeout_unknown_pending_recovery() {
    let mut harness = LifecycleHarness::new(5);
    harness.prepare();
    harness.approve();
    harness
        .walletd_client
        .inject_submit_timeout_after_processing();
    let _result = harness.orchestrator.submit(&mut harness.walletd_client);
    assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Unknown);

    // The restored orchestrator can recover.
    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    // The walletd fake from the original harness has the sealed record. We
    // reuse it by moving it.
    new_harness.walletd_client = std::mem::take(&mut harness.walletd_client);
    let report = new_harness.recover();
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    // No second submit client call (idempotent).
    assert_eq!(new_harness.submit_calls(), 1);
}

#[test]
fn restart_at_finalized_accept_is_terminal_idempotent() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );

    let snapshot = harness.snapshot();
    let Ok(mut restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    assert!(restored.phase().is_terminal());

    // Re-driving any step is an idempotent no-op.
    let Ok(report) = restored.advance_one_poll(&mut FakeIndexerReceiptClientLike::new()) else {
        panic!("poll on terminal is no-op")
    };
    assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

/// A trivial indexer-client stand-in for idempotent-no-op assertions on
/// terminals (no query should be issued).
struct FakeIndexerReceiptClientLike {
    count: u64,
}

impl FakeIndexerReceiptClientLike {
    fn new() -> Self {
        Self { count: 0 }
    }
}

impl tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient
    for FakeIndexerReceiptClientLike
{
    fn fetch_anchor_receipt(
        &mut self,
        _query: &tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1,
    ) -> Result<
        tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerReceiptFetchV1,
        tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerReceiptTransportError,
    > {
        self.count += 1;
        Ok(tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerReceiptFetchV1::NotFound)
    }
}

#[test]
fn restart_at_finalized_fee_only_and_reject_are_terminal() {
    // Fee-only.
    {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        harness.script_receipt(FakeReceiptStep::finalized(common::fee_only_receipt(&tx)));
        let _poll = harness.poll_once();
        assert_eq!(
            harness.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
        );

        let snapshot = harness.snapshot();
        let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
            panic!("snapshot must restore")
        };
        assert_eq!(
            restored.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
        );
        assert!(restored.phase().is_terminal());
    }

    // Reject.
    {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        harness.script_receipt(FakeReceiptStep::finalized(common::rejected_receipt(&tx)));
        let _poll = harness.poll_once();
        assert_eq!(
            harness.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedReject
        );

        let snapshot = harness.snapshot();
        let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
            panic!("snapshot must restore")
        };
        assert_eq!(
            restored.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedReject
        );
        assert!(restored.phase().is_terminal());
    }
}

#[test]
fn restart_at_verification_failed_is_terminal() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::finalized(
        common::missing_anchor_log_receipt(&tx),
    ));
    let _poll = harness.poll_once();
    assert_eq!(
        harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
    assert!(restored.phase().is_terminal());
    assert!(!restored.phase().is_terminal_success());
}

#[test]
fn snapshot_round_trips_deterministically() {
    let mut harness = LifecycleHarness::new(5);
    let _tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::not_found());
    let _poll = harness.poll_once();

    let snapshot1 = harness.snapshot();
    let snapshot2 = harness.snapshot();
    assert_eq!(snapshot1, snapshot2);

    // Restore and re-snapshot: the new snapshot equals the original.
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot1.clone()) else {
        panic!("snapshot must restore")
    };
    let snapshot3 = restored.snapshot();
    assert_eq!(snapshot1, snapshot3);
}

#[test]
fn restart_does_not_rewind_phase_or_re_submit() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    harness.script_receipt(FakeReceiptStep::not_found());
    let _poll = harness.poll_once();
    let calls_before = harness.submit_calls();

    let snapshot = harness.snapshot();
    let Ok(restored) = AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore")
    };

    // Build a new harness with the restored orchestrator and the same fake
    // (moved) so we can observe call counts.
    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    new_harness.walletd_client = std::mem::take(&mut harness.walletd_client);
    new_harness.indexer_client = std::mem::take(&mut harness.indexer_client);

    // Polling after restart must not re-submit.
    let _poll2 = new_harness.poll_once();
    assert_eq!(new_harness.submit_calls(), calls_before);
    let Some(submitted) = new_harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some")
    };
    assert_eq!(submitted.transaction_id(), &tx);
}
