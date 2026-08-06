//! Driver scripted integration tests (Slice 4A10 §16.4).
//!
//! Every scenario drives [`AnchorAppDriver`] through the Slice 4A9 scripted
//! transports. No socket is opened, no real walletd or indexer is contacted,
//! and no transaction is submitted to a live network.

mod common;

use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppDriver, DriverRunOutcome, OperatorDecision, write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport, ScriptedWalletdTransport,
    WalletdAnchorNetworkAdapter,
};

use common::*;

fn build_driver(
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = base_config();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    }
}

fn run(
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
    decision: OperatorDecision,
) -> (
    AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport>,
    DriverRunOutcome,
) {
    let mut driver = build_driver(walletd, indexer);
    let outcome = match driver.run(decision) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    (driver, outcome)
}

#[test]
fn happy_path_finalized_accept() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    match outcome {
        DriverRunOutcome::FinalizedAccept(evidence) => {
            assert_eq!(evidence.final_status(), "ACCEPTED");
            assert_eq!(evidence.receipt_source(), "INDEPENDENT_INDEXER");
        }
        other => panic!("expected FinalizedAccept, got {other:?}"),
    }
}

#[test]
fn fee_only_receipt_is_non_success() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(fee_only_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
    );
    match outcome {
        DriverRunOutcome::FinalizedFeeOnly(evidence) => {
            assert_eq!(evidence.final_status(), "FEE_ONLY_ACCEPTED");
        }
        other => panic!("expected FinalizedFeeOnly, got {other:?}"),
    }
}

#[test]
fn rejected_receipt_is_non_success() {
    // The scripted indexer round-trips a `Finalized(rejected_receipt)` through
    // the Ootle wire `FinalizeOutcome::Commit` (an existing scripted-transport
    // behavior that must not be modified), which would surface as a
    // verification failure rather than a clean reject. The reject scenario is
    // therefore driven through `ScriptedIndexerResponse::Rejected`, which the
    // adapter maps to a finalized rejected receipt via the result-fallback
    // path.
    let _tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = common::rejected_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedReject);
    match outcome {
        DriverRunOutcome::FinalizedReject(evidence) => {
            assert_eq!(evidence.final_status(), "REJECTED");
        }
        other => panic!("expected FinalizedReject, got {other:?}"),
    }
}

#[test]
fn verification_failure_missing_anchor_log() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(missing_anchor_log_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
    match outcome {
        DriverRunOutcome::VerificationFailed(evidence) => {
            assert_eq!(evidence.final_status(), "VERIFICATION_FAILED");
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

#[test]
fn approver_rejection_stops_at_rejected_by_approver() {
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Reject);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
    match outcome {
        DriverRunOutcome::RejectedByApprover(evidence) => {
            assert_eq!(evidence.final_status(), "REJECTED_BY_APPROVER");
        }
        other => panic!("expected RejectedByApprover, got {other:?}"),
    }
}

#[test]
fn no_operator_decision_stops_at_prepared() {
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::NoDecision);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::Prepared);
    match outcome {
        DriverRunOutcome::NotYetFinalized => {}
        other => panic!("expected NotYetFinalized, got {other:?}"),
    }
}

#[test]
fn poll_exhaustion_is_non_success() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let config = exhausted_config();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    };
    let outcome = match driver.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    match outcome {
        DriverRunOutcome::PollExhaustedUnknown(evidence) => {
            assert_eq!(evidence.final_status(), "POLL_EXHAUSTED_UNKNOWN");
        }
        other => panic!("expected PollExhaustedUnknown, got {other:?}"),
    }
    let _ = tx;
}

fn exhausted_config() -> tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig {
    use tari_cc_private_ballot_ootle_anchor_network_adapters::NetworkAdapterConfig;
    let adapter = match NetworkAdapterConfig::new(
        canonical_network(),
        walletd_endpoint(),
        indexer_endpoint(),
        fee_component(),
        seal_signer(),
        max_fee(),
        Some(30),
        1,
        None,
    ) {
        Ok(config) => config,
        Err(_) => panic!("adapter must construct"),
    };
    tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig::new(
        adapter,
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
    )
}

fn restore_from_snapshot(
    snapshot: &tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = base_config();
    let snap_path = config.snapshot_path().to_owned();
    match write_snapshot_atomic(&snap_path, snapshot) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    let walletd = happy_walletd_transport();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    match AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("restore failed: {error}"),
    }
}

#[test]
fn restart_after_submission_before_first_poll() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept after restart, got {other:?}"),
    }
}

#[test]
fn restart_mid_poll() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&polling_in_progress_snapshot(2), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept after mid-poll restart, got {other:?}"),
    }
}

#[test]
fn restart_after_finalized_accept_is_idempotent() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&known_answer_snapshot(), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept idempotent, got {other:?}"),
    }
}

#[test]
fn transaction_id_remains_stable_across_restart() {
    let tx = canonical_transaction_id();
    let before = canonical_transaction_id().as_str().to_owned();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let after = restored.transaction_id().map(|t| t.as_str().to_owned());
    assert_eq!(
        Some(before),
        after,
        "transaction id must remain stable across restart"
    );
}

#[test]
fn fingerprint_remains_stable_across_restart() {
    let tx = canonical_transaction_id();
    let snapshot = submitted_snapshot();
    let fingerprint_before = snapshot
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let restored = restore_from_snapshot(&snapshot, indexer);
    let fingerprint_after = restored
        .snapshot()
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    assert_eq!(
        fingerprint_before, fingerprint_after,
        "fingerprint must remain stable"
    );
}

#[test]
fn no_duplicate_transaction_on_restart() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let submits_before = restored.walletd_adapter().transport().submit_calls();
    let _ = restored.run(OperatorDecision::Approve);
    let submits_after = restored.walletd_adapter().transport().submit_calls();
    assert_eq!(
        submits_before, submits_after,
        "restored driver must not resubmit an already-submitted request"
    );
}

#[test]
fn evidence_file_written_on_terminal_accept() {
    let config = base_config();
    let ev_path = config.evidence_path().to_owned();
    let _ = std::fs::remove_file(&ev_path);
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    };
    let outcome = match driver.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    assert!(
        ev_path.exists(),
        "evidence file must be written on terminal accept"
    );
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn snapshot_file_written_after_run() {
    let config = base_config();
    let snap_path = config.snapshot_path().to_owned();
    let _ = std::fs::remove_file(&snap_path);
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    };
    let outcome = match driver.run(OperatorDecision::NoDecision) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert!(matches!(outcome, DriverRunOutcome::NotYetFinalized));
    assert!(
        snap_path.exists(),
        "snapshot file must be written after run"
    );
    let _ = driver;
}

#[test]
fn snapshot_round_trip_after_run() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    let snapshot = driver.snapshot();
    let snap_path = snapshot_path();
    match write_snapshot_atomic(&snap_path, &snapshot) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    match tari_cc_private_ballot_ootle_anchor_app::read_snapshot(&snap_path) {
        Ok(decoded) => assert_eq!(decoded, snapshot, "snapshot must round-trip after run"),
        Err(error) => panic!("snapshot read failed: {error}"),
    }
}
