//! Bounded single-step driver tests for the GUI publish boundary.
//!
//! [`AnchorAppDriver::run_single_step`] must perform at most one lifecycle
//! transition, never sleep, persist the same durable snapshots as
//! [`AnchorAppDriver::run`], and produce byte-identical terminal artifacts.
//! Every scenario is offline and deterministic (scripted transports).

#![cfg(feature = "test-support")]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppDriver, DriverError, DriverRunOutcome, OperatorDecision, VerifiedRuntimeArchiveFactsV1,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport, ScriptedWalletdResponse,
    ScriptedWalletdTransport, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1;

use common::*;

fn build_driver_with(
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = live_config();
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver.with_runtime_archive_for_test(runtime),
        Err(error) => panic!("driver construction failed: {error:?}"),
    }
}

fn read_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|_| panic!("artifact must read: {}", path.display()))
}

#[test]
fn single_step_prepares_once_and_stops_on_no_decision() {
    let mut driver = build_driver_with(happy_walletd_transport(), not_found_indexer_transport());

    let first = driver
        .run_single_step(OperatorDecision::NoDecision)
        .expect("first single step must succeed");
    assert_eq!(first.outcome, None);
    assert_eq!(first.phase, UnifiedAnchorLifecyclePhase::Prepared);
    assert_eq!(first.next_backoff_secs, None);
    assert_eq!(
        driver.walletd_adapter().transport().create_calls(),
        1,
        "prepare must call walletd exactly once"
    );

    let second = driver
        .run_single_step(OperatorDecision::NoDecision)
        .expect("second single step must succeed");
    assert_eq!(second.outcome, Some(DriverRunOutcome::NotYetFinalized));
    assert_eq!(second.phase, UnifiedAnchorLifecyclePhase::Prepared);
    assert_eq!(
        driver.walletd_adapter().transport().create_calls(),
        1,
        "no duplicate prepare when stopping at NoDecision"
    );
}

#[test]
fn single_step_reaches_finalized_accept_without_sleeping() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut driver = build_driver_with(walletd, indexer);

    let started = Instant::now();
    let mut terminal = None;
    for _ in 0..8 {
        let step = driver
            .run_single_step(OperatorDecision::Approve)
            .expect("single step must succeed");
        if let Some(outcome) = step.outcome {
            terminal = Some(outcome);
            break;
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "single steps must never sleep; took {elapsed:?}"
    );
    match terminal {
        Some(DriverRunOutcome::FinalizedAccept(evidence)) => {
            assert_eq!(evidence.final_status(), "ACCEPTED");
        }
        other => panic!("expected FinalizedAccept, got {other:?}"),
    }
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    assert!(driver.evidence_path().is_file());

    // Re-running the terminal phase is idempotent and rewrites identical
    // evidence bytes.
    let before = read_bytes(driver.evidence_path());
    let again = driver
        .run_single_step(OperatorDecision::Approve)
        .expect("terminal single step must succeed");
    match again.outcome {
        Some(DriverRunOutcome::FinalizedAccept(_)) => {}
        other => panic!("expected idempotent FinalizedAccept, got {other:?}"),
    }
    assert_eq!(before, read_bytes(driver.evidence_path()));
}

#[test]
fn single_step_pending_poll_reports_backoff_without_sleeping() {
    let mut driver = build_driver_with(happy_walletd_transport(), not_found_indexer_transport());

    // Drive to Submitted.
    loop {
        let step = driver
            .run_single_step(OperatorDecision::Approve)
            .expect("drive-to-submit step must succeed");
        assert!(step.outcome.is_none());
        if step.phase == UnifiedAnchorLifecyclePhase::Submitted {
            break;
        }
    }

    let started = Instant::now();
    let miss = driver
        .run_single_step(OperatorDecision::NoDecision)
        .expect("pending poll step must succeed");
    let elapsed = started.elapsed();

    assert!(miss.outcome.is_none());
    assert_eq!(miss.phase, UnifiedAnchorLifecyclePhase::PollingInProgress);
    assert_eq!(
        miss.next_backoff_secs,
        Some(1),
        "live_config backoff base is one second"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "poll step reported backoff but must not sleep; took {elapsed:?}"
    );
}

#[test]
fn stepped_lifecycle_produces_identical_artifacts_to_run() {
    let tx = canonical_transaction_id();

    let mut run_driver = build_driver_with(
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    );
    let run_outcome = run_driver
        .run(OperatorDecision::Approve)
        .expect("baseline run must succeed");
    let run_evidence_path: PathBuf = run_driver.evidence_path().to_owned();
    let run_snapshot_path: PathBuf = run_driver.snapshot_path().to_owned();

    let mut stepped_driver = build_driver_with(
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    );
    let stepped_snapshot_path: PathBuf = stepped_driver.snapshot_path().to_owned();
    let mut stepped_outcome = None;
    for _ in 0..16 {
        let step = stepped_driver
            .run_single_step(OperatorDecision::Approve)
            .expect("stepped drive must succeed");
        if let Some(outcome) = step.outcome {
            stepped_outcome = Some(outcome);
            break;
        }
    }
    let stepped_outcome = stepped_outcome.expect("stepped drive must reach a terminal outcome");

    assert_eq!(
        read_bytes(&run_evidence_path),
        read_bytes(stepped_driver.evidence_path()),
        "terminal evidence must be byte-identical across run styles"
    );
    assert_eq!(
        read_bytes(&run_snapshot_path),
        read_bytes(&stepped_snapshot_path),
        "recovery snapshots must be byte-identical across run styles"
    );
    match (&run_outcome, &stepped_outcome) {
        (DriverRunOutcome::FinalizedAccept(a), DriverRunOutcome::FinalizedAccept(b)) => {
            assert_eq!(a.final_status(), b.final_status());
        }
        _ => panic!("both drives must finalize accept"),
    }
}

#[test]
fn single_step_reject_writes_terminal_rejected_evidence() {
    let mut transport = happy_walletd_transport();
    transport.set_reject_response(ScriptedWalletdResponse::Reject {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Rejected,
    });
    let mut driver = build_driver_with(transport, not_found_indexer_transport());

    let prepared = driver
        .run_single_step(OperatorDecision::NoDecision)
        .expect("prepare step must succeed");
    assert!(prepared.outcome.is_none());

    let rejected = driver
        .run_single_step(OperatorDecision::Reject)
        .expect("reject step must succeed");
    match rejected.outcome {
        Some(DriverRunOutcome::RejectedByApprover(evidence)) => {
            assert_eq!(
                driver.phase(),
                UnifiedAnchorLifecyclePhase::RejectedByApprover
            );
            assert!(driver.evidence_path().is_file());
            assert_eq!(evidence.final_status(), "REJECTED_BY_APPROVER");
        }
        other => panic!("expected RejectedByApprover, got {other:?}"),
    }
}

#[test]
fn single_step_requires_runtime_archive_before_any_network_action() {
    let config = live_config();
    let walletd_adapter =
        WalletdAnchorNetworkAdapter::new(happy_walletd_transport(), canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(not_found_indexer_transport());
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error:?}"),
    };

    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("live config without runtime archive facts must be rejected");

    assert_eq!(error, DriverError::RuntimeArchiveRequired);
}
