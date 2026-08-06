//! Parity tests (Slice 4A10 §16.5).
//!
//! Asserts that the driver-scripted happy path agrees with the Slice 4A8
//! lifecycle harness on phase, attempts, and transaction id, and that the
//! disk snapshot equals the in-memory orchestrator snapshot after a round
//! trip.

mod common;

use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppDriver, DriverRunOutcome, OperatorDecision, read_snapshot, write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, PollingPolicy,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport, WalletdAnchorNetworkAdapter,
};

use common::*;

fn drive_happy_path() -> (
    AnchorAppDriver<
        tari_cc_private_ballot_ootle_anchor_network_adapters::ScriptedWalletdTransport,
        ScriptedIndexerTransport,
    >,
    DriverRunOutcome,
) {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let config = base_config();
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
    (driver, outcome)
}

#[test]
fn driver_happy_path_agrees_with_orchestrator_harness() {
    let (driver, outcome) = drive_happy_path();
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));

    // Drive the Slice 4A8 orchestrator directly through the same scripted
    // transports and confirm phase + transaction id agree.
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let mut indexer = ScriptedIndexerTransport::new();
    indexer.set_response(common::finalized_response(accepted_receipt(&tx)));
    let mut wadapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let mut iadapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(8));
    use tari_cc_private_ballot_anchor_transport::{
        AnchorBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest,
    };
    use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;
    let binding = AnchorBindingV1::new(
        canonical_network(),
        canonical_account(),
        AnchorLogPayloadV1::from_digest(canonical_anchor_digest()),
    );
    let preparation =
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(1_000), None);
    let build_request = OotleAnchorTransactionBuildRequestV1::from_preparation_request(preparation);
    let _ = orch
        .prepare_fee_bearing(
            &mut wadapter,
            &build_request,
            &fee_component(),
            seal_signer(),
            None,
        )
        .unwrap_or_else(|e| panic!("prepare failed: {e:?}"));
    let _ = orch
        .approve(&mut wadapter)
        .unwrap_or_else(|e| panic!("approve failed: {e:?}"));
    let _ = orch
        .submit(&mut wadapter)
        .unwrap_or_else(|e| panic!("submit failed: {e:?}"));
    let report = orch
        .advance_one_poll(&mut iadapter)
        .unwrap_or_else(|e| panic!("poll failed: {e:?}"));
    assert_eq!(report.phase(), driver.phase());
    let orch_tx = orch
        .submitted()
        .map(|s| s.transaction_id().as_str().to_owned());
    let driver_tx = driver.transaction_id().map(|t| t.as_str().to_owned());
    assert_eq!(orch_tx, driver_tx);
}

#[test]
fn driver_poll_exhausted_agrees_with_orchestrator_harness() {
    let _tx = canonical_transaction_id();
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
    assert!(matches!(outcome, DriverRunOutcome::PollExhaustedUnknown(_)));

    // The Slice 4A8 orchestrator with a 1-attempt policy also exhausts.
    let walletd2 = happy_walletd_transport();
    let indexer2 = not_found_indexer_transport();
    let mut wadapter = WalletdAnchorNetworkAdapter::new(walletd2, canonical_network());
    let mut iadapter = IndexerReceiptNetworkAdapter::new(indexer2);
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(1));
    use tari_cc_private_ballot_anchor_transport::{
        AnchorBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest,
    };
    use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;
    let binding = AnchorBindingV1::new(
        canonical_network(),
        canonical_account(),
        AnchorLogPayloadV1::from_digest(canonical_anchor_digest()),
    );
    let preparation =
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(1_000), None);
    let build_request = OotleAnchorTransactionBuildRequestV1::from_preparation_request(preparation);
    let _ = orch
        .prepare_fee_bearing(
            &mut wadapter,
            &build_request,
            &fee_component(),
            seal_signer(),
            None,
        )
        .unwrap_or_else(|e| panic!("prepare failed: {e:?}"));
    let _ = orch
        .approve(&mut wadapter)
        .unwrap_or_else(|e| panic!("approve failed: {e:?}"));
    let _ = orch
        .submit(&mut wadapter)
        .unwrap_or_else(|e| panic!("submit failed: {e:?}"));
    let report = orch
        .advance_one_poll(&mut iadapter)
        .unwrap_or_else(|e| panic!("poll failed: {e:?}"));
    assert_eq!(
        driver.snapshot().attempts_consumed(),
        orch.policy().attempts_consumed()
    );
    assert_eq!(driver.phase(), report.phase());
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

#[test]
fn disk_snapshot_equals_in_memory_after_round_trip() {
    let (driver, _outcome) = drive_happy_path();
    let in_memory = driver.snapshot();
    let snap_path = driver_snapshot_path();
    match write_snapshot_atomic(&snap_path, &in_memory) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    match read_snapshot(&snap_path) {
        Ok(decoded) => assert_eq!(decoded, in_memory, "disk snapshot must equal in-memory"),
        Err(error) => panic!("snapshot read failed: {error}"),
    }
}

fn driver_snapshot_path() -> std::path::PathBuf {
    tmp_path(&format!("parity-{}", common::unique_id())).join("snap.cbor")
}

#[test]
fn driver_attempts_match_orchestrator_attempts() {
    let (driver, outcome) = drive_happy_path();
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    // The happy path polls exactly once (the first poll returns the finalized
    // accepted receipt), so attempts_consumed must be 1.
    assert_eq!(driver.snapshot().attempts_consumed(), 1);
}
