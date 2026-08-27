//! H-1 regression: config/snapshot/evidence binding validation.
//!
//! Tests that restore-time binding validation rejects a config that does not
//! match the immutable anchor binding recorded in the persisted snapshot, and
//! that a successful restore produces byte-identical evidence to the pre-repair
//! behavior. A mismatch never contacts a scripted transport and never mutates
//! the snapshot, evidence, transaction ID, or fingerprint.

#![cfg(feature = "test-support")]

mod common;

use common::*;
use std::path::PathBuf;
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, DriverError, DriverRunOutcome, OperatorDecision,
    VerifiedRuntimeArchiveFactsV1, write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, NetworkAdapterConfig, ScriptedIndexerTransport,
    ScriptedWalletdTransport, WalletdAnchorNetworkAdapter,
};

fn try_restore(
    config: AnchorAppConfig,
) -> Result<AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport>, DriverError> {
    let walletd = happy_walletd_transport();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer = finalized_indexer_transport(accepted_receipt(&canonical_transaction_id()));
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter)
}

fn adapter_with_max_fee(max_fee_value: u64) -> NetworkAdapterConfig {
    NetworkAdapterConfig::new(
        canonical_network(),
        walletd_endpoint(),
        indexer_endpoint(),
        fee_component(),
        seal_signer(),
        AnchorMaxFeeV1::from_units(max_fee_value),
        Some(30),
        8,
        None,
    )
    .unwrap_or_else(|e| panic!("adapter must construct: {e}"))
}

fn base_config_with_paths(snap_path: PathBuf, ev_path: PathBuf) -> AnchorAppConfig {
    AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
    )
}

fn live_config_with_paths(snap_path: PathBuf, ev_path: PathBuf) -> AnchorAppConfig {
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
        live_approval_facts(),
    )
}

#[test]
fn restore_with_different_network_rejected() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        network("igor"),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "different network must be rejected"
    );
}

#[test]
fn restore_with_different_account_rejected() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        account("other-account"),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "different account must be rejected"
    );
}

#[test]
fn restore_with_different_archive_hash_rejected() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        archive_hash(0x99),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "different archive hash must be rejected"
    );
}

#[test]
fn restore_with_different_manifest_hash_rejected() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        manifest_hash(0x99),
        canonical_archive_hash(),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "different manifest hash must be rejected"
    );
}

#[test]
fn restore_with_different_max_fee_rejected() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        adapter_with_max_fee(2_000),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "different max fee must be rejected"
    );
}

#[test]
fn restore_with_unchanged_config_succeeds() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let config = base_config_with_paths(snap_path, ev_path);
    let result = try_restore(config);
    assert!(result.is_ok(), "unchanged config must restore successfully");
}

#[test]
fn restore_produces_byte_identical_evidence() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    let tx = canonical_transaction_id();

    let config = live_config_with_paths(snap_path.clone(), ev_path.clone());
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = AnchorAppDriver::new(config, walletd_adapter, indexer_adapter)
        .unwrap_or_else(|e| panic!("driver construction failed: {e}"))
        .with_runtime_archive_for_test(runtime);
    let outcome = driver
        .run(OperatorDecision::Approve)
        .unwrap_or_else(|e| panic!("driver run failed: {e}"));
    let evidence_fresh = match outcome {
        DriverRunOutcome::FinalizedAccept(e) => e,
        _ => panic!("expected FinalizedAccept"),
    };

    let config2 = live_config_with_paths(snap_path, ev_path);
    let runtime2 = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config2)
        .expect("live config must provide runtime facts");
    let walletd2 = happy_walletd_transport();
    let indexer2 = finalized_indexer_transport(accepted_receipt(&tx));
    let walletd_adapter2 = WalletdAnchorNetworkAdapter::new(walletd2, canonical_network());
    let indexer_adapter2 = IndexerReceiptNetworkAdapter::new(indexer2);
    let mut restored = AnchorAppDriver::restore(config2, walletd_adapter2, indexer_adapter2)
        .unwrap_or_else(|e| panic!("restore failed: {e}"))
        .with_runtime_archive_for_test(runtime2);
    let outcome2 = restored
        .run(OperatorDecision::Approve)
        .unwrap_or_else(|e| panic!("restored run failed: {e}"));
    let evidence_restored = match outcome2 {
        DriverRunOutcome::FinalizedAccept(e) => e,
        _ => panic!("expected FinalizedAccept after restore"),
    };

    assert_eq!(
        evidence_fresh.canonical_bytes(),
        evidence_restored.canonical_bytes(),
        "evidence must be byte-identical after restore"
    );
}

#[test]
fn mismatch_does_not_mutate_snapshot() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));
    let bytes_before = std::fs::read(&snap_path).unwrap_or_else(|e| panic!("read: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        network("igor"),
        snap_path.clone(),
        ev_path,
        1,
        1,
        None,
    );
    let _ = try_restore(mismatched);

    let bytes_after = std::fs::read(&snap_path).unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        bytes_before, bytes_after,
        "snapshot must not be mutated on binding mismatch"
    );
}

#[test]
fn mismatch_does_not_contact_transport() {
    let snap_path = snapshot_path();
    let ev_path = evidence_path();
    write_snapshot_atomic(&snap_path, &known_answer_snapshot())
        .unwrap_or_else(|e| panic!("snapshot write failed: {e}"));

    let mismatched = AnchorAppConfig::new_archive_verified(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        network("igor"),
        snap_path,
        ev_path,
        1,
        1,
        None,
    );
    let result = try_restore(mismatched);
    assert!(
        matches!(result, Err(DriverError::ConfigSnapshotBindingMismatch)),
        "mismatch must be rejected before any transport contact"
    );
}
