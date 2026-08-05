//! Archive and transaction independence (Section J).
//!
//! These tests prove byte-identical archive and anchor artifacts across every
//! orchestration outcome — happy path, fee-only, rejected, verification-failure,
//! not-found, poll-exhausted unknown, submit-timeout → recover, disagreement,
//! and eventual finality after restart — by asserting equality of:
//! * `OotleAnchorRecordV1` canonical CBOR bytes;
//! * `ArchiveHashV1`;
//! * `ManifestHash`;
//! * the recomputed anchor-record digest;
//! * the submitted transaction id;
//! * the unsigned-transaction fingerprint.
//!
//! They also prove that driving, polling, recovering, or restarting the
//! lifecycle cannot change the submitted transaction id or fingerprint.

mod common;

use common::{
    LifecycleHarness, accepted_receipt, fee_only_receipt, missing_anchor_log_receipt,
    rejected_receipt,
};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    FakeReceiptStep, IndexerReceiptTransportError,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

fn reference_network() -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new("esmeralda".to_owned()) {
        Ok(identifier) => identifier,
        Err(_error) => panic!("network must be valid"),
    }
}

fn reference_record() -> (OotleAnchorRecordV1, ManifestHash, ArchiveHashV1) {
    let manifest_hash = ManifestHash::new([0x11; 32]);
    let archive_hash = ArchiveHashV1::new([0x22; 32]);
    let record = OotleAnchorRecordV1::new(reference_network(), manifest_hash, archive_hash);
    (record, manifest_hash, archive_hash)
}

fn canonical_bytes(record: &OotleAnchorRecordV1) -> Vec<u8> {
    match record.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_error) => panic!("reference record must encode"),
    }
}

/// Asserts every offline artifact is byte-identical before and after an
/// orchestration scenario, and that the submitted transaction id and
/// fingerprint are unchanged.
#[allow(clippy::too_many_arguments)]
fn assert_artifacts_unchanged(
    record: &OotleAnchorRecordV1,
    record_bytes_before: &[u8],
    archive_hash: ArchiveHashV1,
    archive_hash_before: [u8; 32],
    manifest_hash: ManifestHash,
    manifest_hash_before: [u8; 32],
    digest_before: [u8; 32],
    tx_before: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
    fingerprint_before: tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1,
    harness: &LifecycleHarness,
) {
    assert_eq!(canonical_bytes(record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);

    let Ok(anchor_digest_after) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must recompute");
    };
    assert_eq!(anchor_digest_after.into_bytes(), digest_before);

    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must exist for fingerprint check");
    };
    assert_eq!(submitted.transaction_id(), tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);
}

#[test]
fn every_orchestration_outcome_leaves_archive_and_transaction_unchanged() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let digest_before = anchor_digest.into_bytes();

    // Build a build request whose payload matches the real record's digest.
    let request = common::build_request("esmeralda", "fee-account", 0x22, 1_000);

    // --- Happy path ---
    {
        let mut harness = LifecycleHarness::new(5);
        let Ok(report) = harness.orchestrator.prepare_fee_bearing(
            &mut harness.walletd_client,
            &request,
            &common::fee_component(),
            common::seal_signer(),
            None,
        ) else {
            panic!("prepare must succeed");
        };
        assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Prepared);
        harness.approve();
        let tx = harness.submit();
        harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
        let _poll = harness.poll_once();
        assert_eq!(
            harness.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedAccept
        );

        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Fee-only, rejected, verification-failure ---
    for (label, builder) in [
        ("fee-only", fee_only_receipt as common::ReceiptBuilder),
        ("rejected", rejected_receipt as common::ReceiptBuilder),
        (
            "verification-failure",
            missing_anchor_log_receipt as common::ReceiptBuilder,
        ),
    ] {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        let receipt = builder(&tx);
        harness.script_receipt(FakeReceiptStep::finalized(receipt));
        let _poll = harness.poll_once();
        assert!(
            harness.phase().is_terminal(),
            "case {label} must be terminal"
        );
        assert!(
            !harness.phase().is_terminal_success(),
            "case {label} must not be success"
        );

        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Not-found, pending, timeout ---
    {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();

        for step in [
            FakeReceiptStep::not_found(),
            FakeReceiptStep::pending(),
            FakeReceiptStep::transport(IndexerReceiptTransportError::Timeout),
            FakeReceiptStep::transport(IndexerReceiptTransportError::MalformedResponse),
        ] {
            harness.script_receipt(step);
            let _poll = harness.poll_once();
        }
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Poll-exhausted unknown ---
    {
        let mut harness = LifecycleHarness::new(1);
        let tx = harness.prepare_approve_submit();
        let _poll = harness.poll_once();
        let _poll2 = harness.poll_once();
        assert_eq!(harness.phase(), UnifiedAnchorLifecyclePhase::Unknown);

        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Submit-timeout → recover ---
    {
        let mut harness = LifecycleHarness::new(5);
        harness.prepare();
        harness.approve();
        harness
            .walletd_client
            .inject_submit_timeout_after_processing();
        let _ = harness.orchestrator.submit(&mut harness.walletd_client);
        let _report = harness.recover();
        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let tx = submitted.transaction_id().clone();
        let fingerprint_before = submitted.binding().fingerprint();
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Disagreement ---
    {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
        let _poll = harness.poll_once();
        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();
        let walletd = rejected_receipt(&tx);
        let _ = harness.orchestrator.check_agreement(&walletd);
        assert_eq!(
            harness.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedDisagreement
        );
        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &harness,
        );
    }

    // --- Eventual finality after restart ---
    {
        let mut harness = LifecycleHarness::new(5);
        let tx = harness.prepare_approve_submit();
        harness.script_receipt(FakeReceiptStep::not_found());
        let _poll = harness.poll_once();
        let Some(submitted) = harness.orchestrator.submitted() else {
            panic!("submitted handle must be Some");
        };
        let fingerprint_before = submitted.binding().fingerprint();

        // Restart.
        let snapshot = harness.snapshot();
        let Ok(restored) = tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
            panic!("snapshot must restore");
        };
        let mut new_harness = LifecycleHarness::new(5);
        new_harness.orchestrator = restored;
        new_harness.walletd_client = std::mem::take(&mut harness.walletd_client);
        new_harness.indexer_client = std::mem::take(&mut harness.indexer_client);
        new_harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx)));
        let _poll2 = new_harness.poll_once();
        assert_eq!(
            new_harness.phase(),
            UnifiedAnchorLifecyclePhase::FinalizedAccept
        );

        assert_artifacts_unchanged(
            &record,
            &record_bytes_before,
            archive_hash,
            archive_hash_before,
            manifest_hash,
            manifest_hash_before,
            digest_before,
            &tx,
            fingerprint_before,
            &new_harness,
        );
    }
}

#[test]
fn driving_polling_recovering_restarting_cannot_change_tx_id_or_fingerprint() {
    let mut harness = LifecycleHarness::new(5);
    let tx = harness.prepare_approve_submit();
    let tx_before = tx.clone();
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some");
    };
    let fingerprint_before = submitted.binding().fingerprint();

    // Poll with not-found.
    harness.script_receipt(FakeReceiptStep::not_found());
    let _ = harness.poll_once();
    let Some(submitted) = harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some");
    };
    assert_eq!(submitted.transaction_id(), &tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);

    // Restart and poll again.
    let snapshot = harness.snapshot();
    let Ok(restored) = tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleOrchestrator::from_snapshot(snapshot) else {
        panic!("snapshot must restore");
    };
    let mut new_harness = LifecycleHarness::new(5);
    new_harness.orchestrator = restored;
    new_harness.walletd_client = std::mem::take(&mut harness.walletd_client);
    new_harness.indexer_client = std::mem::take(&mut harness.indexer_client);
    new_harness.script_receipt(FakeReceiptStep::not_found());
    let _ = new_harness.poll_once();
    let Some(submitted) = new_harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some");
    };
    assert_eq!(submitted.transaction_id(), &tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);

    // Finalize after restart.
    new_harness.script_receipt(FakeReceiptStep::finalized(accepted_receipt(&tx_before)));
    let _ = new_harness.poll_once();
    assert_eq!(
        new_harness.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    let Some(submitted) = new_harness.orchestrator.submitted() else {
        panic!("submitted handle must be Some");
    };
    assert_eq!(submitted.transaction_id(), &tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);
}
