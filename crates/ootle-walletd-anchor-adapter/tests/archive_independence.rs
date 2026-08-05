//! Offline archive independence (Section M).
//!
//! This adapter only ever receives an already-frozen anchor digest (through the
//! payload), never the record or archive, so it cannot touch
//! `OotleAnchorRecordV1`, `ArchiveHashV1`, or the canonical archive bytes. This
//! test snapshots those artifacts, then runs preparation, approval, rejection, a
//! client failure, and a restart import, and asserts every artifact is
//! byte-identical afterward.

mod common;

use common::{fee_component, seal_signer};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest,
    AnchorTransactionId,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorBuildResultV1, OotleAnchorTransactionBuildRequestV1,
    build_unsigned_anchor_transaction,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, WalletdAnchorAdapterError, WalletdAnchorCoordinator,
    WalletdDecisionRequestV1, WalletdSubmitRequestV1,
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

fn build_result_for(payload: AnchorLogPayloadV1) -> OotleAnchorBuildResultV1 {
    let binding = AnchorBindingV1::new(
        reference_network(),
        match tari_cc_private_ballot_anchor_transport::AnchorAccountReference::new(
            "fee-account".to_owned(),
        ) {
            Ok(reference) => reference,
            Err(_error) => panic!("account must be valid"),
        },
        payload,
    );
    let request = OotleAnchorTransactionBuildRequestV1::from_preparation_request(
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(1_000), None),
    );
    match build_unsigned_anchor_transaction(&request) {
        Ok(result) => result,
        Err(_error) => panic!("build result must construct"),
    }
}

fn build_request_for(payload: AnchorLogPayloadV1) -> OotleAnchorTransactionBuildRequestV1 {
    let binding = AnchorBindingV1::new(
        reference_network(),
        match tari_cc_private_ballot_anchor_transport::AnchorAccountReference::new(
            "fee-account".to_owned(),
        ) {
            Ok(reference) => reference,
            Err(_error) => panic!("account must be valid"),
        },
        payload,
    );
    OotleAnchorTransactionBuildRequestV1::from_preparation_request(AnchorPreparationRequest::new(
        binding,
        AnchorMaxFeeV1::from_units(1_000),
        None,
    ))
}

#[test]
fn full_lifecycle_never_mutates_archive_artifacts() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let digest_before = anchor_digest.into_bytes();
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let build = build_result_for(payload);

    // Prepare + approve over the real record's digest.
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &build, seal_signer(), None) else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    if coordinator.approve(&mut client, &decision).is_err() {
        panic!("approve must succeed");
    }

    // A separate rejected request over the same digest.
    let mut reject_coordinator = WalletdAnchorCoordinator::new();
    let Ok(to_reject) = reject_coordinator.prepare(&mut client, &build, seal_signer(), None) else {
        panic!("second prepare must succeed");
    };
    let reject_decision = WalletdDecisionRequestV1::for_prepared(&to_reject);
    if reject_coordinator
        .reject(&mut client, &reject_decision)
        .is_err()
    {
        panic!("reject must succeed");
    }

    // A failing preparation (client rejects creation).
    let mut failing_client = FakeWalletdAnchorClient::new();
    failing_client.inject_create_error(WalletdAnchorAdapterError::RequestCreationRejected);
    let mut failing_coordinator = WalletdAnchorCoordinator::new();
    assert!(
        failing_coordinator
            .prepare(&mut failing_client, &build, seal_signer(), None)
            .is_err()
    );

    // A restart import of the approved coordinator's snapshots.
    let _restored = WalletdAnchorCoordinator::from_snapshots(coordinator.registry().snapshots());

    // Every offline archive artifact is byte-identical after all of the above.
    assert_eq!(canonical_bytes(&record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);

    let Ok(anchor_digest_after) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must recompute");
    };
    assert_eq!(anchor_digest_after.into_bytes(), digest_before);
}

#[test]
fn submission_and_recovery_never_mutate_archive_artifacts() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let request = build_request_for(payload);

    // A full successful fee-bearing submission.
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &request,
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    if coordinator.submit(&mut client, &submit).is_err() {
        panic!("submit must succeed");
    }
    // Idempotent duplicate submission.
    if coordinator.submit(&mut client, &submit).is_err() {
        panic!("idempotent duplicate submit must succeed");
    }

    // A submission whose response is lost, then recovered.
    let mut lost_client = FakeWalletdAnchorClient::new();
    let mut lost_coordinator = WalletdAnchorCoordinator::new();
    let Ok(lost_prepared) = lost_coordinator.prepare_fee_bearing(
        &mut lost_client,
        &request,
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("prepare must succeed");
    };
    let lost_decision = WalletdDecisionRequestV1::for_prepared(&lost_prepared);
    let Ok(lost_approved) = lost_coordinator.approve(&mut lost_client, &lost_decision) else {
        panic!("approve must succeed");
    };
    let lost_submit = WalletdSubmitRequestV1::for_approved(&lost_approved);
    lost_client.inject_submit_timeout_after_processing();
    assert!(
        lost_coordinator
            .submit(&mut lost_client, &lost_submit)
            .is_err()
    );
    if lost_coordinator
        .recover(&mut lost_client, &lost_submit)
        .is_err()
    {
        panic!("recovery must succeed");
    }

    // A submission that is refused (walletd unavailable) and a conflicting-id
    // rejection, over their own coordinators.
    let mut fail_client = FakeWalletdAnchorClient::new();
    let mut fail_coordinator = WalletdAnchorCoordinator::new();
    let Ok(fail_prepared) = fail_coordinator.prepare_fee_bearing(
        &mut fail_client,
        &request,
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("prepare must succeed");
    };
    let fail_decision = WalletdDecisionRequestV1::for_prepared(&fail_prepared);
    let Ok(fail_approved) = fail_coordinator.approve(&mut fail_client, &fail_decision) else {
        panic!("approve must succeed");
    };
    let fail_submit = WalletdSubmitRequestV1::for_approved(&fail_approved);
    if fail_coordinator
        .submit(&mut fail_client, &fail_submit)
        .is_err()
    {
        panic!("submit must succeed");
    }
    let Ok(forged) = AnchorTransactionId::new("aa".repeat(32)) else {
        panic!("forged id must be valid");
    };
    fail_client.force_transaction_id(fail_approved.walletd_request_id(), Some(forged));
    assert_eq!(
        fail_coordinator.recover(&mut fail_client, &fail_submit),
        Err(WalletdAnchorAdapterError::ConflictingTransactionId)
    );

    // A restart import of every coordinator's snapshots.
    let _restored = WalletdAnchorCoordinator::from_snapshots(coordinator.registry().snapshots());
    let _restored_lost =
        WalletdAnchorCoordinator::from_snapshots(lost_coordinator.registry().snapshots());

    // Every offline archive artifact is byte-identical after all of the above.
    assert_eq!(canonical_bytes(&record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);
}
