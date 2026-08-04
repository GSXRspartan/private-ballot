//! Section L — the transport lifecycle never mutates the authoritative offline
//! archive artifacts.
//!
//! Preparing, approving, submitting, finalizing, verifying, failing a
//! preparation, and rejecting an approval are all pure with respect to the
//! frozen [`OotleAnchorRecordV1`] and [`ArchiveHashV1`]; this test snapshots
//! those artifacts before and after the whole lifecycle and asserts they are
//! byte-identical.

mod common;

use common::{account, network};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationError,
    AnchorPreparationRequest, AnchorQueryOutcomeV1, AnchorReceiptSource, AnchorTransactionApprover,
    AnchorTransactionRequestStore, AnchorTransactionSubmitter, DeterministicAnchorFake,
    FakeFinality, verify_anchor_receipt,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

/// Builds the reference completed anchor record and its archive artifacts.
fn reference_record() -> (OotleAnchorRecordV1, ManifestHash, ArchiveHashV1) {
    let manifest_hash = ManifestHash::new([0x11; 32]);
    let archive_hash = ArchiveHashV1::new([0x22; 32]);
    let record = OotleAnchorRecordV1::new(reference_network(), manifest_hash, archive_hash);
    (record, manifest_hash, archive_hash)
}

fn reference_network() -> OotleNetworkIdV1 {
    network("esmeralda")
}

fn canonical_bytes(record: &OotleAnchorRecordV1) -> Vec<u8> {
    match record.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("reference record must encode"),
    }
}

#[test]
fn full_lifecycle_does_not_mutate_archive_artifacts() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let digest_before = anchor_digest.into_bytes();

    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let binding = AnchorBindingV1::new(reference_network(), account("fee-account"), payload);

    let mut fake = DeterministicAnchorFake::new();

    // A failed preparation must not disturb the archive either.
    fake.inject_create_failure(AnchorPreparationError::InjectedFailure);
    assert_eq!(
        fake.create_request(&AnchorPreparationRequest::new(
            binding.clone(),
            AnchorMaxFeeV1::from_units(1_000),
            None,
        )),
        Err(AnchorPreparationError::InjectedFailure)
    );

    // A full successful lifecycle.
    let Ok(prepared) = fake.create_request(&AnchorPreparationRequest::new(
        binding.clone(),
        AnchorMaxFeeV1::from_units(1_000),
        None,
    )) else {
        panic!("preparation should succeed");
    };
    let request_id = prepared.request_id().clone();

    if fake.approve(&request_id, &binding).is_err() {
        panic!("approval should succeed");
    }
    let Ok(submitted) = fake.submit(&request_id, &binding, &anchor_digest) else {
        panic!("submission should succeed");
    };
    fake.set_finality(&request_id, FakeFinality::Accepted);

    let Ok(AnchorQueryOutcomeV1::Finalized(receipt)) =
        fake.query_receipt(submitted.transaction_id(), binding.network())
    else {
        panic!("a finalized receipt should be retrievable");
    };
    if verify_anchor_receipt(
        submitted.transaction_id(),
        binding.network(),
        &AnchorLogPayloadV1::from_digest(anchor_digest),
        &receipt,
    )
    .is_err()
    {
        panic!("finalized receipt should verify");
    }

    // A rejected request on a second binding.
    let Ok(rejected) = fake.create_request(&AnchorPreparationRequest::new(
        binding.clone(),
        AnchorMaxFeeV1::from_units(1_000),
        Some(
            match tari_cc_private_ballot_anchor_transport::AnchorClientReferenceV1::new(
                "second".to_owned(),
            ) {
                Ok(reference) => reference,
                Err(_) => panic!("client reference must be valid"),
            },
        ),
    )) else {
        panic!("second preparation should succeed");
    };
    if fake.reject(rejected.request_id()).is_err() {
        panic!("rejection should succeed");
    }

    // The offline archive artifacts are byte-identical after everything above.
    assert_eq!(canonical_bytes(&record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);

    let Ok(anchor_digest_after) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must recompute");
    };
    assert_eq!(anchor_digest_after.into_bytes(), digest_before);
}
