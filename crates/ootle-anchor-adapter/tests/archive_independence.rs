//! Section L / Section M(19) — transaction construction never mutates the
//! authoritative offline archive artifacts.
//!
//! The adapter only ever receives an already-frozen anchor digest (through the
//! payload), never the record, so it cannot touch `OotleAnchorRecordV1`,
//! `ArchiveHashV1`, or the canonical archive bytes. This test snapshots those
//! artifacts, runs both a successful construction and failing constructions
//! (unsupported network, and mainnet rejection), and asserts every artifact is
//! byte-identical afterward.

mod common;

use common::{account, epoch_binding, network, template_binding};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorTransactionBuildRequestV1, build_unsigned_anchor_transaction,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

fn reference_network() -> OotleNetworkIdV1 {
    network("esmeralda")
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
        Err(_) => panic!("reference record must encode"),
    }
}

fn request_on(
    network_value: &str,
    payload: AnchorLogPayloadV1,
) -> OotleAnchorTransactionBuildRequestV1 {
    let binding = AnchorBindingV1::new(network(network_value), account("fee-account"), payload);
    OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(1_000), None),
        template_binding(),
        epoch_binding(),
    )
}

#[test]
fn construction_and_failures_do_not_mutate_archive_artifacts() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let digest_before = anchor_digest.into_bytes();
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);

    // Successful construction over the real record's digest.
    if build_unsigned_anchor_transaction(&request_on("esmeralda", payload)).is_err() {
        panic!("construction over the real digest must succeed");
    }

    // Network-mapping failure (unsupported testnet name).
    assert!(build_unsigned_anchor_transaction(&request_on("teronet", payload)).is_err());

    // Mainnet rejection failure.
    assert!(build_unsigned_anchor_transaction(&request_on("mainnet", payload)).is_err());

    // Every offline archive artifact is byte-identical after all of the above.
    assert_eq!(canonical_bytes(&record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);

    let Ok(anchor_digest_after) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must recompute");
    };
    assert_eq!(anchor_digest_after.into_bytes(), digest_before);
}
