//! Offline archive and transaction independence (Section L).
//!
//! Receipt retrieval only ever receives an already-frozen anchor digest (through
//! the submitted binding), never the record or archive, so it cannot touch
//! `OotleAnchorRecordV1`, `ArchiveHashV1`, or the canonical archive bytes, and it
//! cannot change the submitted transaction id or unsigned-transaction
//! fingerprint. This test builds a real record, drives receipt queries across
//! every outcome (success, not found, timeout, fee-only, rejected, malformed,
//! duplicate/conflicting logs, disagreement, and eventual finality after
//! restart), and asserts every artifact is byte-identical afterward.

mod common;

use common::{canonical_network, query_of, submit_payload};
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::AnchorLogPayloadV1;
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptCoordinator, FakeIndexerReceiptClient, FakeReceiptStep,
    IndexerReceiptTransportError, compare_walletd_and_indexer, receipt_scenarios,
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

#[test]
fn every_receipt_outcome_leaves_archive_and_transaction_unchanged() {
    let (record, manifest_hash, archive_hash) = reference_record();

    let record_bytes_before = canonical_bytes(&record);
    let archive_hash_before = *archive_hash.as_bytes();
    let manifest_hash_before = *manifest_hash.as_bytes();

    let Ok(anchor_digest) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must compute");
    };
    let digest_before = anchor_digest.into_bytes();
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);

    // A submitted request bound to the real record's digest.
    let submitted = submit_payload(payload);
    let query = query_of(&submitted);
    let tx = submitted.transaction_id().clone();
    let network = canonical_network();

    let tx_before = submitted.transaction_id().clone();
    let fingerprint_before = submitted.binding().fingerprint();

    // Every finalized/transport outcome the contract must cover, each over a
    // fresh coordinator and client so state cannot leak between them.
    let steps: Vec<FakeReceiptStep> = vec![
        FakeReceiptStep::finalized(receipt_scenarios::accepted_receipt(&tx, &network, &payload)),
        FakeReceiptStep::not_found(),
        FakeReceiptStep::pending(),
        FakeReceiptStep::transport(IndexerReceiptTransportError::Timeout),
        FakeReceiptStep::transport(IndexerReceiptTransportError::MalformedResponse),
        FakeReceiptStep::finalized(receipt_scenarios::fee_only_receipt(&tx, &network)),
        FakeReceiptStep::finalized(receipt_scenarios::rejected_receipt(&tx, &network)),
        FakeReceiptStep::finalized(receipt_scenarios::accepted_malformed_anchor_log(
            &tx, &network,
        )),
        FakeReceiptStep::finalized(receipt_scenarios::accepted_duplicate_anchor_logs(
            &tx, &network, &payload,
        )),
    ];

    for step in steps {
        let mut client = FakeIndexerReceiptClient::new();
        client.script(&tx, step);
        let mut coordinator = AnchorReceiptCoordinator::new();
        // Each query returns a report (never an error for these bound cases) and
        // never mutates any offline artifact.
        let _report = coordinator.query(&mut client, &query, &submitted);
        // Restart import of whatever state was recorded.
        let _restored =
            AnchorReceiptCoordinator::from_snapshots(coordinator.registry().snapshots());
    }

    // A walletd/indexer disagreement check also touches no artifact.
    let walletd = receipt_scenarios::walletd_accepted_receipt(&tx, &network, &payload);
    let indexer = receipt_scenarios::rejected_receipt(&tx, &network);
    assert!(compare_walletd_and_indexer(&tx, &network, &walletd, &indexer).is_err());

    // Every offline archive artifact is byte-identical after all of the above.
    assert_eq!(canonical_bytes(&record), record_bytes_before);
    assert_eq!(*archive_hash.as_bytes(), archive_hash_before);
    assert_eq!(*manifest_hash.as_bytes(), manifest_hash_before);

    let Ok(anchor_digest_after) = record.canonical_hash(&Blake3HashProviderV1) else {
        panic!("reference digest must recompute");
    };
    assert_eq!(anchor_digest_after.into_bytes(), digest_before);

    // The submitted transaction id and fingerprint are unchanged: receipt
    // processing cannot alter them.
    assert_eq!(submitted.transaction_id(), &tx_before);
    assert_eq!(submitted.binding().fingerprint(), fingerprint_before);
}
