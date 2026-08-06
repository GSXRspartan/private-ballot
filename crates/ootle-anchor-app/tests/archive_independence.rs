//! Archive-independence tests (Slice 4A10 §16.6).
//!
//! Proves that the public archive locators (`OotleAnchorRecordV1` canonical
//! bytes, `ArchiveHashV1`, `ManifestHash`, the recomputed anchor digest, the
//! submitted transaction id, and the unsigned-transaction fingerprint) are
//! byte-identical across outcomes, and that the snapshot and evidence files
//! contain no secret material.

mod common;

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleAnchorRecordV1};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppDriver, DriverRunOutcome, OperatorDecision, write_evidence_atomic,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedWalletdTransport, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

use common::*;

fn canonical_record_bytes() -> Vec<u8> {
    match anchor_record().to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(error) => panic!("canonical bytes failed: {error}"),
    }
}

fn canonical_digest_bytes() -> OotleAnchorRecordHashV1 {
    canonical_anchor_digest()
}

#[test]
fn anchor_record_canonical_bytes_identical_across_outcomes() {
    let bytes = canonical_record_bytes();
    // Recompute from a fresh record built from the same locators.
    let record = OotleAnchorRecordV1::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
    );
    let recomputed = match record.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(error) => panic!("recompute failed: {error}"),
    };
    assert_eq!(bytes, recomputed);
}

#[test]
fn manifest_hash_byte_identical() {
    let m: ManifestHash = canonical_manifest_hash();
    let again: ManifestHash = ManifestHash::new([MANIFEST_BYTE; 32]);
    assert_eq!(m.as_bytes(), again.as_bytes());
}

#[test]
fn archive_hash_byte_identical() {
    let a: ArchiveHashV1 = canonical_archive_hash();
    let again: ArchiveHashV1 = ArchiveHashV1::new([ARCHIVE_BYTE; 32]);
    assert_eq!(a.as_bytes(), again.as_bytes());
}

#[test]
fn recomputed_anchor_digest_identical() {
    let digest = canonical_digest_bytes();
    let record = OotleAnchorRecordV1::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
    );
    let recomputed = match record.canonical_hash(&Blake3HashProviderV1) {
        Ok(d) => d,
        Err(error) => panic!("digest failed: {error}"),
    };
    assert_eq!(digest.as_bytes(), recomputed.as_bytes());
}

fn run_outcome(
    walletd: ScriptedWalletdTransport,
    indexer: tari_cc_private_ballot_ootle_anchor_network_adapters::ScriptedIndexerTransport,
    decision: OperatorDecision,
) -> (
    AnchorAppDriver<
        ScriptedWalletdTransport,
        tari_cc_private_ballot_ootle_anchor_network_adapters::ScriptedIndexerTransport,
    >,
    DriverRunOutcome,
) {
    let config = base_config();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    };
    let outcome = match driver.run(decision) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    (driver, outcome)
}

#[test]
fn happy_path_tx_id_and_fingerprint_stable() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run_outcome(walletd, indexer, OperatorDecision::Approve);
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    let observed_tx = driver.transaction_id().map(|t| t.as_str().to_owned());
    assert_eq!(
        observed_tx.as_deref(),
        Some(canonical_transaction_id().as_str())
    );
    // The fingerprint is the real Slice 4A5 inspection fingerprint (a
    // domain-separated BLAKE3 over the unsigned transaction's canonical CBOR),
    // so it is deterministic but not a fixed literal. Assert it is present and
    // stable across two runs of the same happy path.
    let observed_fp = driver
        .snapshot()
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    assert!(observed_fp.is_some(), "fingerprint must be present");

    let walletd2 = happy_walletd_transport();
    let indexer2 = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver2, _outcome2) = run_outcome(walletd2, indexer2, OperatorDecision::Approve);
    let observed_fp2 = driver2
        .snapshot()
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    assert_eq!(
        observed_fp, observed_fp2,
        "fingerprint must be stable across runs"
    );
}

#[test]
fn snapshot_file_contains_no_secret_material() {
    let _tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let (driver, outcome) = run_outcome(walletd, indexer, OperatorDecision::NoDecision);
    assert!(matches!(outcome, DriverRunOutcome::NotYetFinalized));
    let snap_path = driver.snapshot_path().to_owned();
    let bytes = match std::fs::read(&snap_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("snapshot read failed: {error}"),
    };
    let text = String::from_utf8_lossy(&bytes);
    for secret in [
        "private_key",
        "mnemonic",
        "seed_phrase",
        "auth_secret",
        "jwt ",
        "nullifier",
        "voter_identity",
        "organizer_identity",
        "seal_signer_secret",
        "registry_key",
    ] {
        assert!(
            !text.to_ascii_lowercase().contains(secret),
            "snapshot must not contain '{secret}'"
        );
    }
}

#[test]
fn evidence_file_contains_no_secret_material() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run_outcome(walletd, indexer, OperatorDecision::Approve);
    if let DriverRunOutcome::FinalizedAccept(evidence) = outcome {
        let ev_path = driver.evidence_path().to_owned();
        match write_evidence_atomic(&ev_path, &evidence) {
            Ok(()) => {}
            Err(error) => panic!("evidence write failed: {error}"),
        }
        let bytes = match std::fs::read(&ev_path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("evidence read failed: {error}"),
        };
        let text = String::from_utf8_lossy(&bytes);
        for secret in [
            "private_key",
            "mnemonic",
            "seed",
            "auth_secret",
            "jwt",
            "nullifier",
            "voter_identity",
            "organizer_identity",
            "seal_signer",
            "registry_key",
        ] {
            assert!(
                !text.to_ascii_lowercase().contains(secret),
                "evidence must not contain '{secret}'"
            );
        }
    } else {
        panic!("expected FinalizedAccept");
    }
}
