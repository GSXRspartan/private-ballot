//! Structured anchor inspector tests (required cases 39-45).

mod common;

use tari_cc_private_ballot_gui_core::{
    GuiErrorCategory, inspect_anchor_config_v1, inspect_anchor_evidence_v1,
    inspect_anchor_snapshot_v1,
};
use tari_cc_private_ballot_ootle_anchor_app::write_snapshot_atomic;

use common::{
    TestDir, anchor_digest, anchor_transaction_id, finalized_accept_snapshot, impossible_snapshot,
    prepared_snapshot, write_anchor_config, write_anchor_evidence,
};

#[test]
fn valid_config_inspection_returns_structured_fields() {
    let dir = TestDir::new("inspect-config");
    let path = write_anchor_config(dir.path());

    let inspection = match inspect_anchor_config_v1(&path) {
        Ok(inspection) => inspection,
        Err(error) => panic!("valid config must inspect: {error}"),
    };

    assert_eq!(inspection.network, "esmeralda");
    assert_eq!(inspection.walletd_endpoint, "http://127.0.0.1:12009/");
    assert_eq!(inspection.indexer_endpoint, "http://127.0.0.1:12500/");
    assert_eq!(inspection.account_reference, "fee-account");
    assert_eq!(inspection.seal_signer, "ACCOUNT_KEY:0");
    assert_eq!(inspection.max_fee, 1_000);
    assert_eq!(inspection.request_timeout_secs, Some(30));
    assert_eq!(inspection.receipt_query_max_attempts, 8);
    assert_eq!(inspection.backoff_base_secs, 1);
    assert_eq!(inspection.backoff_cap_secs, 2);
    assert_eq!(inspection.ttl_secs, None);
    assert_eq!(inspection.manifest_hash_hex.len(), 64);
    assert_eq!(inspection.archive_hash_hex.len(), 64);

    // The derived anchor digest matches a direct anchor-record derivation.
    let expected = anchor_digest();
    assert_eq!(inspection.anchor_digest_hex, lower_hex(expected.as_bytes()));
}

fn lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn tampered_config_is_rejected() {
    let dir = TestDir::new("inspect-config-tampered");
    let path = write_anchor_config(dir.path());
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => panic!("config must be readable"),
    };
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(std::fs::write(&path, tampered).is_ok());

    let error = match inspect_anchor_config_v1(&path) {
        Ok(_) => panic!("tampered config must be rejected"),
        Err(error) => error,
    };
    assert!(error.code().starts_with("CONFIG_"));
}

#[test]
fn valid_prepared_snapshot_inspection() {
    let dir = TestDir::new("inspect-prepared");
    let path = dir.join("snapshot.cbor");
    if write_snapshot_atomic(&path, &prepared_snapshot()).is_err() {
        panic!("prepared snapshot must write");
    }

    let inspection = match inspect_anchor_snapshot_v1(&path) {
        Ok(inspection) => inspection,
        Err(error) => panic!("prepared snapshot must inspect: {error}"),
    };

    assert_eq!(inspection.phase, "PREPARED");
    assert!(!inspection.phase_is_terminal);
    assert!(!inspection.phase_is_terminal_success);
    assert_eq!(inspection.poll_attempts_consumed, 0);
    assert_eq!(inspection.poll_attempts_max, 8);
    assert_eq!(inspection.submitted_transaction_id, None);
    assert_eq!(inspection.snapshot_digest_hex.len(), 64);
    assert_eq!(inspection.walletd.len(), 1);
    assert_eq!(inspection.receipts.len(), 0);

    let walletd = &inspection.walletd[0];
    assert_eq!(walletd.project_request_id, "anchor-request-001");
    assert_eq!(walletd.walletd_request_id, 1);
    assert_eq!(walletd.network, "esmeralda");
    assert_eq!(walletd.account_reference, "fee-account");
    assert_eq!(walletd.max_fee, 1_000);
    assert_eq!(walletd.decision, "PREPARED");
    assert_eq!(walletd.submission_state, "NOT_SUBMITTED");
    assert_eq!(walletd.transaction_id, None);
    assert_eq!(walletd.transaction_fingerprint_hex.len(), 64);
    assert_eq!(walletd.anchor_digest_hex.len(), 64);
    assert!(!walletd.anchor_payload.is_empty());
}

#[test]
fn valid_finalized_accept_snapshot_inspection() {
    let dir = TestDir::new("inspect-finalized");
    let path = dir.join("snapshot.cbor");
    if write_snapshot_atomic(&path, &finalized_accept_snapshot()).is_err() {
        panic!("finalized snapshot must write");
    }

    let inspection = match inspect_anchor_snapshot_v1(&path) {
        Ok(inspection) => inspection,
        Err(error) => panic!("finalized snapshot must inspect: {error}"),
    };

    assert_eq!(inspection.phase, "FINALIZED_ACCEPT");
    assert!(inspection.phase_is_terminal);
    assert!(inspection.phase_is_terminal_success);
    assert_eq!(inspection.poll_attempts_consumed, 5);
    assert_eq!(
        inspection.submitted_transaction_id.as_deref(),
        Some(common::ANCHOR_TX_HEX)
    );
    assert_eq!(inspection.receipts.len(), 1);
    let receipt = &inspection.receipts[0];
    assert_eq!(receipt.query_state, "RECEIPT_FINALIZED_ACCEPT");
    assert_eq!(receipt.final_status, Some("ACCEPTED"));
    assert!(receipt.verified);
    assert_eq!(receipt.transaction_id, common::ANCHOR_TX_HEX);
}

#[test]
fn semantically_impossible_snapshot_is_rejected() {
    let dir = TestDir::new("inspect-impossible");
    let path = dir.join("snapshot.cbor");
    // Digest-consistent (written through the validating encoder) but
    // semantically impossible: a terminal phase with no walletd content.
    if write_snapshot_atomic(&path, &impossible_snapshot()).is_err() {
        panic!("impossible snapshot must encode");
    }

    let error = match inspect_anchor_snapshot_v1(&path) {
        Ok(_) => panic!("semantically impossible snapshot must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.code().starts_with("LIFECYCLE_"),
        "unexpected code: {}",
        error.code()
    );
    assert_eq!(error.category(), GuiErrorCategory::AnchorArtifactIntegrity);
}

#[test]
fn valid_evidence_inspection() {
    let dir = TestDir::new("inspect-evidence");
    let path = write_anchor_evidence(dir.path());

    let inspection = match inspect_anchor_evidence_v1(&path) {
        Ok(inspection) => inspection,
        Err(error) => panic!("valid evidence must inspect: {error}"),
    };

    assert_eq!(inspection.final_status, "REJECTED_BY_APPROVER");
    assert_eq!(inspection.receipt_source, "NONE");
    assert_eq!(inspection.phase, "REJECTED_BY_APPROVER");
    assert_eq!(inspection.network, "esmeralda");
    assert_eq!(inspection.transaction_id, None);
    assert_eq!(inspection.ledger_position, None);
    assert_eq!(inspection.record_digest_hex.len(), 64);
    assert_eq!(inspection.manifest_hash_hex.len(), 64);
    assert_eq!(inspection.archive_hash_hex.len(), 64);
    assert_eq!(inspection.anchor_digest_hex.len(), 64);
    assert_eq!(inspection.snapshot_digest_hex.len(), 64);
    assert!(inspection.human_review_summary.contains("NON-BINDING"));
    assert!(inspection.human_review_summary.contains("authoritative"));
}

#[test]
fn tampered_evidence_is_rejected() {
    let dir = TestDir::new("inspect-evidence-tampered");
    let path = write_anchor_evidence(dir.path());
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => panic!("evidence must be readable"),
    };
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(std::fs::write(&path, tampered).is_ok());

    let error = match inspect_anchor_evidence_v1(&path) {
        Ok(_) => panic!("tampered evidence must be rejected"),
        Err(error) => error,
    };
    assert!(error.code().starts_with("EVIDENCE_"));
    assert_eq!(error.category(), GuiErrorCategory::AnchorArtifactIntegrity);
}

#[test]
fn missing_inspection_targets_are_reported() {
    let dir = TestDir::new("inspect-missing");
    let missing = dir.join("absent.cbor");

    let snapshot_error = match inspect_anchor_snapshot_v1(&missing) {
        Ok(_) => panic!("missing snapshot must fail"),
        Err(error) => error,
    };
    assert_eq!(snapshot_error.code(), "GUI_FILE_NOT_FOUND");

    let evidence_error = match inspect_anchor_evidence_v1(&missing) {
        Ok(_) => panic!("missing evidence must fail"),
        Err(error) => error,
    };
    assert_eq!(evidence_error.code(), "GUI_FILE_NOT_FOUND");

    let config_error = match inspect_anchor_config_v1(&missing) {
        Ok(_) => panic!("missing config must fail"),
        Err(error) => error,
    };
    assert_eq!(config_error.code(), "CONFIG_FILE_NOT_FOUND");
}

#[test]
fn evidence_transaction_id_is_present_when_bound() {
    // A fee-only terminal record carries the transaction id.
    let dir = TestDir::new("inspect-evidence-tx");
    let inputs = tari_cc_private_ballot_ootle_anchor_app::ArchiveProofInputs::new(
        common::anchor_network(),
        common::anchor_manifest_hash(),
        common::anchor_archive_hash(),
        common::anchor_digest(),
    );
    let record =
        match tari_cc_private_ballot_ootle_anchor_app::AnchorEvidenceRecordV1::from_terminal_outcome(
            &inputs,
            tari_cc_private_ballot_ootle_anchor_app::TerminalEvidenceInputs::FeeOnly {
                transaction_id: anchor_transaction_id(),
                ledger_position: Some(182_441),
            },
            &[0x66; 32],
        ) {
            Ok(record) => record,
            Err(_) => panic!("fee-only evidence must construct"),
        };
    let path = dir.join("evidence.cbor");
    if tari_cc_private_ballot_ootle_anchor_app::write_evidence_atomic(&path, &record).is_err() {
        panic!("evidence must write");
    }

    let inspection = match inspect_anchor_evidence_v1(&path) {
        Ok(inspection) => inspection,
        Err(_) => panic!("fee-only evidence must inspect"),
    };
    assert_eq!(inspection.final_status, "FEE_ONLY_ACCEPTED");
    assert_eq!(
        inspection.transaction_id.as_deref(),
        Some(common::ANCHOR_TX_HEX)
    );
    assert_eq!(inspection.ledger_position, Some(182_441));
}
