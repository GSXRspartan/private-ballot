//! Shared deterministic constructors and scripted-transport helpers for the
//! anchor-app test suite (Slice 4A10).
//!
//! Every helper is offline and deterministic. Unused-helper warnings are
//! allowed here, matching the Slice 4A6/4A7/4A8 test convention.

#![allow(dead_code)]

use std::path::PathBuf;

use tari_cc_private_ballot_anchor::{
    OotleAnchorRecordHashV1, OotleAnchorRecordV1, OotleNetworkIdV1,
};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorTransactionId,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, SNAPSHOT_DOMAIN_LABEL_V1, SNAPSHOT_FRAME_PREFIX_V1,
    SNAPSHOT_HASH_ALGORITHM_ID_V1, SNAPSHOT_RECORD_TYPE_ID_V1, SnapshotFileError, WallClockBackoff,
    read_snapshot, write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, NetworkAdapterConfig, ScriptedIndexerResponse, ScriptedIndexerTransport,
    ScriptedWalletdResponse, ScriptedWalletdTransport, WalletdEndpoint,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, AnchorReceiptQueryV1,
    receipt_scenarios,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdAnchorBindingV1, WalletdAnchorSnapshotV1,
    WalletdEffectiveStatusV1, WalletdFeeComponentRef, WalletdRequestDecisionV1, WalletdRequestId,
    WalletdSealSignerRef, WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

pub const MANIFEST_BYTE: u8 = 0x11;
pub const ARCHIVE_BYTE: u8 = 0x22;
pub const ANCHOR_BYTE: u8 = 0x33;
pub const TX_BYTE: u8 = 0x44;
pub const DECLARED_SEAL_PUBLIC_KEY: &str = "seal-public-key-attested";

#[must_use]
pub fn network(value: &str) -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new(value.to_owned()) {
        Ok(identifier) => identifier,
        Err(_) => panic!("test network identifier must be valid"),
    }
}

#[must_use]
pub fn canonical_network() -> OotleNetworkIdV1 {
    network("esmeralda")
}

#[must_use]
pub fn account(value: &str) -> AnchorAccountReference {
    match AnchorAccountReference::new(value.to_owned()) {
        Ok(reference) => reference,
        Err(_) => panic!("test account reference must be valid"),
    }
}

#[must_use]
pub fn canonical_account() -> AnchorAccountReference {
    account("fee-account")
}

#[must_use]
pub fn manifest_hash(byte: u8) -> ManifestHash {
    ManifestHash::new([byte; 32])
}

#[must_use]
pub fn canonical_manifest_hash() -> ManifestHash {
    manifest_hash(MANIFEST_BYTE)
}

#[must_use]
pub fn archive_hash(byte: u8) -> ArchiveHashV1 {
    ArchiveHashV1::new([byte; 32])
}

#[must_use]
pub fn canonical_archive_hash() -> ArchiveHashV1 {
    archive_hash(ARCHIVE_BYTE)
}

#[must_use]
pub fn anchor_record() -> OotleAnchorRecordV1 {
    OotleAnchorRecordV1::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
    )
}

#[must_use]
pub fn canonical_anchor_digest() -> OotleAnchorRecordHashV1 {
    match anchor_record().canonical_hash(&Blake3HashProviderV1) {
        Ok(digest) => digest,
        Err(_) => panic!("canonical anchor digest must compute"),
    }
}

#[must_use]
pub fn canonical_payload() -> AnchorLogPayloadV1 {
    AnchorLogPayloadV1::from_digest(canonical_anchor_digest())
}

#[must_use]
pub fn transaction_id(byte: u8) -> AnchorTransactionId {
    let hex = to_lower_hex_32(byte);
    match AnchorTransactionId::new(hex) {
        Ok(id) => id,
        Err(_) => panic!("test transaction id must be valid"),
    }
}

#[must_use]
pub fn canonical_transaction_id() -> AnchorTransactionId {
    transaction_id(TX_BYTE)
}

#[must_use]
pub fn seal_signer() -> WalletdSealSignerRef {
    WalletdSealSignerRef::AccountKey { index: 0 }
}

#[must_use]
pub fn fee_component() -> WalletdFeeComponentRef {
    let raw = "component_".to_owned() + &"11".repeat(32);
    match WalletdFeeComponentRef::parse(&raw) {
        Ok(component) => component,
        Err(_) => panic!("test fee component must parse"),
    }
}

#[must_use]
pub fn max_fee() -> AnchorMaxFeeV1 {
    AnchorMaxFeeV1::from_units(1_000)
}

#[must_use]
pub fn walletd_endpoint() -> WalletdEndpoint {
    match WalletdEndpoint::parse("http://127.0.0.1:12009") {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("test walletd endpoint must parse"),
    }
}

#[must_use]
pub fn indexer_endpoint() -> IndexerEndpoint {
    match IndexerEndpoint::parse("http://127.0.0.1:12500") {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("test indexer endpoint must parse"),
    }
}

#[must_use]
pub fn network_adapter() -> NetworkAdapterConfig {
    match NetworkAdapterConfig::new(
        canonical_network(),
        walletd_endpoint(),
        indexer_endpoint(),
        fee_component(),
        seal_signer(),
        max_fee(),
        Some(30),
        8,
        None,
    ) {
        Ok(config) => config,
        Err(_) => panic!("test network adapter must construct"),
    }
}

#[must_use]
pub fn tmp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("anchor-app-{}-{name}", std::process::id()));
    let _ = std::fs::create_dir_all(&path);
    path
}

#[must_use]
pub fn snapshot_path() -> PathBuf {
    tmp_path(&format!("snapshot-{}", unique_id())).join("snapshot.cbor")
}

#[must_use]
pub fn evidence_path() -> PathBuf {
    tmp_path(&format!("evidence-{}", unique_id())).join("evidence.cbor")
}

#[must_use]
pub fn base_config() -> AnchorAppConfig {
    AnchorAppConfig::new_archive_verified(
        network_adapter(),
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

#[must_use]
pub fn fast_backoff() -> WallClockBackoff {
    match WallClockBackoff::new(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(1),
    ) {
        Ok(backoff) => backoff,
        Err(_) => panic!("test backoff must construct"),
    }
}

/// A scripted walletd transport that returns the happy-path create/approve/
/// get/submit responses for the canonical transaction id.
#[must_use]
pub fn happy_walletd_transport() -> ScriptedWalletdTransport {
    let mut transport = ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 1,
        expires_at: 0,
    });
    transport.set_approve_response(ScriptedWalletdResponse::Approve {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Approved,
    });
    transport.set_reject_response(ScriptedWalletdResponse::Reject {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Rejected,
    });
    transport.set_get_response(ScriptedWalletdResponse::Get {
        request_id: 1,
        status: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1::Submitted,
        transaction_id: Some(canonical_transaction_id()),
    });
    transport.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: canonical_transaction_id(),
    });
    transport
}

#[must_use]
pub fn finalized_indexer_transport(
    receipt: tari_cc_private_ballot_anchor_transport::AnchorReceiptV1,
) -> ScriptedIndexerTransport {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_response(finalized_response(receipt));
    transport
}

#[must_use]
pub fn finalized_response(
    receipt: tari_cc_private_ballot_anchor_transport::AnchorReceiptV1,
) -> ScriptedIndexerResponse {
    ScriptedIndexerResponse::Finalized(receipt)
}

#[must_use]
pub fn not_found_response() -> ScriptedIndexerResponse {
    ScriptedIndexerResponse::NotFound
}

#[must_use]
pub fn pending_response() -> ScriptedIndexerResponse {
    ScriptedIndexerResponse::Pending
}

#[must_use]
pub fn not_found_indexer_transport() -> ScriptedIndexerTransport {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::NotFound);
    transport
}

#[must_use]
pub fn rejected_indexer_transport() -> ScriptedIndexerTransport {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Rejected {
        reason: Some("execution failure".to_owned()),
    });
    transport
}

#[must_use]
pub fn pending_indexer_transport() -> ScriptedIndexerTransport {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Pending);
    transport
}

#[must_use]
pub fn accepted_receipt(
    tx: &AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1 {
    receipt_scenarios::accepted_receipt(tx, &canonical_network(), &canonical_payload())
}

#[must_use]
pub fn fee_only_receipt(
    tx: &AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1 {
    receipt_scenarios::fee_only_receipt(tx, &canonical_network())
}

#[must_use]
pub fn rejected_receipt(
    tx: &AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1 {
    receipt_scenarios::rejected_receipt(tx, &canonical_network())
}

#[must_use]
pub fn missing_anchor_log_receipt(
    tx: &AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1 {
    receipt_scenarios::accepted_missing_anchor_log(tx, &canonical_network())
}

fn to_lower_hex_32(byte: u8) -> String {
    let mut out = String::with_capacity(64);
    for _ in 0..32 {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

#[must_use]
pub fn lower_hex_32(byte: u8) -> String {
    to_lower_hex_32(byte)
}

/// Returns the canonical phase code for a [`UnifiedAnchorLifecyclePhase`].
#[must_use]
pub fn phase_code(phase: UnifiedAnchorLifecyclePhase) -> &'static str {
    phase.as_str()
}

/// Wraps an arbitrary body in a valid snapshot envelope (correct record-type,
/// hash-algorithm, and recomputed body digest). Used to test body-level
/// rejection paths without going through the validating public encoder.
#[must_use]
pub fn craft_snapshot_envelope(body: &[u8]) -> Vec<u8> {
    let digest = compute_snapshot_digest(body);
    craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &digest,
        body,
    )
}

/// Builds a snapshot envelope from explicit parts, without recomputing the
/// digest. Used to test envelope-level rejection paths (wrong record-type,
/// wrong hash-algorithm, digest mismatch, trailing bytes).
#[must_use]
pub fn craft_envelope_raw(
    record_type: &str,
    hash_algo: &str,
    digest: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    use tari_cc_private_ballot_protocol::CanonicalCborWriter;
    let mut writer = CanonicalCborWriter::new();
    let _ = writer.write_array_len(4);
    let _ = writer.write_text_string(record_type);
    let _ = writer.write_text_string(hash_algo);
    let _ = writer.write_byte_string(digest);
    let _ = writer.write_byte_string(body);
    writer.into_bytes()
}

#[must_use]
pub fn compute_snapshot_digest(body: &[u8]) -> [u8; 32] {
    use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
    let mut framed = Vec::with_capacity(
        SNAPSHOT_FRAME_PREFIX_V1.len() + 1 + SNAPSHOT_DOMAIN_LABEL_V1.len() + 1 + body.len(),
    );
    framed.extend_from_slice(SNAPSHOT_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(SNAPSHOT_DOMAIN_LABEL_V1.as_bytes());
    framed.push(0);
    framed.extend_from_slice(body);
    Blake3HashProviderV1.hash(&framed)
}

/// Writes `bytes` to a fresh temp file and reads it back as a snapshot.
pub fn read_snapshot_raw(
    bytes: &[u8],
) -> Result<
    tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot,
    SnapshotFileError,
> {
    let path = tmp_path("raw").join(format!("{}.cbor", unique_id()));
    match std::fs::write(&path, bytes) {
        Ok(()) => read_snapshot(&path),
        Err(_) => panic!("test raw write must succeed"),
    }
}

/// Reads the canonical bytes of a snapshot written to a fresh temp path.
pub fn snapshot_bytes(snapshot: &AnchorLifecycleRecoverySnapshot) -> Vec<u8> {
    let path = tmp_path("roundtrip").join(format!("{}.cbor", unique_id()));
    match write_snapshot_atomic(&path, snapshot) {
        Ok(()) => match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => panic!("test read must succeed"),
        },
        Err(_) => panic!("test write must succeed"),
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_id() -> u64 {
    UNIQUE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[must_use]
pub fn live_approval_facts() -> tari_cc_private_ballot_ootle_anchor_app::AnchorLiveApprovalFactsV1 {
    tari_cc_private_ballot_ootle_anchor_app::AnchorLiveApprovalFactsV1::new(
        2,
        2,
        false,
        false,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .unwrap_or_else(|_| panic!("live approval facts must construct"))
}

#[must_use]
pub fn reduced_live_approval_facts()
-> tari_cc_private_ballot_ootle_anchor_app::AnchorLiveApprovalFactsV1 {
    tari_cc_private_ballot_ootle_anchor_app::AnchorLiveApprovalFactsV1::new(
        2,
        2,
        true,
        true,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .unwrap_or_else(|_| panic!("reduced live approval facts must construct"))
}

#[must_use]
pub fn live_config() -> AnchorAppConfig {
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
        live_approval_facts(),
    )
}

use tari_cc_private_ballot_anchor_transport::AnchorRequestId;
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::PollingPolicy;

pub const FINGERPRINT_BYTE: u8 = 0x55;

#[must_use]
pub fn fingerprint() -> OotleAnchorInspectionFingerprintV1 {
    OotleAnchorInspectionFingerprintV1::new([FINGERPRINT_BYTE; 32])
}

#[must_use]
pub fn project_request_id() -> AnchorRequestId {
    match AnchorRequestId::new("anchor-request-001".to_owned()) {
        Ok(id) => id,
        Err(_) => panic!("test project request id must be valid"),
    }
}

#[must_use]
pub fn walletd_request_id() -> WalletdRequestId {
    WalletdRequestId::from_walletd(1)
}

#[must_use]
pub fn canonical_binding() -> WalletdAnchorBindingV1 {
    WalletdAnchorBindingV1::new(
        canonical_network(),
        canonical_account(),
        canonical_anchor_digest(),
        canonical_payload(),
        max_fee(),
        fingerprint(),
    )
}

#[must_use]
pub fn canonical_submitted() -> SubmittedWalletdAnchorRequestV1 {
    SubmittedWalletdAnchorRequestV1::new(
        project_request_id(),
        walletd_request_id(),
        canonical_transaction_id(),
        canonical_binding(),
    )
}

#[must_use]
pub fn canonical_query() -> AnchorReceiptQueryV1 {
    AnchorReceiptQueryV1::from_submitted(&canonical_submitted())
}

#[must_use]
pub fn walletd_snapshot(
    decision: WalletdRequestDecisionV1,
    submission: WalletdSubmissionStateV1,
    transaction_id: Option<AnchorTransactionId>,
    status: Option<WalletdEffectiveStatusV1>,
    retry: u32,
    sequence: u64,
) -> WalletdAnchorSnapshotV1 {
    WalletdAnchorSnapshotV1::new(
        project_request_id(),
        walletd_request_id(),
        canonical_binding(),
        decision,
        submission,
        transaction_id,
        status,
        retry,
        sequence,
        None,
    )
}

#[must_use]
pub fn receipt_snapshot(
    state: AnchorReceiptQueryStateV1,
    last_final_status: Option<tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1>,
    verified: bool,
    sequence: u64,
) -> AnchorReceiptQuerySnapshotV1 {
    AnchorReceiptQuerySnapshotV1::new(
        canonical_query(),
        state,
        last_final_status,
        verified,
        sequence,
        None,
    )
}

use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot;

#[must_use]
pub fn empty_snapshot() -> AnchorLifecycleRecoverySnapshot {
    AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::NotPrepared,
        None,
    )
}

#[must_use]
pub fn approved_snapshot() -> AnchorLifecycleRecoverySnapshot {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::NotSubmitted,
        None,
        Some(WalletdEffectiveStatusV1::Approved),
        0,
        1,
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Approved,
        None,
    )
}

#[must_use]
pub fn known_answer_snapshot() -> AnchorLifecycleRecoverySnapshot {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
        Some(tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1::Accepted),
        true,
        1,
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    )
}

#[must_use]
pub fn submitted_snapshot() -> AnchorLifecycleRecoverySnapshot {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::SubmittedNotQueried,
        None,
        false,
        1,
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    )
}

#[must_use]
pub fn polling_in_progress_snapshot(consumed: u32) -> AnchorLifecycleRecoverySnapshot {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptNotFound,
        None,
        false,
        u64::from(consumed),
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, consumed),
        UnifiedAnchorLifecyclePhase::PollingInProgress,
        None,
    )
}
