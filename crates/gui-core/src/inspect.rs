//! Structured, read-only anchor artifact inspectors.
//!
//! These wrappers give a future GUI structured objects equivalent to the
//! anchor application's `--write-config` (read direction), `--inspect-snapshot`,
//! and `--verify-evidence` CLI modes, without parsing CLI stdout, without
//! printing, without writing files, and without any network contact. They
//! call the existing canonical/digest-validating decoders verbatim and run
//! the same semantic lifecycle reconstruction for snapshots.
//!
//! No inspected value is secret: configs never carry walletd auth, and
//! snapshots and evidence records contain only public identifiers, digests,
//! and bounded status codes.

use std::path::Path;

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_ootle_anchor_app::evidence::MAX_EVIDENCE_FILE_BYTES;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorEvidenceRecordV1, MAX_SNAPSHOT_FILE_BYTES, read_snapshot,
    snapshot_digest,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleOrchestrator;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdSealSignerRef;
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use crate::error::GuiCoreError;

/// Structured inspection of one canonical anchor application config.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiAnchorConfigInspectionV1 {
    /// Canonical input provenance (`ArchiveVerified` or `OfflineTestRawHashes`).
    pub input_provenance: String,
    /// Selected network identifier.
    pub network: String,
    /// Configured walletd JSON-RPC endpoint (no credentials).
    pub walletd_endpoint: String,
    /// Configured indexer REST endpoint.
    pub indexer_endpoint: String,
    /// Fee account reference label.
    pub account_reference: String,
    /// Fee component address rendering.
    pub fee_component: String,
    /// Seal signer reference rendering (`ACCOUNT_KEY:n`, etc.).
    pub seal_signer: String,
    /// Maximum fee ceiling.
    pub max_fee: u64,
    /// Optional request timeout in seconds.
    pub request_timeout_secs: Option<u64>,
    /// Maximum receipt-query attempts.
    pub receipt_query_max_attempts: u32,
    /// Election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Archive hash, lowercase hex.
    pub archive_hash_hex: String,
    /// Anchor-record digest derived from the locator triple, lowercase hex.
    pub anchor_digest_hex: String,
    /// Snapshot path recorded in the config.
    pub snapshot_path: String,
    /// Evidence path recorded in the config.
    pub evidence_path: String,
    /// Poll backoff base in seconds.
    pub backoff_base_secs: u64,
    /// Poll backoff cap in seconds.
    pub backoff_cap_secs: u64,
    /// Optional transaction TTL in seconds.
    pub ttl_secs: Option<u64>,
}

/// Structured walletd-side snapshot summary (public fields only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiWalletdSnapshotSummaryV1 {
    /// Deterministic project request identifier.
    pub project_request_id: String,
    /// Opaque walletd request identifier.
    pub walletd_request_id: i32,
    /// Bound network identifier.
    pub network: String,
    /// Bound fee account reference label.
    pub account_reference: String,
    /// Bound anchor-record digest, lowercase hex.
    pub anchor_digest_hex: String,
    /// Bound exact anchor `EmitLog` payload rendering.
    pub anchor_payload: String,
    /// Bound maximum fee.
    pub max_fee: u64,
    /// Bound unsigned-transaction fingerprint, lowercase hex.
    pub transaction_fingerprint_hex: String,
    /// Recorded decision state code.
    pub decision: &'static str,
    /// Recorded submission-attempt state code.
    pub submission_state: &'static str,
    /// Bound sealed transaction id, when known.
    pub transaction_id: Option<String>,
    /// Last confirmed walletd effective status code, when observed.
    pub effective_status: Option<&'static str>,
    /// Recovery-gated submit retry count.
    pub retry_count: u32,
    /// Deterministic registration sequence.
    pub sequence: u64,
    /// Last bounded diagnostic code, if any.
    pub diagnostic: Option<&'static str>,
}

/// Structured receipt-query snapshot summary (public fields only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiReceiptSnapshotSummaryV1 {
    /// Deterministic project request identifier.
    pub project_request_id: String,
    /// Opaque walletd request identifier.
    pub walletd_request_id: i32,
    /// Sealed transaction identifier.
    pub transaction_id: String,
    /// Bound network identifier.
    pub network: String,
    /// Bound fee account reference label.
    pub account_reference: String,
    /// Bound anchor-record digest, lowercase hex.
    pub anchor_digest_hex: String,
    /// Bound exact anchor `EmitLog` payload rendering.
    pub anchor_payload: String,
    /// Bound unsigned-transaction fingerprint, lowercase hex.
    pub transaction_fingerprint_hex: String,
    /// Recorded query state code.
    pub query_state: &'static str,
    /// Last observed finalized status code, if any.
    pub final_status: Option<&'static str>,
    /// Whether the anchor was verified from a finalized full acceptance.
    pub verified: bool,
    /// Deterministic registration sequence.
    pub sequence: u64,
    /// Last bounded diagnostic code, if any.
    pub diagnostic: Option<&'static str>,
}

/// Structured inspection of one durable anchor lifecycle snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiAnchorSnapshotInspectionV1 {
    /// Domain-separated snapshot digest, lowercase hex.
    pub snapshot_digest_hex: String,
    /// Unified lifecycle phase code.
    pub phase: &'static str,
    /// Whether the phase is terminal.
    pub phase_is_terminal: bool,
    /// Whether the phase is a terminal success.
    pub phase_is_terminal_success: bool,
    /// Poll attempts consumed.
    pub poll_attempts_consumed: u32,
    /// Poll attempt bound.
    pub poll_attempts_max: u32,
    /// Submitted transaction id, when the lifecycle reached submission.
    pub submitted_transaction_id: Option<String>,
    /// Last bounded diagnostic code, if any.
    pub diagnostic: Option<&'static str>,
    /// Walletd-side snapshot summaries.
    pub walletd: Vec<GuiWalletdSnapshotSummaryV1>,
    /// Receipt-query snapshot summaries.
    pub receipts: Vec<GuiReceiptSnapshotSummaryV1>,
}

/// Structured inspection of one canonical anchor evidence record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiAnchorEvidenceInspectionV1 {
    /// Evidence body digest, lowercase hex.
    pub record_digest_hex: String,
    /// Final status vocabulary string.
    pub final_status: &'static str,
    /// Receipt source vocabulary string.
    pub receipt_source: &'static str,
    /// Lifecycle phase code recorded for this evidence.
    pub phase: &'static str,
    /// Network identifier.
    pub network: String,
    /// Election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Archive hash, lowercase hex.
    pub archive_hash_hex: String,
    /// Anchor-record digest, lowercase hex.
    pub anchor_digest_hex: String,
    /// Bound transaction id, if any.
    pub transaction_id: Option<String>,
    /// Recorded ledger position, if any.
    pub ledger_position: Option<u64>,
    /// Snapshot digest bound into the evidence, lowercase hex.
    pub snapshot_digest_hex: String,
    /// The fixed human-review summary (contains the non-binding statement).
    pub human_review_summary: String,
}

/// Inspects one canonical anchor application config file.
///
/// Decodes and digest-validates through the existing config loader and
/// derives the anchor-record digest from the configured locator triple,
/// exactly as the application driver's dry-run path does. Never contacts a
/// transport.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] on any validation failure.
pub fn inspect_anchor_config_v1(path: &Path) -> Result<GuiAnchorConfigInspectionV1, GuiCoreError> {
    let config = AnchorAppConfig::from_canonical_file(path)?;
    let adapter = config.network_adapter();

    let record = OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    );
    let anchor_digest = record
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-config"))?;

    let seal_signer = match adapter.seal_signer() {
        WalletdSealSignerRef::AccountKey { index } => format!("ACCOUNT_KEY:{index}"),
        WalletdSealSignerRef::TransactionKey { index } => format!("TRANSACTION_KEY:{index}"),
        WalletdSealSignerRef::ImportedKey { local_key_id } => {
            format!("IMPORTED_KEY:{local_key_id}")
        }
    };

    Ok(GuiAnchorConfigInspectionV1 {
        input_provenance: config.input_provenance().as_str().to_owned(),
        network: config.anchor_record_network().as_str().to_owned(),
        walletd_endpoint: adapter.walletd_endpoint().as_str().to_owned(),
        indexer_endpoint: adapter.indexer_endpoint().as_str().to_owned(),
        account_reference: config.account_reference().as_str().to_owned(),
        fee_component: adapter.fee_component().display_string(),
        seal_signer,
        max_fee: adapter.max_fee().value(),
        request_timeout_secs: adapter.request_timeout_secs(),
        receipt_query_max_attempts: adapter.receipt_query_max_attempts(),
        manifest_hash_hex: crate::hex::to_lower_hex(config.archive_manifest_hash().as_bytes()),
        archive_hash_hex: crate::hex::to_lower_hex(config.archive_hash().as_bytes()),
        anchor_digest_hex: crate::hex::to_lower_hex(anchor_digest.as_bytes()),
        snapshot_path: config.snapshot_path().to_string_lossy().into_owned(),
        evidence_path: config.evidence_path().to_string_lossy().into_owned(),
        backoff_base_secs: config.backoff_base_secs(),
        backoff_cap_secs: config.backoff_cap_secs(),
        ttl_secs: config.ttl_secs(),
    })
}

/// Inspects one durable anchor lifecycle snapshot file.
///
/// Runs the same four validation stages as the CLI `--inspect-snapshot`
/// mode: envelope/record-type validation, digest validation, structural
/// decode, and semantic lifecycle reconstruction
/// ([`AnchorLifecycleOrchestrator::from_snapshot`]). Never contacts a
/// transport and never mutates the file.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] on any validation failure.
pub fn inspect_anchor_snapshot_v1(
    path: &Path,
) -> Result<GuiAnchorSnapshotInspectionV1, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| GuiCoreError::file_not_found("anchor-snapshot"))?;
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure("anchor-snapshot"));
    }
    if metadata.len() > MAX_SNAPSHOT_FILE_BYTES as u64 {
        return Err(GuiCoreError::new(
            "PROTOCOL_LIMIT_EXCEEDED",
            crate::error::GuiErrorCategory::InvalidInput,
            Some("anchor-snapshot"),
            "snapshot file exceeds the protocol object size limit",
        ));
    }

    let snapshot = read_snapshot(path)?;
    let digest = snapshot_digest(&snapshot)?;

    // Semantic reconstruction validation, exactly as the CLI inspector: the
    // declared phase must be consistent with the contained walletd snapshots,
    // receipt snapshots, submitted handle, and polling policy.
    AnchorLifecycleOrchestrator::from_snapshot(snapshot.clone())?;

    let walletd = snapshot
        .walletd_snapshots()
        .iter()
        .map(|entry| {
            let binding = entry.binding();
            GuiWalletdSnapshotSummaryV1 {
                project_request_id: entry.project_request_id().as_str().to_owned(),
                walletd_request_id: entry.walletd_request_id().value(),
                network: binding.network().as_str().to_owned(),
                account_reference: binding.account().as_str().to_owned(),
                anchor_digest_hex: crate::hex::to_lower_hex(binding.anchor_digest().as_bytes()),
                anchor_payload: binding.payload().to_encoded_string(),
                max_fee: binding.max_fee().value(),
                transaction_fingerprint_hex: crate::hex::to_lower_hex(
                    binding.fingerprint().as_bytes(),
                ),
                decision: entry.decision().as_str(),
                submission_state: entry.submission().as_str(),
                transaction_id: entry.transaction_id().map(|id| id.as_str().to_owned()),
                effective_status: entry.last_effective_status().map(|status| status.as_str()),
                retry_count: entry.retry_count(),
                sequence: entry.sequence(),
                diagnostic: entry.last_diagnostic(),
            }
        })
        .collect();

    let receipts = snapshot
        .receipt_snapshots()
        .iter()
        .map(|entry| GuiReceiptSnapshotSummaryV1 {
            project_request_id: entry.project_request_id().as_str().to_owned(),
            walletd_request_id: entry.walletd_request_id().value(),
            transaction_id: entry.transaction_id().as_str().to_owned(),
            network: entry.network().as_str().to_owned(),
            account_reference: entry.account().as_str().to_owned(),
            anchor_digest_hex: crate::hex::to_lower_hex(entry.anchor_digest().as_bytes()),
            anchor_payload: entry.payload().to_encoded_string(),
            transaction_fingerprint_hex: crate::hex::to_lower_hex(entry.fingerprint().as_bytes()),
            query_state: entry.state().as_str(),
            final_status: entry.last_final_status().map(|status| status.as_str()),
            verified: entry.verified(),
            sequence: entry.sequence(),
            diagnostic: entry.last_diagnostic(),
        })
        .collect();

    Ok(GuiAnchorSnapshotInspectionV1 {
        snapshot_digest_hex: crate::hex::to_lower_hex(&digest),
        phase: snapshot.phase().as_str(),
        phase_is_terminal: snapshot.phase().is_terminal(),
        phase_is_terminal_success: snapshot.phase().is_terminal_success(),
        poll_attempts_consumed: snapshot.policy().attempts_consumed(),
        poll_attempts_max: snapshot.policy().max_query_attempts(),
        submitted_transaction_id: snapshot.transaction_id().map(|id| id.as_str().to_owned()),
        diagnostic: snapshot.diagnostic(),
        walletd,
        receipts,
    })
}

/// Inspects one canonical anchor evidence file.
///
/// Decodes through the existing digest-verifying decoder
/// ([`AnchorEvidenceRecordV1::from_canonical_bytes`]), exactly as the CLI
/// `--verify-evidence` mode. Never contacts the network and never mutates
/// the file.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] on any validation failure.
pub fn inspect_anchor_evidence_v1(
    path: &Path,
) -> Result<GuiAnchorEvidenceInspectionV1, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| GuiCoreError::file_not_found("anchor-evidence"))?;
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure("anchor-evidence"));
    }
    if metadata.len() > MAX_EVIDENCE_FILE_BYTES as u64 {
        return Err(GuiCoreError::new(
            "PROTOCOL_LIMIT_EXCEEDED",
            crate::error::GuiErrorCategory::InvalidInput,
            Some("anchor-evidence"),
            "evidence file exceeds the protocol object size limit",
        ));
    }
    let bytes = std::fs::read(path).map_err(|_| GuiCoreError::io_failure("anchor-evidence"))?;

    let record = AnchorEvidenceRecordV1::from_canonical_bytes(&bytes)?;

    Ok(GuiAnchorEvidenceInspectionV1 {
        record_digest_hex: crate::hex::to_lower_hex(&record.digest()),
        final_status: record.final_status(),
        receipt_source: record.receipt_source(),
        phase: record.phase().as_str(),
        network: record.network().as_str().to_owned(),
        manifest_hash_hex: crate::hex::to_lower_hex(record.manifest_hash().as_bytes()),
        archive_hash_hex: crate::hex::to_lower_hex(record.archive_hash().as_bytes()),
        anchor_digest_hex: crate::hex::to_lower_hex(record.anchor_digest().as_bytes()),
        transaction_id: record.transaction_id().map(|id| id.as_str().to_owned()),
        ledger_position: record.ledger_position(),
        snapshot_digest_hex: crate::hex::to_lower_hex(&record.snapshot_digest()),
        human_review_summary: record.human_review_summary(),
    })
}
