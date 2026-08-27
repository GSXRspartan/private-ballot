//! Organizer-side in-process live Ootle anchor publish facade.
//!
//! This module is the gui-core library boundary: it enforces the privacy
//! floor, parses the operator decision, maps driver errors to bounded GUI
//! errors, and composes the public result from a single lifecycle step. It
//! deliberately handles NO walletd auth secret and constructs NO real network
//! transport — those are shell-layer concerns (see the Tauri command). The
//! generic [`run_step_with_transports`] seam accepts pre-built adapters so
//! production passes real transports and tests pass scripted ones.
//!
//! Guarantees preserved at this boundary:
//!
//! * **Archive authority**: every step re-verifies the finalized archive
//!   directory against the canonical config (`restore_live`) before any
//!   network action. Ootle can never bless an unverified or mutated archive.
//! * **Privacy floor**: GUI-driven publishing refuses configs whose explicit
//!   accepted-ballot floor is below
//!   [`GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1`] (or whose
//!   verified cohort is below that floor), so one-voter smoke archives cannot
//!   be casually anchored through this application. The standalone CLI and
//!   offline commitment computation remain unchanged.
//! * **No secrets cross this boundary**: auth resolution and transport
//!   construction are shell-layer concerns. This module never references a
//!   walletd bearer token, seed, or signer secret.
//! * **Bounded steps**: each invocation performs at most one lifecycle
//!   transition via [`AnchorAppDriver::run_single_step`] and never sleeps.

use std::path::Path;

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, DriverError, DriverRunOutcome, MachineReportCode,
    OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1, OperatorDecision,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, IndexerReceiptWireTransport, WalletdAnchorNetworkAdapter,
    WalletdWireTransport,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use crate::error::{GuiCoreError, GuiErrorCategory};

/// Minimum accepted-ballot floor enforced for GUI-driven anchor publishing.
///
/// This is a re-export of the single canonical policy source
/// ([`OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1`], enforced in the
/// shared driver layer for GUI, CLI, and direct driver invocations alike) so
/// there is exactly one definition and no divergent duplicate. A public
/// aggregate anchor over a single ballot would reduce the smallest possible
/// anonymity set to one person, so one-voter cohorts are blocked at the publish
/// boundary even though offline commitment computation and independent
/// verification remain universally available.
pub const GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1: u64 =
    OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1;

/// Public inputs for one bounded live anchor lifecycle step.
///
/// The frontend can NOT choose which environment variable holds the walletd
/// bearer secret (a confused-deputy exfiltration risk): it only signals whether
/// to use auth at all. When `use_walletd_auth` is set, the shell reads the
/// single backend-owned variable [`walletd_auth_env_var_name`] and nothing
/// else.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GuiLiveAnchorStepRequestV1 {
    /// Canonical anchor application config path (generated from the verified
    /// finalized archive by `write_live_anchor_config_from_verified_archive_v1`).
    pub config_path: String,
    /// The finalized archive directory the config was derived from. It is
    /// re-verified against the config before any network action.
    pub archive_directory: String,
    /// Whether the shell should attach the optional walletd bearer token read
    /// from the fixed backend-owned environment variable. The frontend never
    /// supplies a variable name or the token itself.
    #[serde(default)]
    pub use_walletd_auth: bool,
    /// Explicit operator gate: `approve`, `reject`, or `none`.
    pub decision: String,
}

/// The single, backend-owned environment variable name that may hold the
/// walletd bearer token. Re-exported from the shared policy module so the shell
/// and the frontend contract share exactly one definition.
#[must_use]
pub fn walletd_auth_env_var_name() -> &'static str {
    tari_cc_private_ballot_ootle_anchor_app::WALLETD_AUTH_TOKEN_ENV_VAR_V1
}

/// Safe public result of one bounded live anchor lifecycle step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiLiveAnchorStepResultV1 {
    /// Stable machine code for this step (`ANCHOR_APP_*`).
    pub machine_code: String,
    /// Lifecycle phase after this step.
    pub phase: String,
    /// Whether the phase is terminal.
    pub phase_is_terminal: bool,
    /// Whether the phase is the single terminal success state.
    pub phase_is_terminal_success: bool,
    /// Bound transaction id, when one exists.
    pub transaction_id: Option<String>,
    /// Suggested backoff seconds before the next poll attempt.
    pub next_backoff_secs: Option<u64>,
    /// Last bounded lifecycle diagnostic, if any.
    pub diagnostic: Option<&'static str>,
    /// Canonical evidence record path bound in the config.
    pub evidence_path: String,
    /// Whether a terminal evidence record exists at that path now.
    pub evidence_written: bool,
    /// Durable lifecycle snapshot path bound in the config.
    pub snapshot_path: String,
    /// Public Ootle network id.
    pub network: String,
    /// Derived election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Derived finalized archive hash, lowercase hex.
    pub archive_hash_hex: String,
    /// Aggregate anchor commitment digest, lowercase hex.
    pub anchor_digest_hex: String,
}

/// Parses the operator decision string. Shell calls this before constructing
/// any transport.
///
/// # Errors
///
/// Returns [`GuiCoreError::anchor_publish_decision_invalid`] for any string
/// other than `approve`, `reject`, or `none`.
pub fn parse_decision(raw: &str) -> Result<OperatorDecision, GuiCoreError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "approve" => Ok(OperatorDecision::Approve),
        "reject" => Ok(OperatorDecision::Reject),
        "none" => Ok(OperatorDecision::NoDecision),
        _ => Err(GuiCoreError::anchor_publish_decision_invalid()),
    }
}

/// Enforces the GUI publish privacy floor on a loaded config. Shell calls
/// this before constructing any transport.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] if the config lacks live approval
/// facts, the floor is below the minimum, or the cohort is below the floor.
pub fn enforce_publish_privacy_floor(config: &AnchorAppConfig) -> Result<(), GuiCoreError> {
    let Some(facts) = config.live_approval_facts() else {
        return Err(GuiCoreError::anchor_publish_live_facts_missing());
    };
    if facts.required_accepted_ballot_floor()
        < GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1
    {
        return Err(GuiCoreError::anchor_publish_privacy_floor());
    }
    if facts.accepted_ballot_count() < facts.required_accepted_ballot_floor() {
        return Err(GuiCoreError::anchor_publish_accepted_below_floor());
    }
    Ok(())
}

/// Generic core shared by the live entry point and deterministic tests. Every
/// behavior here is identical regardless of transport implementation.
///
/// This is the testable seam: production passes the real transports and
/// `terminal_index_root = None` (production default), tests pass scripted
/// transports and an optional temp-dir override. It performs no I/O of its
/// own beyond what the supplied transports and the driver require.
#[doc(hidden)]
pub fn run_step_with_transports<W, I>(
    config: AnchorAppConfig,
    archive_directory: &Path,
    decision: OperatorDecision,
    walletd_adapter: WalletdAnchorNetworkAdapter<W>,
    indexer_adapter: IndexerReceiptNetworkAdapter<I>,
    terminal_index_root: Option<&Path>,
) -> Result<GuiLiveAnchorStepResultV1, GuiCoreError>
where
    W: WalletdWireTransport,
    I: IndexerReceiptWireTransport,
{
    enforce_publish_privacy_floor(&config)?;
    let mut driver = AnchorAppDriver::restore_live(
        config.clone(),
        walletd_adapter,
        indexer_adapter,
        archive_directory,
    )
    .map_err(map_driver_error)?;
    #[cfg(feature = "test-support")]
    if let Some(root) = terminal_index_root {
        driver = driver.with_terminal_index_root_for_test(root.to_path_buf());
    }
    #[cfg(not(feature = "test-support"))]
    let _ = terminal_index_root;
    let step = driver.run_single_step(decision).map_err(map_driver_error)?;

    let evidence_path = driver.evidence_path().to_path_buf();
    let evidence_written = step
        .outcome
        .as_ref()
        .and_then(DriverRunOutcome::evidence)
        .is_some()
        && evidence_path.is_file();
    let snapshot = driver.snapshot();
    Ok(GuiLiveAnchorStepResultV1 {
        machine_code: machine_code_for(&step.outcome, step.phase).to_owned(),
        phase: step.phase.as_str().to_owned(),
        phase_is_terminal: step.phase.is_terminal(),
        phase_is_terminal_success: step.phase.is_terminal_success(),
        transaction_id: step
            .transaction_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        next_backoff_secs: step.next_backoff_secs,
        diagnostic: snapshot.diagnostic(),
        evidence_path: evidence_path.to_string_lossy().into_owned(),
        evidence_written,
        snapshot_path: driver.snapshot_path().to_string_lossy().into_owned(),
        network: driver.walletd_adapter().network().as_str().to_owned(),
        manifest_hash_hex: crate::hex::to_lower_hex(config.archive_manifest_hash().as_bytes()),
        archive_hash_hex: crate::hex::to_lower_hex(config.archive_hash().as_bytes()),
        anchor_digest_hex: anchor_digest_hex(&config)?,
    })
}

fn machine_code_for(
    outcome: &Option<DriverRunOutcome>,
    phase: UnifiedAnchorLifecyclePhase,
) -> &'static str {
    if let Some(outcome) = outcome {
        return outcome.report_code().as_str();
    }
    match phase {
        UnifiedAnchorLifecyclePhase::Approved => MachineReportCode::Approved.as_str(),
        UnifiedAnchorLifecyclePhase::Submitted | UnifiedAnchorLifecyclePhase::PollingInProgress => {
            MachineReportCode::Polling.as_str()
        }
        UnifiedAnchorLifecyclePhase::Unknown => MachineReportCode::Recovered.as_str(),
        _ => MachineReportCode::Prepared.as_str(),
    }
}

fn anchor_digest_hex(config: &AnchorAppConfig) -> Result<String, GuiCoreError> {
    let record = OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    );
    let digest = record
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-record"))?;
    Ok(crate::hex::to_lower_hex(digest.as_bytes()))
}

/// Maps a [`DriverError`] to a bounded [`GuiCoreError`]. Public so the shell
/// can reuse the same mapping for errors from its own transport construction.
pub fn map_driver_error(error: DriverError) -> GuiCoreError {
    let (code, category, message) = match &error {
        DriverError::InvalidBackoff => (
            "ANCHOR_PUBLISH_INVALID_BACKOFF",
            GuiErrorCategory::InvalidInput,
            "the anchor backoff schedule is invalid",
        ),
        DriverError::Snapshot(_) => (
            "ANCHOR_PUBLISH_SNAPSHOT_FAILURE",
            GuiErrorCategory::AnchorArtifactIntegrity,
            "an anchor snapshot read or write failed",
        ),
        DriverError::Evidence(_) => (
            "ANCHOR_PUBLISH_EVIDENCE_FAILURE",
            GuiErrorCategory::AnchorArtifactIntegrity,
            "anchor evidence construction or writing failed",
        ),
        DriverError::Lifecycle(_) => (
            "ANCHOR_PUBLISH_LIFECYCLE_REJECTED",
            GuiErrorCategory::InvalidLifecycleTransition,
            "the anchor lifecycle rejected the requested step in its current phase",
        ),
        DriverError::Reconstruction => (
            "ANCHOR_PUBLISH_SNAPSHOT_RECONSTRUCTION",
            GuiErrorCategory::AnchorArtifactIntegrity,
            "a persisted anchor snapshot could not be safely reconstructed",
        ),
        DriverError::ReceiptRetrieval => (
            "ANCHOR_PUBLISH_RECEIPT_RETRIEVAL",
            GuiErrorCategory::Unavailable,
            "the accepted-anchor receipt could not be re-queried",
        ),
        DriverError::ConfigSnapshotBindingMismatch => (
            "ANCHOR_PUBLISH_CONFIG_SNAPSHOT_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            "the config does not match the persisted lifecycle binding",
        ),
        DriverError::EvidenceBindingMismatch => (
            "ANCHOR_PUBLISH_EVIDENCE_BINDING_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            "the verified receipt does not match the configured archive anchor",
        ),
        DriverError::OfflineTestRawHashesNotLiveApproved => (
            "ANCHOR_PUBLISH_NOT_LIVE_APPROVED",
            GuiErrorCategory::InvalidInput,
            "this config provenance is not eligible for live publishing",
        ),
        DriverError::LiveApprovalFactsRequired => (
            "ANCHOR_PUBLISH_LIVE_FACTS_REQUIRED",
            GuiErrorCategory::InvalidInput,
            "the config lacks the immutable live approval facts required for publishing",
        ),
        DriverError::LiveTransactionFingerprintRequired => (
            "ANCHOR_PUBLISH_FINGERPRINT_REQUIRED",
            GuiErrorCategory::AnchorArtifactIntegrity,
            "the prepared transaction fingerprint required for evidence is missing",
        ),
        DriverError::TerminalIndex(_) => (
            "ANCHOR_PUBLISH_TERMINAL_INDEX_CONFLICT",
            GuiErrorCategory::BindingMismatch,
            "a conflicting terminal anchor already exists for this election",
        ),
        DriverError::RuntimeArchiveRequired => (
            "ANCHOR_PUBLISH_RUNTIME_ARCHIVE_REQUIRED",
            GuiErrorCategory::InvalidInput,
            "a verified runtime archive directory is required before publishing",
        ),
        DriverError::RuntimeArchiveVerificationFailed => (
            "ANCHOR_PUBLISH_ARCHIVE_VERIFICATION_FAILED",
            GuiErrorCategory::ArchiveIntegrity,
            "the archive failed verification; nothing was published",
        ),
        DriverError::RuntimeArchiveBindingMismatch => (
            "ANCHOR_PUBLISH_ARCHIVE_BINDING_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            "the archive does not match this anchor config; nothing was published",
        ),
        // HIGH-4 shared privacy floor (also enforced early by
        // `enforce_publish_privacy_floor`; this covers the CLI/direct path).
        DriverError::PrivacyFloorNotMet => {
            return GuiCoreError::anchor_publish_privacy_floor();
        }
        // HIGH-2 containment, HIGH-3 endpoint policy, HIGH-1 locking: mapped to
        // the dedicated bounded constructors.
        DriverError::OutputPathWithinArchive => {
            return GuiCoreError::anchor_publish_output_within_archive();
        }
        DriverError::NonLoopbackEndpoint => {
            return GuiCoreError::anchor_publish_endpoint_not_loopback();
        }
        DriverError::PublishLockBusy => {
            return GuiCoreError::anchor_publish_lock_busy();
        }
        DriverError::PublishLockUnavailable => {
            return GuiCoreError::anchor_publish_lock_unavailable();
        }
        DriverError::CreateIntent(_) => (
            "ANCHOR_PUBLISH_CREATE_INTENT_FAILURE",
            GuiErrorCategory::AnchorArtifactIntegrity,
            "the durable walletd create-intent record could not be maintained",
        ),
        DriverError::CreateRecoveryRequired => (
            "ANCHOR_PUBLISH_CREATE_RECOVERY_REQUIRED",
            GuiErrorCategory::InvalidLifecycleTransition,
            "a prior walletd create result is unknown and requires operator reconciliation",
        ),
    };
    GuiCoreError::new(code, category, Some("anchor-publish"), message)
}
