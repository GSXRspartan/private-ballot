//! Application driver that wires the Slice 4A9 real network adapters into the
//! Slice 4A8 lifecycle orchestrator (Slice 4A10).
//!
//! The driver is generic over the wire transport so the same code path can be
//! exercised offline with the Slice 4A9 scripted transports and online with
//! the Slice 4A9 real transports (which require a [`BlockingExecutor`]). It
//! never reimplements any coordinator, orchestrator, or adapter logic: every
//! step delegates to the existing [`AnchorLifecycleOrchestrator`] methods
//! verbatim.
//!
//! The driver:
//!
//! * prepares, approves, rejects, submits, recovers, polls, and finalizes;
//! * persists a canonical snapshot after every state-changing step;
//! * maps the Slice 4A8 abstract polling-attempt index to a bounded
//!   [`std::thread::sleep`] via [`WallClockBackoff`];
//! * never sleeps before the first attempt, after a terminal state, or after
//!   polling-policy exhaustion;
//! * never blind-resubmits;
//! * never claims finality before a verified `FinalizedAccept`;
//! * produces a canonical [`AnchorEvidenceRecordV1`] for every terminal
//!   outcome and writes it atomically;
//! * for the standalone live path, checks a manifest-scoped terminal index
//!   before preparing and records terminal evidence after finality.

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorBindingV1, AnchorLogPayloadV1, AnchorPreparationRequest,
};
use tari_cc_private_ballot_archive::{
    ArchiveDirectoryVerificationV1, ArchiveHashV1, verify_archive_directory_v1,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, AnchorLifecycleRecoverySnapshot, LifecycleError, PollingPolicy,
    UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, IndexerReceiptWireTransport, WalletdAnchorNetworkAdapter,
    WalletdWireTransport,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptCoordinator, AnchorReceiptQueryV1, VerifiedIndexerAnchorV1,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorSnapshotV1, WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

use crate::backoff::WallClockBackoff;
use crate::config::{AnchorAppConfig, AnchorConfigInputProvenanceV1};
use crate::evidence::{
    AnchorEvidenceRecordV1, ArchiveProofInputs, EvidenceError, EvidenceFileError,
    LiveEvidenceApprovalFactsV1, TerminalEvidenceInputs, write_evidence_atomic,
};
use crate::report::MachineReportCode;
use crate::snapshot_store::{self, SnapshotFileError};
use crate::terminal_index::{
    TerminalAnchorIndexRecordV1, TerminalIndexError, default_terminal_index_root,
    read_terminal_index, write_terminal_index,
};

/// Bounded failure while constructing or running the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// The backoff schedule was invalid.
    InvalidBackoff,
    /// A snapshot read or write failed.
    Snapshot(SnapshotFileError),
    /// Evidence construction or writing failed.
    Evidence(EvidenceError),
    /// The lifecycle orchestrator returned an error.
    Lifecycle(LifecycleError),
    /// A snapshot could not be reconstructed after restart.
    Reconstruction,
    /// A receipt re-query failed after a terminal acceptance.
    ReceiptRetrieval,
    /// The current configuration does not match the immutable anchor binding
    /// recorded in the persisted snapshot. The configuration must not be
    /// allowed to reinterpret a lifecycle created for another archive,
    /// election, network, account, fee, payload, or transaction.
    ConfigSnapshotBindingMismatch,
    /// The verified indexer receipt does not match the config-derived archive
    /// locators. ACCEPTED evidence cannot be created for a different archive,
    /// network, or transaction than the one the receipt actually verified.
    EvidenceBindingMismatch,
    /// The config was built from test-only raw hashes and is not eligible for
    /// a live prepare/approve/submit lifecycle.
    OfflineTestRawHashesNotLiveApproved,
    /// The live driver requires immutable approval facts in the canonical
    /// config before it can prepare, approve, submit, or claim idempotent
    /// terminal success.
    LiveApprovalFactsRequired,
    /// Live evidence requires the prepared walletd binding fingerprint.
    LiveTransactionFingerprintRequired,
    /// A manifest-scoped terminal index failed validation or reported a
    /// conflicting terminal anchor before transaction preparation.
    TerminalIndex(TerminalIndexError),
    /// An archive-verified config was run without the required runtime archive proof.
    RuntimeArchiveRequired,
    /// Runtime archive verification failed before any live lifecycle action.
    RuntimeArchiveVerificationFailed,
    /// Runtime archive facts did not exactly match the canonical config.
    RuntimeArchiveBindingMismatch,
}

impl DriverError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidBackoff => "DRIVER_INVALID_BACKOFF",
            Self::Snapshot(error) => error.as_str(),
            Self::Evidence(error) => error.as_str(),
            Self::Lifecycle(error) => error.as_str(),
            Self::Reconstruction => "DRIVER_RECONSTRUCTION",
            Self::ReceiptRetrieval => "DRIVER_RECEIPT_RETRIEVAL",
            Self::ConfigSnapshotBindingMismatch => "DRIVER_CONFIG_SNAPSHOT_BINDING_MISMATCH",
            Self::EvidenceBindingMismatch => "DRIVER_EVIDENCE_BINDING_MISMATCH",
            Self::OfflineTestRawHashesNotLiveApproved => {
                "DRIVER_OFFLINE_TEST_RAW_HASHES_NOT_LIVE_APPROVED"
            }
            Self::LiveApprovalFactsRequired => "DRIVER_LIVE_APPROVAL_FACTS_REQUIRED",
            Self::LiveTransactionFingerprintRequired => {
                "DRIVER_LIVE_TRANSACTION_FINGERPRINT_REQUIRED"
            }
            Self::TerminalIndex(error) => error.as_str(),
            Self::RuntimeArchiveRequired => "DRIVER_RUNTIME_ARCHIVE_REQUIRED",
            Self::RuntimeArchiveVerificationFailed => "DRIVER_RUNTIME_ARCHIVE_VERIFICATION_FAILED",
            Self::RuntimeArchiveBindingMismatch => "DRIVER_RUNTIME_ARCHIVE_BINDING_MISMATCH",
        }
    }
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for DriverError {}

impl From<SnapshotFileError> for DriverError {
    fn from(error: SnapshotFileError) -> Self {
        Self::Snapshot(error)
    }
}

impl From<EvidenceError> for DriverError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

impl From<LifecycleError> for DriverError {
    fn from(error: LifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

impl From<TerminalIndexError> for DriverError {
    fn from(error: TerminalIndexError) -> Self {
        Self::TerminalIndex(error)
    }
}

impl From<tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleReconstructionError>
    for DriverError
{
    fn from(
        _error: tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleReconstructionError,
    ) -> Self {
        Self::Reconstruction
    }
}

impl From<tari_cc_private_ballot_ootle_receipt_anchor_adapter::ReceiptRetrievalError>
    for DriverError
{
    fn from(
        _error: tari_cc_private_ballot_ootle_receipt_anchor_adapter::ReceiptRetrievalError,
    ) -> Self {
        Self::ReceiptRetrieval
    }
}

/// The terminal outcome of a single [`AnchorAppDriver::run`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverRunOutcome {
    /// The anchor was verified as finalized and accepted.
    FinalizedAccept(AnchorEvidenceRecordV1),
    /// The anchor finalized fee-only (the anchor did not land).
    FinalizedFeeOnly(AnchorEvidenceRecordV1),
    /// The anchor was finalized as rejected by the ledger.
    FinalizedReject(AnchorEvidenceRecordV1),
    /// Verification of a finalized receipt failed.
    VerificationFailed(AnchorEvidenceRecordV1),
    /// The walletd and indexer observations disagree.
    Disagreement(AnchorEvidenceRecordV1),
    /// The approver rejected the request before submission.
    RejectedByApprover(AnchorEvidenceRecordV1),
    /// Polling exhausted before finality was observed.
    PollExhaustedUnknown(AnchorEvidenceRecordV1),
    /// The run stopped at a non-terminal, resumable state.
    NotYetFinalized,
}

impl DriverRunOutcome {
    /// Returns the machine report code for this outcome.
    #[must_use]
    pub fn report_code(&self) -> MachineReportCode {
        match self {
            Self::FinalizedAccept(_) => MachineReportCode::FinalizedAccept,
            Self::FinalizedFeeOnly(_) => MachineReportCode::FinalizedFeeOnly,
            Self::FinalizedReject(_) => MachineReportCode::FinalizedReject,
            Self::VerificationFailed(_) => MachineReportCode::VerificationFailed,
            Self::Disagreement(_) => MachineReportCode::Disagreement,
            Self::RejectedByApprover(_) => MachineReportCode::RejectedByApprover,
            Self::PollExhaustedUnknown(_) => MachineReportCode::PollExhaustedUnknown,
            Self::NotYetFinalized => MachineReportCode::NotYetFinalized,
        }
    }

    /// Returns the evidence record, if this is a terminal outcome.
    #[must_use]
    pub fn evidence(&self) -> Option<&AnchorEvidenceRecordV1> {
        match self {
            Self::FinalizedAccept(evidence)
            | Self::FinalizedFeeOnly(evidence)
            | Self::FinalizedReject(evidence)
            | Self::VerificationFailed(evidence)
            | Self::Disagreement(evidence)
            | Self::RejectedByApprover(evidence)
            | Self::PollExhaustedUnknown(evidence) => Some(evidence),
            Self::NotYetFinalized => None,
        }
    }
}

/// The operator's explicit approval gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorDecision {
    /// Approve the prepared request.
    Approve,
    /// Reject the prepared request.
    Reject,
    /// Make no decision; the run stops at `Prepared`.
    NoDecision,
}

/// In-memory proof that one runtime archive verification pass matched the
/// canonical live config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRuntimeArchiveFactsV1 {
    manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
    accepted_ballot_count: u64,
    transport_accepted_count: u64,
    reduced_anonymity: bool,
}

impl VerifiedRuntimeArchiveFactsV1 {
    /// Verifies `archive_dir` and checks every live approval fact against
    /// `config`.
    ///
    /// The returned facts are the archive locators used by the live driver when
    /// building the anchor proof inputs.
    pub fn from_archive_and_config(
        archive_dir: &Path,
        config: &AnchorAppConfig,
    ) -> Result<Self, DriverError> {
        let verification = verify_archive_directory_v1(archive_dir)
            .map_err(|_| DriverError::RuntimeArchiveVerificationFailed)?;
        Self::from_verification_and_config(&verification, config)
    }

    fn from_verification_and_config(
        verification: &ArchiveDirectoryVerificationV1,
        config: &AnchorAppConfig,
    ) -> Result<Self, DriverError> {
        if !verification.verified
            || !verification.finalized
            || !verification.archive_hash_consistent
            || !verification.transport_binding_verified
        {
            return Err(DriverError::RuntimeArchiveVerificationFailed);
        }
        if config.input_provenance() != AnchorConfigInputProvenanceV1::ArchiveVerified {
            return Err(DriverError::OfflineTestRawHashesNotLiveApproved);
        }
        let facts = config
            .live_approval_facts()
            .ok_or(DriverError::LiveApprovalFactsRequired)?;
        if !facts.finalized_archive() {
            return Err(DriverError::RuntimeArchiveBindingMismatch);
        }

        let manifest_hash = ManifestHash::new(parse_hash(
            verification
                .election_manifest_hash_hex
                .as_deref()
                .ok_or(DriverError::RuntimeArchiveVerificationFailed)?,
        )?);
        let archive_hash = ArchiveHashV1::new(parse_hash(
            verification
                .archive_hash_hex
                .as_deref()
                .ok_or(DriverError::RuntimeArchiveVerificationFailed)?,
        )?);
        if manifest_hash != config.archive_manifest_hash() || archive_hash != config.archive_hash()
        {
            return Err(DriverError::RuntimeArchiveBindingMismatch);
        }

        let accepted_ballot_count = u64::try_from(verification.accepted_count)
            .map_err(|_| DriverError::RuntimeArchiveBindingMismatch)?;
        let transport_accepted_count = verification
            .transport_accepted_count
            .ok_or(DriverError::RuntimeArchiveBindingMismatch)?;
        let reduced_anonymity = verification
            .transport_reduced_anonymity
            .ok_or(DriverError::RuntimeArchiveBindingMismatch)?;
        if accepted_ballot_count != facts.accepted_ballot_count()
            || accepted_ballot_count < facts.required_accepted_ballot_floor()
            || transport_accepted_count != accepted_ballot_count
            || reduced_anonymity != facts.reduced_anonymity()
        {
            return Err(DriverError::RuntimeArchiveBindingMismatch);
        }

        Ok(Self {
            manifest_hash,
            archive_hash,
            accepted_ballot_count,
            transport_accepted_count,
            reduced_anonymity,
        })
    }

    /// Test-only constructor for scripted driver tests that do not create a
    /// real finalized archive on disk.
    #[doc(hidden)]
    pub fn matching_config_for_test(config: &AnchorAppConfig) -> Result<Self, DriverError> {
        let facts = config
            .live_approval_facts()
            .ok_or(DriverError::LiveApprovalFactsRequired)?;
        Ok(Self {
            manifest_hash: config.archive_manifest_hash(),
            archive_hash: config.archive_hash(),
            accepted_ballot_count: facts.accepted_ballot_count(),
            transport_accepted_count: facts.accepted_ballot_count(),
            reduced_anonymity: facts.reduced_anonymity(),
        })
    }

    fn ensure_matches_config(&self, config: &AnchorAppConfig) -> Result<(), DriverError> {
        let facts = config
            .live_approval_facts()
            .ok_or(DriverError::LiveApprovalFactsRequired)?;
        if self.manifest_hash != config.archive_manifest_hash()
            || self.archive_hash != config.archive_hash()
            || self.accepted_ballot_count != facts.accepted_ballot_count()
            || self.accepted_ballot_count < facts.required_accepted_ballot_floor()
            || self.transport_accepted_count != self.accepted_ballot_count
            || self.reduced_anonymity != facts.reduced_anonymity()
            || !facts.finalized_archive()
        {
            return Err(DriverError::RuntimeArchiveBindingMismatch);
        }
        Ok(())
    }
}

/// The application driver.
///
/// Generic over the wire transport so the same code path serves both the
/// offline scripted tests (`WalletdAnchorNetworkAdapter<ScriptedWalletdTransport>`,
/// `IndexerReceiptNetworkAdapter<ScriptedIndexerTransport>`) and the online
/// real transports (`WalletdAnchorNetworkAdapter<RealWalletdTransport<E>>`,
/// `IndexerReceiptNetworkAdapter<RealIndexerTransport<E>>`).
pub struct AnchorAppDriver<W, I>
where
    W: WalletdWireTransport,
    I: IndexerReceiptWireTransport,
{
    orchestrator: AnchorLifecycleOrchestrator,
    walletd_adapter: WalletdAnchorNetworkAdapter<W>,
    indexer_adapter: IndexerReceiptNetworkAdapter<I>,
    config: AnchorAppConfig,
    backoff: WallClockBackoff,
    terminal_index_root: Option<PathBuf>,
    terminal_index_phase_override: Option<UnifiedAnchorLifecyclePhase>,
    runtime_archive: Option<VerifiedRuntimeArchiveFactsV1>,
}

impl<W, I> AnchorAppDriver<W, I>
where
    W: WalletdWireTransport,
    I: IndexerReceiptWireTransport,
{
    /// Constructs a fresh driver with an empty orchestrator (no snapshot
    /// loaded).
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidBackoff`] if the configured backoff
    /// schedule is invalid.
    pub fn new(
        config: AnchorAppConfig,
        walletd_adapter: WalletdAnchorNetworkAdapter<W>,
        indexer_adapter: IndexerReceiptNetworkAdapter<I>,
    ) -> Result<Self, DriverError> {
        let backoff = WallClockBackoff::new(
            std::time::Duration::from_secs(config.backoff_base_secs()),
            std::time::Duration::from_secs(config.backoff_cap_secs()),
        )
        .map_err(|_| DriverError::InvalidBackoff)?;
        let max_attempts = config.network_adapter().receipt_query_max_attempts();
        let orchestrator = AnchorLifecycleOrchestrator::new(PollingPolicy::new(max_attempts));
        Ok(Self {
            orchestrator,
            walletd_adapter,
            indexer_adapter,
            config,
            backoff,
            terminal_index_root: None,
            terminal_index_phase_override: None,
            runtime_archive: None,
        })
    }

    /// Constructs a fresh live driver with the production terminal index
    /// enabled.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if driver construction or terminal-index root
    /// resolution fails.
    pub fn new_live(
        config: AnchorAppConfig,
        walletd_adapter: WalletdAnchorNetworkAdapter<W>,
        indexer_adapter: IndexerReceiptNetworkAdapter<I>,
        archive_dir: &Path,
    ) -> Result<Self, DriverError> {
        let runtime_archive =
            VerifiedRuntimeArchiveFactsV1::from_archive_and_config(archive_dir, &config)?;
        let mut driver = Self::new(config, walletd_adapter, indexer_adapter)?;
        driver.terminal_index_root = Some(default_terminal_index_root()?);
        driver.runtime_archive = Some(runtime_archive);
        Ok(driver)
    }

    /// Restores a driver from a previously-persisted snapshot.
    ///
    /// If the snapshot file is absent, this is equivalent to [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] on snapshot read failure or backoff
    /// invalidity.
    pub fn restore(
        config: AnchorAppConfig,
        walletd_adapter: WalletdAnchorNetworkAdapter<W>,
        indexer_adapter: IndexerReceiptNetworkAdapter<I>,
    ) -> Result<Self, DriverError> {
        let backoff = WallClockBackoff::new(
            std::time::Duration::from_secs(config.backoff_base_secs()),
            std::time::Duration::from_secs(config.backoff_cap_secs()),
        )
        .map_err(|_| DriverError::InvalidBackoff)?;
        let snapshot = match snapshot_store::read_snapshot(config.snapshot_path()) {
            Ok(snapshot) => Some(snapshot),
            Err(SnapshotFileError::FileNotFound) => None,
            Err(error) => return Err(DriverError::Snapshot(error)),
        };

        // Restore-time binding validation: the current configuration must not
        // reinterpret a lifecycle created for another archive, election,
        // network, account, fee, payload, or transaction. If a snapshot
        // exists, its immutable anchor binding is compared with the
        // config-derived binding before any transport construction or receipt
        // lookup.
        if let Some(ref snapshot) = snapshot {
            Self::validate_snapshot_binding(&config, snapshot)?;
        }

        let max_attempts = config.network_adapter().receipt_query_max_attempts();
        let orchestrator = match snapshot {
            Some(snapshot) => AnchorLifecycleOrchestrator::from_snapshot(snapshot)?,
            None => AnchorLifecycleOrchestrator::new(PollingPolicy::new(max_attempts)),
        };
        Ok(Self {
            orchestrator,
            walletd_adapter,
            indexer_adapter,
            config,
            backoff,
            terminal_index_root: None,
            terminal_index_phase_override: None,
            runtime_archive: None,
        })
    }

    /// Restores a live driver with the production terminal index enabled.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] on snapshot read/reconstruction failure or
    /// terminal-index root resolution failure.
    pub fn restore_live(
        config: AnchorAppConfig,
        walletd_adapter: WalletdAnchorNetworkAdapter<W>,
        indexer_adapter: IndexerReceiptNetworkAdapter<I>,
        archive_dir: &Path,
    ) -> Result<Self, DriverError> {
        let runtime_archive =
            VerifiedRuntimeArchiveFactsV1::from_archive_and_config(archive_dir, &config)?;
        let mut driver = Self::restore(config, walletd_adapter, indexer_adapter)?;
        driver.terminal_index_root = Some(default_terminal_index_root()?);
        driver.runtime_archive = Some(runtime_archive);
        Ok(driver)
    }

    /// Enables a caller-provided terminal-index root.
    ///
    /// This is used by focused offline tests to avoid shared machine state. The
    /// standalone CLI uses [`Self::restore_live`] and the production default
    /// root.
    #[doc(hidden)]
    #[must_use]
    pub fn with_terminal_index_root_for_test(mut self, root: PathBuf) -> Self {
        self.terminal_index_root = Some(root);
        self
    }

    /// Supplies test-only runtime archive facts for scripted tests that do not
    /// materialize a finalized archive directory.
    #[doc(hidden)]
    #[must_use]
    pub fn with_runtime_archive_for_test(mut self, facts: VerifiedRuntimeArchiveFactsV1) -> Self {
        self.runtime_archive = Some(facts);
        self
    }

    /// Returns the current in-memory recovery snapshot.
    #[must_use]
    pub fn snapshot(&self) -> AnchorLifecycleRecoverySnapshot {
        self.orchestrator.snapshot()
    }

    /// Returns the current lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        if let Some(phase) = self.terminal_index_phase_override {
            return phase;
        }
        self.orchestrator.phase()
    }

    /// Returns a reference to the walletd adapter.
    #[must_use]
    pub fn walletd_adapter(&self) -> &WalletdAnchorNetworkAdapter<W> {
        &self.walletd_adapter
    }

    /// Returns a reference to the indexer adapter.
    #[must_use]
    pub fn indexer_adapter(&self) -> &IndexerReceiptNetworkAdapter<I> {
        &self.indexer_adapter
    }

    /// Returns the bound transaction id, if any.
    #[must_use]
    pub fn transaction_id(
        &self,
    ) -> Option<&tari_cc_private_ballot_anchor_transport::AnchorTransactionId> {
        self.orchestrator.submitted().map(|s| s.transaction_id())
    }

    /// Returns the snapshot file path the driver persists to.
    #[must_use]
    pub fn snapshot_path(&self) -> &std::path::Path {
        self.config.snapshot_path()
    }

    /// Returns the evidence file path the driver writes to.
    #[must_use]
    pub fn evidence_path(&self) -> &std::path::Path {
        self.config.evidence_path()
    }

    /// Drives the lifecycle forward from the current phase according to
    /// `decision`.
    ///
    /// See the module docs for the full run-loop contract. The driver never
    /// auto-approves, never blind-resubmits, and never claims finality before
    /// a verified `FinalizedAccept`.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] on any step failure.
    pub fn run(&mut self, decision: OperatorDecision) -> Result<DriverRunOutcome, DriverError> {
        if self.config.input_provenance() != AnchorConfigInputProvenanceV1::ArchiveVerified {
            return Err(DriverError::OfflineTestRawHashesNotLiveApproved);
        }
        self.require_runtime_archive_for_live_config()?;
        if self.terminal_index_root.is_some() && self.config.live_approval_facts().is_none() {
            return Err(DriverError::LiveApprovalFactsRequired);
        }
        if let Some(evidence) = self.terminal_index_preflight()? {
            self.terminal_index_phase_override = Some(UnifiedAnchorLifecyclePhase::FinalizedAccept);
            return Ok(DriverRunOutcome::FinalizedAccept(evidence));
        }

        loop {
            match self.orchestrator.phase() {
                UnifiedAnchorLifecyclePhase::NotPrepared => {
                    self.step_prepare()?;
                    self.persist_snapshot()?;
                    continue;
                }
                UnifiedAnchorLifecyclePhase::Prepared => match decision {
                    OperatorDecision::Reject => {
                        self.step_reject()?;
                        self.persist_snapshot()?;
                        let evidence =
                            self.terminal_evidence(TerminalEvidenceInputs::RejectedByApprover)?;
                        self.write_terminal_evidence(&evidence)?;
                        return Ok(DriverRunOutcome::RejectedByApprover(evidence));
                    }
                    OperatorDecision::Approve => {
                        self.step_approve()?;
                        self.persist_snapshot()?;
                        continue;
                    }
                    OperatorDecision::NoDecision => {
                        self.persist_snapshot()?;
                        return Ok(DriverRunOutcome::NotYetFinalized);
                    }
                },
                UnifiedAnchorLifecyclePhase::Approved => {
                    self.persist_submit_write_ahead_snapshot()?;
                    self.step_submit()?;
                    self.persist_snapshot()?;
                    continue;
                }
                UnifiedAnchorLifecyclePhase::Unknown => {
                    self.step_recover()?;
                    self.persist_snapshot()?;
                    continue;
                }
                UnifiedAnchorLifecyclePhase::Submitted
                | UnifiedAnchorLifecyclePhase::PollingInProgress => {
                    let outcome = self.step_poll_once_and_maybe_sleep()?;
                    self.persist_snapshot()?;
                    if let Some(outcome) = outcome {
                        if let Some(evidence) = outcome.evidence() {
                            self.write_terminal_evidence(evidence)?;
                        }
                        return Ok(outcome);
                    }
                    continue;
                }
                UnifiedAnchorLifecyclePhase::FinalizedAccept => {
                    let evidence = self.accept_evidence()?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::FinalizedAccept(evidence));
                }
                UnifiedAnchorLifecyclePhase::FinalizedFeeOnly => {
                    let evidence = self.terminal_evidence(TerminalEvidenceInputs::FeeOnly {
                        transaction_id: self
                            .transaction_id()
                            .cloned()
                            .ok_or(DriverError::Lifecycle(LifecycleError::NotSubmitted))?,
                        ledger_position: None,
                    })?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::FinalizedFeeOnly(evidence));
                }
                UnifiedAnchorLifecyclePhase::FinalizedReject => {
                    let evidence = self.terminal_evidence(TerminalEvidenceInputs::Reject {
                        transaction_id: self
                            .transaction_id()
                            .cloned()
                            .ok_or(DriverError::Lifecycle(LifecycleError::NotSubmitted))?,
                        ledger_position: None,
                    })?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::FinalizedReject(evidence));
                }
                UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed => {
                    let evidence =
                        self.terminal_evidence(TerminalEvidenceInputs::VerificationFailed {
                            transaction_id: self.transaction_id().cloned(),
                            ledger_position: None,
                        })?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::VerificationFailed(evidence));
                }
                UnifiedAnchorLifecyclePhase::FinalizedDisagreement => {
                    let evidence =
                        self.terminal_evidence(TerminalEvidenceInputs::Disagreement {
                            transaction_id: self
                                .transaction_id()
                                .cloned()
                                .ok_or(DriverError::Lifecycle(LifecycleError::NotSubmitted))?,
                            ledger_position: None,
                        })?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::Disagreement(evidence));
                }
                UnifiedAnchorLifecyclePhase::RejectedByApprover => {
                    let evidence =
                        self.terminal_evidence(TerminalEvidenceInputs::RejectedByApprover)?;
                    self.write_terminal_evidence(&evidence)?;
                    return Ok(DriverRunOutcome::RejectedByApprover(evidence));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step wrappers (delegate verbatim to the orchestrator)
    // -----------------------------------------------------------------------

    fn build_archive_proof_inputs(&self) -> Result<ArchiveProofInputs, DriverError> {
        let network = self.config.anchor_record_network().clone();
        let (manifest_hash, archive_hash) = match &self.runtime_archive {
            Some(runtime_archive) => (runtime_archive.manifest_hash, runtime_archive.archive_hash),
            None => (
                self.config.archive_manifest_hash(),
                self.config.archive_hash(),
            ),
        };
        // Re-derive the anchor-record digest deterministically from the
        // configured locator triple. This never touches the network and is
        // the same digest the prepare step commits to.
        let record = OotleAnchorRecordV1::new(network.clone(), manifest_hash, archive_hash);
        let anchor_digest = record
            .canonical_hash(&Blake3HashProviderV1)
            .map_err(|_| DriverError::Evidence(EvidenceError::InvalidData))?;
        Ok(ArchiveProofInputs::new(
            network,
            manifest_hash,
            archive_hash,
            anchor_digest,
        ))
    }

    /// Validates that the current configuration's immutable anchor binding
    /// matches the binding recorded in the persisted snapshot.
    ///
    /// This prevents a config change from reinterpreting a lifecycle created
    /// for another archive, election, network, account, fee, payload, or
    /// transaction. It is a pure comparison of already-frozen values and never
    /// contacts a transport or mutates an artifact.
    fn validate_snapshot_binding(
        config: &AnchorAppConfig,
        snapshot: &AnchorLifecycleRecoverySnapshot,
    ) -> Result<(), DriverError> {
        // No walletd snapshot means nothing to compare (NotPrepared).
        let Some(walletd) = snapshot.walletd_snapshots().first() else {
            return Ok(());
        };

        let binding = walletd.binding();

        // Network.
        if config.anchor_record_network() != binding.network() {
            return Err(DriverError::ConfigSnapshotBindingMismatch);
        }

        // Account reference.
        if config.account_reference() != binding.account() {
            return Err(DriverError::ConfigSnapshotBindingMismatch);
        }

        // Anchor-record digest: re-derive from the config's locator triple and
        // compare with the snapshot's recorded digest.
        let record = OotleAnchorRecordV1::new(
            config.anchor_record_network().clone(),
            config.archive_manifest_hash(),
            config.archive_hash(),
        );
        let config_digest = record
            .canonical_hash(&Blake3HashProviderV1)
            .map_err(|_| DriverError::Evidence(EvidenceError::InvalidData))?;
        if config_digest != binding.anchor_digest() {
            return Err(DriverError::ConfigSnapshotBindingMismatch);
        }

        // Canonical anchor-log payload: derived from the digest, so if the
        // digest matches the payload must match too. Check explicitly for
        // defense-in-depth.
        let config_payload = AnchorLogPayloadV1::from_digest(config_digest);
        if &config_payload != binding.payload() {
            return Err(DriverError::ConfigSnapshotBindingMismatch);
        }

        // Maximum fee.
        if config.network_adapter().max_fee() != binding.max_fee() {
            return Err(DriverError::ConfigSnapshotBindingMismatch);
        }

        Ok(())
    }

    fn require_runtime_archive_for_live_config(&self) -> Result<(), DriverError> {
        let runtime_archive = self
            .runtime_archive
            .as_ref()
            .ok_or(DriverError::RuntimeArchiveRequired)?;
        runtime_archive.ensure_matches_config(&self.config)
    }

    fn step_prepare(&mut self) -> Result<(), DriverError> {
        let archive = self.build_archive_proof_inputs()?;
        let payload = AnchorLogPayloadV1::from_digest(archive.anchor_digest());
        let binding = AnchorBindingV1::new(
            self.config.anchor_record_network().clone(),
            self.config.account_reference().clone(),
            payload,
        );
        let max_fee = self.config.network_adapter().max_fee();
        let preparation = AnchorPreparationRequest::new(binding, max_fee, None);
        let build_request = tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1::from_preparation_request(preparation);
        self.orchestrator.prepare_fee_bearing(
            &mut self.walletd_adapter,
            &build_request,
            self.config.network_adapter().fee_component(),
            self.config.network_adapter().seal_signer(),
            self.config.ttl_secs(),
        )?;
        Ok(())
    }

    fn step_approve(&mut self) -> Result<(), DriverError> {
        self.orchestrator.approve(&mut self.walletd_adapter)?;
        Ok(())
    }

    fn step_reject(&mut self) -> Result<(), DriverError> {
        self.orchestrator.reject(&mut self.walletd_adapter)?;
        Ok(())
    }

    fn step_submit(&mut self) -> Result<(), DriverError> {
        self.orchestrator.submit(&mut self.walletd_adapter)?;
        Ok(())
    }

    fn step_recover(&mut self) -> Result<(), DriverError> {
        self.orchestrator.recover(&mut self.walletd_adapter)?;
        Ok(())
    }

    /// Performs exactly one poll. If the phase becomes terminal, builds and
    /// returns the corresponding evidence outcome. If polling exhausts the
    /// policy, builds and returns `PollExhaustedUnknown`. Otherwise computes
    /// the next delay and sleeps.
    ///
    /// Never sleeps after a terminal or exhaustion.
    fn step_poll_once_and_maybe_sleep(&mut self) -> Result<Option<DriverRunOutcome>, DriverError> {
        let report = self
            .orchestrator
            .advance_one_poll(&mut self.indexer_adapter)?;
        let phase = report.phase();

        if phase == UnifiedAnchorLifecyclePhase::FinalizedAccept {
            let evidence = self.accept_evidence()?;
            return Ok(Some(DriverRunOutcome::FinalizedAccept(evidence)));
        }
        if phase == UnifiedAnchorLifecyclePhase::FinalizedFeeOnly {
            let evidence = self.terminal_evidence(TerminalEvidenceInputs::FeeOnly {
                transaction_id: self
                    .transaction_id()
                    .cloned()
                    .ok_or(DriverError::Lifecycle(LifecycleError::NotSubmitted))?,
                ledger_position: None,
            })?;
            return Ok(Some(DriverRunOutcome::FinalizedFeeOnly(evidence)));
        }
        if phase == UnifiedAnchorLifecyclePhase::FinalizedReject {
            let evidence = self.terminal_evidence(TerminalEvidenceInputs::Reject {
                transaction_id: self
                    .transaction_id()
                    .cloned()
                    .ok_or(DriverError::Lifecycle(LifecycleError::NotSubmitted))?,
                ledger_position: None,
            })?;
            return Ok(Some(DriverRunOutcome::FinalizedReject(evidence)));
        }
        if phase == UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed {
            let evidence = self.terminal_evidence(TerminalEvidenceInputs::VerificationFailed {
                transaction_id: self.transaction_id().cloned(),
                ledger_position: None,
            })?;
            return Ok(Some(DriverRunOutcome::VerificationFailed(evidence)));
        }

        // Poll exhaustion surfaces as a resumable `Unknown` with the
        // `POLL_EXHAUSTED` diagnostic. The run loop treats this as a
        // non-success terminal incident.
        if report.diagnostic() == Some("POLL_EXHAUSTED")
            && phase == UnifiedAnchorLifecyclePhase::Unknown
        {
            let evidence =
                self.terminal_evidence(TerminalEvidenceInputs::PollExhaustedUnknown {
                    transaction_id: self.transaction_id().cloned(),
                })?;
            return Ok(Some(DriverRunOutcome::PollExhaustedUnknown(evidence)));
        }

        // Non-terminal: sleep before the next attempt, but never sleep before
        // the first attempt, after a terminal state, or after policy
        // exhaustion. The next attempt index is 1-based.
        let next_attempt = report.attempts_consumed();
        if next_attempt > 0 {
            let delay = self.backoff.delay_for(next_attempt);
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Evidence + snapshot persistence
    // -----------------------------------------------------------------------

    fn accept_evidence(&mut self) -> Result<AnchorEvidenceRecordV1, DriverError> {
        let archive = self.build_archive_proof_inputs()?;
        let snapshot_digest = snapshot_digest_of(&self.orchestrator)?;
        // Re-query the indexer to obtain the `VerifiedIndexerAnchorV1`. The
        // orchestrator's `advance_one_poll` drops the report it built (see the
        // Slice 4A8 source); the receipt coordinator exposes a public `query`
        // that re-runs the pure fetch+verify over the frozen commitments. It
        // mutates no artifact and is safe to call after `FinalizedAccept`.
        let verified = self.requery_verified_indexer_anchor()?;

        // Accepted-evidence binding validation: the config-derived archive
        // locators must match the verified indexer receipt. This prevents a
        // config change from misbinding the ACCEPTED evidence to a different
        // archive, network, or transaction than the one the receipt actually
        // verified. If any comparison fails, no ACCEPTED evidence is created
        // and the existing snapshot and artifacts are left unchanged.
        let verified_evidence = verified.evidence();
        if archive.anchor_digest() != verified_evidence.anchor_digest() {
            return Err(DriverError::EvidenceBindingMismatch);
        }
        if archive.network() != verified_evidence.network() {
            return Err(DriverError::EvidenceBindingMismatch);
        }
        // The verified transaction id must match the submitted lifecycle
        // transaction id.
        let Some(submitted) = self.orchestrator.submitted() else {
            return Err(DriverError::Lifecycle(LifecycleError::NotSubmitted));
        };
        if verified_evidence.transaction_id() != submitted.transaction_id() {
            return Err(DriverError::EvidenceBindingMismatch);
        }

        let live_approval_facts = self.live_evidence_approval_facts()?;
        let evidence = if let Some(facts) = live_approval_facts {
            AnchorEvidenceRecordV1::from_verified_indexer_accept_with_live_approval_facts(
                &archive,
                &verified,
                &snapshot_digest,
                UnifiedAnchorLifecyclePhase::FinalizedAccept,
                facts,
            )?
        } else {
            AnchorEvidenceRecordV1::from_verified_indexer_accept(
                &archive,
                &verified,
                &snapshot_digest,
                UnifiedAnchorLifecyclePhase::FinalizedAccept,
            )?
        };
        Ok(evidence)
    }

    fn terminal_evidence(
        &self,
        inputs: TerminalEvidenceInputs,
    ) -> Result<AnchorEvidenceRecordV1, DriverError> {
        let archive = self.build_archive_proof_inputs()?;
        let snapshot_digest = snapshot_digest_of(&self.orchestrator)?;
        let live_approval_facts = self.live_evidence_approval_facts()?;
        let evidence = if let Some(facts) = live_approval_facts {
            AnchorEvidenceRecordV1::from_terminal_outcome_with_live_approval_facts(
                &archive,
                inputs,
                &snapshot_digest,
                facts,
            )?
        } else {
            AnchorEvidenceRecordV1::from_terminal_outcome(&archive, inputs, &snapshot_digest)?
        };
        Ok(evidence)
    }

    fn live_evidence_approval_facts(
        &self,
    ) -> Result<Option<LiveEvidenceApprovalFactsV1>, DriverError> {
        let Some(facts) = self.config.live_approval_facts() else {
            return Ok(None);
        };
        let snapshot = self.orchestrator.snapshot();
        let Some(walletd_snapshot) = snapshot.walletd_snapshots().first() else {
            return Err(DriverError::LiveTransactionFingerprintRequired);
        };
        let transaction_fingerprint = *walletd_snapshot.binding().fingerprint().as_bytes();
        LiveEvidenceApprovalFactsV1::from_config(
            self.config.input_provenance(),
            facts,
            self.config
                .network_adapter()
                .fee_component()
                .display_string(),
            transaction_fingerprint,
        )
        .map(Some)
        .map_err(DriverError::Evidence)
    }

    fn requery_verified_indexer_anchor(&mut self) -> Result<VerifiedIndexerAnchorV1, DriverError> {
        let Some(submitted) = self.orchestrator.submitted().cloned() else {
            return Err(DriverError::Lifecycle(LifecycleError::NotSubmitted));
        };
        let query = AnchorReceiptQueryV1::from_submitted(&submitted);
        // Build a fresh receipt coordinator. The orchestrator only exposes a
        // shared `&` to its receipt coordinator (its `query` needs `&mut`),
        // and the orchestrator's `advance_one_poll` already drops the report
        // it built. A fresh coordinator re-runs the pure fetch+verify over the
        // frozen commitments (the same deterministic transform the orchestrator
        // ran), mutates no orchestrator state, and yields the
        // `VerifiedIndexerAnchorV1` needed for the ACCEPTED evidence record.
        let mut fresh = AnchorReceiptCoordinator::new();
        let report = fresh.query(&mut self.indexer_adapter, &query, &submitted)?;
        report
            .verified()
            .cloned()
            .ok_or(DriverError::Evidence(EvidenceError::InvalidData))
    }

    fn write_evidence(&self, evidence: &AnchorEvidenceRecordV1) -> Result<(), DriverError> {
        write_evidence_atomic(self.config.evidence_path(), evidence)
            .map_err(map_evidence_file_error)
    }

    fn write_terminal_evidence(
        &self,
        evidence: &AnchorEvidenceRecordV1,
    ) -> Result<(), DriverError> {
        self.write_evidence(evidence)?;
        if let Some(root) = &self.terminal_index_root {
            let record =
                TerminalAnchorIndexRecordV1::from_evidence(evidence, self.config.evidence_path())?;
            write_terminal_index(root, &record)?;
        }
        Ok(())
    }

    fn terminal_index_preflight(&self) -> Result<Option<AnchorEvidenceRecordV1>, DriverError> {
        let Some(root) = &self.terminal_index_root else {
            return Ok(None);
        };
        let archive = self.build_archive_proof_inputs()?;
        let Some(record) = read_terminal_index(root, archive.manifest_hash())? else {
            return Ok(None);
        };
        if !record.is_accepted_for(
            archive.network(),
            archive.manifest_hash(),
            archive.archive_hash(),
            archive.anchor_digest(),
        ) {
            return Err(DriverError::TerminalIndex(TerminalIndexError::Conflict));
        }
        let evidence = record.read_bound_evidence()?;
        Ok(Some(evidence))
    }

    fn persist_snapshot(&self) -> Result<(), DriverError> {
        let snapshot = self.orchestrator.snapshot();
        snapshot_store::write_snapshot_atomic(self.config.snapshot_path(), &snapshot)?;
        Ok(())
    }

    fn persist_submit_write_ahead_snapshot(&self) -> Result<(), DriverError> {
        let current = self.orchestrator.snapshot();
        let Some(walletd) = current.walletd_snapshots().first() else {
            return Err(DriverError::Lifecycle(LifecycleError::NotApproved));
        };
        let intent_walletd = WalletdAnchorSnapshotV1::new(
            walletd.project_request_id().clone(),
            walletd.walletd_request_id(),
            walletd.binding().clone(),
            walletd.decision(),
            WalletdSubmissionStateV1::TimedOutUnknown,
            walletd.transaction_id().cloned(),
            walletd.last_effective_status(),
            walletd.retry_count(),
            walletd.sequence(),
            walletd.last_diagnostic(),
        );
        let intent = AnchorLifecycleRecoverySnapshot::new(
            vec![intent_walletd],
            Vec::new(),
            None,
            current.policy(),
            UnifiedAnchorLifecyclePhase::Unknown,
            current.diagnostic(),
        );
        snapshot_store::write_snapshot_atomic(self.config.snapshot_path(), &intent)?;
        Ok(())
    }
}

fn parse_hash(hex: &str) -> Result<[u8; 32], DriverError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(DriverError::RuntimeArchiveVerificationFailed);
    }
    let mut out = [0_u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(bytes[i * 2])? << 4) | hex_nibble(bytes[i * 2 + 1])?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, DriverError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DriverError::RuntimeArchiveVerificationFailed),
    }
}

fn snapshot_digest_of(orchestrator: &AnchorLifecycleOrchestrator) -> Result<[u8; 32], DriverError> {
    let snapshot = orchestrator.snapshot();
    Ok(snapshot_store::snapshot_digest(&snapshot)?)
}

fn map_evidence_file_error(error: EvidenceFileError) -> DriverError {
    match error {
        EvidenceFileError::IoFailure | EvidenceFileError::AtomicRenameFailure => {
            DriverError::Evidence(EvidenceError::InvalidData)
        }
        EvidenceFileError::ProtocolLimitExceeded => {
            DriverError::Evidence(EvidenceError::ProtocolLimitExceeded)
        }
    }
}
