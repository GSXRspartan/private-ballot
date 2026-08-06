//! Orchestrator driver (Sections A, D, F, G).
//!
//! [`AnchorLifecycleOrchestrator`] owns one [`WalletdAnchorCoordinator`] and one
//! [`AnchorReceiptCoordinator`], the bounded [`PollingPolicy`], and the unified
//! per-anchor lifecycle record and its state. It exposes explicit,
//! caller-advanced steps only — no loops, no sleeping, no async — and calls each
//! coordinator method exactly as designed, forwarding the exact request DTOs.
//!
//! It never re-implements binding checks, receipt conversion, verification, or
//! agreement; never constructs, mutates, signs, or resubmits a transaction; and
//! never holds key custody. It is deterministic given the same inputs and the
//! same fake scripts.
//!
//! [`WalletdAnchorCoordinator`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorCoordinator
//! [`AnchorReceiptCoordinator`]: tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptCoordinator

use tari_cc_private_ballot_anchor_transport::{AnchorFinalStatusV1, AnchorReceiptV1};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptAgreementError, AnchorReceiptCoordinator, AnchorReceiptQueryReportV1,
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, AnchorReceiptQueryV1,
    ReceiptRetrievalError,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    ApprovedWalletdAnchorRequestV1, OotleAnchorTransactionBuildRequestV1,
    PreparedWalletdAnchorRequestV1, SubmittedWalletdAnchorRequestV1, WalletdAnchorAdapterError,
    WalletdAnchorCoordinator, WalletdAnchorSnapshotV1, WalletdDecisionRequestV1,
    WalletdFeeComponentRef, WalletdRecoveryStateV1, WalletdRequestDecisionV1, WalletdSealSignerRef,
    WalletdSubmissionStateV1, WalletdSubmitRequestV1,
};

use crate::policy::PollingPolicy;
use crate::report::{
    LifecycleReceiptQueryOutcome, LifecycleRecoveryOutcome, LifecycleStepOutcome,
    LifecycleStepReport,
};
use crate::snapshot::{AnchorLifecycleRecoverySnapshot, LifecycleReconstructionError};
use crate::state::UnifiedAnchorLifecyclePhase;

/// The unified error type returned by orchestrator steps.
///
/// It wraps the two coordinator error types and adds orchestrator-level
/// preconditions. It never carries a wallet secret, ballot, or pinned Ootle
/// type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// The walletd coordinator returned a bounded error.
    Walletd(WalletdAnchorAdapterError),
    /// The receipt coordinator returned a bounded hard error (binding mismatch
    /// or malformed identifier). Unfavourable receipt outcomes are folded into
    /// the report, not returned as errors.
    Receipt(ReceiptRetrievalError),
    /// The walletd/indexer agreement check disagreed.
    Agreement(AnchorReceiptAgreementError),
    /// A step was called before the lifecycle reached the required phase (for
    /// example, `approve` before `prepare`).
    NotPrepared,
    /// `submit` was called before `approve`.
    NotApproved,
    /// `advance_one_poll` or `check_agreement` was called before `submit`.
    NotSubmitted,
    /// `recover` was called when the lifecycle was not in a submit-unknown
    /// state.
    NotRecoverable,
}

impl LifecycleError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Walletd(error) => error.as_str(),
            Self::Receipt(error) => error.as_str(),
            Self::Agreement(error) => error.as_str(),
            Self::NotPrepared => "LIFECYCLE_NOT_PREPARED",
            Self::NotApproved => "LIFECYCLE_NOT_APPROVED",
            Self::NotSubmitted => "LIFECYCLE_NOT_SUBMITTED",
            Self::NotRecoverable => "LIFECYCLE_NOT_RECOVERABLE",
        }
    }
}

impl core::fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for LifecycleError {}

impl From<WalletdAnchorAdapterError> for LifecycleError {
    fn from(error: WalletdAnchorAdapterError) -> Self {
        Self::Walletd(error)
    }
}

impl From<ReceiptRetrievalError> for LifecycleError {
    fn from(error: ReceiptRetrievalError) -> Self {
        Self::Receipt(error)
    }
}

impl From<AnchorReceiptAgreementError> for LifecycleError {
    fn from(error: AnchorReceiptAgreementError) -> Self {
        Self::Agreement(error)
    }
}

/// The cached last receipt-query report, retained for the agreement check.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedReceiptReport {
    transaction_id: tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
    network: tari_cc_private_ballot_anchor::OotleNetworkIdV1,
    indexer_receipt: Option<AnchorReceiptV1>,
}

/// The offline anchor lifecycle orchestrator.
///
/// It owns the two coordinators, the polling policy, and the cached handles
/// needed to drive the next step. It performs no network call, no timing, and
/// no transaction construction or mutation.
#[derive(Debug)]
pub struct AnchorLifecycleOrchestrator {
    walletd: WalletdAnchorCoordinator,
    receipt: AnchorReceiptCoordinator,
    policy: PollingPolicy,
    phase: UnifiedAnchorLifecyclePhase,
    // Cached live handles (populated by the steps that produce them). On
    // restart these may be None; the orchestrator rebuilds the corresponding
    // request DTOs from the walletd snapshot via the public `::new`
    // constructors when `for_prepared`/`for_approved` are unavailable.
    prepared: Option<PreparedWalletdAnchorRequestV1>,
    approved: Option<ApprovedWalletdAnchorRequestV1>,
    submitted: Option<SubmittedWalletdAnchorRequestV1>,
    query: Option<AnchorReceiptQueryV1>,
    // The last finalized indexer receipt, retained for the optional agreement
    // check. It is never mutated by agreement.
    cached_receipt: Option<CachedReceiptReport>,
    diagnostic: Option<&'static str>,
}

impl Default for AnchorLifecycleOrchestrator {
    fn default() -> Self {
        Self::new(PollingPolicy::default())
    }
}

impl AnchorLifecycleOrchestrator {
    /// Creates an orchestrator with an empty walletd coordinator, an empty
    /// receipt coordinator, and the given polling policy.
    #[must_use]
    pub fn new(policy: PollingPolicy) -> Self {
        Self {
            walletd: WalletdAnchorCoordinator::new(),
            receipt: AnchorReceiptCoordinator::new(),
            policy,
            phase: UnifiedAnchorLifecyclePhase::NotPrepared,
            prepared: None,
            approved: None,
            submitted: None,
            query: None,
            cached_receipt: None,
            diagnostic: None,
        }
    }

    /// Restores an orchestrator from a unified recovery snapshot (Section F
    /// restart).
    ///
    /// Rebuilds both underlying coordinators via their existing
    /// `from_snapshots` constructors and resumes at the correct stage. The
    /// resumed lifecycle will not re-submit, will not rewind a terminal, and
    /// will continue polling within the *remaining* attempt bound.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReconstructionError`] if the walletd and receipt
    /// snapshots disagree on which request they describe, or if a receipt
    /// snapshot exists without a cached submitted handle.
    pub fn from_snapshot(
        snapshot: AnchorLifecycleRecoverySnapshot,
    ) -> Result<Self, LifecycleReconstructionError> {
        Self::from_snapshots(
            snapshot.walletd_snapshots().to_vec(),
            snapshot.receipt_snapshots().to_vec(),
            snapshot.submitted().cloned(),
            snapshot.policy(),
            snapshot.phase(),
            snapshot.diagnostic(),
        )
    }

    /// Restores an orchestrator from its composed snapshot parts.
    ///
    /// This is the lower-level reconstruction used by [`from_snapshot`](Self::from_snapshot).
    /// It is exposed so a caller that stores the parts separately can rebuild
    /// without first assembling the unified snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReconstructionError`] on snapshot inconsistency.
    pub fn from_snapshots(
        walletd_snapshots: Vec<WalletdAnchorSnapshotV1>,
        receipt_snapshots: Vec<AnchorReceiptQuerySnapshotV1>,
        submitted: Option<SubmittedWalletdAnchorRequestV1>,
        policy: PollingPolicy,
        phase: UnifiedAnchorLifecyclePhase,
        diagnostic: Option<&'static str>,
    ) -> Result<Self, LifecycleReconstructionError> {
        // If both a walletd and a receipt snapshot exist, they must describe the
        // same project request.
        if let (Some(walletd_first), Some(receipt_first)) =
            (walletd_snapshots.first(), receipt_snapshots.first())
            && walletd_first.project_request_id() != receipt_first.project_request_id()
        {
            return Err(LifecycleReconstructionError::SnapshotRequestMismatch);
        }

        // A receipt snapshot implies polling, which requires the cached submitted
        // handle (its constructor is crate-private to the walletd adapter).
        if !receipt_snapshots.is_empty() && submitted.is_none() {
            return Err(LifecycleReconstructionError::MissingSubmittedHandle);
        }

        // Strict phase-consistency validation: the declared phase must be
        // derivable from and consistent with the contained walletd snapshots,
        // receipt snapshots, submitted handle, and polling policy state. This
        // prevents a forged snapshot from fabricating a submitted, approved,
        // verified, or successful state from inconsistent parts.
        Self::validate_reconstruction(
            &walletd_snapshots,
            &receipt_snapshots,
            submitted.as_ref(),
            policy,
            phase,
        )?;

        let walletd = WalletdAnchorCoordinator::from_snapshots(walletd_snapshots);
        let receipt = AnchorReceiptCoordinator::from_snapshots(receipt_snapshots);

        // Derive the receipt query from the cached submitted handle, if present.
        let query = submitted.as_ref().map(AnchorReceiptQueryV1::from_submitted);

        Ok(Self {
            walletd,
            receipt,
            policy,
            phase,
            prepared: None,
            approved: None,
            submitted,
            query,
            cached_receipt: None,
            diagnostic,
        })
    }

    /// Returns the walletd coordinator (for registry inspection).
    #[must_use]
    pub const fn walletd_coordinator(&self) -> &WalletdAnchorCoordinator {
        &self.walletd
    }

    /// Returns the receipt coordinator (for registry inspection).
    #[must_use]
    pub const fn receipt_coordinator(&self) -> &AnchorReceiptCoordinator {
        &self.receipt
    }

    /// Returns the polling policy.
    #[must_use]
    pub const fn policy(&self) -> PollingPolicy {
        self.policy
    }

    /// Returns the unified lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        self.phase
    }

    /// Returns the cached submitted request, if the lifecycle reached the
    /// submitted phase.
    #[must_use]
    pub fn submitted(&self) -> Option<&SubmittedWalletdAnchorRequestV1> {
        self.submitted.as_ref()
    }

    /// Returns the cached receipt query, if the lifecycle reached the submitted
    /// phase.
    #[must_use]
    pub fn query(&self) -> Option<&AnchorReceiptQueryV1> {
        self.query.as_ref()
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&'static str> {
        self.diagnostic
    }

    /// Builds a unified recovery snapshot for the current state (Section E).
    #[must_use]
    pub fn snapshot(&self) -> AnchorLifecycleRecoverySnapshot {
        AnchorLifecycleRecoverySnapshot::new(
            self.walletd.registry().snapshots(),
            self.receipt.registry().snapshots(),
            self.submitted.clone(),
            self.policy,
            self.phase,
            self.diagnostic,
        )
    }

    // ------------------------------------------------------------------
    // Step: prepare (Section A)
    // ------------------------------------------------------------------

    /// Prepares a fee-bearing walletd anchor request (Strategy 2), calling
    /// `WalletdAnchorCoordinator::prepare_fee_bearing` verbatim.
    ///
    /// Transitions: `NotPrepared → Prepared`.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::Walletd`] if the walletd coordinator refuses,
    /// is unavailable, or returns a malformed response.
    pub fn prepare_fee_bearing<
        C: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient,
    >(
        &mut self,
        client: &mut C,
        build_request: &OotleAnchorTransactionBuildRequestV1,
        fee_component: &WalletdFeeComponentRef,
        seal_signer: WalletdSealSignerRef,
        ttl_secs: Option<u64>,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }

        let prepared = self.walletd.prepare_fee_bearing(
            client,
            build_request,
            fee_component,
            seal_signer,
            ttl_secs,
        )?;

        self.prepared = Some(prepared.clone());
        self.approved = None;
        self.submitted = None;
        self.query = None;
        self.cached_receipt = None;
        self.diagnostic = None;
        self.phase = UnifiedAnchorLifecyclePhase::Prepared;

        Ok(self.report(LifecycleStepOutcome::Prepared))
    }

    // ------------------------------------------------------------------
    // Step: approve / reject (Section D)
    // ------------------------------------------------------------------

    /// Approves the prepared request, calling `WalletdAnchorCoordinator::approve`
    /// with `WalletdDecisionRequestV1::for_prepared`.
    ///
    /// Transitions: `Prepared → Approved`. Terminal phases are idempotent
    /// no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] on a missing prepared handle, a walletd
    /// error, or an already-decided request.
    pub fn approve<C: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient>(
        &mut self,
        client: &mut C,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }
        if self.phase != UnifiedAnchorLifecyclePhase::Prepared
            && self.phase != UnifiedAnchorLifecyclePhase::Approved
        {
            return Err(LifecycleError::NotPrepared);
        }

        // If we have the live prepared handle, use for_prepared. Otherwise
        // rebuild the decision request from the walletd snapshot (restart path).
        let decision = match self.prepared.as_ref() {
            Some(prepared) => WalletdDecisionRequestV1::for_prepared(prepared),
            None => self.decision_from_snapshot()?,
        };

        let approved = self.walletd.approve(client, &decision)?;
        self.approved = Some(approved);
        self.diagnostic = None;
        self.phase = UnifiedAnchorLifecyclePhase::Approved;
        Ok(self.report(LifecycleStepOutcome::Approved))
    }

    /// Rejects the prepared request, calling `WalletdAnchorCoordinator::reject`
    /// with `WalletdDecisionRequestV1::for_prepared`.
    ///
    /// Transitions: `Prepared → RejectedByApprover` (terminal). Repeated
    /// rejection is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] on a missing prepared handle or a walletd
    /// error.
    pub fn reject<C: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient>(
        &mut self,
        client: &mut C,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase == UnifiedAnchorLifecyclePhase::RejectedByApprover {
            return Ok(self.idempotent_no_op());
        }
        if self.phase != UnifiedAnchorLifecyclePhase::Prepared {
            return Err(LifecycleError::NotPrepared);
        }

        let decision = match self.prepared.as_ref() {
            Some(prepared) => WalletdDecisionRequestV1::for_prepared(prepared),
            None => self.decision_from_snapshot()?,
        };

        self.walletd.reject(client, &decision)?;
        self.diagnostic = None;
        self.phase = UnifiedAnchorLifecyclePhase::RejectedByApprover;
        Ok(self.report(LifecycleStepOutcome::RejectedByApprover))
    }

    // ------------------------------------------------------------------
    // Step: submit (Section D)
    // ------------------------------------------------------------------

    /// Submits the approved request, calling `WalletdAnchorCoordinator::submit`
    /// with `WalletdSubmitRequestV1::for_approved`.
    ///
    /// Transitions:
    /// * `Approved → Submitted` (success);
    /// * `Approved → Unknown` (submit timeout / lost response — recover next).
    ///
    /// On success it builds the receipt query via
    /// `AnchorReceiptQueryV1::from_submitted` and registers it with the receipt
    /// coordinator via `AnchorReceiptCoordinator::register`.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] on a missing approved handle or a walletd
    /// error. A submit timeout is *not* an error here: the phase transitions to
    /// `Unknown` and the report records the outcome.
    pub fn submit<C: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient>(
        &mut self,
        client: &mut C,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }

        // Submitted is idempotent: if we already have a submitted handle, do not
        // re-submit.
        if self.phase == UnifiedAnchorLifecyclePhase::Submitted
            || self.phase == UnifiedAnchorLifecyclePhase::PollingInProgress
        {
            return Ok(self.idempotent_no_op());
        }

        if self.phase != UnifiedAnchorLifecyclePhase::Approved {
            return Err(LifecycleError::NotApproved);
        }

        let submit_request = match self.approved.as_ref() {
            Some(approved) => WalletdSubmitRequestV1::for_approved(approved),
            None => self.submit_request_from_snapshot()?,
        };

        match self.walletd.submit(client, &submit_request) {
            Ok(submitted) => {
                self.register_submitted(submitted)?;
                self.diagnostic = None;
                self.phase = UnifiedAnchorLifecyclePhase::Submitted;
                Ok(self.report(LifecycleStepOutcome::Submitted))
            }
            Err(error) => {
                // A timeout/lost-response/already-submitted marks the request
                // unknown so the next step is recovery, never a blind resubmit.
                // Other errors leave the approval intact for a controlled retry.
                let is_timeout = matches!(
                    error,
                    WalletdAnchorAdapterError::SubmitTimeout
                        | WalletdAnchorAdapterError::MalformedSubmitResponse
                        | WalletdAnchorAdapterError::AlreadySubmitted
                        | WalletdAnchorAdapterError::SubmissionStateUnknown
                );
                self.diagnostic = Some(error.as_str());
                if is_timeout {
                    self.phase = UnifiedAnchorLifecyclePhase::Unknown;
                }
                Err(LifecycleError::Walletd(error))
            }
        }
    }

    // ------------------------------------------------------------------
    // Step: recover (Section D)
    // ------------------------------------------------------------------

    /// Recovers a request whose submit result was lost, calling
    /// `WalletdAnchorCoordinator::recover` verbatim.
    ///
    /// Transitions:
    /// * `Unknown(submit) → Submitted` (recover finds a sealed transaction id);
    /// * `Unknown(submit) → Approved` (recover proves never sealed; retryable);
    /// * `Unknown(submit) → RejectedByApprover` / `Unknown` (recover
    ///   terminal/in-flight).
    ///
    /// When recovery finds a sealed transaction id, the driver calls `submit`
    /// once more — **idempotently** (the walletd coordinator returns the cached
    /// transaction id without a second client call, so no second transaction is
    /// created) — to obtain the `SubmittedWalletdAnchorRequestV1` handle needed
    /// for the receipt query. This is the only safe way to obtain that handle,
    /// because its constructor is crate-private to the walletd adapter.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] if the lifecycle is not in a recoverable
    /// (Unknown) state, or on a walletd recovery error.
    pub fn recover<C: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient>(
        &mut self,
        client: &mut C,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }
        if self.phase != UnifiedAnchorLifecyclePhase::Unknown {
            return Err(LifecycleError::NotRecoverable);
        }

        let submit_request = match self.approved.as_ref() {
            Some(approved) => WalletdSubmitRequestV1::for_approved(approved),
            None => self.submit_request_from_snapshot()?,
        };

        let recovered = self.walletd.recover(client, &submit_request)?;
        let outcome = LifecycleRecoveryOutcome::from(recovered.state());

        match recovered.state() {
            WalletdRecoveryStateV1::Submitted(_) => {
                // Recover found a sealed transaction id. Call submit
                // idempotently — the coordinator returns the cached id without
                // a second client call — to obtain the submitted handle.
                let submitted = self.walletd.submit(client, &submit_request)?;
                self.register_submitted(submitted)?;
                self.phase = UnifiedAnchorLifecyclePhase::Submitted;
                self.diagnostic = None;
            }
            WalletdRecoveryStateV1::NotSubmittedRetryable => {
                // Proven never sealed: safe to retry. The lifecycle returns to
                // Approved so the caller can submit again.
                self.phase = UnifiedAnchorLifecyclePhase::Approved;
                self.diagnostic = None;
            }
            WalletdRecoveryStateV1::SubmissionInProgress
            | WalletdRecoveryStateV1::Pending
            | WalletdRecoveryStateV1::Expired => {
                self.phase = UnifiedAnchorLifecyclePhase::Unknown;
                self.diagnostic = None;
            }
            WalletdRecoveryStateV1::RejectedByApprover => {
                self.phase = UnifiedAnchorLifecyclePhase::RejectedByApprover;
                self.diagnostic = None;
            }
        }

        Ok(self.report(LifecycleStepOutcome::Recovered(outcome)))
    }

    // ------------------------------------------------------------------
    // Step: advance-one-poll (Section D)
    // ------------------------------------------------------------------

    /// Advances the polling by exactly one receipt query, calling
    /// `AnchorReceiptCoordinator::query` exactly once and consuming exactly one
    /// attempt from the policy.
    ///
    /// Transitions:
    /// * `ReceiptNotFound` / `ReceiptPending` / `ReceiptUnknown` → remain
    ///   polling (`PollingInProgress`) until `max_query_attempts` is reached,
    ///   then `Unknown` (resumable, not permanent failure);
    /// * full acceptance + verified → `FinalizedAccept` (terminal success);
    /// * fee-only → `FinalizedFeeOnly` (terminal, non-success);
    /// * rejected → `FinalizedReject` (terminal);
    /// * finalized-but-verification-failed → `FinalizedVerificationFailed`
    ///   (terminal, non-success — never `FinalizedAccept`).
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] if the lifecycle has not reached the
    /// submitted phase, or on a receipt hard error (binding mismatch or
    /// malformed identifier). Unfavourable outcomes (not-found, pending,
    /// timeout) are normal reports, not errors.
    pub fn advance_one_poll<
        C: tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient,
    >(
        &mut self,
        client: &mut C,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }

        // Only Submitted, PollingInProgress, and Unknown (poll-exhausted) may
        // poll. Approved/Prepared/NotPrepared cannot.
        if !matches!(
            self.phase,
            UnifiedAnchorLifecyclePhase::Submitted
                | UnifiedAnchorLifecyclePhase::PollingInProgress
                | UnifiedAnchorLifecyclePhase::Unknown
        ) {
            return Err(LifecycleError::NotSubmitted);
        }

        if self.policy.is_exhausted() {
            // The attempt bound is exhausted. Transition to a resumable Unknown,
            // never a permanent failure.
            self.phase = UnifiedAnchorLifecyclePhase::Unknown;
            self.diagnostic = Some("POLL_EXHAUSTED");
            return Ok(self.report(LifecycleStepOutcome::PolicyExhausted));
        }

        let (query, submitted) = match (&self.query, &self.submitted) {
            (Some(query), Some(submitted)) => (query.clone(), submitted.clone()),
            _ => return Err(LifecycleError::NotSubmitted),
        };

        let report = self.receipt.query(client, &query, &submitted)?;
        self.policy.consume_one();

        // Cache the indexer receipt for the optional agreement check.
        if let Some(receipt) = report.receipt() {
            self.cached_receipt = Some(CachedReceiptReport {
                transaction_id: query.transaction_id().clone(),
                network: query.network().clone(),
                indexer_receipt: Some(receipt.clone()),
            });
        }

        let query_outcome = LifecycleReceiptQueryOutcome::from(report.state());
        self.phase = self.phase_from_receipt_report(&report);
        if self.phase.is_terminal() {
            self.diagnostic = None;
        } else if self.policy.is_exhausted() {
            self.phase = UnifiedAnchorLifecyclePhase::Unknown;
            self.diagnostic = Some("POLL_EXHAUSTED");
        } else {
            self.phase = UnifiedAnchorLifecyclePhase::PollingInProgress;
            self.diagnostic = report.diagnostic();
        }

        Ok(self.report(LifecycleStepOutcome::Polled(query_outcome)))
    }

    // ------------------------------------------------------------------
    // Step: check_agreement (Section G)
    // ------------------------------------------------------------------

    /// Optionally runs the existing `compare_walletd_and_indexer` agreement
    /// check when a walletd finalize observation is available alongside the
    /// independently retrieved indexer receipt.
    ///
    /// A disagreement:
    /// * is surfaced as [`FinalizedDisagreement`](UnifiedAnchorLifecyclePhase::FinalizedDisagreement);
    /// * does *not* mutate the archive, anchor record, submitted transaction
    ///   id, unsigned-transaction fingerprint, or any prior verified receipt
    ///   evidence;
    /// * does not by itself convert a verified acceptance into a failure of the
    ///   underlying artifacts (the cached receipt evidence is preserved
    ///   unchanged).
    ///
    /// This method calls `compare_walletd_and_indexer` verbatim and
    /// re-implements none of its logic.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::Agreement`] on disagreement (the phase is also
    /// set to `FinalizedDisagreement`). Returns
    /// [`LifecycleError::NotSubmitted`] if no indexer receipt has been cached
    /// yet. A terminal phase is an idempotent no-op: the phase, diagnostic, and
    /// cached receipt evidence are never mutated, so a `FinalizedAccept` can
    /// never be rewound to `FinalizedDisagreement` (or any other terminal) by a
    /// late agreement check.
    pub fn check_agreement(
        &mut self,
        walletd_observation: &AnchorReceiptV1,
    ) -> Result<LifecycleStepReport, LifecycleError> {
        if self.phase.is_terminal() {
            return Ok(self.idempotent_no_op());
        }

        let Some(cached) = &self.cached_receipt else {
            return Err(LifecycleError::NotSubmitted);
        };
        let Some(indexer_receipt) = &cached.indexer_receipt else {
            return Err(LifecycleError::NotSubmitted);
        };

        match tari_cc_private_ballot_ootle_receipt_anchor_adapter::compare_walletd_and_indexer(
            &cached.transaction_id,
            &cached.network,
            walletd_observation,
            indexer_receipt,
        ) {
            Ok(()) => {
                self.diagnostic = None;
                Ok(self.report(LifecycleStepOutcome::AgreementOk))
            }
            Err(error) => {
                // Surface disagreement as a distinct terminal. Do NOT mutate the
                // cached receipt evidence or any artifact.
                self.diagnostic = Some(error.as_str());
                self.phase = UnifiedAnchorLifecyclePhase::FinalizedDisagreement;
                Err(LifecycleError::Agreement(error))
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Reconstruction validation (Section D — snapshot phase consistency)
    // ------------------------------------------------------------------

    /// Validates that the declared phase is consistent with the contained
    /// snapshot state.
    ///
    /// This prevents a forged or corrupted snapshot from fabricating a
    /// submitted, approved, verified, or successful state from inconsistent
    /// parts. It is a pure function of the snapshot fields and never contacts
    /// a transport or mutates an artifact.
    fn validate_reconstruction(
        walletd_snapshots: &[WalletdAnchorSnapshotV1],
        receipt_snapshots: &[AnchorReceiptQuerySnapshotV1],
        submitted: Option<&SubmittedWalletdAnchorRequestV1>,
        policy: PollingPolicy,
        phase: UnifiedAnchorLifecyclePhase,
    ) -> Result<(), LifecycleReconstructionError> {
        // A single anchor lifecycle describes at most one walletd snapshot and
        // one receipt-query snapshot.
        if walletd_snapshots.len() > 1 || receipt_snapshots.len() > 1 {
            return Err(LifecycleReconstructionError::TooManySnapshots);
        }

        // Cross-check the submitted handle against the walletd snapshot, if both
        // exist.
        if let Some(submitted) = submitted {
            let Some(walletd) = walletd_snapshots.first() else {
                return Err(LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot);
            };

            if walletd.project_request_id() != submitted.project_request_id()
                || walletd.walletd_request_id() != submitted.walletd_request_id()
            {
                return Err(LifecycleReconstructionError::DuplicateIdentifier);
            }

            if walletd.binding() != submitted.binding() {
                return Err(LifecycleReconstructionError::BindingMismatch);
            }

            // The walletd snapshot's transaction id, when present, must match
            // the submitted handle's transaction id.
            if walletd.transaction_id() != Some(submitted.transaction_id()) {
                return Err(LifecycleReconstructionError::TransactionIdMismatch);
            }
        }

        // Cross-check the receipt snapshot's query against the submitted
        // handle, if both exist.
        if let Some(receipt) = receipt_snapshots.first() {
            let Some(submitted) = submitted else {
                // Already caught by the MissingSubmittedHandle check above,
                // but defend in depth.
                return Err(LifecycleReconstructionError::MissingSubmittedHandle);
            };

            let query = receipt.query();
            if query.project_request_id() != submitted.project_request_id()
                || query.walletd_request_id() != submitted.walletd_request_id()
                || query.transaction_id() != submitted.transaction_id()
                || query.network() != submitted.binding().network()
                || query.account() != submitted.binding().account()
                || query.anchor_digest() != submitted.binding().anchor_digest()
                || query.payload() != submitted.binding().payload()
                || query.fingerprint() != submitted.binding().fingerprint()
            {
                return Err(LifecycleReconstructionError::BindingMismatch);
            }
        }

        // Phase-specific consistency checks.
        let walletd = walletd_snapshots.first();
        let receipt = receipt_snapshots.first();

        match phase {
            UnifiedAnchorLifecyclePhase::NotPrepared => {
                if walletd.is_some() || receipt.is_some() || submitted.is_some() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::Prepared => {
                let Some(ws) = walletd else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if ws.decision() != WalletdRequestDecisionV1::Prepared
                    || ws.submission() != WalletdSubmissionStateV1::NotSubmitted
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                if submitted.is_some() || receipt.is_some() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::Approved => {
                let Some(ws) = walletd else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if ws.decision() != WalletdRequestDecisionV1::Approved
                    || ws.submission() != WalletdSubmissionStateV1::NotSubmitted
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                if submitted.is_some() || receipt.is_some() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::RejectedByApprover => {
                let Some(ws) = walletd else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if ws.decision() != WalletdRequestDecisionV1::Rejected {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                if submitted.is_some() || receipt.is_some() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::Submitted => {
                let Some(submitted) = submitted else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                let Some(ws) = walletd else {
                    return Err(
                        LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot,
                    );
                };
                if ws.submission() != WalletdSubmissionStateV1::Submitted {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                if ws.transaction_id() != Some(submitted.transaction_id()) {
                    return Err(LifecycleReconstructionError::TransactionIdMismatch);
                }
                // Receipt state, if present, must be SubmittedNotQueried and
                // not verified.
                if let Some(rs) = receipt
                    && (rs.state() != AnchorReceiptQueryStateV1::SubmittedNotQueried
                        || rs.verified())
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::PollingInProgress => {
                let Some(submitted) = submitted else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                let Some(ws) = walletd else {
                    return Err(
                        LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot,
                    );
                };
                if ws.submission() != WalletdSubmissionStateV1::Submitted {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                if ws.transaction_id() != Some(submitted.transaction_id()) {
                    return Err(LifecycleReconstructionError::TransactionIdMismatch);
                }
                let Some(rs) = receipt else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                // Receipt state must be a resumable non-terminal state.
                if !matches!(
                    rs.state(),
                    AnchorReceiptQueryStateV1::ReceiptNotFound
                        | AnchorReceiptQueryStateV1::ReceiptPending
                        | AnchorReceiptQueryStateV1::ReceiptUnknown
                        | AnchorReceiptQueryStateV1::SubmittedNotQueried
                ) || rs.verified()
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                // At least one attempt must have been consumed.
                if policy.attempts_consumed() == 0 {
                    return Err(LifecycleReconstructionError::PolicyInconsistent);
                }
            }
            UnifiedAnchorLifecyclePhase::Unknown => {
                // Unknown arises from either a submit timeout (no submitted
                // handle, walletd snapshot with TimedOutUnknown) or poll
                // exhaustion (submitted handle, walletd snapshot with
                // Submitted, non-terminal receipt state).
                if let Some(submitted) = submitted {
                    let Some(ws) = walletd else {
                        return Err(
                            LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot,
                        );
                    };
                    if ws.submission() != WalletdSubmissionStateV1::Submitted
                        || ws.transaction_id() != Some(submitted.transaction_id())
                    {
                        return Err(LifecycleReconstructionError::PhaseStateMismatch);
                    }
                    // Must not carry a verified successful receipt.
                    if let Some(rs) = receipt
                        && rs.verified()
                    {
                        return Err(LifecycleReconstructionError::PhaseStateMismatch);
                    }
                } else {
                    // Submit-timeout Unknown: a walletd snapshot with
                    // TimedOutUnknown must exist.
                    let Some(ws) = walletd else {
                        return Err(LifecycleReconstructionError::PhaseStateMismatch);
                    };
                    if ws.submission() != WalletdSubmissionStateV1::TimedOutUnknown {
                        return Err(LifecycleReconstructionError::PhaseStateMismatch);
                    }
                    if receipt.is_some() {
                        return Err(LifecycleReconstructionError::PhaseStateMismatch);
                    }
                }
            }
            UnifiedAnchorLifecyclePhase::FinalizedAccept => {
                let Some(submitted) = submitted else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                let Some(ws) = walletd else {
                    return Err(
                        LifecycleReconstructionError::SubmittedHandleWithoutWalletdSnapshot,
                    );
                };
                if ws.submission() != WalletdSubmissionStateV1::Submitted
                    || ws.transaction_id() != Some(submitted.transaction_id())
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                let Some(rs) = receipt else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if rs.state() != AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
                    || !rs.verified()
                    || rs.last_final_status() != Some(AnchorFinalStatusV1::Accepted)
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::FinalizedFeeOnly => {
                if submitted.is_none() || receipt.is_none() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                let Some(rs) = receipt else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if rs.state() != AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly || rs.verified()
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::FinalizedReject => {
                if submitted.is_none() || receipt.is_none() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                let Some(rs) = receipt else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                if rs.state() != AnchorReceiptQueryStateV1::ReceiptFinalizedReject || rs.verified()
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed => {
                if submitted.is_none() || receipt.is_none() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
                let Some(rs) = receipt else {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                };
                // Verification failed: state is ReceiptVerificationFailed, or
                // ReceiptFinalizedAccept without a verified flag (a finalized
                // full acceptance that failed verification).
                if !matches!(
                    rs.state(),
                    AnchorReceiptQueryStateV1::ReceiptVerificationFailed
                        | AnchorReceiptQueryStateV1::ReceiptFinalizedAccept
                ) || rs.verified()
                {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
            UnifiedAnchorLifecyclePhase::FinalizedDisagreement => {
                // A disagreement requires a submitted handle and a receipt
                // snapshot (the disagreement is about a submitted transaction's
                // receipt). It must not simultaneously represent a clean
                // verified agreement — but the phase itself
                // (FinalizedDisagreement, not FinalizedAccept) distinguishes
                // them. A verified receipt may coexist with a disagreement
                // diagnostic (the indexer verified but walletd disagreed).
                if submitted.is_none() || receipt.is_none() {
                    return Err(LifecycleReconstructionError::PhaseStateMismatch);
                }
            }
        }

        Ok(())
    }

    /// Registers a submitted request with the receipt coordinator.
    fn register_submitted(
        &mut self,
        submitted: SubmittedWalletdAnchorRequestV1,
    ) -> Result<(), LifecycleError> {
        let query = AnchorReceiptQueryV1::from_submitted(&submitted);
        self.receipt.register(&query, &submitted)?;
        self.submitted = Some(submitted);
        self.query = Some(query);
        self.cached_receipt = None;
        Ok(())
    }

    /// Maps a receipt-query report into the unified phase (Section D).
    fn phase_from_receipt_report(
        &self,
        report: &AnchorReceiptQueryReportV1,
    ) -> UnifiedAnchorLifecyclePhase {
        match report.state() {
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept if report.is_verified_success() => {
                UnifiedAnchorLifecyclePhase::FinalizedAccept
            }
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept => {
                // A finalized full acceptance that did not verify. This distinct
                // non-success terminal is never FinalizedAccept.
                UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
            }
            AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly => {
                UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
            }
            AnchorReceiptQueryStateV1::ReceiptFinalizedReject => {
                UnifiedAnchorLifecyclePhase::FinalizedReject
            }
            AnchorReceiptQueryStateV1::ReceiptVerificationFailed => {
                UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
            }
            // Resumable: remain polling (or exhaust to Unknown in the caller).
            AnchorReceiptQueryStateV1::SubmittedNotQueried
            | AnchorReceiptQueryStateV1::ReceiptNotFound
            | AnchorReceiptQueryStateV1::ReceiptPending
            | AnchorReceiptQueryStateV1::ReceiptUnknown => {
                UnifiedAnchorLifecyclePhase::PollingInProgress
            }
        }
    }

    /// Rebuilds a decision request from the walletd snapshot (restart path).
    fn decision_from_snapshot(&self) -> Result<WalletdDecisionRequestV1, LifecycleError> {
        let snapshot = self.walletd_snapshot()?;
        Ok(WalletdDecisionRequestV1::new(
            snapshot.project_request_id().clone(),
            snapshot.walletd_request_id(),
            snapshot.binding().clone(),
        ))
    }

    /// Rebuilds a submit request from the walletd snapshot (restart path).
    fn submit_request_from_snapshot(&self) -> Result<WalletdSubmitRequestV1, LifecycleError> {
        let snapshot = self.walletd_snapshot()?;
        Ok(WalletdSubmitRequestV1::new(
            snapshot.project_request_id().clone(),
            snapshot.walletd_request_id(),
            snapshot.binding().clone(),
        ))
    }

    /// Returns the single walletd snapshot (owned), or an error if none exists.
    fn walletd_snapshot(&self) -> Result<WalletdAnchorSnapshotV1, LifecycleError> {
        self.walletd
            .registry()
            .snapshots()
            .into_iter()
            .next()
            .ok_or(LifecycleError::NotPrepared)
    }

    /// Builds an idempotent no-op report for a terminal phase.
    fn idempotent_no_op(&self) -> LifecycleStepReport {
        LifecycleStepReport::new(
            self.phase,
            LifecycleStepOutcome::IdempotentNoOp,
            self.policy,
            self.diagnostic,
        )
    }

    /// Builds a step report from the current state.
    fn report(&self, outcome: LifecycleStepOutcome) -> LifecycleStepReport {
        LifecycleStepReport::new(self.phase, outcome, self.policy, self.diagnostic)
    }
}

impl From<&WalletdRecoveryStateV1> for LifecycleRecoveryOutcome {
    fn from(state: &WalletdRecoveryStateV1) -> Self {
        match state {
            WalletdRecoveryStateV1::Submitted(_) => Self::Submitted,
            WalletdRecoveryStateV1::NotSubmittedRetryable => Self::NotSubmittedRetryable,
            WalletdRecoveryStateV1::SubmissionInProgress => Self::SubmissionInProgress,
            WalletdRecoveryStateV1::Pending => Self::Pending,
            WalletdRecoveryStateV1::RejectedByApprover => Self::RejectedByApprover,
            WalletdRecoveryStateV1::Expired => Self::Expired,
        }
    }
}

impl From<AnchorReceiptQueryStateV1> for LifecycleReceiptQueryOutcome {
    fn from(state: AnchorReceiptQueryStateV1) -> Self {
        match state {
            AnchorReceiptQueryStateV1::SubmittedNotQueried => Self::SubmittedNotQueried,
            AnchorReceiptQueryStateV1::ReceiptNotFound => Self::ReceiptNotFound,
            AnchorReceiptQueryStateV1::ReceiptPending => Self::ReceiptPending,
            AnchorReceiptQueryStateV1::ReceiptUnknown => Self::ReceiptUnknown,
            AnchorReceiptQueryStateV1::ReceiptFinalizedAccept => Self::ReceiptFinalizedAccept,
            AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly => Self::ReceiptFinalizedFeeOnly,
            AnchorReceiptQueryStateV1::ReceiptFinalizedReject => Self::ReceiptFinalizedReject,
            AnchorReceiptQueryStateV1::ReceiptVerificationFailed => Self::ReceiptVerificationFailed,
        }
    }
}
