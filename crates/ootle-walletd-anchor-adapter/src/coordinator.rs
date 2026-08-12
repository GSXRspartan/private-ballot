//! Prepare / approve / reject / submit / recover orchestration
//! (Sections C, D, E, F, G, H).
//!
//! [`WalletdAnchorCoordinator`] ties conversion, the narrow client boundary, and
//! the local registry together. It performs every binding check before touching
//! the client, distinguishes user rejection from API failure, makes approval and
//! rejection distinct and terminal, and gates submission and transaction-id
//! recovery so an ambiguous state never creates a second distinct transaction. It
//! never signs or seals a transaction itself (walletd seals at submit; this only
//! maps the returned id) and never fabricates a transaction id. Every operation is
//! a pure transform of already-frozen commitments, so a failure at any step leaves
//! every offline election artifact unchanged.

use tari_cc_private_ballot_anchor_transport::{AnchorRequestId, AnchorTransactionId};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorBuildResultV1, OotleAnchorTransactionBuildRequestV1,
    build_fee_bearing_anchor_transaction,
};

use crate::binding::WalletdAnchorBindingV1;
use crate::client::{
    WalletdAnchorClient, WalletdDecisionCommandV1, WalletdRequestStatusV1, WalletdSubmitCommandV1,
};
use crate::convert::{build_fee_bearing_walletd_create_request, build_walletd_create_request};
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::{WalletdFeeComponentRef, WalletdRequestId, WalletdSealSignerRef};
use crate::registry::{
    LocalWalletdAnchorRegistry, WalletdAnchorSnapshotV1, WalletdRequestDecisionV1,
    WalletdSubmissionStateV1,
};
use crate::results::{
    ApprovedWalletdAnchorRequestV1, PreparedWalletdAnchorRequestV1,
    RecoveredWalletdAnchorRequestV1, RejectedWalletdAnchorRequestV1,
    SubmittedWalletdAnchorRequestV1, WalletdRecoveryStateV1,
};
use crate::status::WalletdEffectiveStatusV1;

/// A fully-bound approval or rejection request.
///
/// It binds every field a decision must agree with (Section E): the project and
/// walletd request identifiers plus the frozen binding (network, account, digest,
/// payload, maximum fee, and inspected unsigned-transaction fingerprint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdDecisionRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
}

impl WalletdDecisionRequestV1 {
    /// Assembles a fully-bound decision request.
    #[must_use]
    pub fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
        }
    }

    /// Builds a decision request that re-binds a prepared result exactly.
    #[must_use]
    pub fn for_prepared(prepared: &PreparedWalletdAnchorRequestV1) -> Self {
        Self::new(
            prepared.project_request_id().clone(),
            prepared.walletd_request_id(),
            prepared.binding().clone(),
        )
    }

    /// Returns the bound project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the bound walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the bound frozen binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }
}

/// A fully-bound submission or recovery request (Sections C, F, H).
///
/// It binds every field submission and recovery must agree with — the project and
/// walletd request identifiers plus the frozen binding — and deliberately carries
/// **no** transaction id: a transaction id exists only after walletd seals, so it
/// can never be a submission input (Section E).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdSubmitRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
}

impl WalletdSubmitRequestV1 {
    /// Assembles a fully-bound submission request.
    #[must_use]
    pub fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
        }
    }

    /// Builds a submission request that re-binds an approved result exactly.
    #[must_use]
    pub fn for_approved(approved: &ApprovedWalletdAnchorRequestV1) -> Self {
        Self::new(
            approved.project_request_id().clone(),
            approved.walletd_request_id(),
            approved.binding().clone(),
        )
    }

    /// Returns the bound project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the bound walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the bound frozen binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }
}

/// The verified, cloned view of a stored record needed for a bound operation.
struct VerifiedRecordView {
    decision: WalletdRequestDecisionV1,
    submission: WalletdSubmissionStateV1,
    transaction_id: Option<AnchorTransactionId>,
    binding: WalletdAnchorBindingV1,
}

/// Coordinates the offline prepare / approve / reject / submit / recover lifecycle.
#[derive(Debug, Default)]
pub struct WalletdAnchorCoordinator {
    registry: LocalWalletdAnchorRegistry,
}

impl WalletdAnchorCoordinator {
    /// Creates a coordinator with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores a coordinator from recovery snapshots (Section G restart).
    #[must_use]
    pub fn from_snapshots(snapshots: Vec<WalletdAnchorSnapshotV1>) -> Self {
        Self {
            registry: LocalWalletdAnchorRegistry::from_snapshots(snapshots),
        }
    }

    /// Returns the underlying registry for snapshot inspection.
    #[must_use]
    pub const fn registry(&self) -> &LocalWalletdAnchorRegistry {
        &self.registry
    }

    /// Prepares a walletd anchor request from a Slice 4A5 build result.
    ///
    /// Re-inspects the unsigned transaction, creates the frozen walletd request,
    /// and records it locally as `Prepared`. Returns a project-owned prepared
    /// result that claims neither signature, transaction identifier, submission,
    /// nor finality.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] if the build result is
    /// unsafe or the client refuses, is unavailable, or returns a malformed
    /// response.
    pub fn prepare<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        build_result: &OotleAnchorBuildResultV1,
        seal_signer: WalletdSealSignerRef,
        ttl_secs: Option<u64>,
    ) -> Result<PreparedWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        let create = build_walletd_create_request(build_result, seal_signer, ttl_secs)?;
        let outcome = client.create_transaction_request(&create)?;

        let project_request_id = create.project_request_id().clone();
        let binding = create.binding().clone();
        let instruction_count = build_result.evidence().instruction_count();
        let fee_present = build_result.evidence().fee_instructions_present();

        self.registry.register_prepared(
            project_request_id.clone(),
            outcome.walletd_request_id(),
            binding.clone(),
        );

        Ok(PreparedWalletdAnchorRequestV1::new(
            project_request_id,
            outcome.walletd_request_id(),
            binding,
            instruction_count,
            fee_present,
            outcome.expires_at(),
        ))
    }

    /// Prepares a **fee-bearing**, submittable walletd anchor request (Strategy 2).
    ///
    /// Resolves the caller-supplied fee account component address into a pinned
    /// Ootle component address (the single place resolution happens), builds a
    /// fee-bearing unsigned transaction carrying exactly one anchor `EmitLog` plus
    /// one `pay_fee_from_component`, re-inspects it fee-aware, creates the frozen
    /// walletd request, and records it as `Prepared`. Unlike [`Self::prepare`], the
    /// resulting request is submittable, because the confirmed
    /// `transaction_requests.submit` path seals the frozen transaction verbatim
    /// without injecting any fee.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] if the fee component is
    /// invalid, the build/inspection is unsafe, or the client refuses, is
    /// unavailable, or returns a malformed response.
    pub fn prepare_fee_bearing<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        build_request: &OotleAnchorTransactionBuildRequestV1,
        fee_component: &WalletdFeeComponentRef,
        seal_signer: WalletdSealSignerRef,
        ttl_secs: Option<u64>,
    ) -> Result<PreparedWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        // Resolve the opaque account into a pinned component address here, at the
        // single leaf that is allowed to, and build the fee-bearing transaction.
        let component = fee_component.component_address();
        let build_result = build_fee_bearing_anchor_transaction(build_request, component)
            .map_err(WalletdAnchorAdapterError::UnsafeUnsignedTransaction)?;

        let create = build_fee_bearing_walletd_create_request(
            &build_result,
            component,
            seal_signer,
            ttl_secs,
        )?;
        let outcome = client.create_transaction_request(&create)?;

        let project_request_id = create.project_request_id().clone();
        let binding = create.binding().clone();
        let instruction_count = build_result.evidence().instruction_count();
        let fee_present = build_result.evidence().fee_instructions_present();

        self.registry.register_prepared(
            project_request_id.clone(),
            outcome.walletd_request_id(),
            binding.clone(),
        );

        Ok(PreparedWalletdAnchorRequestV1::new(
            project_request_id,
            outcome.walletd_request_id(),
            binding,
            instruction_count,
            fee_present,
            outcome.expires_at(),
        ))
    }

    /// Submits an approved, fully-rebound request (Sections C, D, E, G).
    ///
    /// Every binding field is re-verified before the client is touched. A request
    /// already known submitted returns its bound transaction id idempotently
    /// without a second client call, so no second anchor transaction can be made.
    /// A request in the timed-out/unknown state is refused until recovery resolves
    /// it: retry always begins with a status lookup, never a blind resubmit.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on any binding mismatch, an
    /// unapproved / rejected / expired / unknown-state request, a client failure,
    /// a submit timeout, a malformed response, or an already-submitted request.
    pub fn submit<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        submit: &WalletdSubmitRequestV1,
    ) -> Result<SubmittedWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        let view = self.verify_bound_record(
            submit.project_request_id(),
            submit.walletd_request_id(),
            submit.binding(),
        )?;
        let project_request_id = submit.project_request_id().clone();

        // A request already sealed returns its transaction id idempotently; no
        // second submission is issued, so no second transaction can be created.
        if view.submission == WalletdSubmissionStateV1::Submitted {
            if let Some(transaction_id) = view.transaction_id {
                return Ok(SubmittedWalletdAnchorRequestV1::new(
                    project_request_id,
                    submit.walletd_request_id(),
                    transaction_id,
                    view.binding,
                ));
            }
            // Submitted state must always carry an id; treat the inconsistency as
            // an unknown state requiring recovery rather than resubmitting.
            return self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::SubmissionStateUnknown,
            );
        }

        // An ambiguous prior attempt must be resolved by recovery, never by a
        // blind resubmit that could create a second distinct transaction.
        if view.submission == WalletdSubmissionStateV1::TimedOutUnknown {
            return self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::SubmissionStateUnknown,
            );
        }

        match view.decision {
            WalletdRequestDecisionV1::Approved => {}
            WalletdRequestDecisionV1::Prepared => {
                return self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestNotApproved,
                );
            }
            WalletdRequestDecisionV1::Rejected => {
                return self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestAlreadyRejected,
                );
            }
            WalletdRequestDecisionV1::Expired => {
                return self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestExpired,
                );
            }
        }

        let command = WalletdSubmitCommandV1::new(submit.walletd_request_id());
        match client.submit_transaction_request(&command) {
            Ok(outcome) => {
                let transaction_id = outcome.transaction_id().clone();
                self.registry
                    .mark_submitted(&project_request_id, transaction_id.clone());
                self.registry.set_last_effective_status(
                    &project_request_id,
                    WalletdEffectiveStatusV1::Submitted,
                );
                Ok(SubmittedWalletdAnchorRequestV1::new(
                    project_request_id,
                    submit.walletd_request_id(),
                    transaction_id,
                    view.binding,
                ))
            }
            Err(error) => {
                self.registry
                    .set_diagnostic(&project_request_id, error.as_str());
                match &error {
                    // The request may have reached walletd; mark it unknown so the
                    // next step is recovery, never a blind resubmit.
                    WalletdAnchorAdapterError::SubmitTimeout
                    | WalletdAnchorAdapterError::MalformedSubmitResponse
                    | WalletdAnchorAdapterError::AlreadySubmitted => {
                        self.registry.mark_timed_out_unknown(&project_request_id);
                    }
                    // A daemon that could not be reached never sealed anything, so
                    // the approval survives and a later submit is safe.
                    other => self.apply_client_error(&project_request_id, other),
                }
                Err(error)
            }
        }
    }

    /// Recovers a request whose submit result was lost (Sections F, G, H).
    ///
    /// Re-verifies the binding, consults the confirmed status API, proves the
    /// returned frozen transaction is byte-identical to the prepared one, and maps
    /// the observed effective status into a project recovery classification. A
    /// discovered transaction id transitions the request to `Submitted`; a request
    /// still merely approved is safe to retry; a request still submitting is left
    /// unknown. A recovered id that conflicts with a locally bound one is a
    /// security error, never a silent overwrite.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on any binding mismatch, a
    /// fingerprint mismatch, a client failure, a submitted-without-id response, or
    /// a conflicting transaction id.
    pub fn recover<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        recovery: &WalletdSubmitRequestV1,
    ) -> Result<RecoveredWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        let view = self.verify_bound_record(
            recovery.project_request_id(),
            recovery.walletd_request_id(),
            recovery.binding(),
        )?;
        let project_request_id = recovery.project_request_id().clone();

        let status = match client.get_transaction_request(recovery.walletd_request_id()) {
            Ok(status) => status,
            Err(error) => {
                self.registry
                    .set_diagnostic(&project_request_id, error.as_str());
                return Err(error);
            }
        };

        // The frozen request walletd returned must be byte-identical to the one we
        // prepared: absence or mismatch is a security error, not a warning.
        let Some(observed) = status.observed_fingerprint() else {
            return self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::MissingObservedFingerprint,
            );
        };
        if observed != view.binding.fingerprint() {
            return self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::FingerprintMismatch,
            );
        }

        self.registry
            .set_last_effective_status(&project_request_id, status.status());

        let state = match status.status() {
            WalletdEffectiveStatusV1::Submitted => {
                let Some(observed_id) = status.transaction_id().cloned() else {
                    return self.record_and_return(
                        &project_request_id,
                        WalletdAnchorAdapterError::SubmittedButTransactionIdMissing,
                    );
                };
                // A locally bound id that disagrees with the observed one is a
                // conflict, never a silent overwrite.
                if let Some(local_id) = &view.transaction_id
                    && *local_id != observed_id
                {
                    return self.record_and_return(
                        &project_request_id,
                        WalletdAnchorAdapterError::ConflictingTransactionId,
                    );
                }
                self.registry
                    .mark_submitted(&project_request_id, observed_id.clone());
                WalletdRecoveryStateV1::Submitted(observed_id)
            }
            WalletdEffectiveStatusV1::Approved => {
                // Confirmed not submitted: it never sealed, so a controlled retry
                // is safe. A locally recorded id here would be a conflict.
                if view.transaction_id.is_some() {
                    return self.record_and_return(
                        &project_request_id,
                        WalletdAnchorAdapterError::ConflictingTransactionId,
                    );
                }
                self.registry
                    .reset_submission_not_submitted(&project_request_id);
                // Count this recovery cycle that cleared a stuck submit for retry,
                // so a caller can bound how many times it re-attempts.
                if view.submission == WalletdSubmissionStateV1::TimedOutUnknown {
                    self.registry.increment_retry(&project_request_id);
                }
                WalletdRecoveryStateV1::NotSubmittedRetryable
            }
            WalletdEffectiveStatusV1::Submitting => {
                self.registry.mark_timed_out_unknown(&project_request_id);
                WalletdRecoveryStateV1::SubmissionInProgress
            }
            WalletdEffectiveStatusV1::Pending => WalletdRecoveryStateV1::Pending,
            WalletdEffectiveStatusV1::Rejected => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Rejected);
                WalletdRecoveryStateV1::RejectedByApprover
            }
            WalletdEffectiveStatusV1::Expired => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Expired);
                WalletdRecoveryStateV1::Expired
            }
        };

        Ok(RecoveredWalletdAnchorRequestV1::new(
            project_request_id,
            recovery.walletd_request_id(),
            view.binding,
            state,
        ))
    }

    /// Loads and verifies a stored record against a decision request.
    ///
    /// Returns the frozen binding on success. Every mismatch is a specific,
    /// bounded error; a diagnostic is recorded for a found-but-mismatched record.
    fn verify_decision(
        &mut self,
        decision: &WalletdDecisionRequestV1,
    ) -> Result<(WalletdRequestDecisionV1, WalletdAnchorBindingV1), WalletdAnchorAdapterError> {
        let project_request_id = decision.project_request_id();

        let Some(record) = self.registry.record(project_request_id) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };

        let stored_walletd_id = record.walletd_request_id;
        let stored_binding = record.binding.clone();
        let stored_decision = record.decision;

        if stored_walletd_id != decision.walletd_request_id() {
            self.registry.set_diagnostic(
                project_request_id,
                WalletdAnchorAdapterError::RequestIdMismatch.as_str(),
            );
            return Err(WalletdAnchorAdapterError::RequestIdMismatch);
        }

        if let Err(error) = stored_binding.ensure_matches(decision.binding()) {
            self.registry
                .set_diagnostic(project_request_id, error.as_str());
            return Err(error);
        }

        Ok((stored_decision, stored_binding))
    }

    /// Loads and verifies a stored record for a submission or recovery request.
    ///
    /// Like [`Self::verify_decision`] but also returns the submission state and any
    /// bound transaction id. Every mismatch is a specific, bounded error; a
    /// diagnostic is recorded for a found-but-mismatched record.
    fn verify_bound_record(
        &mut self,
        project_request_id: &AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        supplied_binding: &WalletdAnchorBindingV1,
    ) -> Result<VerifiedRecordView, WalletdAnchorAdapterError> {
        let Some(record) = self.registry.record(project_request_id) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };

        let stored_walletd_id = record.walletd_request_id;
        let stored_binding = record.binding.clone();
        let decision = record.decision;
        let submission = record.submission;
        let transaction_id = record.transaction_id.clone();

        if stored_walletd_id != walletd_request_id {
            self.registry.set_diagnostic(
                project_request_id,
                WalletdAnchorAdapterError::RequestIdMismatch.as_str(),
            );
            return Err(WalletdAnchorAdapterError::RequestIdMismatch);
        }

        if let Err(error) = stored_binding.ensure_matches(supplied_binding) {
            self.registry
                .set_diagnostic(project_request_id, error.as_str());
            return Err(error);
        }

        Ok(VerifiedRecordView {
            decision,
            submission,
            transaction_id,
            binding: stored_binding,
        })
    }

    /// Approves a prepared request (Section E).
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on any binding mismatch,
    /// an unknown/rejected/expired/already-decided request, or a client failure.
    pub fn approve<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        decision: &WalletdDecisionRequestV1,
    ) -> Result<ApprovedWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        let (stored_decision, stored_binding) = self.verify_decision(decision)?;
        let project_request_id = decision.project_request_id().clone();

        match stored_decision {
            WalletdRequestDecisionV1::Approved => {
                return Err(WalletdAnchorAdapterError::RequestAlreadyApproved);
            }
            WalletdRequestDecisionV1::Rejected => {
                return Err(WalletdAnchorAdapterError::RequestAlreadyRejected);
            }
            WalletdRequestDecisionV1::Expired => {
                return Err(WalletdAnchorAdapterError::RequestExpired);
            }
            WalletdRequestDecisionV1::Prepared => {}
        }

        let command = WalletdDecisionCommandV1::new(decision.walletd_request_id());
        let outcome = match client.approve_transaction_request(&command) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.apply_client_error(&project_request_id, &error);
                return Err(error);
            }
        };

        match outcome.status() {
            WalletdEffectiveStatusV1::Approved => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Approved);
                Ok(ApprovedWalletdAnchorRequestV1::new(
                    project_request_id,
                    decision.walletd_request_id(),
                    stored_binding,
                ))
            }
            WalletdEffectiveStatusV1::Rejected => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Rejected);
                self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::ApprovalRejected,
                )
            }
            WalletdEffectiveStatusV1::Expired => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Expired);
                self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestExpired,
                )
            }
            WalletdEffectiveStatusV1::Pending
            | WalletdEffectiveStatusV1::Submitting
            | WalletdEffectiveStatusV1::Submitted => self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::UnsupportedWalletdApi {
                    detail: "approve returned a non-approval status",
                },
            ),
        }
    }

    /// Rejects a prepared request (Section F).
    ///
    /// Rejection is terminal for this adapter: a rejected request can never be
    /// approved later. Repeated rejection is deterministic and does not re-call
    /// the client.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on any binding mismatch, an
    /// unknown/approved/expired request, or a client failure.
    pub fn reject<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        decision: &WalletdDecisionRequestV1,
    ) -> Result<RejectedWalletdAnchorRequestV1, WalletdAnchorAdapterError> {
        let (stored_decision, stored_binding) = self.verify_decision(decision)?;
        let project_request_id = decision.project_request_id().clone();

        match stored_decision {
            WalletdRequestDecisionV1::Rejected => {
                // Deterministic idempotent rejection: no second client call.
                return Ok(RejectedWalletdAnchorRequestV1::new(
                    project_request_id,
                    decision.walletd_request_id(),
                    stored_binding,
                ));
            }
            WalletdRequestDecisionV1::Approved => {
                return Err(WalletdAnchorAdapterError::RequestAlreadyApproved);
            }
            WalletdRequestDecisionV1::Expired => {
                return Err(WalletdAnchorAdapterError::RequestExpired);
            }
            WalletdRequestDecisionV1::Prepared => {}
        }

        let command = WalletdDecisionCommandV1::new(decision.walletd_request_id());
        let outcome = match client.reject_transaction_request(&command) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.apply_client_error(&project_request_id, &error);
                return Err(error);
            }
        };

        match outcome.status() {
            WalletdEffectiveStatusV1::Rejected => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Rejected);
                Ok(RejectedWalletdAnchorRequestV1::new(
                    project_request_id,
                    decision.walletd_request_id(),
                    stored_binding,
                ))
            }
            WalletdEffectiveStatusV1::Approved => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Approved);
                self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestAlreadyApproved,
                )
            }
            WalletdEffectiveStatusV1::Expired => {
                self.registry
                    .set_decision(&project_request_id, WalletdRequestDecisionV1::Expired);
                self.record_and_return(
                    &project_request_id,
                    WalletdAnchorAdapterError::RequestExpired,
                )
            }
            WalletdEffectiveStatusV1::Pending
            | WalletdEffectiveStatusV1::Submitting
            | WalletdEffectiveStatusV1::Submitted => self.record_and_return(
                &project_request_id,
                WalletdAnchorAdapterError::UnsupportedWalletdApi {
                    detail: "reject returned a non-rejection status",
                },
            ),
        }
    }

    /// Reads a stored request's current status (optional read boundary).
    ///
    /// # Errors
    ///
    /// Returns [`WalletdAnchorAdapterError::RequestNotFound`] for an unknown
    /// project request, a client error, or
    /// [`WalletdAnchorAdapterError::UnsupportedWalletdApi`] if walletd unexpectedly
    /// reports a sealed transaction identifier before submission.
    pub fn query_status<C: WalletdAnchorClient>(
        &mut self,
        client: &mut C,
        project_request_id: &AnchorRequestId,
    ) -> Result<WalletdRequestStatusV1, WalletdAnchorAdapterError> {
        let Some(record) = self.registry.record(project_request_id) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };
        let walletd_request_id = record.walletd_request_id;

        let status = client.get_transaction_request(walletd_request_id)?;
        if status.has_transaction_id() {
            return Err(WalletdAnchorAdapterError::UnsupportedWalletdApi {
                detail: "status reported a transaction id before submission",
            });
        }
        Ok(status)
    }

    /// Records a client error's decision effect on the stored record.
    fn apply_client_error(
        &mut self,
        project_request_id: &AnchorRequestId,
        error: &WalletdAnchorAdapterError,
    ) {
        self.registry
            .set_diagnostic(project_request_id, error.as_str());
        match error {
            WalletdAnchorAdapterError::RequestExpired => {
                self.registry
                    .set_decision(project_request_id, WalletdRequestDecisionV1::Expired);
            }
            WalletdAnchorAdapterError::RequestAlreadyRejected => {
                self.registry
                    .set_decision(project_request_id, WalletdRequestDecisionV1::Rejected);
            }
            WalletdAnchorAdapterError::RequestAlreadyApproved => {
                self.registry
                    .set_decision(project_request_id, WalletdRequestDecisionV1::Approved);
            }
            _ => {}
        }
    }

    /// Records a diagnostic and returns the error, for any result type.
    fn record_and_return<T>(
        &mut self,
        project_request_id: &AnchorRequestId,
        error: WalletdAnchorAdapterError,
    ) -> Result<T, WalletdAnchorAdapterError> {
        self.registry
            .set_diagnostic(project_request_id, error.as_str());
        Err(error)
    }
}
