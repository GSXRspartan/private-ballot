//! Prepare / approve / reject orchestration (Sections C, E, F, G).
//!
//! [`WalletdAnchorCoordinator`] ties conversion, the narrow client boundary, and
//! the local registry together. It performs every binding check before touching
//! the client, distinguishes user rejection from API failure, and makes approval
//! and rejection distinct and terminal. It never signs, seals, submits, or
//! produces a transaction identifier, and every operation is a pure transform of
//! already-frozen commitments, so a failure at any step leaves every offline
//! election artifact unchanged.

use tari_cc_private_ballot_anchor_transport::AnchorRequestId;
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorBuildResultV1;

use crate::binding::WalletdAnchorBindingV1;
use crate::client::{WalletdAnchorClient, WalletdDecisionCommandV1, WalletdRequestStatusV1};
use crate::convert::build_walletd_create_request;
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::{WalletdRequestId, WalletdSealSignerRef};
use crate::registry::{
    LocalWalletdAnchorRegistry, WalletdAnchorSnapshotV1, WalletdRequestDecisionV1,
};
use crate::results::{
    ApprovedWalletdAnchorRequestV1, PreparedWalletdAnchorRequestV1, RejectedWalletdAnchorRequestV1,
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

/// Coordinates the offline prepare / approve / reject lifecycle over a client.
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
            outcome.expires_at(),
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
