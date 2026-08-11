//! Rust-owned voter workflow state and local canonical ballot preparation.

use serde::Serialize;
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, BallotPackageV1, BallotPackageV1Input, CandidateId,
    ElectionLifecycleStateV1,
};
use tari_cc_private_ballot_crypto::prove_tari_triptych_prototype_v1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, PROTOCOL_VERSION_V1, ValidationCode};
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::hex::{from_hex, to_lower_hex};
use crate::summary::GuiCandidateSummaryV1;
use crate::voter_credential::{
    GuiVoterCredentialSessionV1, GuiVoterCredentialStatusV1, GuiVoterEligibilityV1,
};

/// Public notice about the local-only proof workflow.
pub const PROOF_GENERATION_DEFERRED_NOTICE: &str =
    "Proof construction is local; no ballot is submitted by this application.";

/// Stable public workflow-state code derived from Rust-owned voter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GuiVoterWorkflowStateV1 {
    /// The voter must confirm the election details first.
    ReviewRequired,
    /// No Rust-side credential is loaded.
    CredentialMissing,
    /// The loaded credential is not eligible for this frozen registry.
    CredentialNotEligible,
    /// No authoritative ballot selection is loaded.
    SelectionIncomplete,
    /// Selection is valid and future proof preparation would be permitted.
    SelectionReady,
    /// A future proof operation token is active.
    PreparingProof,
    /// Future ready state. Not reachable in production in Slice 5A10A.
    PreparedBallotReady,
}

impl GuiVoterWorkflowStateV1 {
    /// Returns the stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewRequired => "ReviewRequired",
            Self::CredentialMissing => "CredentialMissing",
            Self::CredentialNotEligible => "CredentialNotEligible",
            Self::SelectionIncomplete => "SelectionIncomplete",
            Self::SelectionReady => "SelectionReady",
            Self::PreparingProof => "PreparingProof",
            Self::PreparedBallotReady => "PreparedBallotReady",
        }
    }
}

/// Public election binding used only for GUI session identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterElectionBindingV1 {
    /// Election identifier, lowercase hex.
    pub election_id_hex: String,
    /// Recomputed manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Recomputed registry commitment, lowercase hex.
    pub registry_commitment_hex: String,
    /// Recomputed candidate-set commitment, lowercase hex.
    pub candidate_set_commitment_hex: String,
}

impl GuiVoterElectionBindingV1 {
    /// Builds the binding from validated canonical artifacts.
    #[must_use]
    pub fn from_artifacts(artifacts: &GuiElectionArtifactsV1) -> Self {
        Self {
            election_id_hex: to_lower_hex(artifacts.manifest().election_id().as_bytes()),
            manifest_hash_hex: to_lower_hex(artifacts.manifest_hash().as_bytes()),
            registry_commitment_hex: to_lower_hex(artifacts.registry_commitment().as_bytes()),
            candidate_set_commitment_hex: to_lower_hex(
                artifacts.candidate_set_commitment().as_bytes(),
            ),
        }
    }
}

/// Safe status for the current validated voter selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterSelectionStatusV1 {
    /// Whether a valid authoritative selection is stored in Rust.
    pub selection_loaded: bool,
    /// Selected option machine IDs, lowercase hex, in canonical order.
    pub selected_option_ids_hex: Vec<String>,
    /// Selected display labels, in canonical machine-ID order.
    pub selected_display_labels: Vec<String>,
    /// Count of selected options.
    pub selected_count: usize,
    /// Manifest minimum approvals.
    pub approval_min: usize,
    /// Manifest maximum approvals.
    pub approval_max: usize,
    /// Whether the manifest permits an empty selection.
    pub abstention_allowed: bool,
    /// Whether the stored payload is an abstention.
    pub abstaining: bool,
    /// Whether the stored selection is valid and can feed future preparation.
    pub valid: bool,
    /// Public lifecycle state code.
    pub lifecycle_state: &'static str,
    /// Whether all Rust-side gates for future proof preparation are satisfied.
    pub can_prepare_ballot: bool,
    /// Non-secret session revision incremented on every selection change.
    pub selection_revision: u64,
    /// Bounded display message.
    pub message: &'static str,
}

impl GuiVoterSelectionStatusV1 {
    fn empty(
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        can_prepare_ballot: bool,
        selection_revision: u64,
        message: &'static str,
    ) -> Self {
        let limits = artifacts.manifest().approval_limits();
        Self {
            selection_loaded: false,
            selected_option_ids_hex: Vec::new(),
            selected_display_labels: Vec::new(),
            selected_count: 0,
            approval_min: limits.minimum(),
            approval_max: limits.maximum(),
            abstention_allowed: limits.allow_abstention(),
            abstaining: false,
            valid: false,
            lifecycle_state: lifecycle_state.as_str(),
            can_prepare_ballot,
            selection_revision,
            message,
        }
    }
}

/// Public prepared-ballot state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiPreparedBallotStatusV1 {
    /// Stable state code.
    pub state: &'static str,
    /// Current operation id while preparation is in progress.
    pub operation_id: Option<u64>,
    /// True only for a verified package while the election remains open.
    pub ready_to_export: bool,
    /// Safe public prepared-ballot details, present only after verification.
    pub summary: Option<GuiPreparedBallotSummaryV1>,
    /// Bounded display message.
    pub message: &'static str,
}

/// Safe public description of a locally verified canonical ballot package.
/// Raw proof bytes and all secret/witness material remain Rust-owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiPreparedBallotSummaryV1 {
    pub election_id_hex: String,
    pub manifest_hash_hex: String,
    pub selected_option_ids_hex: Vec<String>,
    pub selected_display_labels: Vec<String>,
    pub abstaining: bool,
    pub proof_suite_id: String,
    pub canonical_package_bytes: usize,
    pub package_digest_hex: String,
    pub locally_verified: bool,
    pub ready_to_export: bool,
}

/// Safe metadata returned after successful export and read-back verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiPreparedBallotExportV1 {
    pub canonical_package_bytes: usize,
    pub package_digest_hex: String,
}

/// Safe public summary of the whole Rust-owned voter workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterWorkflowStatusV1 {
    /// Bound election identity/fingerprint for this voter session.
    pub election_binding: GuiVoterElectionBindingV1,
    /// Public credential status. No secret fields.
    pub credential: GuiVoterCredentialStatusV1,
    /// Public selection status. No proof/nullifier/member index.
    pub selection: GuiVoterSelectionStatusV1,
    /// Public prepared-ballot status.
    pub prepared_ballot: GuiPreparedBallotStatusV1,
    /// Stable workflow state.
    pub workflow_state: GuiVoterWorkflowStateV1,
    /// Whether future proof preparation is currently allowed.
    pub can_prepare_ballot: bool,
    /// Non-secret credential generation id.
    pub credential_generation: u64,
    /// Non-secret selection revision id.
    pub selection_revision: u64,
    /// Non-secret preparation generation id.
    pub preparation_generation: u64,
    /// Fixed notice about local-only proof preparation.
    pub preparation_notice: &'static str,
}

/// Non-secret token captured before future expensive proof work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiVoterPreparationTokenV1 {
    operation_id: u64,
    election_binding: GuiVoterElectionBindingV1,
    credential_generation: u64,
    selection_revision: u64,
}

impl GuiVoterPreparationTokenV1 {
    /// Returns the non-secret operation id.
    #[must_use]
    pub const fn operation_id(&self) -> u64 {
        self.operation_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreparedBallotStateV1 {
    None,
    Preparing {
        operation_id: u64,
    },
    Invalidated {
        reason: &'static str,
    },
    Ready {
        canonical_bytes: Vec<u8>,
        summary: GuiPreparedBallotSummaryV1,
    },
    #[cfg(test)]
    TestReady {
        marker: &'static str,
    },
}

impl PreparedBallotStateV1 {
    fn status(&self, lifecycle_state: ElectionLifecycleStateV1) -> GuiPreparedBallotStatusV1 {
        match self {
            Self::None => GuiPreparedBallotStatusV1 {
                state: "None",
                operation_id: None,
                ready_to_export: false,
                summary: None,
                message: "No ballot has been prepared.",
            },
            Self::Preparing { operation_id } => GuiPreparedBallotStatusV1 {
                state: "Preparing",
                operation_id: Some(*operation_id),
                ready_to_export: false,
                summary: None,
                message: "A future proof preparation operation is in progress.",
            },
            Self::Invalidated { reason } => GuiPreparedBallotStatusV1 {
                state: "Invalidated",
                operation_id: None,
                ready_to_export: false,
                summary: None,
                message: reason,
            },
            Self::Ready { summary, .. } => GuiPreparedBallotStatusV1 {
                state: "Ready",
                operation_id: None,
                ready_to_export: matches!(lifecycle_state, ElectionLifecycleStateV1::Open),
                summary: Some(GuiPreparedBallotSummaryV1 {
                    ready_to_export: matches!(lifecycle_state, ElectionLifecycleStateV1::Open),
                    ..summary.clone()
                }),
                message: if matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
                    "Canonical ballot package is locally verified and ready to export."
                } else {
                    "Election is no longer open; this prepared ballot is not exportable."
                },
            },
            #[cfg(test)]
            Self::TestReady { .. } => GuiPreparedBallotStatusV1 {
                state: "TestReady",
                operation_id: None,
                ready_to_export: false,
                summary: None,
                message: "Synthetic non-crypto marker installed by a test.",
            },
        }
    }

    const fn is_preparing(&self) -> bool {
        matches!(self, Self::Preparing { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuiVoterBallotSelectionV1 {
    payload: ApprovalBallotPayload,
}

impl GuiVoterBallotSelectionV1 {
    fn status(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        can_prepare_ballot: bool,
        selection_revision: u64,
    ) -> GuiVoterSelectionStatusV1 {
        let limits = artifacts.manifest().approval_limits();
        let selected_option_ids_hex: Vec<String> = self
            .payload
            .selections()
            .iter()
            .map(|id| to_lower_hex(id.as_bytes()))
            .collect();
        let selected_display_labels = self
            .payload
            .selections()
            .iter()
            .filter_map(|id| {
                artifacts
                    .candidates()
                    .candidates()
                    .iter()
                    .find(|candidate| candidate.id() == id)
                    .map(|candidate| candidate.display_name().to_owned())
            })
            .collect();

        GuiVoterSelectionStatusV1 {
            selection_loaded: true,
            selected_count: selected_option_ids_hex.len(),
            selected_option_ids_hex,
            selected_display_labels,
            approval_min: limits.minimum(),
            approval_max: limits.maximum(),
            abstention_allowed: limits.allow_abstention(),
            abstaining: self.payload.is_abstention(),
            valid: true,
            lifecycle_state: lifecycle_state.as_str(),
            can_prepare_ballot,
            selection_revision,
            message: "Selection is valid.",
        }
    }
}

/// One Rust-owned voter workflow session bound to the active election.
#[derive(Debug)]
pub struct GuiVoterSessionV1 {
    election_binding: GuiVoterElectionBindingV1,
    credential: Option<GuiVoterCredentialSessionV1>,
    selection: Option<GuiVoterBallotSelectionV1>,
    credential_generation: u64,
    selection_revision: u64,
    preparation_generation: u64,
    prepared_ballot: PreparedBallotStateV1,
}

impl GuiVoterSessionV1 {
    /// Creates a fresh voter session bound to the loaded election.
    #[must_use]
    pub fn new(artifacts: &GuiElectionArtifactsV1) -> Self {
        Self {
            election_binding: GuiVoterElectionBindingV1::from_artifacts(artifacts),
            credential: None,
            selection: None,
            credential_generation: 0,
            selection_revision: 0,
            preparation_generation: 0,
            prepared_ballot: PreparedBallotStateV1::None,
        }
    }

    /// Installs a Rust-owned pending credential after binding it to the
    /// currently loaded frozen registry. The credential never crosses a DTO.
    pub fn install_credential(
        &mut self,
        credential: crate::voter_credential::VoterGovernanceCredentialV1,
        artifacts: &GuiElectionArtifactsV1,
    ) -> Result<GuiVoterCredentialStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let credential = GuiVoterCredentialSessionV1::from_credential(
            credential,
            crate::voter_credential::GuiVoterCredentialOriginV1::Generated,
            artifacts.registry(),
        )?;
        let status = credential.status();
        self.credential = Some(credential);
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Credential changed; prepared ballot state was cleared.");
        Ok(status)
    }

    /// Returns the private credential to the shell-owned pending slot when an
    /// election is unloaded. This preserves the current-process bootstrap
    /// workflow without retaining any election-specific eligibility state.
    pub fn take_credential(&mut self) -> Option<crate::voter_credential::VoterGovernanceCredentialV1> {
        let credential = self.credential.take()?.into_credential();
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Election changed; prepared ballot state was cleared.");
        Some(credential)
    }

    /// Returns whether this session still belongs to the supplied artifacts.
    #[must_use]
    pub fn is_bound_to(&self, artifacts: &GuiElectionArtifactsV1) -> bool {
        self.election_binding == GuiVoterElectionBindingV1::from_artifacts(artifacts)
    }

    /// Generates/replaces the Rust-only credential and invalidates prepared
    /// state. The existing selection remains because it is public and
    /// credential-independent.
    pub fn generate_credential(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
    ) -> Result<GuiVoterCredentialStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let credential = GuiVoterCredentialSessionV1::generate_for(artifacts)?;
        let status = credential.status();
        self.credential = Some(credential);
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Credential changed; prepared ballot state was cleared.");
        Ok(status)
    }

    /// Clears the Rust-only credential and invalidates prepared state. The
    /// selection remains for UX because it carries no credential-dependent
    /// state.
    #[must_use]
    pub fn reset_credential(&mut self) -> GuiVoterCredentialStatusV1 {
        self.credential = None;
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Credential reset; prepared ballot state was cleared.");
        GuiVoterCredentialStatusV1::unloaded()
    }

    /// Clears credential, selection, prepared state, and all active operation
    /// tokens for this election-bound voter workflow.
    pub fn reset_workflow(&mut self) {
        self.credential = None;
        self.selection = None;
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.selection_revision = self.selection_revision.saturating_add(1);
        self.invalidate_prepared("Voter workflow reset; prepared ballot state was cleared.");
    }

    /// Validates and stores one authoritative voter selection.
    pub fn set_selection(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        selected_option_ids_hex: Vec<String>,
        abstain: bool,
    ) -> Result<GuiVoterSelectionStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        if abstain && !selected_option_ids_hex.is_empty() {
            return Err(GuiCoreError::new(
                "GUI_ABSTENTION_WITH_SELECTIONS",
                GuiErrorCategory::InvalidInput,
                Some("selection"),
                "abstention cannot be combined with selected options",
            ));
        }

        let mut selected = Vec::with_capacity(selected_option_ids_hex.len());
        for hex in selected_option_ids_hex {
            let Some(bytes) = from_hex(&hex) else {
                return Err(GuiCoreError::malformed_hex_input());
            };
            let id = CandidateId::new(bytes)
                .map_err(|error| GuiCoreError::from_protocol(&error, "selection"))?;
            selected.push(id);
        }

        let payload = ApprovalBallotPayload::new(
            selected,
            artifacts.candidates(),
            artifacts.manifest().approval_limits(),
        )
        .map_err(|error| GuiCoreError::from_protocol(&error, "selection"))?;

        self.selection = Some(GuiVoterBallotSelectionV1 { payload });
        self.selection_revision = self.selection_revision.saturating_add(1);
        self.invalidate_prepared("Selection changed; prepared ballot state was cleared.");
        Ok(self.selection_status(artifacts, lifecycle_state))
    }

    /// Clears the current selection and invalidates prepared state.
    pub fn clear_selection(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiVoterSelectionStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.selection = None;
        self.selection_revision = self.selection_revision.saturating_add(1);
        self.invalidate_prepared("Selection cleared; prepared ballot state was cleared.");
        Ok(self.selection_status(artifacts, lifecycle_state))
    }

    /// Returns the public credential status only.
    #[must_use]
    pub fn credential_status(&self) -> GuiVoterCredentialStatusV1 {
        self.credential
            .as_ref()
            .map(GuiVoterCredentialSessionV1::status)
            .unwrap_or_else(GuiVoterCredentialStatusV1::unloaded)
    }

    /// Returns the public selection status only.
    #[must_use]
    pub fn selection_status(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> GuiVoterSelectionStatusV1 {
        let can_prepare_ballot = self.can_prepare_ballot(lifecycle_state);
        match self.selection.as_ref() {
            Some(selection) => selection.status(
                artifacts,
                lifecycle_state,
                can_prepare_ballot,
                self.selection_revision,
            ),
            None => GuiVoterSelectionStatusV1::empty(
                artifacts,
                lifecycle_state,
                can_prepare_ballot,
                self.selection_revision,
                "No ballot selection is loaded.",
            ),
        }
    }

    /// Returns a complete safe public workflow status.
    #[must_use]
    pub fn workflow_status(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        review_confirmed: bool,
    ) -> GuiVoterWorkflowStatusV1 {
        let credential = self.credential_status();
        let selection = self.selection_status(artifacts, lifecycle_state);
        let can_prepare_ballot = self.can_prepare_ballot(lifecycle_state);
        let workflow_state = self.workflow_state(review_confirmed, lifecycle_state);
        GuiVoterWorkflowStatusV1 {
            election_binding: self.election_binding.clone(),
            credential,
            selection,
            prepared_ballot: self.prepared_ballot.status(lifecycle_state),
            workflow_state,
            can_prepare_ballot,
            credential_generation: self.credential_generation,
            selection_revision: self.selection_revision,
            preparation_generation: self.preparation_generation,
            preparation_notice: PROOF_GENERATION_DEFERRED_NOTICE,
        }
    }

    /// Starts a synthetic preparation operation token for architecture tests
    /// and future 5A10B ownership flow. No proof work is performed here.
    pub fn begin_preparation_operation(
        &mut self,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiVoterPreparationTokenV1, GuiCoreError> {
        if !self.can_prepare_ballot(lifecycle_state) {
            return Err(GuiCoreError::new(
                ValidationCode::ElectionNotOpen.as_str(),
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("prepare-ballot"),
                "ballot preparation requires an open election, eligible credential, and valid selection",
            ));
        }
        self.preparation_generation = self.preparation_generation.saturating_add(1);
        let operation_id = self.preparation_generation;
        self.prepared_ballot = PreparedBallotStateV1::Preparing { operation_id };
        Ok(GuiVoterPreparationTokenV1 {
            operation_id,
            election_binding: self.election_binding.clone(),
            credential_generation: self.credential_generation,
            selection_revision: self.selection_revision,
        })
    }

    /// Marks lifecycle-related prepared state invalid when voting closes or
    /// advances past the future proof gate.
    pub fn invalidate_for_lifecycle_change(&mut self, lifecycle_state: ElectionLifecycleStateV1) {
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open)
            && self.prepared_ballot.is_preparing()
        {
            self.invalidate_prepared("Lifecycle changed; prepared ballot state was cleared.");
        }
    }

    /// Constructs, encodes, decodes, and independently verifies one real
    /// Triptych ballot package. The caller holds the voter-session mutex for
    /// this whole method, so the credential is borrowed without cloning.
    pub fn prepare_ballot(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiPreparedBallotStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let token = self.begin_preparation_operation(lifecycle_state)?;
        let result = (|| {
            let credential = self.credential.as_ref().ok_or_else(|| {
                GuiCoreError::new(
                    "GUI_NO_VOTER_CREDENTIAL",
                    GuiErrorCategory::InvalidInput,
                    Some("prepare-ballot"),
                    "a voter credential is required before preparing a ballot",
                )
            })?;
            let selection = self.selection.as_ref().ok_or_else(|| {
                GuiCoreError::new(
                    "GUI_NO_BALLOT_SELECTION",
                    GuiErrorCategory::InvalidInput,
                    Some("prepare-ballot"),
                    "a valid ballot selection is required before preparing a ballot",
                )
            })?;
            let provider = Blake3HashProviderV1;
            let verifier =
                build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
                    .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
            let statement = reconstruct_approval_proof_statement(
                artifacts.manifest(),
                &selection.payload,
                &provider,
            )
            .map_err(|error| GuiCoreError::from_protocol(&error, "proof-statement"))?;
            let proof = prove_tari_triptych_prototype_v1(
                &statement,
                &verifier,
                credential.credential().secret_key(),
            )
            .map_err(|error| GuiCoreError::from_protocol(&error, "proof"))?;
            let package = BallotPackageV1::new(BallotPackageV1Input {
                protocol_version: PROTOCOL_VERSION_V1,
                manifest_hash: artifacts.manifest_hash(),
                proof_suite_id: artifacts.manifest().proof_suite_id().to_owned(),
                proof,
                payload: selection.payload.clone(),
            })
            .map_err(|error| GuiCoreError::from_protocol(&error, "ballot-package"))?;
            let canonical_bytes = package
                .to_canonical_cbor()
                .map_err(|error| GuiCoreError::from_protocol(&error, "ballot-package"))?;
            let decoded = BallotPackageV1::from_canonical_cbor(
                &canonical_bytes,
                artifacts.candidates(),
                artifacts.manifest().approval_limits(),
            )
            .map_err(|error| GuiCoreError::from_protocol(&error, "ballot-package"))?;
            decoded
                .validate_manifest_binding(
                    artifacts.manifest_hash(),
                    artifacts.manifest().proof_suite_id(),
                )
                .map_err(|error| GuiCoreError::from_protocol(&error, "ballot-package"))?;
            verify_approval_proof(
                artifacts.manifest(),
                decoded.payload(),
                decoded.proof(),
                &provider,
                &verifier,
            )
            .map_err(|error| GuiCoreError::from_protocol(&error, "proof"))?;
            let digest = decoded
                .canonical_hash(&provider)
                .map_err(|error| GuiCoreError::from_protocol(&error, "ballot-package"))?;
            let selection_status =
                selection.status(artifacts, lifecycle_state, true, self.selection_revision);
            Ok::<_, GuiCoreError>((
                canonical_bytes.clone(),
                GuiPreparedBallotSummaryV1 {
                    election_id_hex: self.election_binding.election_id_hex.clone(),
                    manifest_hash_hex: self.election_binding.manifest_hash_hex.clone(),
                    selected_option_ids_hex: selection_status.selected_option_ids_hex,
                    selected_display_labels: selection_status.selected_display_labels,
                    abstaining: selection.payload.is_abstention(),
                    proof_suite_id: artifacts.manifest().proof_suite_id().to_owned(),
                    canonical_package_bytes: canonical_bytes.len(),
                    package_digest_hex: to_lower_hex(&digest),
                    locally_verified: true,
                    ready_to_export: true,
                },
            ))
        })();
        match result {
            Ok((canonical_bytes, summary)) if self.matches_token(lifecycle_state, &token) => {
                self.prepared_ballot = PreparedBallotStateV1::Ready {
                    canonical_bytes,
                    summary,
                };
                Ok(self.prepared_ballot.status(lifecycle_state))
            }
            Ok(_) => {
                self.invalidate_prepared(
                    "Prepared ballot became stale before it could be installed.",
                );
                Err(GuiCoreError::new(
                    "GUI_STALE_PREPARATION",
                    GuiErrorCategory::InvalidLifecycleTransition,
                    Some("prepare-ballot"),
                    "the ballot preparation result is no longer current",
                ))
            }
            Err(error) => {
                self.invalidate_prepared(
                    "Ballot preparation failed; no prepared ballot is available.",
                );
                Err(error)
            }
        }
    }

    /// Writes a verified package without overwrite, then verifies exact bytes
    /// read back from disk through the existing verifier path.
    pub fn export_prepared_ballot(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        path: &std::path::Path,
    ) -> Result<GuiPreparedBallotExportV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            return Err(GuiCoreError::new(
                "GUI_PREPARED_BALLOT_NOT_EXPORTABLE",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("export-ballot"),
                "a prepared ballot can be exported only while the election is open",
            ));
        }
        let PreparedBallotStateV1::Ready {
            canonical_bytes,
            summary,
        } = &self.prepared_ballot
        else {
            return Err(GuiCoreError::new(
                "GUI_NO_PREPARED_BALLOT",
                GuiErrorCategory::InvalidInput,
                Some("export-ballot"),
                "no locally verified ballot package is available",
            ));
        };
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    GuiCoreError::new(
                        "GUI_BALLOT_EXPORT_COLLISION",
                        GuiErrorCategory::FileIo,
                        Some("export-ballot"),
                        "For safety, ballot exports never overwrite an existing file. Choose a new filename.",
                    )
                } else {
                    GuiCoreError::io_failure("export-ballot")
                }
            })?;
        file.write_all(canonical_bytes)
            .map_err(|_| GuiCoreError::io_failure("export-ballot"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("export-ballot"))?;
        let read_back =
            std::fs::read(path).map_err(|_| GuiCoreError::io_failure("export-ballot"))?;
        if read_back != *canonical_bytes {
            return Err(GuiCoreError::new(
                "GUI_BALLOT_EXPORT_READBACK_FAILED",
                GuiErrorCategory::FileIo,
                Some("export-ballot"),
                "ballot package read-back did not match the prepared bytes",
            ));
        }
        let provider = Blake3HashProviderV1;
        let verifier =
            build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
                .map_err(|_| {
                    GuiCoreError::new(
                        "GUI_BALLOT_EXPORT_READBACK_FAILED",
                        GuiErrorCategory::ProofFailure,
                        Some("export-ballot"),
                        "ballot package read-back verification failed",
                    )
                })?;
        let package = BallotPackageV1::from_canonical_cbor(
            &read_back,
            artifacts.candidates(),
            artifacts.manifest().approval_limits(),
        )
        .map_err(|_| {
            GuiCoreError::new(
                "GUI_BALLOT_EXPORT_READBACK_FAILED",
                GuiErrorCategory::ProofFailure,
                Some("export-ballot"),
                "ballot package read-back verification failed",
            )
        })?;
        verify_approval_proof(
            artifacts.manifest(),
            package.payload(),
            package.proof(),
            &provider,
            &verifier,
        )
        .map_err(|_| {
            GuiCoreError::new(
                "GUI_BALLOT_EXPORT_READBACK_FAILED",
                GuiErrorCategory::ProofFailure,
                Some("export-ballot"),
                "ballot package read-back verification failed",
            )
        })?;
        Ok(GuiPreparedBallotExportV1 {
            canonical_package_bytes: read_back.len(),
            package_digest_hex: summary.package_digest_hex.clone(),
        })
    }

    /// Borrows the exact, locally verified canonical ballot bytes while the
    /// election remains open. This is intentionally Rust-only: callers may
    /// pass the bytes to an authenticated transport coordinator, but must not
    /// serialize them through a frontend boundary or reconstruct a package.
    pub fn prepared_canonical_ballot_bytes(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<&[u8], GuiCoreError> {
        self.ensure_bound(artifacts)?;
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            return Err(GuiCoreError::new(
                "GUI_PREPARED_BALLOT_NOT_SUBMITTABLE",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("submit-ballot"),
                "a prepared ballot can be submitted only while the election is open",
            ));
        }
        let PreparedBallotStateV1::Ready { canonical_bytes, .. } = &self.prepared_ballot else {
            return Err(GuiCoreError::new(
                "GUI_NO_PREPARED_BALLOT",
                GuiErrorCategory::InvalidInput,
                Some("submit-ballot"),
                "no locally verified ballot package is available",
            ));
        };
        Ok(canonical_bytes)
    }

    #[cfg(test)]
    pub fn install_test_prepared_marker(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        token: &GuiVoterPreparationTokenV1,
        marker: &'static str,
    ) -> Result<bool, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        if self.matches_token(lifecycle_state, token) {
            self.prepared_ballot = PreparedBallotStateV1::TestReady { marker };
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn ensure_bound(&self, artifacts: &GuiElectionArtifactsV1) -> Result<(), GuiCoreError> {
        if self.is_bound_to(artifacts) {
            Ok(())
        } else {
            Err(GuiCoreError::new(
                "GUI_VOTER_SESSION_ELECTION_MISMATCH",
                GuiErrorCategory::BindingMismatch,
                Some("voter-session"),
                "voter session belongs to a different loaded election",
            ))
        }
    }

    fn workflow_state(
        &self,
        review_confirmed: bool,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> GuiVoterWorkflowStateV1 {
        if !review_confirmed {
            return GuiVoterWorkflowStateV1::ReviewRequired;
        }
        match self.credential_status().eligibility {
            GuiVoterEligibilityV1::NotChecked => GuiVoterWorkflowStateV1::CredentialMissing,
            GuiVoterEligibilityV1::NotEligible => GuiVoterWorkflowStateV1::CredentialNotEligible,
            GuiVoterEligibilityV1::Eligible => {
                if self.selection.is_none() {
                    GuiVoterWorkflowStateV1::SelectionIncomplete
                } else if self.prepared_ballot.is_preparing() {
                    GuiVoterWorkflowStateV1::PreparingProof
                } else if matches!(self.prepared_ballot, PreparedBallotStateV1::Ready { .. }) {
                    GuiVoterWorkflowStateV1::PreparedBallotReady
                } else if self.can_prepare_ballot(lifecycle_state) {
                    GuiVoterWorkflowStateV1::SelectionReady
                } else {
                    GuiVoterWorkflowStateV1::SelectionIncomplete
                }
            }
        }
    }

    fn can_prepare_ballot(&self, lifecycle_state: ElectionLifecycleStateV1) -> bool {
        matches!(lifecycle_state, ElectionLifecycleStateV1::Open)
            && matches!(
                self.credential_status().eligibility,
                GuiVoterEligibilityV1::Eligible
            )
            && self.selection.is_some()
    }

    fn matches_token(
        &self,
        lifecycle_state: ElectionLifecycleStateV1,
        token: &GuiVoterPreparationTokenV1,
    ) -> bool {
        matches!(lifecycle_state, ElectionLifecycleStateV1::Open)
            && self.prepared_ballot
                == PreparedBallotStateV1::Preparing {
                    operation_id: token.operation_id,
                }
            && self.election_binding == token.election_binding
            && self.credential_generation == token.credential_generation
            && self.selection_revision == token.selection_revision
            && self.preparation_generation == token.operation_id
    }

    fn invalidate_prepared(&mut self, reason: &'static str) {
        self.preparation_generation = self.preparation_generation.saturating_add(1);
        self.prepared_ballot = PreparedBallotStateV1::Invalidated { reason };
    }
}

/// Returns candidate summaries in canonical order for frontend selection.
#[must_use]
pub fn voter_selectable_options(artifacts: &GuiElectionArtifactsV1) -> Vec<GuiCandidateSummaryV1> {
    artifacts
        .candidates()
        .candidates()
        .iter()
        .map(|candidate| {
            let id_bytes = candidate.id().as_bytes();
            GuiCandidateSummaryV1 {
                machine_id_hex: to_lower_hex(id_bytes),
                machine_id_text: core::str::from_utf8(id_bytes).ok().map(str::to_owned),
                display_name: candidate.display_name().to_owned(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use serde_json::Value;
    use tari_cc_private_ballot_ballot::{
        ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateSet,
        ElectionId, ElectionManifestV1, ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
    use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, PROTOCOL_VERSION_V1};
    use tari_cc_private_ballot_registry::RegistrySnapshot;

    use crate::voter_credential::{GuiVoterCredentialOriginV1, VoterGovernanceCredentialV1};

    #[test]
    fn valid_single_selection_is_stored() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = GuiVoterSessionV1::new(&artifacts);

        let status = ok(session.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![hex_id(b"candidate-a")],
            false,
        ));

        assert!(status.valid);
        assert_eq!(status.selected_option_ids_hex, vec![hex_id(b"candidate-a")]);
        assert!(!status.abstaining);
    }

    #[test]
    fn valid_multiple_selection_is_sorted_canonically() {
        let artifacts = artifacts(false, limits(1, 3, false), b"election-a");
        let mut session = GuiVoterSessionV1::new(&artifacts);

        let status = ok(session.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![hex_id(b"candidate-c"), hex_id(b"candidate-a")],
            false,
        ));

        assert_eq!(
            status.selected_option_ids_hex,
            vec![hex_id(b"candidate-a"), hex_id(b"candidate-c")]
        );
    }

    #[test]
    fn unknown_duplicate_below_min_and_above_max_are_rejected() {
        let artifacts = artifacts(false, limits(2, 2, false), b"election-a");
        let mut session = GuiVoterSessionV1::new(&artifacts);

        assert_code(
            session.set_selection(
                &artifacts,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-z")],
                false,
            ),
            ValidationCode::SelectionCountOutOfRange.as_str(),
        );
        assert_code(
            session.set_selection(
                &artifacts,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-a"), hex_id(b"candidate-a")],
                false,
            ),
            ValidationCode::DuplicateSelection.as_str(),
        );
        assert_code(
            session.set_selection(
                &artifacts,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-a")],
                false,
            ),
            ValidationCode::SelectionCountOutOfRange.as_str(),
        );
        assert_code(
            session.set_selection(
                &artifacts,
                ElectionLifecycleStateV1::Open,
                vec![
                    hex_id(b"candidate-a"),
                    hex_id(b"candidate-b"),
                    hex_id(b"candidate-c"),
                ],
                false,
            ),
            ValidationCode::SelectionCountOutOfRange.as_str(),
        );
    }

    #[test]
    fn unknown_option_rejected_when_count_is_in_range() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = GuiVoterSessionV1::new(&artifacts);

        assert_code(
            session.set_selection(
                &artifacts,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-z")],
                false,
            ),
            ValidationCode::UnknownCandidateId.as_str(),
        );
    }

    #[test]
    fn abstention_rules_follow_canonical_payload_semantics() {
        let allowed = artifacts(true, limits(1, 2, true), b"election-a");
        let forbidden = artifacts(false, limits(1, 2, false), b"election-a");
        let mut allowed_session = GuiVoterSessionV1::new(&allowed);
        let mut forbidden_session = GuiVoterSessionV1::new(&forbidden);

        let status = ok(allowed_session.set_selection(
            &allowed,
            ElectionLifecycleStateV1::Open,
            Vec::new(),
            true,
        ));
        assert!(status.abstaining);
        assert_code(
            forbidden_session.set_selection(
                &forbidden,
                ElectionLifecycleStateV1::Open,
                Vec::new(),
                true,
            ),
            ValidationCode::SelectionCountOutOfRange.as_str(),
        );
        assert_code(
            allowed_session.set_selection(
                &allowed,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-a")],
                true,
            ),
            "GUI_ABSTENTION_WITH_SELECTIONS",
        );
    }

    #[test]
    fn election_change_rejects_old_session_and_new_session_starts_clear() {
        let first = artifacts(false, limits(1, 2, false), b"election-a");
        let second = artifacts(false, limits(1, 2, false), b"election-b");
        let mut session = GuiVoterSessionV1::new(&first);
        assert!(
            session
                .set_selection(
                    &first,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );

        assert_code(
            session.set_selection(
                &second,
                ElectionLifecycleStateV1::Open,
                vec![hex_id(b"candidate-a")],
                false,
            ),
            "GUI_VOTER_SESSION_ELECTION_MISMATCH",
        );
        let second_session = GuiVoterSessionV1::new(&second);
        assert!(
            !second_session
                .selection_status(&second, ElectionLifecycleStateV1::Open)
                .selection_loaded
        );
    }

    #[test]
    fn set_selection_reports_frozen_lifecycle_without_prepare_readiness() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);

        let status = ok(select_candidate_a(
            &mut session,
            &artifacts,
            ElectionLifecycleStateV1::Frozen,
        ));

        assert!(status.selection_loaded);
        assert_eq!(
            status.lifecycle_state,
            ElectionLifecycleStateV1::Frozen.as_str()
        );
        assert!(!status.can_prepare_ballot);
    }

    #[test]
    fn set_selection_reports_open_lifecycle_and_prepare_readiness() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);

        let status = ok(select_candidate_a(
            &mut session,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));

        assert_eq!(
            status.lifecycle_state,
            ElectionLifecycleStateV1::Open.as_str()
        );
        assert!(status.can_prepare_ballot);
    }

    #[test]
    fn set_selection_reports_closed_lifecycle_without_prepare_readiness() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);

        let status = ok(select_candidate_a(
            &mut session,
            &artifacts,
            ElectionLifecycleStateV1::Closed,
        ));

        assert!(status.selection_loaded);
        assert_eq!(
            status.lifecycle_state,
            ElectionLifecycleStateV1::Closed.as_str()
        );
        assert!(!status.can_prepare_ballot);
    }

    #[test]
    fn set_selection_never_fabricates_open_lifecycle() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        for lifecycle_state in [
            ElectionLifecycleStateV1::Frozen,
            ElectionLifecycleStateV1::Closed,
            ElectionLifecycleStateV1::Verified,
            ElectionLifecycleStateV1::Finalized,
        ] {
            let mut session = eligible_session(&artifacts);
            let status = ok(select_candidate_a(
                &mut session,
                &artifacts,
                lifecycle_state,
            ));

            assert_eq!(status.lifecycle_state, lifecycle_state.as_str());
            assert_ne!(
                status.lifecycle_state,
                ElectionLifecycleStateV1::Open.as_str()
            );
            assert!(!status.can_prepare_ballot);
        }
    }

    #[test]
    fn reset_paths_clear_or_invalidate_state_deliberately() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));

        let old_generation = session.credential_generation;
        let _status = session.reset_credential();
        assert!(session.selection.is_some());
        assert!(session.credential_generation > old_generation);
        assert!(!ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &token,
            "old",
        )));

        session.reset_workflow();
        assert!(session.selection.is_none());
        assert!(session.credential.is_none());
    }

    #[test]
    fn selection_change_rejects_stale_operation_result() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));

        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-b")],
                    false,
                )
                .is_ok()
        );

        assert!(!ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &token,
            "old",
        )));
    }

    #[test]
    fn competing_preparation_operation_rejects_first_token_as_stale() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            select_candidate_a(&mut session, &artifacts, ElectionLifecycleStateV1::Open).is_ok()
        );

        let first = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));
        let second = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));

        assert_ne!(first.operation_id(), second.operation_id());
        assert!(!ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &first,
            "first",
        )));
        assert!(ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &second,
            "second",
        )));
        let PreparedBallotStateV1::TestReady { marker } = session.prepared_ballot else {
            panic!("second token should install test marker");
        };
        assert_eq!(marker, "second");
    }

    #[test]
    fn begin_preparation_operation_rejects_missing_or_invalid_gates() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut no_credential = GuiVoterSessionV1::new(&artifacts);
        ok(select_candidate_a(
            &mut no_credential,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));
        assert_code(
            no_credential.begin_preparation_operation(ElectionLifecycleStateV1::Open),
            ValidationCode::ElectionNotOpen.as_str(),
        );

        let mut not_eligible = ineligible_session(&artifacts);
        ok(select_candidate_a(
            &mut not_eligible,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));
        assert_code(
            not_eligible.begin_preparation_operation(ElectionLifecycleStateV1::Open),
            ValidationCode::ElectionNotOpen.as_str(),
        );

        let mut no_selection = eligible_session(&artifacts);
        assert_code(
            no_selection.begin_preparation_operation(ElectionLifecycleStateV1::Open),
            ValidationCode::ElectionNotOpen.as_str(),
        );

        for lifecycle_state in [
            ElectionLifecycleStateV1::Frozen,
            ElectionLifecycleStateV1::Closed,
            ElectionLifecycleStateV1::Verified,
            ElectionLifecycleStateV1::Finalized,
        ] {
            let mut session = eligible_session(&artifacts);
            ok(select_candidate_a(
                &mut session,
                &artifacts,
                ElectionLifecycleStateV1::Open,
            ));
            assert_code(
                session.begin_preparation_operation(lifecycle_state),
                ValidationCode::ElectionNotOpen.as_str(),
            );
        }
    }

    #[test]
    fn current_matching_operation_token_can_install_test_marker_only() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));

        assert!(ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &token,
            "ready",
        )));
        let PreparedBallotStateV1::TestReady { marker } = session.prepared_ballot else {
            panic!("test marker should install");
        };
        assert_eq!(marker, "ready");
    }

    #[test]
    fn lifecycle_change_rejects_future_preparation_result() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));

        session.invalidate_for_lifecycle_change(ElectionLifecycleStateV1::Closed);

        assert!(!ok(session.install_test_prepared_marker(
            &artifacts,
            ElectionLifecycleStateV1::Closed,
            &token,
            "old",
        )));
    }

    #[test]
    fn eligible_credential_selection_and_real_proof_prepare_a_verified_package() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        ok(select_candidate_a(
            &mut session,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));

        let prepared = ok(session.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open));
        let summary = match prepared.summary {
            Some(summary) => summary,
            None => panic!("real proof preparation must return a safe summary"),
        };

        assert_eq!(prepared.state, "Ready");
        assert!(prepared.ready_to_export);
        assert!(summary.locally_verified);
        assert_eq!(
            summary.selected_option_ids_hex,
            vec![hex_id(b"candidate-a")]
        );
        let json = match serde_json::to_string(&summary) {
            Ok(json) => json,
            Err(_) => panic!("prepared summary must serialize"),
        };
        assert!(!json.contains("linkability"));
    }

    #[test]
    fn generated_credential_prepares_exports_and_intakes_once() {
        let credential = ok(VoterGovernanceCredentialV1::generate());
        let public_key = ok(credential.public_key_bytes());
        let registry = registry_from_keys(&[public_key]);
        let artifacts = artifacts_for_registry(registry, limits(1, 2, false), b"bridge-election");
        let mut voter = GuiVoterSessionV1::new(&artifacts);
        let status = ok(voter.install_credential(credential, &artifacts));
        assert_eq!(status.eligibility, GuiVoterEligibilityV1::Eligible);
        ok(select_candidate_a(
            &mut voter,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));
        let prepared = ok(voter.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open));
        assert!(prepared.ready_to_export);

        let path = std::env::temp_dir().join(format!(
            "tari-cc-private-ballot-5a10b-{}.cbor",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let exported =
            ok(voter.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &path));
        let bytes = ok(std::fs::read(&path));
        assert_eq!(bytes.len(), exported.canonical_package_bytes);
        assert!(
            BallotPackageV1::from_canonical_cbor(
                &bytes,
                artifacts.candidates(),
                artifacts.manifest().approval_limits(),
            )
            .is_ok()
        );

        let mut organizer = ok(crate::session::GuiElectionSessionV1::new(artifacts.clone()));
        ok(organizer.open());
        assert!(ok(organizer.intake_ballot(&bytes)).accepted);
        let duplicate = ok(organizer.intake_ballot(&bytes));
        assert!(!duplicate.accepted);
        assert_eq!(duplicate.code, "DUPLICATE_BALLOT");
        // The public status is redacted, but the authoritative ledger and
        // transcript still record one acceptance and one duplicate rejection.
        assert_eq!(organizer.accepted_count(), 1);
        assert_eq!(organizer.transcript().accepted_count(), 1);
        assert_eq!(organizer.transcript().rejected_count(), 1);

        let mut altered = bytes.clone();
        let last = altered.len().saturating_sub(1);
        altered[last] ^= 0x01;
        let mut mutated_organizer = ok(crate::session::GuiElectionSessionV1::new(artifacts));
        ok(mutated_organizer.open());
        assert!(!ok(mutated_organizer.intake_ballot(&altered)).accepted);
        ok(std::fs::remove_file(path));
    }

    #[test]
    fn safe_dtos_contain_no_secret_or_member_index_fields() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );

        let status = session.workflow_status(&artifacts, ElectionLifecycleStateV1::Open, true);
        let json = ok_json(serde_json::to_value(&status));
        let rendered = json.to_string().to_lowercase();
        let secret_hex = to_lower_hex(&Scalar::from(7_u64).to_bytes());
        assert!(!rendered.contains(&secret_hex));
        let object = match json.as_object() {
            Some(object) => object,
            None => panic!("workflow status should serialize as object"),
        };
        for marker in [
            "secret",
            "scalar",
            "seed",
            "mnemonic",
            "private",
            "credential_bytes",
            "wallet_seed",
            "registry_index",
            "member_index",
            "nullifier",
            "proof",
        ] {
            for field in object.keys() {
                assert!(
                    !field.to_lowercase().contains(marker),
                    "DTO field leaked marker {marker}: {field}"
                );
            }
        }
    }

    #[test]
    fn operation_token_contains_no_secret_derived_material() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        assert!(
            session
                .set_selection(
                    &artifacts,
                    ElectionLifecycleStateV1::Open,
                    vec![hex_id(b"candidate-a")],
                    false,
                )
                .is_ok()
        );
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));
        let rendered = format!("{token:?}").to_lowercase();

        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("scalar"));
        assert_eq!(token.operation_id(), session.preparation_generation);
    }

    fn eligible_session(artifacts: &GuiElectionArtifactsV1) -> GuiVoterSessionV1 {
        credential_session(artifacts, 7)
    }

    fn ineligible_session(artifacts: &GuiElectionArtifactsV1) -> GuiVoterSessionV1 {
        credential_session(artifacts, 5)
    }

    fn credential_session(artifacts: &GuiElectionArtifactsV1, scalar: u64) -> GuiVoterSessionV1 {
        let mut session = GuiVoterSessionV1::new(artifacts);
        let credential = ok(VoterGovernanceCredentialV1::from_test_canonical_scalar(
            Scalar::from(scalar).to_bytes(),
        ));
        let credential_session = ok(GuiVoterCredentialSessionV1::from_credential(
            credential,
            GuiVoterCredentialOriginV1::Generated,
            artifacts.registry(),
        ));
        session.credential = Some(credential_session);
        session.credential_generation = 1;
        session
    }

    fn select_candidate_a(
        session: &mut GuiVoterSessionV1,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiVoterSelectionStatusV1, GuiCoreError> {
        session.set_selection(
            artifacts,
            lifecycle_state,
            vec![hex_id(b"candidate-a")],
            false,
        )
    }

    fn artifacts(
        _abstention: bool,
        approval_limits: ApprovalLimits,
        election_id: &[u8],
    ) -> GuiElectionArtifactsV1 {
        let provider = Blake3HashProviderV1;
        let registry = registry();
        let candidates = candidates();
        let registry_commitment = ok(registry.canonical_commitment(&provider));
        let candidate_set_commitment = ok(candidates.canonical_commitment(&provider));
        let manifest = ok(ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: ok(ElectionId::new(election_id.to_vec())),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits,
            governance_source_revision: "voter-session-test".to_owned(),
        }));
        let manifest_bytes = ok(manifest.to_canonical_cbor());
        let registry_bytes = ok(registry.to_canonical_cbor());
        let candidate_bytes = ok(candidates.to_canonical_cbor());
        ok(GuiElectionArtifactsV1::from_bytes(
            &manifest_bytes,
            &registry_bytes,
            &candidate_bytes,
        ))
    }

    fn artifacts_for_registry(
        registry: RegistrySnapshot,
        approval_limits: ApprovalLimits,
        election_id: &[u8],
    ) -> GuiElectionArtifactsV1 {
        let provider = Blake3HashProviderV1;
        let candidates = candidates();
        let manifest = ok(ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: ok(ElectionId::new(election_id.to_vec())),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: ok(registry.canonical_commitment(&provider)),
            candidate_set_commitment: ok(candidates.canonical_commitment(&provider)),
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits,
            governance_source_revision: "voter-session-test".to_owned(),
        }));
        ok(GuiElectionArtifactsV1::from_bytes(
            &ok(manifest.to_canonical_cbor()),
            &ok(registry.to_canonical_cbor()),
            &ok(candidates.to_canonical_cbor()),
        ))
    }

    fn candidates() -> CandidateSet {
        let defs = vec![
            ok(CandidateDefinition::new(
                id(b"candidate-a"),
                "Candidate A".to_owned(),
            )),
            ok(CandidateDefinition::new(
                id(b"candidate-b"),
                "Candidate B".to_owned(),
            )),
            ok(CandidateDefinition::new(
                id(b"candidate-c"),
                "Candidate C".to_owned(),
            )),
        ];
        ok(CandidateSet::new(defs))
    }

    fn registry() -> RegistrySnapshot {
        let mut keys = Vec::new();
        for scalar in [7_u64, 11, 13] {
            let scalar = Scalar::from(scalar);
            keys.push((RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes());
        }
        keys.sort_unstable();
        let mut writer = tari_cc_private_ballot_protocol::CanonicalCborWriter::new();
        assert!(writer.write_array_len(keys.len()).is_ok());
        for key in keys {
            assert!(writer.write_byte_string(&key).is_ok());
        }
        ok(RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()))
    }

    fn registry_from_keys(keys: &[[u8; 32]]) -> RegistrySnapshot {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        let mut writer = tari_cc_private_ballot_protocol::CanonicalCborWriter::new();
        assert!(writer.write_array_len(sorted.len()).is_ok());
        for key in sorted {
            assert!(writer.write_byte_string(&key).is_ok());
        }
        ok(RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()))
    }

    fn limits(minimum: usize, maximum: usize, allow_abstention: bool) -> ApprovalLimits {
        ok(ApprovalLimits::new(minimum, maximum, allow_abstention))
    }

    fn id(bytes: &[u8]) -> CandidateId {
        ok(CandidateId::new(bytes.to_vec()))
    }

    fn hex_id(bytes: &[u8]) -> String {
        to_lower_hex(bytes)
    }

    fn assert_code<T>(result: Result<T, GuiCoreError>, code: &'static str) {
        match result {
            Ok(_) => panic!("expected error {code}"),
            Err(error) => assert_eq!(error.code(), code),
        }
    }

    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    fn ok_json(result: serde_json::Result<Value>) -> Value {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected json error: {error:?}"),
        }
    }
}
