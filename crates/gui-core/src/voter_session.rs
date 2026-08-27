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
use crate::transport::{
    AuthenticatedTransportReceiptV1, DescriptorConsistencyStoreV1, PrivateBallotEnvelopeV1,
    TransportAuthorityRootSetV1, TransportDescriptorV1, TransportRoutePolicyV1,
    VoterReceiptStateV1,
};
use crate::voter_cast_lock::{
    GuiVoterCastLockStateV1, PendingReleaseRetryHandleV1, cast_record_exists_v1,
    finalize_verified_cast_temp_without_overwrite, load_pending_release_retry_handle_v1,
    persist_release_receipt_evidence_v1, probe_cast_export_destination_supports_no_overwrite_v1,
    promote_cast_record_to_cast_v1, public_credential_fingerprint_hex_v1,
    read_and_verify_staged_release_envelope_v1, release_receipt_evidence_path_v1,
    stage_release_envelope_v1, staged_release_envelope_digest_hex_v1,
    staged_release_envelope_path_v1, write_cast_record_pending_private_transport_v1,
    write_cast_record_pending_v1,
};
use crate::voter_credential::{
    GuiVoterCredentialOriginV1, GuiVoterCredentialSessionV1, GuiVoterCredentialStatusV1,
    GuiVoterEligibilityV1, VoterGovernanceCredentialV1,
};

/// Public notice about the local-only proof workflow.
pub const PROOF_GENERATION_DEFERRED_NOTICE: &str =
    "Proof construction is local; no ballot is submitted by this application.";

/// Test-only panic injection point for proving the fail-closed preparation
/// recovery: when set, [`GuiVoterSessionV1::prepare_ballot`]'s proof work
/// panics after `Preparing` has been installed, exactly like a worker crash.
#[cfg(test)]
pub(crate) static TEST_PANIC_DURING_PROOF_WORK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Stable public workflow-state code derived from Rust-owned voter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GuiVoterWorkflowStateV1 {
    /// The voter must confirm the election details first.
    ReviewRequired,
    /// No Rust-side credential is loaded.
    CredentialMissing,
    /// The loaded credential is not eligible for this frozen registry.
    CredentialNotEligible,
    /// The authoritative lifecycle is not OPEN: voting has not opened yet
    /// (FROZEN) or has closed (CLOSED or later). Nothing else in the voter
    /// workflow can proceed, so this truth dominates selection/credential
    /// states. The exact wording comes from `selection.lifecycle_state`.
    ElectionNotOpen,
    /// No authoritative ballot selection is loaded.
    SelectionIncomplete,
    /// Selection is valid and future proof preparation would be permitted.
    SelectionReady,
    /// A future proof operation token is active.
    PreparingProof,
    /// Future ready state. Not reachable in production in Slice 5A10A.
    PreparedBallotReady,
    /// The ballot was exported and irrevocably cast locally for this election.
    BallotCast,
    /// A cast export is durably committed but awaiting safe finalization; the
    /// voter is locked out of preparing a different ballot.
    CastPending,
}

impl GuiVoterWorkflowStateV1 {
    /// Returns the stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReviewRequired => "ReviewRequired",
            Self::CredentialMissing => "CredentialMissing",
            Self::CredentialNotEligible => "CredentialNotEligible",
            Self::ElectionNotOpen => "ElectionNotOpen",
            Self::SelectionIncomplete => "SelectionIncomplete",
            Self::SelectionReady => "SelectionReady",
            Self::PreparingProof => "PreparingProof",
            Self::PreparedBallotReady => "PreparedBallotReady",
            Self::BallotCast => "BallotCast",
            Self::CastPending => "CastPending",
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

/// The single carrier operation the shared release boundary invokes: deliver an
/// already-authenticated opaque submission envelope to the organizer collector
/// and return the raw authenticated receipt bytes it produced.
///
/// This trait is the ONLY point at which ballot bytes may leave the process, and
/// it is invoked strictly after the durable `CAST_PENDING` release record is
/// written. A carrier must never fall back to a direct/clearnet route; a
/// delivery or receipt failure is surfaced as `Err`, keeping the voter locked
/// and the SAME staged envelope retriable. Implementations must not log the
/// envelope or receipt bytes.
///
/// The delivery receives the SAME already-verified `TransportDescriptorV1` the
/// release boundary authenticated (root-pinned, manifest-bound, route-checked,
/// fingerprint-pinned) and the staged envelope was sealed to. A network carrier
/// MUST derive its destination route from this descriptor, never from an
/// independently supplied address, so the transmitted ciphertext can only ever
/// reach the destination the verified descriptor names. Route confusion is thus
/// structurally impossible rather than detected after the fact.
pub trait PrivateReleaseCarrierV1 {
    /// Sends the exact opaque envelope bytes to the destination named by the
    /// verified `descriptor` and returns the raw authenticated receipt bytes on
    /// success. Any inability to obtain an authenticated receipt is an error;
    /// there is no direct-network fallback and no destination other than the
    /// one derived from `descriptor`.
    fn deliver_opaque_envelope(
        &mut self,
        descriptor: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<Vec<u8>, GuiCoreError>;
}

/// Safe metadata returned after a private-transport release attempt. It exposes
/// only the durable local release state and the voter-safe receipt projection;
/// no descriptor, endpoint, envelope, or organizer intake field crosses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiPrivateReleaseResultV1 {
    /// Durable local cast state after this attempt: `CAST` only once an
    /// authenticated receipt is verified and persisted; otherwise `CAST_PENDING`.
    pub cast_lock_state: &'static str,
    /// Voter-safe transport receipt state, or `PENDING` when delivery is
    /// uncertain (no authenticated receipt yet).
    pub receipt_state: &'static str,
    /// Whether the ballot has irreversibly left local control (delivery
    /// authenticated). This is NOT organizer acceptance, tally inclusion, or
    /// anchoring.
    pub released: bool,
    /// Canonical package digest of the released ballot.
    pub package_digest_hex: String,
    /// A bounded, PRIVACY-SAFE stage label describing WHY an uncertain
    /// (`CAST_PENDING`) attempt did not complete, for the controlled-test
    /// Advanced/diagnostics panel only. `None` on success and whenever there is
    /// no safe stage to report. It NEVER carries plaintext choice, ballot
    /// package, proof, witness, credential/HPKE/receipt-signing secret,
    /// passphrase, member index, private nullifier, staged envelope bytes, or
    /// any voter IP / Tor circuit / network identity — only which processing
    /// stage classified the outcome. The durable state semantics are unchanged:
    /// this field is purely additive diagnostics and never alters `CAST_PENDING`
    /// fail-closed behavior. Vocabulary:
    /// `PRIVATE_TRANSPORT_UNAVAILABLE`, `RECEIPT_PARSE_FAILED`,
    /// `RECEIPT_SIGNATURE_INVALID`, `RECEIPT_DESCRIPTOR_MISMATCH`,
    /// `RECEIPT_PACKAGE_MISMATCH`, `RECEIPT_REJECTED_BY_ORGANIZER`,
    /// `RECEIPT_PERSIST_FAILED`, `CAST_PROMOTION_FAILED`.
    pub diagnostic_stage: Option<&'static str>,
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
    /// Durable local cast state for this election + credential. `NOT_CAST` while
    /// the ballot may still be reconsidered; `CAST` once exported/cast;
    /// `CAST_PENDING` during crash recovery. Defense-in-depth only — the
    /// election-scoped nullifier remains the authoritative one-vote rule.
    pub cast_lock_state: &'static str,
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
    /// The ballot was exported and cast; the canonical bytes are intentionally
    /// dropped so a cast session cannot re-export or reconsider.
    Cast {
        package_digest_hex: Option<String>,
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
            Self::Cast { .. } => GuiPreparedBallotStatusV1 {
                state: "Cast",
                operation_id: None,
                ready_to_export: false,
                summary: None,
                message: "This ballot was exported and cast on this device for this election.",
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
    /// Local durable-cast cache. Authoritative durable state lives on disk; the
    /// shell re-applies it via [`Self::apply_cast_lock_state`] before every
    /// gated operation, so this cache never overrides the durable record.
    cast_lock: GuiVoterCastLockStateV1,
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
            cast_lock: GuiVoterCastLockStateV1::NotCast,
        }
    }

    /// Installs a Rust-owned pending credential after binding it to the
    /// currently loaded frozen registry. The credential never crosses a DTO.
    pub fn install_credential(
        &mut self,
        credential: VoterGovernanceCredentialV1,
        artifacts: &GuiElectionArtifactsV1,
    ) -> Result<GuiVoterCredentialStatusV1, GuiCoreError> {
        self.install_credential_with_origin(
            credential,
            GuiVoterCredentialOriginV1::Generated,
            artifacts,
        )
    }

    /// Installs a Rust-owned credential with its public durability origin
    /// after binding it to the currently loaded frozen registry. The
    /// credential never crosses a DTO.
    pub fn install_credential_with_origin(
        &mut self,
        credential: VoterGovernanceCredentialV1,
        origin: GuiVoterCredentialOriginV1,
        artifacts: &GuiElectionArtifactsV1,
    ) -> Result<GuiVoterCredentialStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let credential =
            GuiVoterCredentialSessionV1::from_credential(credential, origin, artifacts.registry())?;
        let status = credential.status();
        self.credential = Some(credential);
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Credential changed; prepared ballot state was cleared.");
        Ok(status)
    }

    /// Returns the private credential to the shell-owned pending slot when an
    /// election is unloaded. This preserves the current-process bootstrap
    /// workflow without retaining any election-specific eligibility state.
    pub fn take_credential(&mut self) -> Option<VoterGovernanceCredentialV1> {
        self.take_credential_with_origin()
            .map(|(credential, _origin)| credential)
    }

    /// Returns the private credential and its public durability origin to the
    /// shell-owned pending slot when an election is unloaded.
    pub fn take_credential_with_origin(
        &mut self,
    ) -> Option<(VoterGovernanceCredentialV1, GuiVoterCredentialOriginV1)> {
        let session = self.credential.take()?;
        let origin = session.origin();
        let credential = session.into_credential();
        self.credential_generation = self.credential_generation.saturating_add(1);
        self.invalidate_prepared("Election changed; prepared ballot state was cleared.");
        Some((credential, origin))
    }

    /// Updates only the public durability origin for the current active
    /// credential. This is used when a same-key session-only credential is
    /// copied into the default local store without replacing the secret object.
    pub fn set_credential_origin(
        &mut self,
        origin: GuiVoterCredentialOriginV1,
    ) -> GuiVoterCredentialStatusV1 {
        if let Some(credential) = self.credential.as_mut() {
            credential.set_origin(origin);
            return credential.status();
        }
        GuiVoterCredentialStatusV1::unloaded()
    }

    /// Writes a fresh encrypted V1 backup for the current active credential.
    /// This does not mutate the voter session.
    pub fn backup_credential_to_path(
        &self,
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<crate::voter_credential_store::GuiVoterCredentialBackupResultV1, GuiCoreError> {
        let Some(credential) = self.credential.as_ref() else {
            return Err(GuiCoreError::credential_not_loaded());
        };
        crate::voter_credential_store::backup_voter_credential_to_path_v1(
            credential.credential(),
            path,
            passphrase,
        )
    }

    /// Returns the active credential public governance key as lowercase hex,
    /// if a credential is loaded.
    #[must_use]
    pub fn credential_public_key_hex(&self) -> Option<String> {
        self.credential_status().public_governance_key_hex
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
    ///
    /// Selection is refused unless the election is OPEN: the backend is
    /// authoritative, so a checkbox can never become workflow state while
    /// voting is closed or not yet open (the two-computer phantom-selection
    /// root cause). Callers surface [`ValidationCode::ElectionNotOpen`] and
    /// roll their optimistic UI back.
    pub fn set_selection(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        selected_option_ids_hex: Vec<String>,
        abstain: bool,
    ) -> Result<GuiVoterSelectionStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.ensure_not_cast_locked()?;
        ensure_selection_lifecycle_open(lifecycle_state)?;
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
    ///
    /// Like [`Self::set_selection`], this is refused while the election is not
    /// OPEN so local selection state can never change outside an open vote.
    pub fn clear_selection(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiVoterSelectionStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.ensure_not_cast_locked()?;
        ensure_selection_lifecycle_open(lifecycle_state)?;
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
        let mut status = match self.selection.as_ref() {
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
        };
        // While the election is not OPEN the lifecycle truth dominates the
        // selection wording so the UI can never claim a usable response state.
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            status.message = match lifecycle_state {
                ElectionLifecycleStateV1::Frozen => {
                    "Voting has not opened yet; responses can be chosen only while voting is open."
                }
                _ => "Voting has closed; responses can no longer be chosen or changed.",
            };
        }
        status
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
            cast_lock_state: self.cast_lock.as_str(),
        }
    }

    /// Starts a synthetic preparation operation token for architecture tests
    /// and future 5A10B ownership flow. No proof work is performed here.
    pub fn begin_preparation_operation(
        &mut self,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiVoterPreparationTokenV1, GuiCoreError> {
        self.ensure_not_cast_locked()?;
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
    ///
    /// FAIL-CLOSED PREPARATION RECOVERY: every exit path — success, stale
    /// token, verification failure, AND an unexpected panic inside the proof
    /// work — leaves the prepared state explicitly NOT `Preparing`. A runtime
    /// failure can therefore never wedge the workflow: the voter stays
    /// `NotCast` with no staged submission and may safely retry proof
    /// generation. (The panic path matters because this runs on a blocking
    /// worker; without recovery a panicking worker would strand `Preparing`.)
    pub fn prepare_ballot(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiPreparedBallotStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let token = self.begin_preparation_operation(lifecycle_state)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            if TEST_PANIC_DURING_PROOF_WORK.load(std::sync::atomic::Ordering::SeqCst) {
                panic!("injected proof-worker crash");
            }
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
        }));
        let result = match result {
            Ok(inner) => inner,
            Err(_) => {
                // The proof worker panicked. Recover here — while this method
                // still owns `&mut self` and no mutex guard can be poisoned by
                // the unwind (the caller's guard is outside this frame, and
                // catch_unwind stopped it before it escaped) — so the prepared
                // state can never remain stuck in `Preparing`.
                Err(GuiCoreError::new(
                    "GUI_PREPARATION_TASK_FAILED",
                    GuiErrorCategory::ProofFailure,
                    Some("prepare-ballot"),
                    "the proof generation task failed unexpectedly; no ballot was prepared and you may try again",
                ))
            }
        };
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

    /// Fail-closed recovery for an ABANDONED preparation operation: flips a
    /// stuck `Preparing` state back to `Invalidated` so the voter can retry.
    ///
    /// This is the backend-authoritative counterpart to
    /// [`Self::prepare_ballot`]'s internal recovery. The SHELL calls it when it
    /// can prove no live worker owns the operation (its preparation slot is
    /// free) while the state still reads `Preparing` — i.e. the worker died
    /// before `prepare_ballot` could recover on its own. It never touches
    /// `Ready`, `Cast`, or cast-lock state, and it bumps the preparation
    /// generation so any older in-flight result becomes stale and can never
    /// install over newer election/credential/selection state.
    pub fn fail_abandoned_preparation(&mut self) -> bool {
        if self.prepared_ballot.is_preparing() {
            self.invalidate_prepared(
                "A previous proof attempt was interrupted before it finished; you may safely try again.",
            );
            return true;
        }
        false
    }

    /// Token-guarded recovery: invalidates the prepared state ONLY if it is
    /// still exactly the `Preparing` operation identified by `token` AND every
    /// generation the token captured is still current. A stale token (older
    /// operation id, changed credential, changed selection, or different
    /// binding) can never clear a NEWER preparation. Returns whether recovery
    /// fired.
    pub fn fail_preparation_operation(&mut self, token: &GuiVoterPreparationTokenV1) -> bool {
        if self.matches_token(ElectionLifecycleStateV1::Open, token) {
            self.invalidate_prepared(
                "The proof attempt did not complete; no prepared ballot is available.",
            );
            true
        } else {
            false
        }
    }

    /// The non-secret operation id currently `Preparing`, if any.
    #[must_use]
    pub fn preparing_operation_id(&self) -> Option<u64> {
        match &self.prepared_ballot {
            PreparedBallotStateV1::Preparing { operation_id } => Some(*operation_id),
            _ => None,
        }
    }

    /// Writes a verified package without overwrite, then verifies exact bytes
    /// read back from disk through the existing verifier path. This is the pure
    /// file export with no cast-lock semantics; the shell uses
    /// [`Self::export_and_cast_prepared_ballot`] for the voter-facing action.
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
        let written = write_and_verify_ballot_package_to_path(canonical_bytes, artifacts, path)?;
        Ok(GuiPreparedBallotExportV1 {
            canonical_package_bytes: written,
            package_digest_hex: summary.package_digest_hex.clone(),
        })
    }

    /// Exports the prepared ballot AND records an irrevocable local cast for the
    /// (election, public-credential) pair.
    ///
    /// Crash-safe ordering (fail closed after the boundary is durably crossed):
    ///
    /// 1. Refuse if already locked, if the durable record already exists, or if
    ///    the final path exists (fail fast — no lock written on a trivial error).
    /// 2. Probe the destination directory supports no-overwrite hard-link
    ///    finalization; on an unsupported filesystem (e.g. FAT32/exFAT) refuse
    ///    BEFORE any durable cast state, so the voter stays `NOT_CAST` and may
    ///    choose another location.
    /// 3. Write the ballot bytes to a sibling temp file, sync, read back, and
    ///    verify the exact bytes + proof.
    /// 4. Durably write a PENDING cast record binding election + fingerprint +
    ///    package digest + temp/final paths.
    /// 5. Expose the final file via `hard_link(temp, final)` — atomic
    ///    create-or-fail, never overwriting an existing target.
    /// 6. Promote the record to CAST and mark the session cast.
    ///
    /// A crash before step 4 leaves the voter free; a crash after step 4 keeps
    /// the voter locked, and recovery (in [`crate::voter_cast_lock`]) finalizes
    /// the same ballot when it can prove it, never a different one.
    pub fn export_and_cast_prepared_ballot(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        final_path: &std::path::Path,
        cast_locks_dir: &std::path::Path,
    ) -> Result<GuiPreparedBallotExportV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.ensure_not_cast_locked()?;
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            return Err(GuiCoreError::new(
                "GUI_PREPARED_BALLOT_NOT_EXPORTABLE",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("export-ballot"),
                "a prepared ballot can be exported only while the election is open",
            ));
        }
        let (canonical_bytes, package_digest_hex) = match &self.prepared_ballot {
            PreparedBallotStateV1::Ready {
                canonical_bytes,
                summary,
            } => (canonical_bytes.clone(), summary.package_digest_hex.clone()),
            _ => {
                return Err(GuiCoreError::new(
                    "GUI_NO_PREPARED_BALLOT",
                    GuiErrorCategory::InvalidInput,
                    Some("export-ballot"),
                    "no locally verified ballot package is available",
                ));
            }
        };
        let fingerprint = self.credential_fingerprint()?;
        let manifest_hash_hex = self.election_binding.manifest_hash_hex.clone();

        // Defense in depth: never overwrite an existing durable cast for this
        // pair (this also fails closed if a record is present from a prior run).
        if cast_record_exists_v1(cast_locks_dir, &manifest_hash_hex, &fingerprint)? {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Err(GuiCoreError::new(
                "GUI_BALLOT_ALREADY_CAST",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("voter-cast-lock"),
                "a ballot has already been cast for this election with this credential",
            ));
        }

        // Fail fast on a final-path collision BEFORE any durable lock is written,
        // preserving the existing no-overwrite guarantee.
        if final_path.exists() {
            return Err(GuiCoreError::new(
                "GUI_BALLOT_EXPORT_COLLISION",
                GuiErrorCategory::FileIo,
                Some("export-ballot"),
                "For safety, ballot exports never overwrite an existing file. Choose a new filename.",
            ));
        }

        // Preflight: confirm the destination directory supports the
        // no-overwrite hard-link finalization the real export path requires.
        // This MUST run before any durable cast state (and before the real
        // ballot temp is written) so an unsupported destination such as a
        // FAT32/exFAT removable drive is rejected with the voter left NOT_CAST
        // and no PENDING record on disk. The probe uses throwaway files in the
        // destination directory and never touches the real final path.
        probe_cast_export_destination_supports_no_overwrite_v1(final_path)?;

        // Write + verify the ballot to a sibling temp file (same directory, so
        // the later no-overwrite finalization stays on one filesystem).
        let temp_path = cast_temp_path(final_path);
        let _ = std::fs::remove_file(&temp_path);
        let written =
            write_and_verify_ballot_package_to_path(&canonical_bytes, artifacts, &temp_path)?;

        // The irreversible boundary: durably record the pending cast BEFORE the
        // final file is exposed.
        write_cast_record_pending_v1(
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            &package_digest_hex,
            final_path,
            &temp_path,
        )?;

        // Expose the final export file WITHOUT overwriting an existing target
        // (atomic create-or-fail via hard link — closes the former
        // exists()-then-rename TOCTOU). On collision or any finalize failure the
        // PENDING record is durable and the verified temp is preserved, so the
        // voter stays locked and recovery can finalize the SAME ballot later.
        if let Err(error) = finalize_verified_cast_temp_without_overwrite(&temp_path, final_path) {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Err(error);
        }

        // The final file now holds our ballot and the record is durable-PENDING.
        // If promotion is interrupted, recovery promotes the same cast; keep the
        // voter locked (CastPending) rather than reporting success.
        if promote_cast_record_to_cast_v1(cast_locks_dir, &manifest_hash_hex, &fingerprint).is_err()
        {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Err(GuiCoreError::io_failure("export-ballot"));
        }
        self.cast_lock = GuiVoterCastLockStateV1::Cast;
        self.prepared_ballot = PreparedBallotStateV1::Cast {
            package_digest_hex: Some(package_digest_hex.clone()),
        };
        Ok(GuiPreparedBallotExportV1 {
            canonical_package_bytes: written,
            package_digest_hex,
        })
    }

    /// Releases the prepared ballot through a private online transport carrier,
    /// crossing the SAME durable irreversible cast boundary as offline export.
    ///
    /// Crash-safe ordering (fail closed once the boundary is durably crossed):
    ///
    /// 1. Refuse if already locked or a durable record already exists (fail fast,
    ///    NOT_CAST preserved).
    /// 2. Verify the descriptor is root-pinned, manifest/election-bound, and
    ///    permits an online route — BEFORE any staging or PENDING. A bad/untrusted
    ///    descriptor leaves the voter NOT_CAST with no bytes transmitted.
    /// 3. Construct the EXACT opaque submission envelope from the canonical
    ///    prepared package via the existing HPKE transport layer.
    /// 4. Durably stage that exact envelope for retry.
    /// 5. Durably write a PENDING private-transport release record.
    /// 6. Invoke the carrier (the FIRST point ballot bytes can leave the process).
    /// 7. Verify the returned receipt is authenticated by the descriptor and
    ///    acknowledges the exact released package; persist it durably.
    /// 8. Promote to CAST.
    ///
    /// Any failure at or after step 5 keeps the voter `CAST_PENDING` (locked)
    /// with the SAME staged envelope retriable; it never unlocks and never
    /// produces a different ballot.
    #[allow(clippy::too_many_arguments)]
    pub fn release_prepared_ballot_via_private_transport(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
        descriptor: &TransportDescriptorV1,
        roots: &TransportAuthorityRootSetV1,
        consistency: &mut DescriptorConsistencyStoreV1,
        cast_locks_dir: &std::path::Path,
        staging_dir: &std::path::Path,
        carrier: &mut dyn PrivateReleaseCarrierV1,
    ) -> Result<GuiPrivateReleaseResultV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.ensure_not_cast_locked()?;
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            return Err(GuiCoreError::new(
                "GUI_PREPARED_BALLOT_NOT_SUBMITTABLE",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("private-release"),
                "a prepared ballot can be released only while the election is open",
            ));
        }
        let (canonical_bytes, package_digest_hex) = match &self.prepared_ballot {
            PreparedBallotStateV1::Ready {
                canonical_bytes,
                summary,
            } => (canonical_bytes.clone(), summary.package_digest_hex.clone()),
            _ => {
                return Err(GuiCoreError::new(
                    "GUI_NO_PREPARED_BALLOT",
                    GuiErrorCategory::InvalidInput,
                    Some("private-release"),
                    "no locally verified ballot package is available",
                ));
            }
        };
        let fingerprint = self.credential_fingerprint()?;
        let manifest_hash_hex = self.election_binding.manifest_hash_hex.clone();

        // Defense in depth: never overwrite an existing durable cast for this
        // pair. Fail closed (locked) if a record is already present.
        if cast_record_exists_v1(cast_locks_dir, &manifest_hash_hex, &fingerprint)? {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Err(GuiCoreError::new(
                "GUI_BALLOT_ALREADY_CAST",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("voter-cast-lock"),
                "a ballot has already been cast for this election with this credential",
            ));
        }

        // Verify descriptor trust + election/route binding BEFORE staging,
        // PENDING, or any transmission. A failure here leaves the voter
        // NOT_CAST; no ballot bytes are staged or sent.
        let descriptor_fingerprint_hex =
            self.verify_release_descriptor(artifacts, descriptor, roots, consistency)?;

        // Construct the EXACT opaque submission envelope via the existing HPKE
        // transport layer; this is what will be staged, sent, and (on retry)
        // retransmitted byte-for-byte.
        let envelope = PrivateBallotEnvelopeV1::seal(descriptor, &canonical_bytes)
            .and_then(|sealed| sealed.to_canonical_cbor())
            .map_err(map_envelope_seal_error)?;
        // Digest the EXACT bytes that are staged (and later delivered); this is
        // the primary exact-retry integrity invariant recorded in the durable
        // PENDING record.
        let staged_envelope_digest_hex = staged_release_envelope_digest_hex_v1(&envelope);

        let staged_envelope_path =
            staged_release_envelope_path_v1(staging_dir, &manifest_hash_hex, &fingerprint);
        let receipt_evidence_path =
            release_receipt_evidence_path_v1(staging_dir, &manifest_hash_hex, &fingerprint);

        // Durably stage the exact envelope, then durably record PENDING (with the
        // staged digest). After this point the boundary is crossed: every path
        // stays locked.
        stage_release_envelope_v1(&staged_envelope_path, &envelope)?;
        write_cast_record_pending_private_transport_v1(
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            &package_digest_hex,
            &staged_envelope_path,
            &staged_envelope_digest_hex,
            &descriptor_fingerprint_hex,
            &receipt_evidence_path,
        )?;
        self.cast_lock = GuiVoterCastLockStateV1::CastPending;

        // Initial send and retry share one authoritative path: both re-read the
        // staged file and verify its exact bytes/canonical form/public bindings
        // before the carrier is ever invoked, so their semantics cannot drift.
        self.verify_staged_then_deliver_release(
            descriptor,
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            &package_digest_hex,
            &staged_envelope_path,
            &staged_envelope_digest_hex,
            &descriptor_fingerprint_hex,
            &receipt_evidence_path,
            carrier,
        )
    }

    /// Retries the SAME durably staged private-transport release after a crash
    /// or an uncertain send. It retransmits the EXACT staged opaque envelope; it
    /// never re-seals or produces a different ballot. Fail-closed: any failure
    /// keeps the voter `CAST_PENDING`.
    #[allow(clippy::too_many_arguments)]
    pub fn retry_pending_private_transport_release(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        descriptor: &TransportDescriptorV1,
        roots: &TransportAuthorityRootSetV1,
        consistency: &mut DescriptorConsistencyStoreV1,
        cast_locks_dir: &std::path::Path,
        carrier: &mut dyn PrivateReleaseCarrierV1,
    ) -> Result<GuiPrivateReleaseResultV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        let fingerprint = self.credential_fingerprint()?;
        let manifest_hash_hex = self.election_binding.manifest_hash_hex.clone();

        let Some(handle) =
            load_pending_release_retry_handle_v1(cast_locks_dir, &manifest_hash_hex, &fingerprint)
        else {
            return Err(GuiCoreError::new(
                "GUI_NO_PENDING_RELEASE",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("private-release"),
                "there is no pending private-transport release to retry",
            ));
        };
        // We are (correctly) locked while a PENDING release exists.
        self.cast_lock = GuiVoterCastLockStateV1::CastPending;

        // Re-establish descriptor trust and confirm it is the SAME descriptor
        // the staged envelope was sealed to, before retransmitting.
        let descriptor_fingerprint_hex =
            self.verify_release_descriptor(artifacts, descriptor, roots, consistency)?;
        if descriptor_fingerprint_hex != handle.descriptor_fingerprint_hex {
            return Err(GuiCoreError::new(
                "GUI_RELEASE_DESCRIPTOR_CHANGED",
                GuiErrorCategory::BindingMismatch,
                Some("private-release"),
                "the transport descriptor changed; the pending ballot remains cast-pending",
            ));
        }

        // Retransmit the EXACT staged bytes; a missing or altered staged artifact
        // keeps the voter locked (fail closed) and is never transmitted.
        let PendingReleaseRetryHandleV1 {
            staged_envelope_path,
            staged_envelope_digest_hex,
            package_digest_hex,
            receipt_evidence_path,
            ..
        } = handle;

        self.verify_staged_then_deliver_release(
            descriptor,
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            &package_digest_hex,
            &staged_envelope_path,
            &staged_envelope_digest_hex,
            &descriptor_fingerprint_hex,
            &receipt_evidence_path,
            carrier,
        )
    }

    /// Re-reads and verifies the EXACT staged opaque envelope (byte digest +
    /// strict canonical form + public descriptor bindings) BEFORE any carrier is
    /// invoked, then delivers it. A tampered or missing staged artifact is never
    /// transmitted: the carrier is not called, the voter stays `CAST_PENDING`,
    /// and a bounded tamper/recovery error is returned. Shared by initial send
    /// and retry so the two cannot diverge and both send exactly the recorded
    /// artifact.
    #[allow(clippy::too_many_arguments)]
    fn verify_staged_then_deliver_release(
        &mut self,
        descriptor: &TransportDescriptorV1,
        cast_locks_dir: &std::path::Path,
        manifest_hash_hex: &str,
        fingerprint: &str,
        package_digest_hex: &str,
        staged_envelope_path: &std::path::Path,
        staged_envelope_digest_hex: &str,
        descriptor_fingerprint_hex: &str,
        receipt_evidence_path: &std::path::Path,
        carrier: &mut dyn PrivateReleaseCarrierV1,
    ) -> Result<GuiPrivateReleaseResultV1, GuiCoreError> {
        let envelope = match read_and_verify_staged_release_envelope_v1(
            staged_envelope_path,
            staged_envelope_digest_hex,
            descriptor,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                // Fail closed: stay locked, never transmit, never reseal.
                self.cast_lock = GuiVoterCastLockStateV1::CastPending;
                return Err(error);
            }
        };
        self.deliver_and_finalize_release(
            descriptor,
            cast_locks_dir,
            manifest_hash_hex,
            fingerprint,
            package_digest_hex,
            descriptor_fingerprint_hex,
            receipt_evidence_path,
            &envelope,
            carrier,
        )
    }

    /// Shared tail of release + retry: invoke the carrier, authenticate and
    /// persist the receipt, and promote to CAST. Every failure branch leaves the
    /// voter `CAST_PENDING` (locked) with the staged envelope retained.
    #[allow(clippy::too_many_arguments)]
    fn deliver_and_finalize_release(
        &mut self,
        descriptor: &TransportDescriptorV1,
        cast_locks_dir: &std::path::Path,
        manifest_hash_hex: &str,
        fingerprint: &str,
        package_digest_hex: &str,
        descriptor_fingerprint_hex: &str,
        receipt_evidence_path: &std::path::Path,
        envelope: &[u8],
        carrier: &mut dyn PrivateReleaseCarrierV1,
    ) -> Result<GuiPrivateReleaseResultV1, GuiCoreError> {
        // The FIRST point ballot bytes can leave the process. A durable PENDING
        // record already exists. The carrier receives the SAME verified
        // descriptor the envelope was sealed to and derives its route from it.
        //
        // A carrier failure keeps the coarse voter-facing behavior (locked,
        // retriable) but records a bounded safe stage for the Advanced panel.
        // The carrier's own coarse code is intentionally NOT reflected verbatim
        // (it could vary); the authoritative finer network picture is on the
        // organizer's local terminal (Phase C), which is not a remote oracle.
        let receipt_bytes = match carrier.deliver_opaque_envelope(descriptor, envelope) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.cast_lock = GuiVoterCastLockStateV1::CastPending;
                return Ok(self.pending_release_result(
                    package_digest_hex,
                    Some("PRIVATE_TRANSPORT_UNAVAILABLE"),
                ));
            }
        };

        // Promote only on an authenticated receipt that acknowledges the exact
        // released package. An unauthenticated success code is never sufficient.
        let receipt = match AuthenticatedTransportReceiptV1::from_canonical_cbor(&receipt_bytes) {
            Ok(receipt) => receipt,
            Err(_) => {
                self.cast_lock = GuiVoterCastLockStateV1::CastPending;
                return Ok(
                    self.pending_release_result(package_digest_hex, Some("RECEIPT_PARSE_FAILED"))
                );
            }
        };
        // Authenticated binding: signed by a descriptor receipt key, bound to
        // THIS exact descriptor fingerprint (verify_for_descriptor enforces
        // receipt.descriptor_fingerprint == descriptor.fingerprint()), and
        // acknowledging the exact released package. The explicit fingerprint
        // comparison against the pending record's descriptor is defense in depth.
        // Each failing check maps to a distinct, privacy-safe stage (none reveals
        // any secret — only which receipt check failed).
        if receipt.verify_for_descriptor(descriptor).is_err() {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(
                self.pending_release_result(package_digest_hex, Some("RECEIPT_SIGNATURE_INVALID"))
            );
        }
        if to_lower_hex(&receipt.descriptor_fingerprint()) != descriptor_fingerprint_hex {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(self
                .pending_release_result(package_digest_hex, Some("RECEIPT_DESCRIPTOR_MISMATCH")));
        }
        if to_lower_hex(&receipt.package_digest()) != package_digest_hex {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(
                self.pending_release_result(package_digest_hex, Some("RECEIPT_PACKAGE_MISMATCH"))
            );
        }
        // A rejected/duplicate delivery is authenticated but must not promote to
        // CAST; the ballot has still irreversibly left local control, so the
        // voter stays locked (CAST_PENDING) and the truthful receipt is shown.
        if !matches!(
            receipt.receipt().state,
            VoterReceiptStateV1::Accepted | VoterReceiptStateV1::Received
        ) {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(GuiPrivateReleaseResultV1 {
                cast_lock_state: GuiVoterCastLockStateV1::CastPending.as_str(),
                receipt_state: receipt_state_str(receipt.receipt().state),
                released: false,
                package_digest_hex: package_digest_hex.to_owned(),
                diagnostic_stage: Some("RECEIPT_REJECTED_BY_ORGANIZER"),
            });
        }

        // Persist the authenticated receipt so a crash before promotion recovers
        // by re-verifying it; then promote to the terminal CAST state. A failure
        // here means the ballot WAS accepted by the organizer but the local
        // finalization did not complete — the voter stays locked and can retry.
        if persist_release_receipt_evidence_v1(receipt_evidence_path, &receipt_bytes).is_err() {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(
                self.pending_release_result(package_digest_hex, Some("RECEIPT_PERSIST_FAILED"))
            );
        }
        if promote_cast_record_to_cast_v1(cast_locks_dir, manifest_hash_hex, fingerprint).is_err() {
            self.cast_lock = GuiVoterCastLockStateV1::CastPending;
            return Ok(
                self.pending_release_result(package_digest_hex, Some("CAST_PROMOTION_FAILED"))
            );
        }

        self.cast_lock = GuiVoterCastLockStateV1::Cast;
        self.prepared_ballot = PreparedBallotStateV1::Cast {
            package_digest_hex: Some(package_digest_hex.to_owned()),
        };
        Ok(GuiPrivateReleaseResultV1 {
            cast_lock_state: GuiVoterCastLockStateV1::Cast.as_str(),
            receipt_state: receipt_state_str(receipt.receipt().state),
            released: true,
            package_digest_hex: package_digest_hex.to_owned(),
            diagnostic_stage: None,
        })
    }

    fn pending_release_result(
        &self,
        package_digest_hex: &str,
        diagnostic_stage: Option<&'static str>,
    ) -> GuiPrivateReleaseResultV1 {
        GuiPrivateReleaseResultV1 {
            cast_lock_state: GuiVoterCastLockStateV1::CastPending.as_str(),
            receipt_state: "PENDING",
            released: false,
            package_digest_hex: package_digest_hex.to_owned(),
            diagnostic_stage,
        }
    }

    /// Verifies a transport descriptor is trusted (root-pinned, manifest-bound),
    /// bound to THIS election, and permits an online route. Returns the
    /// descriptor's canonical fingerprint (lowercase hex) on success.
    fn verify_release_descriptor(
        &self,
        artifacts: &GuiElectionArtifactsV1,
        descriptor: &TransportDescriptorV1,
        roots: &TransportAuthorityRootSetV1,
        consistency: &mut DescriptorConsistencyStoreV1,
    ) -> Result<String, GuiCoreError> {
        roots
            .verify_and_accept_descriptor(descriptor, artifacts.manifest_hash(), consistency)
            .map_err(map_descriptor_release_error)?;
        if descriptor.election_id() != artifacts.manifest().election_id().as_bytes() {
            return Err(GuiCoreError::new(
                "GUI_RELEASE_WRONG_ELECTION",
                GuiErrorCategory::BindingMismatch,
                Some("private-release"),
                "the transport descriptor is bound to a different election",
            ));
        }
        if matches!(descriptor.route(), TransportRoutePolicyV1::OfflineOnly) {
            return Err(GuiCoreError::new(
                "GUI_RELEASE_ROUTE_UNSUPPORTED",
                GuiErrorCategory::InvalidInput,
                Some("private-release"),
                "the transport descriptor does not permit an online route",
            ));
        }
        descriptor
            .fingerprint()
            .map(|fingerprint| to_lower_hex(&fingerprint))
            .map_err(map_descriptor_release_error)
    }

    /// Discards the prepared ballot so the voter can reconsider ("Change my
    /// choice"). Refused once a durable cast lock is active. This authoritatively
    /// drops the old canonical package and proof in Rust; a subsequent
    /// preparation builds a brand-new package with the normal election-bound
    /// proof and nullifier mechanism.
    pub fn discard_prepared_ballot(
        &mut self,
        artifacts: &GuiElectionArtifactsV1,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<GuiPreparedBallotStatusV1, GuiCoreError> {
        self.ensure_bound(artifacts)?;
        self.ensure_not_cast_locked()?;
        self.invalidate_prepared(
            "Ballot discarded so you can change your choice; prepare a new ballot when ready.",
        );
        Ok(self.prepared_ballot.status(lifecycle_state))
    }

    /// Returns the domain-separated fingerprint of the loaded credential's
    /// public governance key, for cast-lock keying.
    fn credential_fingerprint(&self) -> Result<String, GuiCoreError> {
        let public_key_hex = self
            .credential_status()
            .public_governance_key_hex
            .ok_or_else(|| {
                GuiCoreError::new(
                    "GUI_NO_VOTER_CREDENTIAL",
                    GuiErrorCategory::InvalidInput,
                    Some("export-ballot"),
                    "a voter credential is required to cast a ballot",
                )
            })?;
        public_credential_fingerprint_hex_v1(&public_key_hex).ok_or_else(|| {
            GuiCoreError::new(
                "GUI_CAST_LOCK_FINGERPRINT_FAILED",
                GuiErrorCategory::InvalidInput,
                Some("voter-cast-lock"),
                "the credential public key could not be fingerprinted",
            )
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
        let PreparedBallotStateV1::Ready {
            canonical_bytes, ..
        } = &self.prepared_ballot
        else {
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

    /// Refuses selection/preparation/export changes once a durable local cast
    /// lock is active. This is enforced in Rust so a modified frontend cannot
    /// change or re-prepare a ballot after export.
    fn ensure_not_cast_locked(&self) -> Result<(), GuiCoreError> {
        if self.cast_lock.is_locked() {
            return Err(GuiCoreError::new(
                "GUI_BALLOT_ALREADY_CAST",
                GuiErrorCategory::InvalidLifecycleTransition,
                Some("voter-cast-lock"),
                "this ballot was already exported and cast for this election; it cannot be changed",
            ));
        }
        Ok(())
    }

    /// Applies the durable cast state resolved by the shell. Cached only for
    /// reporting/gating; the on-disk record remains authoritative.
    pub fn apply_cast_lock_state(&mut self, state: GuiVoterCastLockStateV1) {
        self.cast_lock = state;
    }

    /// Returns the current cached cast-lock state.
    #[must_use]
    pub fn cast_lock_state(&self) -> GuiVoterCastLockStateV1 {
        self.cast_lock
    }

    fn workflow_state(
        &self,
        review_confirmed: bool,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> GuiVoterWorkflowStateV1 {
        if !review_confirmed {
            return GuiVoterWorkflowStateV1::ReviewRequired;
        }
        // A durable local cast overrides ordinary selection/preparation states:
        // the ballot has been released and cannot be reconsidered here.
        match self.cast_lock {
            GuiVoterCastLockStateV1::Cast => return GuiVoterWorkflowStateV1::BallotCast,
            GuiVoterCastLockStateV1::CastPending => return GuiVoterWorkflowStateV1::CastPending,
            GuiVoterCastLockStateV1::NotCast => {}
        }
        // The authoritative lifecycle dominates everything below it: while the
        // election is not OPEN, no selection or preparation may proceed, so
        // the workflow must SAY that instead of a misleading
        // "choose a response" (the two-computer FROZEN failure).
        if !matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
            return GuiVoterWorkflowStateV1::ElectionNotOpen;
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

/// Fixed, safe phase labels for private-release diagnostics. They identify WHICH
/// release phase produced a failure — attached to the error `context` — without
/// exposing any secret, ballot plaintext, key, or network-identity material:
/// only the coarse phase and the bounded failure class cross the boundary. This
/// is the instrumentation that lets a runtime failure be attributed to a phase
/// instead of being collapsed into one ambiguous "transport unavailable".
pub const RELEASE_PHASE_DESCRIPTOR_AUTH: &str = "release-descriptor-auth";
pub const RELEASE_PHASE_ENVELOPE_SEAL: &str = "release-envelope-seal";

/// Maps a descriptor AUTHENTICITY / election-binding / consistency failure
/// (root trust, signature, wrong election, generation pinning conflict, or a
/// malformed descriptor) to a bounded, HONEST **terminal** error.
///
/// This phase runs BEFORE any staging or transmission and depends ONLY on local
/// cryptographic/canonical inputs — never on remote reachability. It is
/// therefore NOT a transient transport-availability failure and MUST NOT be
/// auto-retried: it fails closed (the voter stays `NotCast`, nothing is staged).
/// The bounded failure class is preserved in the machine code so a runtime
/// failure identifies the exact check that rejected the descriptor, rather than
/// being masked as a "retry later" transport outage.
/// Selection changes require an OPEN election. This is the single shared
/// lifecycle gate for `set_selection`/`clear_selection`, keeping backend
/// selection state truthful with respect to the authoritative lifecycle.
fn ensure_selection_lifecycle_open(
    lifecycle_state: ElectionLifecycleStateV1,
) -> Result<(), GuiCoreError> {
    if matches!(lifecycle_state, ElectionLifecycleStateV1::Open) {
        return Ok(());
    }
    Err(GuiCoreError::new(
        ValidationCode::ElectionNotOpen.as_str(),
        GuiErrorCategory::InvalidLifecycleTransition,
        Some("selection"),
        match lifecycle_state {
            ElectionLifecycleStateV1::Frozen => {
                "voting has not opened yet; responses can be chosen only while voting is open"
            }
            _ => "voting has closed; responses can no longer be chosen or changed",
        },
    ))
}

fn map_descriptor_release_error(error: crate::transport::TransportError) -> GuiCoreError {
    use crate::transport::TransportError as E;
    let (code, message) = match error {
        E::UntrustedRoot => (
            "GUI_RELEASE_DESCRIPTOR_UNTRUSTED",
            "the ballot-office connection is not signed by a trusted authority; re-obtain the connection file",
        ),
        E::DescriptorConflict => (
            "GUI_RELEASE_DESCRIPTOR_CONFLICT",
            "a different ballot-office connection was already pinned for this election; the connection file is inconsistent",
        ),
        E::WrongElection => (
            "GUI_RELEASE_DESCRIPTOR_WRONG_ELECTION",
            "the ballot-office connection is bound to a different election",
        ),
        E::InvalidDescriptor => (
            "GUI_RELEASE_DESCRIPTOR_INVALID",
            "the ballot-office connection file is malformed",
        ),
        _ => (
            "GUI_RELEASE_DESCRIPTOR_UNVERIFIED",
            "the ballot-office connection could not be verified for this election",
        ),
    };
    GuiCoreError::new(
        code,
        GuiErrorCategory::BindingMismatch,
        Some(RELEASE_PHASE_DESCRIPTOR_AUTH),
        message,
    )
}

/// Maps an envelope SEAL failure (local HPKE sealing / padding / canonical
/// encoding of the exact submission) to a bounded, HONEST **terminal** error.
/// This phase also runs BEFORE staging and is purely local cryptographic work,
/// never a remote-availability issue, so it fails closed and is not auto-retried.
fn map_envelope_seal_error(error: crate::transport::TransportError) -> GuiCoreError {
    use crate::transport::TransportError as E;
    let (code, message) = match error {
        E::OversizedPayload => (
            "GUI_RELEASE_BALLOT_OVERSIZED",
            "the prepared ballot exceeds the configured transport padding size",
        ),
        _ => (
            "GUI_RELEASE_ENVELOPE_SEAL_FAILED",
            "the anonymous ballot envelope could not be sealed for private transport",
        ),
    };
    GuiCoreError::new(
        code,
        GuiErrorCategory::InvalidInput,
        Some(RELEASE_PHASE_ENVELOPE_SEAL),
        message,
    )
}

/// Stable voter-safe string for a transport receipt state.
const fn receipt_state_str(state: VoterReceiptStateV1) -> &'static str {
    match state {
        VoterReceiptStateV1::Received => "RECEIVED",
        VoterReceiptStateV1::Accepted => "ACCEPTED",
        VoterReceiptStateV1::Rejected => "REJECTED",
    }
}

/// Writes exact canonical ballot bytes to a new path (never overwriting), syncs,
/// reads them back, and re-verifies the read-back package and proof through the
/// authoritative verifier. Returns the number of bytes read back.
fn write_and_verify_ballot_package_to_path(
    canonical_bytes: &[u8],
    artifacts: &GuiElectionArtifactsV1,
    path: &std::path::Path,
) -> Result<usize, GuiCoreError> {
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
    let read_back = std::fs::read(path).map_err(|_| GuiCoreError::io_failure("export-ballot"))?;
    if read_back != *canonical_bytes {
        return Err(GuiCoreError::new(
            "GUI_BALLOT_EXPORT_READBACK_FAILED",
            GuiErrorCategory::FileIo,
            Some("export-ballot"),
            "ballot package read-back did not match the prepared bytes",
        ));
    }
    let provider = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
        .map_err(|_| readback_verification_failed())?;
    let package = BallotPackageV1::from_canonical_cbor(
        &read_back,
        artifacts.candidates(),
        artifacts.manifest().approval_limits(),
    )
    .map_err(|_| readback_verification_failed())?;
    verify_approval_proof(
        artifacts.manifest(),
        package.payload(),
        package.proof(),
        &provider,
        &verifier,
    )
    .map_err(|_| readback_verification_failed())?;
    Ok(read_back.len())
}

fn readback_verification_failed() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_BALLOT_EXPORT_READBACK_FAILED",
        GuiErrorCategory::ProofFailure,
        Some("export-ballot"),
        "ballot package read-back verification failed",
    )
}

/// Returns the sibling temp path for a crash-safe cast export. Keeping it in the
/// same directory as the final path keeps the no-overwrite finalization (a hard
/// link) on one filesystem.
fn cast_temp_path(final_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = final_path.as_os_str().to_owned();
    name.push(".castpart");
    std::path::PathBuf::from(name)
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
    fn set_selection_is_refused_while_frozen_with_truthful_error() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);

        // The two-computer phantom-selection root cause: a FROZEN election
        // must REFUSE selection outright so no checkbox can become workflow
        // state while voting has not opened.
        let error =
            match select_candidate_a(&mut session, &artifacts, ElectionLifecycleStateV1::Frozen) {
                Ok(_) => panic!("frozen election must refuse selection"),
                Err(error) => error,
            };
        assert_eq!(error.code(), "ELECTION_NOT_OPEN");

        let status = session.selection_status(&artifacts, ElectionLifecycleStateV1::Frozen);
        assert!(!status.selection_loaded);
        assert_eq!(
            status.lifecycle_state,
            ElectionLifecycleStateV1::Frozen.as_str()
        );
        assert!(!status.can_prepare_ballot);
        assert!(
            status.message.contains("has not opened"),
            "selection message must tell the lifecycle truth: {}",
            status.message
        );
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
    fn set_selection_is_refused_once_closed() {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);

        let error =
            match select_candidate_a(&mut session, &artifacts, ElectionLifecycleStateV1::Closed) {
                Ok(_) => panic!("closed election must refuse selection"),
                Err(error) => error,
            };
        assert_eq!(error.code(), "ELECTION_NOT_OPEN");

        let status = session.selection_status(&artifacts, ElectionLifecycleStateV1::Closed);
        assert!(!status.selection_loaded);
        assert_eq!(
            status.lifecycle_state,
            ElectionLifecycleStateV1::Closed.as_str()
        );
        assert!(!status.can_prepare_ballot);
        assert!(
            status.message.contains("closed"),
            "selection message must say voting closed: {}",
            status.message
        );
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
            // Every non-open lifecycle refuses selection outright, so stored
            // selection state can never exist outside an open election.
            let error = match select_candidate_a(&mut session, &artifacts, lifecycle_state) {
                Ok(_) => panic!("non-open lifecycle must refuse selection"),
                Err(error) => error,
            };
            assert_eq!(error.code(), "ELECTION_NOT_OPEN");

            let status = session.selection_status(&artifacts, lifecycle_state);
            assert!(!status.selection_loaded);
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

    fn open_preparable_session() -> (GuiElectionArtifactsV1, GuiVoterSessionV1) {
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        let mut session = eligible_session(&artifacts);
        ok(select_candidate_a(
            &mut session,
            &artifacts,
            ElectionLifecycleStateV1::Open,
        ));
        (artifacts, session)
    }

    // -------------------------------------------------------------------------
    // FAIL-CLOSED PREPARATION RECOVERY: no runtime failure may leave the voter
    // permanently `Preparing`; the voter stays NOT_CAST and may safely retry.
    // -------------------------------------------------------------------------

    #[test]
    fn panicking_proof_work_leaves_no_preparing_state_and_allows_retry() {
        let (artifacts, mut session) = open_preparable_session();

        TEST_PANIC_DURING_PROOF_WORK.store(true, std::sync::atomic::Ordering::SeqCst);
        let result = session.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open);
        TEST_PANIC_DURING_PROOF_WORK.store(false, std::sync::atomic::Ordering::SeqCst);

        assert_code(result, "GUI_PREPARATION_TASK_FAILED");
        assert_eq!(session.preparing_operation_id(), None);
        let status = session
            .prepared_ballot
            .status(ElectionLifecycleStateV1::Open);
        assert_eq!(status.state, "Invalidated");
        assert!(!status.ready_to_export);
        // Cast boundary untouched and a retry succeeds for real.
        assert_eq!(session.cast_lock, GuiVoterCastLockStateV1::NotCast);
        let retry = ok(session.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open));
        assert_eq!(retry.state, "Ready");
    }

    #[test]
    fn abandoned_preparing_operation_is_recoverable_fail_closed() {
        let (_artifacts, mut session) = open_preparable_session();
        let token = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));
        assert_eq!(session.preparing_operation_id(), Some(token.operation_id()));

        assert!(session.fail_abandoned_preparation());
        assert_eq!(session.preparing_operation_id(), None);
        let status = session
            .prepared_ballot
            .status(ElectionLifecycleStateV1::Open);
        assert_eq!(status.state, "Invalidated");

        // Recovery is idempotent outside Preparing and never touches cast state.
        assert!(!session.fail_abandoned_preparation());
        assert_eq!(session.cast_lock, GuiVoterCastLockStateV1::NotCast);
    }

    #[test]
    fn stale_recovery_token_cannot_clear_a_newer_preparation() {
        let (_artifacts, mut session) = open_preparable_session();
        let stale = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));
        // A newer operation supersedes the stale one.
        let fresh = ok(session.begin_preparation_operation(ElectionLifecycleStateV1::Open));
        assert_ne!(stale.operation_id(), fresh.operation_id());

        assert!(!session.fail_preparation_operation(&stale));
        assert_eq!(
            session.preparing_operation_id(),
            Some(fresh.operation_id()),
            "a stale token must never clear a newer preparation"
        );
        assert!(session.fail_preparation_operation(&fresh));
        assert_eq!(session.preparing_operation_id(), None);
    }

    #[test]
    fn preparation_refused_for_foreign_election_leaves_no_preparing_state() {
        // A session bound to another election must refuse before any
        // `Preparing` state exists, and must leave cast state untouched.
        let other_election_artifacts = artifacts(false, limits(1, 2, false), b"other-election");
        let mut session = eligible_session(&other_election_artifacts);
        let artifacts = artifacts(false, limits(1, 2, false), b"election-a");
        assert_code(
            session.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open),
            "GUI_VOTER_SESSION_ELECTION_MISMATCH",
        );
        assert_eq!(session.preparing_operation_id(), None);
        assert_eq!(session.cast_lock, GuiVoterCastLockStateV1::NotCast);
    }
}
