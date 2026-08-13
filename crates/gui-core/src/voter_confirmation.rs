//! Voter confirmation boundary view model (Slice 5A8).
//!
//! The first real voter confirmation view. This is **read-only confirmation
//! only**: it surfaces exactly the values that are cryptographically bound by
//! the election manifest, clearly labels any application-local presentation as
//! non-canonical, and reports governance document status honestly. It performs
//! no credential handling, no proof generation, no ballot selection, and no
//! network access.
//!
//! # Cryptographically bound vs informational
//!
//! Every field in [`GuiVoterElectionConfirmationV1::bound`] is reconstructed
//! from the canonical manifest and the validated artifact triple. The
//! application-local presentation type is carried separately under
//! `presentation` and is explicitly marked `presentation_is_canonical = false`.
//! V2 manifests expose the exact bound proposal question; V1 manifests keep an
//! explicit no-question notice.
//!
//! # No secrets
//!
//! The DTO contains no voter secret scalar, private key, seed, mnemonic, wallet
//! auth, or signing material. Only public identifiers, commitments, digests,
//! and bound approval rules cross the boundary.

use crate::artifacts::GuiElectionArtifactsV1;
use crate::governance::{
    GuiGovernanceDocumentDigestV1, GuiGovernanceDocumentStatusV1, match_governance_document,
};
use crate::summary::GuiCandidateSummaryV1;

/// Placeholder label for the next voter stage. `Continue` advances only to this
/// placeholder; credential/proof handling remains deferred to a separately
/// reviewed slice.
pub const VOTER_NEXT_STAGE_PLACEHOLDER: &str =
    "Credential and proof workflow will be enabled in the next reviewed slice.";

/// One cryptographically bound value shown to the voter as authoritative.
///
/// Every field here is reconstructed from the canonical manifest and the
/// validated artifact triple. The voter is told: "These values are
/// cryptographically bound by the election manifest."
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiVoterBoundFieldsV1 {
    /// Stable election identifier, lowercase hex.
    pub election_id_hex: String,
    /// Election identifier as UTF-8 text, when valid.
    pub election_id_text: Option<String>,
    /// Canonical V2 ballot question, when the manifest schema binds one.
    pub proposal_question: Option<String>,
    /// Canonical ballot-kind identifier (always `NON_BINDING_APPROVAL_PILOT`).
    pub ballot_kind: &'static str,
    /// Canonical ballot-confidentiality identifier (always `PUBLIC`).
    pub ballot_confidentiality: &'static str,
    /// Recomputed election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// The bound governance source revision string.
    pub governance_source_revision: String,
    /// Proof-suite identifier from the manifest.
    pub proof_suite_id: String,
    /// Minimum selections per ballot.
    pub approval_min: usize,
    /// Maximum selections per ballot.
    pub approval_max: usize,
    /// Whether an empty selection (abstention) is permitted.
    pub abstention_allowed: bool,
    /// Option display labels in canonical machine-ID order. These are bound
    /// through the candidate-set commitment.
    pub option_display_labels: Vec<String>,
}

/// Auditor-facing advanced commitments, reconstructed from the validated
/// artifact triple.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiVoterAdvancedDetailsV1 {
    /// Option machine IDs (lowercase hex) in canonical order.
    pub option_machine_ids_hex: Vec<String>,
    /// Recomputed registry commitment, lowercase hex.
    pub registry_commitment_hex: String,
    /// Recomputed candidate-set commitment, lowercase hex.
    pub candidate_set_commitment_hex: String,
    /// Number of registered voters (the anonymity-set size).
    pub voter_count: usize,
}

/// The complete voter confirmation view model.
///
/// Construct with [`build_voter_election_confirmation`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiVoterElectionConfirmationV1 {
    /// Cryptographically bound fields shown as authoritative.
    pub bound: GuiVoterBoundFieldsV1,
    /// Auditor-facing advanced commitments.
    pub advanced: GuiVoterAdvancedDetailsV1,
    /// Candidates in canonical machine-ID order (full summary).
    pub candidates: Vec<GuiCandidateSummaryV1>,
    /// Governance document match status, when a document digest is available.
    pub governance_document_status: GuiGovernanceDocumentStatusV1,
    /// Application-local presentation label (non-canonical). Always
    /// `presentation_is_canonical = false` for version one.
    pub presentation_is_canonical: bool,
    /// Explicit notice that the presentation label is not part of
    /// the election manifest.
    pub presentation_notice: &'static str,
    /// Placeholder label for the next voter stage.
    pub next_stage_placeholder: &'static str,
    /// Explicit legacy notice when no canonical proposal question exists.
    pub no_proposal_question_notice: Option<&'static str>,
}

/// Notice shown next to the presentation label.
pub const PRESENTATION_NOTICE: &str =
    "This presentation label is application-local and is not part of the election manifest.";

/// Notice shown where a proposal question would otherwise appear.
pub const NO_PROPOSAL_QUESTION_NOTICE: &str = "The version-one manifest carries no title, description, or proposal-question field. \
     The governance source revision and the option display names are the binding.";

/// Builds the voter confirmation view model from the validated artifact triple
/// and an optional governance document digest (computed from a locally selected
/// document). Performs no I/O and no network access.
#[must_use]
pub fn build_voter_election_confirmation(
    artifacts: &GuiElectionArtifactsV1,
    governance_document: Option<&GuiGovernanceDocumentDigestV1>,
) -> GuiVoterElectionConfirmationV1 {
    let manifest = artifacts.manifest();
    let election_id_bytes = manifest.election_id().as_bytes();

    let candidates: Vec<GuiCandidateSummaryV1> = artifacts
        .candidates()
        .candidates()
        .iter()
        .map(|candidate| {
            let id_bytes = candidate.id().as_bytes();
            GuiCandidateSummaryV1 {
                machine_id_hex: crate::hex::to_lower_hex(id_bytes),
                machine_id_text: core::str::from_utf8(id_bytes).ok().map(str::to_owned),
                display_name: candidate.display_name().to_owned(),
            }
        })
        .collect();

    let bound = GuiVoterBoundFieldsV1 {
        election_id_hex: crate::hex::to_lower_hex(election_id_bytes),
        election_id_text: core::str::from_utf8(election_id_bytes)
            .ok()
            .map(str::to_owned),
        proposal_question: manifest.proposal_question().map(str::to_owned),
        ballot_kind: manifest.ballot_kind().as_str(),
        ballot_confidentiality: manifest.ballot_confidentiality().as_str(),
        manifest_hash_hex: crate::hex::to_lower_hex(artifacts.manifest_hash().as_bytes()),
        governance_source_revision: manifest.governance_source_revision().to_owned(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        approval_min: manifest.approval_limits().minimum(),
        approval_max: manifest.approval_limits().maximum(),
        abstention_allowed: manifest.approval_limits().allow_abstention(),
        option_display_labels: candidates.iter().map(|c| c.display_name.clone()).collect(),
    };

    let advanced = GuiVoterAdvancedDetailsV1 {
        option_machine_ids_hex: candidates
            .iter()
            .map(|c| c.machine_id_hex.clone())
            .collect(),
        registry_commitment_hex: crate::hex::to_lower_hex(
            artifacts.registry_commitment().as_bytes(),
        ),
        candidate_set_commitment_hex: crate::hex::to_lower_hex(
            artifacts.candidate_set_commitment().as_bytes(),
        ),
        voter_count: artifacts.registry().len(),
    };

    let governance_document_status =
        match_governance_document(manifest.governance_source_revision(), governance_document);

    GuiVoterElectionConfirmationV1 {
        bound,
        advanced,
        candidates,
        governance_document_status,
        presentation_is_canonical: false,
        presentation_notice: PRESENTATION_NOTICE,
        next_stage_placeholder: VOTER_NEXT_STAGE_PLACEHOLDER,
        no_proposal_question_notice: if manifest.proposal_question().is_some() {
            None
        } else {
            Some(NO_PROPOSAL_QUESTION_NOTICE)
        },
    }
}
