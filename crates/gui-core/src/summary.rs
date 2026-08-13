//! Application-facing view models.
//!
//! These DTOs are plain, bounded data intended for serialization at the
//! Tauri boundary. They contain no secret-bearing fields: no voter secret
//! scalar, no walletd auth, no wallet seed, no mnemonic, no signing material.
//! `serde::Serialize` derives were added in Slice 5A3, the shell slice that
//! needs them (per ADR-0007); no `Deserialize` derive exists because the
//! backend never accepts a view model back from the frontend.

/// One candidate as shown to a user.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiCandidateSummaryV1 {
    /// Stable machine identifier, lowercase hex.
    pub machine_id_hex: String,
    /// Machine identifier as UTF-8 text, when it is valid UTF-8.
    pub machine_id_text: Option<String>,
    /// Human-facing display name.
    pub display_name: String,
}

/// Human-facing summary of one validated election.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionSummaryV1 {
    /// Manifest schema generation (`1` or `2`).
    pub manifest_schema_version: u16,
    /// Stable election identifier, lowercase hex.
    pub election_id_hex: String,
    /// Election identifier as UTF-8 text, when it is valid UTF-8.
    pub election_id_text: Option<String>,
    /// Lifecycle state code (`DRAFT`..`FINALIZED`) when a session is active.
    pub lifecycle_state: Option<&'static str>,
    /// Recomputed election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Recomputed registry commitment, lowercase hex.
    pub registry_commitment_hex: String,
    /// Recomputed candidate-set commitment, lowercase hex.
    pub candidate_set_commitment_hex: String,
    /// Number of registered voters (the anonymity-set size).
    pub voter_count: usize,
    /// Proof suite identifier from the manifest.
    pub proof_suite_id: String,
    /// Stable ballot-kind identifier.
    pub ballot_kind: &'static str,
    /// Stable ballot-confidentiality identifier.
    pub ballot_confidentiality: &'static str,
    /// Minimum selections per ballot.
    pub approval_min: usize,
    /// Maximum selections per ballot.
    pub approval_max: usize,
    /// Whether an empty selection (abstention) is permitted.
    pub abstention_allowed: bool,
    /// Governance source revision pinned by the manifest.
    pub governance_source_revision: String,
    /// Canonical V2 ballot question, when the manifest schema binds one.
    pub proposal_question: Option<String>,
    /// Candidates in canonical machine-ID order.
    pub candidates: Vec<GuiCandidateSummaryV1>,
}
