//! GUI-facing wrapper over the shared offline archive verifier.

use std::path::Path;

use tari_cc_private_ballot_archive::{
    ArchiveDirectoryFileCheckV1, ArchiveDirectoryVerificationV1, ArchiveGovernancePinFactV1,
    ArchiveLeadingResultV1, ArchiveTallySummaryV1, ArchiveVerifierError,
};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::governance::GuiGovernanceArchivePinFactV1;
use crate::tally::{GuiLeadingResultV1, GuiTallyCountV1, GuiTallySummaryV1};

pub use tari_cc_private_ballot_archive::{
    STAGE_ARCHIVE_HASH, STAGE_ARCHIVE_MANIFEST, STAGE_BALLOT_REPLAY, STAGE_CATALOG_FILES,
    STAGE_ELECTION_ARTIFACTS, STAGE_GOVERNANCE_PIN, STAGE_TRANSPORT_BINDING,
};

/// One hash-covered content file's on-disk check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveFileCheckV1 {
    /// Canonical archive-relative path.
    pub path: String,
    /// Whether the file is present on disk.
    pub present: bool,
    /// Whether the recorded digest matches the recomputed digest.
    pub digest_ok: bool,
}

/// The structured result of one full offline archive verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveVerificationV1 {
    /// True only when every stage passed completely.
    pub verified: bool,
    /// True only when verification passed and the top-level canonical archive
    /// manifest binds this exact content catalog to FINALIZED lifecycle state.
    pub finalized: bool,
    /// The first failing stage, if any.
    pub failure_stage: Option<&'static str>,
    /// The stable machine code of the first failure, if any.
    pub failure_code: Option<String>,
    /// Number of hash-covered content files in the catalog.
    pub file_count: usize,
    /// Per-file presence and digest results in canonical path order.
    pub files: Vec<GuiArchiveFileCheckV1>,
    /// Number of archived ballot packages.
    pub ballot_package_count: usize,
    /// Number of replayed accepted decisions.
    pub accepted_count: usize,
    /// Number of replayed rejected decisions.
    pub rejected_count: usize,
    /// Whether the replayed transcript decides every submission.
    pub transcript_complete: bool,
    /// Recomputed deterministic tally, when replay completed.
    pub tally: Option<GuiTallySummaryV1>,
    /// The archived manifest's own hash, lowercase hex, when decodable.
    pub archive_hash_hex: Option<String>,
    /// The archive hash rebuilt from on-disk files, lowercase hex.
    pub recomputed_archive_hash_hex: Option<String>,
    /// Whether the rebuilt manifest and hash equal the archived ones.
    pub archive_hash_consistent: bool,
    /// The recomputed election manifest hash, lowercase hex.
    pub election_manifest_hash_hex: Option<String>,
    /// Distinct application-level governance source pin match fact.
    pub governance_source_matches_pin: GuiGovernanceArchivePinFactV1,
    /// Whether this archive includes the optional transport binding artifact.
    pub transport_binding_present: bool,
    /// Whether the included binding decoded canonically and belongs to this election.
    pub transport_binding_verified: bool,
    /// Final public transport batch-set commitment when a binding verifies.
    pub transport_batch_set_commitment_hex: Option<String>,
    /// Accepted ballot count claimed by the verified final transport binding.
    pub transport_accepted_count: Option<u64>,
    /// Whether any verified final transport batch reports reduced anonymity.
    pub transport_reduced_anonymity: Option<bool>,
}

/// Verifies one complete offline archive directory.
///
/// This preserves the original gui-core API while delegating every replay check
/// to the shared `tari-cc-private-ballot-archive` verifier.
pub fn verify_archive_directory_v1(dir: &Path) -> Result<GuiArchiveVerificationV1, GuiCoreError> {
    let result = tari_cc_private_ballot_archive::verify_archive_directory_v1(dir)
        .map_err(map_archive_verifier_error)?;
    Ok(map_verification(result))
}

fn map_verification(result: ArchiveDirectoryVerificationV1) -> GuiArchiveVerificationV1 {
    GuiArchiveVerificationV1 {
        verified: result.verified,
        finalized: result.finalized,
        failure_stage: result.failure_stage,
        failure_code: result.failure_code,
        file_count: result.file_count,
        files: result.files.into_iter().map(map_file_check).collect(),
        ballot_package_count: result.ballot_package_count,
        accepted_count: result.accepted_count,
        rejected_count: result.rejected_count,
        transcript_complete: result.transcript_complete,
        tally: result.tally.map(map_tally),
        archive_hash_hex: result.archive_hash_hex,
        recomputed_archive_hash_hex: result.recomputed_archive_hash_hex,
        archive_hash_consistent: result.archive_hash_consistent,
        election_manifest_hash_hex: result.election_manifest_hash_hex,
        governance_source_matches_pin: map_governance_pin(result.governance_source_matches_pin),
        transport_binding_present: result.transport_binding_present,
        transport_binding_verified: result.transport_binding_verified,
        transport_batch_set_commitment_hex: result.transport_batch_set_commitment_hex,
        transport_accepted_count: result.transport_accepted_count,
        transport_reduced_anonymity: result.transport_reduced_anonymity,
    }
}

fn map_file_check(check: ArchiveDirectoryFileCheckV1) -> GuiArchiveFileCheckV1 {
    GuiArchiveFileCheckV1 {
        path: check.path,
        present: check.present,
        digest_ok: check.digest_ok,
    }
}

fn map_governance_pin(fact: ArchiveGovernancePinFactV1) -> GuiGovernanceArchivePinFactV1 {
    match fact {
        ArchiveGovernancePinFactV1::Matched => GuiGovernanceArchivePinFactV1::Matched,
        ArchiveGovernancePinFactV1::Mismatch => GuiGovernanceArchivePinFactV1::Mismatch,
        ArchiveGovernancePinFactV1::Missing => GuiGovernanceArchivePinFactV1::Missing,
        ArchiveGovernancePinFactV1::OperatorAttested => {
            GuiGovernanceArchivePinFactV1::OperatorAttested
        }
        ArchiveGovernancePinFactV1::NotApplicable => GuiGovernanceArchivePinFactV1::NotApplicable,
    }
}

fn map_tally(tally: ArchiveTallySummaryV1) -> GuiTallySummaryV1 {
    GuiTallySummaryV1 {
        accepted_ballots: tally.accepted_ballots,
        abstentions: tally.abstentions,
        counts: tally
            .counts
            .into_iter()
            .map(|count| GuiTallyCountV1 {
                candidate_id_hex: count.candidate_id_hex,
                candidate_id_text: count.candidate_id_text,
                display_name: count.display_name,
                approvals: count.approvals,
            })
            .collect(),
        leading: match tally.leading {
            ArchiveLeadingResultV1::NoApprovals => GuiLeadingResultV1::NoApprovals,
            ArchiveLeadingResultV1::SingleLeader {
                candidate_id_hex,
                display_name,
                approvals,
            } => GuiLeadingResultV1::SingleLeader {
                candidate_id_hex,
                display_name,
                approvals,
            },
            ArchiveLeadingResultV1::Tie {
                candidate_ids_hex,
                approvals,
            } => GuiLeadingResultV1::Tie {
                candidate_ids_hex,
                approvals,
            },
        },
    }
}

fn map_archive_verifier_error(error: ArchiveVerifierError) -> GuiCoreError {
    match error {
        ArchiveVerifierError::FileNotFound => GuiCoreError::file_not_found("archive-directory"),
        ArchiveVerifierError::IoFailure => GuiCoreError::io_failure("archive-directory"),
        ArchiveVerifierError::ProtocolLimitExceeded => GuiCoreError::new(
            "PROTOCOL_LIMIT_EXCEEDED",
            GuiErrorCategory::InvalidInput,
            Some("archive-file"),
            "archive file exceeds the protocol object size limit",
        ),
    }
}
