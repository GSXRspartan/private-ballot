//! Public verification of the transport-binding → archive → Phase 4 chain.
//!
//! This module never submits or signs an Ootle transaction. It consumes only a
//! completed archive and the existing canonical Phase 4 evidence record.

use std::path::Path;

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_archive::{ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveManifestV1};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorEvidenceRecordV1, evidence::MAX_EVIDENCE_FILE_BYTES,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use crate::archive_verify::verify_archive_directory_v1;
use crate::error::{GuiCoreError, GuiErrorCategory};

/// Safe public conclusion for the full transport/archive/anchor chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiTransportAnchorVerificationV1 {
    /// `ANCHORED` only when every archived and Phase 4 verification gate passes.
    pub state: &'static str,
    /// Whether the completed archive contains and verifies the binding artifact.
    pub transport_binding_verified: bool,
    /// Whether the completed archive itself verified in the independent replay path.
    pub archive_verified: bool,
    /// Whether the completed archive canonically binds FINALIZED lifecycle state.
    pub archive_finalized: bool,
    /// Whether existing canonical Phase 4 evidence verified the matching archive anchor.
    pub anchor_verified: bool,
    /// The final transport batch-set commitment, when the archive binding verified.
    pub transport_batch_set_commitment_hex: Option<String>,
}

/// Verifies a public final transport anchor chain. `SUBMITTED`, absent, failed,
/// or mismatched evidence always returns `INCLUDED`, never `ANCHORED`.
pub fn verify_transport_archive_anchor_v1(
    archive_dir: &Path,
    evidence_path: &Path,
) -> Result<GuiTransportAnchorVerificationV1, GuiCoreError> {
    let archive = verify_archive_directory_v1(archive_dir)?;
    let mut result = GuiTransportAnchorVerificationV1 {
        state: "INCLUDED",
        transport_binding_verified: archive.transport_binding_verified,
        archive_verified: archive.verified,
        archive_finalized: archive.finalized,
        anchor_verified: false,
        transport_batch_set_commitment_hex: archive.transport_batch_set_commitment_hex,
    };
    if !result.archive_verified || !result.archive_finalized || !result.transport_binding_verified {
        return Ok(result);
    }

    let evidence_metadata = std::fs::symlink_metadata(evidence_path)
        .map_err(|_| GuiCoreError::file_not_found("anchor-evidence"))?;
    if !evidence_metadata.is_file() || evidence_metadata.len() > MAX_EVIDENCE_FILE_BYTES as u64 {
        return Err(GuiCoreError::new(
            "GUI_ANCHOR_EVIDENCE_INVALID",
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-evidence"),
            "anchor evidence is not a bounded regular file",
        ));
    }
    let evidence_bytes =
        std::fs::read(evidence_path).map_err(|_| GuiCoreError::io_failure("anchor-evidence"))?;
    let evidence = AnchorEvidenceRecordV1::from_canonical_bytes(&evidence_bytes).map_err(|_| {
        GuiCoreError::new(
            "GUI_ANCHOR_EVIDENCE_INVALID",
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-evidence"),
            "anchor evidence failed canonical verification",
        )
    })?;

    let archive_manifest_bytes = std::fs::read(archive_dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .map_err(|_| GuiCoreError::file_not_found("archive-manifest"))?;
    let archive_manifest = ArchiveManifestV1::from_canonical_cbor(&archive_manifest_bytes)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    let archive_hash = archive_manifest
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;

    let rebuilt_record = OotleAnchorRecordV1::new(
        evidence.network().clone(),
        evidence.manifest_hash(),
        evidence.archive_hash(),
    );
    let anchor_digest = rebuilt_record
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-record"))?;
    if evidence.manifest_hash() == archive_manifest.election_manifest_hash()
        && evidence.archive_hash() == archive_hash
        && evidence.anchor_digest() == anchor_digest
        && evidence.phase().is_terminal_success()
        && evidence.final_status() == "ACCEPTED"
    {
        result.anchor_verified = true;
        result.state = "ANCHORED";
    }
    Ok(result)
}
