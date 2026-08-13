//! Canonical election-artifact loading with cross-binding validation.
//!
//! The supported election package is exactly three canonical artifacts:
//! the election manifest, the voter registry, and the candidate set. This
//! module deliberately does not define a container or bundle format. The
//! loader never trusts filenames and never infers election identity from
//! directory names: every check is derived from the decoded bytes.

use std::path::Path;

use tari_cc_private_ballot_ballot::{CandidateSet, ElectionManifest};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CandidateSetCommitment, MAX_CANONICAL_OBJECT_BYTES, ManifestHash,
    RegistryCommitment, ValidationCode,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::ProductionProofSuitePolicyV1;

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::summary::{GuiCandidateSummaryV1, GuiElectionSummaryV1};

/// One validated, cross-bound election artifact triple.
///
/// Construction guarantees:
///
/// 1. every artifact decoded as strict canonical CBOR at a supported version;
/// 2. the recomputed registry commitment equals the manifest's;
/// 3. the recomputed candidate-set commitment equals the manifest's;
/// 4. the manifest hash was recomputed with the production BLAKE3 provider;
/// 5. the manifest's proof suite passes the production suite policy.
#[derive(Debug, Clone)]
pub struct GuiElectionArtifactsV1 {
    manifest: ElectionManifest,
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest_hash: ManifestHash,
    registry_commitment: RegistryCommitment,
    candidate_set_commitment: CandidateSetCommitment,
}

impl GuiElectionArtifactsV1 {
    /// Loads and validates the three canonical artifacts from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] on any decode, version, binding, or
    /// proof-suite failure. No partial object is returned.
    pub fn from_bytes(
        manifest_bytes: &[u8],
        registry_bytes: &[u8],
        candidate_bytes: &[u8],
    ) -> Result<Self, GuiCoreError> {
        let manifest = ElectionManifest::from_canonical_cbor(manifest_bytes)
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;
        let registry = RegistrySnapshot::from_canonical_cbor(registry_bytes)
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        let candidates = CandidateSet::from_canonical_cbor(candidate_bytes)
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;

        let provider = Blake3HashProviderV1;

        let registry_commitment = registry
            .canonical_commitment(&provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        if registry_commitment != manifest.registry_commitment() {
            return Err(GuiCoreError::registry_commitment_mismatch());
        }

        let candidate_set_commitment = candidates
            .canonical_commitment(&provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;
        if candidate_set_commitment != manifest.candidate_set_commitment() {
            return Err(GuiCoreError::from_protocol(
                &tari_cc_private_ballot_protocol::ProtocolError::new(
                    ValidationCode::CandidateSetCommitmentMismatch,
                    "the candidate-set commitment does not match the election manifest",
                ),
                "candidates",
            ));
        }

        let manifest_hash = manifest
            .canonical_hash(&provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;

        ProductionProofSuitePolicyV1::new()
            .validate(manifest.proof_suite_id())
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;

        Ok(Self {
            manifest,
            registry,
            candidates,
            manifest_hash,
            registry_commitment,
            candidate_set_commitment,
        })
    }

    /// Loads and validates the three canonical artifacts from exact paths.
    ///
    /// Files larger than the protocol object limit are rejected before being
    /// read into memory. Filenames carry no meaning; only the decoded bytes
    /// are validated.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] on any I/O, size, decode, binding,
    /// or proof-suite failure.
    pub fn from_paths(
        manifest_path: &Path,
        registry_path: &Path,
        candidate_path: &Path,
    ) -> Result<Self, GuiCoreError> {
        let manifest_bytes = read_bounded(manifest_path, "manifest")?;
        let registry_bytes = read_bounded(registry_path, "registry")?;
        let candidate_bytes = read_bounded(candidate_path, "candidates")?;
        Self::from_bytes(&manifest_bytes, &registry_bytes, &candidate_bytes)
    }

    /// Returns the validated election manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ElectionManifest {
        &self.manifest
    }

    /// Returns the validated frozen voter registry.
    #[must_use]
    pub const fn registry(&self) -> &RegistrySnapshot {
        &self.registry
    }

    /// Returns the validated candidate set.
    #[must_use]
    pub const fn candidates(&self) -> &CandidateSet {
        &self.candidates
    }

    /// Returns the recomputed election manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the recomputed registry commitment.
    #[must_use]
    pub const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }

    /// Returns the recomputed candidate-set commitment.
    #[must_use]
    pub const fn candidate_set_commitment(&self) -> CandidateSetCommitment {
        self.candidate_set_commitment
    }

    /// Returns the human-facing election summary without lifecycle state.
    #[must_use]
    pub fn summary(&self) -> GuiElectionSummaryV1 {
        self.summary_with_lifecycle(None)
    }

    /// Returns the human-facing election summary with an optional lifecycle
    /// state code supplied by a session.
    #[must_use]
    pub(crate) fn summary_with_lifecycle(
        &self,
        lifecycle_state: Option<&'static str>,
    ) -> GuiElectionSummaryV1 {
        let election_id_bytes = self.manifest.election_id().as_bytes();
        GuiElectionSummaryV1 {
            manifest_schema_version: self.manifest.manifest_schema_version(),
            election_id_hex: crate::hex::to_lower_hex(election_id_bytes),
            election_id_text: core::str::from_utf8(election_id_bytes)
                .ok()
                .map(str::to_owned),
            lifecycle_state,
            manifest_hash_hex: crate::hex::to_lower_hex(self.manifest_hash.as_bytes()),
            registry_commitment_hex: crate::hex::to_lower_hex(self.registry_commitment.as_bytes()),
            candidate_set_commitment_hex: crate::hex::to_lower_hex(
                self.candidate_set_commitment.as_bytes(),
            ),
            voter_count: self.registry.len(),
            proof_suite_id: self.manifest.proof_suite_id().to_owned(),
            ballot_kind: self.manifest.ballot_kind().as_str(),
            ballot_confidentiality: self.manifest.ballot_confidentiality().as_str(),
            approval_min: self.manifest.approval_limits().minimum(),
            approval_max: self.manifest.approval_limits().maximum(),
            abstention_allowed: self.manifest.approval_limits().allow_abstention(),
            governance_source_revision: self.manifest.governance_source_revision().to_owned(),
            proposal_question: self.manifest.proposal_question().map(str::to_owned),
            candidates: self
                .candidates
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
                .collect(),
        }
    }
}

/// Reads one artifact file, rejecting missing, unreadable, non-regular, or
/// oversized files before allocating.
fn read_bounded(path: &Path, context: &'static str) -> Result<Vec<u8>, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found(context)
        } else {
            GuiCoreError::io_failure(context)
        }
    })?;
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure(context));
    }
    if metadata.len() > MAX_CANONICAL_OBJECT_BYTES as u64 {
        return Err(GuiCoreError::new(
            ValidationCode::ProtocolLimitExceeded.as_str(),
            GuiErrorCategory::InvalidInput,
            Some(context),
            "artifact file exceeds the protocol object size limit",
        ));
    }
    std::fs::read(path).map_err(|_| GuiCoreError::io_failure(context))
}
