//! Organizer election-creation facade (Slice 5A6).
//!
//! Application-facing organizer workflow for constructing a new private-ballot
//! election from non-secret public inputs only. The Rust facade — not the
//! frontend — validates every field, constructs the canonical registry,
//! candidate set, and manifest, derives all commitments and the manifest hash,
//! and freezes the election through the existing lifecycle. The frontend
//! collects ordinary strings and public keys; Rust builds the canonical types.
//!
//! # Canonical scope
//!
//! The version-one manifest carries exactly one ballot kind
//! (`NON_BINDING_APPROVAL_PILOT`) and no title, description, proposal text, or
//! ballot-type discriminator. The candidate/governance/ballot-measure label is
//! therefore **application-local presentation only**; it is never serialized
//! into canonical election files and does not survive export/import. It is
//! documented as such and tested to prove it does not alter canonical bytes.
//!
//! The only cryptographically bound governance text is the manifest's
//! `governance_source_revision`; option display names and machine IDs are
//! bound through the candidate-set commitment. No authoritative proposal
//! question text exists in the protocol, so this facade intentionally exposes
//! none: unbound text must never be presented to a voter as the signed
//! question.
//!
//! # No secrets
//!
//! The draft holds only public governance keys and display data. It never
//! accepts or stores voter key material, wallet seed data, mnemonic material,
//! or signing material.

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_archive::ArchiveFileDigestV1;
use tari_cc_private_ballot_ballot::{
    ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateId,
    CandidateSet, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    RISTRETTO_COMPRESSED_POINT_BYTES, RistrettoPublicKeyV1, TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, ManifestHash, MAX_GOVERNANCE_REVISION_BYTES, PROTOCOL_VERSION_V1,
    ProtocolError, ValidationCode,
};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::governance::{
    GuiGovernanceDocumentDigestV1, GuiGovernanceDocumentStatusV1, GuiGovernanceSourcePinV1,
    content_digest_pin_for_bytes, match_governance_document, read_governance_document,
    validate_governance_source_pin,
};
use crate::hex::{abbreviate_hex, from_hex, to_lower_hex};
use crate::session::GuiElectionSessionV1;
use crate::summary::GuiElectionSummaryV1;

/// Canonical export filenames (shared with the archive writer convention).
const ELECTION_MANIFEST_FILE: &str = "election-manifest.cbor";
const VOTER_REGISTRY_FILE: &str = "voter-registry.cbor";
const CANDIDATE_SET_FILE: &str = "candidate-set.cbor";

/// Application-local ballot presentation vocabulary (non-canonical).
///
/// The version-one manifest carries only `NON_BINDING_APPROVAL_PILOT`; it does
/// not distinguish candidate elections from governance proposals or ballot
/// measures. This label selects presentation vocabulary in the UI only. It is
/// never serialized into canonical election files and does not survive
/// export/import through the existing loader.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub enum GuiBallotPresentationType {
    Candidate,
    GovernanceProposal,
    #[default]
    BallotMeasure,
}

impl GuiBallotPresentationType {
    /// Returns the stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::GovernanceProposal => "GOVERNANCE_PROPOSAL",
            Self::BallotMeasure => "BALLOT_MEASURE",
        }
    }

    /// Parses one supported presentation identifier (stable or kebab form).
    pub fn from_identifier(value: &str) -> Result<Self, GuiCoreError> {
        match value {
            "CANDIDATE" | "candidate" => Ok(Self::Candidate),
            "GOVERNANCE_PROPOSAL" | "governance-proposal" => Ok(Self::GovernanceProposal),
            "BALLOT_MEASURE" | "ballot-measure" => Ok(Self::BallotMeasure),
            _ => Err(GuiCoreError::new(
                "GUI_UNKNOWN_PRESENTATION",
                GuiErrorCategory::InvalidInput,
                Some("draft"),
                "unknown ballot presentation type",
            )),
        }
    }
}

/// One draft option as shown to the organizer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiDraftOptionV1 {
    /// Stable machine identifier, lowercase hex.
    pub machine_id_hex: String,
    /// Machine identifier as UTF-8 text, when valid UTF-8.
    pub machine_id_text: Option<String>,
    /// Human-facing display name.
    pub display_name: String,
}

/// One eligible voter public key as shown to the organizer (abbreviated).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiDraftVoterV1 {
    /// Full governance public key, lowercase hex.
    pub public_key_hex: String,
    /// Abbreviated key for compact table display.
    pub public_key_abbrev: String,
}

/// Pre-freeze review of the current draft.
///
/// Commitments and the manifest hash are computed only when the relevant
/// sections are complete; they are `None` otherwise. `complete` is true when
/// the draft has everything required to freeze.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionDraftPreviewV1 {
    pub election_id_hex: Option<String>,
    pub election_id_text: Option<String>,
    pub governance_source_revision: Option<String>,
    pub proof_suite_id: String,
    pub approval_min: Option<usize>,
    pub approval_max: Option<usize>,
    pub allow_abstention: bool,
    pub voter_count: usize,
    pub registry_commitment_hex: Option<String>,
    pub voters: Vec<GuiDraftVoterV1>,
    pub options: Vec<GuiDraftOptionV1>,
    pub candidate_set_commitment_hex: Option<String>,
    pub manifest_hash_hex: Option<String>,
    pub presentation: GuiBallotPresentationType,
    pub complete: bool,
    pub missing: Vec<&'static str>,
    pub frozen: bool,
    /// Safe creation result retained by a frozen draft so a remounted
    /// organizer screen can restore its read-only frozen view.
    pub creation_result: Option<GuiElectionCreationResultV1>,
    /// Whether the presentation type is part of the canonical manifest. Always
    /// `false` for version one; documented for the frontend.
    pub presentation_is_canonical: bool,
    /// Application-level validation of the governance source pin (Slice 5A8).
    /// Advisory: format validity is not a hard freeze gate; only a
    /// content-digest mismatch against a selected document blocks freeze.
    pub governance_source_pin: GuiGovernanceSourcePinV1,
    /// The selected governance document digest, when one has been attached.
    pub governance_document: Option<GuiGovernanceDocumentDigestV1>,
    /// Match status between the bound revision and the selected document.
    pub governance_document_status: GuiGovernanceDocumentStatusV1,
}

/// The result of a successful freeze.
///
/// Carries the frozen election summary (lifecycle `FROZEN`) plus the
/// application-local presentation type, which is explicitly non-canonical.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionCreationResultV1 {
    pub summary: GuiElectionSummaryV1,
    pub presentation: GuiBallotPresentationType,
    /// Always `false` for version one: the presentation type does not survive
    /// canonical export/import.
    pub presentation_is_canonical: bool,
}

/// One exported canonical election file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionExportFileV1 {
    /// Canonical relative filename.
    pub path: String,
    /// Absolute path on disk.
    pub absolute_path: String,
    /// File size in bytes.
    pub bytes: u64,
    /// Domain-separated archive-file digest, lowercase hex.
    pub digest_hex: String,
}

/// The result of exporting the three canonical election artifacts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionExportResultV1 {
    pub directory: String,
    pub manifest_hash_hex: String,
    pub registry_commitment_hex: String,
    pub candidate_set_commitment_hex: String,
    pub files: Vec<GuiElectionExportFileV1>,
}

/// Mutable, non-secret organizer draft for one election under construction.
///
/// The draft is the authoritative organizer-side model: the frontend collects
/// ordinary strings and public keys, but Rust validates every field. After
/// [`freeze`](Self::freeze), the draft becomes immutable: every mutator
/// returns a bounded [`GuiCoreError`] so a modified frontend cannot mutate a
/// frozen election through this facade.
pub struct GuiElectionDraftV1 {
    election_id: Option<Vec<u8>>,
    governance_source_revision: Option<String>,
    approval_min: Option<usize>,
    approval_max: Option<usize>,
    allow_abstention: bool,
    voters: Vec<Vec<u8>>,
    options: Vec<(Vec<u8>, String)>,
    presentation: GuiBallotPresentationType,
    /// Selected governance document raw bytes (non-secret, bounded by the pilot
    /// limit). Retained so the archive writer can include the exact bytes the
    /// organizer pinned.
    governance_document_bytes: Option<Vec<u8>>,
    /// Digest metadata for the selected governance document.
    governance_document_digest: Option<GuiGovernanceDocumentDigestV1>,
    frozen: bool,
    result: Option<GuiElectionCreationResultV1>,
}

impl Default for GuiElectionDraftV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuiElectionDraftV1 {
    /// Creates a fresh draft with production defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            election_id: None,
            governance_source_revision: None,
            approval_min: None,
            approval_max: None,
            allow_abstention: false,
            voters: Vec::new(),
            options: Vec::new(),
            presentation: GuiBallotPresentationType::default(),
            governance_document_bytes: None,
            governance_document_digest: None,
            frozen: false,
            result: None,
        }
    }

    /// Returns whether the draft has been frozen.
    #[must_use]
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Returns the frozen creation result, if any.
    #[must_use]
    pub fn creation_result(&self) -> Option<&GuiElectionCreationResultV1> {
        self.result.as_ref()
    }

    /// Returns the number of currently entered eligible voters.
    #[must_use]
    pub fn voter_count(&self) -> usize {
        self.voters.len()
    }

    fn reject_if_frozen(&self) -> Result<(), GuiCoreError> {
        if self.frozen {
            return Err(GuiCoreError::draft_already_frozen());
        }
        Ok(())
    }

    /// Sets the election basics: the election identifier (text) and the
    /// governance source revision. The proof suite is fixed to the production
    /// Triptych suite and is not selectable by the organizer.
    pub fn set_basics(
        &mut self,
        election_id_text: String,
        governance_source_revision: String,
    ) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        let id_bytes = election_id_text.into_bytes();
        ElectionId::new(id_bytes.clone()).map_err(|error| wrap(&error, "basics"))?;
        validate_governance_revision(&governance_source_revision)?;
        self.election_id = Some(id_bytes);
        self.governance_source_revision = Some(governance_source_revision);
        Ok(())
    }

    /// Sets only the governance source revision, leaving the election
    /// identifier intact. Used after a governance document digest is computed
    /// so the organizer can pin the document by content digest without
    /// re-entering the election identifier.
    pub fn set_governance_source_revision(
        &mut self,
        governance_source_revision: String,
    ) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        validate_governance_revision(&governance_source_revision)?;
        self.governance_source_revision = Some(governance_source_revision);
        Ok(())
    }

    /// Returns the currently selected governance document digest metadata, if
    /// any.
    #[must_use]
    pub fn governance_document_digest(&self) -> Option<&GuiGovernanceDocumentDigestV1> {
        self.governance_document_digest.as_ref()
    }

    /// Returns the currently selected governance document bytes, if any. The
    /// bytes are non-secret governance content retained for archive inclusion.
    #[must_use]
    pub fn governance_document_bytes(&self) -> Option<&[u8]> {
        self.governance_document_bytes.as_deref()
    }

    /// Selects a governance document from a local path. Reads, sizes-checks,
    /// and digests the exact raw bytes (no semantic parsing, no network). The
    /// document is treated as immutable raw bytes for hashing and archival.
    /// Symlinks, directories, and oversized files are rejected.
    pub fn set_governance_document(&mut self, path: &Path) -> Result<GuiGovernanceDocumentDigestV1, GuiCoreError> {
        self.reject_if_frozen()?;
        let (bytes, digest) = read_governance_document(path)?;
        self.governance_document_bytes = Some(bytes);
        self.governance_document_digest = Some(digest.clone());
        Ok(digest)
    }

    /// Clears any selected governance document.
    pub fn clear_governance_document(&mut self) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        self.governance_document_bytes = None;
        self.governance_document_digest = None;
        Ok(())
    }

    /// Convenience: pins the currently selected governance document by content
    /// digest, setting `governance_source_revision` to `blake3:<digest>`. This
    /// is the recommended pilot workflow. Requires that a governance document
    /// has been selected.
    pub fn use_governance_document_digest_as_revision(&mut self) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        let bytes = self
            .governance_document_bytes
            .as_ref()
            .ok_or_else(GuiCoreError::no_governance_document)?;
        let pin = content_digest_pin_for_bytes(bytes);
        validate_governance_revision(&pin)?;
        self.governance_source_revision = Some(pin);
        Ok(())
    }

    /// Sets the voting rules. `approval_max` is also checked against the
    /// option count at freeze time.
    ///
    /// Organizer safety rule: if abstention is disabled, `approval_max` must be
    /// at least 1. The canonical `ApprovalLimits` type permits
    /// `minimum = maximum = 0` with `allow_abstention = false`, but no valid
    /// ballot could then be cast (an empty selection requires abstention, and a
    /// non-empty selection would exceed the zero maximum). The facade rejects
    /// that combination here so an uncastable election can never be frozen.
    pub fn set_rules(
        &mut self,
        approval_min: usize,
        approval_max: usize,
        allow_abstention: bool,
    ) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        ApprovalLimits::new(approval_min, approval_max, allow_abstention)
            .map_err(|error| wrap(&error, "rules"))?;
        if !allow_abstention && approval_max == 0 {
            return Err(GuiCoreError::uncastable_approval_limits());
        }
        self.approval_min = Some(approval_min);
        self.approval_max = Some(approval_max);
        self.allow_abstention = allow_abstention;
        Ok(())
    }

    /// Replaces the entire eligible-voter list from lowercase/uppercase hex
    /// governance public keys. Each key is validated as a canonical non-
    /// identity Ristretto255 point and duplicates are rejected. An empty list
    /// is permitted during editing (freeze rejects an empty registry).
    pub fn set_voters(&mut self, public_key_hexs: Vec<String>) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(public_key_hexs.len());
        for hex in public_key_hexs {
            let trimmed = hex.trim();
            let bytes = from_hex(trimmed).ok_or_else(GuiCoreError::malformed_hex_input)?;
            if bytes.len() != RISTRETTO_COMPRESSED_POINT_BYTES {
                return Err(GuiCoreError::malformed_public_key());
            }
            RistrettoPublicKeyV1::from_bytes(&bytes)
                .map_err(|_| GuiCoreError::malformed_public_key())?;
            keys.push(bytes);
        }
        if has_duplicate(&keys) {
            return Err(GuiCoreError::new(
                ValidationCode::DuplicateGovernanceKey.as_str(),
                GuiErrorCategory::InvalidInput,
                Some("voters"),
                "duplicate governance public key",
            ));
        }
        self.voters = keys;
        Ok(())
    }

    /// Replaces the entire option list. Each option is `(machine_id_text,
    /// display_name)`; the machine ID is encoded as UTF-8 bytes. Duplicate IDs
    /// are rejected. Duplicate display labels (after the existing display-label
    /// normalization, i.e. trimmed for comparison only — canonical labels are
    /// not altered) are also rejected, because voters primarily read display
    /// labels and must not be presented with indistinguishable options. An
    /// empty list is permitted during editing (freeze rejects an empty option
    /// set).
    pub fn set_options(
        &mut self,
        options: Vec<(String, String)>,
    ) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        let mut built: Vec<(Vec<u8>, String)> = Vec::with_capacity(options.len());
        for (id_text, display_name) in options {
            let id_bytes = id_text.into_bytes();
            let id = CandidateId::new(id_bytes.clone()).map_err(|e| wrap(&e, "options"))?;
            CandidateDefinition::new(id, display_name.clone()).map_err(|e| wrap(&e, "options"))?;
            built.push((id_bytes, display_name));
        }
        let ids: Vec<Vec<u8>> = built.iter().map(|(id, _)| id.clone()).collect();
        if has_duplicate(&ids) {
            return Err(GuiCoreError::new(
                ValidationCode::DuplicateCandidateId.as_str(),
                GuiErrorCategory::InvalidInput,
                Some("options"),
                "duplicate ballot option machine identifier",
            ));
        }
        // Organizer-facade safety rule: reject duplicate display labels. The
        // canonical CandidateSet deduplicates by machine ID only; this check
        // is purely an organizer UX guard. Comparison uses the same trim
        // normalization the backend's display-label validation already applies
        // (CandidateDefinition::new checks `display_name.trim().is_empty()`).
        // Canonical labels are never altered here.
        let mut labels: Vec<&str> = built.iter().map(|(_, name)| name.trim()).collect();
        labels.sort_unstable();
        if labels.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(GuiCoreError::duplicate_option_display_label());
        }
        self.options = built;
        Ok(())
    }

    /// Sets the application-local presentation type (non-canonical).
    pub fn set_presentation(&mut self, presentation: GuiBallotPresentationType) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        self.presentation = presentation;
        Ok(())
    }

    /// Imports an existing canonical registry CBOR file into the draft,
    /// replacing the current voter list with its public keys. Reuses the
    /// canonical registry decoder; introduces no new format.
    pub fn import_registry_bytes(&mut self, registry_cbor: &[u8]) -> Result<(), GuiCoreError> {
        self.reject_if_frozen()?;
        let snapshot = RegistrySnapshot::from_canonical_cbor(registry_cbor)
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        self.voters = snapshot
            .entries()
            .iter()
            .map(|entry| entry.governance_key().as_bytes().to_vec())
            .collect();
        Ok(())
    }

    /// Returns a pre-freeze review of the current draft.
    ///
    /// Computes the registry commitment, candidate-set commitment, and manifest
    /// hash for the sections that are complete. The manifest hash is computed
    /// only when the draft is complete enough to freeze.
    pub fn preview(&self) -> GuiElectionDraftPreviewV1 {
        let provider = Blake3HashProviderV1;

        let registry_commitment_hex = if !self.voters.is_empty() {
            match self.build_registry() {
                Ok(snapshot) => snapshot
                    .canonical_commitment(&provider)
                    .map(|c| to_lower_hex(c.as_bytes()))
                    .ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let candidate_set_commitment_hex = if !self.options.is_empty() {
            match self.build_candidate_set() {
                Ok(set) => set
                    .canonical_commitment(&provider)
                    .map(|c| to_lower_hex(c.as_bytes()))
                    .ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let missing = self.missing_fields();
        let complete = missing.is_empty();

        let manifest_hash_hex = if complete {
            self.build_manifest_hash(&provider).map(|h| to_lower_hex(h.as_bytes())).ok()
        } else {
            None
        };

        let election_id_hex = self.election_id.as_ref().map(|b| to_lower_hex(b));
        let election_id_text = self
            .election_id
            .as_ref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok().map(str::to_owned));

        let revision = self
            .governance_source_revision
            .clone()
            .unwrap_or_default();
        let pin = validate_governance_source_pin(&revision);
        let doc_status = match_governance_document(&revision, self.governance_document_digest.as_ref());

        GuiElectionDraftPreviewV1 {
            election_id_hex,
            election_id_text,
            governance_source_revision: self.governance_source_revision.clone(),
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_min: self.approval_min,
            approval_max: self.approval_max,
            allow_abstention: self.allow_abstention,
            voter_count: self.voters.len(),
            registry_commitment_hex,
            voters: self.voter_view(),
            options: self.option_view(),
            candidate_set_commitment_hex,
            manifest_hash_hex,
            presentation: self.presentation,
            complete,
            missing,
            frozen: self.frozen,
            creation_result: self.result.clone(),
            presentation_is_canonical: false,
            governance_source_pin: pin,
            governance_document: self.governance_document_digest.clone(),
            governance_document_status: doc_status,
        }
    }

    /// Freezes the draft: validates every field, constructs the canonical
    /// registry, candidate set, and manifest, re-loads the cross-bound artifact
    /// triple through the existing loader, and opens a frozen session. After
    /// this returns, every mutator on this draft fails.
    ///
    /// Returns the serializable creation result and the frozen session. The
    /// shell owns the session; the draft keeps only the result for queries.
    pub fn freeze(
        &mut self,
    ) -> Result<(GuiElectionCreationResultV1, GuiElectionSessionV1), GuiCoreError> {
        if self.frozen {
            return Err(GuiCoreError::draft_already_frozen());
        }
        let missing = self.missing_fields();
        if !missing.is_empty() {
            return Err(GuiCoreError::draft_incomplete());
        }

        let provider = Blake3HashProviderV1;
        let registry = self.build_registry()?;
        let candidates = self.build_candidate_set()?;

        let registry_commitment = registry
            .canonical_commitment(&provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        let candidate_set_commitment = candidates
            .canonical_commitment(&provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;

        let election_id = ElectionId::new(self.election_id.clone().unwrap_or_default())
            .map_err(|error| wrap(&error, "basics"))?;
        let governance_source_revision =
            self.governance_source_revision.clone().unwrap_or_default();
        let approval_limits = ApprovalLimits::new(
            self.approval_min.unwrap_or(0),
            self.approval_max.unwrap_or(0),
            self.allow_abstention,
        )
        .map_err(|error| wrap(&error, "rules"))?;

        let manifest = ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits,
            governance_source_revision,
        })
        .map_err(|error| wrap(&error, "manifest"))?;

        // ADR-0008 governance source hard gate: if the bound revision is a
        // content-digest pin and a governance document has been selected, the
        // document digest MUST match. This is the one application-level freeze
        // gate introduced by Slice 5A8; it does not alter the canonical
        // manifest bytes and does not gate on pin format validity (advisory),
        // preserving the existing V1 vectors and round-trip behavior.
        let revision_str = manifest.governance_source_revision();
        let pin = validate_governance_source_pin(revision_str);
        if pin.is_content_digest()
            && let Some(doc) = self.governance_document_digest.as_ref()
            && pin.digest_hex.as_deref() != Some(doc.digest_hex.as_str())
        {
            return Err(GuiCoreError::governance_digest_mismatch());
        }

        let manifest_bytes = manifest
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;
        let registry_bytes = registry
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        let candidate_bytes = candidates
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;

        // Reload through the existing cross-binding loader so the exported
        // bytes are guaranteed to round-trip identically.
        let artifacts = GuiElectionArtifactsV1::from_bytes(&manifest_bytes, &registry_bytes, &candidate_bytes)?;
        let session = GuiElectionSessionV1::new(artifacts)?;
        let summary = session.summary();

        let result = GuiElectionCreationResultV1 {
            summary,
            presentation: self.presentation,
            presentation_is_canonical: false,
        };

        self.frozen = true;
        self.result = Some(result.clone());
        Ok((result, session))
    }

    fn build_registry(&self) -> Result<RegistrySnapshot, GuiCoreError> {
        let entries = self
            .voters
            .iter()
            .map(|bytes| {
                let key = GovernancePublicKey::new(bytes.clone())
                    .map_err(|error| wrap(&error, "voters"))?;
                let registration = VoterGovernanceKeyRegistrationV1::new(
                    key,
                    VoterKeyProvisioningV1::ImportedByVoter,
                );
                Ok(RegistryEntry::from_voter_registration(registration))
            })
            .collect::<Result<Vec<_>, GuiCoreError>>()?;
        RegistrySnapshot::new(entries).map_err(|error| GuiCoreError::from_protocol(&error, "voters"))
    }

    fn build_candidate_set(&self) -> Result<CandidateSet, GuiCoreError> {
        let definitions = self
            .options
            .iter()
            .map(|(id_bytes, name)| {
                let id = CandidateId::new(id_bytes.clone()).map_err(|e| wrap(&e, "options"))?;
                CandidateDefinition::new(id, name.clone()).map_err(|e| wrap(&e, "options"))
            })
            .collect::<Result<Vec<_>, GuiCoreError>>()?;
        CandidateSet::new(definitions).map_err(|error| GuiCoreError::from_protocol(&error, "options"))
    }

    fn build_manifest_hash(&self, provider: &Blake3HashProviderV1) -> Result<ManifestHash, GuiCoreError> {
        let registry = self.build_registry()?;
        let candidates = self.build_candidate_set()?;
        let registry_commitment = registry
            .canonical_commitment(provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        let candidate_set_commitment = candidates
            .canonical_commitment(provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;
        let election_id = ElectionId::new(self.election_id.clone().unwrap_or_default())
            .map_err(|error| wrap(&error, "basics"))?;
        let approval_limits = ApprovalLimits::new(
            self.approval_min.unwrap_or(0),
            self.approval_max.unwrap_or(0),
            self.allow_abstention,
        )
        .map_err(|error| wrap(&error, "rules"))?;
        let manifest = ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits,
            governance_source_revision: self.governance_source_revision.clone().unwrap_or_default(),
        })
        .map_err(|error| wrap(&error, "manifest"))?;
        manifest
            .canonical_hash(provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))
    }

    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.election_id.is_none() {
            missing.push("election_id");
        }
        if self.governance_source_revision.is_none() {
            missing.push("governance_source_revision");
        }
        if self.approval_min.is_none() || self.approval_max.is_none() {
            missing.push("approval_limits");
        }
        if self.voters.is_empty() {
            missing.push("voters");
        }
        if self.options.is_empty() {
            missing.push("options");
        }
        if let Some(max) = self.approval_max
            && max > self.options.len()
            && !self.options.is_empty()
        {
            missing.push("approval_max_le_options");
        }
        missing
    }

    fn voter_view(&self) -> Vec<GuiDraftVoterV1> {
        self.voters
            .iter()
            .map(|bytes| {
                let hex = to_lower_hex(bytes);
                GuiDraftVoterV1 {
                    public_key_abbrev: abbreviate_hex(&hex, 8, 6),
                    public_key_hex: hex,
                }
            })
            .collect()
    }

    fn option_view(&self) -> Vec<GuiDraftOptionV1> {
        self.options
            .iter()
            .map(|(id_bytes, name)| GuiDraftOptionV1 {
                machine_id_hex: to_lower_hex(id_bytes),
                machine_id_text: std::str::from_utf8(id_bytes).ok().map(str::to_owned),
                display_name: name.clone(),
            })
            .collect()
    }
}

/// Writes the three canonical election artifacts (manifest, registry,
/// candidate set) into `target_dir` using the canonical filenames, never
/// overwriting existing files. Returns the exact paths, byte sizes, digests,
/// and the manifest hash.
///
/// This is the organizer "export election package" step. It is distinct from
/// the post-voting archive writer (which also records submissions and an
/// archive manifest). The three files written here reload through the
/// existing [`GuiElectionArtifactsV1::from_paths`] loader.
pub fn write_election_artifacts_v1(
    artifacts: &GuiElectionArtifactsV1,
    target_dir: &Path,
) -> Result<GuiElectionExportResultV1, GuiCoreError> {
    prepare_export_target(target_dir)?;

    let provider = Blake3HashProviderV1;
    let manifest_bytes = artifacts
        .manifest()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;
    let registry_bytes = artifacts
        .registry()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
    let candidate_bytes = artifacts
        .candidates()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;

    let files = [
        (ELECTION_MANIFEST_FILE, &manifest_bytes[..]),
        (VOTER_REGISTRY_FILE, &registry_bytes[..]),
        (CANDIDATE_SET_FILE, &candidate_bytes[..]),
    ];

    let mut summaries = Vec::with_capacity(3);
    for (name, bytes) in files {
        let path = target_dir.join(name);
        write_file_atomic(&path, bytes)?;
        let digest = ArchiveFileDigestV1::for_bytes(&provider, bytes);
        summaries.push(GuiElectionExportFileV1 {
            path: name.to_owned(),
            absolute_path: path.to_string_lossy().into_owned(),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            digest_hex: to_lower_hex(digest.as_bytes()),
        });
    }

    Ok(GuiElectionExportResultV1 {
        directory: target_dir.to_string_lossy().into_owned(),
        manifest_hash_hex: to_lower_hex(artifacts.manifest_hash().as_bytes()),
        registry_commitment_hex: to_lower_hex(artifacts.registry_commitment().as_bytes()),
        candidate_set_commitment_hex: to_lower_hex(artifacts.candidate_set_commitment().as_bytes()),
        files: summaries,
    })
}

fn validate_governance_revision(revision: &str) -> Result<(), GuiCoreError> {
    if revision.trim().is_empty() {
        return Err(GuiCoreError::from_protocol(
            &ProtocolError::new(
                ValidationCode::EmptyGovernanceSourceRevision,
                "governance source revision must not be empty",
            ),
            "basics",
        ));
    }
    if revision.len() > MAX_GOVERNANCE_REVISION_BYTES {
        return Err(GuiCoreError::from_protocol(
            &ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "governance revision exceeds the protocol size limit",
            ),
            "basics",
        ));
    }
    Ok(())
}

fn wrap(error: &ProtocolError, context: &'static str) -> GuiCoreError {
    GuiCoreError::from_protocol(error, context)
}

fn has_duplicate(keys: &[Vec<u8>]) -> bool {
    let mut sorted: Vec<&Vec<u8>> = keys.iter().collect();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

fn prepare_export_target(target_dir: &Path) -> Result<(), GuiCoreError> {
    match std::fs::symlink_metadata(target_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(GuiCoreError::export_target_invalid());
            }
            let mut entries = std::fs::read_dir(target_dir)
                .map_err(|_| GuiCoreError::io_failure("export-directory"))?;
            if entries.next().is_some() {
                return Err(GuiCoreError::export_target_not_empty());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(target_dir)
                .map_err(|_| GuiCoreError::io_failure("export-directory"))
        }
        Err(_) => Err(GuiCoreError::io_failure("export-directory")),
    }
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), GuiCoreError> {
    if path.exists() {
        return Err(GuiCoreError::export_target_not_empty());
    }
    let mut tmp: PathBuf = path.to_path_buf();
    let mut name = std::ffi::OsString::from(path.file_name().unwrap_or_default());
    name.push(".tmp");
    tmp.set_file_name(name);
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| GuiCoreError::io_failure("export-file"))?;
        use std::io::Write;
        file.write_all(bytes)
            .map_err(|_| GuiCoreError::io_failure("export-file"))?;
        file.flush()
            .map_err(|_| GuiCoreError::io_failure("export-file"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("export-file"))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|_| GuiCoreError::io_failure("export-file"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_round_trips_identifiers() {
        for p in [
            GuiBallotPresentationType::Candidate,
            GuiBallotPresentationType::GovernanceProposal,
            GuiBallotPresentationType::BallotMeasure,
        ] {
            let parsed = GuiBallotPresentationType::from_identifier(p.as_str());
            assert!(matches!(parsed, Ok(got) if got == p));
        }
        assert!(GuiBallotPresentationType::from_identifier("nope").is_err());
    }

    #[test]
    fn hex_decode_rejects_odd_and_bad() {
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
        let decoded = from_hex("deadbeef");
        assert!(matches!(decoded, Some(ref b) if b == &vec![0xde_u8, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn abbreviate_keeps_short_intact() {
        assert_eq!(abbreviate_hex("abcd", 4, 4), "abcd");
        assert_eq!(abbreviate_hex("deadbeefcafe", 4, 4), "dead\u{2026}cafe");
    }
}
