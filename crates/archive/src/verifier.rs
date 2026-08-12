//! Shared offline archive-directory replay verifier.
//!
//! This is the single runtime verifier for finalized archive facts consumed by
//! both `gui-core` and the standalone Ootle anchor app. It performs no network,
//! walletd, or indexer access.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tari_cc_private_ballot_ballot::{CandidateSet, ElectionLifecycleV1, ElectionManifestV1};
use tari_cc_private_ballot_crypto::TariTriptychPrototypeVerifierV1;
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, ManifestHash, RegistryCommitment, ValidationCode,
    MAX_CANONICAL_OBJECT_BYTES, MAX_GOVERNANCE_REVISION_BYTES, hash_domain_separated,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, ProductionProofSuitePolicyV1,
    build_tari_triptych_verifier_from_registry_v1, ingest_approval_ballot_package_v1,
};

use crate::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ARCHIVE_SIGNATURE_PATH_PREFIX, ArchiveFileCatalogV1,
    ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1, BallotDecisionOutcomeV1,
    BallotPackageDigestV1, TRANSPORT_ARCHIVE_BINDING_PATH_V1, TransportArchiveBindingV1,
    VerificationTranscriptV1,
};

/// Canonical archive path of the election manifest.
pub const ELECTION_MANIFEST_ARCHIVE_PATH: &str = "election-manifest.cbor";
/// Canonical archive path of the candidate set.
pub const CANDIDATE_SET_ARCHIVE_PATH: &str = "candidate-set.cbor";
/// Canonical archive path of the frozen voter registry.
pub const VOTER_REGISTRY_ARCHIVE_PATH: &str = "voter-registry.cbor";
/// Canonical archive directory prefix for ballot packages.
pub const SUBMISSIONS_ARCHIVE_DIR: &str = "submissions";
/// Project-controlled archive path for a governance supporting document.
pub const GOVERNANCE_DOCUMENT_ARCHIVE_PATH: &str = "governance/source.bin";
/// Conservative pilot maximum for one governance document.
pub const MAX_GOVERNANCE_DOCUMENT_BYTES: usize = 50 * 1024 * 1024;
/// Prefix for a content-digest governance source pin.
pub const GOVERNANCE_PIN_PREFIX_BLAKE3: &str = "blake3:";
/// Prefix for a Git commit governance source pin.
pub const GOVERNANCE_PIN_PREFIX_GIT: &str = "git:";

const BLAKE3_DIGEST_HEX_LEN: usize = 64;
const GIT_SHA_HEX_LEN: usize = 40;

/// Verification stage: archive manifest presence, decode, and hash provider.
pub const STAGE_ARCHIVE_MANIFEST: &str = "ARCHIVE_MANIFEST";
/// Verification stage: catalog membership and per-file digest checks.
pub const STAGE_CATALOG_FILES: &str = "CATALOG_FILES";
/// Verification stage: election artifact decode and cross-binding checks.
pub const STAGE_ELECTION_ARTIFACTS: &str = "ELECTION_ARTIFACTS";
/// Verification stage: governance source pin to archived document cross-check.
pub const STAGE_GOVERNANCE_PIN: &str = "GOVERNANCE_PIN";
/// Verification stage: deterministic ballot replay through proof verification.
pub const STAGE_BALLOT_REPLAY: &str = "BALLOT_REPLAY";
/// Verification stage: archive manifest rebuild and archive-hash comparison.
pub const STAGE_ARCHIVE_HASH: &str = "ARCHIVE_HASH";
/// Verification stage: optional public transport binding artifact.
pub const STAGE_TRANSPORT_BINDING: &str = "TRANSPORT_BINDING";

/// Bounded filesystem-level failure while verifying an archive directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveVerifierError {
    /// The requested archive directory or file was missing.
    FileNotFound,
    /// A filesystem operation failed.
    IoFailure,
    /// A file exceeded its verifier size bound.
    ProtocolLimitExceeded,
}

impl ArchiveVerifierError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FileNotFound => "GUI_FILE_NOT_FOUND",
            Self::IoFailure => "GUI_IO_ERROR",
            Self::ProtocolLimitExceeded => "PROTOCOL_LIMIT_EXCEEDED",
        }
    }
}

impl core::fmt::Display for ArchiveVerifierError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ArchiveVerifierError {}

/// One hash-covered content file's on-disk check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveDirectoryFileCheckV1 {
    /// Canonical archive-relative path.
    pub path: String,
    /// Whether the file is present on disk.
    pub present: bool,
    /// Whether the recorded digest matches the recomputed digest.
    pub digest_ok: bool,
}

/// Archive-level fact for an archived governance source pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveGovernancePinFactV1 {
    /// A `blake3:` pin matched the archived governance document digest.
    Matched,
    /// A `blake3:` pin and archived governance document disagreed.
    Mismatch,
    /// A `blake3:` pin was present but the governance document was absent.
    Missing,
    /// A `git:` pin is format-valid but operator-attested only.
    OperatorAttested,
    /// No recognized immutable pin applied.
    NotApplicable,
}

/// One candidate's approval count with its display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveTallyCountV1 {
    /// Stable machine candidate identifier, lowercase hex.
    pub candidate_id_hex: String,
    /// Machine identifier as UTF-8 text, when valid.
    pub candidate_id_text: Option<String>,
    /// Human-facing display name.
    pub display_name: String,
    /// Number of approvals.
    pub approvals: u64,
}

/// The leading tally outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveLeadingResultV1 {
    /// No candidate received any approval.
    NoApprovals,
    /// Exactly one candidate leads.
    SingleLeader {
        /// Stable machine candidate identifier, lowercase hex.
        candidate_id_hex: String,
        /// Human-facing display name.
        display_name: String,
        /// The leading approval count.
        approvals: u64,
    },
    /// Multiple candidates share the highest approval count.
    Tie {
        /// Tied machine candidate identifiers, lowercase hex.
        candidate_ids_hex: Vec<String>,
        /// The shared approval count.
        approvals: u64,
    },
}

/// Deterministic tally summary produced by archive replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveTallySummaryV1 {
    /// Number of accepted ballots included in the tally.
    pub accepted_ballots: u64,
    /// Number of accepted abstentions.
    pub abstentions: u64,
    /// Per-candidate counts in canonical machine-ID order.
    pub counts: Vec<ArchiveTallyCountV1>,
    /// The leading outcome.
    pub leading: ArchiveLeadingResultV1,
}

/// The structured result of one full offline archive verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveDirectoryVerificationV1 {
    /// True only when every stage passed completely.
    pub verified: bool,
    /// True only when verification passed and the manifest binds FINALIZED.
    pub finalized: bool,
    /// The first failing stage, if any.
    pub failure_stage: Option<&'static str>,
    /// Stable machine code of the first failure, if any.
    pub failure_code: Option<String>,
    /// Number of hash-covered content files in the catalog.
    pub file_count: usize,
    /// Per-file presence and digest results in canonical path order.
    pub files: Vec<ArchiveDirectoryFileCheckV1>,
    /// Number of archived ballot packages.
    pub ballot_package_count: usize,
    /// Number of replayed accepted decisions.
    pub accepted_count: usize,
    /// Number of replayed rejected decisions.
    pub rejected_count: usize,
    /// Whether the replayed transcript decides every submission.
    pub transcript_complete: bool,
    /// Recomputed deterministic tally, when replay completed.
    pub tally: Option<ArchiveTallySummaryV1>,
    /// The archived manifest's own hash, lowercase hex, when decodable.
    pub archive_hash_hex: Option<String>,
    /// The archive hash rebuilt from on-disk files, lowercase hex.
    pub recomputed_archive_hash_hex: Option<String>,
    /// Whether the rebuilt manifest and hash equal the archived ones.
    pub archive_hash_consistent: bool,
    /// The recomputed election manifest hash, lowercase hex.
    pub election_manifest_hash_hex: Option<String>,
    /// Whether the archived governance document matches the bound pin.
    pub governance_source_matches_pin: ArchiveGovernancePinFactV1,
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

impl ArchiveDirectoryVerificationV1 {
    fn empty() -> Self {
        Self {
            verified: false,
            finalized: false,
            failure_stage: None,
            failure_code: None,
            file_count: 0,
            files: Vec::new(),
            ballot_package_count: 0,
            accepted_count: 0,
            rejected_count: 0,
            transcript_complete: false,
            tally: None,
            archive_hash_hex: None,
            recomputed_archive_hash_hex: None,
            archive_hash_consistent: false,
            election_manifest_hash_hex: None,
            governance_source_matches_pin: ArchiveGovernancePinFactV1::NotApplicable,
            transport_binding_present: false,
            transport_binding_verified: false,
            transport_batch_set_commitment_hex: None,
            transport_accepted_count: None,
            transport_reduced_anonymity: None,
        }
    }

    fn fail(mut self, stage: &'static str, code: &str) -> Self {
        self.verified = false;
        self.failure_stage = Some(stage);
        self.failure_code = Some(code.to_owned());
        self
    }
}

/// Verifies one complete offline archive directory.
///
/// Integrity failures are returned as a structured `Ok` result with
/// `verified=false`; filesystem-level failures return [`ArchiveVerifierError`].
pub fn verify_archive_directory_v1(
    dir: &Path,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArchiveVerifierError::FileNotFound
        } else {
            ArchiveVerifierError::IoFailure
        }
    })?;
    if !metadata.is_dir() {
        return Err(ArchiveVerifierError::IoFailure);
    }

    let provider = Blake3HashProviderV1;
    let mut result = ArchiveDirectoryVerificationV1::empty();

    let manifest_path = dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH);
    let manifest_bytes = match read_bounded(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error == ArchiveVerifierError::FileNotFound => {
            return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, "GUI_ARCHIVE_MISSING_FILE"));
        }
        Err(error) => return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code())),
    };
    let archive_manifest = match ArchiveManifestV1::from_canonical_cbor(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str())),
    };
    if let Err(error) = archive_manifest.validate_hash_provider(&provider) {
        return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str()));
    }
    let archive_hash = archive_manifest
        .canonical_hash(&provider)
        .map_err(|_| ArchiveVerifierError::IoFailure)?;
    result.archive_hash_hex = Some(to_lower_hex(archive_hash.as_bytes()));
    result.file_count = archive_manifest.files().len();

    let disk_files = enumerate_disk_files(dir)?;
    let catalog_paths: BTreeSet<String> = archive_manifest
        .files()
        .entries()
        .iter()
        .map(|entry| entry.path().as_str().to_owned())
        .collect();
    if catalog_paths.difference(&disk_files).next().is_some() {
        for entry in archive_manifest.files().entries() {
            result.files.push(ArchiveDirectoryFileCheckV1 {
                path: entry.path().as_str().to_owned(),
                present: disk_files.contains(entry.path().as_str()),
                digest_ok: false,
            });
        }
        return Ok(result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_MISSING_FILE"));
    }
    if disk_files.difference(&catalog_paths).next().is_some() {
        return Ok(result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_UNEXPECTED_FILE"));
    }

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in archive_manifest.files().entries() {
        let path = entry.path().as_str();
        let bytes = read_bounded_archive_file(&dir.join(path), path)?;
        let digest_ok = entry.verify_bytes(&provider, &bytes).is_ok();
        result.files.push(ArchiveDirectoryFileCheckV1 {
            path: path.to_owned(),
            present: true,
            digest_ok,
        });
        if !digest_ok {
            return Ok(result.fail(STAGE_CATALOG_FILES, "ARCHIVE_FILE_DIGEST_MISMATCH"));
        }
        files.insert(path.to_owned(), bytes);
    }

    for path in [
        ELECTION_MANIFEST_ARCHIVE_PATH,
        VOTER_REGISTRY_ARCHIVE_PATH,
        CANDIDATE_SET_ARCHIVE_PATH,
    ] {
        if !catalog_paths.contains(path) {
            return Ok(result.fail(STAGE_ELECTION_ARTIFACTS, "GUI_ARCHIVE_MISSING_ARTIFACT"));
        }
    }
    let artifacts = match ArchiveElectionArtifactsV1::from_bytes(
        &files[ELECTION_MANIFEST_ARCHIVE_PATH],
        &files[VOTER_REGISTRY_ARCHIVE_PATH],
        &files[CANDIDATE_SET_ARCHIVE_PATH],
    ) {
        Ok(artifacts) => artifacts,
        Err(code) => return Ok(result.fail(STAGE_ELECTION_ARTIFACTS, code)),
    };
    result.election_manifest_hash_hex = Some(to_lower_hex(artifacts.manifest_hash().as_bytes()));

    if let Some(bytes) = files.get(TRANSPORT_ARCHIVE_BINDING_PATH_V1) {
        result.transport_binding_present = true;
        let binding = match TransportArchiveBindingV1::from_canonical_cbor(bytes) {
            Ok(binding) => binding,
            Err(error) => return Ok(result.fail(STAGE_TRANSPORT_BINDING, error.code().as_str())),
        };
        if binding.manifest_hash() != artifacts.manifest_hash()
            || binding.election_id() != artifacts.manifest().election_id().as_bytes()
        {
            return Ok(result.fail(
                STAGE_TRANSPORT_BINDING,
                "GUI_TRANSPORT_ARCHIVE_BINDING_MISMATCH",
            ));
        }
        result.transport_binding_verified = true;
        result.transport_batch_set_commitment_hex =
            Some(to_lower_hex_slice(&binding.final_batch_set_commitment()));
        result.transport_accepted_count = Some(
            binding
                .batches()
                .iter()
                .map(|batch| batch.accepted_unique_count())
                .sum(),
        );
        result.transport_reduced_anonymity =
            Some(binding.batches().iter().any(|batch| batch.reduced_anonymity()));
    }

    let revision = artifacts.manifest().governance_source_revision();
    let pin = validate_governance_source_pin(revision);
    if pin.is_content_digest() {
        let Some(pin_hex) = pin.digest_hex.as_deref() else {
            return Ok(result.fail(STAGE_GOVERNANCE_PIN, "GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH"));
        };
        let gov_entry = archive_manifest
            .files()
            .entries()
            .iter()
            .find(|entry| entry.path().as_str() == GOVERNANCE_DOCUMENT_ARCHIVE_PATH);
        match gov_entry {
            None => {
                result.governance_source_matches_pin = ArchiveGovernancePinFactV1::Missing;
                return Ok(result.fail(
                    STAGE_GOVERNANCE_PIN,
                    "GUI_GOVERNANCE_ARCHIVE_DOCUMENT_MISSING",
                ));
            }
            Some(entry) => {
                let cat_hex = to_lower_hex(entry.digest().as_bytes());
                if cat_hex == pin_hex {
                    result.governance_source_matches_pin = ArchiveGovernancePinFactV1::Matched;
                } else {
                    result.governance_source_matches_pin = ArchiveGovernancePinFactV1::Mismatch;
                    return Ok(result.fail(
                        STAGE_GOVERNANCE_PIN,
                        "GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH",
                    ));
                }
            }
        }
    } else if pin.is_git_commit() {
        result.governance_source_matches_pin = ArchiveGovernancePinFactV1::OperatorAttested;
    } else {
        result.governance_source_matches_pin = ArchiveGovernancePinFactV1::NotApplicable;
    }

    let submission_paths: Vec<String> = catalog_paths
        .iter()
        .filter(|path| path.starts_with(&format!("{SUBMISSIONS_ARCHIVE_DIR}/")))
        .cloned()
        .collect();
    result.ballot_package_count = submission_paths.len();

    let mut session = match ArchiveReplaySessionV1::new(artifacts) {
        Ok(session) => session,
        Err(code) => return Ok(result.fail(STAGE_BALLOT_REPLAY, code)),
    };
    if let Err(code) = session.open() {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, code));
    }
    for path in &submission_paths {
        if let Err(code) = session.intake_ballot(&files[path]) {
            return Ok(result.fail(STAGE_BALLOT_REPLAY, code));
        }
    }
    if let Err(error) = session.transcript().validate_complete() {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code().as_str()));
    }
    result.transcript_complete = true;
    result.accepted_count = session.transcript().accepted_count();
    result.rejected_count = session.transcript().rejected_count();

    let tally = match session.direct_tally() {
        Ok(tally) => tally,
        Err(code) => return Ok(result.fail(STAGE_BALLOT_REPLAY, code)),
    };
    result.tally = Some(summarize_tally(&tally, session.artifacts().candidates()));

    let rebuilt_entries = files
        .iter()
        .map(|(path, bytes)| {
            let archive_path = ArchivePathV1::new(path.clone()).map_err(|_| ArchiveVerifierError::IoFailure)?;
            Ok(ArchiveFileEntryV1::for_bytes(archive_path, &provider, bytes))
        })
        .collect::<Result<Vec<_>, ArchiveVerifierError>>()?;
    let rebuilt_catalog = ArchiveFileCatalogV1::new(rebuilt_entries)
        .map_err(|_| ArchiveVerifierError::IoFailure)?;
    let rebuilt_manifest = if archive_manifest.is_finalized_archive_manifest() {
        ArchiveManifestV1::finalized_for_provider(
            session.artifacts().manifest_hash(),
            rebuilt_catalog,
            &provider,
        )
    } else {
        ArchiveManifestV1::for_provider(session.artifacts().manifest_hash(), rebuilt_catalog, &provider)
    }
    .map_err(|_| ArchiveVerifierError::IoFailure)?;
    let recomputed_hash = rebuilt_manifest
        .canonical_hash(&provider)
        .map_err(|_| ArchiveVerifierError::IoFailure)?;
    result.recomputed_archive_hash_hex = Some(to_lower_hex(recomputed_hash.as_bytes()));
    result.archive_hash_consistent =
        rebuilt_manifest == archive_manifest && recomputed_hash == archive_hash;
    if !result.archive_hash_consistent {
        return Ok(result.fail(STAGE_ARCHIVE_HASH, "ARCHIVE_MANIFEST_HASH_MISMATCH"));
    }

    result.verified = true;
    result.finalized = archive_manifest.is_finalized_archive_manifest();
    Ok(result)
}

#[derive(Debug, Clone)]
struct ArchiveElectionArtifactsV1 {
    manifest: ElectionManifestV1,
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest_hash: ManifestHash,
    registry_commitment: RegistryCommitment,
}

impl ArchiveElectionArtifactsV1 {
    fn from_bytes(
        manifest_bytes: &[u8],
        registry_bytes: &[u8],
        candidate_bytes: &[u8],
    ) -> Result<Self, &'static str> {
        let manifest = ElectionManifestV1::from_canonical_cbor(manifest_bytes)
            .map_err(|error| error.code().as_str())?;
        let registry = RegistrySnapshot::from_canonical_cbor(registry_bytes)
            .map_err(|error| error.code().as_str())?;
        let candidates = CandidateSet::from_canonical_cbor(candidate_bytes)
            .map_err(|error| error.code().as_str())?;

        let provider = Blake3HashProviderV1;
        let registry_commitment = registry
            .canonical_commitment(&provider)
            .map_err(|error| error.code().as_str())?;
        if registry_commitment != manifest.registry_commitment() {
            return Err("GUI_REGISTRY_COMMITMENT_MISMATCH");
        }

        let candidate_set_commitment = candidates
            .canonical_commitment(&provider)
            .map_err(|error| error.code().as_str())?;
        if candidate_set_commitment != manifest.candidate_set_commitment() {
            return Err(ValidationCode::CandidateSetCommitmentMismatch.as_str());
        }

        let manifest_hash = manifest
            .canonical_hash(&provider)
            .map_err(|error| error.code().as_str())?;

        ProductionProofSuitePolicyV1::new()
            .validate(manifest.proof_suite_id())
            .map_err(|error| error.code().as_str())?;

        Ok(Self {
            manifest,
            registry,
            candidates,
            manifest_hash,
            registry_commitment,
        })
    }

    const fn manifest(&self) -> &ElectionManifestV1 {
        &self.manifest
    }

    const fn registry(&self) -> &RegistrySnapshot {
        &self.registry
    }

    const fn candidates(&self) -> &CandidateSet {
        &self.candidates
    }

    const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }
}

#[derive(Debug)]
struct ArchiveReplaySessionV1 {
    artifacts: ArchiveElectionArtifactsV1,
    verifier: TariTriptychPrototypeVerifierV1,
    lifecycle: ElectionLifecycleV1,
    ledger: BallotAcceptanceLedger,
    transcript: VerificationTranscriptV1,
}

impl ArchiveReplaySessionV1 {
    fn new(artifacts: ArchiveElectionArtifactsV1) -> Result<Self, &'static str> {
        let provider = Blake3HashProviderV1;
        let verifier = build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
            .map_err(|error| error.code().as_str())?;

        let mut lifecycle = ElectionLifecycleV1::new();
        lifecycle
            .freeze(artifacts.manifest_hash(), artifacts.registry_commitment())
            .map_err(|error| error.code().as_str())?;

        let transcript = VerificationTranscriptV1::new(artifacts.manifest_hash());
        Ok(Self {
            artifacts,
            verifier,
            lifecycle,
            ledger: BallotAcceptanceLedger::new(),
            transcript,
        })
    }

    fn open(&mut self) -> Result<(), &'static str> {
        self.lifecycle.open().map_err(|error| error.code().as_str())
    }

    fn intake_ballot(&mut self, package_bytes: &[u8]) -> Result<(), &'static str> {
        let provider = Blake3HashProviderV1;
        let digest = BallotPackageDigestV1::new(hash_domain_separated(
            &provider,
            HashDomain::BallotPackageV1,
            package_bytes,
        ));
        let sequence = self
            .transcript
            .record_submission(digest, true)
            .map_err(|error| error.code().as_str())?;
        let outcome = match ingest_approval_ballot_package_v1(
            package_bytes,
            self.artifacts.manifest(),
            self.artifacts.candidates(),
            &self.lifecycle,
            &mut self.ledger,
            &provider,
            &self.verifier,
        ) {
            Ok(()) => BallotDecisionOutcomeV1::Accepted,
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };
        self.transcript
            .record_decision(sequence, digest, outcome)
            .map_err(|error| error.code().as_str())?;
        Ok(())
    }

    fn direct_tally(&self) -> Result<ApprovalTally, &'static str> {
        ApprovalTally::from_ballots(
            self.artifacts.candidates(),
            self.ledger
                .accepted_ballots()
                .iter()
                .map(|ballot| ballot.payload()),
        )
        .map_err(|error| error.code().as_str())
    }

    const fn artifacts(&self) -> &ArchiveElectionArtifactsV1 {
        &self.artifacts
    }

    const fn transcript(&self) -> &VerificationTranscriptV1 {
        &self.transcript
    }
}

struct GovernanceSourcePinV1 {
    kind: GovernanceSourcePinKind,
    format_valid: bool,
    digest_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovernanceSourcePinKind {
    Blake3Digest,
    GitCommit,
    Unrecognized,
}

impl GovernanceSourcePinV1 {
    fn is_content_digest(&self) -> bool {
        self.kind == GovernanceSourcePinKind::Blake3Digest && self.format_valid
    }

    fn is_git_commit(&self) -> bool {
        self.kind == GovernanceSourcePinKind::GitCommit && self.format_valid
    }
}

fn validate_governance_source_pin(revision: &str) -> GovernanceSourcePinV1 {
    if revision.len() > MAX_GOVERNANCE_REVISION_BYTES {
        return unrecognized_pin();
    }
    if let Some(hex_part) = revision.strip_prefix(GOVERNANCE_PIN_PREFIX_BLAKE3) {
        let normalized_hex = hex_part.to_ascii_lowercase();
        if hex_part.len() == BLAKE3_DIGEST_HEX_LEN && is_lowercase_hex(&normalized_hex) {
            return GovernanceSourcePinV1 {
                kind: GovernanceSourcePinKind::Blake3Digest,
                format_valid: true,
                digest_hex: Some(normalized_hex),
            };
        }
        return unrecognized_pin();
    }
    if let Some(hex_part) = revision.strip_prefix(GOVERNANCE_PIN_PREFIX_GIT) {
        let normalized_hex = hex_part.to_ascii_lowercase();
        if hex_part.len() == GIT_SHA_HEX_LEN && is_lowercase_hex(&normalized_hex) {
            return GovernanceSourcePinV1 {
                kind: GovernanceSourcePinKind::GitCommit,
                format_valid: true,
                digest_hex: None,
            };
        }
        return unrecognized_pin();
    }
    unrecognized_pin()
}

fn unrecognized_pin() -> GovernanceSourcePinV1 {
    GovernanceSourcePinV1 {
        kind: GovernanceSourcePinKind::Unrecognized,
        format_valid: false,
        digest_hex: None,
    }
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn summarize_tally(tally: &ApprovalTally, candidates: &CandidateSet) -> ArchiveTallySummaryV1 {
    let display_name_of = |id_bytes: &[u8]| -> String {
        candidates
            .candidates()
            .iter()
            .find(|candidate| candidate.id().as_bytes() == id_bytes)
            .map(|candidate| candidate.display_name().to_owned())
            .unwrap_or_default()
    };

    let counts = tally
        .counts()
        .iter()
        .map(|count| {
            let id_bytes = count.candidate_id().as_bytes();
            ArchiveTallyCountV1 {
                candidate_id_hex: to_lower_hex_slice(id_bytes),
                candidate_id_text: core::str::from_utf8(id_bytes).ok().map(str::to_owned),
                display_name: display_name_of(id_bytes),
                approvals: count.approvals(),
            }
        })
        .collect();

    let leading = match tally.leading_result() {
        LeadingResult::NoApprovals => ArchiveLeadingResultV1::NoApprovals,
        LeadingResult::SingleLeader {
            candidate_id,
            approvals,
        } => ArchiveLeadingResultV1::SingleLeader {
            candidate_id_hex: to_lower_hex_slice(candidate_id.as_bytes()),
            display_name: display_name_of(candidate_id.as_bytes()),
            approvals,
        },
        LeadingResult::Tie {
            candidate_ids,
            approvals,
        } => ArchiveLeadingResultV1::Tie {
            candidate_ids_hex: candidate_ids
                .iter()
                .map(|id| to_lower_hex_slice(id.as_bytes()))
                .collect(),
            approvals,
        },
    };

    ArchiveTallySummaryV1 {
        accepted_ballots: tally.accepted_ballots(),
        abstentions: tally.abstentions(),
        counts,
        leading,
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ArchiveVerifierError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArchiveVerifierError::FileNotFound
        } else {
            ArchiveVerifierError::IoFailure
        }
    })?;
    if !metadata.is_file() {
        return Err(ArchiveVerifierError::IoFailure);
    }
    if metadata.len() > MAX_CANONICAL_OBJECT_BYTES as u64 {
        return Err(ArchiveVerifierError::ProtocolLimitExceeded);
    }
    std::fs::read(path).map_err(|_| ArchiveVerifierError::IoFailure)
}

fn read_bounded_archive_file(
    path: &Path,
    relative: &str,
) -> Result<Vec<u8>, ArchiveVerifierError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArchiveVerifierError::FileNotFound
        } else {
            ArchiveVerifierError::IoFailure
        }
    })?;
    if !metadata.is_file() {
        return Err(ArchiveVerifierError::IoFailure);
    }
    let limit = if relative == GOVERNANCE_DOCUMENT_ARCHIVE_PATH {
        MAX_GOVERNANCE_DOCUMENT_BYTES
    } else {
        MAX_CANONICAL_OBJECT_BYTES
    };
    if metadata.len() > limit as u64 {
        return Err(ArchiveVerifierError::ProtocolLimitExceeded);
    }
    std::fs::read(path).map_err(|_| ArchiveVerifierError::IoFailure)
}

fn enumerate_disk_files(dir: &Path) -> Result<BTreeSet<String>, ArchiveVerifierError> {
    let mut files = BTreeSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries =
            std::fs::read_dir(&current).map_err(|_| ArchiveVerifierError::IoFailure)?;
        for entry in entries {
            let entry = entry.map_err(|_| ArchiveVerifierError::IoFailure)?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|_| ArchiveVerifierError::IoFailure)?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(dir)
                .map_err(|_| ArchiveVerifierError::IoFailure)?;
            let mut canonical = String::new();
            for (index, component) in relative.components().enumerate() {
                if index > 0 {
                    canonical.push('/');
                }
                let std::path::Component::Normal(part) = component else {
                    return Err(ArchiveVerifierError::IoFailure);
                };
                canonical.push_str(&part.to_string_lossy());
            }
            if canonical == ARCHIVE_MANIFEST_CANONICAL_PATH {
                continue;
            }
            if canonical.starts_with(ARCHIVE_SIGNATURE_PATH_PREFIX) {
                continue;
            }
            files.insert(canonical);
        }
    }
    Ok(files)
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    to_lower_hex_slice(bytes)
}

fn to_lower_hex_slice(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
