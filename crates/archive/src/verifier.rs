//! Shared offline archive-directory replay verifier.
//!
//! This is the single runtime verifier for finalized archive facts consumed by
//! both `gui-core` and the standalone Ootle anchor app. It performs no network,
//! walletd, or indexer access.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tari_cc_private_ballot_ballot::{CandidateSet, ElectionLifecycleV1, ElectionManifest};
use tari_cc_private_ballot_crypto::TariTriptychPrototypeVerifierV1;
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, MAX_CANONICAL_OBJECT_BYTES, MAX_GOVERNANCE_REVISION_BYTES,
    ManifestHash, ProtocolError, RegistryCommitment, ValidationCode, hash_domain_separated,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, ProductionProofSuitePolicyV1, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, verify_approval_ballot_packages_batch_v1,
};

#[cfg(test)]
use tari_cc_private_ballot_verifier::ingest_approval_ballot_package_v1;

use crate::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ARCHIVE_SIGNATURE_PATH_PREFIX, ArchiveFileCatalogV1,
    ArchiveFileEntryV1, ArchiveHashV1, ArchiveManifestV1, ArchivePathV1, BallotDecisionOutcomeV1,
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

/// Maximum archived submissions whose Triptych proofs are verified together in
/// one shared multiscalar batch (archive verification Stage 1).
///
/// Batching amortizes one ring multiscalar multiplication across many proofs
/// and reuses one immutable election context per batch, while per-submission
/// structural checks, exact per-input rejection codes, and full-blame isolation
/// of one invalid proof are all preserved by
/// [`verify_approval_ballot_packages_batch_v1`]. Election semantics (nullifier
/// ledger, first-valid-wins, transcript, tally) are applied serially in
/// canonical archive order after the batch results are computed.
pub const ARCHIVE_REPLAY_BATCH_SIZE_V1: usize = 16;

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
    /// Decoded election manifest schema generation, when the manifest decoded.
    pub election_manifest_schema_version: Option<u16>,
    /// Verified V2 proposal question, derived only from canonical manifest bytes.
    pub proposal_question: Option<String>,
    /// Election id bytes, lowercase hex, derived from the decoded manifest.
    pub election_id_hex: Option<String>,
    /// Stable ballot-kind identifier from the decoded manifest.
    pub ballot_kind_id: Option<String>,
    /// Stable ballot-confidentiality identifier from the decoded manifest.
    pub ballot_confidentiality_id: Option<String>,
    /// Proof-suite identifier from the decoded manifest.
    pub proof_suite_id: Option<String>,
    /// Registry commitment, lowercase hex, from the decoded manifest.
    pub registry_commitment_hex: Option<String>,
    /// Candidate/option-set commitment, lowercase hex, from the decoded manifest.
    pub option_set_commitment_hex: Option<String>,
    /// Eligible voter count from the frozen registry snapshot.
    pub eligible_voter_count: Option<u64>,
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
            election_manifest_schema_version: None,
            proposal_question: None,
            election_id_hex: None,
            ballot_kind_id: None,
            ballot_confidentiality_id: None,
            proof_suite_id: None,
            registry_commitment_hex: None,
            option_set_commitment_hex: None,
            eligible_voter_count: None,
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

/// The outcome of re-establishing the current on-disk archive identity and
/// catalog: either a fail-closed result, or a fully revalidated identity whose
/// remaining verification stages are a pure function of the read bytes.
pub(crate) enum EstablishOutcomeV1 {
    /// A fail-closed structured result (manifest/catalog stage failure). This is
    /// never cached.
    Failed(ArchiveDirectoryVerificationV1),
    /// Current identity re-established: manifest decoded and hashed, catalog set
    /// equality checked, and every catalog file re-read and digest-verified.
    Established(EstablishedIdentityV1),
}

/// A fully revalidated current archive identity and its exact catalog bytes.
///
/// Reaching this means the current on-disk content is bit-identical to the
/// content committed by the freshly decoded manifest (every catalog file's
/// domain-separated digest was recomputed and matched). The remaining
/// verification stages (artifact decode, transport/governance, ballot replay,
/// archive-hash rebuild) are therefore a pure function of these bytes.
pub(crate) struct EstablishedIdentityV1 {
    archive_hash: ArchiveHashV1,
    archive_manifest: ArchiveManifestV1,
    files: BTreeMap<String, Vec<u8>>,
    result: ArchiveDirectoryVerificationV1,
}

impl EstablishedIdentityV1 {
    pub(crate) const fn archive_hash(&self) -> ArchiveHashV1 {
        self.archive_hash
    }
}

/// Verifies one complete offline archive directory.
///
/// Integrity failures are returned as a structured `Ok` result with
/// `verified=false`; filesystem-level failures return [`ArchiveVerifierError`].
pub fn verify_archive_directory_v1(
    dir: &Path,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    match establish_identity_and_catalog(dir)? {
        EstablishOutcomeV1::Failed(result) => Ok(result),
        EstablishOutcomeV1::Established(established) => finish_verification(established),
    }
}

/// Full archive verification using the retained pre-Stage-1 serial replay.
/// Test-only parity reference for [`verify_archive_directory_v1`].
#[cfg(test)]
pub(crate) fn verify_archive_directory_serial_for_test(
    dir: &Path,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    match establish_identity_and_catalog(dir)? {
        EstablishOutcomeV1::Failed(result) => Ok(result),
        EstablishOutcomeV1::Established(established) => {
            finish_verification_serial_for_test(established)
        }
    }
}

/// Re-establishes the current archive identity and revalidates every catalog
/// file against the freshly decoded manifest.
///
/// This is the mandatory, always-run portion of both the full verifier and the
/// memoized fast path: it reads and strictly decodes the current manifest,
/// enforces catalog set equality against the current disk contents, and
/// bounded-reads and re-digests every catalog file. It never trusts mtime,
/// size, or a prior result. Any missing, unexpected, non-regular, oversized,
/// reparse/symlink, digest, or read anomaly fails closed identically to the
/// legacy path.
pub(crate) fn establish_identity_and_catalog(
    dir: &Path,
) -> Result<EstablishOutcomeV1, ArchiveVerifierError> {
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
            return Ok(EstablishOutcomeV1::Failed(
                result.fail(STAGE_ARCHIVE_MANIFEST, "GUI_ARCHIVE_MISSING_FILE"),
            ));
        }
        Err(error) => {
            return Ok(EstablishOutcomeV1::Failed(
                result.fail(STAGE_ARCHIVE_MANIFEST, error.code()),
            ));
        }
    };
    let archive_manifest = match ArchiveManifestV1::from_canonical_cbor(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return Ok(EstablishOutcomeV1::Failed(
                result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str()),
            ));
        }
    };
    if let Err(error) = archive_manifest.validate_hash_provider(&provider) {
        return Ok(EstablishOutcomeV1::Failed(
            result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str()),
        ));
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
        return Ok(EstablishOutcomeV1::Failed(
            result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_MISSING_FILE"),
        ));
    }
    if disk_files.difference(&catalog_paths).next().is_some() {
        return Ok(EstablishOutcomeV1::Failed(
            result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_UNEXPECTED_FILE"),
        ));
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
            return Ok(EstablishOutcomeV1::Failed(
                result.fail(STAGE_CATALOG_FILES, "ARCHIVE_FILE_DIGEST_MISMATCH"),
            ));
        }
        files.insert(path.to_owned(), bytes);
    }

    // Every catalog file's current bytes were re-read and re-digested against
    // the freshly decoded manifest: the current identity is fully established.
    crate::instrumentation::record_catalog_revalidation();
    Ok(EstablishOutcomeV1::Established(EstablishedIdentityV1 {
        archive_hash,
        archive_manifest,
        files,
        result,
    }))
}

/// Completes the remaining verification stages from an already re-established
/// identity: election-artifact decode/binding, transport binding, governance
/// pin, deterministic ballot replay through Triptych proof verification, and the
/// archive-hash rebuild. These stages are a pure function of the read bytes.
///
/// This is the expensive work the Slice 4D memo skips on a cache hit. It
/// increments the full-verification, replay, and per-submission Triptych
/// counters at this authoritative boundary so a direct (non-memoized) verify â€”
/// including the live-driver seam â€” is also counted. The ballot replay uses
/// bounded batch verification ([`ARCHIVE_REPLAY_BATCH_SIZE_V1`]) with strictly
/// serial canonical application; the retained per-submission serial ingest is
/// kept as the parity reference for the equivalence tests.
pub(crate) fn finish_verification(
    established: EstablishedIdentityV1,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    finish_verification_replaying(established, ArchiveReplaySessionV1::replay_batched)
}

/// Completes the remaining verification stages using the retained pre-Stage-1
/// serial replay (one individual Triptych verify per submission). Test-only
/// parity reference: production replay is batched via [`finish_verification`].
#[cfg(test)]
pub(crate) fn finish_verification_serial_for_test(
    established: EstablishedIdentityV1,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    finish_verification_replaying(established, ArchiveReplaySessionV1::replay_serial_for_test)
}

/// Full-verification driver with an injected replay strategy. The strategy
/// computes per-submission cryptographic validity and applies it to the
/// authoritative transcript, nullifier ledger, and tally; every other stage is
/// identical for both strategies.
fn finish_verification_replaying(
    established: EstablishedIdentityV1,
    replay: impl FnOnce(&mut ArchiveReplaySessionV1, &[&[u8]]) -> Result<(), &'static str>,
) -> Result<ArchiveDirectoryVerificationV1, ArchiveVerifierError> {
    crate::instrumentation::record_full_verification();
    let provider = Blake3HashProviderV1;
    let EstablishedIdentityV1 {
        archive_hash,
        archive_manifest,
        files,
        mut result,
    } = established;
    let catalog_paths: BTreeSet<String> = archive_manifest
        .files()
        .entries()
        .iter()
        .map(|entry| entry.path().as_str().to_owned())
        .collect();

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
    result.election_manifest_schema_version = Some(artifacts.manifest().manifest_schema_version());
    result.proposal_question = artifacts.manifest().proposal_question().map(str::to_owned);
    // Public manifest/registry-derived fields for the V2 public anchor payload.
    // All read-only projections of already-decoded, already-verified artifacts.
    {
        let manifest = artifacts.manifest();
        result.election_id_hex = Some(to_lower_hex_slice(manifest.election_id().as_bytes()));
        result.ballot_kind_id = Some(manifest.ballot_kind().as_str().to_owned());
        result.ballot_confidentiality_id =
            Some(manifest.ballot_confidentiality().as_str().to_owned());
        result.proof_suite_id = Some(manifest.proof_suite_id().to_owned());
        result.registry_commitment_hex =
            Some(to_lower_hex(manifest.registry_commitment().as_bytes()));
        result.option_set_commitment_hex =
            Some(to_lower_hex(manifest.candidate_set_commitment().as_bytes()));
        result.eligible_voter_count = Some(artifacts.registry().entries().len() as u64);
    }

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
        result.transport_reduced_anonymity = Some(
            binding
                .batches()
                .iter()
                .any(|batch| batch.reduced_anonymity()),
        );
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
                    return Ok(
                        result.fail(STAGE_GOVERNANCE_PIN, "GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH")
                    );
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
    crate::instrumentation::record_historical_replay();
    let submission_packages: Vec<&[u8]> = submission_paths
        .iter()
        .map(|path| files[path].as_slice())
        .collect();
    if let Err(code) = replay(&mut session, &submission_packages) {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, code));
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
            let archive_path =
                ArchivePathV1::new(path.clone()).map_err(|_| ArchiveVerifierError::IoFailure)?;
            Ok(ArchiveFileEntryV1::for_bytes(
                archive_path,
                &provider,
                bytes,
            ))
        })
        .collect::<Result<Vec<_>, ArchiveVerifierError>>()?;
    let rebuilt_catalog =
        ArchiveFileCatalogV1::new(rebuilt_entries).map_err(|_| ArchiveVerifierError::IoFailure)?;
    let rebuilt_manifest = if archive_manifest.is_finalized_archive_manifest() {
        ArchiveManifestV1::finalized_for_provider(
            session.artifacts().manifest_hash(),
            rebuilt_catalog,
            &provider,
        )
    } else {
        ArchiveManifestV1::for_provider(
            session.artifacts().manifest_hash(),
            rebuilt_catalog,
            &provider,
        )
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
    manifest: ElectionManifest,
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
        let manifest = ElectionManifest::from_canonical_cbor(manifest_bytes)
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

    const fn manifest(&self) -> &ElectionManifest {
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
        let verifier =
            build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
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

    /// Replays every archived submission through bounded batch Triptych
    /// verification (archive verification Stage 1).
    ///
    /// Cryptographic proof validity for each contiguous canonical chunk of at
    /// most [`ARCHIVE_REPLAY_BATCH_SIZE_V1`] submissions is computed together
    /// by [`verify_approval_ballot_packages_batch_v1`], which returns exactly
    /// one result per submission, in submission order, and is guaranteed
    /// equivalent to the retained serial ingest per submission â€” including
    /// exact rejection codes and full-blame isolation of one invalid proof
    /// inside a failed batch. The ordered results are then applied to the
    /// authoritative transcript, nullifier ledger, and tally SEQUENTIALLY in
    /// canonical submission order, so every order-sensitive election semantic
    /// (nullifier insertion, duplicate rejection, first-valid-ballot-wins,
    /// transcript sequencing, accepted/rejected classification, tally) is
    /// byte-for-byte the serial behavior, independent of chunking.
    fn replay_batched(&mut self, packages: &[&[u8]]) -> Result<(), &'static str> {
        let provider = Blake3HashProviderV1;
        let mut results = Vec::with_capacity(packages.len());
        for chunk in packages.chunks(ARCHIVE_REPLAY_BATCH_SIZE_V1) {
            results.extend(verify_approval_ballot_packages_batch_v1(
                chunk,
                self.artifacts.manifest(),
                self.artifacts.candidates(),
                &provider,
                &self.verifier,
            ));
        }
        // Fail closed if the batch contract (exactly one result per input, in
        // input order) is ever broken; nothing is applied to the transcript.
        if results.len() != packages.len() {
            return Err(ValidationCode::InvalidData.as_str());
        }

        for (package_bytes, verification) in packages.iter().zip(results) {
            // One archived submission = one Triptych verify. The
            // qualification-counter semantic is preserved per submission even
            // though the cryptographic work is batched.
            crate::instrumentation::add_historical_triptych_verifies(1);
            self.apply_verified(package_bytes, verification)?;
        }
        Ok(())
    }

    /// Applies one already-computed per-submission verification result to the
    /// authoritative session, sequentially and in canonical submission order.
    ///
    /// This reproduces the retained serial ingest semantics exactly: transcript
    /// submission, then the combined (cryptographic validity â†’ ledger
    /// acceptance) decision, then transcript decision recording. A
    /// cryptographically invalid or structurally rejected submission records
    /// the same deterministic `Rejected(code)` decision the serial ingest would
    /// record; it never mutates the acceptance ledger.
    fn apply_verified(
        &mut self,
        package_bytes: &[u8],
        verification: Result<VerifiedApprovalBallotV1, ProtocolError>,
    ) -> Result<(), &'static str> {
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
        let outcome = match verification {
            Ok(ballot) => match self.ledger.accept_verified(&self.lifecycle, ballot) {
                Ok(()) => BallotDecisionOutcomeV1::Accepted,
                Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
            },
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };
        self.transcript
            .record_decision(sequence, digest, outcome)
            .map_err(|error| error.code().as_str())?;
        Ok(())
    }

    /// Retained pre-Stage-1 serial ingest: one full ingest (exactly one
    /// individual Triptych verify) per archived submission. Production replay
    /// is [`Self::replay_batched`]; this behavior is retained verbatim as the
    /// parity reference for the batch-equivalence tests.
    #[cfg(test)]
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

    /// Serial parity reference over the whole submission set: the exact replay
    /// loop `finish_verification` performed before Stage 1.
    #[cfg(test)]
    fn replay_serial_for_test(&mut self, packages: &[&[u8]]) -> Result<(), &'static str> {
        for package_bytes in packages {
            crate::instrumentation::add_historical_triptych_verifies(1);
            self.intake_ballot(package_bytes)?;
        }
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

fn read_bounded_archive_file(path: &Path, relative: &str) -> Result<Vec<u8>, ArchiveVerifierError> {
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
        let entries = std::fs::read_dir(&current).map_err(|_| ArchiveVerifierError::IoFailure)?;
        for entry in entries {
            let entry = entry.map_err(|_| ArchiveVerifierError::IoFailure)?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|_| ArchiveVerifierError::IoFailure)?;
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

#[cfg(test)]
mod tests {
    //! Stage 1 batch-replay equivalence tests.
    //!
    //! Every test proves the production batched replay
    //! ([`ArchiveReplaySessionV1::replay_batched`], batch 16) is exactly
    //! equivalent to the retained pre-Stage-1 serial replay
    //! ([`ArchiveReplaySessionV1::replay_serial_for_test`], one individual
    //! Triptych verify per submission): identical transcript submissions and
    //! decisions (including exact rejection codes), identical
    //! first-valid-ballot/duplicate-nullifier handling, identical tally, and â€”
    //! end to end through the full verifier â€” an identical
    //! [`ArchiveDirectoryVerificationV1`] report. The archive-verification
    //! counters are process-global, so every test that can touch them holds a
    //! shared lock across its reset/measure window.

    use super::*;
    use tari_cc_private_ballot_ballot::{
        ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
        BallotPackageEnvelopeV1, BallotPackageV1, BallotPackageV1Input, CandidateDefinition,
        CandidateId, CandidateSet, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_crypto::{
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
    };
    use tari_cc_private_ballot_protocol::{CanonicalCborWriter, PROTOCOL_VERSION_V1};
    use tari_cc_private_ballot_registry::RegistrySnapshot;
    use tari_cc_private_ballot_verifier::{
        build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    };

    use crate::{
        ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
        ArchiveVerificationMemoV1, archive_verification_snapshot,
        reset_archive_verification_counters,
    };

    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const SECRET_SCALARS: [u64; 3] = [7, 11, 13];
    const RISTRETTO_POINT_BYTES: usize = 32;

    fn scalar_bytes(value: u64) -> [u8; RISTRETTO_POINT_BYTES] {
        let mut bytes = [0_u8; RISTRETTO_POINT_BYTES];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn candidate_id(bytes: &[u8]) -> CandidateId {
        CandidateId::new(bytes.to_vec()).expect("test candidate ID must be valid")
    }

    fn candidate_set() -> CandidateSet {
        let definitions = [
            CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned()),
            CandidateDefinition::new(candidate_id(b"candidate-b"), "Candidate B".to_owned()),
            CandidateDefinition::new(candidate_id(b"candidate-c"), "Candidate C".to_owned()),
        ];
        let definitions: Vec<_> = definitions
            .into_iter()
            .map(|candidate| candidate.expect("test candidate must be valid"))
            .collect();
        CandidateSet::new(definitions).expect("test candidate set must be valid")
    }

    fn candidate_set_bytes() -> Vec<u8> {
        candidate_set()
            .to_canonical_cbor()
            .expect("test candidate set must encode")
    }

    fn registry_bytes() -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = SECRET_SCALARS
            .iter()
            .map(|scalar| {
                let secret = TariTriptychSecretKeyV1::from_canonical_bytes(scalar_bytes(*scalar))
                    .expect("test secret scalar must be canonical");
                secret
                    .governance_public_key()
                    .expect("test public key must derive")
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        keys.sort_unstable();
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(keys.len()).expect("array len");
        for key in keys {
            writer.write_byte_string(&key).expect("key encode");
        }
        writer.into_bytes()
    }

    fn registry() -> RegistrySnapshot {
        RegistrySnapshot::from_canonical_cbor(&registry_bytes()).expect("test registry must decode")
    }

    fn approval_limits() -> ApprovalLimits {
        ApprovalLimits::new(1, 2, false).expect("test approval limits must be valid")
    }

    fn manifest() -> ElectionManifestV1 {
        let provider = Blake3HashProviderV1;
        let registry_commitment = registry()
            .canonical_commitment(&provider)
            .expect("test registry commitment must derive");
        let candidate_set_commitment = candidate_set()
            .canonical_commitment(&provider)
            .expect("test candidate commitment must derive");
        let election_id = ElectionId::new(b"archive-batch-parity-election".to_vec())
            .expect("test election ID must be valid");
        ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "archive-batch-parity-test-revision".to_owned(),
        })
        .expect("test manifest must be valid")
    }

    fn manifest_bytes() -> Vec<u8> {
        manifest()
            .to_canonical_cbor()
            .expect("test manifest must encode")
    }

    /// Builds one real Triptych ballot package for `voter_index` selecting
    /// `selections`, mirroring the gui-core test fixtures.
    fn package_bytes(voter_index: usize, selections: &[&[u8]]) -> Vec<u8> {
        let provider = Blake3HashProviderV1;
        let manifest = manifest();
        let candidates = candidate_set();
        let registry = registry();
        let selection_ids: Vec<CandidateId> =
            selections.iter().map(|id| candidate_id(id)).collect();
        let payload = ApprovalBallotPayload::new(selection_ids, &candidates, approval_limits())
            .expect("test payload must be valid");
        let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &provider)
            .expect("test verifier must construct");
        let statement = reconstruct_approval_proof_statement(&manifest, &payload, &provider)
            .expect("test statement must reconstruct");
        let secret = TariTriptychSecretKeyV1::from_canonical_bytes(scalar_bytes(
            SECRET_SCALARS[voter_index],
        ))
        .expect("test secret must be canonical");
        let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret)
            .expect("test proof must construct");
        let manifest_hash = manifest
            .canonical_hash(&provider)
            .expect("test manifest hash must derive");
        let package = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash,
            proof_suite_id: manifest.proof_suite_id().to_owned(),
            proof,
            payload,
        })
        .expect("test package must be valid");
        package
            .to_canonical_cbor()
            .expect("test package must encode")
    }

    /// Builds a package whose proof authenticates a DIFFERENT statement: the
    /// donor's valid proof is spliced onto another voter's payload. The
    /// envelope and proof both parse, so this is the "cryptographically
    /// invalid inside a batch" case that must be isolated by full blame.
    fn cross_statement_package_bytes(donor_bytes: &[u8]) -> Vec<u8> {
        let provider = Blake3HashProviderV1;
        let manifest = manifest();
        let candidates = candidate_set();
        let donor = BallotPackageEnvelopeV1::from_canonical_cbor(donor_bytes)
            .expect("donor envelope must decode")
            .into_ballot_package(&candidates, approval_limits())
            .expect("donor package must decode");
        let recipient_selections: Vec<CandidateId> = vec![candidate_id(b"candidate-a")];
        let recipient_payload =
            ApprovalBallotPayload::new(recipient_selections, &candidates, approval_limits())
                .expect("recipient payload must be valid");
        let manifest_hash = manifest
            .canonical_hash(&provider)
            .expect("test manifest hash must derive");
        let package = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash,
            proof_suite_id: manifest.proof_suite_id().to_owned(),
            proof: donor.proof().to_vec(),
            payload: recipient_payload,
        })
        .expect("spliced package must be structurally valid");
        package
            .to_canonical_cbor()
            .expect("spliced package must encode")
    }

    fn open_replay_session() -> ArchiveReplaySessionV1 {
        let artifacts = ArchiveElectionArtifactsV1::from_bytes(
            &manifest_bytes(),
            &registry_bytes(),
            &candidate_set_bytes(),
        )
        .expect("test artifacts must load");
        let mut session =
            ArchiveReplaySessionV1::new(artifacts).expect("test replay session must construct");
        session.open().expect("test replay session must open");
        session
    }

    struct ParityCase {
        label: &'static str,
        packages: Vec<Vec<u8>>,
    }

    fn parity_cases() -> Vec<ParityCase> {
        let valid_a = package_bytes(0, &[b"candidate-a"]);
        let valid_b = package_bytes(1, &[b"candidate-b", b"candidate-c"]);
        let valid_c = package_bytes(2, &[b"candidate-c"]);
        let duplicate_of_a = package_bytes(0, &[b"candidate-b"]);
        let invalid_mid = cross_statement_package_bytes(&valid_b);
        let malformed = vec![0xff];
        vec![
            ParityCase {
                label: "all-valid",
                packages: vec![valid_a.clone(), valid_b.clone(), valid_c.clone()],
            },
            ParityCase {
                label: "one-invalid-proof-mid-batch",
                packages: vec![
                    valid_a.clone(),
                    invalid_mid,
                    valid_c.clone(),
                    valid_b.clone(),
                ],
            },
            ParityCase {
                label: "malformed-package",
                packages: vec![valid_a.clone(), malformed, valid_c.clone()],
            },
            ParityCase {
                label: "duplicate-nullifier-first-valid-wins",
                packages: vec![valid_a.clone(), duplicate_of_a, valid_c.clone()],
            },
        ]
    }

    #[test]
    fn batched_replay_matches_serial_replay_transcript_decision_for_decision() {
        let _guard = COUNTER_LOCK.lock().expect("counter lock");
        for case in parity_cases() {
            let label = case.label;
            let slices: Vec<&[u8]> = case.packages.iter().map(Vec::as_slice).collect();

            let mut serial = open_replay_session();
            serial
                .replay_serial_for_test(&slices)
                .unwrap_or_else(|code| panic!("serial replay must complete: {label}: {code}"));

            let mut batched = open_replay_session();
            batched
                .replay_batched(&slices)
                .unwrap_or_else(|code| panic!("batched replay must complete: {label}: {code}"));

            assert_eq!(
                serial.transcript(),
                batched.transcript(),
                "transcript parity failed for {label}",
            );
            assert_eq!(
                serial.transcript().accepted_count(),
                batched.transcript().accepted_count(),
                "accepted-count parity failed for {label}",
            );
            assert_eq!(
                serial.transcript().rejected_count(),
                batched.transcript().rejected_count(),
                "rejected-count parity failed for {label}",
            );

            let serial_tally = serial.direct_tally().expect("serial tally");
            let batched_tally = batched.direct_tally().expect("batched tally");
            let candidates = candidate_set();
            assert_eq!(
                summarize_tally(&serial_tally, &candidates),
                summarize_tally(&batched_tally, &candidates),
                "tally parity failed for {label}",
            );
        }
    }

    #[test]
    fn one_invalid_proof_in_a_batch_rejects_only_itself() {
        let _guard = COUNTER_LOCK.lock().expect("counter lock");
        let valid_a = package_bytes(0, &[b"candidate-a"]);
        let valid_b = package_bytes(1, &[b"candidate-b", b"candidate-c"]);
        let valid_c = package_bytes(2, &[b"candidate-c"]);
        let invalid = cross_statement_package_bytes(&valid_b);
        let packages = vec![valid_a, invalid, valid_c, valid_b];
        let slices: Vec<&[u8]> = packages.iter().map(Vec::as_slice).collect();

        let mut session = open_replay_session();
        session
            .replay_batched(&slices)
            .expect("batched replay must complete");

        let decisions = session.transcript().decisions();
        assert_eq!(decisions.len(), 4);
        assert!(
            decisions[0].outcome().is_accepted(),
            "valid neighbor before the invalid proof must stay accepted",
        );
        assert!(
            matches!(
                decisions[1].outcome(),
                BallotDecisionOutcomeV1::Rejected(ValidationCode::MalformedProof)
            ),
            "the invalid proof itself must receive the exact cryptographic rejection",
        );
        assert!(
            decisions[2].outcome().is_accepted(),
            "valid neighbor after the invalid proof must stay accepted",
        );
        assert!(
            decisions[3].outcome().is_accepted(),
            "valid tail of the batch must stay accepted",
        );
    }

    #[test]
    fn duplicate_nullifier_rejects_exactly_the_second_ballot() {
        let _guard = COUNTER_LOCK.lock().expect("counter lock");
        let first = package_bytes(1, &[b"candidate-a"]);
        let duplicate = package_bytes(1, &[b"candidate-b"]);
        let packages = vec![first, duplicate];
        let slices: Vec<&[u8]> = packages.iter().map(Vec::as_slice).collect();

        let mut session = open_replay_session();
        session
            .replay_batched(&slices)
            .expect("batched replay must complete");

        let decisions = session.transcript().decisions();
        assert!(decisions[0].outcome().is_accepted());
        assert!(
            matches!(
                decisions[1].outcome(),
                BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier)
            ),
            "the duplicate must receive the first-valid-ballot rejection",
        );
        assert_eq!(session.transcript().accepted_count(), 1);
    }

    fn test_dir(label: &str) -> std::path::PathBuf {
        static UNIQUE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = UNIQUE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "archive-batch-parity-{}-{label}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir must be creatable");
        dir
    }

    /// Writes one complete on-disk archive directory over the given packages,
    /// mirroring the gui-core archive writer layout (legacy V1 manifest).
    fn write_archive_dir(dir: &std::path::Path, packages: &[Vec<u8>]) {
        let provider = Blake3HashProviderV1;
        let manifest = manifest();
        let manifest_hash = manifest
            .canonical_hash(&provider)
            .expect("test manifest hash must derive");

        let mut files: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        files.insert(ELECTION_MANIFEST_ARCHIVE_PATH.to_owned(), manifest_bytes());
        files.insert(CANDIDATE_SET_ARCHIVE_PATH.to_owned(), candidate_set_bytes());
        files.insert(VOTER_REGISTRY_ARCHIVE_PATH.to_owned(), registry_bytes());
        for (index, package) in packages.iter().enumerate() {
            files.insert(
                format!("{SUBMISSIONS_ARCHIVE_DIR}/{index:08}.cbor"),
                package.clone(),
            );
        }

        let entries = files
            .iter()
            .map(|(path, bytes)| {
                let archive_path =
                    ArchivePathV1::new(path.clone()).expect("test archive path must be valid");
                ArchiveFileEntryV1::for_bytes(archive_path, &provider, bytes)
            })
            .collect::<Vec<_>>();
        let catalog = ArchiveFileCatalogV1::new(entries).expect("test catalog must construct");
        let archive_manifest = ArchiveManifestV1::for_provider(manifest_hash, catalog, &provider)
            .expect("test archive manifest must construct");
        let archive_manifest_bytes = archive_manifest
            .to_canonical_cbor()
            .expect("test archive manifest must encode");

        std::fs::create_dir_all(dir.join(SUBMISSIONS_ARCHIVE_DIR))
            .expect("submissions dir must be creatable");
        for (path, bytes) in &files {
            std::fs::write(dir.join(path), bytes).expect("archive file must write");
        }
        std::fs::write(
            dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH),
            archive_manifest_bytes,
        )
        .expect("archive manifest must write");
    }

    #[test]
    fn full_verification_report_parity_serial_vs_batched() {
        let _guard = COUNTER_LOCK.lock().expect("counter lock");
        for case in parity_cases() {
            let label = case.label;
            let dir = test_dir(case.label);
            write_archive_dir(&dir, &case.packages);

            let serial = verify_archive_directory_serial_for_test(&dir)
                .expect("serial full verification must complete");
            let batched =
                verify_archive_directory_v1(&dir).expect("batched full verification must complete");

            assert_eq!(serial, batched, "full report parity failed for {label}",);
            assert!(
                batched.verified,
                "verification must pass with rejected decisions recorded: {label}",
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn batched_full_verification_preserves_qualification_counter_semantics() {
        let _guard = COUNTER_LOCK.lock().expect("counter lock");
        reset_archive_verification_counters();

        let packages: Vec<Vec<u8>> = (0..5)
            .map(|index| {
                let selections: &[&[u8]] = match index % 3 {
                    0 => &[b"candidate-a"],
                    1 => &[b"candidate-b"],
                    _ => &[b"candidate-c"],
                };
                package_bytes(index % 3, selections)
            })
            .collect();
        let dir = test_dir("counter-semantics");
        write_archive_dir(&dir, &packages);

        let before = archive_verification_snapshot();
        let verification =
            verify_archive_directory_v1(&dir).expect("batched full verification must complete");
        assert!(verification.verified);
        let after = archive_verification_snapshot();

        assert_eq!(
            after.archive_full_verification_count - before.archive_full_verification_count,
            1
        );
        assert_eq!(
            after.archive_historical_replay_count - before.archive_historical_replay_count,
            1
        );
        assert_eq!(
            after.archive_historical_triptych_verifies
                - before.archive_historical_triptych_verifies,
            5,
            "one archived submission = one Triptych verify, preserved under batching",
        );

        // Memo behavior: a fresh memo's first request is a full (miss)
        // verification with the same counter semantics; the second request
        // over the unchanged archive is a hit that performs zero repeated
        // Triptych verifies and returns the identical report.
        let memo = ArchiveVerificationMemoV1::default();
        let miss_before = archive_verification_snapshot();
        let first = memo
            .verify(&dir)
            .expect("memo miss verification must complete");
        assert!(first.verified);
        let miss_after = archive_verification_snapshot();
        assert_eq!(
            miss_after.archive_historical_triptych_verifies
                - miss_before.archive_historical_triptych_verifies,
            5,
            "a memo miss performs the full replay with the same per-submission counters",
        );

        let hit_before = archive_verification_snapshot();
        let hit = memo
            .verify(&dir)
            .expect("memo hit verification must complete");
        assert!(hit.verified);
        assert_eq!(
            hit.as_ref(),
            first.as_ref(),
            "memo hit output equals the fresh verification report",
        );
        let hit_after = archive_verification_snapshot();
        assert_eq!(
            hit_after.archive_historical_triptych_verifies
                - hit_before.archive_historical_triptych_verifies,
            0,
            "a memo hit performs zero repeated historical Triptych verifies",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
