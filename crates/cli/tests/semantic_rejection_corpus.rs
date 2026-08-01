use std::{
    fs,
    path::{Path, PathBuf},
};

use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveHashV1,
    ArchiveManifestV1, ArchivePathV1, BallotDecisionOutcomeV1, BallotPackageDigestV1,
    IngestSequenceV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::test_only_verifier::TestOnlyProofVerifierV1;
use tari_cc_private_ballot_protocol::{
    CandidateSetCommitment, HashProvider, ManifestHash, PROTOCOL_VERSION_V1, ProtocolError,
    RegistryCommitment, TEST_ONLY_SUITE_ID, ValidationCode, test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    UnsupportedManifestVersion,
    UnsupportedPackageVersion,
    WrongManifestHash,
    UnsupportedProofSuite,
    EmptyProof,
    MalformedTestOnlyProof,
    ProofForOtherBallot,
    DuplicateNullifier,
    ElectionNotOpen,
    LifecycleWrongManifest,
    LifecycleWrongRegistry,
    DecisionWithoutSubmission,
    SkippedReplayDecision,
    DuplicateReplayDecision,
    ReplayDigestMismatch,
    IncompleteReplayTranscript,
    ArchiveFileDigestMismatch,
    ArchiveManifestHashMismatch,
    ArchiveProviderMismatch,
    ArchiveSelfReference,
}

#[derive(Debug, Clone, Copy)]
struct SemanticCase {
    id: &'static str,
    scenario: Scenario,
    expected: ValidationCode,
}

const CASES: &[SemanticCase] = &[
    SemanticCase {
        id: "unsupported-manifest-version",
        scenario: Scenario::UnsupportedManifestVersion,
        expected: ValidationCode::UnsupportedProtocolVersion,
    },
    SemanticCase {
        id: "unsupported-package-version",
        scenario: Scenario::UnsupportedPackageVersion,
        expected: ValidationCode::UnsupportedProtocolVersion,
    },
    SemanticCase {
        id: "wrong-manifest-hash",
        scenario: Scenario::WrongManifestHash,
        expected: ValidationCode::WrongManifestHash,
    },
    SemanticCase {
        id: "unsupported-proof-suite",
        scenario: Scenario::UnsupportedProofSuite,
        expected: ValidationCode::UnsupportedProofSuite,
    },
    SemanticCase {
        id: "empty-proof",
        scenario: Scenario::EmptyProof,
        expected: ValidationCode::InvalidData,
    },
    SemanticCase {
        id: "malformed-test-only-proof",
        scenario: Scenario::MalformedTestOnlyProof,
        expected: ValidationCode::InvalidData,
    },
    SemanticCase {
        id: "proof-for-other-ballot",
        scenario: Scenario::ProofForOtherBallot,
        expected: ValidationCode::InvalidData,
    },
    SemanticCase {
        id: "duplicate-nullifier",
        scenario: Scenario::DuplicateNullifier,
        expected: ValidationCode::DuplicateNullifier,
    },
    SemanticCase {
        id: "election-not-open",
        scenario: Scenario::ElectionNotOpen,
        expected: ValidationCode::ElectionNotOpen,
    },
    SemanticCase {
        id: "lifecycle-wrong-manifest",
        scenario: Scenario::LifecycleWrongManifest,
        expected: ValidationCode::WrongManifestHash,
    },
    SemanticCase {
        id: "lifecycle-wrong-registry",
        scenario: Scenario::LifecycleWrongRegistry,
        expected: ValidationCode::LifecycleCommitmentMismatch,
    },
    SemanticCase {
        id: "decision-without-submission",
        scenario: Scenario::DecisionWithoutSubmission,
        expected: ValidationCode::InvalidIngestSequence,
    },
    SemanticCase {
        id: "skipped-replay-decision",
        scenario: Scenario::SkippedReplayDecision,
        expected: ValidationCode::InvalidIngestSequence,
    },
    SemanticCase {
        id: "duplicate-replay-decision",
        scenario: Scenario::DuplicateReplayDecision,
        expected: ValidationCode::DuplicateBallotDecision,
    },
    SemanticCase {
        id: "replay-digest-mismatch",
        scenario: Scenario::ReplayDigestMismatch,
        expected: ValidationCode::BallotDecisionDigestMismatch,
    },
    SemanticCase {
        id: "incomplete-replay-transcript",
        scenario: Scenario::IncompleteReplayTranscript,
        expected: ValidationCode::IncompleteVerificationTranscript,
    },
    SemanticCase {
        id: "archive-file-digest-mismatch",
        scenario: Scenario::ArchiveFileDigestMismatch,
        expected: ValidationCode::ArchiveFileDigestMismatch,
    },
    SemanticCase {
        id: "archive-manifest-hash-mismatch",
        scenario: Scenario::ArchiveManifestHashMismatch,
        expected: ValidationCode::ArchiveManifestHashMismatch,
    },
    SemanticCase {
        id: "archive-provider-mismatch",
        scenario: Scenario::ArchiveProviderMismatch,
        expected: ValidationCode::UnsupportedHashAlgorithm,
    },
    SemanticCase {
        id: "archive-self-reference",
        scenario: Scenario::ArchiveSelfReference,
        expected: ValidationCode::InvalidArchiveManifest,
    },
];

#[derive(Debug, Clone, Copy)]
struct OtherHasher;

impl HashProvider for OtherHasher {
    fn algorithm_id(&self) -> &'static str {
        "OTHER_TEST_HASH_PROVIDER"
    }

    fn hash(&self, _framed_input: &[u8]) -> [u8; 32] {
        [0x55_u8; 32]
    }
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join("invalid")
        .join("semantic-v1")
}

fn case_root(case: SemanticCase) -> PathBuf {
    corpus_root().join(case.id)
}

fn read_case_text(case: SemanticCase, name: &str) -> String {
    let path = case_root(case).join(name);

    let Ok(text) = fs::read_to_string(&path) else {
        panic!(
            "failed to read semantic corpus metadata: {}",
            path.display()
        );
    };

    text
}

fn candidate_id(value: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(value.to_vec()) else {
        panic!("test candidate ID must be valid");
    };

    id
}

fn candidate(value: &[u8], name: &str) -> CandidateDefinition {
    let Ok(candidate) = CandidateDefinition::new(candidate_id(value), name.to_owned()) else {
        panic!("test candidate must be valid");
    };

    candidate
}

fn candidate_set() -> CandidateSet {
    let Ok(candidates) = CandidateSet::new(vec![
        candidate(b"a", "Candidate A"),
        candidate(b"b", "Candidate B"),
    ]) else {
        panic!("test candidate set must be valid");
    };

    candidates
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
        panic!("test approval limits must be valid");
    };

    limits
}

fn payload(selection: &[u8]) -> ApprovalBallotPayload {
    let candidates = candidate_set();

    let Ok(payload) = ApprovalBallotPayload::new(
        vec![candidate_id(selection)],
        &candidates,
        approval_limits(),
    ) else {
        panic!("test payload must be valid");
    };

    payload
}

fn election_id() -> ElectionId {
    let Ok(id) = ElectionId::new(b"semantic-pilot".to_vec()) else {
        panic!("test election ID must be valid");
    };

    id
}

fn manifest_input(
    protocol_version: u16,
    proof_suite_id: &str,
    registry_byte: u8,
) -> ElectionManifestV1Input {
    ElectionManifestV1Input {
        protocol_version,
        election_id: election_id(),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: RegistryCommitment::new([registry_byte; 32]),
        candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
        proof_suite_id: proof_suite_id.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "semantic-rev-1".to_owned(),
    }
}

fn manifest() -> ElectionManifestV1 {
    let Ok(manifest) =
        ElectionManifestV1::new(manifest_input(PROTOCOL_VERSION_V1, TEST_ONLY_SUITE_ID, 1))
    else {
        panic!("test manifest must be valid");
    };

    manifest
}

fn manifest_hash(
    manifest: &ElectionManifestV1,
    provider: &TestOnlyDeterministicHasher,
) -> ManifestHash {
    let Ok(hash) = manifest.canonical_hash(provider) else {
        panic!("test manifest hash must be valid");
    };

    hash
}

fn package(
    protocol_version: u16,
    manifest_hash: ManifestHash,
    proof_suite_id: &str,
) -> Result<BallotPackageV1, ProtocolError> {
    BallotPackageV1::new(BallotPackageV1Input {
        protocol_version,
        manifest_hash,
        proof_suite_id: proof_suite_id.to_owned(),
        proof: b"TEST_ONLY_TRANSPORT_PROOF".to_vec(),
        payload: payload(b"a"),
    })
}

fn verified_ballot(
    manifest: &ElectionManifestV1,
    ballot_payload: &ApprovalBallotPayload,
    nullifier: &[u8],
) -> VerifiedApprovalBallotV1 {
    let provider = TestOnlyDeterministicHasher;

    let Ok(statement) = reconstruct_approval_proof_statement(manifest, ballot_payload, &provider)
    else {
        panic!("test proof statement must be valid");
    };

    let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
        panic!("test proof bytes must be valid");
    };

    let Ok(verifier) = TestOnlyProofVerifierV1::new(nullifier.to_vec()) else {
        panic!("test verifier must be valid");
    };

    let Ok(ballot) = verify_approval_proof(manifest, ballot_payload, &proof, &provider, &verifier)
    else {
        panic!("test ballot verification must succeed");
    };

    ballot
}

fn frozen_lifecycle(
    manifest: &ElectionManifestV1,
    frozen_manifest_hash: ManifestHash,
    registry_byte: u8,
    open: bool,
) -> Result<ElectionLifecycleV1, ProtocolError> {
    let mut lifecycle = ElectionLifecycleV1::new();

    lifecycle.freeze(
        frozen_manifest_hash,
        RegistryCommitment::new([registry_byte; 32]),
    )?;

    if open {
        lifecycle.open()?;
    }

    let _ = manifest;

    Ok(lifecycle)
}

fn archive_path(value: &str) -> ArchivePathV1 {
    let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
        panic!("test archive path must be valid");
    };

    path
}

fn archive_catalog(provider: &TestOnlyDeterministicHasher, path: &str) -> ArchiveFileCatalogV1 {
    let entry =
        ArchiveFileEntryV1::for_bytes(archive_path(path), provider, b"semantic archive bytes");

    let Ok(catalog) = ArchiveFileCatalogV1::new(vec![entry]) else {
        panic!("test archive catalog must be valid");
    };

    catalog
}

fn archive_manifest(provider: &TestOnlyDeterministicHasher) -> ArchiveManifestV1 {
    let Ok(manifest) = ArchiveManifestV1::for_provider(
        ManifestHash::new([1_u8; 32]),
        archive_catalog(provider, "manifest.cbor"),
        provider,
    ) else {
        panic!("test archive manifest must be valid");
    };

    manifest
}

fn execute_scenario(scenario: Scenario) -> Result<(), ProtocolError> {
    match scenario {
        Scenario::UnsupportedManifestVersion => {
            ElectionManifestV1::new(manifest_input(2, TEST_ONLY_SUITE_ID, 1)).map(|_| ())
        }
        Scenario::UnsupportedPackageVersion => {
            package(2, ManifestHash::new([5_u8; 32]), TEST_ONLY_SUITE_ID).map(|_| ())
        }
        Scenario::WrongManifestHash => {
            let package = package(
                PROTOCOL_VERSION_V1,
                ManifestHash::new([5_u8; 32]),
                TEST_ONLY_SUITE_ID,
            )?;

            package.validate_manifest_binding(ManifestHash::new([9_u8; 32]), TEST_ONLY_SUITE_ID)
        }
        Scenario::UnsupportedProofSuite => {
            let expected_manifest = ManifestHash::new([5_u8; 32]);
            let package = package(PROTOCOL_VERSION_V1, expected_manifest, TEST_ONLY_SUITE_ID)?;

            package.validate_manifest_binding(expected_manifest, "OTHER_SUITE")
        }
        Scenario::EmptyProof => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let ballot_payload = payload(b"a");
            let verifier = TestOnlyProofVerifierV1::new(b"empty-proof-nf".to_vec())?;

            verify_approval_proof(&manifest, &ballot_payload, &[], &provider, &verifier).map(|_| ())
        }
        Scenario::MalformedTestOnlyProof => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let ballot_payload = payload(b"a");
            let verifier = TestOnlyProofVerifierV1::new(b"malformed-proof-nf".to_vec())?;

            verify_approval_proof(
                &manifest,
                &ballot_payload,
                b"not-a-valid-test-proof",
                &provider,
                &verifier,
            )
            .map(|_| ())
        }
        Scenario::ProofForOtherBallot => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let first_payload = payload(b"a");
            let second_payload = payload(b"b");
            let verifier = TestOnlyProofVerifierV1::new(b"other-ballot-nf".to_vec())?;

            let statement =
                reconstruct_approval_proof_statement(&manifest, &first_payload, &provider)?;

            let proof = TestOnlyProofVerifierV1::proof_for(&statement)?;

            verify_approval_proof(&manifest, &second_payload, &proof, &provider, &verifier)
                .map(|_| ())
        }
        Scenario::DuplicateNullifier => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let hash = manifest_hash(&manifest, &provider);
            let lifecycle = frozen_lifecycle(&manifest, hash, 1, true)?;
            let ballot_payload = payload(b"a");
            let first = verified_ballot(&manifest, &ballot_payload, b"duplicate-nf");
            let second = verified_ballot(&manifest, &ballot_payload, b"duplicate-nf");
            let mut ledger = BallotAcceptanceLedger::new();

            ledger.accept_verified(&lifecycle, first)?;
            ledger.accept_verified(&lifecycle, second)
        }
        Scenario::ElectionNotOpen => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let hash = manifest_hash(&manifest, &provider);
            let lifecycle = frozen_lifecycle(&manifest, hash, 1, false)?;
            let ballot_payload = payload(b"a");
            let ballot = verified_ballot(&manifest, &ballot_payload, b"frozen-nf");
            let mut ledger = BallotAcceptanceLedger::new();

            ledger.accept_verified(&lifecycle, ballot)
        }
        Scenario::LifecycleWrongManifest => {
            let manifest = manifest();
            let lifecycle = frozen_lifecycle(&manifest, ManifestHash::new([9_u8; 32]), 1, true)?;
            let ballot_payload = payload(b"a");
            let ballot = verified_ballot(&manifest, &ballot_payload, b"wrong-manifest-nf");
            let mut ledger = BallotAcceptanceLedger::new();

            ledger.accept_verified(&lifecycle, ballot)
        }
        Scenario::LifecycleWrongRegistry => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = manifest();
            let hash = manifest_hash(&manifest, &provider);
            let lifecycle = frozen_lifecycle(&manifest, hash, 9, true)?;
            let ballot_payload = payload(b"a");
            let ballot = verified_ballot(&manifest, &ballot_payload, b"wrong-registry-nf");
            let mut ledger = BallotAcceptanceLedger::new();

            ledger.accept_verified(&lifecycle, ballot)
        }
        Scenario::DecisionWithoutSubmission => {
            let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([1_u8; 32]));

            transcript.record_decision(
                IngestSequenceV1::new(0),
                BallotPackageDigestV1::new([1_u8; 32]),
                BallotDecisionOutcomeV1::Accepted,
            )
        }
        Scenario::SkippedReplayDecision => {
            let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([1_u8; 32]));

            let _first =
                transcript.record_submission(BallotPackageDigestV1::new([1_u8; 32]), true)?;

            let second =
                transcript.record_submission(BallotPackageDigestV1::new([2_u8; 32]), true)?;

            transcript.record_decision(
                second,
                BallotPackageDigestV1::new([2_u8; 32]),
                BallotDecisionOutcomeV1::Accepted,
            )
        }
        Scenario::DuplicateReplayDecision => {
            let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([1_u8; 32]));

            let sequence =
                transcript.record_submission(BallotPackageDigestV1::new([1_u8; 32]), true)?;

            transcript.record_decision(
                sequence,
                BallotPackageDigestV1::new([1_u8; 32]),
                BallotDecisionOutcomeV1::Accepted,
            )?;

            transcript.record_decision(
                sequence,
                BallotPackageDigestV1::new([1_u8; 32]),
                BallotDecisionOutcomeV1::Accepted,
            )
        }
        Scenario::ReplayDigestMismatch => {
            let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([1_u8; 32]));

            let sequence =
                transcript.record_submission(BallotPackageDigestV1::new([1_u8; 32]), true)?;

            transcript.record_decision(
                sequence,
                BallotPackageDigestV1::new([9_u8; 32]),
                BallotDecisionOutcomeV1::Accepted,
            )
        }
        Scenario::IncompleteReplayTranscript => {
            let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([1_u8; 32]));

            let _sequence =
                transcript.record_submission(BallotPackageDigestV1::new([1_u8; 32]), true)?;

            transcript.validate_complete()
        }
        Scenario::ArchiveFileDigestMismatch => {
            let provider = TestOnlyDeterministicHasher;

            let entry = ArchiveFileEntryV1::for_bytes(
                archive_path("manifest.cbor"),
                &provider,
                b"original bytes",
            );

            entry.verify_bytes(&provider, b"changed bytes")
        }
        Scenario::ArchiveManifestHashMismatch => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = archive_manifest(&provider);

            manifest.verify_hash(&provider, ArchiveHashV1::new([9_u8; 32]))
        }
        Scenario::ArchiveProviderMismatch => {
            let provider = TestOnlyDeterministicHasher;
            let manifest = archive_manifest(&provider);

            manifest.canonical_hash(&OtherHasher).map(|_| ())
        }
        Scenario::ArchiveSelfReference => {
            let provider = TestOnlyDeterministicHasher;

            ArchiveManifestV1::for_provider(
                ManifestHash::new([1_u8; 32]),
                archive_catalog(&provider, ARCHIVE_MANIFEST_CANONICAL_PATH),
                &provider,
            )
            .map(|_| ())
        }
    }
}

fn rejection_code(case: SemanticCase) -> ValidationCode {
    let result = execute_scenario(case.scenario);

    let Err(error) = result else {
        panic!(
            "semantic rejection case unexpectedly succeeded: {}",
            case.id
        );
    };

    error.code()
}

#[test]
fn semantic_rejection_corpus_layout_is_complete() {
    assert_eq!(CASES.len(), 20);

    for case in CASES {
        let root = case_root(*case);

        for required_name in ["description.md", "scenario.json", "expected.json"] {
            let path = root.join(required_name);

            assert!(
                path.is_file(),
                "missing semantic corpus file for {}: {}",
                case.id,
                path.display()
            );
        }

        let description = read_case_text(*case, "description.md");
        assert!(!description.trim().is_empty());

        let scenario = read_case_text(*case, "scenario.json");
        assert!(scenario.contains("phase2-semantic-rejection-case-v1"));
        assert!(scenario.contains(case.id));
        assert!(scenario.contains("constructed-public-api-scenario"));

        let expected = read_case_text(*case, "expected.json");
        assert!(expected.contains("phase2-semantic-rejection-expected-v1"));
        assert!(expected.contains(case.id));
        assert!(expected.contains(case.expected.as_str()));
        assert!(expected.contains("\"accepted\": false"));
    }
}

#[test]
fn semantic_rejection_corpus_returns_exact_codes() {
    for case in CASES {
        assert_eq!(
            rejection_code(*case),
            case.expected,
            "wrong semantic rejection code for {}",
            case.id
        );
    }
}

#[test]
fn semantic_rejection_codes_are_deterministic() {
    for case in CASES {
        let first = rejection_code(*case);

        for _ in 0..3 {
            assert_eq!(
                rejection_code(*case),
                first,
                "nondeterministic semantic rejection for {}",
                case.id
            );
        }
    }
}
