use std::{
    fs,
    path::{Path, PathBuf},
};

use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionManifestV1, ElectionManifestV1Input, ElectionManifestV2, ElectionManifestV2Input,
};
use tari_cc_private_ballot_crypto::test_only_verifier::{
    TEST_ONLY_PROOF_MARKER, TestOnlyProofVerifierV1,
};
use tari_cc_private_ballot_protocol::{
    HashDomain, PROTOCOL_VERSION_V1, TEST_ONLY_SUITE_ID, hash_domain_separated,
    test_only::{TEST_ONLY_HASH_ALGORITHM_ID, TestOnlyDeterministicHasher},
};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
};
use tari_cc_private_ballot_verifier::{
    reconstruct_approval_proof_statement, verify_approval_proof,
};

const REQUIRED_CASE_FILES: &[&str] = &[
    "description.md",
    "input.json",
    "canonical.cbor",
    "canonical.hex",
    "expected.json",
    "expected-hashes.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionType {
    CandidateElection,
    BallotMeasure,
}

impl DecisionType {
    const fn slug(self) -> &'static str {
        match self {
            Self::CandidateElection => "candidate-election",
            Self::BallotMeasure => "ballot-measure",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CandidateElection => "Candidate election",
            Self::BallotMeasure => "Ballot measure",
        }
    }

    const fn governance_revision(self) -> &'static str {
        match self {
            Self::CandidateElection => "candidate-roster-revision-2026-08-01",
            Self::BallotMeasure => "ballot-measure-revision-2026-08-01",
        }
    }

    const fn proposal_question(self) -> &'static str {
        match self {
            Self::CandidateElection => "Which council candidates should advance?",
            Self::BallotMeasure => "Should the council adopt the ballot measure?",
        }
    }

    const fn election_identifier(self) -> &'static [u8] {
        match self {
            Self::CandidateElection => b"council-candidate-election-pilot-0001",
            Self::BallotMeasure => b"council-ballot-measure-pilot-0001",
        }
    }

    const fn nullifier(self) -> &'static [u8] {
        match self {
            Self::CandidateElection => b"candidate-election-nullifier-0001",
            Self::BallotMeasure => b"ballot-measure-nullifier-0001",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::CandidateElection => {
                "A public, non-binding approval election selecting Council candidates by stable machine identifiers."
            }
            Self::BallotMeasure => {
                "A public, non-binding ballot measure selecting approve or reject while permitting an empty abstention ballot."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VectorKind {
    ElectionManifestV1,
    ElectionManifestV2,
    BallotPackage,
    ArchiveManifest,
}

impl VectorKind {
    const fn slug(self) -> &'static str {
        match self {
            Self::ElectionManifestV1 => "election-manifest",
            Self::ElectionManifestV2 => "election-manifest-v2",
            Self::BallotPackage => "ballot-package",
            Self::ArchiveManifest => "archive-manifest",
        }
    }

    const fn object_family(self) -> &'static str {
        match self {
            Self::ElectionManifestV1 => "election-manifest-v1",
            Self::ElectionManifestV2 => "election-manifest-v2",
            Self::BallotPackage => "ballot-package-v1",
            Self::ArchiveManifest => "archive-manifest-v1",
        }
    }

    const fn decoder_target(self) -> &'static str {
        match self {
            Self::ElectionManifestV1 => "ElectionManifestV1::from_canonical_cbor",
            Self::ElectionManifestV2 => "ElectionManifestV2::from_canonical_cbor",
            Self::BallotPackage => "BallotPackageV1::from_canonical_cbor",
            Self::ArchiveManifest => "ArchiveManifestV1::from_canonical_cbor",
        }
    }

    const fn hash_domain(self) -> HashDomain {
        match self {
            Self::ElectionManifestV1 => HashDomain::ElectionManifestV1,
            Self::ElectionManifestV2 => HashDomain::ElectionManifestV2,
            Self::BallotPackage => HashDomain::BallotPackageV1,
            Self::ArchiveManifest => HashDomain::ArchiveManifestV1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedVector {
    id: String,
    decision_type: DecisionType,
    kind: VectorKind,
    canonical: Vec<u8>,
    digest: [u8; 32],
}

impl PublishedVector {
    fn description_markdown(&self) -> String {
        let proof_note = match self.kind {
            VectorKind::BallotPackage => format!(
                "\nThe package contains the explicit forgeable proof marker `{TEST_ONLY_PROOF_MARKER}` and is not anonymous or suitable for binding elections.\n"
            ),
            VectorKind::ElectionManifestV1
            | VectorKind::ElectionManifestV2
            | VectorKind::ArchiveManifest => {
                "\nThe object commits to the reserved test-only proof or hash plumbing and is not suitable for binding elections.\n".to_owned()
            }
        };

        format!(
            "# {}\n\n{}\n\nDecision type: `{}`.\n\nObject family: `{}`.\n{}\nThe canonical CBOR bytes are authoritative. JSON and hexadecimal files are presentation artifacts.\n",
            self.id,
            self.decision_type.summary(),
            self.decision_type.slug(),
            self.kind.object_family(),
            proof_note,
        )
    }

    fn input_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"tari-cc-private-ballot-valid-input-v1\",\n",
                "  \"vector_id\": \"{}\",\n",
                "  \"object_family\": \"{}\",\n",
                "  \"decision_type\": \"{}\",\n",
                "  \"decision_label\": \"{}\",\n",
                "  \"ballot_kind\": \"NON_BINDING_APPROVAL_PILOT\",\n",
                "  \"ballot_confidentiality\": \"PUBLIC\",\n",
                "  \"proof_suite_id\": \"{}\",\n",
                "  \"allows_abstention\": true\n",
                "}}\n",
            ),
            self.id,
            self.kind.object_family(),
            self.decision_type.slug(),
            self.decision_type.label(),
            TEST_ONLY_SUITE_ID,
        )
    }

    fn expected_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"tari-cc-private-ballot-valid-result-v1\",\n",
                "  \"vector_id\": \"{}\",\n",
                "  \"decision_type\": \"{}\",\n",
                "  \"accepted\": true,\n",
                "  \"decoder_target\": \"{}\",\n",
                "  \"canonical_byte_length\": {},\n",
                "  \"canonical_encoding\": \"deterministic-cbor-rfc8949-4.2.1\"\n",
                "}}\n",
            ),
            self.id,
            self.decision_type.slug(),
            self.kind.decoder_target(),
            self.canonical.len(),
        )
    }

    fn expected_hashes_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"tari-cc-private-ballot-valid-hash-v1\",\n",
                "  \"vector_id\": \"{}\",\n",
                "  \"decision_type\": \"{}\",\n",
                "  \"hash_algorithm_id\": \"{}\",\n",
                "  \"domain_label\": \"{}\",\n",
                "  \"digest_hex\": \"{}\"\n",
                "}}\n",
            ),
            self.id,
            self.decision_type.slug(),
            TEST_ONLY_HASH_ALGORITHM_ID,
            self.kind.hash_domain().label(),
            lowercase_hex(&self.digest),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecisionFixture {
    decision_type: DecisionType,
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    limits: ApprovalLimits,
    manifest: ElectionManifestV1,
    manifest_v2: ElectionManifestV2,
    package: BallotPackageV1,
    archive_manifest: ArchiveManifestV1,
    archive_files: Vec<(String, Vec<u8>)>,
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join("valid")
        .join("canonical-v1")
}

fn case_root(case: &PublishedVector) -> PathBuf {
    vector_root().join(&case.id)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

fn governance_entry(bytes: &[u8]) -> RegistryEntry {
    let Ok(key) = GovernancePublicKey::new(bytes.to_vec()) else {
        panic!("published governance key must be valid");
    };

    let registration =
        VoterGovernanceKeyRegistrationV1::new(key, VoterKeyProvisioningV1::GeneratedByVoter);

    RegistryEntry::from_voter_registration(registration)
}

fn registry_snapshot(decision_type: DecisionType) -> RegistrySnapshot {
    let entries = match decision_type {
        DecisionType::CandidateElection => vec![
            governance_entry(b"candidate-election-voter-charlie"),
            governance_entry(b"candidate-election-voter-alpha"),
            governance_entry(b"candidate-election-voter-bravo"),
        ],
        DecisionType::BallotMeasure => vec![
            governance_entry(b"ballot-measure-voter-charlie"),
            governance_entry(b"ballot-measure-voter-alpha"),
            governance_entry(b"ballot-measure-voter-bravo"),
        ],
    };

    let Ok(snapshot) = RegistrySnapshot::new(entries) else {
        panic!("published registry snapshot must be valid");
    };

    snapshot
}

fn candidate_id(value: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(value.to_vec()) else {
        panic!("published option identifier must be valid");
    };

    id
}

fn candidate(value: &[u8], display_name: &str) -> CandidateDefinition {
    let Ok(candidate) = CandidateDefinition::new(candidate_id(value), display_name.to_owned())
    else {
        panic!("published selectable option must be valid");
    };

    candidate
}

fn candidate_set(decision_type: DecisionType) -> CandidateSet {
    let definitions = match decision_type {
        DecisionType::CandidateElection => vec![
            candidate(b"candidate-charlie", "Candidate Charlie"),
            candidate(b"candidate-alpha", "Candidate Alpha"),
            candidate(b"candidate-bravo", "Candidate Bravo"),
        ],
        DecisionType::BallotMeasure => vec![
            candidate(b"reject", "Reject the Measure"),
            candidate(b"approve", "Approve the Measure"),
        ],
    };

    let Ok(candidates) = CandidateSet::new(definitions) else {
        panic!("published selectable-option set must be valid");
    };

    candidates
}

fn approval_limits(decision_type: DecisionType) -> ApprovalLimits {
    let result = match decision_type {
        DecisionType::CandidateElection => ApprovalLimits::new(1, 2, true),
        DecisionType::BallotMeasure => ApprovalLimits::new(1, 1, true),
    };

    let Ok(limits) = result else {
        panic!("published approval limits must be valid");
    };

    limits
}

fn approval_payload(
    decision_type: DecisionType,
    candidates: &CandidateSet,
    limits: ApprovalLimits,
) -> ApprovalBallotPayload {
    let selections = match decision_type {
        DecisionType::CandidateElection => vec![
            candidate_id(b"candidate-charlie"),
            candidate_id(b"candidate-alpha"),
        ],
        DecisionType::BallotMeasure => vec![candidate_id(b"approve")],
    };

    let Ok(payload) = ApprovalBallotPayload::new(selections, candidates, limits) else {
        panic!("published approval payload must be valid");
    };

    payload
}

fn archive_path(value: &str) -> ArchivePathV1 {
    let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
        panic!("published archive path must be valid");
    };

    path
}

fn fixture(decision_type: DecisionType) -> DecisionFixture {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry_snapshot(decision_type);
    let candidates = candidate_set(decision_type);
    let limits = approval_limits(decision_type);

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("published registry commitment must succeed");
    };

    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("published candidate-set commitment must succeed");
    };

    let Ok(election_id) = ElectionId::new(decision_type.election_identifier().to_vec()) else {
        panic!("published decision identifier must be valid");
    };

    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        approval_limits: limits,
        governance_source_revision: decision_type.governance_revision().to_owned(),
    }) else {
        panic!("published election manifest must be valid");
    };

    let Ok(v2_election_id) = ElectionId::new(decision_type.election_identifier().to_vec()) else {
        panic!("published decision identifier must be valid");
    };

    let Ok(manifest_v2) = ElectionManifestV2::new(ElectionManifestV2Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: v2_election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        approval_limits: limits,
        governance_source_revision: decision_type.governance_revision().to_owned(),
        proposal_question: decision_type.proposal_question().to_owned(),
    }) else {
        panic!("published version-two election manifest must be valid");
    };

    let payload = approval_payload(decision_type, &candidates, limits);

    let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &payload, &provider) else {
        panic!("published proof statement reconstruction must succeed");
    };

    let Ok(proof) =
        TestOnlyProofVerifierV1::proof_for_with_nullifier(&statement, decision_type.nullifier())
    else {
        panic!("published test-only proof generation must succeed");
    };

    assert!(proof.starts_with(TEST_ONLY_PROOF_MARKER.as_bytes()));

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("published election-manifest hash must succeed");
    };

    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        proof,
        payload,
    }) else {
        panic!("published ballot package must be valid");
    };

    let Ok(registry_bytes) = registry.to_canonical_cbor() else {
        panic!("published registry encoding must succeed");
    };

    let Ok(candidate_bytes) = candidates.to_canonical_cbor() else {
        panic!("published candidate-set encoding must succeed");
    };

    let Ok(manifest_bytes) = manifest.to_canonical_cbor() else {
        panic!("published election-manifest encoding must succeed");
    };

    let Ok(package_bytes) = package.to_canonical_cbor() else {
        panic!("published ballot-package encoding must succeed");
    };

    let archive_files = vec![
        ("ballots/ballot-0001.cbor".to_owned(), package_bytes),
        ("candidate-set.cbor".to_owned(), candidate_bytes),
        ("election-manifest.cbor".to_owned(), manifest_bytes),
        ("registry.cbor".to_owned(), registry_bytes),
    ];

    let entries = archive_files
        .iter()
        .map(|(path, bytes)| ArchiveFileEntryV1::for_bytes(archive_path(path), &provider, bytes))
        .collect();

    let Ok(catalog) = ArchiveFileCatalogV1::new(entries) else {
        panic!("published archive file catalog must be valid");
    };

    let Ok(archive_manifest) = ArchiveManifestV1::for_provider(manifest_hash, catalog, &provider)
    else {
        panic!("published archive manifest must be valid");
    };

    DecisionFixture {
        decision_type,
        registry,
        candidates,
        limits,
        manifest,
        manifest_v2,
        package,
        archive_manifest,
        archive_files,
    }
}

fn published_vector(fixture: &DecisionFixture, kind: VectorKind) -> PublishedVector {
    let provider = TestOnlyDeterministicHasher;

    let (canonical, digest) = match kind {
        VectorKind::ElectionManifestV1 => {
            let Ok(canonical) = fixture.manifest.to_canonical_cbor() else {
                panic!("published election-manifest encoding must succeed");
            };

            let Ok(hash) = fixture.manifest.canonical_hash(&provider) else {
                panic!("published election-manifest hash must succeed");
            };

            (canonical, hash.into_bytes())
        }
        VectorKind::ElectionManifestV2 => {
            let Ok(canonical) = fixture.manifest_v2.to_canonical_cbor() else {
                panic!("published version-two election-manifest encoding must succeed");
            };

            let Ok(hash) = fixture.manifest_v2.canonical_hash(&provider) else {
                panic!("published version-two election-manifest hash must succeed");
            };

            (canonical, hash.into_bytes())
        }
        VectorKind::BallotPackage => {
            let Ok(canonical) = fixture.package.to_canonical_cbor() else {
                panic!("published ballot-package encoding must succeed");
            };

            let Ok(hash) = fixture.package.canonical_hash(&provider) else {
                panic!("published ballot-package hash must succeed");
            };

            (canonical, hash)
        }
        VectorKind::ArchiveManifest => {
            let Ok(canonical) = fixture.archive_manifest.to_canonical_cbor() else {
                panic!("published archive-manifest encoding must succeed");
            };

            let Ok(hash) = fixture.archive_manifest.canonical_hash(&provider) else {
                panic!("published archive-manifest hash must succeed");
            };

            (canonical, hash.into_bytes())
        }
    };

    assert_eq!(
        digest,
        hash_domain_separated(&provider, kind.hash_domain(), &canonical),
    );

    PublishedVector {
        id: format!("{}-{}", kind.slug(), fixture.decision_type.slug()),
        decision_type: fixture.decision_type,
        kind,
        canonical,
        digest,
    }
}

fn vectors() -> Vec<PublishedVector> {
    let mut vectors = Vec::new();

    for decision_type in [DecisionType::CandidateElection, DecisionType::BallotMeasure] {
        let fixture = fixture(decision_type);

        for kind in [
            VectorKind::ElectionManifestV1,
            VectorKind::ElectionManifestV2,
            VectorKind::BallotPackage,
            VectorKind::ArchiveManifest,
        ] {
            vectors.push(published_vector(&fixture, kind));
        }
    }

    vectors
}

fn write_text(path: &Path, text: &str) {
    if let Err(error) = fs::write(path, text.as_bytes()) {
        panic!("failed to write {}: {error}", path.display());
    }
}

fn write_case(case: &PublishedVector) {
    let root = case_root(case);

    if let Err(error) = fs::create_dir_all(&root) {
        panic!("failed to create {}: {error}", root.display());
    }

    write_text(&root.join("description.md"), &case.description_markdown());
    write_text(&root.join("input.json"), &case.input_json());

    if let Err(error) = fs::write(root.join("canonical.cbor"), &case.canonical) {
        panic!("failed to write canonical bytes for {}: {error}", case.id);
    }

    write_text(
        &root.join("canonical.hex"),
        &(lowercase_hex(&case.canonical) + "\n"),
    );
    write_text(&root.join("expected.json"), &case.expected_json());
    write_text(
        &root.join("expected-hashes.json"),
        &case.expected_hashes_json(),
    );
}

fn read_text(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        panic!("failed to read text fixture: {}", path.display());
    };

    text.replace("\r\n", "\n")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    let Ok(bytes) = fs::read(path) else {
        panic!("failed to read binary fixture: {}", path.display());
    };

    bytes
}

fn directory_entry_names(path: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(path) else {
        panic!("failed to enumerate fixture directory: {}", path.display());
    };

    let mut names = Vec::new();

    for entry in entries {
        let Ok(entry) = entry else {
            panic!("failed to read an entry under {}", path.display());
        };

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            panic!(
                "fixture path contains non-UTF-8 text under {}",
                path.display()
            );
        };

        names.push(name);
    }

    names.sort();
    names
}

fn decode_and_reencode(case: &PublishedVector, canonical: &[u8]) -> Vec<u8> {
    let provider = TestOnlyDeterministicHasher;
    let fixture = fixture(case.decision_type);

    match case.kind {
        VectorKind::ElectionManifestV1 => {
            let Ok(decoded) = ElectionManifestV1::from_canonical_cbor(canonical) else {
                panic!("published election-manifest vector must decode");
            };

            assert_eq!(decoded, fixture.manifest);
            assert_eq!(
                decoded.election_id().as_bytes(),
                case.decision_type.election_identifier()
            );
            assert_eq!(
                decoded.governance_source_revision(),
                case.decision_type.governance_revision(),
            );

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published election-manifest vector must re-encode");
            };

            reencoded
        }
        VectorKind::ElectionManifestV2 => {
            let Ok(decoded) = ElectionManifestV2::from_canonical_cbor(canonical) else {
                panic!("published version-two election-manifest vector must decode");
            };

            assert_eq!(decoded, fixture.manifest_v2);
            assert_eq!(
                decoded.election_id().as_bytes(),
                case.decision_type.election_identifier()
            );
            assert_eq!(
                decoded.governance_source_revision(),
                case.decision_type.governance_revision(),
            );
            assert_eq!(
                decoded.proposal_question(),
                case.decision_type.proposal_question(),
            );

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published version-two election-manifest vector must re-encode");
            };

            reencoded
        }
        VectorKind::BallotPackage => {
            let Ok(decoded) = BallotPackageV1::from_canonical_cbor(
                canonical,
                &fixture.candidates,
                fixture.limits,
            ) else {
                panic!("published ballot-package vector must decode");
            };

            assert_eq!(decoded, fixture.package);

            let Ok(manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
                panic!("published manifest hash must succeed");
            };

            assert!(
                decoded
                    .validate_manifest_binding(manifest_hash, TEST_ONLY_SUITE_ID)
                    .is_ok()
            );

            let verifier = TestOnlyProofVerifierV1::replay();

            let Ok(verified) = verify_approval_proof(
                &fixture.manifest,
                decoded.payload(),
                decoded.proof(),
                &provider,
                &verifier,
            ) else {
                panic!("published self-contained test proof must verify");
            };

            assert_eq!(
                verified.nullifier().as_bytes(),
                case.decision_type.nullifier(),
            );

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published ballot-package vector must re-encode");
            };

            reencoded
        }
        VectorKind::ArchiveManifest => {
            let Ok(decoded) = ArchiveManifestV1::from_canonical_cbor(canonical) else {
                panic!("published archive-manifest vector must decode");
            };

            assert_eq!(decoded, fixture.archive_manifest);
            assert!(decoded.validate_hash_provider(&provider).is_ok());

            let Ok(manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
                panic!("published manifest hash must succeed");
            };

            assert_eq!(decoded.election_manifest_hash(), manifest_hash);
            assert_eq!(decoded.files().len(), fixture.archive_files.len());

            for entry in decoded.files().entries() {
                let Some((_, bytes)) = fixture
                    .archive_files
                    .iter()
                    .find(|(path, _)| path == entry.path().as_str())
                else {
                    panic!("archive vector references an unknown content file");
                };

                assert!(entry.verify_bytes(&provider, bytes).is_ok());
            }

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published archive-manifest vector must re-encode");
            };

            reencoded
        }
    }
}

#[test]
#[ignore = "explicitly regenerates checked-in decision vector fixtures"]
fn regenerate_valid_decision_vectors() {
    for case in vectors() {
        write_case(&case);
    }
}

#[test]
fn valid_decision_vector_layout_is_complete() {
    let readme = vector_root().join("README.md");

    assert!(readme.is_file());

    let mut expected_files: Vec<String> = REQUIRED_CASE_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();

    expected_files.sort();

    for case in vectors() {
        assert_eq!(
            directory_entry_names(&case_root(&case)),
            expected_files,
            "published vector layout differs for {}",
            case.id,
        );
    }
}

#[test]
fn published_decision_vectors_match_elections_and_ballot_measures() {
    let provider = TestOnlyDeterministicHasher;
    let cases = vectors();

    assert_eq!(cases.len(), 8);
    assert!(
        cases
            .iter()
            .any(|case| case.decision_type == DecisionType::CandidateElection)
    );
    assert!(
        cases
            .iter()
            .any(|case| case.decision_type == DecisionType::BallotMeasure)
    );

    for case in cases {
        let root = case_root(&case);
        let canonical = read_bytes(&root.join("canonical.cbor"));

        assert_eq!(
            canonical, case.canonical,
            "canonical bytes differ for {}",
            case.id,
        );

        assert_eq!(
            read_text(&root.join("canonical.hex")).trim(),
            lowercase_hex(&canonical),
            "hex rendering differs for {}",
            case.id,
        );

        assert_eq!(
            decode_and_reencode(&case, &canonical),
            canonical,
            "decode/re-encode identity failed for {}",
            case.id,
        );

        assert_eq!(
            hash_domain_separated(&provider, case.kind.hash_domain(), &canonical),
            case.digest,
            "domain-separated digest differs for {}",
            case.id,
        );

        let description = read_text(&root.join("description.md"));

        assert!(description.contains(&case.id));
        assert!(description.contains(case.decision_type.slug()));
        assert!(description.contains(case.kind.object_family()));

        let input = read_text(&root.join("input.json"));

        assert!(input.contains(&case.id));
        assert!(input.contains(case.decision_type.slug()));
        assert!(input.contains(case.kind.object_family()));
        assert!(input.contains(TEST_ONLY_SUITE_ID));
        assert!(input.contains("\"allows_abstention\": true"));

        let expected = read_text(&root.join("expected.json"));

        assert!(expected.contains("\"accepted\": true"));
        assert!(expected.contains(case.decision_type.slug()));
        assert!(expected.contains(case.kind.decoder_target()));
        assert!(expected.contains(&format!("\"canonical_byte_length\": {}", canonical.len(),)));

        let hashes = read_text(&root.join("expected-hashes.json"));

        assert!(hashes.contains(case.decision_type.slug()));
        assert!(hashes.contains(TEST_ONLY_HASH_ALGORITHM_ID));
        assert!(hashes.contains(case.kind.hash_domain().label()));
        assert!(hashes.contains(&lowercase_hex(&case.digest)));
    }
}
