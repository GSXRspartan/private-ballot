use core::fmt::Debug;

use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
    CandidateDefinition, CandidateId, CandidateSet, ElectionId, ElectionManifestV1,
    ElectionManifestV1Input,
};
use tari_cc_private_ballot_protocol::{
    BallotPayloadHash, CandidateSetCommitment, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1,
    ProofStatementV1, ProofStatementV1Input, ProtocolError, RegistryCommitment, TEST_ONLY_SUITE_ID,
};
use tari_cc_private_ballot_protocol::{HashProvider, test_only::TestOnlyDeterministicHasher};
use tari_cc_private_ballot_registry::RegistrySnapshot;

fn candidate_id(value: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(value.to_vec()) else {
        panic!("test candidate identifier must be valid");
    };

    id
}

fn candidate(value: &[u8], display_name: &str) -> CandidateDefinition {
    let Ok(candidate) = CandidateDefinition::new(candidate_id(value), display_name.to_owned())
    else {
        panic!("test candidate definition must be valid");
    };

    candidate
}

fn candidate_set() -> CandidateSet {
    let Ok(candidates) = CandidateSet::new(vec![
        candidate(b"candidate-a", "Candidate A"),
        candidate(b"candidate-b", "Candidate B"),
        candidate(b"candidate-c", "Candidate C"),
    ]) else {
        panic!("test candidate set must be valid");
    };

    candidates
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 2, true) else {
        panic!("test approval limits must be valid");
    };

    limits
}

fn approval_payload(candidates: &CandidateSet) -> ApprovalBallotPayload {
    let Ok(payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a"), candidate_id(b"candidate-c")],
        candidates,
        approval_limits(),
    ) else {
        panic!("test approval payload must be valid");
    };

    payload
}

fn election_id() -> ElectionId {
    let Ok(id) = ElectionId::new(b"mutation-matrix-election".to_vec()) else {
        panic!("test election identifier must be valid");
    };

    id
}

fn election_manifest() -> ElectionManifestV1 {
    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: election_id(),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: RegistryCommitment::new([1_u8; 32]),
        candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "mutation-revision-1".to_owned(),
    }) else {
        panic!("test election manifest must be valid");
    };

    manifest
}

fn assert_mutation_matrix<T, Decode, Encode>(
    label: &str,
    baseline: &T,
    canonical_bytes: &[u8],
    decode: Decode,
    encode: Encode,
) where
    T: Debug + PartialEq,
    Decode: Fn(&[u8]) -> Result<T, ProtocolError>,
    Encode: Fn(&T) -> Result<Vec<u8>, ProtocolError>,
{
    let mutation_masks = [0x01_u8, 0x80_u8, 0xff_u8];
    let mut accepted_mutations = 0_usize;
    let mut rejected_mutations = 0_usize;

    for index in 0..canonical_bytes.len() {
        for mask in mutation_masks {
            let mut mutated = canonical_bytes.to_vec();
            mutated[index] ^= mask;

            assert_ne!(
                mutated, canonical_bytes,
                "{label} mutation did not alter the canonical bytes"
            );

            match decode(&mutated) {
                Ok(decoded) => {
                    accepted_mutations += 1;

                    assert_ne!(
                        &decoded, baseline,
                        "{label} mutation at byte {index} with mask {mask:#04x} \
                         decoded to the original logical object"
                    );

                    let Ok(reencoded) = encode(&decoded) else {
                        panic!(
                            "{label} accepted mutation at byte {index} with \
                             mask {mask:#04x} could not be re-encoded"
                        );
                    };

                    assert_eq!(
                        reencoded, mutated,
                        "{label} accepted noncanonical mutation at byte {index} \
                         with mask {mask:#04x}"
                    );
                }
                Err(first_error) => {
                    rejected_mutations += 1;

                    for repetition in 0..3 {
                        let Err(next_error) = decode(&mutated) else {
                            panic!(
                                "{label} mutation at byte {index} with \
                                 mask {mask:#04x} was rejected once but \
                                 accepted during repetition {repetition}"
                            );
                        };

                        assert_eq!(
                            next_error.code(),
                            first_error.code(),
                            "{label} mutation at byte {index} with \
                             mask {mask:#04x} produced a nondeterministic \
                             rejection code"
                        );
                    }
                }
            }
        }
    }

    let expected_attempts = canonical_bytes.len() * mutation_masks.len();

    assert_eq!(
        accepted_mutations + rejected_mutations,
        expected_attempts,
        "{label} mutation matrix did not process every mutation"
    );

    assert!(
        accepted_mutations > 0,
        "{label} mutation matrix found no alternate valid objects"
    );

    assert!(
        rejected_mutations > 0,
        "{label} mutation matrix found no rejected encodings"
    );
}

#[test]
fn candidate_set_byte_mutations_are_canonical_or_rejected_deterministically() {
    let candidates = candidate_set();

    let Ok(encoded) = candidates.to_canonical_cbor() else {
        panic!("candidate set encoding must succeed");
    };

    assert_mutation_matrix(
        "candidate set",
        &candidates,
        &encoded,
        CandidateSet::from_canonical_cbor,
        CandidateSet::to_canonical_cbor,
    );
}

#[test]
fn approval_payload_byte_mutations_are_canonical_or_rejected_deterministically() {
    let candidates = candidate_set();
    let limits = approval_limits();
    let payload = approval_payload(&candidates);

    let Ok(encoded) = payload.to_canonical_cbor() else {
        panic!("approval payload encoding must succeed");
    };

    assert_mutation_matrix(
        "approval payload",
        &payload,
        &encoded,
        |bytes| ApprovalBallotPayload::from_canonical_cbor(bytes, &candidates, limits),
        ApprovalBallotPayload::to_canonical_cbor,
    );
}

#[test]
fn election_manifest_byte_mutations_are_canonical_or_rejected_deterministically() {
    let manifest = election_manifest();

    let Ok(encoded) = manifest.to_canonical_cbor() else {
        panic!("election manifest encoding must succeed");
    };

    assert_mutation_matrix(
        "election manifest",
        &manifest,
        &encoded,
        ElectionManifestV1::from_canonical_cbor,
        ElectionManifestV1::to_canonical_cbor,
    );
}
fn registry_snapshot() -> RegistrySnapshot {
    let encoded = vec![
        0x83, 0x45, b'k', b'e', b'y', b'-', b'a', 0x45, b'k', b'e', b'y', b'-', b'b', 0x45, b'k',
        b'e', b'y', b'-', b'c',
    ];

    let Ok(snapshot) = RegistrySnapshot::from_canonical_cbor(&encoded) else {
        panic!("test registry snapshot must be valid");
    };

    snapshot
}

fn proof_statement_input() -> ProofStatementV1Input {
    ProofStatementV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        manifest_hash: ManifestHash::new([1_u8; 32]),
        election_scope: ElectionScope::new([2_u8; 32]),
        registry_commitment: RegistryCommitment::new([3_u8; 32]),
        ballot_payload_hash: BallotPayloadHash::new([4_u8; 32]),
        ballot_kind_id: "NON_BINDING_APPROVAL_PILOT".to_owned(),
        ballot_confidentiality_id: "PUBLIC".to_owned(),
    }
}

fn proof_statement(input: ProofStatementV1Input) -> ProofStatementV1 {
    let Ok(statement) = ProofStatementV1::new(input) else {
        panic!("test proof statement must be valid");
    };

    statement
}

#[test]
fn registry_byte_mutations_are_canonical_or_rejected_deterministically() {
    let registry = registry_snapshot();

    let Ok(encoded) = registry.to_canonical_cbor() else {
        panic!("registry encoding must succeed");
    };

    assert_mutation_matrix(
        "registry snapshot",
        &registry,
        &encoded,
        RegistrySnapshot::from_canonical_cbor,
        RegistrySnapshot::to_canonical_cbor,
    );
}

#[test]
fn candidate_and_approval_input_order_do_not_change_canonical_bytes() {
    let Ok(first_candidates) = CandidateSet::new(vec![
        candidate(b"candidate-a", "Candidate A"),
        candidate(b"candidate-b", "Candidate B"),
        candidate(b"candidate-c", "Candidate C"),
    ]) else {
        panic!("first candidate set must be valid");
    };

    let Ok(second_candidates) = CandidateSet::new(vec![
        candidate(b"candidate-c", "Candidate C"),
        candidate(b"candidate-a", "Candidate A"),
        candidate(b"candidate-b", "Candidate B"),
    ]) else {
        panic!("second candidate set must be valid");
    };

    let Ok(first_candidate_bytes) = first_candidates.to_canonical_cbor() else {
        panic!("first candidate encoding must succeed");
    };

    let Ok(second_candidate_bytes) = second_candidates.to_canonical_cbor() else {
        panic!("second candidate encoding must succeed");
    };

    assert_eq!(first_candidate_bytes, second_candidate_bytes);

    let Ok(first_payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-c"), candidate_id(b"candidate-a")],
        &first_candidates,
        approval_limits(),
    ) else {
        panic!("first approval payload must be valid");
    };

    let Ok(second_payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a"), candidate_id(b"candidate-c")],
        &second_candidates,
        approval_limits(),
    ) else {
        panic!("second approval payload must be valid");
    };

    let Ok(first_payload_bytes) = first_payload.to_canonical_cbor() else {
        panic!("first approval payload encoding must succeed");
    };

    let Ok(second_payload_bytes) = second_payload.to_canonical_cbor() else {
        panic!("second approval payload encoding must succeed");
    };

    assert_eq!(first_payload_bytes, second_payload_bytes);
}

#[test]
fn every_mutable_proof_statement_field_changes_canonical_and_transcript_bytes() {
    let baseline = proof_statement(proof_statement_input());

    let Ok(baseline_canonical) = baseline.to_canonical_cbor() else {
        panic!("baseline proof-statement encoding must succeed");
    };

    let Ok(baseline_transcript) = baseline.transcript_bytes() else {
        panic!("baseline proof-statement transcript must succeed");
    };

    let mut variants = Vec::new();

    let mut changed_suite = proof_statement_input();
    changed_suite.proof_suite_id = "OTHER_TEST_SUITE".to_owned();
    variants.push(("proof suite", proof_statement(changed_suite)));

    let mut changed_manifest = proof_statement_input();
    changed_manifest.manifest_hash = ManifestHash::new([9_u8; 32]);
    variants.push(("manifest hash", proof_statement(changed_manifest)));

    let mut changed_scope = proof_statement_input();
    changed_scope.election_scope = ElectionScope::new([9_u8; 32]);
    variants.push(("election scope", proof_statement(changed_scope)));

    let mut changed_registry = proof_statement_input();
    changed_registry.registry_commitment = RegistryCommitment::new([9_u8; 32]);
    variants.push(("registry commitment", proof_statement(changed_registry)));

    let mut changed_payload = proof_statement_input();
    changed_payload.ballot_payload_hash = BallotPayloadHash::new([9_u8; 32]);
    variants.push(("ballot payload hash", proof_statement(changed_payload)));

    let mut changed_kind = proof_statement_input();
    changed_kind.ballot_kind_id = "OTHER_BALLOT_KIND".to_owned();
    variants.push(("ballot kind", proof_statement(changed_kind)));

    let mut changed_confidentiality = proof_statement_input();
    changed_confidentiality.ballot_confidentiality_id = "OTHER_MODE".to_owned();
    variants.push((
        "ballot confidentiality",
        proof_statement(changed_confidentiality),
    ));

    assert_eq!(variants.len(), 7);

    for (label, variant) in variants {
        let Ok(variant_canonical) = variant.to_canonical_cbor() else {
            panic!("{label} proof-statement encoding must succeed");
        };

        let Ok(variant_transcript) = variant.transcript_bytes() else {
            panic!("{label} proof-statement transcript must succeed");
        };

        assert_ne!(
            variant_canonical, baseline_canonical,
            "{label} mutation did not change canonical proof-statement bytes"
        );

        assert_ne!(
            variant_transcript, baseline_transcript,
            "{label} mutation did not change transcript bytes"
        );
    }
}
#[derive(Debug, Clone, Copy)]
struct AlternateTestHasher;

impl HashProvider for AlternateTestHasher {
    fn algorithm_id(&self) -> &'static str {
        "ALTERNATE_TEST_HASH_PROVIDER"
    }

    fn hash(&self, framed_input: &[u8]) -> [u8; 32] {
        let provider = TestOnlyDeterministicHasher;
        provider.hash(framed_input)
    }
}

fn archive_path(value: &str) -> ArchivePathV1 {
    let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
        panic!("test archive path must be valid");
    };

    path
}

fn archive_catalog<H: HashProvider>(values: &[(&str, u8)], provider: &H) -> ArchiveFileCatalogV1 {
    let entries = values
        .iter()
        .map(|(value, content_byte)| {
            let bytes = [*content_byte; 4];

            ArchiveFileEntryV1::for_bytes(archive_path(value), provider, &bytes)
        })
        .collect();

    let Ok(catalog) = ArchiveFileCatalogV1::new(entries) else {
        panic!("test archive catalog must be valid");
    };

    catalog
}

fn archive_manifest_with_provider<H: HashProvider>(
    election_hash_byte: u8,
    values: &[(&str, u8)],
    provider: &H,
) -> ArchiveManifestV1 {
    let Ok(manifest) = ArchiveManifestV1::for_provider(
        ManifestHash::new([election_hash_byte; 32]),
        archive_catalog(values, provider),
        provider,
    ) else {
        panic!("test archive manifest must be valid");
    };

    manifest
}

#[test]
fn archive_manifest_byte_mutations_are_canonical_or_rejected_deterministically() {
    let provider = TestOnlyDeterministicHasher;

    let manifest = archive_manifest_with_provider(
        1,
        &[
            ("README.md", 1),
            ("manifest.cbor", 2),
            ("submissions/00000000.cbor", 3),
        ],
        &provider,
    );

    let Ok(encoded) = manifest.to_canonical_cbor() else {
        panic!("archive-manifest encoding must succeed");
    };

    assert_mutation_matrix(
        "archive manifest",
        &manifest,
        &encoded,
        ArchiveManifestV1::from_canonical_cbor,
        ArchiveManifestV1::to_canonical_cbor,
    );
}

#[test]
fn archive_file_input_order_does_not_change_canonical_bytes_or_hash() {
    let provider = TestOnlyDeterministicHasher;

    let first = archive_manifest_with_provider(
        1,
        &[
            ("submissions/00000000.cbor", 3),
            ("README.md", 1),
            ("manifest.cbor", 2),
        ],
        &provider,
    );

    let second = archive_manifest_with_provider(
        1,
        &[
            ("manifest.cbor", 2),
            ("submissions/00000000.cbor", 3),
            ("README.md", 1),
        ],
        &provider,
    );

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("first archive-manifest encoding must succeed");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second archive-manifest encoding must succeed");
    };

    let Ok(first_hash) = first.canonical_hash(&provider) else {
        panic!("first archive hash must succeed");
    };

    let Ok(second_hash) = second.canonical_hash(&provider) else {
        panic!("second archive hash must succeed");
    };

    assert_eq!(first_bytes, second_bytes);
    assert_eq!(first_hash, second_hash);
}

#[test]
fn every_constructible_archive_manifest_field_changes_bytes_and_hash() {
    let provider = TestOnlyDeterministicHasher;

    let baseline_values = [
        ("README.md", 1),
        ("manifest.cbor", 2),
        ("submissions/00000000.cbor", 3),
    ];

    let baseline = archive_manifest_with_provider(1, &baseline_values, &provider);

    let Ok(baseline_bytes) = baseline.to_canonical_cbor() else {
        panic!("baseline archive-manifest encoding must succeed");
    };

    let Ok(baseline_hash) = baseline.canonical_hash(&provider) else {
        panic!("baseline archive hash must succeed");
    };

    let changed_election = archive_manifest_with_provider(9, &baseline_values, &provider);

    let changed_digest = archive_manifest_with_provider(
        1,
        &[
            ("README.md", 9),
            ("manifest.cbor", 2),
            ("submissions/00000000.cbor", 3),
        ],
        &provider,
    );

    let changed_path = archive_manifest_with_provider(
        1,
        &[
            ("README.md", 1),
            ("manifest.cbor", 2),
            ("submissions/00000001.cbor", 3),
        ],
        &provider,
    );

    let alternate_provider = AlternateTestHasher;

    let changed_algorithm =
        archive_manifest_with_provider(1, &baseline_values, &alternate_provider);

    let Ok(changed_election_bytes) = changed_election.to_canonical_cbor() else {
        panic!("changed-election manifest encoding must succeed");
    };

    let Ok(changed_election_hash) = changed_election.canonical_hash(&provider) else {
        panic!("changed-election archive hash must succeed");
    };

    let Ok(changed_digest_bytes) = changed_digest.to_canonical_cbor() else {
        panic!("changed-digest manifest encoding must succeed");
    };

    let Ok(changed_digest_hash) = changed_digest.canonical_hash(&provider) else {
        panic!("changed-digest archive hash must succeed");
    };

    let Ok(changed_path_bytes) = changed_path.to_canonical_cbor() else {
        panic!("changed-path manifest encoding must succeed");
    };

    let Ok(changed_path_hash) = changed_path.canonical_hash(&provider) else {
        panic!("changed-path archive hash must succeed");
    };

    let Ok(changed_algorithm_bytes) = changed_algorithm.to_canonical_cbor() else {
        panic!("changed-algorithm manifest encoding must succeed");
    };

    let Ok(changed_algorithm_hash) = changed_algorithm.canonical_hash(&alternate_provider) else {
        panic!("changed-algorithm archive hash must succeed");
    };

    let variants = [
        (
            "election manifest hash",
            changed_election_bytes,
            changed_election_hash,
        ),
        (
            "archive file digest",
            changed_digest_bytes,
            changed_digest_hash,
        ),
        ("archive file path", changed_path_bytes, changed_path_hash),
        (
            "archive hash algorithm",
            changed_algorithm_bytes,
            changed_algorithm_hash,
        ),
    ];

    for (label, variant_bytes, variant_hash) in variants {
        assert_ne!(
            variant_bytes, baseline_bytes,
            "{label} mutation did not change canonical archive bytes"
        );

        assert_ne!(
            variant_hash, baseline_hash,
            "{label} mutation did not change the final archive hash"
        );
    }
}
