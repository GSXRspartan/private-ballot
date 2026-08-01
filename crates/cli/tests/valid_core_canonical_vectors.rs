use std::{
    fs,
    path::{Path, PathBuf},
};

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
};
use tari_cc_private_ballot_protocol::{
    HashDomain, hash_domain_separated,
    test_only::{TEST_ONLY_HASH_ALGORITHM_ID, TestOnlyDeterministicHasher},
};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
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
enum VectorKind {
    RegistrySnapshot,
    CandidateSet,
    ApprovalBallotPayload,
}

impl VectorKind {
    const fn object_family(self) -> &'static str {
        match self {
            Self::RegistrySnapshot => "registry-snapshot-v1",
            Self::CandidateSet => "candidate-set-v1",
            Self::ApprovalBallotPayload => "approval-ballot-payload-v1",
        }
    }

    const fn decoder_target(self) -> &'static str {
        match self {
            Self::RegistrySnapshot => "RegistrySnapshot::from_canonical_cbor",
            Self::CandidateSet => "CandidateSet::from_canonical_cbor",
            Self::ApprovalBallotPayload => "ApprovalBallotPayload::from_canonical_cbor",
        }
    }

    const fn hash_domain(self) -> HashDomain {
        match self {
            Self::RegistrySnapshot => HashDomain::RegistrySnapshotV1,
            Self::CandidateSet => HashDomain::CandidateSetV1,
            Self::ApprovalBallotPayload => HashDomain::ApprovalBallotPayloadV1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedVector {
    id: &'static str,
    kind: VectorKind,
    description: &'static str,
    input_order_note: &'static str,
    canonical: Vec<u8>,
    digest: [u8; 32],
}

impl PublishedVector {
    fn description_markdown(&self) -> String {
        format!(
            "# {}\n\n{}\n\nObject family: `{}`.\n\nThe canonical CBOR bytes are authoritative. JSON and hexadecimal files are presentation artifacts.\n",
            self.id,
            self.description,
            self.kind.object_family(),
        )
    }

    fn input_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"tari-cc-private-ballot-valid-input-v1\",\n",
                "  \"vector_id\": \"{}\",\n",
                "  \"object_family\": \"{}\",\n",
                "  \"input_order_note\": \"{}\"\n",
                "}}\n",
            ),
            self.id,
            self.kind.object_family(),
            self.input_order_note,
        )
    }

    fn expected_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"tari-cc-private-ballot-valid-result-v1\",\n",
                "  \"vector_id\": \"{}\",\n",
                "  \"accepted\": true,\n",
                "  \"decoder_target\": \"{}\",\n",
                "  \"canonical_byte_length\": {},\n",
                "  \"canonical_encoding\": \"deterministic-cbor-rfc8949-4.2.1\"\n",
                "}}\n",
            ),
            self.id,
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
                "  \"hash_algorithm_id\": \"{}\",\n",
                "  \"domain_label\": \"{}\",\n",
                "  \"digest_hex\": \"{}\"\n",
                "}}\n",
            ),
            self.id,
            TEST_ONLY_HASH_ALGORITHM_ID,
            self.kind.hash_domain().label(),
            lowercase_hex(&self.digest),
        )
    }
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join("valid")
        .join("canonical-v1")
}

fn case_root(case: &PublishedVector) -> PathBuf {
    vector_root().join(case.id)
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

fn registry_snapshot() -> RegistrySnapshot {
    let Ok(snapshot) = RegistrySnapshot::new(vec![
        governance_entry(b"governance-key-charlie"),
        governance_entry(b"governance-key-alpha"),
        governance_entry(b"governance-key-bravo"),
    ]) else {
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
        panic!("published governance option must be valid");
    };

    candidate
}

fn candidate_set() -> CandidateSet {
    let Ok(candidates) = CandidateSet::new(vec![
        candidate(b"reject", "Reject"),
        candidate(b"approve", "Approve"),
        candidate(b"defer", "Defer"),
    ]) else {
        panic!("published candidate set must be valid");
    };

    candidates
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, true) else {
        panic!("published approval limits must be valid");
    };

    limits
}

fn approval_payload() -> ApprovalBallotPayload {
    let candidates = candidate_set();

    let Ok(payload) = ApprovalBallotPayload::new(
        vec![candidate_id(b"approve")],
        &candidates,
        approval_limits(),
    ) else {
        panic!("published approval payload must be valid");
    };

    payload
}

fn registry_vector() -> PublishedVector {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry_snapshot();

    let Ok(canonical) = registry.to_canonical_cbor() else {
        panic!("published registry encoding must succeed");
    };

    let Ok(commitment) = registry.canonical_commitment(&provider) else {
        panic!("published registry commitment must succeed");
    };

    let digest = hash_domain_separated(&provider, HashDomain::RegistrySnapshotV1, &canonical);

    assert_eq!(commitment.into_bytes(), digest);

    PublishedVector {
        id: "registry-snapshot-multi-member",
        kind: VectorKind::RegistrySnapshot,
        description: "A three-member voter-owned governance-key registry supplied in noncanonical input order and encoded in canonical key order.",
        input_order_note: "charlie, alpha, bravo; canonical encoding sorts by governance-key bytes",
        canonical,
        digest,
    }
}

fn candidate_vector() -> PublishedVector {
    let provider = TestOnlyDeterministicHasher;
    let candidates = candidate_set();

    let Ok(canonical) = candidates.to_canonical_cbor() else {
        panic!("published candidate-set encoding must succeed");
    };

    let Ok(commitment) = candidates.canonical_commitment(&provider) else {
        panic!("published candidate-set commitment must succeed");
    };

    let digest = hash_domain_separated(&provider, HashDomain::CandidateSetV1, &canonical);

    assert_eq!(commitment.into_bytes(), digest);

    PublishedVector {
        id: "candidate-set-governance-options",
        kind: VectorKind::CandidateSet,
        description: "Three stable governance option identifiers with separate display names, supplied out of order and encoded by canonical identifier order.",
        input_order_note: "reject, approve, defer; canonical encoding sorts by stable option identifier bytes",
        canonical,
        digest,
    }
}

fn approval_vector() -> PublishedVector {
    let provider = TestOnlyDeterministicHasher;
    let payload = approval_payload();

    let Ok(canonical) = payload.to_canonical_cbor() else {
        panic!("published approval-payload encoding must succeed");
    };

    let Ok(payload_hash) = payload.canonical_hash(&provider) else {
        panic!("published approval-payload hash must succeed");
    };

    let digest = hash_domain_separated(&provider, HashDomain::ApprovalBallotPayloadV1, &canonical);

    assert_eq!(payload_hash.into_bytes(), digest);

    PublishedVector {
        id: "approval-ballot-single-selection",
        kind: VectorKind::ApprovalBallotPayload,
        description: "A public approval ballot selecting the stable `approve` option under an exactly-one-choice policy that also permits abstention.",
        input_order_note: "single selection approve; canonical order is unchanged",
        canonical,
        digest,
    }
}

fn vectors() -> Vec<PublishedVector> {
    vec![registry_vector(), candidate_vector(), approval_vector()]
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

fn decode_and_reencode(kind: VectorKind, canonical: &[u8]) -> Vec<u8> {
    match kind {
        VectorKind::RegistrySnapshot => {
            let Ok(decoded) = RegistrySnapshot::from_canonical_cbor(canonical) else {
                panic!("published registry vector must decode");
            };

            assert_eq!(decoded, registry_snapshot());

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published registry vector must re-encode");
            };

            reencoded
        }
        VectorKind::CandidateSet => {
            let Ok(decoded) = CandidateSet::from_canonical_cbor(canonical) else {
                panic!("published candidate-set vector must decode");
            };

            assert_eq!(decoded, candidate_set());

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published candidate-set vector must re-encode");
            };

            reencoded
        }
        VectorKind::ApprovalBallotPayload => {
            let candidates = candidate_set();

            let Ok(decoded) = ApprovalBallotPayload::from_canonical_cbor(
                canonical,
                &candidates,
                approval_limits(),
            ) else {
                panic!("published approval vector must decode");
            };

            assert_eq!(decoded, approval_payload());

            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("published approval vector must re-encode");
            };

            reencoded
        }
    }
}

#[test]
#[ignore = "explicitly regenerates checked-in valid vector fixtures"]
fn regenerate_valid_core_vectors() {
    for case in vectors() {
        write_case(&case);
    }
}

#[test]
fn valid_core_vector_layout_is_complete() {
    let cases = vectors();
    let root = vector_root();

    let mut expected_case_names: Vec<String> =
        cases.iter().map(|case| case.id.to_owned()).collect();

    expected_case_names.sort();

    assert_eq!(directory_entry_names(&root), expected_case_names);

    let mut expected_files: Vec<String> = REQUIRED_CASE_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();

    expected_files.sort();

    for case in &cases {
        assert_eq!(
            directory_entry_names(&case_root(case)),
            expected_files,
            "published vector layout differs for {}",
            case.id,
        );
    }
}

#[test]
fn published_valid_core_vectors_match_canonical_objects() {
    let provider = TestOnlyDeterministicHasher;

    for case in vectors() {
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
            decode_and_reencode(case.kind, &canonical),
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

        assert!(description.contains(case.id));
        assert!(description.contains(case.kind.object_family()));

        let input = read_text(&root.join("input.json"));

        assert!(input.contains(case.id));
        assert!(input.contains(case.kind.object_family()));
        assert!(input.contains(case.input_order_note));

        let expected = read_text(&root.join("expected.json"));

        assert!(expected.contains("\"accepted\": true"));
        assert!(expected.contains(case.kind.decoder_target()));
        assert!(expected.contains(&format!("\"canonical_byte_length\": {}", canonical.len(),)));

        let hashes = read_text(&root.join("expected-hashes.json"));

        assert!(hashes.contains(TEST_ONLY_HASH_ALGORITHM_ID));
        assert!(hashes.contains(case.kind.hash_domain().label()));
        assert!(hashes.contains(&lowercase_hex(&case.digest)));
    }
}
