use std::{
    fs,
    path::{Path, PathBuf},
};

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
};
use tari_cc_private_ballot_protocol::{CanonicalCborReader, ProtocolError, ValidationCode};
use tari_cc_private_ballot_registry::RegistrySnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusTarget {
    GenericArray,
    GenericUnsigned,
    GenericText,
    RegistrySnapshot,
    CandidateSet,
    ApprovalMinOneMaxTwo,
    ApprovalMinOneMaxOne,
}

impl CorpusTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GenericArray => "generic-array",
            Self::GenericUnsigned => "generic-unsigned",
            Self::GenericText => "generic-text",
            Self::RegistrySnapshot => "registry-snapshot",
            Self::CandidateSet => "candidate-set",
            Self::ApprovalMinOneMaxTwo => "approval-payload-min1-max2",
            Self::ApprovalMinOneMaxOne => "approval-payload-min1-max1",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CorpusCase {
    id: &'static str,
    target: CorpusTarget,
    expected: ValidationCode,
}

const CASES: &[CorpusCase] = &[
    CorpusCase {
        id: "truncated-candidate-set",
        target: CorpusTarget::CandidateSet,
        expected: ValidationCode::InvalidCbor,
    },
    CorpusCase {
        id: "trailing-registry-data",
        target: CorpusTarget::RegistrySnapshot,
        expected: ValidationCode::TrailingCborData,
    },
    CorpusCase {
        id: "indefinite-array",
        target: CorpusTarget::GenericArray,
        expected: ValidationCode::NonCanonicalCbor,
    },
    CorpusCase {
        id: "non-shortest-unsigned",
        target: CorpusTarget::GenericUnsigned,
        expected: ValidationCode::NonCanonicalCbor,
    },
    CorpusCase {
        id: "invalid-utf8-text",
        target: CorpusTarget::GenericText,
        expected: ValidationCode::InvalidCbor,
    },
    CorpusCase {
        id: "wrong-candidate-entry-type",
        target: CorpusTarget::CandidateSet,
        expected: ValidationCode::UnexpectedCborType,
    },
    CorpusCase {
        id: "empty-registry",
        target: CorpusTarget::RegistrySnapshot,
        expected: ValidationCode::EmptyRegistry,
    },
    CorpusCase {
        id: "duplicate-registry-key",
        target: CorpusTarget::RegistrySnapshot,
        expected: ValidationCode::DuplicateGovernanceKey,
    },
    CorpusCase {
        id: "unsorted-registry-key",
        target: CorpusTarget::RegistrySnapshot,
        expected: ValidationCode::NonCanonicalCbor,
    },
    CorpusCase {
        id: "empty-candidate-set",
        target: CorpusTarget::CandidateSet,
        expected: ValidationCode::EmptyCandidateSet,
    },
    CorpusCase {
        id: "duplicate-candidate-id",
        target: CorpusTarget::CandidateSet,
        expected: ValidationCode::DuplicateCandidateId,
    },
    CorpusCase {
        id: "unsorted-candidate-id",
        target: CorpusTarget::CandidateSet,
        expected: ValidationCode::NonCanonicalCbor,
    },
    CorpusCase {
        id: "unknown-approval-selection",
        target: CorpusTarget::ApprovalMinOneMaxTwo,
        expected: ValidationCode::UnknownCandidateId,
    },
    CorpusCase {
        id: "duplicate-approval-selection",
        target: CorpusTarget::ApprovalMinOneMaxTwo,
        expected: ValidationCode::DuplicateSelection,
    },
    CorpusCase {
        id: "too-few-approval-selections",
        target: CorpusTarget::ApprovalMinOneMaxTwo,
        expected: ValidationCode::SelectionCountOutOfRange,
    },
    CorpusCase {
        id: "too-many-approval-selections",
        target: CorpusTarget::ApprovalMinOneMaxOne,
        expected: ValidationCode::SelectionCountOutOfRange,
    },
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join("invalid")
        .join("cbor-v1")
}

fn case_root(case: CorpusCase) -> PathBuf {
    corpus_root().join(case.id)
}

fn read_case_bytes(case: CorpusCase) -> Vec<u8> {
    let path = case_root(case).join("invalid.cbor");

    let Ok(bytes) = fs::read(&path) else {
        panic!("failed to read corpus bytes: {}", path.display());
    };

    bytes
}

fn read_case_text(case: CorpusCase, name: &str) -> String {
    let path = case_root(case).join(name);

    let Ok(text) = fs::read_to_string(&path) else {
        panic!("failed to read corpus metadata: {}", path.display());
    };

    text
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join("")
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

fn approval_limits(minimum: usize, maximum: usize) -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(minimum, maximum, false) else {
        panic!("test approval limits must be valid");
    };

    limits
}

fn decode_case(target: CorpusTarget, bytes: &[u8]) -> Result<(), ProtocolError> {
    match target {
        CorpusTarget::GenericArray => {
            let mut reader = CanonicalCborReader::new(bytes);
            let _ = reader.read_array_len()?;
            reader.finish()
        }
        CorpusTarget::GenericUnsigned => {
            let mut reader = CanonicalCborReader::new(bytes);
            let _ = reader.read_unsigned()?;
            reader.finish()
        }
        CorpusTarget::GenericText => {
            let mut reader = CanonicalCborReader::new(bytes);
            let _ = reader.read_text_string()?;
            reader.finish()
        }
        CorpusTarget::RegistrySnapshot => RegistrySnapshot::from_canonical_cbor(bytes).map(|_| ()),
        CorpusTarget::CandidateSet => CandidateSet::from_canonical_cbor(bytes).map(|_| ()),
        CorpusTarget::ApprovalMinOneMaxTwo => {
            let candidates = candidate_set();

            ApprovalBallotPayload::from_canonical_cbor(bytes, &candidates, approval_limits(1, 2))
                .map(|_| ())
        }
        CorpusTarget::ApprovalMinOneMaxOne => {
            let candidates = candidate_set();

            ApprovalBallotPayload::from_canonical_cbor(bytes, &candidates, approval_limits(1, 1))
                .map(|_| ())
        }
    }
}

fn rejection_code(case: CorpusCase, bytes: &[u8]) -> ValidationCode {
    let result = decode_case(case.target, bytes);

    let Err(error) = result else {
        panic!(
            "hostile corpus case unexpectedly decoded: {} ({})",
            case.id,
            case.target.as_str()
        );
    };

    error.code()
}

#[test]
fn hostile_cbor_corpus_layout_is_complete() {
    assert_eq!(CASES.len(), 16);

    for case in CASES {
        let root = case_root(*case);

        for required_name in [
            "description.md",
            "input.json",
            "invalid.cbor",
            "invalid.hex",
            "expected.json",
        ] {
            let path = root.join(required_name);

            assert!(
                path.is_file(),
                "missing corpus file for {}: {}",
                case.id,
                path.display()
            );
        }

        let description = read_case_text(*case, "description.md");
        assert!(!description.trim().is_empty());

        let input = read_case_text(*case, "input.json");
        assert!(input.contains(case.id));
        assert!(input.contains(case.target.as_str()));

        let expected = read_case_text(*case, "expected.json");
        assert!(expected.contains(case.id));
        assert!(expected.contains(case.target.as_str()));
        assert!(expected.contains(case.expected.as_str()));
        assert!(expected.contains("\"accepted\": false"));

        let bytes = read_case_bytes(*case);
        let encoded_hex = read_case_text(*case, "invalid.hex");

        assert_eq!(encoded_hex.trim(), lowercase_hex(&bytes));
    }
}

#[test]
fn hostile_cbor_corpus_rejects_with_exact_codes() {
    for case in CASES {
        let bytes = read_case_bytes(*case);
        let actual = rejection_code(*case, &bytes);

        assert_eq!(
            actual,
            case.expected,
            "wrong rejection code for {} ({})",
            case.id,
            case.target.as_str()
        );
    }
}

#[test]
fn hostile_cbor_rejection_codes_are_deterministic() {
    for case in CASES {
        let bytes = read_case_bytes(*case);
        let first = rejection_code(*case, &bytes);

        for _ in 0..3 {
            assert_eq!(
                rejection_code(*case, &bytes),
                first,
                "nondeterministic rejection code for {}",
                case.id
            );
        }
    }
}
