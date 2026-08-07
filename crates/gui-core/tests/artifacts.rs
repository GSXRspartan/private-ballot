//! Election artifact loader tests (required cases 1-8).

mod common;

use tari_cc_private_ballot_ballot::{CandidateDefinition, CandidateSet};
use tari_cc_private_ballot_gui_core::{GuiElectionArtifactsV1, GuiErrorCategory};
use tari_cc_private_ballot_protocol::{CanonicalCborWriter, TEST_ONLY_SUITE_ID};

use common::{
    TestDir, candidate_bytes, candidate_id, manifest_bytes, manifest_with, registry_bytes, voters,
};

fn load_valid() -> GuiElectionArtifactsV1 {
    let result = GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &registry_bytes(),
        &candidate_bytes(),
    );
    match result {
        Ok(artifacts) => artifacts,
        Err(error) => panic!("valid artifacts must load: {error}"),
    }
}

fn write_file(path: &std::path::Path, bytes: Vec<u8>) {
    assert!(
        std::fs::write(path, bytes).is_ok(),
        "test write must succeed"
    );
}

#[test]
fn valid_three_file_election_loads_from_bytes() {
    let artifacts = load_valid();
    let summary = artifacts.summary();

    assert_eq!(summary.voter_count, 3);
    assert_eq!(summary.candidates.len(), 3);
    assert_eq!(summary.approval_min, 1);
    assert_eq!(summary.approval_max, 2);
    assert!(!summary.abstention_allowed);
    assert_eq!(summary.ballot_kind, "NON_BINDING_APPROVAL_PILOT");
    assert_eq!(
        summary.governance_source_revision,
        "gui-core-test-revision-1"
    );
    assert_eq!(summary.manifest_hash_hex.len(), 64);
    assert_eq!(summary.registry_commitment_hex.len(), 64);
    assert_eq!(summary.candidate_set_commitment_hex.len(), 64);
}

#[test]
fn valid_three_file_election_loads_from_paths() {
    let dir = TestDir::new("artifacts-paths");
    let manifest_path = dir.join("some file.cbor");
    let registry_path = dir.join("registry.cbor");
    let candidate_path = dir.join("candidates.cbor");
    write_file(&manifest_path, manifest_bytes());
    write_file(&registry_path, registry_bytes());
    write_file(&candidate_path, candidate_bytes());

    let result =
        GuiElectionArtifactsV1::from_paths(&manifest_path, &registry_path, &candidate_path);
    let artifacts = match result {
        Ok(artifacts) => artifacts,
        Err(error) => panic!("valid artifact paths must load: {error}"),
    };

    // Filenames carry no meaning: the same bytes under any name load.
    assert_eq!(artifacts.manifest_hash(), load_valid().manifest_hash());
}

#[test]
fn missing_artifact_file_is_rejected() {
    let dir = TestDir::new("artifacts-missing");
    let missing = dir.join("absent.cbor");
    let error = match GuiElectionArtifactsV1::from_paths(&missing, &missing, &missing) {
        Ok(_) => panic!("missing files must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_FILE_NOT_FOUND");
    assert_eq!(error.category(), GuiErrorCategory::FileIo);
}

#[test]
fn wrong_registry_commitment_is_rejected() {
    // A two-member registry cannot match the canonical three-member manifest.
    let mut two_voter_keys: Vec<[u8; 32]> = voters()
        .iter()
        .take(2)
        .map(|voter| voter.public_bytes)
        .collect();
    two_voter_keys.sort_unstable();
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(two_voter_keys.len()).is_ok());
    for key in two_voter_keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }
    let wrong_registry = writer.into_bytes();

    let error = match GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &wrong_registry,
        &candidate_bytes(),
    ) {
        Ok(_) => panic!("mismatched registry must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_REGISTRY_COMMITMENT_MISMATCH");
    assert_eq!(error.category(), GuiErrorCategory::BindingMismatch);
}

#[test]
fn wrong_candidate_commitment_is_rejected() {
    let first = match CandidateDefinition::new(candidate_id(b"candidate-a"), "A".to_owned()) {
        Ok(candidate) => candidate,
        Err(_) => panic!("fixture candidate must be valid"),
    };
    let second = match CandidateDefinition::new(candidate_id(b"candidate-z"), "Z".to_owned()) {
        Ok(candidate) => candidate,
        Err(_) => panic!("fixture candidate must be valid"),
    };
    let other_set = match CandidateSet::new(vec![first, second]) {
        Ok(set) => set,
        Err(_) => panic!("fixture candidate set must be valid"),
    };
    let other_bytes = match other_set.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture candidate set must encode"),
    };

    let error = match GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &registry_bytes(),
        &other_bytes,
    ) {
        Ok(_) => panic!("mismatched candidate set must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "CANDIDATE_SET_COMMITMENT_MISMATCH");
    assert_eq!(error.category(), GuiErrorCategory::BindingMismatch);
}

#[test]
fn wrong_artifact_in_manifest_slot_is_rejected() {
    // Registry bytes are not a manifest: the manifest slot must reject them.
    let error = match GuiElectionArtifactsV1::from_bytes(
        &registry_bytes(),
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(_) => panic!("wrong manifest artifact must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.context(), Some("manifest"));
}

#[test]
fn malformed_cbor_is_rejected() {
    let mut truncated = registry_bytes();
    truncated.truncate(truncated.len() / 2);

    let error =
        match GuiElectionArtifactsV1::from_bytes(&manifest_bytes(), &truncated, &candidate_bytes())
        {
            Ok(_) => panic!("truncated registry must be rejected"),
            Err(error) => error,
        };
    assert_eq!(error.code(), "INVALID_CBOR");
    assert_eq!(error.context(), Some("registry"));
}

#[test]
fn non_canonical_cbor_is_rejected() {
    // The canonical three-member registry begins with array(3) = 0x83.
    // Re-encode the length in non-shortest form (0x98 0x03).
    let canonical = registry_bytes();
    assert_eq!(canonical[0], 0x83);
    let mut non_canonical = vec![0x98, 0x03];
    non_canonical.extend_from_slice(&canonical[1..]);

    let error = match GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &non_canonical,
        &candidate_bytes(),
    ) {
        Ok(_) => panic!("non-canonical registry must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "NON_CANONICAL_CBOR");
}

#[test]
fn unsupported_manifest_version_is_rejected() {
    // Canonical manifest: array(9) = 0x89, then unsigned version = 0x01.
    let mut version_two = manifest_bytes();
    assert_eq!(version_two[0], 0x89);
    assert_eq!(version_two[1], 0x01);
    version_two[1] = 0x02;

    let error = match GuiElectionArtifactsV1::from_bytes(
        &version_two,
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(_) => panic!("unsupported version must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "UNSUPPORTED_PROTOCOL_VERSION");
    assert_eq!(error.category(), GuiErrorCategory::UnsupportedFormat);
}

#[test]
fn test_only_proof_suite_is_rejected_by_production_policy() {
    let test_only_manifest = manifest_with(
        b"gui-core-test-election",
        TEST_ONLY_SUITE_ID,
        common::approval_limits(),
    );
    let test_only_bytes = match test_only_manifest.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("test-only manifest must encode"),
    };

    let error = match GuiElectionArtifactsV1::from_bytes(
        &test_only_bytes,
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(_) => panic!("test-only suite must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "UNSUPPORTED_PROOF_SUITE");
    assert_eq!(error.category(), GuiErrorCategory::UnsupportedFormat);
}

#[test]
fn summary_display_names_and_ids_match_manifest() {
    let artifacts = load_valid();
    let summary = artifacts.summary();
    let names: Vec<&str> = summary
        .candidates
        .iter()
        .map(|candidate| candidate.display_name.as_str())
        .collect();
    assert_eq!(names, vec!["Candidate A", "Candidate B", "Candidate C"]);
    let ids: Vec<Option<&str>> = summary
        .candidates
        .iter()
        .map(|candidate| candidate.machine_id_text.as_deref())
        .collect();
    assert_eq!(
        ids,
        vec![
            Some("candidate-a"),
            Some("candidate-b"),
            Some("candidate-c")
        ]
    );
}
