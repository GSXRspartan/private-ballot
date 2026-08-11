//! Ballot intake facade tests (required cases 9-15).

mod common;

use tari_cc_private_ballot_ballot::{ApprovalBallotPayload, BallotPackageV1, BallotPackageV1Input};
use tari_cc_private_ballot_gui_core::{GuiElectionSessionV1, GuiErrorCategory, GuiIntakeCategory};
use tari_cc_private_ballot_protocol::PROTOCOL_VERSION_V1;

use common::{
    candidate_id, candidate_set, manifest, manifest_with, manifest_with_revision, open_session,
    package_bytes_for, triptych_package_bytes,
};

#[test]
fn valid_real_triptych_ballot_is_accepted() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    let result = match session.intake_ballot(&package) {
        Ok(result) => result,
        Err(error) => panic!("valid ballot intake must succeed: {error}"),
    };

    assert!(result.accepted);
    assert_eq!(result.code, "ACCEPTED");
    assert_eq!(result.category, GuiIntakeCategory::Accepted);
    assert_eq!(result.package_digest_hex.len(), 64);
    assert_eq!(session.accepted_count(), 1);
    assert_eq!(session.transcript().accepted_count(), 1);
}

#[test]
fn duplicate_nullifier_is_rejected_with_first_valid_reference() {
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let duplicate = triptych_package_bytes(0, &[b"candidate-b"]);

    let first_result = match session.intake_ballot(&first) {
        Ok(result) => result,
        Err(error) => panic!("first ballot must intake: {error}"),
    };
    assert!(first_result.accepted);

    let duplicate_result = match session.intake_ballot(&duplicate) {
        Ok(result) => result,
        Err(error) => panic!("duplicate ballot intake must return a decision: {error}"),
    };

    assert!(!duplicate_result.accepted);
    assert_eq!(duplicate_result.code, "DUPLICATE_BALLOT");
    assert_eq!(duplicate_result.category, GuiIntakeCategory::Duplicate);
    assert_eq!(first_result.package_digest_hex.len(), 64);
    // The first valid ballot still counts; the ledger was not replaced.
    assert_eq!(session.accepted_count(), 1);
    assert_eq!(session.transcript().rejected_count(), 1);
}

#[test]
fn exact_replay_is_rejected_by_nullifier_not_package_digest_only() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    let first = match session.intake_ballot_package_bytes(&package) {
        Ok(result) => result,
        Err(error) => panic!("first ballot must intake: {error}"),
    };
    let replay = match session.intake_ballot_package_bytes(&package) {
        Ok(result) => result,
        Err(error) => panic!("replay must return a duplicate decision: {error}"),
    };

    assert!(first.accepted);
    assert!(!replay.accepted);
    assert_eq!(replay.code, "DUPLICATE_BALLOT");
    assert_eq!(replay.category, GuiIntakeCategory::Duplicate);
    assert_eq!(first.package_digest_hex, replay.package_digest_hex);
    assert_eq!(session.accepted_count(), 1);
}

#[test]
fn wrong_manifest_ballot_is_rejected() {
    let mut session = open_session();
    let other_manifest = manifest_with(
        b"gui-core-other-election",
        tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        common::approval_limits(),
    );
    let foreign = package_bytes_for(&other_manifest, 1, &[b"candidate-a"]);

    let result = match session.intake_ballot(&foreign) {
        Ok(result) => result,
        Err(error) => panic!("foreign ballot intake must return a decision: {error}"),
    };

    assert!(!result.accepted);
    assert_eq!(result.code, "WRONG_MANIFEST_HASH");
    assert_eq!(result.category, GuiIntakeCategory::WrongElection);
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn governance_source_revision_mutation_rejects_preserved_package() {
    let old_manifest = manifest_with_revision("governance-revision-a");
    let preserved_package = package_bytes_for(&old_manifest, 1, &[b"candidate-a"]);
    let new_artifacts = common::artifacts_with_revision("governance-revision-b");
    let mut session = match GuiElectionSessionV1::new(new_artifacts) {
        Ok(session) => session,
        Err(error) => panic!("mutated-revision session must construct: {error}"),
    };
    if let Err(error) = session.open() {
        panic!("mutated-revision session must open: {error}");
    }

    let result = match session.intake_ballot_package_bytes(&preserved_package) {
        Ok(result) => result,
        Err(error) => panic!("revision-mismatched package must return a decision: {error}"),
    };

    assert!(!result.accepted);
    assert_eq!(result.code, "WRONG_MANIFEST_HASH");
    assert_eq!(result.category, GuiIntakeCategory::WrongElection);
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn ballot_referencing_unknown_candidate_is_rejected() {
    let mut session = open_session();
    let manifest = manifest();
    let candidates = candidate_set();

    // Build a payload against a superset containing an unknown candidate,
    // then bind it to the canonical manifest hash.
    let superset = {
        let mut definitions = candidates.candidates().to_vec();
        let extra = match tari_cc_private_ballot_ballot::CandidateDefinition::new(
            candidate_id(b"candidate-z"),
            "Candidate Z".to_owned(),
        ) {
            Ok(candidate) => candidate,
            Err(_) => panic!("fixture candidate must be valid"),
        };
        definitions.push(extra);
        match tari_cc_private_ballot_ballot::CandidateSet::new(definitions) {
            Ok(set) => set,
            Err(_) => panic!("superset must be valid"),
        }
    };
    let payload = match ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-z")],
        &superset,
        manifest.approval_limits(),
    ) {
        Ok(payload) => payload,
        Err(_) => panic!("superset payload must be valid"),
    };
    let provider = tari_cc_private_ballot_protocol::Blake3HashProviderV1;
    let manifest_hash = match manifest.canonical_hash(&provider) {
        Ok(hash) => hash,
        Err(_) => panic!("manifest hash must derive"),
    };
    let package = match BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: vec![0x01],
        payload,
    }) {
        Ok(package) => package,
        Err(_) => panic!("fixture package must be structurally valid"),
    };
    let bytes = match package.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture package must encode"),
    };

    let result = match session.intake_ballot(&bytes) {
        Ok(result) => result,
        Err(error) => panic!("unknown-candidate ballot must return a decision: {error}"),
    };

    assert!(!result.accepted);
    assert_eq!(result.code, "UNKNOWN_CANDIDATE_ID");
    assert_eq!(result.category, GuiIntakeCategory::Invalid);
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn trailing_bytes_are_rejected_by_canonical_byte_boundary() {
    let mut session = open_session();
    let mut package = triptych_package_bytes(0, &[b"candidate-a"]);
    package.push(0x00);

    let result = match session.intake_ballot_package_bytes(&package) {
        Ok(result) => result,
        Err(error) => panic!("trailing bytes must return a rejection decision: {error}"),
    };

    assert!(!result.accepted);
    assert_eq!(result.category, GuiIntakeCategory::Invalid);
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn malformed_proof_is_rejected() {
    let mut session = open_session();
    let valid = triptych_package_bytes(1, &[b"candidate-a"]);

    // Tamper the Triptych proof-envelope version byte inside a structurally
    // valid package, mirroring the existing real-Triptych replay test.
    let envelope =
        match tari_cc_private_ballot_ballot::BallotPackageEnvelopeV1::from_canonical_cbor(&valid) {
            Ok(envelope) => envelope,
            Err(_) => panic!("valid package must decode as envelope"),
        };
    let package = match envelope.into_ballot_package(&candidate_set(), manifest().approval_limits())
    {
        Ok(package) => package,
        Err(_) => panic!("valid package must decode"),
    };
    let mut tampered_proof = package.proof().to_vec();
    let Some(first_byte) = tampered_proof.first_mut() else {
        panic!("proof must not be empty");
    };
    *first_byte ^= 0x01;
    let tampered = match BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: package.manifest_hash(),
        proof_suite_id: package.proof_suite_id().to_owned(),
        proof: tampered_proof,
        payload: package.payload().clone(),
    }) {
        Ok(package) => package,
        Err(_) => panic!("tampered package must be structurally valid"),
    };
    let bytes = match tampered.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("tampered package must encode"),
    };

    let result = match session.intake_ballot(&bytes) {
        Ok(result) => result,
        Err(error) => panic!("malformed-proof ballot must return a decision: {error}"),
    };

    assert!(!result.accepted);
    assert!(
        result.code == "MALFORMED_PROOF" || result.code == "INVALID_DATA",
        "unexpected code: {}",
        result.code
    );
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn intake_result_does_not_expose_voter_identity_or_source_metadata() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    let result = match session.intake_ballot_package_bytes(&package) {
        Ok(result) => result,
        Err(error) => panic!("valid ballot intake must succeed: {error}"),
    };
    let rendered = match serde_json::to_string(&result) {
        Ok(rendered) => rendered.to_lowercase(),
        Err(error) => panic!("intake result must serialize: {error}"),
    };

    for forbidden in [
        "path",
        "filename",
        "file_name",
        "import_time",
        "ip",
        "username",
        "machine",
        "voter_identity",
        "registry_index",
        "member_index",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "intake result exposed forbidden marker {forbidden}: {rendered}"
        );
    }
}

#[test]
fn rejected_ballot_does_not_mutate_accepted_state() {
    let mut session = open_session();
    let valid = triptych_package_bytes(0, &[b"candidate-a"]);
    let duplicate = triptych_package_bytes(0, &[b"candidate-b"]);

    assert!(match session.intake_ballot(&valid) {
        Ok(result) => result.accepted,
        Err(_) => false,
    });
    let accepted_before = session.accepted_count();

    let duplicate_result = match session.intake_ballot(&duplicate) {
        Ok(result) => result,
        Err(_) => panic!("duplicate must return a decision"),
    };
    assert!(!duplicate_result.accepted);
    assert_eq!(session.accepted_count(), accepted_before);

    // A later valid ballot from a different voter is unaffected.
    let other = triptych_package_bytes(1, &[b"candidate-a"]);
    let other_result = match session.intake_ballot(&other) {
        Ok(result) => result,
        Err(_) => panic!("distinct ballot must return a decision"),
    };
    assert!(other_result.accepted);
    assert_eq!(session.accepted_count(), accepted_before + 1);
}

#[test]
fn intake_sequence_and_transcript_are_deterministic() {
    let packages = [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate
        triptych_package_bytes(2, &[b"candidate-a", b"candidate-c"]),
    ];

    let mut first = open_session();
    let mut second = open_session();

    for (index, package) in packages.iter().enumerate() {
        let first_result = match first.intake_ballot(package) {
            Ok(result) => result,
            Err(_) => panic!("first session intake must succeed"),
        };
        let second_result = match second.intake_ballot(package) {
            Ok(result) => result,
            Err(_) => panic!("second session intake must succeed"),
        };
        assert_eq!(first_result, second_result);
        let expected = if index == 2 {
            GuiIntakeCategory::Duplicate
        } else {
            GuiIntakeCategory::Accepted
        };
        assert_eq!(first_result.category, expected);
    }

    assert_eq!(first.transcript(), second.transcript());
    assert_eq!(first.transcript().accepted_count(), 3);
    assert_eq!(first.transcript().rejected_count(), 1);
    assert!(first.transcript().validate_complete().is_ok());
}

#[test]
fn intake_outside_open_state_is_a_facade_error_without_recording() {
    // Frozen (never opened) session.
    let frozen_session = GuiElectionSessionV1::new(common::artifacts());
    let mut frozen_session = match frozen_session {
        Ok(session) => session,
        Err(_) => panic!("session must construct"),
    };
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    let error = match frozen_session.intake_ballot(&package) {
        Ok(_) => panic!("frozen session must refuse intake"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");
    assert_eq!(
        error.category(),
        GuiErrorCategory::InvalidLifecycleTransition
    );
    assert_eq!(frozen_session.transcript().submissions().len(), 0);

    // Closed session.
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("open session must close: {error}");
    }
    let error = match session.intake_ballot(&package) {
        Ok(_) => panic!("closed session must refuse intake"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");
    assert_eq!(session.transcript().submissions().len(), 0);
}

#[test]
fn intake_is_authoritatively_open_only_across_lifecycle() {
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    let mut frozen = match GuiElectionSessionV1::new(common::artifacts()) {
        Ok(session) => session,
        Err(error) => panic!("frozen session must construct: {error}"),
    };
    assert_not_open(&mut frozen, &package);

    let mut open = open_session();
    let open_result = match open.intake_ballot_package_bytes(&package) {
        Ok(result) => result,
        Err(error) => panic!("open intake must return accepted result: {error}"),
    };
    assert!(open_result.accepted);

    let mut closed = open_session();
    if let Err(error) = closed.close() {
        panic!("session must close: {error}");
    }
    assert_not_open(&mut closed, &package);

    let mut verified = open_session();
    if let Err(error) = verified.close() {
        panic!("session must close before verification: {error}");
    }
    if let Err(error) = verified.mark_verified() {
        panic!("session must mark verified: {error}");
    }
    assert_not_open(&mut verified, &package);

    let mut finalized = open_session();
    if let Err(error) = finalized.close() {
        panic!("session must close before verification: {error}");
    }
    if let Err(error) = finalized.mark_verified() {
        panic!("session must mark verified before finalization: {error}");
    }
    if let Err(error) = finalized.finalize() {
        panic!("session must finalize: {error}");
    }
    assert_not_open(&mut finalized, &package);
}

fn assert_not_open(session: &mut GuiElectionSessionV1, package: &[u8]) {
    let error = match session.intake_ballot_package_bytes(package) {
        Ok(_) => panic!("non-open session must refuse intake"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");
    assert_eq!(session.transcript().submissions().len(), 0);
}
