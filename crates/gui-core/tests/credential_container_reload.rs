mod common;

use tari_cc_private_ballot_ballot::{
    BallotConfidentialityV1, BallotKindV1, BallotPackageV1, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    ElectionLifecycleStateV1, GuiElectionArtifactsV1, GuiVoterSessionV1,
    VoterGovernanceCredentialV1, export_voter_credential_container_v1,
    import_voter_credential_container_v1, read_voter_credential_container_v1,
    write_voter_credential_container_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, verify_approval_proof,
};

#[test]
fn encrypted_reloaded_credential_uses_real_triptych_and_preserves_duplicate_protection() {
    let passphrase = "portable governance credential";
    let original = ok(VoterGovernanceCredentialV1::generate());
    let original_public_key = ok(original.public_key_bytes());
    let container = ok(export_voter_credential_container_v1(&original, passphrase));
    let dir = common::TestDir::new("credential-container-reload");
    let credential_path = dir.join("credential.tcbcred");

    ok(write_voter_credential_container_v1(
        &credential_path,
        &container,
    ));
    let read_container = ok(read_voter_credential_container_v1(&credential_path));
    let first_copy = ok(import_voter_credential_container_v1(
        &read_container,
        passphrase,
    ));
    let second_copy = ok(import_voter_credential_container_v1(
        &read_container,
        passphrase,
    ));

    assert_eq!(ok(first_copy.public_key_bytes()), original_public_key);
    assert_eq!(ok(second_copy.public_key_bytes()), original_public_key);

    let artifacts = artifacts_for_public_key(original_public_key, b"reload-election-a");
    assert!(registry_contains(
        artifacts.registry(),
        &original_public_key
    ));

    let first_bytes = prepared_package_bytes(
        first_copy,
        &artifacts,
        &[b"candidate-a".as_slice()],
        &dir.join("first.cbor"),
    );
    let second_bytes = prepared_package_bytes(
        second_copy,
        &artifacts,
        &[b"candidate-b".as_slice()],
        &dir.join("second.cbor"),
    );
    let first_verified = ok(verify_package(&artifacts, &first_bytes));
    let second_verified = ok(verify_package(&artifacts, &second_bytes));

    assert_eq!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes()
    );

    let lifecycle = open_lifecycle(&artifacts);
    let mut ledger = BallotAcceptanceLedger::new();
    ok(ledger.accept_verified(&lifecycle, first_verified));
    let duplicate = ledger.accept_verified(&lifecycle, second_verified);

    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
}

#[test]
fn same_imported_credential_has_distinct_real_triptych_nullifiers_across_elections() {
    let passphrase = "cross election credential";
    let original = ok(VoterGovernanceCredentialV1::generate());
    let original_public_key = ok(original.public_key_bytes());
    let container = ok(export_voter_credential_container_v1(&original, passphrase));

    let first_artifacts = artifacts_for_public_key(original_public_key, b"reload-election-b1");
    let second_artifacts = artifacts_for_public_key(original_public_key, b"reload-election-b2");
    let first_copy = ok(import_voter_credential_container_v1(&container, passphrase));
    let second_copy = ok(import_voter_credential_container_v1(&container, passphrase));
    let dir = common::TestDir::new("credential-container-cross-election");

    let first_bytes = prepared_package_bytes(
        first_copy,
        &first_artifacts,
        &[b"candidate-a".as_slice()],
        &dir.join("first.cbor"),
    );
    let second_bytes = prepared_package_bytes(
        second_copy,
        &second_artifacts,
        &[b"candidate-a".as_slice()],
        &dir.join("second.cbor"),
    );
    let first_verified = ok(verify_package(&first_artifacts, &first_bytes));
    let second_verified = ok(verify_package(&second_artifacts, &second_bytes));

    assert_ne!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes()
    );
    assert_ne!(
        first_verified.statement().election_scope(),
        second_verified.statement().election_scope()
    );
}

fn prepared_package_bytes(
    credential: VoterGovernanceCredentialV1,
    artifacts: &GuiElectionArtifactsV1,
    selections: &[&[u8]],
    path: &std::path::Path,
) -> Vec<u8> {
    let mut session = GuiVoterSessionV1::new(artifacts);
    let status = ok(session.install_credential(credential, artifacts));
    assert!(status.can_continue);
    let selection_hex: Vec<String> = selections
        .iter()
        .map(|selection| lower_hex(common::candidate_id(selection).as_bytes()))
        .collect();
    ok(session.set_selection(
        artifacts,
        ElectionLifecycleStateV1::Open,
        selection_hex,
        false,
    ));
    let prepared = ok(session.prepare_ballot(artifacts, ElectionLifecycleStateV1::Open));
    assert!(prepared.ready_to_export);
    ok(session.export_prepared_ballot(artifacts, ElectionLifecycleStateV1::Open, path));
    ok(std::fs::read(path))
}

fn verify_package(
    artifacts: &GuiElectionArtifactsV1,
    bytes: &[u8],
) -> Result<VerifiedApprovalBallotV1, ProtocolError> {
    let package =
        BallotPackageV1::from_canonical_cbor(bytes, artifacts.candidates(), approval_limits())?;
    let provider = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)?;

    verify_approval_proof(
        artifacts.manifest(),
        package.payload(),
        package.proof(),
        &provider,
        &verifier,
    )
}

fn artifacts_for_public_key(public_key: [u8; 32], election_id: &[u8]) -> GuiElectionArtifactsV1 {
    let provider = Blake3HashProviderV1;
    let registry = registry_from_key(public_key);
    let registry_bytes = registry_bytes_from_key(public_key);
    let candidates = common::candidate_set();
    let manifest = manifest_for(&registry, &candidates, election_id, &provider);
    let manifest_bytes = ok(manifest.to_canonical_cbor());
    let candidate_bytes = ok(candidates.to_canonical_cbor());

    ok(GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes,
        &registry_bytes,
        &candidate_bytes,
    ))
}

fn manifest_for(
    registry: &RegistrySnapshot,
    candidates: &CandidateSet,
    election_id: &[u8],
    provider: &Blake3HashProviderV1,
) -> ElectionManifestV1 {
    ok(ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: ok(ElectionId::new(election_id.to_vec())),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: ok(registry.canonical_commitment(provider)),
        candidate_set_commitment: ok(candidates.canonical_commitment(provider)),
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "credential-container-reload-test".to_owned(),
    }))
}

fn registry_from_key(public_key: [u8; 32]) -> RegistrySnapshot {
    ok(RegistrySnapshot::from_canonical_cbor(
        &registry_bytes_from_key(public_key),
    ))
}

fn registry_bytes_from_key(public_key: [u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(1).is_ok());
    assert!(writer.write_byte_string(&public_key).is_ok());
    writer.into_bytes()
}

fn registry_contains(registry: &RegistrySnapshot, public_key: &[u8; 32]) -> bool {
    registry
        .entries()
        .iter()
        .any(|entry| entry.governance_key().as_bytes() == public_key)
}

fn open_lifecycle(artifacts: &GuiElectionArtifactsV1) -> ElectionLifecycleV1 {
    let mut lifecycle = ElectionLifecycleV1::new();
    assert!(
        lifecycle
            .freeze(artifacts.manifest_hash(), artifacts.registry_commitment())
            .is_ok()
    );
    assert!(lifecycle.open().is_ok());
    lifecycle
}

fn approval_limits() -> tari_cc_private_ballot_ballot::ApprovalLimits {
    common::approval_limits()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}
