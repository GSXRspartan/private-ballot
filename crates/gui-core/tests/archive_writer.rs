//! Archive writer tests (required cases 20-26).

#![allow(clippy::expect_used)]

mod common;

use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ARCHIVE_MANIFEST_VERSION_V2, ArchiveHashV1, ArchiveManifestV1,
    TRANSPORT_ARCHIVE_BINDING_PATH_V1, TransportArchiveBatchV1, TransportArchiveBindingV1,
};
use tari_cc_private_ballot_gui_core::archive_writer::{
    submission_archive_path, write_archive_directory_v1,
    write_archive_directory_v1_with_transport_binding, write_finalized_archive_v1,
    write_finalized_archive_v1_with_governance_document,
    write_finalized_archive_v1_with_transport_binding,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiLiveAnchorConfigRequestV1, verify_archive_directory_v1,
    verify_transport_archive_anchor_v1, write_live_anchor_config_from_verified_archive_v1,
};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorConfigInputProvenanceV1, FEE_COMPONENT_ASSURANCE_VERIFIED,
    SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use common::{
    TestDir, open_session, triptych_package_bytes, write_accepted_anchor_evidence_for,
    write_anchor_evidence,
};

fn session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = open_session();
    intake_canonical_packages(&mut session);
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    session
}

fn finalized_session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = session_with_ballots();
    finalize_closed_session(&mut session);
    session
}

fn finalized_session_from_packages(packages: &[Vec<u8>]) -> GuiElectionSessionV1 {
    let mut session = open_session();
    intake_packages(&mut session, packages);
    finalize_closed_session(&mut session);
    session
}

fn finalize_closed_session(session: &mut GuiElectionSessionV1) {
    if let Err(error) = session.mark_verified() {
        panic!("session must mark verified: {error}");
    }
    if let Err(error) = session.finalize() {
        panic!("session must finalize: {error}");
    }
    assert_eq!(session.lifecycle_state(), "FINALIZED");
}

/// The canonical package byte set, built once per call. Triptych proofs use
/// fresh OS randomness by design, so callers needing identical bytes across
/// two sessions must build once and share.
fn canonical_packages() -> Vec<Vec<u8>> {
    vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate, still archived
    ]
}

fn intake_canonical_packages(session: &mut GuiElectionSessionV1) {
    for package in &canonical_packages() {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
}

fn intake_packages(session: &mut GuiElectionSessionV1, packages: &[Vec<u8>]) {
    for package in packages {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
}

#[test]
fn archive_layout_is_deterministic() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-layout");
    let target = dir.join("archive");

    let result = match write_archive_directory_v1(&session, &target) {
        Ok(result) => result,
        Err(error) => panic!("archive write must succeed: {error}"),
    };

    let paths: Vec<&str> = result.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "candidate-set.cbor",
            "election-manifest.cbor",
            submission_archive_path(0).as_str(),
            submission_archive_path(1).as_str(),
            submission_archive_path(2).as_str(),
            "voter-registry.cbor",
        ]
    );
    assert_eq!(result.archive_manifest_path, "archive-manifest.cbor");
    assert_eq!(result.archive_hash_hex.len(), 64);
    assert_eq!(result.election_manifest_hash_hex.len(), 64);
    assert!(target.join("archive-manifest.cbor").is_file());
    for file in &result.files {
        assert!(target.join(&file.path).is_file(), "missing {}", file.path);
        assert_eq!(file.digest_hex.len(), 64);
        assert!(file.bytes > 0);
    }
}

#[test]
fn identical_package_bytes_produce_identical_archives() {
    // Proofs carry fresh randomness, so determinism is asserted over identical
    // canonical package bytes ingested into two independent sessions.
    let packages = canonical_packages();
    let mut first = open_session();
    intake_packages(&mut first, &packages);
    let mut second = open_session();
    intake_packages(&mut second, &packages);
    let dir = TestDir::new("archive-determinism");

    let first_result = match write_archive_directory_v1(&first, &dir.join("first")) {
        Ok(result) => result,
        Err(_) => panic!("first write must succeed"),
    };
    let second_result = match write_archive_directory_v1(&second, &dir.join("second")) {
        Ok(result) => result,
        Err(_) => panic!("second write must succeed"),
    };

    assert_eq!(
        first_result.archive_hash_hex,
        second_result.archive_hash_hex
    );
    assert_eq!(first_result.files, second_result.files);

    // Byte-identical content, including the archive manifest file itself.
    for file in &first_result.files {
        let left = std::fs::read(dir.join("first").join(&file.path));
        let right = std::fs::read(dir.join("second").join(&file.path));
        assert_eq!(left.ok(), right.ok());
    }
    let left = std::fs::read(dir.join("first").join("archive-manifest.cbor"));
    let right = std::fs::read(dir.join("second").join("archive-manifest.cbor"));
    assert_eq!(left.ok(), right.ok());
}

#[test]
fn non_empty_target_directory_is_rejected_without_overwrite() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-collision");
    let target = dir.join("archive");
    assert!(std::fs::create_dir(&target).is_ok());
    let sentinel = target.join("pre-existing.txt");
    assert!(std::fs::write(&sentinel, b"do not touch").is_ok());

    let error = match write_archive_directory_v1(&session, &target) {
        Ok(_) => panic!("non-empty target must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_ARCHIVE_TARGET_NOT_EMPTY");

    // The pre-existing content is untouched and nothing was written.
    let contents = std::fs::read(&sentinel);
    assert_eq!(contents.ok(), Some(b"do not touch".to_vec()));
    let entry_count = match std::fs::read_dir(&target) {
        Ok(entries) => entries.count(),
        Err(_) => panic!("target dir must be readable"),
    };
    assert_eq!(entry_count, 1);
}

#[test]
fn file_target_is_rejected() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-file-target");
    let target = dir.join("not-a-dir");
    assert!(std::fs::write(&target, b"file").is_ok());

    let error = match write_archive_directory_v1(&session, &target) {
        Ok(_) => panic!("file target must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_ARCHIVE_TARGET_INVALID");
}

#[test]
fn zero_ballot_archive_writes_and_verifies() {
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let dir = TestDir::new("archive-zero-ballots");
    let target = dir.join("archive");

    let result = match write_archive_directory_v1(&session, &target) {
        Ok(result) => result,
        Err(error) => panic!("zero-ballot write must succeed: {error}"),
    };
    assert_eq!(result.files.len(), 3);

    let verification = match verify_archive_directory_v1(&target) {
        Ok(verification) => verification,
        Err(error) => panic!("zero-ballot archive must verify: {error}"),
    };
    assert!(
        verification.verified,
        "failure: {:?}",
        verification.failure_code
    );
    assert_eq!(verification.ballot_package_count, 0);
    assert_eq!(verification.accepted_count, 0);
    assert!(!verification.finalized);
}

#[test]
fn finalized_session_can_produce_finalized_archive() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finalized");
    let target = dir.join("archive");

    let written = write_finalized_archive_v1(&session, &target)
        .expect("FINALIZED session must write finalized archive");
    assert_eq!(written.archive_hash_hex.len(), 64);

    let verified = verify_archive_directory_v1(&target).expect("archive must verify");
    assert!(verified.verified, "failure: {:?}", verified.failure_code);
    assert!(verified.finalized);

    let manifest_bytes = std::fs::read(target.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("archive manifest must read");
    let manifest = ArchiveManifestV1::from_canonical_cbor(&manifest_bytes)
        .expect("archive manifest must decode");
    assert_eq!(
        manifest.archive_manifest_version(),
        ARCHIVE_MANIFEST_VERSION_V2
    );
    assert_eq!(manifest.final_lifecycle_state(), Some("FINALIZED"));
    assert!(manifest.is_finalized_archive_manifest());
}

#[test]
fn finalized_governance_archive_path_keeps_finalized_gate() {
    let doc = b"governance source bytes";
    let mut verified = session_with_ballots();
    verified
        .mark_verified()
        .expect("session should reach VERIFIED");
    let dir = TestDir::new("archive-finalized-governance-gate");

    let error = write_finalized_archive_v1_with_governance_document(
        &verified,
        &dir.join("verified"),
        Some(doc),
    )
    .expect_err("VERIFIED session must not write finalized archive");
    assert_eq!(error.code(), "GUI_ARCHIVE_NOT_FINALIZED");

    let mut finalized = verified;
    finalized.finalize().expect("session should reach FINALIZED");
    let target = dir.join("finalized");
    write_finalized_archive_v1_with_governance_document(&finalized, &target, Some(doc))
        .expect("FINALIZED session must write finalized archive with governance document");

    let verification = verify_archive_directory_v1(&target).expect("archive must verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
    assert!(verification.finalized);
    assert!(
        verification
            .files
            .iter()
            .any(|file| file.path == "governance/source.bin" && file.present)
    );
}

#[test]
fn legacy_archive_verifies_but_is_not_finalized() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-legacy-not-finalized");
    let target = dir.join("archive");
    write_archive_directory_v1(&session, &target).expect("legacy archive must write");

    let verified = verify_archive_directory_v1(&target).expect("archive must verify");
    assert!(verified.verified, "failure: {:?}", verified.failure_code);
    assert!(!verified.finalized);
}

#[test]
fn non_final_lifecycle_states_cannot_write_finalized_archive() {
    let open = open_session();
    let dir = TestDir::new("archive-finality-open");
    let error = write_finalized_archive_v1(&open, &dir.join("archive"))
        .expect_err("OPEN session must not write finalized archive");
    assert_eq!(error.code(), "GUI_ARCHIVE_NOT_FINALIZED");

    let closed = session_with_ballots();
    let dir = TestDir::new("archive-finality-closed");
    let error = write_finalized_archive_v1(&closed, &dir.join("archive"))
        .expect_err("CLOSED session must not write finalized archive");
    assert_eq!(error.code(), "GUI_ARCHIVE_NOT_FINALIZED");

    let mut verified = session_with_ballots();
    verified
        .mark_verified()
        .expect("session should reach VERIFIED");
    let dir = TestDir::new("archive-finality-verified");
    let error = write_finalized_archive_v1(&verified, &dir.join("archive"))
        .expect_err("VERIFIED session must not write finalized archive");
    assert_eq!(error.code(), "GUI_ARCHIVE_NOT_FINALIZED");
}

#[test]
fn finalized_archive_commitment_is_deterministic_for_same_bytes() {
    let packages = canonical_packages();
    let first = finalized_session_from_packages(&packages);
    let second = finalized_session_from_packages(&packages);
    let dir = TestDir::new("archive-finality-deterministic");

    let first_result = write_finalized_archive_v1(&first, &dir.join("first"))
        .expect("first finalized archive must write");
    let second_result = write_finalized_archive_v1(&second, &dir.join("second"))
        .expect("second finalized archive must write");

    assert_eq!(
        first_result.archive_hash_hex,
        second_result.archive_hash_hex
    );
    let first_manifest = std::fs::read(dir.join("first").join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("first manifest must read");
    let second_manifest = std::fs::read(dir.join("second").join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("second manifest must read");
    assert_eq!(first_manifest, second_manifest);
}

#[test]
fn finalized_archive_non_empty_target_is_rejected() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finality-non-empty");
    let target = dir.join("archive");
    std::fs::create_dir(&target).expect("target directory must create");
    std::fs::write(target.join("sentinel.txt"), b"keep").expect("sentinel must write");

    let error = write_finalized_archive_v1(&session, &target)
        .expect_err("non-empty target must be rejected");
    assert_eq!(error.code(), "GUI_ARCHIVE_TARGET_NOT_EMPTY");
    assert_eq!(
        std::fs::read(target.join("sentinel.txt")).expect("sentinel must remain"),
        b"keep"
    );
}

#[test]
fn finalized_lifecycle_value_mutation_is_rejected() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finality-lifecycle-mutation");
    let target = dir.join("archive");
    write_finalized_archive_v1(&session, &target).expect("finalized archive must write");

    let manifest_path = target.join(ARCHIVE_MANIFEST_CANONICAL_PATH);
    let mut bytes = std::fs::read(&manifest_path).expect("manifest must read");
    let needle = b"FINALIZED";
    let replacement = b"VERIFIEDX";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("FINALIZED marker must be present");
    bytes[offset..offset + needle.len()].copy_from_slice(replacement);
    std::fs::write(&manifest_path, bytes).expect("manifest mutation must write");

    let result = verify_archive_directory_v1(&target).expect("verification result");
    assert!(!result.verified);
    assert!(!result.finalized);
    assert_eq!(result.failure_stage, Some("ARCHIVE_MANIFEST"));
}

#[test]
fn finalized_manifest_copied_to_different_submission_set_is_rejected() {
    let first = finalized_session_with_ballots();
    let second = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finality-copy");
    let first_target = dir.join("first");
    let second_target = dir.join("second");
    write_finalized_archive_v1(&first, &first_target).expect("first archive must write");
    write_finalized_archive_v1(&second, &second_target).expect("second archive must write");

    let copied = std::fs::read(first_target.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("first manifest must read");
    std::fs::write(second_target.join(ARCHIVE_MANIFEST_CANONICAL_PATH), copied)
        .expect("manifest copy must write");

    let result = verify_archive_directory_v1(&second_target).expect("verification result");
    assert!(!result.verified);
    assert!(!result.finalized);
}

#[test]
fn changed_submission_after_finality_commitment_is_rejected() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finality-submission-mutation");
    let target = dir.join("archive");
    write_finalized_archive_v1(&session, &target).expect("finalized archive must write");

    let path = target.join(submission_archive_path(0));
    let mut bytes = std::fs::read(&path).expect("submission must read");
    bytes[0] ^= 1;
    std::fs::write(&path, bytes).expect("submission mutation must write");

    let result = verify_archive_directory_v1(&target).expect("verification result");
    assert!(!result.verified);
    assert!(!result.finalized);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn changed_manifest_after_finality_commitment_is_rejected() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-finality-manifest-mutation");
    let target = dir.join("archive");
    write_finalized_archive_v1(&session, &target).expect("finalized archive must write");

    let path = target.join("election-manifest.cbor");
    let mut bytes = std::fs::read(&path).expect("manifest must read");
    bytes[0] ^= 1;
    std::fs::write(&path, bytes).expect("manifest mutation must write");

    let result = verify_archive_directory_v1(&target).expect("verification result");
    assert!(!result.verified);
    assert!(!result.finalized);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
}

fn transport_binding(session: &GuiElectionSessionV1) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session
            .artifacts()
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        session.artifacts().manifest_hash(),
        [7; 32],
        3,
        vec![
            TransportArchiveBatchV1::new(9, [9; 32], 2, false),
            TransportArchiveBatchV1::new(4, [4; 32], 1, true),
        ],
    )
    .expect("fixture transport binding must construct")
}

fn live_transport_binding(
    session: &GuiElectionSessionV1,
    reduced_anonymity: bool,
) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session
            .artifacts()
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        session.artifacts().manifest_hash(),
        [8; 32],
        4,
        vec![TransportArchiveBatchV1::new(
            1,
            [1; 32],
            session.transcript().accepted_count() as u64,
            reduced_anonymity,
        )],
    )
    .expect("live fixture transport binding must construct")
}

fn live_config_request(
    dir: &TestDir,
    archive_directory: &std::path::Path,
    floor: u64,
    reduced_anonymity_acknowledged: bool,
) -> GuiLiveAnchorConfigRequestV1 {
    GuiLiveAnchorConfigRequestV1 {
        archive_directory: archive_directory.to_string_lossy().into_owned(),
        output_config_path: dir
            .join("live-anchor-config.cbor")
            .to_string_lossy()
            .into_owned(),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:12009".to_owned(),
        indexer_endpoint: "http://127.0.0.1:12500".to_owned(),
        account_reference: "fee-account".to_owned(),
        fee_component: format!("component_{}", "11".repeat(32)),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        declared_seal_public_key: "seal-public-key-attested".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1_000,
        required_accepted_ballot_floor: floor,
        reduced_anonymity_acknowledged,
        snapshot_path: dir
            .join("live-anchor-snapshot.cbor")
            .to_string_lossy()
            .into_owned(),
        evidence_path: dir
            .join("live-anchor-evidence.cbor")
            .to_string_lossy()
            .into_owned(),
        backoff_base_secs: 1,
        backoff_cap_secs: 2,
        receipt_query_attempts: 8,
        request_timeout_secs: Some(30),
        ttl_secs: None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn live_anchor_config_from_finalized_archive_accepts_exact_floor() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-live-config-success");
    let target = dir.join("archive");
    let binding = live_transport_binding(&session, false);
    write_finalized_archive_v1_with_transport_binding(&session, &target, &binding)
        .expect("finalized bound archive must write");
    let verification = verify_archive_directory_v1(&target).expect("archive must verify");
    let floor = verification.accepted_count as u64;
    let request = live_config_request(&dir, &target, floor, false);

    let result = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect("live config must write");

    assert_eq!(result.input_provenance, "ArchiveVerified");
    assert_eq!(
        result.manifest_hash_hex,
        verification
            .election_manifest_hash_hex
            .expect("manifest hash present")
    );
    assert_eq!(
        result.archive_hash_hex,
        verification.archive_hash_hex.expect("archive hash present")
    );
    assert_eq!(result.accepted_ballot_count, floor);
    assert_eq!(result.required_accepted_ballot_floor, floor);
    assert!(!result.reduced_anonymity);
    assert_eq!(result.seal_assurance, "ATTESTED");
    assert!(std::path::Path::new(&result.config_path).exists());

    let config = AnchorAppConfig::from_canonical_file(std::path::Path::new(&result.config_path))
        .expect("written config must decode");
    assert_eq!(
        config.input_provenance(),
        AnchorConfigInputProvenanceV1::ArchiveVerified
    );
    let facts = config
        .live_approval_facts()
        .expect("live config must bind approval facts");
    assert!(facts.finalized_archive());
    assert_eq!(facts.accepted_ballot_count(), floor);
    assert_eq!(facts.required_accepted_ballot_floor(), floor);
    assert!(!facts.reduced_anonymity());
    assert!(!facts.reduced_anonymity_acknowledged());
    assert_eq!(
        facts.declared_seal_public_key(),
        request.declared_seal_public_key.as_str()
    );
    assert!(facts.dedicated_organizer_wallet_attested());
    assert_eq!(
        facts.fee_component_assurance(),
        FEE_COMPONENT_ASSURANCE_VERIFIED
    );
    assert_eq!(
        facts.seal_public_key_assurance(),
        SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED
    );
}

#[test]
fn live_anchor_config_rejects_legacy_verified_archive() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-live-config-legacy");
    let target = dir.join("archive");
    let binding = live_transport_binding(&session, false);
    write_archive_directory_v1_with_transport_binding(&session, &target, &binding)
        .expect("legacy bound archive must write");
    let request = live_config_request(
        &dir,
        &target,
        session.transcript().accepted_count() as u64,
        false,
    );

    let error = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect_err("legacy archive must not produce live config");
    assert_eq!(error.code(), "GUI_LIVE_ANCHOR_ARCHIVE_NOT_FINALIZED");
}

#[test]
fn live_anchor_config_rejects_accepted_count_below_floor() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-live-config-floor");
    let target = dir.join("archive");
    let binding = live_transport_binding(&session, false);
    write_finalized_archive_v1_with_transport_binding(&session, &target, &binding)
        .expect("finalized bound archive must write");
    let request = live_config_request(
        &dir,
        &target,
        session.transcript().accepted_count() as u64 + 1,
        false,
    );

    let error = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect_err("floor above accepted count must fail");
    assert_eq!(error.code(), "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_NOT_MET");
}

#[test]
fn live_anchor_config_requires_reduced_anonymity_acknowledgement() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-live-config-reduced");
    let target = dir.join("archive");
    let binding = live_transport_binding(&session, true);
    write_finalized_archive_v1_with_transport_binding(&session, &target, &binding)
        .expect("finalized bound archive must write");
    let floor = session.transcript().accepted_count() as u64;
    let request = live_config_request(&dir, &target, floor, false);

    let error = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect_err("reduced anonymity requires acknowledgement");
    assert_eq!(
        error.code(),
        "GUI_LIVE_ANCHOR_REDUCED_ANONYMITY_ACK_REQUIRED"
    );

    let second_dir = TestDir::new("archive-live-config-reduced-ack");
    let second_request = live_config_request(&second_dir, &target, floor, true);
    let result = write_live_anchor_config_from_verified_archive_v1(&second_request)
        .expect("acknowledged reduced anonymity can write");
    assert!(result.reduced_anonymity);
    assert!(result.reduced_anonymity_acknowledged);
    let config = AnchorAppConfig::from_canonical_file(std::path::Path::new(&result.config_path))
        .expect("written reduced config must decode");
    let facts = config
        .live_approval_facts()
        .expect("reduced config must bind approval facts");
    assert!(facts.reduced_anonymity());
    assert!(facts.reduced_anonymity_acknowledged());
}

#[test]
fn live_anchor_config_requires_dedicated_wallet_attestation() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-live-config-dedicated-wallet");
    let target = dir.join("archive");
    let binding = live_transport_binding(&session, false);
    write_finalized_archive_v1_with_transport_binding(&session, &target, &binding)
        .expect("finalized bound archive must write");
    let floor = session.transcript().accepted_count() as u64;
    let mut request = live_config_request(&dir, &target, floor, false);
    request.dedicated_organizer_wallet_attested = false;

    let error = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect_err("dedicated wallet attestation is required");
    assert_eq!(error.code(), "GUI_LIVE_ANCHOR_DEDICATED_WALLET_REQUIRED");
}

#[test]
fn live_anchor_config_rejects_transport_accepted_count_mismatch() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-live-config-transport-mismatch");
    let target = dir.join("archive");
    let binding = transport_binding(&session);
    write_finalized_archive_v1_with_transport_binding(&session, &target, &binding)
        .expect("finalized bound archive must write");
    let request = live_config_request(
        &dir,
        &target,
        session.transcript().accepted_count() as u64,
        true,
    );

    let error = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect_err("transport count mismatch must fail");
    assert_eq!(error.code(), "GUI_LIVE_ANCHOR_TRANSPORT_COUNT_MISMATCH");
}

#[test]
fn transport_binding_is_covered_by_the_completed_archive_hash() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-binding");
    let target = dir.join("archive");
    let binding = transport_binding(&session);

    let written = write_archive_directory_v1_with_transport_binding(&session, &target, &binding)
        .expect("bound archive must write");
    assert!(
        written
            .files
            .iter()
            .any(|file| file.path == TRANSPORT_ARCHIVE_BINDING_PATH_V1)
    );

    let verified = verify_archive_directory_v1(&target).expect("archive must verify");
    assert!(verified.verified, "failure: {:?}", verified.failure_code);
    assert!(verified.transport_binding_present);
    assert!(verified.transport_binding_verified);
    assert_eq!(
        verified.transport_batch_set_commitment_hex,
        Some(lower_hex(&binding.final_batch_set_commitment()))
    );

    let binding_path = target.join(TRANSPORT_ARCHIVE_BINDING_PATH_V1);
    let mut bytes = std::fs::read(&binding_path).expect("binding must be readable");
    bytes[0] ^= 1;
    std::fs::write(binding_path, bytes).expect("binding mutation must write");
    let mutated = verify_archive_directory_v1(&target).expect("integrity result");
    assert!(!mutated.verified);
    assert_eq!(mutated.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn transport_binding_for_another_election_is_rejected_before_archive_hashing() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-binding-mismatch");
    let binding = TransportArchiveBindingV1::new(
        b"other-election".to_vec(),
        session.artifacts().manifest_hash(),
        [7; 32],
        3,
        vec![TransportArchiveBatchV1::new(1, [1; 32], 1, false)],
    )
    .expect("syntactically valid other-election binding");

    let error =
        write_archive_directory_v1_with_transport_binding(&session, &dir.join("archive"), &binding)
            .expect_err("mismatched binding must be rejected");
    assert_eq!(error.code(), "GUI_TRANSPORT_ARCHIVE_BINDING_MISMATCH");
}

#[test]
fn unrelated_or_non_success_phase4_evidence_never_marks_transport_anchored() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-rejected");
    let target = dir.join("archive");
    write_finalized_archive_v1_with_transport_binding(
        &session,
        &target,
        &transport_binding(&session),
    )
    .expect("bound archive must write");

    // The fixture is a valid existing Phase 4 non-success evidence record for
    // another archive. It must not promote this transport commitment.
    let evidence_path = write_anchor_evidence(dir.path());
    let result =
        verify_transport_archive_anchor_v1(&target, &evidence_path).expect("verification result");
    assert_eq!(result.state, "INCLUDED");
    assert!(result.transport_binding_verified);
    assert!(result.archive_finalized);
    assert!(!result.anchor_verified);
}

#[test]
fn exact_finalized_accept_evidence_marks_transport_anchored() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-accepted");
    let target = dir.join("archive");
    write_finalized_archive_v1_with_transport_binding(
        &session,
        &target,
        &transport_binding(&session),
    )
    .expect("bound archive must write");
    let manifest_bytes = std::fs::read(target.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("archive manifest reads");
    let archive_manifest =
        ArchiveManifestV1::from_canonical_cbor(&manifest_bytes).expect("archive manifest decodes");
    let archive_hash = archive_manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("archive hash derives");
    let evidence = write_accepted_anchor_evidence_for(
        dir.path(),
        session.artifacts().manifest_hash(),
        archive_hash,
        session.transcript().accepted_count() as u64,
    );
    let result =
        verify_transport_archive_anchor_v1(&target, &evidence).expect("accepted evidence verifies");
    assert_eq!(result.state, "ANCHORED");
    assert!(result.archive_finalized);
    assert!(result.anchor_verified);
}

#[test]
fn finalized_accept_evidence_for_another_archive_never_marks_transport_anchored() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-wrong-archive");
    let target = dir.join("archive");
    write_finalized_archive_v1_with_transport_binding(
        &session,
        &target,
        &transport_binding(&session),
    )
    .expect("bound archive must write");
    let evidence = write_accepted_anchor_evidence_for(
        dir.path(),
        session.artifacts().manifest_hash(),
        ArchiveHashV1::new([0xA5; 32]),
        session.transcript().accepted_count() as u64,
    );
    let result = verify_transport_archive_anchor_v1(&target, &evidence)
        .expect("mismatched evidence returns safe state");
    assert_eq!(result.state, "INCLUDED");
    assert!(!result.anchor_verified);
}

#[test]
fn legacy_verified_transport_archive_never_marks_transport_anchored() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-legacy");
    let target = dir.join("archive");
    write_archive_directory_v1_with_transport_binding(
        &session,
        &target,
        &transport_binding(&session),
    )
    .expect("legacy bound archive must write");
    let manifest_bytes = std::fs::read(target.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("archive manifest reads");
    let archive_manifest =
        ArchiveManifestV1::from_canonical_cbor(&manifest_bytes).expect("archive manifest decodes");
    let archive_hash = archive_manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("archive hash derives");
    let evidence = write_accepted_anchor_evidence_for(
        dir.path(),
        session.artifacts().manifest_hash(),
        archive_hash,
        session.transcript().accepted_count() as u64,
    );

    let result =
        verify_transport_archive_anchor_v1(&target, &evidence).expect("accepted evidence verifies");
    assert_eq!(result.state, "INCLUDED");
    assert!(result.archive_verified);
    assert!(!result.archive_finalized);
    assert!(result.transport_binding_verified);
    assert!(!result.anchor_verified);
}
