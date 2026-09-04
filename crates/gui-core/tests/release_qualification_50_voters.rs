//! Release qualification fixture for the first hard-use scale stage.
//!
//! This is intentionally an isolated integration target: it uses a 50-member
//! registry, canonical artifacts, and real Triptych proofs without changing
//! production protocol or durable-format behavior.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use curve25519_dalek_v4::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_v4::scalar::Scalar;
use tari_cc_private_ballot_archive::{
    ArchiveVerificationCountersSnapshotV1, ArchiveVerificationMemoV1, TransportArchiveBatchV1,
    TransportArchiveBindingV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionArtifactsV1, GuiElectionSessionV1, GuiLiveAnchorConfigRequestV1,
    LoadedElectionWorkspaceV1, VerifiedElectionSessionCacheV1,
    advance_verified_session_after_commit_v1, append_accepted_ballot_package_to_inbox_v1,
    archive_verification_snapshot, ensure_election_workspaces_directory_v1,
    ingest_private_intake_inbox_into_session_v1, instrumentation,
    reset_archive_verification_counters, resume_election_workspace_with_verified_session_cache_v1,
    verify_archive_directory_with_memo_v1, workspace_id_for_session_v1,
    write_finalized_archive_v1_with_transport_binding,
    write_live_anchor_config_from_verified_archive_with_memo_v1,
    write_session_workspace_revision_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};

const MEMBER_COUNT: usize = 50;
const DIRECT_VALID_COUNT: usize = 44;

struct QualificationFixture {
    artifacts: GuiElectionArtifactsV1,
    manifest: ElectionManifestV1,
    candidates: CandidateSet,
    registry: RegistrySnapshot,
    secret_keys: Vec<[u8; 32]>,
}

struct TestDir {
    path: std::path::PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "gui-core-release-qualification-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("qualification directory must be creatable");
        Self { path }
    }

    fn join(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn candidate(id: &[u8], label: &str) -> CandidateDefinition {
    CandidateDefinition::new(
        CandidateId::new(id.to_vec()).expect("candidate identifier must be valid"),
        label.to_owned(),
    )
    .expect("candidate must be valid")
}

fn qualification_fixture() -> QualificationFixture {
    let provider = Blake3HashProviderV1;
    let mut public_keys = Vec::with_capacity(MEMBER_COUNT);
    let mut secret_keys = Vec::with_capacity(MEMBER_COUNT);
    for scalar in 101_u64..=150 {
        let scalar = Scalar::from(scalar);
        public_keys.push((RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes());
        secret_keys.push(scalar.to_bytes());
    }
    public_keys.sort_unstable();

    let mut registry_writer = CanonicalCborWriter::new();
    registry_writer
        .write_array_len(public_keys.len())
        .expect("registry length must encode");
    for public_key in public_keys {
        registry_writer
            .write_byte_string(&public_key)
            .expect("registry key must encode");
    }
    let registry_bytes = registry_writer.into_bytes();
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_bytes)
        .expect("50-member registry must decode");

    let candidates = CandidateSet::new(vec![
        candidate(b"candidate-avery", "Avery Chen"),
        candidate(b"candidate-blair", "Blair Morgan"),
        candidate(b"candidate-casey", "Casey Rivera"),
    ])
    .expect("candidate set must be valid");
    let candidates_bytes = candidates
        .to_canonical_cbor()
        .expect("candidate set must encode");
    let manifest = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: ElectionId::new(b"release-qualification-50-voters".to_vec())
            .expect("election identifier must be valid"),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: registry
            .canonical_commitment(&provider)
            .expect("registry commitment must derive"),
        candidate_set_commitment: candidates
            .canonical_commitment(&provider)
            .expect("candidate commitment must derive"),
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: ApprovalLimits::new(1, 1, false).expect("approval limits must be valid"),
        governance_source_revision: "release-qualification-fixture-v1".to_owned(),
    })
    .expect("manifest must be valid");
    let manifest_bytes = manifest.to_canonical_cbor().expect("manifest must encode");
    let artifacts =
        GuiElectionArtifactsV1::from_bytes(&manifest_bytes, &registry_bytes, &candidates_bytes)
            .expect("validated artifacts must load");

    QualificationFixture {
        artifacts,
        manifest,
        candidates,
        registry,
        secret_keys,
    }
}

fn real_package(fixture: &QualificationFixture, voter_index: usize, selection: &[u8]) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let payload = ApprovalBallotPayload::new(
        vec![CandidateId::new(selection.to_vec()).expect("selection identifier must be valid")],
        &fixture.candidates,
        fixture.manifest.approval_limits(),
    )
    .expect("payload must be valid");
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
        .expect("registry verifier must build");
    let statement = reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider)
        .expect("proof statement must reconstruct");
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(fixture.secret_keys[voter_index])
        .expect("fixture secret must be canonical");
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret)
        .expect("real Triptych proof must construct");
    BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: fixture
            .manifest
            .canonical_hash(&provider)
            .expect("manifest hash must derive"),
        proof_suite_id: fixture.manifest.proof_suite_id().to_owned(),
        proof,
        payload,
    })
    .expect("ballot package must be valid")
    .to_canonical_cbor()
    .expect("ballot package must encode")
}

fn resume(
    root: &Path,
    workspace_id: &str,
    cache: &VerifiedElectionSessionCacheV1,
) -> GuiElectionSessionV1 {
    match resume_election_workspace_with_verified_session_cache_v1(root, workspace_id, cache)
        .expect("workspace resume must succeed")
    {
        LoadedElectionWorkspaceV1::Session { session, .. } => session,
        LoadedElectionWorkspaceV1::Draft { .. } => {
            panic!("qualification requires a session workspace")
        }
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = (sorted.len() * numerator)
        .div_ceil(denominator)
        .saturating_sub(1);
    sorted[rank]
}

fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .expect("qualification directory must be readable")
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                directory_bytes(&path)
            } else {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            }
        })
        .sum()
}

fn archive_delta(
    before: ArchiveVerificationCountersSnapshotV1,
    after: ArchiveVerificationCountersSnapshotV1,
) -> ArchiveVerificationCountersSnapshotV1 {
    ArchiveVerificationCountersSnapshotV1 {
        archive_verification_cache_hits: after.archive_verification_cache_hits
            - before.archive_verification_cache_hits,
        archive_verification_cache_misses: after.archive_verification_cache_misses
            - before.archive_verification_cache_misses,
        archive_full_verification_count: after.archive_full_verification_count
            - before.archive_full_verification_count,
        archive_catalog_revalidations: after.archive_catalog_revalidations
            - before.archive_catalog_revalidations,
        archive_historical_replay_count: after.archive_historical_replay_count
            - before.archive_historical_replay_count,
        archive_historical_triptych_verifies: after.archive_historical_triptych_verifies
            - before.archive_historical_triptych_verifies,
        archive_cache_evictions: after.archive_cache_evictions - before.archive_cache_evictions,
        archive_cache_identity_drift: after.archive_cache_identity_drift
            - before.archive_cache_identity_drift,
        archive_single_flight_waits: after.archive_single_flight_waits
            - before.archive_single_flight_waits,
    }
}

#[test]
fn release_qualification_exercises_a_50_member_election() {
    let fixture_start = Instant::now();
    let fixture = qualification_fixture();
    assert_eq!(fixture.artifacts.registry().len(), MEMBER_COUNT);
    let mut session = GuiElectionSessionV1::new(fixture.artifacts.clone())
        .expect("session must construct from the qualification artifacts");
    session.open().expect("session must open");
    let election_creation_us = micros(fixture_start.elapsed());

    let temp = TestDir::new("50-voters");
    let workspace_root = ensure_election_workspaces_directory_v1(&temp.join("workspaces"))
        .expect("workspace root must be created");
    let workspace_id = workspace_id_for_session_v1(&session);
    write_session_workspace_revision_v1(&workspace_root, &workspace_id, &session)
        .expect("initial workspace revision must write");

    let live_cache = VerifiedElectionSessionCacheV1::default();
    instrumentation::reset();
    let _initial_resume = resume(&workspace_root, &workspace_id, &live_cache);
    let initial_resume = instrumentation::snapshot();
    assert_eq!(initial_resume.historical_ballots_replayed, 0);

    let selections: [&[u8]; 3] = [b"candidate-avery", b"candidate-blair", b"candidate-casey"];
    let proof_generation_start = Instant::now();
    let mut direct_valid = Vec::with_capacity(DIRECT_VALID_COUNT);
    for voter_index in 0..DIRECT_VALID_COUNT {
        direct_valid.push(real_package(
            &fixture,
            voter_index,
            selections[voter_index % selections.len()],
        ));
    }
    let private_package = real_package(&fixture, 44, selections[2]);
    let duplicate_package = real_package(&fixture, 0, selections[1]);
    let valid_after_rejection = real_package(&fixture, 45, selections[0]);
    let final_valid = real_package(&fixture, 46, selections[1]);
    let proof_generation_us = micros(proof_generation_start.elapsed());

    let mut intake_us = Vec::new();
    let first_start = Instant::now();
    assert!(
        session
            .intake_ballot(&direct_valid[0])
            .expect("first real ballot must intake")
            .accepted
    );
    intake_us.push(micros(first_start.elapsed()));
    let advanced_revision =
        write_session_workspace_revision_v1(&workspace_root, &workspace_id, &session)
            .expect("first mutation must persist");
    assert!(
        advance_verified_session_after_commit_v1(
            &workspace_root,
            &workspace_id,
            advanced_revision,
            &session,
            &live_cache,
        )
        .expect("verified session advance must check")
    );
    instrumentation::reset();
    let _post_mutation = resume(&workspace_root, &workspace_id, &live_cache);
    let post_mutation = instrumentation::snapshot();
    assert_eq!(post_mutation.historical_ballots_replayed, 0);
    assert_eq!(post_mutation.triptych_adapter_verify_calls, 0);

    for package in direct_valid.iter().skip(1) {
        let start = Instant::now();
        assert!(
            session
                .intake_ballot(package)
                .expect("real ballot must intake")
                .accepted
        );
        intake_us.push(micros(start.elapsed()));
    }

    let inbox = temp.join("private-inbox");
    assert!(
        append_accepted_ballot_package_to_inbox_v1(&inbox, &private_package)
            .expect("private-intake package must persist")
    );
    let private_start = Instant::now();
    let private_first = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("private-intake reconciliation must succeed");
    let private_intake_us = micros(private_start.elapsed());
    assert_eq!(private_first.newly_accepted, 1);

    let duplicate_start = Instant::now();
    let duplicate = session
        .intake_ballot(&duplicate_package)
        .expect("duplicate package is a recorded rejection");
    intake_us.push(micros(duplicate_start.elapsed()));
    assert!(!duplicate.accepted);
    assert_eq!(duplicate.code, "DUPLICATE_BALLOT");

    let mut malformed = valid_after_rejection.clone();
    malformed.pop();
    let malformed_start = Instant::now();
    let malformed_result = session
        .intake_ballot(&malformed)
        .expect("malformed package is a recorded rejection");
    intake_us.push(micros(malformed_start.elapsed()));
    assert!(!malformed_result.accepted);

    let replayed_start = Instant::now();
    let private_replay = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("already-decided private package must reconcile");
    let private_replay_us = micros(replayed_start.elapsed());
    assert_eq!(private_replay.newly_accepted, 0);
    assert_eq!(private_replay.duplicates, 1);

    for package in [&valid_after_rejection, &final_valid] {
        let start = Instant::now();
        assert!(
            session
                .intake_ballot(package)
                .expect("later valid ballot must intake")
                .accepted
        );
        intake_us.push(micros(start.elapsed()));
    }
    assert_eq!(session.accepted_count(), 47);
    assert_eq!(
        session.packages().len(),
        49,
        "reconciliation retry is not re-recorded"
    );

    for package in
        direct_valid
            .iter()
            .chain([&private_package, &valid_after_rejection, &final_valid])
    {
        let _ = append_accepted_ballot_package_to_inbox_v1(&inbox, package)
            .expect("accepted package must be appendable to the qualification inbox");
    }
    instrumentation::reset();
    let indexed_sync = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("indexed private reconciliation must succeed");
    let indexed_counters = instrumentation::snapshot();
    assert_eq!(indexed_sync.discovered, 47);
    assert_eq!(indexed_sync.duplicates, 47);
    assert_eq!(indexed_counters.private_intake_digest_index_hits, 47);
    assert_eq!(indexed_counters.private_intake_linear_transcript_scans, 0);

    instrumentation::reset();
    let unchanged_sync = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("unchanged inbox reconciliation must succeed");
    let unchanged_counters = instrumentation::snapshot();
    assert_eq!(unchanged_sync.duplicates, 47);
    assert_eq!(unchanged_counters.private_inbox_files_skipped_unchanged, 47);
    assert_eq!(unchanged_counters.private_intake_linear_transcript_scans, 0);

    write_session_workspace_revision_v1(&workspace_root, &workspace_id, &session)
        .expect("full intake state must persist");
    let workspace_bytes = directory_bytes(&workspace_root);

    let cold_cache = VerifiedElectionSessionCacheV1::default();
    instrumentation::reset();
    let cold_start = Instant::now();
    let cold = resume(&workspace_root, &workspace_id, &cold_cache);
    let cold_resume_us = micros(cold_start.elapsed());
    let cold_counters = instrumentation::snapshot();
    assert_eq!(cold.accepted_count(), session.accepted_count());
    assert_eq!(cold.transcript(), session.transcript());
    assert_eq!(cold_counters.historical_ballots_replayed, 49);
    assert!(cold_counters.historical_parallel_reconstruction_count >= 1);

    instrumentation::reset();
    let warm_start = Instant::now();
    let warm = resume(&workspace_root, &workspace_id, &cold_cache);
    let warm_resume_us = micros(warm_start.elapsed());
    let warm_counters = instrumentation::snapshot();
    assert_eq!(warm.accepted_count(), session.accepted_count());
    assert_eq!(warm_counters.historical_ballots_replayed, 0);
    assert_eq!(warm_counters.triptych_adapter_verify_calls, 0);
    assert_eq!(warm_counters.verified_session_cache_hits, 1);

    let close_start = Instant::now();
    session.close().expect("election must close");
    let close_us = micros(close_start.elapsed());
    let tally_start = Instant::now();
    let first_tally = session.tally().expect("closed tally must compute");
    let tally_us = micros(tally_start.elapsed());
    let repeat_tally = session.tally().expect("repeated tally must compute");
    assert_eq!(first_tally, repeat_tally);
    assert_eq!(first_tally.accepted_ballots, 47);
    assert_eq!(first_tally.counts.len(), 3);
    assert_eq!(first_tally.counts[0].display_name, "Avery Chen");
    assert_eq!(first_tally.counts[1].display_name, "Blair Morgan");
    assert_eq!(first_tally.counts[2].display_name, "Casey Rivera");

    let finalize_start = Instant::now();
    session
        .mark_verified()
        .expect("closed election must mark verified");
    session.finalize().expect("verified election must finalize");
    let finalize_us = micros(finalize_start.elapsed());

    let archive = temp.join("archive");
    let transport_binding = TransportArchiveBindingV1::new(
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
            session.accepted_count() as u64,
            false,
        )],
    )
    .expect("non-network transport binding must be valid");
    let archive_start = Instant::now();
    write_finalized_archive_v1_with_transport_binding(&session, &archive, &transport_binding)
        .expect("finalized archive must write");
    let archive_write_us = micros(archive_start.elapsed());

    let memo = ArchiveVerificationMemoV1::default();
    reset_archive_verification_counters();
    let first_verify_start = Instant::now();
    let first_archive = verify_archive_directory_with_memo_v1(&memo, &archive)
        .expect("first archive verification must complete");
    let first_archive_us = micros(first_verify_start.elapsed());
    let first_archive_counters = archive_delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(first_archive.verified);
    assert_eq!(first_archive_counters.archive_historical_replay_count, 1);

    let memo_before = archive_verification_snapshot();
    let memo_verify_start = Instant::now();
    let second_archive = verify_archive_directory_with_memo_v1(&memo, &archive)
        .expect("memoized archive verification must complete");
    let memo_archive_us = micros(memo_verify_start.elapsed());
    let memo_archive_counters = archive_delta(memo_before, archive_verification_snapshot());
    assert_eq!(first_archive, second_archive);
    assert_eq!(
        memo_archive_counters.archive_historical_triptych_verifies,
        0
    );

    let anchor_config = GuiLiveAnchorConfigRequestV1 {
        archive_directory: archive.to_string_lossy().into_owned(),
        output_config_path: temp
            .join("anchor-config.cbor")
            .to_string_lossy()
            .into_owned(),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:12009".to_owned(),
        indexer_endpoint: "http://127.0.0.1:50124".to_owned(),
        template_address: format!("template_{}", "22".repeat(32)),
        template_module: "tari_private_ballot_anchor".to_owned(),
        template_event_topic: "tari_private_ballot_anchor.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1"
            .to_owned(),
        template_artifact_digest_hex: "33".repeat(32),
        max_epoch_delta: 12,
        account_reference: "fee-account".to_owned(),
        fee_component: format!("component_{}", "11".repeat(32)),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        declared_seal_public_key: "release-qualification-attested".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1_000,
        required_accepted_ballot_floor: 47,
        reduced_anonymity_acknowledged: false,
        snapshot_path: temp
            .join("anchor-snapshot.cbor")
            .to_string_lossy()
            .into_owned(),
        evidence_path: temp
            .join("anchor-evidence.cbor")
            .to_string_lossy()
            .into_owned(),
        backoff_base_secs: 1,
        backoff_cap_secs: 2,
        receipt_query_attempts: 8,
        request_timeout_secs: Some(30),
        ttl_secs: None,
    };
    let anchor_result =
        write_live_anchor_config_from_verified_archive_with_memo_v1(&memo, &anchor_config)
            .expect("non-network anchor preparation must succeed");
    assert_eq!(anchor_result.accepted_ballot_count, 47);

    intake_us.sort_unstable();
    println!(
        "QUAL50_METRICS election_creation_us={election_creation_us} proof_generation_us={proof_generation_us} intake_min_us={} intake_median_us={} intake_p95_us={} intake_max_us={} cold_resume_us={cold_resume_us} warm_resume_us={warm_resume_us} warm_historical_triptych_verifies={} post_mutation_historical_triptych_verifies={} private_intake_us={private_intake_us} private_replay_us={private_replay_us} private_index_hits={} private_linear_scans={} close_us={close_us} tally_us={tally_us} finalize_us={finalize_us} archive_write_us={archive_write_us} archive_first_verify_us={first_archive_us} archive_memo_verify_us={memo_archive_us} archive_first_replay={} archive_first_triptych_verifies={} archive_memo_triptych_verifies={} workspace_bytes={workspace_bytes}",
        intake_us[0],
        percentile(&intake_us, 1, 2),
        percentile(&intake_us, 95, 100),
        intake_us[intake_us.len() - 1],
        warm_counters.triptych_adapter_verify_calls,
        post_mutation.triptych_adapter_verify_calls,
        indexed_counters.private_intake_digest_index_hits,
        indexed_counters.private_intake_linear_transcript_scans,
        first_archive_counters.archive_historical_replay_count,
        first_archive_counters.archive_historical_triptych_verifies,
        memo_archive_counters.archive_historical_triptych_verifies,
    );
}

/// Read-only diagnostic for a manually captured Release-GUI archive.
///
/// The paths deliberately come from explicit operator environment variables so
/// this test neither discovers nor changes a user's local election state. It
/// compares the replay-verified durable workspace with the newly written
/// archive and prints the verifier's structured transport-binding facts.
#[test]
#[ignore = "requires explicit preserved-archive and workspace environment variables"]
fn preserved_release_gui_archive_diagnostic() {
    let archive_dir = PathBuf::from(
        std::env::var("TARI_QUAL_ARCHIVE_DIR")
            .expect("TARI_QUAL_ARCHIVE_DIR must name the preserved archive"),
    );
    let workspaces_dir = PathBuf::from(
        std::env::var("TARI_QUAL_WORKSPACES_DIR")
            .expect("TARI_QUAL_WORKSPACES_DIR must name the durable workspace root"),
    );
    let workspace_id = std::env::var("TARI_QUAL_WORKSPACE_ID")
        .expect("TARI_QUAL_WORKSPACE_ID must name the selected workspace");

    let memo = ArchiveVerificationMemoV1::default();
    let archive = verify_archive_directory_with_memo_v1(&memo, &archive_dir)
        .expect("the preserved archive must be independently inspectable");
    println!(
        "QUAL50_EVIDENCE_ARCHIVE verified={} finalized={} failure_stage={:?} failure_code={:?} file_count={} packages={} accepted={} rejected={} transcript_complete={} archive_hash={:?} recomputed_hash={:?} hash_consistent={} manifest_hash={:?} transport_binding_present={} transport_binding_verified={} transport_accepted={:?} transport_reduced_anonymity={:?}",
        archive.verified,
        archive.finalized,
        archive.failure_stage,
        archive.failure_code,
        archive.file_count,
        archive.ballot_package_count,
        archive.accepted_count,
        archive.rejected_count,
        archive.transcript_complete,
        archive.archive_hash_hex,
        archive.recomputed_archive_hash_hex,
        archive.archive_hash_consistent,
        archive.election_manifest_hash_hex,
        archive.transport_binding_present,
        archive.transport_binding_verified,
        archive.transport_accepted_count,
        archive.transport_reduced_anonymity,
    );

    let cache = VerifiedElectionSessionCacheV1::default();
    let loaded = resume_election_workspace_with_verified_session_cache_v1(
        &workspaces_dir,
        &workspace_id,
        &cache,
    )
    .expect("the selected durable workspace must replay and resume");
    let LoadedElectionWorkspaceV1::Session { session, workspace } = loaded else {
        panic!("the selected workspace must contain an election session");
    };
    let summary = session.summary();
    let state_matches = session.lifecycle_state() == "FINALIZED" && archive.finalized;
    let packages_match = session.packages().len() == archive.ballot_package_count;
    let accepted_match = session.accepted_count() == archive.accepted_count;
    let manifest_matches =
        archive.election_manifest_hash_hex.as_deref() == Some(summary.manifest_hash_hex.as_str());
    println!(
        "QUAL50_EVIDENCE_WORKSPACE id={} revision={} lifecycle={} stored_packages={} replayed_packages={} replayed_accepted={} manifest_hash={} state_matches_archive={} packages_match_archive={} accepted_match_archive={} manifest_matches_archive={}",
        workspace.workspace_id,
        workspace.last_revision,
        session.lifecycle_state(),
        workspace.stored_ballot_count,
        session.packages().len(),
        session.accepted_count(),
        summary.manifest_hash_hex,
        state_matches,
        packages_match,
        accepted_match,
        manifest_matches,
    );

    assert!(
        archive.verified,
        "archive replay/hash verification must succeed"
    );
    assert!(archive.finalized, "archive must record FINALIZED lifecycle");
    assert!(
        archive.archive_hash_consistent,
        "archive hash must match catalog"
    );
    assert!(
        !archive.transport_binding_present && !archive.transport_binding_verified,
        "the preserved finding must isolate an absent transport binding"
    );
    assert!(state_matches && packages_match && accepted_match && manifest_matches);
}
