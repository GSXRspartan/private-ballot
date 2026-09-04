//! Generic Release scale qualification harness (TEST-ONLY).
//!
//! ONE parameterized integration target that exercises the full corrected
//! organizer workflow — election creation, registry construction, real Triptych
//! proof generation, direct + private-intake, durable writes, warm/cold resume,
//! private-intake indexing, tally, lifecycle, finalization, a transport-BOUND
//! finalized archive, independent archive verification, archive-verification
//! memoization, and non-network live-anchor preparation (NEVER a live publish) —
//! at an operator-selected registry size.
//!
//! It changes no production protocol, durable format, or crypto. It reuses the
//! SAME reviewed writer / verifier / anchor-config functions the Tauri
//! `write_finalized_archive` and `write_live_anchor_config_from_verified_archive`
//! commands call, so a green run is direct backend qualification evidence for
//! that build's archive/anchor path at the selected scale.
//!
//! # How to run
//!
//! Select the scale with `BALLOT_SCALE_REGISTRY` and run the ignored test:
//!
//! ```powershell
//! $env:BALLOT_SCALE_REGISTRY = '100'
//! cargo test -p tari-cc-private-ballot-gui-core --release --features test-support \
//!   --test release_scale_qualification release_scale_qualification -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Supported sizes: 50, 100, 500, 1000, 2048, 4096. Any other value — including
//! anything above the protocol maximum of 4096 — is rejected. Prefer the
//! `tools/load-test/RUN_SCALE_QUALIFICATION.ps1` wrapper, which sets the MSVC/vcpkg environment,
//! performs disk and runtime safety checks, and stores a timestamped CSV.
//!
//! Optional: set `BALLOT_SCALE_CSV` to a file path; the harness appends one CSV
//! row (writing the header if the file is new). It always prints one
//! `SCALE_QUAL_ROW` line and one `SCALE_QUAL_HEADER` line to stdout regardless.

#![allow(clippy::expect_used)]

use std::fs;
use std::io::Write as _;
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
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychPrototypeVerifierV1, TariTriptychSecretKeyV1,
    prove_tari_triptych_prototype_v1,
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
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1, ProofStatementV1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};

/// The protocol maximum registry size. No scale may exceed this.
const PROTOCOL_MAX_MEMBERS: usize = 4_096;
/// The exact scales this harness supports. 50 is retained for regression parity
/// with `release_qualification_50_voters`.
const SUPPORTED_SCALES: [usize; 6] = [50, 100, 500, 1000, 2048, 4096];

/// CSV column order. Single source of truth for the schema; the PowerShell
/// wrapper and `docs/development/load-testing/SCALE_QUALIFICATION_HARNESS.md`
/// document these exact names.
const CSV_HEADER: &str = "timestamp,registry_size,ballots_exercised,accepted,rejected,\
creation_ms,proof_generation_ms,intake_min_ms,intake_median_ms,intake_p95_ms,intake_max_ms,\
cold_resume_ms,warm_resume_ms,cold_historical_triptych_verifies,warm_historical_triptych_verifies,\
post_mutation_historical_triptych_verifies,private_intake_index_probes,private_intake_linear_scans,\
tally_ms,finalization_ms,archive_write_ms,archive_verify_ms,archive_memo_verify_ms,\
archive_memo_historical_triptych_verifies,anchor_prepare_ms,peak_ram_bytes,workspace_disk_bytes,\
logical_read_bytes,logical_write_bytes,result,notes";

struct ScaleFixture {
    artifacts: GuiElectionArtifactsV1,
    manifest: ElectionManifestV1,
    candidates: CandidateSet,
    registry: RegistrySnapshot,
    secret_keys: Vec<[u8; 32]>,
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "gui-core-scale-qualification-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scale directory must be creatable");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        // A successful run cleans its own scratch. On a FAILURE the drop happens
        // during panic unwind: preserve the scratch for forensic inspection and
        // print its path, never auto-deleting evidence after a failure.
        if std::thread::panicking() {
            eprintln!(
                "SCALE_QUAL_PRESERVED failed-run scratch retained: {}",
                self.path.display()
            );
            return;
        }
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

/// Reads and validates the operator-selected scale. Rejects unsupported values
/// and anything above the protocol maximum, fail-closed with a precise message.
fn read_scale() -> usize {
    let raw = std::env::var("BALLOT_SCALE_REGISTRY").unwrap_or_else(|_| {
        panic!(
            "BALLOT_SCALE_REGISTRY is required; supported sizes: {SUPPORTED_SCALES:?} (protocol max {PROTOCOL_MAX_MEMBERS})"
        )
    });
    let n: usize = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("BALLOT_SCALE_REGISTRY must be an integer; got {raw:?}"));
    assert!(
        n <= PROTOCOL_MAX_MEMBERS,
        "BALLOT_SCALE_REGISTRY {n} exceeds the protocol maximum of {PROTOCOL_MAX_MEMBERS}",
    );
    assert!(
        SUPPORTED_SCALES.contains(&n),
        "BALLOT_SCALE_REGISTRY {n} is not a supported scale {SUPPORTED_SCALES:?}",
    );
    n
}

fn build_fixture(member_count: usize) -> ScaleFixture {
    let provider = Blake3HashProviderV1;
    let mut public_keys = Vec::with_capacity(member_count);
    let mut secret_keys = Vec::with_capacity(member_count);
    // Distinct non-zero scalars, one per member. 101.. keeps them well clear of
    // the tiny-scalar edge and matches the 50-member fixture's base.
    for offset in 0..member_count {
        let scalar = Scalar::from(101_u64 + offset as u64);
        public_keys.push((RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes());
        secret_keys.push(scalar.to_bytes());
    }
    // The registry is canonical (sorted public keys). Secret keys are left in
    // generation order: a Triptych ring proof proves membership for SOME ring
    // member (hiding which), so any distinct secret whose public key is in the
    // registry yields a valid proof and a distinct nullifier — position need not
    // match. This mirrors the reviewed 50-member qualification fixture.
    public_keys.sort_unstable();

    let mut registry_writer = CanonicalCborWriter::new();
    registry_writer
        .write_array_len(public_keys.len())
        .expect("registry length must encode");
    for public_key in &public_keys {
        registry_writer
            .write_byte_string(public_key)
            .expect("registry key must encode");
    }
    let registry_bytes = registry_writer.into_bytes();
    let registry =
        RegistrySnapshot::from_canonical_cbor(&registry_bytes).expect("registry must decode");

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
        election_id: ElectionId::new(format!("release-scale-{member_count}").into_bytes())
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
        governance_source_revision: format!("release-scale-fixture-{member_count}"),
    })
    .expect("manifest must be valid");
    let manifest_bytes = manifest.to_canonical_cbor().expect("manifest must encode");
    let artifacts =
        GuiElectionArtifactsV1::from_bytes(&manifest_bytes, &registry_bytes, &candidates_bytes)
            .expect("validated artifacts must load");

    ScaleFixture {
        artifacts,
        manifest,
        candidates,
        registry,
        secret_keys,
    }
}

/// A reusable proving context so proof generation is O(N × proof-cost), not
/// O(N²): the registry verifier and the (three) per-selection statements are
/// built exactly once.
struct ProvingContext {
    verifier: TariTriptychPrototypeVerifierV1,
    payloads: Vec<ApprovalBallotPayload>,
    statements: Vec<ProofStatementV1>,
}

fn build_proving_context(fixture: &ScaleFixture) -> ProvingContext {
    let provider = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
        .expect("registry verifier must build once");
    let selections: [&[u8]; 3] = [b"candidate-avery", b"candidate-blair", b"candidate-casey"];
    let mut payloads = Vec::with_capacity(3);
    let mut statements = Vec::with_capacity(3);
    for selection in selections {
        let payload = ApprovalBallotPayload::new(
            vec![CandidateId::new(selection.to_vec()).expect("selection id must be valid")],
            &fixture.candidates,
            fixture.manifest.approval_limits(),
        )
        .expect("payload must be valid");
        let statement =
            reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider)
                .expect("proof statement must reconstruct");
        payloads.push(payload);
        statements.push(statement);
    }
    ProvingContext {
        verifier,
        payloads,
        statements,
    }
}

/// Generates one real, voter-bound ballot package using the shared proving
/// context (no per-call verifier rebuild).
fn real_package(fixture: &ScaleFixture, ctx: &ProvingContext, voter_index: usize) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let selection = voter_index % ctx.statements.len();
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(fixture.secret_keys[voter_index])
        .expect("fixture secret must be canonical");
    let proof =
        prove_tari_triptych_prototype_v1(&ctx.statements[selection], &ctx.verifier, &secret)
            .expect("real Triptych proof must construct");
    BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: fixture
            .manifest
            .canonical_hash(&provider)
            .expect("manifest hash must derive"),
        proof_suite_id: fixture.manifest.proof_suite_id().to_owned(),
        proof,
        payload: ctx.payloads[selection].clone(),
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
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("scale run requires a session workspace"),
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn millis_str(micros: u64) -> String {
    format!("{:.3}", micros as f64 / 1000.0)
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (sorted.len() * numerator).div_ceil(denominator);
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

fn directory_bytes(path: &Path) -> u64 {
    let mut total = 0_u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.is_dir() {
                total = total.saturating_add(directory_bytes(&entry.path()));
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// Returns `(historical_replay_count, historical_triptych_verifies)` for the
/// archive-verification counters between two snapshots.
fn archive_delta(
    before: ArchiveVerificationCountersSnapshotV1,
    after: ArchiveVerificationCountersSnapshotV1,
) -> (u64, u64) {
    (
        after
            .archive_historical_replay_count
            .saturating_sub(before.archive_historical_replay_count),
        after
            .archive_historical_triptych_verifies
            .saturating_sub(before.archive_historical_triptych_verifies),
    )
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn emit_csv_row(fields: &[String]) {
    let row = fields.join(",");
    println!("SCALE_QUAL_HEADER {CSV_HEADER}");
    println!("SCALE_QUAL_ROW {row}");
    if let Ok(path) = std::env::var("BALLOT_SCALE_CSV") {
        let path = PathBuf::from(path);
        let need_header =
            !path.exists() || fs::metadata(&path).map(|m| m.len() == 0).unwrap_or(true);
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            if need_header {
                let _ = writeln!(file, "{CSV_HEADER}");
            }
            let _ = writeln!(file, "{row}");
        }
    }
}

/// The one parameterized scale run. Ignored by default so a normal
/// `cargo test` never launches an expensive scale workload; the harness selects
/// the size from `BALLOT_SCALE_REGISTRY` and runs under `--ignored`.
#[test]
#[ignore = "scale harness; set BALLOT_SCALE_REGISTRY and run with --ignored"]
fn release_scale_qualification() {
    let n = read_scale();
    assert!(n >= 12, "scale harness requires at least 12 members");

    // ---- election creation + registry construction ----
    let creation_start = Instant::now();
    let fixture = build_fixture(n);
    assert_eq!(fixture.artifacts.registry().len(), n);
    let mut session =
        GuiElectionSessionV1::new(fixture.artifacts.clone()).expect("session must construct");
    session.open().expect("session must open");
    let creation_us = micros(creation_start.elapsed());

    let temp = TestDir::new(&format!("{n}"));
    let workspace_root = ensure_election_workspaces_directory_v1(&temp.join("workspaces"))
        .expect("workspace root must be created");
    let workspace_id = workspace_id_for_session_v1(&session);
    write_session_workspace_revision_v1(&workspace_root, &workspace_id, &session)
        .expect("initial workspace revision must write");

    let live_cache = VerifiedElectionSessionCacheV1::default();
    instrumentation::reset();
    let _initial = resume(&workspace_root, &workspace_id, &live_cache);
    assert_eq!(instrumentation::snapshot().historical_ballots_replayed, 0);

    // ---- real proof generation (O(N) proofs, one verifier build) ----
    // Voter layout (generalized from the 50-member fixture):
    //   0 .. direct_valid_count       -> direct valid intake
    //   private_index                 -> routed only via the private inbox
    //   after_index, final_index      -> later valid intake (post-rejection)
    //   voter 0 (reused)              -> duplicate rejection
    //   truncated later package       -> malformed rejection
    // accepted == direct_valid_count + 3 == n - 3 ; recorded packages == n - 1.
    let direct_valid_count = n - 6;
    let private_index = n - 6;
    let after_index = n - 5;
    let final_index = n - 4;

    let ctx = build_proving_context(&fixture);
    let proof_start = Instant::now();
    let mut direct_valid = Vec::with_capacity(direct_valid_count);
    for voter_index in 0..direct_valid_count {
        direct_valid.push(real_package(&fixture, &ctx, voter_index));
    }
    let private_package = real_package(&fixture, &ctx, private_index);
    let duplicate_package = real_package(&fixture, &ctx, 0);
    let valid_after_rejection = real_package(&fixture, &ctx, after_index);
    let final_valid = real_package(&fixture, &ctx, final_index);
    let proof_generation_us = micros(proof_start.elapsed());

    // ---- intake (direct) with a durable-commit + verified-cache advance ----
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
    let _post = resume(&workspace_root, &workspace_id, &live_cache);
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

    // ---- private intake (durable inbox reconciliation) ----
    let inbox = temp.join("private-inbox");
    assert!(
        append_accepted_ballot_package_to_inbox_v1(&inbox, &private_package)
            .expect("private-intake package must persist")
    );
    let private_first = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("private-intake reconciliation must succeed");
    assert_eq!(private_first.newly_accepted, 1);

    // ---- rejection scenarios (duplicate + malformed) ----
    let dup_start = Instant::now();
    let duplicate = session
        .intake_ballot(&duplicate_package)
        .expect("duplicate package is a recorded rejection");
    intake_us.push(micros(dup_start.elapsed()));
    assert!(!duplicate.accepted);
    assert_eq!(duplicate.code, "DUPLICATE_BALLOT");

    let mut malformed = valid_after_rejection.clone();
    malformed.pop();
    let mal_start = Instant::now();
    let malformed_result = session
        .intake_ballot(&malformed)
        .expect("malformed package is a recorded rejection");
    intake_us.push(micros(mal_start.elapsed()));
    assert!(!malformed_result.accepted);

    // reconciliation retry: already-decided private package changes nothing.
    let replay = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("already-decided private package must reconcile");
    assert_eq!(replay.newly_accepted, 0);

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
    let expected_accepted = n - 3;
    assert_eq!(session.accepted_count() as usize, expected_accepted);
    assert_eq!(session.packages().len(), n - 1);

    // ---- private-intake indexing over the full accepted set ----
    for package in
        direct_valid
            .iter()
            .chain([&private_package, &valid_after_rejection, &final_valid])
    {
        let _ = append_accepted_ballot_package_to_inbox_v1(&inbox, package)
            .expect("accepted package must be appendable to the inbox");
    }
    instrumentation::reset();
    let indexed = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session)
        .expect("indexed private reconciliation must succeed");
    let indexed_counters = instrumentation::snapshot();
    assert_eq!(indexed.newly_accepted, 0);
    assert_eq!(
        indexed_counters.private_intake_linear_transcript_scans, 0,
        "indexed reconciliation must never linear-scan the transcript",
    );

    // ---- durable persistence + cold / warm resume ----
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
    assert!(cold_counters.historical_ballots_replayed > 0);

    instrumentation::reset();
    let warm_start = Instant::now();
    let warm = resume(&workspace_root, &workspace_id, &cold_cache);
    let warm_resume_us = micros(warm_start.elapsed());
    let warm_counters = instrumentation::snapshot();
    assert_eq!(warm.accepted_count(), session.accepted_count());
    assert_eq!(warm_counters.historical_ballots_replayed, 0);
    assert_eq!(warm_counters.triptych_adapter_verify_calls, 0);

    // ---- tally + lifecycle + finalization ----
    session.close().expect("election must close");
    let tally_start = Instant::now();
    let tally = session.tally().expect("closed tally must compute");
    let tally_us = micros(tally_start.elapsed());
    assert_eq!(tally.accepted_ballots as usize, expected_accepted);
    assert_eq!(tally.counts.len(), 3);

    let finalize_start = Instant::now();
    session
        .mark_verified()
        .expect("closed election must verify");
    session.finalize().expect("verified election must finalize");
    let finalization_us = micros(finalize_start.elapsed());

    // ---- transport-BOUND finalized archive ----
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
        .expect("finalized bound archive must write");
    let archive_write_us = micros(archive_start.elapsed());

    // ---- independent archive verification + memoization ----
    let memo = ArchiveVerificationMemoV1::default();
    reset_archive_verification_counters();
    let verify_start = Instant::now();
    let first = verify_archive_directory_with_memo_v1(&memo, &archive)
        .expect("first archive verification must complete");
    let archive_verify_us = micros(verify_start.elapsed());
    let (first_replay_count, first_triptych_verifies) = archive_delta(
        ArchiveVerificationCountersSnapshotV1::default(),
        archive_verification_snapshot(),
    );
    assert!(first.verified);
    assert!(first.finalized);
    assert!(first.transport_binding_present);
    assert!(first.transport_binding_verified);

    let memo_before = archive_verification_snapshot();
    let memo_start = Instant::now();
    let second = verify_archive_directory_with_memo_v1(&memo, &archive)
        .expect("memoized archive verification must complete");
    let archive_memo_verify_us = micros(memo_start.elapsed());
    let (_memo_replay_count, memo_triptych_verifies) =
        archive_delta(memo_before, archive_verification_snapshot());
    assert_eq!(first, second);
    assert_eq!(memo_triptych_verifies, 0);

    // ---- non-network live-anchor preparation (NEVER a live publish) ----
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
        declared_seal_public_key: "release-scale-attested".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1_000,
        required_accepted_ballot_floor: expected_accepted as u64,
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
    let anchor_start = Instant::now();
    let anchor_result =
        write_live_anchor_config_from_verified_archive_with_memo_v1(&memo, &anchor_config)
            .expect("non-network anchor preparation must succeed");
    let anchor_prepare_us = micros(anchor_start.elapsed());
    assert_eq!(
        anchor_result.accepted_ballot_count as usize,
        expected_accepted
    );

    // ---- machine-readable result row ----
    intake_us.sort_unstable();
    let ballots_exercised = n - 1; // recorded packages (accepted + duplicate + malformed)
    let rejected = 2; // duplicate + malformed
    let fields = vec![
        unix_timestamp().to_string(),
        n.to_string(),
        ballots_exercised.to_string(),
        expected_accepted.to_string(),
        rejected.to_string(),
        millis_str(creation_us),
        millis_str(proof_generation_us),
        millis_str(intake_us[0]),
        millis_str(percentile(&intake_us, 1, 2)),
        millis_str(percentile(&intake_us, 95, 100)),
        millis_str(intake_us[intake_us.len() - 1]),
        millis_str(cold_resume_us),
        millis_str(warm_resume_us),
        cold_counters.triptych_adapter_verify_calls.to_string(),
        warm_counters.triptych_adapter_verify_calls.to_string(),
        post_mutation.triptych_adapter_verify_calls.to_string(),
        indexed_counters
            .private_intake_digest_index_hits
            .to_string(),
        indexed_counters
            .private_intake_linear_transcript_scans
            .to_string(),
        millis_str(tally_us),
        millis_str(finalization_us),
        millis_str(archive_write_us),
        millis_str(archive_verify_us),
        millis_str(archive_memo_verify_us),
        memo_triptych_verifies.to_string(),
        millis_str(anchor_prepare_us),
        "NA".to_owned(), // peak_ram_bytes — not sampled in-process
        workspace_bytes.to_string(),
        "NA".to_owned(), // logical_read_bytes — not instrumented
        "NA".to_owned(), // logical_write_bytes — not instrumented
        "PASS".to_owned(),
        format!(
            "archive_replay={first_replay_count} archive_triptych={first_triptych_verifies} cold_replayed={}",
            cold_counters.historical_ballots_replayed,
        ),
    ];
    emit_csv_row(&fields);
}
