#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tari_cc_private_ballot_gui_core::{
    DescriptorConsistencyStoreV1, ElectionLifecycleStateV1, GuiElectionArtifactsV1,
    GuiVoterCredentialOriginV1, GuiVoterEligibilityV1, GuiVoterSessionV1,
    TransportAuthorityRootSetV1, VoterCredentialContainerV1, VoterGovernanceCredentialV1,
    read_voter_credential_container_v1, write_voter_credential_container_v1,
};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
};
use tari_cc_private_ballot_transport_gateway::load_voter_public_bundle_v1;
use tari_cc_private_ballot_transport_network::{
    TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1,
};

pub mod managed_tor;

const DEFAULT_PASSPHRASE_ENV: &str = "TARI_BALLOT_LOAD_PASSPHRASE";
const ORGANIZER_REGISTRY_FILE: &str = "voter-registry.cbor";

/// Authoritative registry-member ceiling shared with the on-disk registry
/// canonicalization gate (`crates/protocol/src/limits.rs`). Kept re-exported at
/// this stable name so operator tools (the standalone Load Tester GUI, the
/// distributed CLI) can display the exact same maximum the crypto layer
/// enforces, instead of inventing a UI-only constant that could drift.
pub use tari_cc_private_ballot_protocol::MAX_REGISTRY_MEMBERS as DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS;

/// UI threshold above which operator tools should warn that a run performs
/// real Triptych proof generation for every simulated voter. Not a protocol
/// value — purely presentation guidance so a 100-voter smoke run never
/// silently turns into an all-day proof-heavy job.
pub const DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD: usize = 100;

pub fn run_cli(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut args: Vec<String> = args.into_iter().collect();
    let prog = args
        .first()
        .cloned()
        .unwrap_or_else(|| "tari-cc-private-ballot-cli".to_owned());
    if args.len() <= 1 {
        print_usage(&prog);
        return ExitCode::SUCCESS;
    }
    args.remove(0);
    let command = args.remove(0);
    let result = match command.as_str() {
        "--help" | "-h" | "help" => {
            print_usage(&prog);
            Ok(())
        }
        "distributed-cohort" => run_distributed_cohort(args),
        "distributed-partition" => run_distributed_partition(args),
        "distributed-submit" => run_distributed_submit(args),
        _ => Err(format!("unknown command: {command}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("Private Ballot protocol workspace");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  {prog} distributed-cohort --count <N> --out <dir> [--passphrase-env <ENV>]");
    eprintln!(
        "  {prog} distributed-partition --credentials <dir> --out <dir> --start-index <N> --count <N>"
    );
    eprintln!(
        "  {prog} distributed-submit --manifest <path> --registry <path> --candidates <path> --voter-public-bundle <path> --credentials <dir> --tor-exe <absolute-tor-path>|--tor-socks <ip:port> --results <path> [--choice round-robin|all:<candidate-id-hex>] [--count <N>] [--start-index <N>] [--concurrency 1] [--passphrase-env <ENV>] [--state-dir <dir>] [--run-id <id>]"
    );
    eprintln!();
    eprintln!(
        "distributed-submit accepts exactly one Tor mode: --tor-exe (the tool validates, starts, waits for SOCKS readiness, and stops an ISOLATED Tor process it owns) or the legacy --tor-socks (an already-running local SOCKS listener you manage). Supplying both is rejected."
    );
    eprintln!("No command starts walletd, indexer, GUI, or Ootle services.");
}

fn run_distributed_cohort(args: Vec<String>) -> Result<(), String> {
    let parsed = ParsedArgs::new(args)?;
    let count = parsed.required_usize("--count")?;
    let out = parsed.required_path("--out")?;
    let passphrase_env = parsed
        .optional_value("--passphrase-env")?
        .unwrap_or_else(|| DEFAULT_PASSPHRASE_ENV.to_owned());
    parsed.finish()?;
    let passphrase = env::var(&passphrase_env)
        .map_err(|_| format!("set {passphrase_env} to the test credential passphrase"))?;
    let summary = generate_distributed_cohort(count, &out, &passphrase)?;
    println!("Distributed cohort generated");
    println!("Credentials:      {}", summary.credentials_written);
    println!("Registry voters:  {}", summary.registry_members);
    println!("Organizer file:   {}", summary.organizer_registry.display());
    println!("Voter directory:  {}", summary.voters_dir.display());
    Ok(())
}

fn run_distributed_partition(args: Vec<String>) -> Result<(), String> {
    let parsed = ParsedArgs::new(args)?;
    let credentials = parsed.required_path("--credentials")?;
    let out = parsed.required_path("--out")?;
    let start_index = parsed.required_usize("--start-index")?;
    let count = parsed.required_usize("--count")?;
    parsed.finish()?;
    let copied = partition_credentials(&credentials, &out, start_index, count)?;
    println!("Credential partition written");
    println!("Credentials copied: {copied}");
    println!("Output directory:   {}", out.display());
    Ok(())
}

fn run_distributed_submit(args: Vec<String>) -> Result<(), String> {
    let parsed = ParsedArgs::new(args)?;
    // Exactly one Tor mode, resolved fail-closed BEFORE anything else runs.
    // Ambiguity (--tor-exe AND --tor-socks) and under-specification (neither)
    // are both rejected; there is no silent guess and no clearnet fallback.
    let tor_mode = managed_tor::resolve_tor_endpoint_mode_v1(
        parsed.optional_path("--tor-exe")?.as_deref(),
        parsed.optional_socket("--tor-socks")?,
    )?;
    let mut config = LoadDriverConfig {
        manifest_path: parsed.required_path("--manifest")?,
        registry_path: parsed.required_path("--registry")?,
        candidate_path: parsed.required_path("--candidates")?,
        voter_public_bundle_path: parsed.required_path("--voter-public-bundle")?,
        credentials_dir: parsed.required_path("--credentials")?,
        tor_socks: match &tor_mode {
            managed_tor::TorEndpointModeV1::ExistingSocks { socks_addr } => *socks_addr,
            // Managed mode replaces this placeholder with the freshly
            // reserved loopback endpoint AFTER Tor is actually ready.
            managed_tor::TorEndpointModeV1::Managed { .. } => SocketAddr::from(([127, 0, 0, 1], 0)),
        },
        results_path: parsed.required_path("--results")?,
        state_dir: parsed.optional_path("--state-dir")?,
        count: parsed.optional_usize("--count")?,
        start_index: parsed.optional_usize("--start-index")?.unwrap_or(1),
        concurrency: parsed.optional_usize("--concurrency")?.unwrap_or(1),
        choice: ChoiceDistribution::parse(
            parsed
                .optional_value("--choice")?
                .as_deref()
                .unwrap_or("round-robin"),
        )?,
        passphrase_env: parsed
            .optional_value("--passphrase-env")?
            .unwrap_or_else(|| DEFAULT_PASSPHRASE_ENV.to_owned()),
        host_run_id: parsed
            .optional_value("--run-id")?
            .unwrap_or_else(default_run_id),
    };
    parsed.finish()?;
    let passphrase = env::var(&config.passphrase_env).map_err(|_| {
        format!(
            "set {} to the test credential passphrase",
            config.passphrase_env
        )
    })?;
    validate_load_driver_config(&config)?;
    match tor_mode {
        managed_tor::TorEndpointModeV1::ExistingSocks { socks_addr } => {
            // MODE B — existing SOCKS: the exact workflow of the prior physical
            // 500-voter run. The operator manages the Tor process entirely.
            config.tor_socks = socks_addr;
            let started = SystemTime::now();
            let report = run_load_driver(&config, &passphrase)?;
            write_json_report(&config.results_path, &report)?;
            write_managed_tor_run_metadata(
                &config,
                "existing-socks",
                started,
                &report,
                socks_addr,
                None,
                None,
                None,
                None,
            )?;
            print_report_summary(&report);
        }
        managed_tor::TorEndpointModeV1::Managed { tor_exe } => {
            run_distributed_submit_managed(config, tor_exe, &passphrase)?;
        }
    }
    Ok(())
}

/// MODE A — managed Tor. Validates the operator-supplied executable, starts an
/// ISOLATED Tor process owned by this run, waits for REAL SOCKS readiness,
/// submits the cohort through that Tor instance, and always stops/reaps ONLY
/// the child it launched. On success the disposable runtime is removed; on
/// failure it is preserved (bounded stderr log) as evidence. There is no
/// clearnet fallback: a Tor failure fails the whole run before any ballot
/// bytes exist.
fn run_distributed_submit_managed(
    mut config: LoadDriverConfig,
    tor_exe: PathBuf,
    passphrase: &str,
) -> Result<DistributedLoadReportV1, String> {
    let started = SystemTime::now();
    let start_instant = Instant::now();
    let runtime_base = managed_tor::managed_runtime_base_for_results(&config.results_path);
    let startup =
        managed_tor::ManagedTorStartupConfigV1::new(tor_exe.clone(), runtime_base.clone());
    let mut session = managed_tor::start_managed_tor_session(&startup)?;
    config.tor_socks = session.socks_addr();
    // Optional bounded `tor --version` evidence from the validated executable.
    let tor_version = managed_tor::capture_tor_version_v1(&tor_exe);
    let outcome = run_load_driver(&config, passphrase)
        .and_then(|report| write_json_report(&config.results_path, &report).map(|()| report));
    let finished = SystemTime::now();
    let onion_hostname = load_voter_public_bundle_v1(&config.voter_public_bundle_path)
        .ok()
        .and_then(|bundle| bundle.descriptor.onion_endpoints().first().cloned());
    let tor_executable_basename = tor_exe
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let tor_run_directory_name = session
        .run_dir()
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let socks_endpoint = session.socks_addr().to_string();
    let run_dir = session.run_dir().to_path_buf();
    let elapsed_ms = start_instant.elapsed().as_millis();
    // Stop and reap ONLY the child this session launched, on every exit path.
    session.shutdown();
    let report = match outcome {
        Ok(report) => report,
        Err(error) => {
            return Err(format!(
                "{error}; managed Tor stopped and reaped; isolated Tor run evidence preserved: {}",
                run_dir.display()
            ));
        }
    };
    let metadata = managed_tor::ManagedTorRunMetadataV1 {
        metadata_type: managed_tor::MANAGED_TOR_RUN_METADATA_TYPE_V1,
        tor_mode: "managed-tor",
        started_utc: managed_tor::format_utc_timestamp(started),
        finished_utc: managed_tor::format_utc_timestamp(finished),
        socks_endpoint: socks_endpoint.clone(),
        onion_hostname,
        tor_executable_basename,
        tor_version,
        tor_run_directory_name,
        tor_process_stopped_by_runner: Some(true),
        elapsed_ms,
    };
    write_managed_tor_metadata_file(&config.results_path, &metadata)?;
    // Success: remove the disposable runtime state. This directory is derived
    // solely from this run's results path and holds only this run's fresh
    // `run-*` child directory — never production Tor state.
    let _ = fs::remove_dir_all(&runtime_base);
    println!("Managed Tor ready endpoint: {socks_endpoint}");
    println!(
        "Tor executable: {}",
        metadata
            .tor_executable_basename
            .as_deref()
            .unwrap_or("unknown")
    );
    print_report_summary(&report);
    Ok(report)
}

fn write_managed_tor_metadata_file(
    results_path: &Path,
    metadata: &managed_tor::ManagedTorRunMetadataV1,
) -> Result<(), String> {
    let path = managed_tor::managed_tor_metadata_path(results_path);
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|_| "could not encode managed-Tor run metadata".to_owned())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "could not create managed-Tor metadata directory".to_owned())?;
    }
    fs::write(&path, &bytes).map_err(|_| "could not write managed-Tor metadata".to_owned())
}

#[allow(clippy::too_many_arguments)]
fn write_managed_tor_run_metadata(
    config: &LoadDriverConfig,
    tor_mode: &'static str,
    started: SystemTime,
    report: &DistributedLoadReportV1,
    socks_addr: SocketAddr,
    tor_executable_basename: Option<String>,
    tor_version: Option<String>,
    tor_run_directory_name: Option<String>,
    tor_process_stopped_by_runner: Option<bool>,
) -> Result<(), String> {
    let onion_hostname = load_voter_public_bundle_v1(&config.voter_public_bundle_path)
        .ok()
        .and_then(|bundle| bundle.descriptor.onion_endpoints().first().cloned());
    let metadata = managed_tor::ManagedTorRunMetadataV1 {
        metadata_type: managed_tor::MANAGED_TOR_RUN_METADATA_TYPE_V1,
        tor_mode,
        started_utc: managed_tor::format_utc_timestamp(started),
        finished_utc: managed_tor::format_utc_timestamp(SystemTime::now()),
        socks_endpoint: socks_addr.to_string(),
        onion_hostname,
        tor_executable_basename,
        tor_version,
        tor_run_directory_name,
        tor_process_stopped_by_runner,
        elapsed_ms: report.elapsed_ms,
    };
    write_managed_tor_metadata_file(&config.results_path, &metadata)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceDistribution {
    RoundRobin,
    All { candidate_id_hex: String },
}

impl ChoiceDistribution {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input == "round-robin" {
            return Ok(Self::RoundRobin);
        }
        if let Some(candidate_id_hex) = input.strip_prefix("all:") {
            if candidate_id_hex.is_empty() {
                return Err("all:<candidate-id-hex> requires a candidate id".to_owned());
            }
            return Ok(Self::All {
                candidate_id_hex: candidate_id_hex.to_owned(),
            });
        }
        Err("choice must be round-robin or all:<candidate-id-hex>".to_owned())
    }

    pub fn choose(
        &self,
        candidate_ids_hex: &[String],
        voter_offset: usize,
    ) -> Result<String, String> {
        match self {
            Self::RoundRobin => {
                if candidate_ids_hex.is_empty() {
                    return Err("candidate set is empty".to_owned());
                }
                Ok(candidate_ids_hex[voter_offset % candidate_ids_hex.len()].clone())
            }
            Self::All { candidate_id_hex } => {
                if !candidate_ids_hex.iter().any(|id| id == candidate_id_hex) {
                    return Err("configured candidate id is not in the candidate set".to_owned());
                }
                Ok(candidate_id_hex.clone())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadDriverConfig {
    pub manifest_path: PathBuf,
    pub registry_path: PathBuf,
    pub candidate_path: PathBuf,
    pub voter_public_bundle_path: PathBuf,
    pub credentials_dir: PathBuf,
    pub tor_socks: SocketAddr,
    pub results_path: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub count: Option<usize>,
    pub start_index: usize,
    pub concurrency: usize,
    pub choice: ChoiceDistribution,
    pub passphrase_env: String,
    pub host_run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CohortSummary {
    pub organizer_registry: PathBuf,
    pub voters_dir: PathBuf,
    pub credentials_written: usize,
    pub registry_members: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DistributedLoadReportV1 {
    pub report_type: &'static str,
    pub host_run_id: String,
    pub requested_voter_count: usize,
    pub credentials_loaded: usize,
    pub duplicate_credentials_detected: usize,
    pub proofs_successfully_generated: usize,
    pub proof_generation_failures: usize,
    pub submission_attempts: usize,
    pub successful_submissions: usize,
    pub failed_submissions: usize,
    pub receipts_received: usize,
    pub receipts_successfully_verified: usize,
    pub receipt_verification_failures: usize,
    pub elapsed_ms: u128,
    pub average_proof_preparation_ms: u128,
    pub average_submission_ms: u128,
    pub expected_submission_counts: Vec<CandidateCountV1>,
    pub observed_successful_submission_counts: Vec<CandidateCountV1>,
    pub failures: Vec<LoadDriverFailureV1>,
    /// How many of the requested voters actually completed a submission attempt
    /// (successful + failed). This is `<= requested_voter_count`; when the run
    /// terminates via COMPLETE it equals `requested_voter_count`, and when it
    /// terminates via STOPPED / FAILED it may be lower.
    pub completed_voters: usize,
    /// How many of the requested voters were never reached because the run
    /// stopped (cooperative Stop After Current Voter) or failed early.
    pub remaining_voters: usize,
    /// Which state produced this report. `RUNNING` = the run is still active
    /// (mid-run incremental snapshot); `COMPLETE` = every requested voter
    /// reached a submission attempt boundary; `STOPPED` = the operator asked
    /// the run to stop after the currently-active voter finished; `FAILED` =
    /// the driver could not proceed (setup, transport, persistence, or a fatal
    /// error before/after some voters).
    pub terminal_state: LoadDriverTerminalStateV1,
}

/// Run state of a load-driver report. Serialized as a plain uppercase
/// string so the report JSON stays operator-readable and matches the labels
/// the GUI already renders. Mid-run incremental snapshots are always `RUNNING`
/// — a partial snapshot must never be mistakable for a finished run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoadDriverTerminalStateV1 {
    Running,
    Complete,
    Stopped,
    Failed,
}

/// Progress event emitted after each voter completes its submission boundary.
/// Values are secret-free — no credential material, no decrypted keys, no
/// passphrase; the only per-voter identifier is the credential file's
/// operating-system path, which is what the operator selected on disk.
#[derive(Debug, Clone, Serialize)]
pub struct LoadDriverProgressV1 {
    pub total_voters: usize,
    pub completed_voters: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub failed: usize,
    pub remaining: usize,
    pub current_credential_file: Option<String>,
    pub elapsed_ms: u128,
    pub average_ms_per_completed_voter: u128,
    pub estimated_remaining_ms: Option<u128>,
    pub terminal_state: Option<LoadDriverTerminalStateV1>,
}

/// Static input validation summary — the read-only result of
/// [`validate_load_driver_inputs`]. Confirms that every artifact exists, that
/// the voter public bundle binds to the manifest/registry the operator
/// selected, and that the credentials directory holds the expected count.
/// Emits no network activity and never spawns Tor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadDriverValidationSummary {
    pub credential_count: usize,
    pub requested_voter_count: usize,
    /// How many credential files the driver would actually select with the
    /// requested start index/count. Validation fails closed unless this
    /// equals `requested_voter_count`.
    pub selected_voter_count: usize,
    pub start_index: usize,
    pub tor_socks: String,
    pub choice: String,
}

/// Cooperative run controls threaded through
/// [`run_load_driver_with_control`]. Every field is optional and defaults to
/// `None` / `false`, so callers that only need the terminal report can supply
/// [`LoadDriverRunControl::default`].
#[derive(Default)]
pub struct LoadDriverRunControl<'a> {
    /// Optional progress callback fired after every voter reaches a submission
    /// boundary and once more with the terminal state.
    pub progress: Option<&'a mut dyn FnMut(LoadDriverProgressV1)>,
    /// Optional cancel probe consulted BEFORE each new voter. Returning `true`
    /// stops the loop after the currently-active voter safely finishes.
    pub cancel: Option<&'a dyn Fn() -> bool>,
    /// When set, the driver writes the report to `config.results_path` after
    /// every voter using an atomic replace, so a crash preserves the last
    /// known state on disk.
    pub persist_incremental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateCountV1 {
    pub candidate_id_hex: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadDriverFailureV1 {
    pub credential_file: String,
    pub stage: &'static str,
    pub code: String,
}

pub fn generate_distributed_cohort(
    count: usize,
    out: &Path,
    passphrase: &str,
) -> Result<CohortSummary, String> {
    if count == 0 {
        return Err("count must be greater than zero".to_owned());
    }
    prepare_fresh_directory(out)?;
    let organizer_dir = out.join("organizer");
    let voters_dir = out.join("voters");
    fs::create_dir_all(&organizer_dir).map_err(|_| "could not create organizer dir".to_owned())?;
    fs::create_dir_all(&voters_dir).map_err(|_| "could not create voters dir".to_owned())?;

    let mut entries = Vec::with_capacity(count);
    let mut public_keys = HashSet::with_capacity(count);
    for index in 1..=count {
        let credential = VoterGovernanceCredentialV1::generate()
            .map_err(|error| format!("credential generation failed: {}", error.code()))?;
        let public_key = credential
            .public_key_bytes()
            .map_err(|error| format!("public key derivation failed: {}", error.code()))?;
        if !public_keys.insert(public_key) {
            return Err("generated duplicate public governance key".to_owned());
        }
        let container = VoterCredentialContainerV1::encrypt(&credential, passphrase)
            .map_err(|error| format!("credential encryption failed: {}", error.code()))?;
        let filename = format!("voter-{index:04}.tcbcred");
        write_voter_credential_container_v1(&voters_dir.join(filename), &container)
            .map_err(|error| format!("credential write failed: {}", error.code()))?;
        let key = GovernancePublicKey::new(public_key.to_vec())
            .map_err(|error| format!("registry key failed: {}", error.code().as_str()))?;
        let registration =
            VoterGovernanceKeyRegistrationV1::new(key, VoterKeyProvisioningV1::GeneratedByVoter);
        entries.push(RegistryEntry::from_voter_registration(registration));
    }

    let registry = RegistrySnapshot::new(entries)
        .map_err(|error| format!("registry build failed: {}", error.code().as_str()))?;
    let registry_bytes = registry
        .to_canonical_cbor()
        .map_err(|error| format!("registry encode failed: {}", error.code().as_str()))?;
    let organizer_registry = organizer_dir.join(ORGANIZER_REGISTRY_FILE);
    write_new_file(&organizer_registry, &registry_bytes)?;

    Ok(CohortSummary {
        organizer_registry,
        voters_dir,
        credentials_written: count,
        registry_members: registry.len(),
    })
}

/// Summary returned by [`partition_credentials_with_summary`] — same copy
/// semantics as [`partition_credentials`], but returns the destination path
/// and the inclusive first/last voter numbers so the GUI can present the
/// operator with the same confirmation without re-deriving the arithmetic in
/// the frontend.
#[derive(Debug, Clone)]
pub struct PartitionSummary {
    pub credentials_detected: usize,
    pub credentials_copied: usize,
    pub first_voter_index: usize,
    pub last_voter_index: usize,
    pub destination: PathBuf,
}

/// Counts `.tcbcred` files directly under `credentials_dir` (no recursion,
/// same filter used by [`select_credential_paths`]). Used by the GUI to
/// display "N test voter credentials detected" without decrypting them.
pub fn credential_count(credentials_dir: &Path) -> Result<usize, String> {
    let mut count = 0;
    let entries =
        fs::read_dir(credentials_dir).map_err(|_| "could not read credentials dir".to_owned())?;
    for entry in entries {
        let entry = entry.map_err(|_| "could not read credentials dir entry".to_owned())?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("tcbcred") {
            count += 1;
        }
    }
    Ok(count)
}

/// Like [`partition_credentials`], but returns a rich [`PartitionSummary`] so
/// the GUI can render "voters 1 through 250" without recomputing the range.
pub fn partition_credentials_with_summary(
    credentials_dir: &Path,
    out: &Path,
    start_index: usize,
    count: usize,
) -> Result<PartitionSummary, String> {
    let detected = credential_count(credentials_dir)?;
    let copied = partition_credentials(credentials_dir, out, start_index, count)?;
    Ok(PartitionSummary {
        credentials_detected: detected,
        credentials_copied: copied,
        first_voter_index: start_index,
        last_voter_index: start_index + count - 1,
        destination: out.to_path_buf(),
    })
}

pub fn partition_credentials(
    credentials_dir: &Path,
    out: &Path,
    start_index: usize,
    count: usize,
) -> Result<usize, String> {
    if start_index == 0 {
        return Err("start-index is one-based and must be greater than zero".to_owned());
    }
    if count == 0 {
        return Err("count must be greater than zero".to_owned());
    }
    prepare_fresh_directory(out)?;
    let selected = select_credential_paths(credentials_dir, start_index, Some(count))?;
    if selected.len() != count {
        return Err(format!(
            "requested {count} credentials but only {} were available",
            selected.len()
        ));
    }
    for path in &selected {
        let Some(name) = path.file_name() else {
            return Err("credential path has no file name".to_owned());
        };
        fs::copy(path, out.join(name)).map_err(|_| "credential copy failed".to_owned())?;
    }
    Ok(selected.len())
}

/// Read-only static validation: static config checks + artifact binding
/// (manifest/registry/candidates decode, voter public bundle binds to that
/// election) + credentials directory scan. Emits no network activity, spawns
/// no processes, and never touches Tor.
///
/// The returned [`LoadDriverValidationSummary`] is what the GUI's
/// `validate_load_test` command surfaces so the operator can see the numbers
/// they are about to run against before Run Test is enabled.
pub fn validate_load_driver_inputs(
    config: &LoadDriverConfig,
) -> Result<LoadDriverValidationSummary, String> {
    validate_load_driver_config(config)?;
    let artifacts = GuiElectionArtifactsV1::from_paths(
        &config.manifest_path,
        &config.registry_path,
        &config.candidate_path,
    )
    .map_err(|error| format!("election artifacts failed: {}", error.code()))?;
    // Loading the voter public bundle triggers the shared binding check (the
    // bundle's root must be the same authority the manifest/registry the
    // organizer published); a wrong-election bundle fails closed here without
    // any network activity.
    let bundle = load_voter_public_bundle_v1(&config.voter_public_bundle_path)
        .map_err(|error| format!("voter public bundle failed: {error}"))?;
    let _ = &artifacts;
    let _ = &bundle;
    let credential_count = credential_count(&config.credentials_dir)?;
    let choice = match &config.choice {
        ChoiceDistribution::RoundRobin => "round-robin".to_owned(),
        ChoiceDistribution::All { candidate_id_hex } => format!("all:{candidate_id_hex}"),
    };
    validate_results_output_path(&config.results_path)?;
    let selected = ensure_exact_selection(config)?;
    let requested = config.count.unwrap_or(selected.len());
    Ok(LoadDriverValidationSummary {
        credential_count,
        requested_voter_count: requested,
        selected_voter_count: selected.len(),
        start_index: config.start_index,
        tor_socks: config.tor_socks.to_string(),
        choice,
    })
}

/// Validates the results output destination WITHOUT writing the report file:
/// the path must be non-empty, must not be an existing directory, and its
/// parent directory must be creatable/existing so the atomic replace can
/// commit there. Used by offline validation and by the driver's pre-run gate.
pub fn validate_results_output_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("results output path is required".to_owned());
    }
    if path.is_dir() {
        return Err("results output path must be a file, not a directory".to_owned());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|_| {
                "results output folder could not be created; choose a writable location".to_owned()
            })?;
            if !parent.is_dir() {
                return Err("results output folder is not a usable directory".to_owned());
            }
        }
    }
    Ok(())
}

/// The driver's exact-selection invariant: IF a requested voter count N is
/// given, THEN exactly N credential files must be selected before the first
/// voter runs. A copied partition directory is indexed LOCALLY by the files it
/// contains (a partition holding global voters 251–500 runs with local start
/// index 1), so a selection that skips past the local files is an operator
/// input error and must fail closed — never a partial run that still reports
/// COMPLETE.
fn ensure_exact_selection(config: &LoadDriverConfig) -> Result<Vec<PathBuf>, String> {
    let selected =
        select_credential_paths(&config.credentials_dir, config.start_index, config.count)?;
    if let Some(requested) = config.count {
        if selected.len() != requested {
            return Err(format!(
                "requested {requested} voters but only {} credentials are available from this directory at local start index {}; a copied partition directory is indexed locally, so start at 1",
                selected.len(),
                config.start_index
            ));
        }
    }
    if selected.is_empty() {
        return Err(format!(
            "no test voter credentials were selected from the credentials directory (local start index {}); a copied partition directory is indexed locally, so start at 1",
            config.start_index
        ));
    }
    Ok(selected)
}

pub fn validate_load_driver_config(config: &LoadDriverConfig) -> Result<(), String> {
    if config.start_index == 0 {
        return Err("start-index is one-based and must be greater than zero".to_owned());
    }
    if matches!(config.count, Some(0)) {
        return Err("count must be greater than zero".to_owned());
    }
    if config.concurrency == 0 {
        return Err("concurrency must be greater than zero".to_owned());
    }
    if config.concurrency != 1 {
        return Err(
            "this first load-driver slice supports sequential submission only; use --concurrency 1"
                .to_owned(),
        );
    }
    for (label, path) in [
        ("manifest", &config.manifest_path),
        ("registry", &config.registry_path),
        ("candidates", &config.candidate_path),
        ("voter-public-bundle", &config.voter_public_bundle_path),
        ("credentials", &config.credentials_dir),
    ] {
        if !path.exists() {
            return Err(format!("{label} path does not exist: {}", path.display()));
        }
    }
    if !config.credentials_dir.is_dir() {
        return Err("credentials path must be a directory".to_owned());
    }
    Ok(())
}

pub fn run_load_driver(
    config: &LoadDriverConfig,
    passphrase: &str,
) -> Result<DistributedLoadReportV1, String> {
    run_load_driver_with_control(config, passphrase, &mut LoadDriverRunControl::default())
}

/// Full driver run with cooperative controls. Callers get:
///   * a `progress` callback fired after every voter completes its submission
///     boundary (and once more with the terminal state);
///   * an optional `cancel` probe consulted BEFORE each new voter is started —
///     the currently-active voter is NEVER torn down mid-proof or mid-submit,
///     so a Stop request reaches STOPPED only after that voter finishes;
///   * optional incremental persistence of the running report to
///     `config.results_path` so a crash or hard-kill preserves the last state.
///
/// This is the seam the standalone Load Tester GUI uses. Adding controls here
/// keeps a single shared load-driver implementation (there is no second
/// engine in the GUI).
pub fn run_load_driver_with_control(
    config: &LoadDriverConfig,
    passphrase: &str,
    control: &mut LoadDriverRunControl<'_>,
) -> Result<DistributedLoadReportV1, String> {
    validate_load_driver_config(config)?;
    // Exact-selection invariant FIRST: if the requested count cannot be
    // satisfied exactly from the credentials directory, fail closed before any
    // election artifact is loaded, before Tor starts, and before any voter is
    // touched. A copied partition directory is indexed locally, so a global
    // start index that skips past the local files is rejected here.
    let selected_paths = ensure_exact_selection(config)?;
    // Persisting the authoritative per-host results is part of the run
    // contract: fail closed BEFORE the first voter when incremental
    // persistence was requested but the results destination is unusable.
    if control.persist_incremental {
        validate_results_output_path(&config.results_path)?;
    }
    let started = Instant::now();
    let artifacts = GuiElectionArtifactsV1::from_paths(
        &config.manifest_path,
        &config.registry_path,
        &config.candidate_path,
    )
    .map_err(|error| format!("election artifacts failed: {}", error.code()))?;
    let candidate_ids_hex: Vec<String> = artifacts
        .summary()
        .candidates
        .iter()
        .map(|candidate| candidate.machine_id_hex.clone())
        .collect();
    let bundle = load_voter_public_bundle_v1(&config.voter_public_bundle_path)
        .map_err(|error| format!("voter public bundle failed: {error}"))?;
    let roots = TransportAuthorityRootSetV1::new(bundle.root);
    let mut consistency = DescriptorConsistencyStoreV1::default();
    let mut carrier =
        TorSocksPrivateReleaseCarrierV1::new(config.tor_socks, TorCarrierTimeoutsV1::default())
            .map_err(|error| format!("tor carrier config failed: {error}"))?;
    let state_dir = config
        .state_dir
        .clone()
        .unwrap_or_else(|| default_state_dir_for_results(&config.results_path));
    let cast_locks_dir = state_dir.join("cast-locks");
    let staging_dir = state_dir.join("release-staging");
    fs::create_dir_all(&cast_locks_dir).map_err(|_| "could not create cast-lock dir".to_owned())?;
    fs::create_dir_all(&staging_dir).map_err(|_| "could not create staging dir".to_owned())?;

    let mut loaded_public_keys = HashSet::new();
    let mut duplicate_credentials_detected = 0;
    let mut credentials_loaded = 0;
    let mut proofs_successfully_generated = 0;
    let mut proof_generation_failures = 0;
    let mut submission_attempts = 0;
    let mut successful_submissions = 0;
    let mut failed_submissions = 0;
    let mut receipts_received = 0;
    let mut receipts_successfully_verified = 0;
    let mut receipt_verification_failures = 0;
    let mut proof_total = Duration::ZERO;
    let mut submission_total = Duration::ZERO;
    let mut expected = CountAccumulator::default();
    let mut observed = CountAccumulator::default();
    let mut failures = Vec::new();

    let total_voters = selected_paths.len();
    // The run is RUNNING until the loop exhausts every selected voter (→
    // COMPLETE) or a break path downgrades the state (STOPPED / FAILED). This
    // makes a final COMPLETE structurally impossible unless every requested
    // voter reached its completion boundary.
    let mut terminal_state = LoadDriverTerminalStateV1::Running;
    let mut completed_voters: usize = 0;

    for (offset, path) in selected_paths.iter().enumerate() {
        // Cooperative Stop-After-Current-Voter: the check runs BEFORE the next
        // voter starts, so an operator-triggered stop never tears down a proof
        // or a submission mid-flight. The currently-active voter always
        // completes safely before the driver stops.
        if control
            .cancel
            .as_ref()
            .map(|probe| probe())
            .unwrap_or(false)
        {
            terminal_state = LoadDriverTerminalStateV1::Stopped;
            break;
        }
        let display_path = path.to_string_lossy().into_owned();
        let selected_candidate = config.choice.choose(&candidate_ids_hex, offset)?;
        expected.add(selected_candidate.clone());

        let container = match read_voter_credential_container_v1(path) {
            Ok(container) => container,
            Err(error) => {
                failures.push(failure(
                    display_path.clone(),
                    "credential-read",
                    error.code(),
                ));
                completed_voters += 1;
                if !record_voter_boundary(
                    control,
                    config,
                    total_voters,
                    completed_voters,
                    successful_submissions,
                    receipt_verification_failures,
                    failed_submissions,
                    &display_path,
                    started,
                    &make_running_report(
                        config,
                        total_voters,
                        credentials_loaded,
                        duplicate_credentials_detected,
                        proofs_successfully_generated,
                        proof_generation_failures,
                        submission_attempts,
                        successful_submissions,
                        failed_submissions,
                        receipts_received,
                        receipts_successfully_verified,
                        receipt_verification_failures,
                        started,
                        proof_total,
                        submission_total,
                        &expected,
                        &observed,
                        &failures,
                        completed_voters,
                    ),
                    &mut failures,
                ) {
                    terminal_state = LoadDriverTerminalStateV1::Failed;
                    break;
                }
                continue;
            }
        };
        let public_key = container.public_key_bytes();
        if !loaded_public_keys.insert(public_key) {
            duplicate_credentials_detected += 1;
            failures.push(LoadDriverFailureV1 {
                credential_file: display_path.clone(),
                stage: "credential-duplicate",
                code: "DUPLICATE_CREDENTIAL".to_owned(),
            });
            completed_voters += 1;
            if !record_voter_boundary(
                control,
                config,
                total_voters,
                completed_voters,
                successful_submissions,
                receipt_verification_failures,
                failed_submissions,
                &display_path,
                started,
                &make_running_report(
                    config,
                    total_voters,
                    credentials_loaded,
                    duplicate_credentials_detected,
                    proofs_successfully_generated,
                    proof_generation_failures,
                    submission_attempts,
                    successful_submissions,
                    failed_submissions,
                    receipts_received,
                    receipts_successfully_verified,
                    receipt_verification_failures,
                    started,
                    proof_total,
                    submission_total,
                    &expected,
                    &observed,
                    &failures,
                    completed_voters,
                ),
                &mut failures,
            ) {
                terminal_state = LoadDriverTerminalStateV1::Failed;
                break;
            }
            continue;
        }
        let credential = match container.decrypt(passphrase) {
            Ok(credential) => credential,
            Err(error) => {
                failures.push(failure(
                    display_path.clone(),
                    "credential-decrypt",
                    error.code(),
                ));
                completed_voters += 1;
                if !record_voter_boundary(
                    control,
                    config,
                    total_voters,
                    completed_voters,
                    successful_submissions,
                    receipt_verification_failures,
                    failed_submissions,
                    &display_path,
                    started,
                    &make_running_report(
                        config,
                        total_voters,
                        credentials_loaded,
                        duplicate_credentials_detected,
                        proofs_successfully_generated,
                        proof_generation_failures,
                        submission_attempts,
                        successful_submissions,
                        failed_submissions,
                        receipts_received,
                        receipts_successfully_verified,
                        receipt_verification_failures,
                        started,
                        proof_total,
                        submission_total,
                        &expected,
                        &observed,
                        &failures,
                        completed_voters,
                    ),
                    &mut failures,
                ) {
                    terminal_state = LoadDriverTerminalStateV1::Failed;
                    break;
                }
                continue;
            }
        };
        credentials_loaded += 1;

        let mut voter = GuiVoterSessionV1::new(&artifacts);
        let status = match voter.install_credential_with_origin(
            credential,
            GuiVoterCredentialOriginV1::ImportedSession,
            &artifacts,
        ) {
            Ok(status) => status,
            Err(error) => {
                failures.push(failure(
                    display_path.clone(),
                    "credential-install",
                    error.code(),
                ));
                completed_voters += 1;
                if !record_voter_boundary(
                    control,
                    config,
                    total_voters,
                    completed_voters,
                    successful_submissions,
                    receipt_verification_failures,
                    failed_submissions,
                    &display_path,
                    started,
                    &make_running_report(
                        config,
                        total_voters,
                        credentials_loaded,
                        duplicate_credentials_detected,
                        proofs_successfully_generated,
                        proof_generation_failures,
                        submission_attempts,
                        successful_submissions,
                        failed_submissions,
                        receipts_received,
                        receipts_successfully_verified,
                        receipt_verification_failures,
                        started,
                        proof_total,
                        submission_total,
                        &expected,
                        &observed,
                        &failures,
                        completed_voters,
                    ),
                    &mut failures,
                ) {
                    terminal_state = LoadDriverTerminalStateV1::Failed;
                    break;
                }
                continue;
            }
        };
        if status.eligibility != GuiVoterEligibilityV1::Eligible {
            failures.push(LoadDriverFailureV1 {
                credential_file: display_path.clone(),
                stage: "eligibility",
                code: "CREDENTIAL_NOT_ELIGIBLE".to_owned(),
            });
            completed_voters += 1;
            if !record_voter_boundary(
                control,
                config,
                total_voters,
                completed_voters,
                successful_submissions,
                receipt_verification_failures,
                failed_submissions,
                &display_path,
                started,
                &make_running_report(
                    config,
                    total_voters,
                    credentials_loaded,
                    duplicate_credentials_detected,
                    proofs_successfully_generated,
                    proof_generation_failures,
                    submission_attempts,
                    successful_submissions,
                    failed_submissions,
                    receipts_received,
                    receipts_successfully_verified,
                    receipt_verification_failures,
                    started,
                    proof_total,
                    submission_total,
                    &expected,
                    &observed,
                    &failures,
                    completed_voters,
                ),
                &mut failures,
            ) {
                terminal_state = LoadDriverTerminalStateV1::Failed;
                break;
            }
            continue;
        }
        if let Err(error) = voter.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![selected_candidate.clone()],
            false,
        ) {
            failures.push(failure(display_path.clone(), "selection", error.code()));
            completed_voters += 1;
            if !record_voter_boundary(
                control,
                config,
                total_voters,
                completed_voters,
                successful_submissions,
                receipt_verification_failures,
                failed_submissions,
                &display_path,
                started,
                &make_running_report(
                    config,
                    total_voters,
                    credentials_loaded,
                    duplicate_credentials_detected,
                    proofs_successfully_generated,
                    proof_generation_failures,
                    submission_attempts,
                    successful_submissions,
                    failed_submissions,
                    receipts_received,
                    receipts_successfully_verified,
                    receipt_verification_failures,
                    started,
                    proof_total,
                    submission_total,
                    &expected,
                    &observed,
                    &failures,
                    completed_voters,
                ),
                &mut failures,
            ) {
                terminal_state = LoadDriverTerminalStateV1::Failed;
                break;
            }
            continue;
        }

        let proof_started = Instant::now();
        if let Err(error) = voter.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open) {
            proof_total += proof_started.elapsed();
            proof_generation_failures += 1;
            failures.push(failure(display_path.clone(), "proof", error.code()));
            completed_voters += 1;
            if !record_voter_boundary(
                control,
                config,
                total_voters,
                completed_voters,
                successful_submissions,
                receipt_verification_failures,
                failed_submissions,
                &display_path,
                started,
                &make_running_report(
                    config,
                    total_voters,
                    credentials_loaded,
                    duplicate_credentials_detected,
                    proofs_successfully_generated,
                    proof_generation_failures,
                    submission_attempts,
                    successful_submissions,
                    failed_submissions,
                    receipts_received,
                    receipts_successfully_verified,
                    receipt_verification_failures,
                    started,
                    proof_total,
                    submission_total,
                    &expected,
                    &observed,
                    &failures,
                    completed_voters,
                ),
                &mut failures,
            ) {
                terminal_state = LoadDriverTerminalStateV1::Failed;
                break;
            }
            continue;
        }
        proof_total += proof_started.elapsed();
        proofs_successfully_generated += 1;

        let submission_started = Instant::now();
        submission_attempts += 1;
        match voter.release_prepared_ballot_via_private_transport(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &bundle.descriptor,
            &roots,
            &mut consistency,
            &cast_locks_dir,
            &staging_dir,
            &mut carrier,
        ) {
            Ok(result) if result.released => {
                submission_total += submission_started.elapsed();
                successful_submissions += 1;
                receipts_received += 1;
                receipts_successfully_verified += 1;
                observed.add(selected_candidate);
            }
            Ok(result) => {
                submission_total += submission_started.elapsed();
                failed_submissions += 1;
                if result.receipt_state != "PENDING" {
                    receipts_received += 1;
                    receipt_verification_failures += 1;
                }
                failures.push(LoadDriverFailureV1 {
                    credential_file: display_path.clone(),
                    stage: result.diagnostic_stage.unwrap_or("submission"),
                    code: result.receipt_state.to_owned(),
                });
            }
            Err(error) => {
                submission_total += submission_started.elapsed();
                failed_submissions += 1;
                failures.push(failure(display_path.clone(), "submission", error.code()));
            }
        }
        completed_voters += 1;
        if !record_voter_boundary(
            control,
            config,
            total_voters,
            completed_voters,
            successful_submissions,
            receipt_verification_failures,
            failed_submissions,
            &display_path,
            started,
            &make_running_report(
                config,
                total_voters,
                credentials_loaded,
                duplicate_credentials_detected,
                proofs_successfully_generated,
                proof_generation_failures,
                submission_attempts,
                successful_submissions,
                failed_submissions,
                receipts_received,
                receipts_successfully_verified,
                receipt_verification_failures,
                started,
                proof_total,
                submission_total,
                &expected,
                &observed,
                &failures,
                completed_voters,
            ),
            &mut failures,
        ) {
            terminal_state = LoadDriverTerminalStateV1::Failed;
            break;
        }
    }

    let remaining_voters = total_voters.saturating_sub(completed_voters);
    let mut report = DistributedLoadReportV1 {
        report_type: "TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1",
        host_run_id: config.host_run_id.clone(),
        requested_voter_count: total_voters,
        credentials_loaded,
        duplicate_credentials_detected,
        proofs_successfully_generated,
        proof_generation_failures,
        submission_attempts,
        successful_submissions,
        failed_submissions,
        receipts_received,
        receipts_successfully_verified,
        receipt_verification_failures,
        elapsed_ms: started.elapsed().as_millis(),
        average_proof_preparation_ms: average_ms(
            proof_total,
            proofs_successfully_generated + proof_generation_failures,
        ),
        average_submission_ms: average_ms(submission_total, submission_attempts),
        expected_submission_counts: expected.into_counts(),
        observed_successful_submission_counts: observed.into_counts(),
        failures,
        completed_voters,
        remaining_voters,
        terminal_state,
    };
    // Downgrade RUNNING → COMPLETE only when the loop exhausted every selected
    // voter. Break paths (cooperative stop, persistence failure) already set
    // their own state, so COMPLETE here proves completed_voters == requested.
    if report.terminal_state == LoadDriverTerminalStateV1::Running
        && report.completed_voters == report.requested_voter_count
    {
        report.terminal_state = LoadDriverTerminalStateV1::Complete;
    } else if report.terminal_state == LoadDriverTerminalStateV1::Running {
        report.terminal_state = LoadDriverTerminalStateV1::Failed;
        report.failures.push(results_persist_failure());
    }
    // Persist the terminal report (atomic replace) if the caller asked for
    // incremental persistence — mid-run writes went to the results path, and
    // the last write is the authoritative terminal one. A terminal persistence
    // failure is NEVER silently swallowed: it downgrades the reported state to
    // FAILED so a missing local evidence file can never masquerade as a
    // successful COMPLETE, without touching already-submitted voter truth.
    if control.persist_incremental && atomic_replace_json(&config.results_path, &report).is_err() {
        if report.terminal_state != LoadDriverTerminalStateV1::Failed {
            report.terminal_state = LoadDriverTerminalStateV1::Failed;
            report.failures.push(results_persist_failure());
        }
        // One best-effort corrected write so the on-disk snapshot matches the
        // returned FAILED report if the failure was transient. No submission
        // is retried and no new voter is started by this write.
        let _ = atomic_replace_json(&config.results_path, &report);
    }
    // Fire the final progress event with the terminal state so subscribers
    // (the GUI) observe a well-defined end even without polling the return
    // value.
    emit_progress_final(
        control,
        total_voters,
        completed_voters,
        successful_submissions,
        receipt_verification_failures,
        failed_submissions,
        started,
        report.terminal_state,
    );
    Ok(report)
}

/// Helper: build a full report snapshot mid-run for progress persistence.
/// Same fields as the final report; terminal_state is always `RUNNING` so a
/// partial snapshot can never be mistaken for a finished run. The final
/// terminal report is built separately with COMPLETE / STOPPED / FAILED.
#[allow(clippy::too_many_arguments)]
fn make_running_report(
    config: &LoadDriverConfig,
    total_voters: usize,
    credentials_loaded: usize,
    duplicate_credentials_detected: usize,
    proofs_successfully_generated: usize,
    proof_generation_failures: usize,
    submission_attempts: usize,
    successful_submissions: usize,
    failed_submissions: usize,
    receipts_received: usize,
    receipts_successfully_verified: usize,
    receipt_verification_failures: usize,
    started: Instant,
    proof_total: Duration,
    submission_total: Duration,
    expected: &CountAccumulator,
    observed: &CountAccumulator,
    failures: &[LoadDriverFailureV1],
    completed_voters: usize,
) -> DistributedLoadReportV1 {
    DistributedLoadReportV1 {
        report_type: "TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1",
        host_run_id: config.host_run_id.clone(),
        requested_voter_count: total_voters,
        credentials_loaded,
        duplicate_credentials_detected,
        proofs_successfully_generated,
        proof_generation_failures,
        submission_attempts,
        successful_submissions,
        failed_submissions,
        receipts_received,
        receipts_successfully_verified,
        receipt_verification_failures,
        elapsed_ms: started.elapsed().as_millis(),
        average_proof_preparation_ms: average_ms(
            proof_total,
            proofs_successfully_generated + proof_generation_failures,
        ),
        average_submission_ms: average_ms(submission_total, submission_attempts),
        expected_submission_counts: expected.clone().into_counts(),
        observed_successful_submission_counts: observed.clone().into_counts(),
        failures: failures.to_vec(),
        completed_voters,
        remaining_voters: total_voters.saturating_sub(completed_voters),
        terminal_state: LoadDriverTerminalStateV1::Running,
    }
}

/// The failure record used when the authoritative per-host results JSON cannot
/// be persisted. The message and code are fixed constants: they never embed
/// filesystem paths, passphrases, credentials, or any other secret material.
fn results_persist_failure() -> LoadDriverFailureV1 {
    LoadDriverFailureV1 {
        credential_file: String::new(),
        stage: "results-persist",
        code: "RESULTS_PERSIST_FAILED".to_owned(),
    }
}

/// Records one voter's completion boundary: persists the RUNNING snapshot and
/// emits progress. Returns false when the authoritative results persistence
/// FAILED — the caller must stop before beginning another voter so local
/// evidence can never silently diverge from organizer truth. The voter that
/// just finished is already counted (its submission outcome is preserved); a
/// persistence failure never "un-submits" it and never triggers a retry that
/// could double-submit.
#[allow(clippy::too_many_arguments)]
fn record_voter_boundary(
    control: &mut LoadDriverRunControl<'_>,
    config: &LoadDriverConfig,
    total_voters: usize,
    completed_voters: usize,
    accepted: usize,
    rejected: usize,
    failed: usize,
    current_credential_file: &str,
    started: Instant,
    running_report: &DistributedLoadReportV1,
    failures: &mut Vec<LoadDriverFailureV1>,
) -> bool {
    if control.persist_incremental
        && atomic_replace_json(&config.results_path, running_report).is_err()
    {
        failures.push(results_persist_failure());
        return false;
    }
    if let Some(progress) = control.progress.as_deref_mut() {
        let elapsed_ms = started.elapsed().as_millis();
        let average = if completed_voters > 0 {
            elapsed_ms / completed_voters as u128
        } else {
            0
        };
        let remaining = total_voters.saturating_sub(completed_voters);
        let estimated_remaining_ms = if completed_voters > 0 {
            Some(average * remaining as u128)
        } else {
            None
        };
        progress(LoadDriverProgressV1 {
            total_voters,
            completed_voters,
            accepted,
            rejected,
            failed,
            remaining,
            current_credential_file: Some(current_credential_file.to_owned()),
            elapsed_ms,
            average_ms_per_completed_voter: average,
            estimated_remaining_ms,
            terminal_state: None,
        });
    }
    true
}

fn emit_progress_final(
    control: &mut LoadDriverRunControl<'_>,
    total_voters: usize,
    completed_voters: usize,
    accepted: usize,
    rejected: usize,
    failed: usize,
    started: Instant,
    terminal: LoadDriverTerminalStateV1,
) {
    if let Some(progress) = control.progress.as_deref_mut() {
        let elapsed_ms = started.elapsed().as_millis();
        let average = if completed_voters > 0 {
            elapsed_ms / completed_voters as u128
        } else {
            0
        };
        let remaining = total_voters.saturating_sub(completed_voters);
        progress(LoadDriverProgressV1 {
            total_voters,
            completed_voters,
            accepted,
            rejected,
            failed,
            remaining,
            current_credential_file: None,
            elapsed_ms,
            average_ms_per_completed_voter: average,
            estimated_remaining_ms: Some(0),
            terminal_state: Some(terminal),
        });
    }
}

/// Atomic replace of a JSON report file: write to a sibling `.tmp` file then
/// rename over the destination. On Windows the rename is atomic on the same
/// volume; on Unix `rename(2)` is atomic. Callers ignore errors — this is a
/// best-effort incremental persistence path, not the authoritative return
/// value.
fn atomic_replace_json(path: &Path, report: &DistributedLoadReportV1) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(report).map_err(|_| "could not encode report".to_owned())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "could not create parent directory".to_owned())?;
    }
    let mut tmp = path.to_path_buf();
    let tmp_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.tmp"))
        .unwrap_or_else(|| "distributed-load-results.json.tmp".to_owned());
    tmp.set_file_name(tmp_name);
    fs::write(&tmp, &bytes).map_err(|_| "could not write partial report".to_owned())?;
    fs::rename(&tmp, path).map_err(|_| "could not commit partial report".to_owned())?;
    Ok(())
}

pub fn select_credential_paths(
    credentials_dir: &Path,
    start_index: usize,
    count: Option<usize>,
) -> Result<Vec<PathBuf>, String> {
    if start_index == 0 {
        return Err("start-index is one-based and must be greater than zero".to_owned());
    }
    let mut paths = Vec::new();
    let entries =
        fs::read_dir(credentials_dir).map_err(|_| "could not read credentials dir".to_owned())?;
    for entry in entries {
        let entry = entry.map_err(|_| "could not read credentials dir entry".to_owned())?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("tcbcred") {
            paths.push(path);
        }
    }
    paths.sort();
    let skipped = start_index - 1;
    let iter = paths.into_iter().skip(skipped);
    Ok(match count {
        Some(count) => iter.take(count).collect(),
        None => iter.collect(),
    })
}

pub fn detect_duplicate_container_headers(paths: &[PathBuf]) -> Result<usize, String> {
    let mut seen = HashSet::new();
    let mut duplicates = 0;
    for path in paths {
        let container = read_voter_credential_container_v1(path)
            .map_err(|error| format!("credential parse failed: {}", error.code()))?;
        if !seen.insert(container.public_key_bytes()) {
            duplicates += 1;
        }
    }
    Ok(duplicates)
}

fn failure(path: String, stage: &'static str, code: &str) -> LoadDriverFailureV1 {
    LoadDriverFailureV1 {
        credential_file: path,
        stage,
        code: code.to_owned(),
    }
}

fn write_json_report(path: &Path, report: &DistributedLoadReportV1) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(report).map_err(|_| "could not encode report".to_owned())?;
    write_new_file(path, &bytes)
}

fn print_report_summary(report: &DistributedLoadReportV1) {
    println!("Distributed voter run complete");
    println!("Credentials loaded:       {}", report.credentials_loaded);
    println!(
        "Proofs generated:         {}",
        report.proofs_successfully_generated
    );
    println!("Submissions attempted:    {}", report.submission_attempts);
    println!(
        "Receipts verified:        {}",
        report.receipts_successfully_verified
    );
    println!("Failures:                 {}", report.failures.len());
    println!("Elapsed ms:               {}", report.elapsed_ms);
    println!(
        "Average proof ms:         {}",
        report.average_proof_preparation_ms
    );
    println!("Average submission ms:    {}", report.average_submission_ms);
}

fn average_ms(total: Duration, count: usize) -> u128 {
    if count == 0 {
        0
    } else {
        total.as_millis() / count as u128
    }
}

#[derive(Default, Clone)]
struct CountAccumulator {
    keys: BTreeSet<String>,
    counts: std::collections::BTreeMap<String, usize>,
}

impl CountAccumulator {
    fn add(&mut self, candidate_id_hex: String) {
        self.keys.insert(candidate_id_hex.clone());
        let count = self.counts.entry(candidate_id_hex).or_insert(0);
        *count += 1;
    }

    fn into_counts(self) -> Vec<CandidateCountV1> {
        self.keys
            .into_iter()
            .map(|candidate_id_hex| CandidateCountV1 {
                count: self.counts.get(&candidate_id_hex).copied().unwrap_or(0),
                candidate_id_hex,
            })
            .collect()
    }
}

fn default_run_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("run-{now}")
}

fn default_state_dir_for_results(results_path: &Path) -> PathBuf {
    let mut base = results_path.to_path_buf();
    let state_name = results_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.state"))
        .unwrap_or_else(|| "distributed-load-results.state".to_owned());
    base.set_file_name(state_name);
    base
}

fn prepare_fresh_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "target exists and is not a directory: {}",
                path.display()
            ));
        }
        let mut entries =
            fs::read_dir(path).map_err(|_| "could not inspect target directory".to_owned())?;
        if entries.next().is_some() {
            return Err(format!(
                "target directory must be empty: {}",
                path.display()
            ));
        }
    } else {
        fs::create_dir_all(path).map_err(|_| format!("could not create {}", path.display()))?;
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "could not create parent directory".to_owned())?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .map_err(|_| format!("could not create new file: {}", path.display()))?;
    use std::io::Write;
    file.write_all(bytes)
        .map_err(|_| format!("could not write file: {}", path.display()))?;
    file.sync_all()
        .map_err(|_| format!("could not sync file: {}", path.display()))?;
    Ok(())
}

struct ParsedArgs {
    args: Vec<String>,
}

impl ParsedArgs {
    fn new(args: Vec<String>) -> Result<Self, String> {
        Ok(Self { args })
    }

    fn required_value(&self, name: &str) -> Result<String, String> {
        self.optional_value(name)?
            .ok_or_else(|| format!("missing required argument {name}"))
    }

    fn optional_value(&self, name: &str) -> Result<Option<String>, String> {
        let mut found = None;
        let mut index = 0;
        while index < self.args.len() {
            if self.args[index] == name {
                if found.is_some() {
                    return Err(format!("argument supplied more than once: {name}"));
                }
                let Some(value) = self.args.get(index + 1) else {
                    return Err(format!("missing value for {name}"));
                };
                found = Some(value.clone());
                index += 2;
            } else {
                index += 1;
            }
        }
        Ok(found)
    }

    fn required_path(&self, name: &str) -> Result<PathBuf, String> {
        Ok(PathBuf::from(self.required_value(name)?))
    }

    fn optional_path(&self, name: &str) -> Result<Option<PathBuf>, String> {
        Ok(self.optional_value(name)?.map(PathBuf::from))
    }

    fn required_usize(&self, name: &str) -> Result<usize, String> {
        parse_usize(name, &self.required_value(name)?)
    }

    fn optional_usize(&self, name: &str) -> Result<Option<usize>, String> {
        self.optional_value(name)?
            .map(|value| parse_usize(name, &value))
            .transpose()
    }

    fn optional_socket(&self, name: &str) -> Result<Option<SocketAddr>, String> {
        self.optional_value(name)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("{name} must be an ip:port socket address"))
            })
            .transpose()
    }

    fn finish(&self) -> Result<(), String> {
        let known = [
            "--count",
            "--out",
            "--passphrase-env",
            "--credentials",
            "--start-index",
            "--manifest",
            "--registry",
            "--candidates",
            "--voter-public-bundle",
            "--tor-socks",
            "--tor-exe",
            "--results",
            "--state-dir",
            "--concurrency",
            "--choice",
            "--run-id",
        ];
        let mut index = 0;
        while index < self.args.len() {
            let arg = &self.args[index];
            if !known.contains(&arg.as_str()) {
                return Err(format!("unknown argument: {arg}"));
            }
            if self.args.get(index + 1).is_none() {
                return Err(format!("missing value for {arg}"));
            }
            index += 2;
        }
        Ok(())
    }
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_choice_distribution_is_deterministic() {
        let distribution = ChoiceDistribution::RoundRobin;
        let candidates = vec!["aa".to_owned(), "bb".to_owned(), "cc".to_owned()];
        let mut selected = Vec::new();
        for index in 0..7 {
            match distribution.choose(&candidates, index) {
                Ok(value) => selected.push(value),
                Err(error) => panic!("{error}"),
            }
        }

        assert_eq!(
            selected,
            vec![
                "aa".to_owned(),
                "bb".to_owned(),
                "cc".to_owned(),
                "aa".to_owned(),
                "bb".to_owned(),
                "cc".to_owned(),
                "aa".to_owned(),
            ]
        );
    }

    #[test]
    fn all_choice_requires_existing_candidate() {
        let distribution = match ChoiceDistribution::parse("all:bb") {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        };
        let candidates = vec!["aa".to_owned(), "bb".to_owned()];

        assert_eq!(distribution.choose(&candidates, 9), Ok("bb".to_owned()));
        assert!(ChoiceDistribution::parse("all:").is_err());
        assert!(
            (ChoiceDistribution::All {
                candidate_id_hex: "cc".to_owned()
            })
            .choose(&candidates, 0)
            .is_err()
        );
    }

    #[test]
    fn load_driver_config_rejects_zero_and_parallel_concurrency() {
        let base = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path: PathBuf::from("results.json"),
            state_dir: None,
            count: Some(1),
            start_index: 1,
            concurrency: 0,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "test".to_owned(),
        };

        assert!(validate_load_driver_config(&base).is_err());
        let mut parallel = base.clone();
        parallel.concurrency = 2;
        assert!(validate_load_driver_config(&parallel).is_err());
    }

    #[test]
    fn report_serialization_omits_secret_markers() {
        let report = DistributedLoadReportV1 {
            report_type: "TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1",
            host_run_id: "host-a".to_owned(),
            requested_voter_count: 2,
            credentials_loaded: 2,
            duplicate_credentials_detected: 0,
            proofs_successfully_generated: 2,
            proof_generation_failures: 0,
            submission_attempts: 2,
            successful_submissions: 2,
            failed_submissions: 0,
            receipts_received: 2,
            receipts_successfully_verified: 2,
            receipt_verification_failures: 0,
            elapsed_ms: 10,
            average_proof_preparation_ms: 4,
            average_submission_ms: 1,
            expected_submission_counts: vec![CandidateCountV1 {
                candidate_id_hex: "aa".to_owned(),
                count: 2,
            }],
            observed_successful_submission_counts: vec![CandidateCountV1 {
                candidate_id_hex: "aa".to_owned(),
                count: 2,
            }],
            failures: Vec::new(),
            completed_voters: 2,
            remaining_voters: 0,
            terminal_state: LoadDriverTerminalStateV1::Complete,
        };
        let json = match serde_json::to_string(&report) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        };
        let lower = json.to_lowercase();
        for marker in [
            "secret",
            "scalar",
            "passphrase",
            "raw credential",
            "credential_bytes",
            "mnemonic",
        ] {
            assert!(!lower.contains(marker), "report leaked marker {marker}");
        }
    }

    /// F3 — every state serializes as the operator-readable uppercase label,
    /// including the new RUNNING snapshot state.
    #[test]
    fn terminal_state_serialization_covers_running_snapshot_state() {
        assert_eq!(
            serde_json::to_string(&LoadDriverTerminalStateV1::Running).unwrap(),
            "\"RUNNING\""
        );
        assert_eq!(
            serde_json::to_string(&LoadDriverTerminalStateV1::Complete).unwrap(),
            "\"COMPLETE\""
        );
        assert_eq!(
            serde_json::to_string(&LoadDriverTerminalStateV1::Stopped).unwrap(),
            "\"STOPPED\""
        );
        assert_eq!(
            serde_json::to_string(&LoadDriverTerminalStateV1::Failed).unwrap(),
            "\"FAILED\""
        );
    }

    /// F3 — a mid-run snapshot is always RUNNING, never a false COMPLETE, and
    /// its counts stay mutually consistent (87 of 250 → remaining 163).
    #[test]
    fn running_snapshot_state_is_running_with_consistent_counts() {
        let config = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path: PathBuf::from("results.json"),
            state_dir: None,
            count: Some(250),
            start_index: 1,
            concurrency: 1,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "host-a".to_owned(),
        };
        let snapshot = make_running_report(
            &config,
            250,
            87,
            0,
            80,
            7,
            87,
            80,
            7,
            80,
            80,
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::ZERO,
            &CountAccumulator::default(),
            &CountAccumulator::default(),
            &[],
            87,
        );
        assert_eq!(snapshot.terminal_state, LoadDriverTerminalStateV1::Running);
        assert_eq!(snapshot.completed_voters, 87);
        assert_eq!(snapshot.remaining_voters, 163);
        assert_eq!(snapshot.requested_voter_count, 250);
        // No underflow: saturating subtraction keeps the invariant.
        let over = make_running_report(
            &config,
            250,
            251,
            0,
            251,
            0,
            251,
            251,
            0,
            251,
            251,
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::ZERO,
            &CountAccumulator::default(),
            &CountAccumulator::default(),
            &[],
            251,
        );
        assert_eq!(over.remaining_voters, 0);
        // The serialized snapshot must carry the RUNNING label.
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(
            json.contains("\"RUNNING\""),
            "snapshot must serialize RUNNING"
        );
        assert!(
            !json.contains("\"COMPLETE\""),
            "snapshot must not claim COMPLETE"
        );
    }

    /// F1 — atomic persistence succeeds on a usable destination and round-trips.
    #[test]
    fn atomic_replace_json_round_trips_on_usable_destination() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("nested").join("results.json");
        let config = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path: path.clone(),
            state_dir: None,
            count: Some(1),
            start_index: 1,
            concurrency: 1,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "host-a".to_owned(),
        };
        let snapshot = make_running_report(
            &config,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::ZERO,
            &CountAccumulator::default(),
            &CountAccumulator::default(),
            &[],
            0,
        );
        atomic_replace_json(&path, &snapshot).expect("persistence succeeds");
        let bytes = fs::read(&path).expect("report exists on disk");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("\"RUNNING\""));
        // No sibling temp file is left behind by a successful replace.
        let tmp = scratch.path().join("nested").join("results.json.tmp");
        assert!(!tmp.exists(), "atomic replace must not leak its .tmp file");
    }

    /// F1 — persistence failure modes are deterministic and fail closed: a
    /// parent that is a regular file, and a destination that is a directory.
    #[test]
    fn atomic_replace_json_fails_closed_on_unusable_destinations() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let parent_file = scratch.path().join("not-a-dir");
        fs::write(&parent_file, b"regular file").expect("write parent file");
        let config = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path: PathBuf::new(),
            state_dir: None,
            count: Some(1),
            start_index: 1,
            concurrency: 1,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "host-a".to_owned(),
        };
        let snapshot = make_running_report(
            &config,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::ZERO,
            &CountAccumulator::default(),
            &CountAccumulator::default(),
            &[],
            0,
        );
        let mut config = config;
        config.results_path = parent_file.join("results.json");
        assert!(
            atomic_replace_json(&config.results_path, &snapshot).is_err(),
            "parent-is-a-file must fail"
        );
        let destination_dir = scratch.path().join("results-dir");
        fs::create_dir_all(&destination_dir).expect("create dir");
        assert!(
            atomic_replace_json(&destination_dir, &snapshot).is_err(),
            "destination-is-a-directory must fail"
        );
    }

    /// F1 — a persistence failure at the voter boundary is surfaced, never
    /// silently ignored, and never leaks the results path or any secret.
    #[test]
    fn record_voter_boundary_surfaces_persistence_failure_without_leaking() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let parent_file = scratch.path().join("not-a-dir");
        fs::write(&parent_file, b"regular file").expect("write parent file");
        let results_path = parent_file.join("results.json");
        let config = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path,
            state_dir: None,
            count: Some(2),
            start_index: 1,
            concurrency: 1,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "host-a".to_owned(),
        };
        let mut progress_events: Vec<LoadDriverProgressV1> = Vec::new();
        let mut progress = |event: LoadDriverProgressV1| progress_events.push(event);
        let mut control = LoadDriverRunControl {
            progress: Some(&mut progress),
            cancel: None,
            persist_incremental: true,
        };
        let snapshot = make_running_report(
            &config,
            2,
            1,
            0,
            1,
            0,
            1,
            1,
            0,
            1,
            1,
            0,
            Instant::now(),
            Duration::ZERO,
            Duration::ZERO,
            &CountAccumulator::default(),
            &CountAccumulator::default(),
            &[],
            1,
        );
        let mut failures = Vec::new();
        let continued = record_voter_boundary(
            &mut control,
            &config,
            2,
            1,
            1,
            0,
            0,
            "voter-0001.tcbcred",
            Instant::now(),
            &snapshot,
            &mut failures,
        );
        // The boundary reports failure so the driver stops before the next voter.
        assert!(!continued, "persistence failure must stop the run");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].stage, "results-persist");
        assert_eq!(failures[0].code, "RESULTS_PERSIST_FAILED");
        // The voter that completed is still truthfully counted.
        assert_eq!(snapshot.completed_voters, 1);
        // No secret or operator path may appear in the failure record.
        let rendered = format!("{} {}", failures[0].stage, failures[0].code);
        let lower = rendered.to_lowercase();
        for marker in [
            "passphrase",
            "secret",
            "scalar",
            "not-a-dir",
            "results.json",
        ] {
            assert!(
                !lower.contains(marker),
                "persistence failure leaked {marker}"
            );
        }
    }

    /// F1 — an unusable results destination is rejected by offline validation
    /// before any network activity or Tor startup.
    #[test]
    fn validate_rejects_missing_and_unusable_results_paths() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let mut config = LoadDriverConfig {
            manifest_path: PathBuf::from("."),
            registry_path: PathBuf::from("."),
            candidate_path: PathBuf::from("."),
            voter_public_bundle_path: PathBuf::from("."),
            credentials_dir: PathBuf::from("."),
            tor_socks: SocketAddr::from(([127, 0, 0, 1], 9050)),
            results_path: PathBuf::new(),
            state_dir: None,
            count: Some(1),
            start_index: 1,
            concurrency: 1,
            choice: ChoiceDistribution::RoundRobin,
            passphrase_env: DEFAULT_PASSPHRASE_ENV.to_owned(),
            host_run_id: "test".to_owned(),
        };
        let error = validate_results_output_path(&config.results_path)
            .expect_err("empty results path must be rejected");
        assert!(error.contains("required"), "{error}");
        config.results_path = scratch.path().to_path_buf();
        assert!(validate_results_output_path(&config.results_path).is_err());
        let parent_file = scratch.path().join("not-a-dir");
        fs::write(&parent_file, b"regular file").expect("write parent file");
        config.results_path = parent_file.join("results.json");
        assert!(validate_results_output_path(&config.results_path).is_err());
        config.results_path = scratch.path().join("ok").join("results.json");
        validate_results_output_path(&config.results_path).expect("usable path accepted");
    }

    #[test]
    fn credential_selection_is_one_based_and_sorted() {
        let root = unique_temp_dir("selection");
        if let Err(error) = fs::create_dir_all(&root) {
            panic!("{error}");
        }
        for name in [
            "voter-0003.tcbcred",
            "voter-0001.tcbcred",
            "voter-0002.tcbcred",
        ] {
            if let Err(error) = write_new_file(&root.join(name), b"not-a-real-container") {
                panic!("{error}");
            }
        }

        let selected = match select_credential_paths(&root, 2, Some(2)) {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        };
        let names: Vec<String> = selected
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            names,
            vec![
                "voter-0002.tcbcred".to_owned(),
                "voter-0003.tcbcred".to_owned()
            ]
        );
        let _ = fs::remove_dir_all(root);
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        dir.push(format!("tari-load-driver-{label}-{now}"));
        dir
    }
}
