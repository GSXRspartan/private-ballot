#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

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

const DEFAULT_PASSPHRASE_ENV: &str = "TARI_BALLOT_LOAD_PASSPHRASE";
const ORGANIZER_REGISTRY_FILE: &str = "voter-registry.cbor";

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
    eprintln!("Tari CC Private Ballot protocol workspace");
    eprintln!();
    eprintln!("usage:");
    eprintln!("  {prog} distributed-cohort --count <N> --out <dir> [--passphrase-env <ENV>]");
    eprintln!(
        "  {prog} distributed-partition --credentials <dir> --out <dir> --start-index <N> --count <N>"
    );
    eprintln!(
        "  {prog} distributed-submit --manifest <path> --registry <path> --candidates <path> --voter-public-bundle <path> --credentials <dir> --tor-socks <ip:port> --results <path> [--choice round-robin|all:<candidate-id-hex>] [--count <N>] [--start-index <N>] [--concurrency 1] [--passphrase-env <ENV>] [--state-dir <dir>]"
    );
    eprintln!();
    eprintln!("No command starts Tor, walletd, indexer, GUI, or Ootle services.");
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
    let config = LoadDriverConfig {
        manifest_path: parsed.required_path("--manifest")?,
        registry_path: parsed.required_path("--registry")?,
        candidate_path: parsed.required_path("--candidates")?,
        voter_public_bundle_path: parsed.required_path("--voter-public-bundle")?,
        credentials_dir: parsed.required_path("--credentials")?,
        tor_socks: parsed.required_socket("--tor-socks")?,
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
    let report = run_load_driver(&config, &passphrase)?;
    write_json_report(&config.results_path, &report)?;
    print_report_summary(&report);
    Ok(())
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
    validate_load_driver_config(config)?;
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
    let selected_paths =
        select_credential_paths(&config.credentials_dir, config.start_index, config.count)?;
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

    for (offset, path) in selected_paths.iter().enumerate() {
        let display_path = path.to_string_lossy().into_owned();
        let selected_candidate = config.choice.choose(&candidate_ids_hex, offset)?;
        expected.add(selected_candidate.clone());

        let container = match read_voter_credential_container_v1(path) {
            Ok(container) => container,
            Err(error) => {
                failures.push(failure(display_path, "credential-read", error.code()));
                continue;
            }
        };
        let public_key = container.public_key_bytes();
        if !loaded_public_keys.insert(public_key) {
            duplicate_credentials_detected += 1;
            failures.push(LoadDriverFailureV1 {
                credential_file: display_path,
                stage: "credential-duplicate",
                code: "DUPLICATE_CREDENTIAL".to_owned(),
            });
            continue;
        }
        let credential = match container.decrypt(passphrase) {
            Ok(credential) => credential,
            Err(error) => {
                failures.push(failure(display_path, "credential-decrypt", error.code()));
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
                failures.push(failure(display_path, "credential-install", error.code()));
                continue;
            }
        };
        if status.eligibility != GuiVoterEligibilityV1::Eligible {
            failures.push(LoadDriverFailureV1 {
                credential_file: display_path,
                stage: "eligibility",
                code: "CREDENTIAL_NOT_ELIGIBLE".to_owned(),
            });
            continue;
        }
        if let Err(error) = voter.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![selected_candidate.clone()],
            false,
        ) {
            failures.push(failure(display_path, "selection", error.code()));
            continue;
        }

        let proof_started = Instant::now();
        if let Err(error) = voter.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open) {
            proof_total += proof_started.elapsed();
            proof_generation_failures += 1;
            failures.push(failure(display_path, "proof", error.code()));
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
                    credential_file: display_path,
                    stage: result.diagnostic_stage.unwrap_or("submission"),
                    code: result.receipt_state.to_owned(),
                });
            }
            Err(error) => {
                submission_total += submission_started.elapsed();
                failed_submissions += 1;
                failures.push(failure(display_path, "submission", error.code()));
            }
        }
    }

    Ok(DistributedLoadReportV1 {
        report_type: "TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1",
        host_run_id: config.host_run_id.clone(),
        requested_voter_count: selected_paths.len(),
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
    })
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

#[derive(Default)]
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

    fn required_socket(&self, name: &str) -> Result<SocketAddr, String> {
        self.required_value(name)?
            .parse()
            .map_err(|_| format!("{name} must be an ip:port socket address"))
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
