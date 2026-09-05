#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_cli::managed_tor::{
    MANAGED_TOR_RUN_METADATA_TYPE_V1, ManagedTorRunMetadataV1, ManagedTorStartupConfigV1,
    capture_tor_version_v1, format_utc_timestamp, managed_runtime_base_for_results,
    managed_tor_metadata_path, start_managed_tor_session,
};
use tari_cc_private_ballot_cli::{
    ChoiceDistribution, CohortSummary, DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD,
    DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS, LoadDriverConfig, LoadDriverProgressV1,
    LoadDriverRunControl, LoadDriverValidationSummary, PartitionSummary, credential_count,
    generate_distributed_cohort, partition_credentials_with_summary, run_load_driver_with_control,
    validate_load_driver_inputs, validate_results_output_path,
};
use tari_cc_private_ballot_transport_network::validate_tor_executable_v1;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

/// UI-visible mode strings understood by both frontend and backend for the
/// Tor endpoint. `managed` is the normal path — the operator picked a Tor
/// executable and the GUI owns Tor's lifecycle. `manual-socks` is the
/// advanced fallback — the operator already runs a local Tor listener and
/// gives the GUI its loopback SOCKS endpoint. These names deliberately
/// match the frontend contract so a future rename never silently drifts.
const TOR_MODE_MANAGED: &str = "managed";
const TOR_MODE_MANUAL_SOCKS: &str = "manual-socks";

#[derive(Default)]
struct RunnerState {
    running: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
}

// Cleared on every worker exit path — normal return or a panic inside the
// blocking closure. Without this, a panicked worker would leave `running`
// true and lock out further runs until the app restarts.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CommandError {
    code: String,
    category: String,
    context: Option<String>,
    message: String,
}

impl CommandError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "LOAD_TESTER_INVALID_INPUT".to_owned(),
            category: "INVALID_INPUT".to_owned(),
            context: None,
            message: message.into(),
        }
    }

    fn tor_invalid(message: impl Into<String>) -> Self {
        Self {
            code: "LOAD_TESTER_TOR_EXECUTABLE_INVALID".to_owned(),
            category: "INVALID_INPUT".to_owned(),
            context: None,
            message: message.into(),
        }
    }

    fn tor_failed(message: impl Into<String>) -> Self {
        Self {
            code: "LOAD_TESTER_TOR_FAILED".to_owned(),
            category: "TRANSPORT".to_owned(),
            context: None,
            message: message.into(),
        }
    }

    fn running() -> Self {
        Self {
            code: "LOAD_TESTER_RUN_ALREADY_ACTIVE".to_owned(),
            category: "INVALID_LIFECYCLE_TRANSITION".to_owned(),
            context: None,
            message: "a load test is already running".to_owned(),
        }
    }

    fn from_harness(message: String) -> Self {
        let lower = message.to_lowercase();
        let safe = if lower.contains("passphrase") {
            "credential passphrase was invalid or unavailable".to_owned()
        } else {
            message
        };
        Self {
            code: "LOAD_TESTER_HARNESS_ERROR".to_owned(),
            category: "HARNESS".to_owned(),
            context: None,
            message: safe,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CohortRequest {
    voter_count: usize,
    output_dir: String,
    passphrase: String,
    confirm_passphrase: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CohortResult {
    organizer_registry: String,
    voters_dir: String,
    credentials_generated: usize,
    registry_members: usize,
    elapsed_ms: u128,
    max_registry_members: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartitionRequest {
    credentials_dir: String,
    start_index: usize,
    voter_count: usize,
    output_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartitionDetectResult {
    credentials_detected: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartitionResult {
    credentials_detected: usize,
    credentials_copied: usize,
    first_voter: usize,
    last_voter: usize,
    destination: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoadTestRequest {
    manifest_path: String,
    registry_path: String,
    candidate_path: String,
    voter_public_bundle_path: String,
    credentials_dir: String,
    passphrase: String,
    /// `managed` or `manual-socks`. Exactly one of `tor_exe` / `tor_socks`
    /// must be populated to match, and the resolver rejects ambiguous
    /// combinations rather than picking silently.
    tor_mode: String,
    /// Absolute path to the operator-selected Tor executable when
    /// `tor_mode == "managed"`. Passed through the shared `validate_tor_
    /// executable_v1` policy — never a PATH lookup, never a shell invocation.
    tor_exe: Option<String>,
    /// Loopback `ip:port` of an already-running Tor SOCKS listener when
    /// `tor_mode == "manual-socks"`.
    tor_socks: Option<String>,
    results_path: String,
    choice: String,
    count: Option<usize>,
    start_index: usize,
    run_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TorExecutableRequest {
    tor_exe: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TorExecutableStatus {
    accepted: bool,
    executable_basename: Option<String>,
    /// Filled in only when a Tor executable was actually spawned (Test Tor).
    /// Validation never spawns anything, so it stays `None` on validate.
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestTorResult {
    tor_ready: bool,
    version: Option<String>,
    socks_addr: String,
    started_utc: String,
    stopped_utc: String,
    executable_basename: Option<String>,
    stopped_by_runner: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellInfo {
    product_name: &'static str,
    max_registry_members: usize,
    large_run_warning_threshold: usize,
    default_tor_socks: &'static str,
    concurrency: usize,
}

#[tauri::command]
fn shell_info() -> ShellInfo {
    ShellInfo {
        product_name: "Private Ballot Load Tester",
        max_registry_members: DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS,
        large_run_warning_threshold: DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD,
        default_tor_socks: "127.0.0.1:9050",
        concurrency: 1,
    }
}

#[tauri::command]
async fn generate_cohort(request: CohortRequest) -> Result<CohortResult, CommandError> {
    validate_passphrase_confirmation(&request.passphrase, &request.confirm_passphrase)?;
    // Cohort generation performs repeated Triptych credential generation plus
    // Argon2id encryption and filesystem writes. Run it on a blocking worker so
    // the Tauri UI thread stays responsive at larger test sizes.
    tauri::async_runtime::spawn_blocking(move || {
        let passphrase = Zeroizing::new(request.passphrase);
        let started = Instant::now();
        let summary = generate_distributed_cohort(
            request.voter_count,
            &PathBuf::from(request.output_dir),
            passphrase.as_str(),
        )
        .map_err(CommandError::from_harness)?;
        Ok(cohort_result(summary, started.elapsed().as_millis()))
    })
    .await
    .map_err(|_| CommandError::from_harness("cohort generation worker failed".to_owned()))?
}

#[tauri::command]
fn detect_partition_credentials(
    credentials_dir: String,
) -> Result<PartitionDetectResult, CommandError> {
    let count =
        credential_count(&PathBuf::from(credentials_dir)).map_err(CommandError::from_harness)?;
    Ok(PartitionDetectResult {
        credentials_detected: count,
    })
}

#[tauri::command]
async fn create_partition(request: PartitionRequest) -> Result<PartitionResult, CommandError> {
    // Partitioning copies encrypted credential files and scans directories; run
    // it off the UI thread so large partitions never freeze the window.
    tauri::async_runtime::spawn_blocking(move || {
        let summary = partition_credentials_with_summary(
            &PathBuf::from(request.credentials_dir),
            &PathBuf::from(request.output_dir),
            request.start_index,
            request.voter_count,
        )
        .map_err(CommandError::from_harness)?;
        Ok(partition_result(summary))
    })
    .await
    .map_err(|_| CommandError::from_harness("partition worker failed".to_owned()))?
}

/// Static-only Tor executable validation. Runs the SAME shared policy the
/// production managed-Tor feature enforces (absolute path, exists, regular
/// file, no symlink/reparse point, no control chars, Unix executable-bit
/// where applicable). Does NOT spawn Tor. Does NOT touch the network. This
/// is what the "Select Tor executable" button triggers to render the small
/// Ready ✓ / Invalid pill.
#[tauri::command]
fn validate_tor_executable(
    request: TorExecutableRequest,
) -> Result<TorExecutableStatus, CommandError> {
    let path = PathBuf::from(&request.tor_exe);
    validate_tor_executable_v1(&path)
        .map_err(|error| CommandError::tor_invalid(error.to_string()))?;
    Ok(TorExecutableStatus {
        accepted: true,
        executable_basename: basename_string(&path),
        version: None,
    })
}

/// Diagnostic-only managed-Tor bootstrap. Validates the executable again,
/// creates an isolated temporary run directory, reserves an ephemeral
/// loopback SOCKS port, spawns Tor through the shared spawner, waits for
/// REAL SOCKS5 readiness, and then immediately shuts Tor down and reaps
/// the child. NEVER loads a voter credential, prepares a ballot, or
/// contacts the organizer onion — this is strictly a "does managed Tor
/// come up on this host" check.
#[tauri::command]
async fn test_tor(request: TorExecutableRequest) -> Result<TestTorResult, CommandError> {
    tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&request.tor_exe);
        validate_tor_executable_v1(&path)
            .map_err(|error| CommandError::tor_invalid(error.to_string()))?;
        let executable_basename = basename_string(&path);
        // Temp directory scoped to Test Tor only — never the production
        // managed-Tor DataDirectory used by the real load run.
        let scratch = tempfile::Builder::new()
            .prefix("private-ballot-test-tor-")
            .tempdir()
            .map_err(|_| {
                CommandError::tor_failed(
                    "could not allocate a temporary directory for Test Tor".to_owned(),
                )
            })?;
        let startup = ManagedTorStartupConfigV1::new(path.clone(), scratch.path().to_path_buf());
        let started_utc = format_utc_timestamp(SystemTime::now());
        let mut session = start_managed_tor_session(&startup).map_err(CommandError::tor_failed)?;
        // Capture bounded `tor --version` — best-effort evidence, ignored on
        // any failure or timeout (the started session is what actually
        // proves readiness).
        let version = capture_tor_version_v1(&path);
        let socks_addr = session.socks_addr().to_string();
        session.shutdown();
        // Explicit drop for clarity; tempdir also removes the run directory.
        drop(session);
        drop(scratch);
        let stopped_utc = format_utc_timestamp(SystemTime::now());
        Ok(TestTorResult {
            tor_ready: true,
            version,
            socks_addr,
            started_utc,
            stopped_utc,
            executable_basename,
            stopped_by_runner: true,
        })
    })
    .await
    .map_err(|_| CommandError::from_harness("Test Tor worker failed".to_owned()))?
}

#[tauri::command]
async fn validate_load_test(
    request: LoadTestRequest,
) -> Result<LoadDriverValidationSummary, CommandError> {
    // Static Tor policy check FIRST, before touching disk. Fail closed on
    // ambiguous Tor mode and invalid executables. NEVER spawns Tor here.
    prevalidate_tor_selection(&request)?;
    // Durable per-host results evidence is mandatory: reject a missing or
    // unusable results destination during offline validation too.
    validate_results_destination(&request)?;
    let config = load_config_for_validation(&request)?;
    tauri::async_runtime::spawn_blocking(move || {
        validate_load_driver_inputs(&config).map_err(CommandError::from_harness)
    })
    .await
    .map_err(|_| CommandError::from_harness("validation worker failed".to_owned()))?
}

#[tauri::command]
async fn start_load_test(
    app: AppHandle,
    state: State<'_, RunnerState>,
    request: LoadTestRequest,
) -> Result<serde_json::Value, CommandError> {
    // Re-run static Tor validation on Start too — an operator could change
    // the field between Validate and Start, so we never rely on prior state.
    prevalidate_tor_selection(&request)?;
    // Independent of the frontend: a Run Test without a usable results
    // destination is rejected here even if the frontend gate was bypassed.
    validate_results_destination(&request)?;

    if state.running.swap(true, Ordering::SeqCst) {
        return Err(CommandError::running());
    }
    state.cancel.store(false, Ordering::SeqCst);

    let running = Arc::clone(&state.running);
    let cancel = Arc::clone(&state.cancel);
    let passphrase = request.passphrase.clone();
    let results_path = PathBuf::from(&request.results_path);

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        // The guard clears `running` on every exit path — normal return or a
        // panic inside the harness — so a failed worker can never lock out
        // subsequent runs.
        let _running_guard = RunningGuard(running);
        let passphrase = Zeroizing::new(passphrase);

        // Emit a starting-Tor event so the UI can render the transition.
        let _ = app.emit("load-status", TorStatusEvent::starting_tor());

        // Managed vs manual SOCKS: managed mode owns Tor's lifecycle; manual
        // mode does not spawn anything, and the manual SOCKS endpoint is used
        // as-is (advanced/debug fallback).
        let (
            socks_addr,
            tor_session,
            tor_mode_str,
            tor_exe_basename,
            tor_version,
            tor_run_directory_name,
        ) = match request.tor_mode.as_str() {
            mode if mode == TOR_MODE_MANAGED => {
                let tor_exe = request.tor_exe.as_deref().ok_or_else(|| {
                    CommandError::tor_invalid("managed Tor requires a Tor executable".to_owned())
                })?;
                let tor_exe_path = PathBuf::from(tor_exe);
                validate_tor_executable_v1(&tor_exe_path)
                    .map_err(|error| CommandError::tor_invalid(error.to_string()))?;
                let runtime_base = managed_runtime_base_for_results(&results_path);
                if let Some(parent) = runtime_base.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let startup = ManagedTorStartupConfigV1::new(tor_exe_path.clone(), runtime_base);
                let session =
                    start_managed_tor_session(&startup).map_err(CommandError::tor_failed)?;
                let socks_addr = session.socks_addr();
                let run_dir_name = session
                    .run_dir()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|s| s.to_owned());
                let _ = app.emit("load-status", TorStatusEvent::tor_ready(socks_addr));
                (
                    socks_addr,
                    Some(session),
                    "managed_tor",
                    basename_string(&tor_exe_path),
                    capture_tor_version_v1(&tor_exe_path),
                    run_dir_name,
                )
            }
            mode if mode == TOR_MODE_MANUAL_SOCKS => {
                let raw = request.tor_socks.as_deref().ok_or_else(|| {
                    CommandError::invalid(
                        "manual SOCKS mode requires an ip:port endpoint".to_owned(),
                    )
                })?;
                let socks_addr: SocketAddr = raw.parse().map_err(|_| {
                    CommandError::invalid("Tor SOCKS endpoint must be an ip:port socket address")
                })?;
                let _ = app.emit("load-status", TorStatusEvent::tor_ready(socks_addr));
                (socks_addr, None, "existing_socks", None, None, None)
            }
            other => {
                return Err(CommandError::invalid(format!("unknown Tor mode: {other}")));
            }
        };

        // Build the LoadDriverConfig now that a real loopback SOCKS endpoint
        // is available.
        let config = build_run_config(&request, socks_addr)?;

        let started_utc = SystemTime::now();
        let mut progress = |progress: LoadDriverProgressV1| {
            let _ = app.emit("load-progress", progress);
        };
        let should_cancel = || cancel.load(Ordering::SeqCst);
        let mut control = LoadDriverRunControl {
            progress: Some(&mut progress),
            cancel: Some(&should_cancel),
            persist_incremental: true,
        };
        let outcome = run_load_driver_with_control(&config, passphrase.as_str(), &mut control);

        // Regardless of outcome, stop/reap Tor if we started it. Dropping the
        // session already does this; the explicit `shutdown()` here is
        // idempotent and pairs with the Ready → Stopping event surface.
        let stopped_by_runner = tor_session.is_some();
        if let Some(mut session) = tor_session {
            let _ = app.emit("load-status", TorStatusEvent::stopping_tor());
            session.shutdown();
            drop(session);
        }

        // Write the managed-Tor evidence sidecar next to the results file.
        let onion_hostname =
            tari_cc_private_ballot_transport_gateway_ok(&request.voter_public_bundle_path);
        let elapsed_ms = outcome
            .as_ref()
            .map(|report| report.elapsed_ms)
            .unwrap_or(0);
        let metadata = ManagedTorRunMetadataV1 {
            metadata_type: MANAGED_TOR_RUN_METADATA_TYPE_V1,
            tor_mode: tor_mode_str,
            started_utc: format_utc_timestamp(started_utc),
            finished_utc: format_utc_timestamp(SystemTime::now()),
            socks_endpoint: socks_addr.to_string(),
            onion_hostname,
            tor_executable_basename: tor_exe_basename,
            tor_version,
            tor_run_directory_name,
            tor_process_stopped_by_runner: Some(stopped_by_runner),
            elapsed_ms,
        };
        let meta_path = managed_tor_metadata_path(&results_path);
        if let Err(metadata_error) = write_metadata_file(&meta_path, &metadata) {
            // Secondary evidence, never the election authority: a metadata
            // sidecar failure is surfaced explicitly as a warning but must NOT
            // alter the submission result (no re-send, no false failure of the
            // ballots themselves). The message is a fixed safe string — no
            // paths, no secrets.
            let _ = app.emit(
                "load-warning",
                format!(
                    "the managed-Tor evidence file could not be written ({metadata_error}); the load-test results report itself is unaffected"
                ),
            );
        }

        outcome.map_err(CommandError::from_harness)
    })
    .await
    .map_err(|_| CommandError::from_harness("load test worker failed".to_owned()))?;

    let report = outcome?;
    serde_json::to_value(report)
        .map_err(|_| CommandError::from_harness("could not serialize load report".to_owned()))
}

#[tauri::command]
fn stop_after_current_voter(state: State<'_, RunnerState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

/// Durable results evidence is mandatory for Run Test: the results path must
/// be non-empty and its destination usable. Shared by validate and start so
/// the frontend can never talk the backend into an evidence-less run.
fn validate_results_destination(request: &LoadTestRequest) -> Result<(), CommandError> {
    validate_results_output_path(Path::new(&request.results_path))
        .map_err(CommandError::invalid)
}

fn validate_passphrase_confirmation(
    passphrase: &str,
    confirm_passphrase: &str,
) -> Result<(), CommandError> {
    if passphrase.is_empty() {
        return Err(CommandError::invalid(
            "test credential passphrase is required",
        ));
    }
    if passphrase != confirm_passphrase {
        return Err(CommandError::invalid(
            "passphrase confirmation does not match",
        ));
    }
    Ok(())
}

/// Static-only Tor selection check shared by validate and start. Rejects
/// ambiguous configuration (both fields set / mode set to an unknown value)
/// and delegates the actual policy check to `validate_tor_executable_v1`.
/// Emits no network activity and starts no processes.
fn prevalidate_tor_selection(request: &LoadTestRequest) -> Result<(), CommandError> {
    match request.tor_mode.as_str() {
        mode if mode == TOR_MODE_MANAGED => {
            let path_str = request.tor_exe.as_deref().ok_or_else(|| {
                CommandError::tor_invalid("managed Tor requires a Tor executable")
            })?;
            if path_str.trim().is_empty() {
                return Err(CommandError::tor_invalid(
                    "managed Tor requires a Tor executable",
                ));
            }
            if request
                .tor_socks
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(CommandError::invalid(
                    "supply either a Tor executable (managed) or a Tor SOCKS endpoint (advanced) — not both",
                ));
            }
            let path = PathBuf::from(path_str);
            validate_tor_executable_v1(&path)
                .map_err(|error| CommandError::tor_invalid(error.to_string()))?;
            Ok(())
        }
        mode if mode == TOR_MODE_MANUAL_SOCKS => {
            let socks_str = request.tor_socks.as_deref().ok_or_else(|| {
                CommandError::invalid("manual SOCKS mode requires an ip:port endpoint")
            })?;
            if socks_str.trim().is_empty() {
                return Err(CommandError::invalid(
                    "manual SOCKS mode requires an ip:port endpoint",
                ));
            }
            if request
                .tor_exe
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(CommandError::invalid(
                    "supply either a Tor executable (managed) or a Tor SOCKS endpoint (advanced) — not both",
                ));
            }
            let _: SocketAddr = socks_str.parse().map_err(|_| {
                CommandError::invalid("Tor SOCKS endpoint must be an ip:port socket address")
            })?;
            Ok(())
        }
        other => Err(CommandError::invalid(format!(
            "unknown Tor mode '{other}'; supply managed or manual-socks"
        ))),
    }
}

/// Builds a `LoadDriverConfig` suitable for `validate_load_driver_inputs`.
/// The SOCKS endpoint here is only a syntactic placeholder for validation
/// purposes — a loopback `127.0.0.1:1` — because managed mode has not yet
/// spawned Tor when validate runs. The final `run_load_driver_with_control`
/// call receives the REAL reserved port through `build_run_config` below.
fn load_config_for_validation(request: &LoadTestRequest) -> Result<LoadDriverConfig, CommandError> {
    if request.passphrase.is_empty() {
        return Err(CommandError::invalid("credential passphrase is required"));
    }
    // Prefer the actual manual SOCKS endpoint when provided; otherwise use a
    // pinned loopback placeholder purely for syntactic parsing. Managed mode
    // will replace this with a real reserved port at start time — validate
    // never uses this endpoint for anything network-facing.
    let tor_socks: SocketAddr = match request.tor_socks.as_deref() {
        Some(raw) if !raw.trim().is_empty() => raw.parse().map_err(|_| {
            CommandError::invalid("Tor SOCKS endpoint must be an ip:port socket address")
        })?,
        _ => "127.0.0.1:1"
            .parse()
            .expect("hardcoded loopback placeholder"),
    };
    let choice = ChoiceDistribution::parse(&request.choice).map_err(CommandError::invalid)?;
    Ok(LoadDriverConfig {
        manifest_path: PathBuf::from(&request.manifest_path),
        registry_path: PathBuf::from(&request.registry_path),
        candidate_path: PathBuf::from(&request.candidate_path),
        voter_public_bundle_path: PathBuf::from(&request.voter_public_bundle_path),
        credentials_dir: PathBuf::from(&request.credentials_dir),
        tor_socks,
        results_path: PathBuf::from(&request.results_path),
        state_dir: None,
        count: request.count,
        start_index: request.start_index,
        concurrency: 1,
        choice,
        passphrase_env: "GUI_DIRECT_INPUT".to_owned(),
        host_run_id: request
            .run_id
            .clone()
            .unwrap_or_else(|| "gui-load-test".to_owned()),
    })
}

fn build_run_config(
    request: &LoadTestRequest,
    tor_socks: SocketAddr,
) -> Result<LoadDriverConfig, CommandError> {
    if request.passphrase.is_empty() {
        return Err(CommandError::invalid("credential passphrase is required"));
    }
    let choice = ChoiceDistribution::parse(&request.choice).map_err(CommandError::invalid)?;
    Ok(LoadDriverConfig {
        manifest_path: PathBuf::from(&request.manifest_path),
        registry_path: PathBuf::from(&request.registry_path),
        candidate_path: PathBuf::from(&request.candidate_path),
        voter_public_bundle_path: PathBuf::from(&request.voter_public_bundle_path),
        credentials_dir: PathBuf::from(&request.credentials_dir),
        tor_socks,
        results_path: PathBuf::from(&request.results_path),
        state_dir: None,
        count: request.count,
        start_index: request.start_index,
        concurrency: 1,
        choice,
        passphrase_env: "GUI_DIRECT_INPUT".to_owned(),
        host_run_id: request
            .run_id
            .clone()
            .unwrap_or_else(|| "gui-load-test".to_owned()),
    })
}

fn cohort_result(summary: CohortSummary, elapsed_ms: u128) -> CohortResult {
    CohortResult {
        organizer_registry: summary.organizer_registry.display().to_string(),
        voters_dir: summary.voters_dir.display().to_string(),
        credentials_generated: summary.credentials_written,
        registry_members: summary.registry_members,
        elapsed_ms,
        max_registry_members: DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS,
    }
}

fn partition_result(summary: PartitionSummary) -> PartitionResult {
    PartitionResult {
        credentials_detected: summary.credentials_detected,
        credentials_copied: summary.credentials_copied,
        first_voter: summary.first_voter_index,
        last_voter: summary.last_voter_index,
        destination: summary.destination.display().to_string(),
    }
}

fn basename_string(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|s| s.to_owned())
}

fn write_metadata_file(path: &Path, metadata: &ManagedTorRunMetadataV1) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|_| "could not encode managed-Tor metadata".to_owned())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "could not create parent directory".to_owned())?;
    }
    let mut tmp = path.to_path_buf();
    let tmp_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.tmp"))
        .unwrap_or_else(|| "managed-tor-metadata.json.tmp".to_owned());
    tmp.set_file_name(tmp_name);
    std::fs::write(&tmp, &bytes).map_err(|_| "could not write managed-Tor metadata".to_owned())?;
    std::fs::rename(&tmp, path).map_err(|_| "could not commit managed-Tor metadata".to_owned())?;
    Ok(())
}

/// Loads the voter public bundle only to extract the onion hostname for the
/// evidence sidecar. Failures are silent (metadata is best-effort operational
/// evidence, not a run gate).
fn tari_cc_private_ballot_transport_gateway_ok(path: &str) -> Option<String> {
    use tari_cc_private_ballot_transport_gateway::load_voter_public_bundle_v1;
    let bundle = load_voter_public_bundle_v1(&PathBuf::from(path)).ok()?;
    bundle.descriptor.onion_endpoints().first().cloned()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TorStatusEvent {
    stage: &'static str,
    socks_addr: Option<String>,
}

impl TorStatusEvent {
    fn starting_tor() -> Self {
        Self {
            stage: "STARTING_TOR",
            socks_addr: None,
        }
    }

    fn tor_ready(socks_addr: SocketAddr) -> Self {
        Self {
            stage: "TOR_READY",
            socks_addr: Some(socks_addr.to_string()),
        }
    }

    fn stopping_tor() -> Self {
        Self {
            stage: "STOPPING_TOR",
            socks_addr: None,
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(RunnerState::default())
        .invoke_handler(tauri::generate_handler![
            shell_info,
            generate_cohort,
            detect_partition_credentials,
            create_partition,
            validate_tor_executable,
            test_tor,
            validate_load_test,
            start_load_test,
            stop_after_current_voter,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Private Ballot Load Tester shell")
        .run(|app_handle, event| {
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                let state = app_handle.state::<RunnerState>();
                state.cancel.store(true, Ordering::SeqCst);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(passphrase: &str, tor_mode: &str) -> LoadTestRequest {
        LoadTestRequest {
            manifest_path: "election-manifest.cbor".to_owned(),
            registry_path: "voter-registry.cbor".to_owned(),
            candidate_path: "candidate-set.cbor".to_owned(),
            voter_public_bundle_path: "voter-public-bundle.cbor".to_owned(),
            credentials_dir: "voters".to_owned(),
            passphrase: passphrase.to_owned(),
            tor_mode: tor_mode.to_owned(),
            tor_exe: None,
            tor_socks: None,
            results_path: "results.json".to_owned(),
            choice: "round-robin".to_owned(),
            count: Some(1),
            start_index: 1,
            run_id: None,
        }
    }

    #[test]
    fn empty_results_path_is_rejected() {
        let mut request = sample_request("secret", TOR_MODE_MANAGED);
        request.tor_exe = Some(String::from("C:/absolute/tor.exe"));
        request.results_path = String::new();
        let error = validate_results_destination(&request).expect_err("empty must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(rendered.contains("results output path"));
    }

    #[test]
    fn results_path_pointing_at_a_directory_is_rejected() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let mut request = sample_request("secret", TOR_MODE_MANAGED);
        request.tor_exe = Some(String::from("C:/absolute/tor.exe"));
        request.results_path = scratch.path().to_string_lossy().into_owned();
        let error = validate_results_destination(&request).expect_err("directory must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
    }

    #[test]
    fn results_path_with_unusable_parent_is_rejected() {
        // Parent exists as a REGULAR FILE: the atomic replace can never commit
        // there, so start must fail closed before any voter runs.
        let scratch = tempfile::tempdir().expect("scratch dir");
        let parent_file = scratch.path().join("not-a-dir");
        std::fs::write(&parent_file, b"regular file").expect("write parent file");
        let mut request = sample_request("secret", TOR_MODE_MANAGED);
        request.tor_exe = Some(String::from("C:/absolute/tor.exe"));
        request.results_path =
            parent_file.join("results.json").to_string_lossy().into_owned();
        let error = validate_results_destination(&request).expect_err("unusable parent must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(
            !rendered.contains(parent_file.to_string_lossy().as_ref()),
            "results destination errors must not leak operator paths"
        );
    }

    #[test]
    fn usable_results_path_is_accepted() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let mut request = sample_request("secret", TOR_MODE_MANAGED);
        request.tor_exe = Some(String::from("C:/absolute/tor.exe"));
        request.results_path =
            scratch.path().join("nested").join("results.json").to_string_lossy().into_owned();
        validate_results_destination(&request).expect("usable destination must be accepted");
        assert!(
            scratch.path().join("nested").is_dir(),
            "validation may create the missing parent directory"
        );
    }

    #[test]
    fn passphrase_confirmation_mismatch_does_not_echo_secret() {
        let error = validate_passphrase_confirmation("super-secret-value", "different")
            .expect_err("mismatch must fail");
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("confirmation"));
    }

    #[test]
    fn empty_passphrase_is_rejected_before_run() {
        let mut request = sample_request("", TOR_MODE_MANUAL_SOCKS);
        request.tor_socks = Some("127.0.0.1:9050".to_owned());
        let error =
            load_config_for_validation(&request).expect_err("empty passphrase must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(rendered.contains("passphrase"));
    }

    #[test]
    fn manual_socks_hostname_is_rejected() {
        let mut request = sample_request("secret", TOR_MODE_MANUAL_SOCKS);
        request.tor_socks = Some("localhost:9050".to_owned());
        let error = prevalidate_tor_selection(&request).expect_err("hostnames are rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
    }

    #[test]
    fn managed_mode_requires_a_tor_executable() {
        let request = sample_request("secret", TOR_MODE_MANAGED);
        let error = prevalidate_tor_selection(&request).expect_err("managed needs tor_exe");
        assert_eq!(error.code, "LOAD_TESTER_TOR_EXECUTABLE_INVALID");
    }

    #[test]
    fn ambiguous_tor_config_is_rejected() {
        let mut request = sample_request("secret", TOR_MODE_MANAGED);
        request.tor_exe = Some(String::from("C:/absolute/tor.exe"));
        request.tor_socks = Some(String::from("127.0.0.1:9050"));
        let error = prevalidate_tor_selection(&request).expect_err("ambiguity must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_INVALID_INPUT");
    }

    #[test]
    fn relative_tor_executable_is_rejected_by_static_validator() {
        let error = validate_tor_executable(TorExecutableRequest {
            tor_exe: "tor.exe".to_owned(),
        })
        .expect_err("relative path must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_TOR_EXECUTABLE_INVALID");
    }

    #[test]
    fn missing_tor_executable_is_rejected_by_static_validator() {
        // Absolute nonexistent path: rejected without spawning anything.
        #[cfg(windows)]
        let path = "C:/absolutely-does-not-exist/tor.exe";
        #[cfg(unix)]
        let path = "/absolutely-does-not-exist/tor";
        let error = validate_tor_executable(TorExecutableRequest {
            tor_exe: path.to_owned(),
        })
        .expect_err("missing path must be rejected");
        assert_eq!(error.code, "LOAD_TESTER_TOR_EXECUTABLE_INVALID");
    }

    #[test]
    fn shell_info_reports_authoritative_registry_limit_and_sequential_concurrency() {
        let info = shell_info();
        assert_eq!(
            info.max_registry_members,
            DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS
        );
        assert_eq!(info.concurrency, 1);
    }

    #[test]
    fn running_guard_resets_flag_on_drop() {
        let flag = Arc::new(AtomicBool::new(true));
        {
            let _guard = RunningGuard(Arc::clone(&flag));
            assert!(flag.load(Ordering::SeqCst));
        }
        assert!(
            !flag.load(Ordering::SeqCst),
            "the guard must clear the running flag when it drops"
        );
    }

    #[test]
    fn passphrase_never_leaks_through_command_error_serialization() {
        let error = CommandError::from_harness("bad passphrase for credential".to_owned());
        let rendered = serde_json::to_string(&error).expect("error serializes");
        assert!(!rendered.contains("bad passphrase for credential"));
        assert!(rendered.contains("invalid"));
    }

    #[test]
    fn tor_metadata_never_contains_passphrase_marker() {
        let metadata = ManagedTorRunMetadataV1 {
            metadata_type: MANAGED_TOR_RUN_METADATA_TYPE_V1,
            tor_mode: "managed_tor",
            started_utc: "2026-09-04T00:00:00Z".to_owned(),
            finished_utc: "2026-09-04T00:00:01Z".to_owned(),
            socks_endpoint: "127.0.0.1:12345".to_owned(),
            onion_hostname: Some("abcdef.onion:443".to_owned()),
            tor_executable_basename: Some("tor.exe".to_owned()),
            tor_version: Some("Tor 0.4.8.10".to_owned()),
            tor_run_directory_name: Some("run-0000".to_owned()),
            tor_process_stopped_by_runner: Some(true),
            elapsed_ms: 42,
        };
        let rendered = serde_json::to_string(&metadata).expect("metadata serializes");
        let lower = rendered.to_lowercase();
        for marker in [
            "passphrase",
            "credential",
            "secret",
            "scalar",
            "private_key",
        ] {
            assert!(
                !lower.contains(marker),
                "managed-Tor metadata leaked a secret marker: {marker}"
            );
        }
    }
}
