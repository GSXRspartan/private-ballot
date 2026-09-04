//! Managed-Tor runtime for the distributed voter load driver (CLI side).
//!
//! This module lets each distributed voter host run its OWN operator-supplied
//! Tor executable without any manual pre-launch step:
//!
//!   1. the operator passes an explicit absolute `--tor-exe <path>` (validated
//!      with the SAME shared policy as the production managed-Tor feature), or
//!      the legacy `--tor-socks <ip:port>` for an already-running listener;
//!   2. managed mode reserves a fresh loopback SOCKS port, allocates a fresh
//!      isolated run directory (its own Tor `DataDirectory` — never the
//!      production Private Ballot Tor state), generates the minimal
//!      client-only Tor config, and spawns `tor.exe` directly (no shell, no
//!      PATH lookup, no download);
//!   3. readiness is the REAL reviewed SOCKS5 probe — a successful spawn is
//!      never treated as a ready Tor;
//!   4. the session owns ONLY the child it launched: dropping the session or
//!      any error path stops/reaps that child, never any other Tor process;
//!   5. on success the disposable runtime is removed; on failure it is
//!      preserved (bounded stderr log) as failure evidence.
//!
//! There is deliberately NO clearnet/relay fallback anywhere: if managed Tor
//! fails, the run fails and no ballot bytes leave the host.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tari_cc_private_ballot_transport_network::{
    ManagedTorChildV1, ManagedTorConfigV1, ManagedTorControllerV1, ManagedTorReadinessProbeV1,
    ManagedTorSpawnerV1, StderrLogFileTorSpawnerV1, SystemManagedTorReadinessProbeV1,
    TorSocksPrivateReleaseCarrierV1, create_fresh_run_directory_v1, reserve_loopback_socks_port_v1,
    validate_tor_executable_v1,
};

/// Bounded startup budget for a managed load-driver Tor child. Matches the
/// qualified production voter-side startup budget.
pub const MANAGED_TOR_STARTUP_TIMEOUT_V1: Duration = Duration::from_secs(60);

/// Bounded connect/handshake budgets for the readiness probe (same shape as the
/// production voter-side preflight).
const SOCKS_PROBE_CONNECT: Duration = Duration::from_secs(10);
const SOCKS_PROBE_HANDSHAKE: Duration = Duration::from_secs(20);

/// Bounded budget for the optional `tor --version` evidence capture.
const TOR_VERSION_BUDGET: Duration = Duration::from_secs(5);
/// Bounded ceiling on captured `tor --version` output.
const TOR_VERSION_MAX_CHARS: usize = 128;

/// Serializable, non-secret run metadata written next to every load-driver
/// results file. It intentionally records ONLY non-secret operational
/// evidence: basenames (never full operator paths), the loopback SOCKS
/// endpoint, and process lifecycle facts. No onion private keys, voter
/// credentials, passphrases, or Tor private state are ever recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedTorRunMetadataV1 {
    pub metadata_type: &'static str,
    /// "managed-tor" (CLI started Tor) or "existing-socks" (operator-supplied
    /// listener; preserved legacy workflow).
    pub tor_mode: &'static str,
    pub started_utc: String,
    pub finished_utc: String,
    pub socks_endpoint: String,
    /// Public organizer onion hostname from the verified voter-public bundle.
    pub onion_hostname: Option<String>,
    /// Basename of the operator-supplied Tor executable (path itself omitted).
    pub tor_executable_basename: Option<String>,
    /// Optional `tor --version` output (bounded, single line).
    pub tor_version: Option<String>,
    /// Name of the disposable run directory under the operator's run output.
    pub tor_run_directory_name: Option<String>,
    /// Whether the runner stopped/reaped the Tor child it launched.
    pub tor_process_stopped_by_runner: Option<bool>,
    pub elapsed_ms: u128,
}

pub const MANAGED_TOR_RUN_METADATA_TYPE_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_MANAGED_TOR_RUN_METADATA_V1";

/// Which Tor SOCKS endpoint the distributed submitter will use. Exactly one
/// variant is ever constructible: supplying both inputs is rejected as
/// ambiguous and supplying neither is rejected as under-specified (fail
/// closed — no guessing, no silent fallback to any clearnet path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorEndpointModeV1 {
    /// MODE A — managed: the tool validates the operator-supplied executable
    /// and starts/stops an isolated Tor process itself.
    Managed { tor_exe: PathBuf },
    /// MODE B — existing: an operator-run local Tor SOCKS listener (the exact
    /// workflow of the prior physical 500-voter test).
    ExistingSocks { socks_addr: SocketAddr },
}

/// Resolves the Tor endpoint mode from the two CLI inputs. Ambiguity is
/// rejected (both supplied) rather than resolved by silent precedence.
pub fn resolve_tor_endpoint_mode_v1(
    tor_exe: Option<&Path>,
    tor_socks: Option<SocketAddr>,
) -> Result<TorEndpointModeV1, String> {
    match (tor_exe, tor_socks) {
        (Some(_), Some(_)) => Err(
            "supply either --tor-exe (managed Tor) or --tor-socks (existing SOCKS listener), not both; refusing to guess"
                .to_owned(),
        ),
        (None, None) => Err(
            "supply --tor-exe (managed Tor) or --tor-socks (existing SOCKS listener)".to_owned(),
        ),
        (Some(tor_exe), None) => {
            validate_tor_executable_v1(tor_exe)
                .map_err(|error| format!("tor executable rejected: {error}"))?;
            Ok(TorEndpointModeV1::Managed {
                tor_exe: tor_exe.to_path_buf(),
            })
        }
        (None, Some(socks_addr)) => {
            // Fail closed on non-loopback endpoints: the carrier construction
            // is the single shared loopback gate, so a LAN/public address can
            // never become the submission route.
            TorSocksPrivateReleaseCarrierV1::new(
                socks_addr,
                tari_cc_private_ballot_transport_network::TorCarrierTimeoutsV1::default(),
            )
            .map_err(|_| {
                format!(
                    "--tor-socks must be a loopback ip:port endpoint (got {socks_addr})"
                )
            })?;
            Ok(TorEndpointModeV1::ExistingSocks { socks_addr })
        }
    }
}

/// Locally-owned inputs for ONE managed-Tor load-driver start. The Tor
/// executable is operator-supplied and re-validated at start; the runtime base
/// is a parent directory (under the run output) into which a fresh unique run
/// directory is allocated per start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedTorStartupConfigV1 {
    pub tor_exe: PathBuf,
    pub runtime_base: PathBuf,
    pub startup_timeout: Duration,
}

impl ManagedTorStartupConfigV1 {
    pub fn new(tor_exe: PathBuf, runtime_base: PathBuf) -> Self {
        Self {
            tor_exe,
            runtime_base,
            startup_timeout: MANAGED_TOR_STARTUP_TIMEOUT_V1,
        }
    }
}

/// Pure derivation of the isolated per-run Tor inputs for a run directory and
/// reserved SOCKS port. Testable without any process or network.
pub fn managed_tor_config_for_run(
    startup: &ManagedTorStartupConfigV1,
    run_dir: &Path,
    socks_port: u16,
) -> Result<ManagedTorConfigV1, String> {
    validate_tor_executable_v1(&startup.tor_exe)
        .map_err(|error| format!("tor executable rejected: {error}"))?;
    if socks_port == 0 {
        return Err("managed Tor SOCKS port must be non-zero".to_owned());
    }
    Ok(ManagedTorConfigV1 {
        executable: startup.tor_exe.clone(),
        data_directory: run_dir.join("tor-data"),
        config_file: run_dir.join("torrc"),
        socks_port,
        startup_timeout: startup.startup_timeout,
    })
}

/// An owned managed-Tor session. Dropping the session (on success, on any
/// error path after start, or on user interrupt unwinding) stops and reaps the
/// child it launched. Only THIS child is ever touched: no process list is
/// scanned and no other Tor (manual SOCKS provider, Tor Browser, production
/// Private Ballot Tor) is signalled.
pub struct ManagedTorSessionV1<C: ManagedTorChildV1> {
    controller: ManagedTorControllerV1<C>,
    socks_addr: SocketAddr,
    run_dir: PathBuf,
    stopped: bool,
}

impl<C: ManagedTorChildV1> ManagedTorSessionV1<C> {
    /// The validated loopback SOCKS endpoint the carrier must use.
    #[must_use]
    pub const fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The disposable run directory backing this session (isolated Tor
    /// `DataDirectory` parent; never shared with production Tor state).
    #[must_use]
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// Explicitly stops and reaps the owned Tor child. Idempotent; the Drop
    /// impl performs the same bounded cleanup as a backstop.
    pub fn shutdown(&mut self) {
        self.controller.shutdown();
        self.stopped = true;
    }
}

impl<C: ManagedTorChildV1> Drop for ManagedTorSessionV1<C> {
    fn drop(&mut self) {
        if !self.stopped {
            self.controller.shutdown();
        }
    }
}

/// Starts a managed Tor session using injected spawner/readiness seams. The
/// production path supplies the reviewed system probe + stderr-log spawner;
/// tests supply fakes. Never starts networking without an explicit caller.
#[cfg(test)]
pub fn start_managed_tor_session_with_seams<C: ManagedTorChildV1, S, P>(
    startup: &ManagedTorStartupConfigV1,
    spawner: &S,
    probe: &mut P,
    elapsed: impl FnMut() -> Duration,
) -> Result<ManagedTorSessionV1<C>, String>
where
    S: ManagedTorSpawnerV1<Child = C>,
    P: ManagedTorReadinessProbeV1,
{
    let socks_port = reserve_loopback_socks_port_v1()
        .map_err(|_| "no loopback SOCKS port could be reserved for managed Tor".to_owned())?;
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], socks_port));
    let run_dir = create_fresh_run_directory_v1(&startup.runtime_base)
        .map_err(|_| "could not allocate an isolated managed-Tor run directory".to_owned())?;
    let config = managed_tor_config_for_run(startup, &run_dir, socks_port)?;
    let controller = ManagedTorControllerV1::start(&config, spawner, probe, elapsed).map_err(|_| {
        format!(
            "managed Tor failed to start or the SOCKS5 listener did not become ready within {}s; no ballots were submitted (run evidence preserved)",
            startup.startup_timeout.as_secs()
        )
    })?;
    Ok(ManagedTorSessionV1 {
        controller,
        socks_addr,
        run_dir,
        stopped: false,
    })
}

/// The production-path start: the reviewed system SOCKS probe and the shared
/// stderr-log spawner (bounded evidence file, never a pipe).
pub fn start_managed_tor_session(
    startup: &ManagedTorStartupConfigV1,
) -> Result<ManagedTorSessionV1<Child>, String> {
    let socks_port = reserve_loopback_socks_port_v1()
        .map_err(|_| "no loopback SOCKS port could be reserved for managed Tor".to_owned())?;
    let run_dir = create_fresh_run_directory_v1(&startup.runtime_base)
        .map_err(|_| "could not allocate an isolated managed-Tor run directory".to_owned())?;
    let config = managed_tor_config_for_run(startup, &run_dir, socks_port)?;
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], socks_port));
    let mut probe = SystemManagedTorReadinessProbeV1::new(
        socks_addr,
        SOCKS_PROBE_CONNECT,
        SOCKS_PROBE_HANDSHAKE,
    )
    .map_err(|_| "invalid managed-Tor SOCKS endpoint".to_owned())?;
    let spawner = StderrLogFileTorSpawnerV1 {
        stderr_log: run_dir.join("tor-stderr.log"),
    };
    let start = Instant::now();
    let controller = ManagedTorControllerV1::start(&config, &spawner, &mut probe, || start.elapsed())
        .map_err(|_| {
            format!(
                "managed Tor failed to start or the SOCKS5 listener did not become ready within {}s; no ballots were submitted (run evidence preserved)",
                startup.startup_timeout.as_secs()
            )
        })?;
    Ok(ManagedTorSessionV1 {
        controller,
        socks_addr,
        run_dir,
        stopped: false,
    })
}

/// Optionally captures `tor --version` from the ALREADY-VALIDATED executable:
/// direct spawn (no shell), bounded stdout, bounded wait; on any failure or
/// timeout the child is killed and `None` is returned. A version lookup
/// failure is never permission to bypass validation and never changes the run
/// outcome.
pub fn capture_tor_version_v1(executable: &Path) -> Option<String> {
    use std::io::Read;
    let mut child = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 512];
        let mut stream = stdout;
        // Bounded read loop: at most a few chunks, then stop.
        for _ in 0..8 {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    if buffer.len() >= TOR_VERSION_MAX_CHARS * 4 {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&buffer).into_owned()
    });
    let deadline = Instant::now() + TOR_VERSION_BUDGET;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => break None,
        }
    };
    if status.is_none() {
        // Bounded budget exceeded: kill the version child and reap it.
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let output = reader.join().ok()?;
    parse_tor_version_line(&output)
}

/// Pure parser for bounded `tor --version` output: first non-empty line,
/// trimmed, control-character free, length-capped. Testable without Tor.
pub fn parse_tor_version_line(raw: &str) -> Option<String> {
    let line = raw.lines().find(|line| !line.trim().is_empty())?.trim();
    if line.is_empty() || line.chars().any(char::is_control) {
        return None;
    }
    if !line.starts_with("Tor ") {
        return None;
    }
    let mut bounded: String = line.chars().take(TOR_VERSION_MAX_CHARS).collect();
    if line.chars().count() > TOR_VERSION_MAX_CHARS {
        bounded.push('…');
    }
    Some(bounded)
}

/// Derives the deterministic parent directory for disposable managed-Tor
/// runtime state: a sibling of the results file, e.g.
/// `<results>.managed-tor-runtime\run-<unique>\`. Never the production Tor
/// data directory; never shared between runs.
pub fn managed_runtime_base_for_results(results_path: &Path) -> PathBuf {
    let stem = results_path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "distributed-load-results".to_owned());
    results_path.with_file_name(format!("{stem}.managed-tor-runtime"))
}

/// Derives the non-secret metadata file path next to the results file.
pub fn managed_tor_metadata_path(results_path: &Path) -> PathBuf {
    let stem = results_path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "distributed-load-results".to_owned());
    results_path.with_file_name(format!("{stem}.managed-tor-metadata.json"))
}

/// Formats a `SystemTime` as a bounded UTC timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`) with no external dependencies.
pub fn format_utc_timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Inverse of Howard Hinnant's `days_from_civil` (UTC, proleptic Gregorian).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::io;
    use std::path::PathBuf;

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tari-load-driver-mt-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // ---------------------------------------------------------------------
    // Mode resolution: ambiguity rejection, validation, no clearnet fallback.
    // ---------------------------------------------------------------------

    #[test]
    fn both_tor_inputs_are_rejected_as_ambiguous() {
        let error = resolve_tor_endpoint_mode_v1(
            Some(Path::new("/tmp/tor")),
            Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
        )
        .expect_err("both inputs must be ambiguous");
        assert!(error.contains("not both"), "{error}");
    }

    #[test]
    fn neither_tor_input_is_rejected() {
        assert!(resolve_tor_endpoint_mode_v1(None, None).is_err());
    }

    #[test]
    fn relative_tor_executable_is_rejected() {
        let error = resolve_tor_endpoint_mode_v1(Some(Path::new("tor.exe")), None)
            .expect_err("relative must reject");
        assert!(error.contains("absolute"), "{error}");
    }

    #[test]
    fn missing_tor_executable_is_rejected() {
        #[cfg(windows)]
        let bogus = PathBuf::from(r"C:\definitely\not\here\tor.exe");
        #[cfg(not(windows))]
        let bogus = PathBuf::from("/definitely/not/here/tor");
        let error = resolve_tor_endpoint_mode_v1(Some(bogus.as_path()), None)
            .expect_err("missing must reject");
        assert!(
            error.contains("not found") || error.contains("rejected"),
            "{error}"
        );
    }

    #[test]
    fn existing_socks_mode_is_preserved_for_loopback_endpoints() {
        let mode =
            resolve_tor_endpoint_mode_v1(None, Some(SocketAddr::from(([127, 0, 0, 1], 9050))))
                .expect("loopback socks accepted");
        assert_eq!(
            mode,
            TorEndpointModeV1::ExistingSocks {
                socks_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            }
        );
    }

    #[test]
    fn existing_socks_mode_rejects_non_loopback_endpoints() {
        // No clearnet fallback: a LAN/public address can never be accepted.
        for addr in [
            SocketAddr::from(([10, 0, 0, 5], 9050)),
            SocketAddr::from(([203, 0, 113, 7], 9050)),
            SocketAddr::from(([0, 0, 0, 0], 9050)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        ] {
            assert!(
                resolve_tor_endpoint_mode_v1(None, Some(addr)).is_err(),
                "{addr}"
            );
        }
    }

    #[test]
    fn managed_mode_requires_a_validated_executable() {
        let base = unique_test_dir("valid-exe");
        std::fs::create_dir_all(&base).expect("base");
        let exe = base.join("tor.exe");
        std::fs::write(&exe, b"not-a-real-tor").expect("write");
        let mode = resolve_tor_endpoint_mode_v1(Some(exe.as_path()), None).expect("valid exe");
        assert_eq!(mode, TorEndpointModeV1::Managed { tor_exe: exe });
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---------------------------------------------------------------------
    // Managed session: isolated endpoint + run directory, seam-driven start.
    // ---------------------------------------------------------------------

    /// Creates a fake but VALIDATED-shaped absolute executable file (the
    /// session tests never execute it; they inject fake spawners).
    fn fake_tor_executable(label: &str) -> PathBuf {
        let base = unique_test_dir(label);
        std::fs::create_dir_all(&base).expect("base");
        let exe = base.join("tor.exe");
        std::fs::write(&exe, b"not-a-real-tor").expect("write");
        exe
    }

    #[derive(Default)]
    struct FakeChild {
        exited: bool,
        killed: bool,
    }
    impl ManagedTorChildV1 for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(self.exited.then_some(1))
        }
        fn kill(&mut self) -> io::Result<()> {
            self.killed = true;
            Ok(())
        }
    }
    struct FakeSpawner {
        child: FakeChild,
    }
    impl ManagedTorSpawnerV1 for FakeSpawner {
        type Child = FakeChild;
        fn spawn(&self, _: &Path, _: &Path) -> io::Result<FakeChild> {
            Ok(FakeChild {
                exited: self.child.exited,
                killed: false,
            })
        }
    }
    struct FakeProbe(bool);
    impl ManagedTorReadinessProbeV1 for FakeProbe {
        fn ready(
            &mut self,
        ) -> Result<bool, tari_cc_private_ballot_transport_network::PrivateTransportNetworkErrorV1>
        {
            Ok(self.0)
        }
    }

    #[test]
    fn managed_session_uses_an_isolated_loopback_socks_endpoint_and_run_dir() {
        let exe = fake_tor_executable("session");
        let base = exe.parent().expect("parent").to_path_buf();
        let startup = ManagedTorStartupConfigV1::new(exe, base.clone());
        let mut probe = FakeProbe(true);
        let session = start_managed_tor_session_with_seams(
            &startup,
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut probe,
            || Duration::ZERO,
        )
        .expect("session starts");
        assert!(session.socks_addr().ip().is_loopback());
        assert_ne!(session.socks_addr().port(), 0, "never a fixed/zero port");
        let run_dir = session.run_dir().to_path_buf();
        assert!(run_dir.starts_with(&base), "isolated under the run base");
        assert!(
            run_dir
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("run-")),
            "fresh unique run directory"
        );
        drop(session);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn startup_failure_kills_the_attempted_child() {
        // Regression-shaped test: Tor spawns but never becomes ready. The
        // controller must kill the child it launched (no orphan), and the
        // start must fail closed — no SOCKS endpoint is ever reported ready.
        let exe = fake_tor_executable("startup-failure");
        let startup = ManagedTorStartupConfigV1 {
            tor_exe: exe,
            runtime_base: unique_test_dir("startup-failure-base"),
            startup_timeout: Duration::from_millis(50),
        };
        let kills = std::rc::Rc::new(std::cell::Cell::new(0_u32));
        struct KillObservingSpawner {
            kills: std::rc::Rc<std::cell::Cell<u32>>,
        }
        impl ManagedTorSpawnerV1 for KillObservingSpawner {
            type Child = KillObservingChild;
            fn spawn(&self, _: &Path, _: &Path) -> io::Result<KillObservingChild> {
                Ok(KillObservingChild {
                    kills: self.kills.clone(),
                })
            }
        }
        struct KillObservingChild {
            kills: std::rc::Rc<std::cell::Cell<u32>>,
        }
        impl ManagedTorChildV1 for KillObservingChild {
            fn try_wait(&mut self) -> io::Result<Option<i32>> {
                Ok(None)
            }
            fn kill(&mut self) -> io::Result<()> {
                self.kills.set(self.kills.get() + 1);
                Ok(())
            }
        }
        let mut probe = FakeProbe(false);
        let result = start_managed_tor_session_with_seams(
            &startup,
            &KillObservingSpawner {
                kills: kills.clone(),
            },
            &mut probe,
            || Duration::from_millis(100),
        );
        assert!(result.is_err(), "readiness timeout must fail the run");
        assert!(
            kills.get() >= 1,
            "startup failure must kill the attempted child (no orphan)"
        );
    }

    #[test]
    fn session_drop_and_shutdown_reap_the_owned_child() {
        // Submission failures, interrupts, and panics unwind through Drop; the
        // owned child must be killed in every case.
        let exe = fake_tor_executable("drop-reap");
        let startup = ManagedTorStartupConfigV1::new(exe, unique_test_dir("drop-reap-base"));
        let mut probe = FakeProbe(true);
        let session = start_managed_tor_session_with_seams(
            &startup,
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut probe,
            || Duration::ZERO,
        )
        .expect("session starts");
        drop(session);
    }

    #[test]
    fn managed_tor_config_is_isolated_and_client_only() {
        let base = unique_test_dir("config");
        std::fs::create_dir_all(&base).expect("base");
        let exe = base.join("tor.exe");
        std::fs::write(&exe, b"not-a-real-tor").expect("write");
        let run_dir = base.join("run-x");
        std::fs::create_dir_all(&run_dir).expect("run dir");
        let startup = ManagedTorStartupConfigV1::new(exe, base.clone());
        let config = managed_tor_config_for_run(&startup, &run_dir, 19_050).expect("config");
        assert_eq!(config.data_directory, run_dir.join("tor-data"));
        assert_eq!(config.config_file, run_dir.join("torrc"));
        assert_eq!(config.socks_port, 19_050);
        // The generated config is client-only: a loopback SOCKS listener and an
        // isolated data directory, no hidden service, no control port.
        config.write_config().expect("config writes");
        let torrc = std::fs::read_to_string(&config.config_file).expect("torrc");
        assert!(torrc.contains("SocksPort 127.0.0.1:19050"), "{torrc}");
        assert!(torrc.contains("ClientOnly 1"), "{torrc}");
        assert!(!torrc.contains("HiddenService"), "{torrc}");
        assert!(!torrc.contains("ControlPort"), "{torrc}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn managed_tor_config_rejects_zero_port() {
        let exe = fake_tor_executable("zero-port");
        let startup = ManagedTorStartupConfigV1::new(exe, unique_test_dir("zero-port-base"));
        assert!(managed_tor_config_for_run(&startup, Path::new("/tmp/run"), 0).is_err());
    }

    // ---------------------------------------------------------------------
    // Tor version capture parser (pure; no Tor binary needed).
    // ---------------------------------------------------------------------

    #[test]
    fn tor_version_line_parses_bounded_output() {
        assert_eq!(
            parse_tor_version_line("Tor version 0.4.8.12 (git-abc123).\n"),
            Some("Tor version 0.4.8.12 (git-abc123).".to_owned())
        );
        assert_eq!(parse_tor_version_line("\n\n"), None);
        assert_eq!(parse_tor_version_line("not tor output\n"), None);
        assert_eq!(parse_tor_version_line("Tor bad\u{0}version\n"), None);
        let long = format!("Tor {}\n", "x".repeat(500));
        let parsed = parse_tor_version_line(&long).expect("capped");
        assert!(parsed.chars().count() <= TOR_VERSION_MAX_CHARS + 1);
    }

    // ---------------------------------------------------------------------
    // Metadata: path derivation, timestamps, and secret omission.
    // ---------------------------------------------------------------------

    #[test]
    fn runtime_and_metadata_paths_derive_from_results_without_sharing_state() {
        let results = PathBuf::from("C:\\runs\\desktop\\results.json");
        let runtime = managed_runtime_base_for_results(&results);
        let metadata = managed_tor_metadata_path(&results);
        assert!(runtime.ends_with("results.managed-tor-runtime"));
        assert!(metadata.ends_with("results.managed-tor-metadata.json"));
        assert_ne!(runtime, metadata);
    }

    #[test]
    fn metadata_serialization_omits_secret_material() {
        let metadata = ManagedTorRunMetadataV1 {
            metadata_type: MANAGED_TOR_RUN_METADATA_TYPE_V1,
            tor_mode: "managed-tor",
            started_utc: "2026-09-03T00:00:00Z".to_owned(),
            finished_utc: "2026-09-03T00:05:00Z".to_owned(),
            socks_endpoint: "127.0.0.1:54321".to_owned(),
            onion_hostname: Some(
                "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".to_owned(),
            ),
            tor_executable_basename: Some("tor.exe".to_owned()),
            tor_version: Some("Tor version 0.4.8.12.".to_owned()),
            tor_run_directory_name: Some("run-0001".to_owned()),
            tor_process_stopped_by_runner: Some(true),
            elapsed_ms: 300_000,
        };
        let json = serde_json::to_string_pretty(&metadata).expect("serialize");
        let lower = json.to_lowercase();
        for marker in [
            "secret",
            "passphrase",
            "scalar",
            "private key",
            "private_key",
            "onion private",
            "auth cookie",
            "api key",
            "credential_bytes",
            "mnemonic",
        ] {
            assert!(!lower.contains(marker), "metadata leaked marker {marker}");
        }
        // The metadata records the executable basename, never the full path.
        assert!(
            !json.contains('\\'),
            "no absolute paths in metadata: {json}"
        );
    }

    #[test]
    fn utc_timestamp_formatting_is_stable() {
        assert_eq!(format_utc_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-09-03 00:00:00 UTC = 1788393600 seconds.
        let time = UNIX_EPOCH + Duration::from_secs(1_788_393_600);
        assert_eq!(format_utc_timestamp(time), "2026-09-03T00:00:00Z");
    }

    #[test]
    fn reserved_managed_port_is_loopback_and_fresh() {
        use std::net::TcpListener;
        let first = reserve_loopback_socks_port_v1().expect("reserve");
        assert_ne!(first, 0);
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, first))
            .expect("reserved port is re-bindable");
        drop(listener);
    }

    // ---------------------------------------------------------------------
    // OPTIONAL real-Tor smoke test (PART: real Tor bootstrap evidence).
    //
    // Non-destructive: runs ONLY if the operator exports
    //   PB_MANAGED_TOR_SMOKE_TOR_EXE=<absolute path to an installed tor.exe>
    // Uses an isolated temp DataDirectory, performs NO election submission,
    // NO voter credentials, NO organizer state change, and stops/reaps the
    // child it started. Never runs in CI; never downloads Tor.
    // ---------------------------------------------------------------------

    #[test]
    #[ignore = "operator-provided real Tor smoke test; set PB_MANAGED_TOR_SMOKE_TOR_EXE"]
    fn managed_tor_bootstrap_smoke_with_real_tor() {
        let Some(raw) = std::env::var_os("PB_MANAGED_TOR_SMOKE_TOR_EXE") else {
            eprintln!("skipped: PB_MANAGED_TOR_SMOKE_TOR_EXE is not set");
            return;
        };
        let tor_exe = PathBuf::from(raw);
        validate_tor_executable_v1(&tor_exe).expect("operator tor.exe must validate");
        let base = unique_test_dir("smoke");
        let startup = ManagedTorStartupConfigV1 {
            tor_exe: tor_exe.clone(),
            runtime_base: base.clone(),
            startup_timeout: MANAGED_TOR_STARTUP_TIMEOUT_V1,
        };
        let mut session = start_managed_tor_session(&startup)
            .expect("managed Tor must reach REAL SOCKS5 readiness");
        assert!(session.socks_addr().ip().is_loopback());
        assert_ne!(session.socks_addr().port(), 0);
        // Fresh readiness re-probe against the SAME endpoint (no carrier use).
        let mut probe = SystemManagedTorReadinessProbeV1::new(
            session.socks_addr(),
            SOCKS_PROBE_CONNECT,
            SOCKS_PROBE_HANDSHAKE,
        )
        .expect("probe");
        assert!(probe.ready().expect("probe ok"), "SOCKS must be ready NOW");
        session.shutdown();
        // Stopping is bounded and synchronous for the owned child (Child::kill
        // + controller shutdown); the disposable runtime is removed below.
        let _ = std::fs::remove_dir_all(&base);
    }
}
