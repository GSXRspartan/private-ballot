//! Controlled-test organizer intake binary.
//!
//! Compiled only under the `managed-tor-test` feature:
//!
//! ```text
//! cargo run -p tari-cc-private-ballot-transport-gateway `
//!     --features managed-tor-test --bin private-ballot-tor-test-intake -- `
//!     <manifest.cbor> <registry.cbor> <option-set.cbor> <tor.exe> <test-root>
//! ```
//!
//! It reuses the persisted organizer private bundle + hidden-service identity
//! produced by `private-ballot-tor-test-provision`, starts the loopback
//! collector, launches the owned `tor.exe`, verifies the persisted hostname
//! matches the signed descriptor, and enters the collector service loop.
//!
//! `--help` parses and exits without launching Tor.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tari_cc_private_ballot_gui_core::{
    GuiElectionArtifactsV1, GuiElectionSessionV1, ensure_private_intake_inbox_directory_v1,
};
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, LoadedOrganizerPrivateBundleV1, OrganizerCollectorServiceLoopV1,
    ThreadSafeCollectorHandlerV1, TransportGatewaySimulatorV1, load_organizer_private_bundle_v1,
    validate_intake_startup_v1,
};
use tari_cc_private_ballot_transport_network::{
    DiscoveryTimeoutV1, ManagedTorSpawnerV1, OrganizerHiddenServiceTorConfigV1,
    SystemManagedTorSpawnerV1, discover_organizer_onion_hostname_v1,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args
        .first()
        .map(String::as_str)
        .unwrap_or("private-ballot-tor-test-intake");
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help") {
        usage(prog);
        return ExitCode::SUCCESS;
    }
    if args.len() != 6 && args.len() != 7 {
        usage(prog);
        return ExitCode::from(2);
    }
    let manifest_path = Path::new(&args[1]);
    let registry_path = Path::new(&args[2]);
    let option_set_path = Path::new(&args[3]);
    let tor_executable = Path::new(&args[4]);
    let test_root = Path::new(&args[5]);
    // Optional 6th positional: the organizer GUI's app-data root. When supplied
    // (operator-local, never remote), accepted canonical ballot packages are
    // durably handed off into the app-owned, election-scoped inbox the GUI
    // ingests into its authoritative durable workspace.
    let app_data_root = args.get(6).map(PathBuf::from);

    if let Err(message) = run(
        manifest_path,
        registry_path,
        option_set_path,
        tor_executable,
        test_root,
        app_data_root.as_deref(),
    ) {
        eprintln!("intake failed: {message}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn usage(prog: &str) {
    eprintln!(
        "usage: {prog} <manifest.cbor> <registry.cbor> <option-set.cbor> <tor.exe> <test-root> [organizer-app-data-root]"
    );
    eprintln!();
    eprintln!("Controlled-test organizer intake. Reuses the persisted organizer");
    eprintln!("private bundle and hidden-service identity from <test-root>/organizer-private.");
    eprintln!("Starts the loopback collector, launches the owned tor.exe, verifies the");
    eprintln!("persisted onion hostname matches the signed descriptor, and accepts ballots.");
    eprintln!();
    eprintln!("  [organizer-app-data-root]  optional absolute path to the organizer GUI's");
    eprintln!("                             app-data directory. When given, each accepted");
    eprintln!("                             ballot is handed off into the app-owned durable");
    eprintln!("                             intake inbox the GUI ingests into its workspace.");
    eprintln!("  --help    show this help and exit (no Tor is launched)");
}

fn run(
    manifest_path: &Path,
    registry_path: &Path,
    option_set_path: &Path,
    tor_executable: &Path,
    test_root: &Path,
    app_data_root: Option<&Path>,
) -> Result<(), String> {
    // 1. Validate CLI inputs.
    validate_tor_executable(tor_executable)?;
    if !test_root.is_absolute() {
        return Err("the test-root-directory must be an absolute path".to_owned());
    }
    if let Some(root) = app_data_root {
        if !root.is_absolute() {
            return Err("the organizer app-data root must be an absolute path".to_owned());
        }
    }

    let organizer_private_dir = test_root.join("organizer-private");
    let tor_data_dir = test_root.join("organizer-tor-data");
    let hidden_service_dir = test_root.join("organizer-hidden-service");
    let torrc_path = test_root.join("organizer-intake-torrc");

    // 2. Load organizer private bundle.
    let bundle = load_organizer_private_bundle_v1(&organizer_private_dir)
        .map_err(|e| format!("organizer private bundle: {e}"))?;
    eprintln!("organizer private bundle loaded");

    // 3. Load election/workspace artifacts.
    let artifacts =
        GuiElectionArtifactsV1::from_paths(manifest_path, registry_path, option_set_path)
            .map_err(|e| format!("election artifacts: {}", e.code()))?;
    let election_title = artifacts
        .summary()
        .election_id_text
        .clone()
        .unwrap_or_else(|| artifacts.summary().election_id_hex.clone());

    // Resolve the app-owned, election-scoped durable hand-off inbox if the
    // operator supplied the organizer GUI app-data root. The election
    // sub-directory is derived from the manifest hash (never remote input), so
    // the intake process cannot be pointed at an arbitrary path by a voter.
    let accepted_package_inbox = match app_data_root {
        Some(root) => {
            let manifest_hash_hex = artifacts.summary().manifest_hash_hex.clone();
            let dir = ensure_private_intake_inbox_directory_v1(root, &manifest_hash_hex)
                .map_err(|e| format!("intake inbox: {}", e.code()))?;
            eprintln!("durable intake inbox: {}", dir.display());
            Some(dir)
        }
        None => {
            eprintln!(
                "durable intake inbox: (none — accepted ballots stay in-process; pass the organizer app-data root to hand off to the GUI workspace)"
            );
            None
        }
    };

    // 4. Read the persisted hidden-service hostname (if present).
    let hostname_file = hidden_service_dir.join("hostname");
    let persisted_hostname: Option<String> = match std::fs::read_to_string(&hostname_file) {
        Ok(content) => {
            let trimmed = content.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Err(_) => None,
    };

    // 5. Verify ALL key/descriptor/election bindings BEFORE any collector or Tor.
    validate_intake_startup_v1(&bundle, &artifacts, persisted_hostname.as_deref())
        .map_err(|e| format!("startup validation: {e}"))?;
    eprintln!("descriptor verified under test root");
    eprintln!("election: {election_title}");

    // 6. Open the election session for ballot intake.
    let mut session = GuiElectionSessionV1::new(artifacts.clone())
        .map_err(|e| format!("session: {}", e.code()))?;
    session
        .open()
        .map_err(|e| format!("open election: {}", e.code()))?;

    // 7. Bind collector to loopback ephemeral port. The listener is RETAINED
    // (kept bound) through the Tor startup + hostname verification phases so
    // the actual port is fixed in the torrc, but NO service loop is accepting
    // requests yet. A local caller cannot cause gateway intake during this
    // phase because no worker is servicing the listener.
    let collector =
        tari_cc_private_ballot_transport_gateway::OpaqueEnvelopeCollectorV1::bind_loopback_port(0)
            .map_err(|_| "could not bind the loopback collector".to_owned())?;
    let collector_addr = collector
        .local_addr()
        .map_err(|_| "could not read the collector address".to_owned())?;
    let collector_port = collector_addr.port();
    eprintln!("collector: {collector_addr}");

    // 8. Write the intake torrc with the ACTUAL collector port.
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: tor_data_dir.clone(),
        config_file: torrc_path.clone(),
        hidden_service_dir: hidden_service_dir.clone(),
        collector_port,
        startup_timeout: Duration::from_secs(90),
    };
    tor_config
        .write_config()
        .map_err(|_| "could not write the intake torrc".to_owned())?;

    // 9. Launch owned tor.exe child directly (argument vector, no shell).
    let mut child = SystemManagedTorSpawnerV1
        .spawn(tor_executable, &torrc_path)
        .map_err(|e| format!("could not start tor.exe: {e}"))?;
    eprintln!("tor: starting (pid may vary)");

    // 10. Verify child remains alive, then discover the runtime hostname.
    let mut child_alive = || {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    };
    if !child_alive() {
        // Collector listener is dropped on return (reaped implicitly). Never READY.
        return Err("tor.exe exited before the hidden service was published".to_owned());
    }

    let timeout = DiscoveryTimeoutV1::new(Duration::from_secs(90));
    let runtime_hostname =
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(e) => {
                let _ = child.kill();
                // Collector listener dropped on return. Never READY.
                return Err(format!("hostname discovery: {e}"));
            }
        };

    // 11. Critical: runtime hostname MUST equal the signed descriptor onion
    // BEFORE any ballot can be accepted. A mismatch fails closed: reap the Tor
    // child, drop the collector listener, and never print READY.
    let descriptor_onion = bundle
        .descriptor
        .onion_endpoints()
        .first()
        .ok_or_else(|| "descriptor has no onion endpoint".to_owned())?;
    if descriptor_onion != &runtime_hostname {
        let _ = child.kill();
        return Err(format!(
            "hidden-service hostname mismatch: descriptor={descriptor_onion} runtime={runtime_hostname}"
        ));
    }
    eprintln!("hidden service: {runtime_hostname}");

    // 12. ONLY NOW (after runtime onion equality) construct and start the
    // collector service loop using the already-bound collector. This is the
    // first point a ballot could be accepted.
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session_arc = Arc::new(Mutex::new(session));
    let descriptor_arc = Arc::new(bundle.descriptor.clone());
    let receiver_key_arc = reconstruct_receiver_key(&bundle)?;
    let receipt_key_arc = Arc::new(bundle.material.receipt_signing_key.clone());
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway.clone(),
        descriptor_arc,
        receiver_key_arc,
        session_arc,
        receipt_key_arc,
        "test-receipt-key".to_owned(),
    );
    let handler = match accepted_package_inbox {
        Some(inbox_dir) => handler.with_accepted_package_inbox(inbox_dir),
        None => handler,
    };
    let service_loop =
        OrganizerCollectorServiceLoopV1::start(collector, handler, Duration::from_millis(50))
            .map_err(|_| "could not start the collector service loop".to_owned())?;

    // 13. Verify the worker actually started (catches an inverted loop
    // condition or immediate worker exit). If the worker is already dead,
    // reap Tor and fail closed without ever printing READY.
    if !service_loop.worker_is_alive() {
        let _ = child.kill();
        let _ = service_loop.stop(Duration::from_secs(2));
        return Err("the collector service worker exited immediately on start".to_owned());
    }

    // 14. Print READY only after runtime onion equality AND a live worker.
    let accepted = service_loop.accepted_unique_count();
    eprintln!();
    eprintln!("Private Ballot controlled Tor intake");
    eprintln!("Election: {election_title}");
    eprintln!("Descriptor verified");
    eprintln!("Collector: {collector_addr}");
    eprintln!("Hidden service: {runtime_hostname}");
    eprintln!("Tor: running");
    eprintln!("Accepted ballots: {accepted}");
    eprintln!("PRIVATE INTAKE READY");
    eprintln!();

    // Ctrl+C handling: the simplest safe approach without adding a signal
    // dependency is to poll the stop flag on the service loop and child alive
    // in the main thread. A dedicated thread sets the flag on Ctrl+C via
    // the standard `ctrl_c` channel if available. We use a simple polling
    // loop: the main thread blocks on `child.wait()`, and on return stops
    // the collector.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();

    // Spawn a thin Ctrl+C handler using `std::thread` + a POSIX-like approach.
    // On Windows, Ctrl+C sends SIGBREAK to child processes automatically; we
    // also set our own flag. This is the smallest safe approach without a new
    // dependency.
    let _ctrl_thread = std::thread::Builder::new()
        .name("ctrl-c".to_owned())
        .spawn(move || {
            // Block on stdin or just sleep; on Ctrl+C the OS delivers to the
            // process group and child.wait() in the main thread returns.
            // We poll the stop flag as a backup.
            while !stop_for_handler.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
            }
        })
        .map_err(|_| "could not start ctrl-c handler".to_owned())?;

    // Wait for the Tor child to exit (Ctrl+C, kill, or crash) while reporting the
    // running accepted-ballot count LIVE, so the operator can tell when a ballot
    // has actually arrived (Issue 13). Per-request outcomes are ALSO printed so
    // the operator can tell, on the FIRST attempt, whether a request reached the
    // collector and what happened to it — including rejections that never change
    // the accepted count. Only safe aggregates and bounded stage labels are
    // printed — never plaintext votes, credential material, member index,
    // nullifier, proof, envelope bytes, receipt bytes, or any client/network
    // identity. The collector's HTTP response to the remote voter stays coarse;
    // this finer stage is LOCAL to the organizer terminal only.
    // Classification is driven by the SERVICED-REQUEST edge, and the
    // new-acceptance decision compares the accepted count against its value at
    // the PREVIOUS serviced edge (`accepted_at_last_serviced`) — never against a
    // separately-throttled print variable. This removes the earlier
    // observability race where the accepted count (incremented inside the intake
    // handler, before the worker bumps its serviced counter) could be reported
    // in an earlier poll than the serviced edge, so the first genuinely accepted
    // ballot was mislabelled "RECEIPT RETURNED (no new acceptance)". Both the
    // ACCEPTED/RECEIPT classification and the "Accepted ballots" line are now
    // emitted together on the serviced edge. Only safe aggregates and bounded
    // stage labels are printed — never plaintext votes, credential material,
    // member index, nullifier, proof, envelope bytes, receipt bytes, or any
    // client/network identity.
    let mut last_serviced = service_loop.serviced_request_count();
    let mut accepted_at_last_serviced = accepted;
    let mut last_printed_count = accepted;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break, // Tor child exited (Ctrl+C, kill, crash).
            Ok(None) => {}
        }
        let observation = service_loop.last_request_observation();
        let count = service_loop.accepted_unique_count();
        if observation.serviced_count != last_serviced {
            last_serviced = observation.serviced_count;
            // A strictly higher accepted count since the previous serviced edge
            // means THIS request added a new unique vote. An unchanged count with
            // a 200 receipt is an exact-retry recovery or an authenticated
            // rejection — never a second vote.
            let newly_accepted = count > accepted_at_last_serviced;
            accepted_at_last_serviced = count;
            eprintln!();
            eprintln!("Ballot request received");
            if observation.last_receipt_returned {
                if newly_accepted {
                    eprintln!("Result: ACCEPTED");
                } else {
                    eprintln!("Result: RECEIPT RETURNED (no new acceptance)");
                }
            } else {
                eprintln!("Result: REJECTED");
            }
            eprintln!("Stage: {}", observation.last_stage);
            if count != last_printed_count {
                last_printed_count = count;
                eprintln!("Accepted ballots: {count}");
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    stop.store(true, Ordering::Relaxed);

    // 15. Clean shutdown: stop collector, reap Tor child already exited. Print a
    // final aggregate summary (a duplicate/retried exact envelope never inflates
    // this count).
    let final_count = service_loop.accepted_unique_count();
    eprintln!("shutting down collector...");
    let _ = service_loop.stop(Duration::from_secs(3));
    eprintln!(
        "intake stopped (accepted ballots: {final_count}; hidden-service identity preserved)"
    );
    Ok(())
}

fn reconstruct_receiver_key(
    bundle: &LoadedOrganizerPrivateBundleV1,
) -> Result<Arc<GatewayReceiverKeyV1>, String> {
    let secret = bundle.material.gateway_receiver_key.secret_bytes();
    let key = GatewayReceiverKeyV1::from_secret_bytes(secret)
        .map_err(|_| "could not reconstruct the gateway receiver key".to_owned())?;
    Ok(Arc::new(key))
}

fn validate_tor_executable(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("the tor.exe path must be absolute".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("tor.exe: {e}"))?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err("tor.exe must be a regular file (no symlinks/reparse points)".to_owned());
    }
    if path
        .as_os_str()
        .to_string_lossy()
        .chars()
        .any(char::is_control)
    {
        return Err("tor.exe path must not contain control characters".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}
