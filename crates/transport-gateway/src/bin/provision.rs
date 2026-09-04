//! Controlled-test organizer provisioning binary.
//!
//! Compiled only under the `managed-tor` feature:
//!
//! ```text
//! cargo run -p tari-cc-private-ballot-transport-gateway `
//!     --features managed-tor --bin private-ballot-tor-test-provision -- `
//!     <manifest.cbor> <registry.cbor> <option-set.cbor> <tor.exe> <test-root>
//! ```
//!
//! It creates the organizer-side material and the voter public bundle for the
//! one-computer controlled Tor test:
//!
//!   1. loads the three canonical election artifacts;
//!   2. writes the organizer managed-Tor hidden-service torrc (virtual port 80
//!      → `127.0.0.1:<collector_port>`);
//!   3. starts the user-supplied absolute `tor.exe` directly (no shell);
//!   4. waits for the hidden-service hostname with a bounded timeout;
//!   5. stops tor.exe (the hostname is persistent in the HiddenServiceDir);
//!   6. signs a `TransportDescriptorV1` binding the discovered onion;
//!   7. writes the organizer PRIVATE bundle and the voter PUBLIC bundle.
//!
//! The actual ballot intake (collector + tor.exe) is a separate step the user
//! runs during the manual test (see docs/TOR_ONE_COMPUTER_TEST.md). No secret
//! is ever hard-coded, printed, or committed.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use tari_cc_private_ballot_gui_core::{GuiElectionArtifactsV1, TransportDescriptorV1};
use tari_cc_private_ballot_transport_gateway::{
    TransportElectionBindingV1, generate_transport_authority_material_v1, provision_organizer_transport_bundles_v1,
};
use tari_cc_private_ballot_transport_network::{
    DiscoveryTimeoutV1, ManagedTorSpawnerV1, OrganizerHiddenServiceTorConfigV1,
    SystemManagedTorSpawnerV1, discover_organizer_onion_hostname_v1,
};

/// The loopback collector port the hidden service forwards to. The runbook
/// starts the organizer collector on this exact port so the persistent torrc
/// remains valid across the discovery and intake phases.
const ORGANIZER_COLLECTOR_PORT: u16 = 18080;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args
        .first()
        .map(String::as_str)
        .unwrap_or("private-ballot-tor-test-provision");
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help") {
        usage(prog);
        return ExitCode::SUCCESS;
    }
    if args.len() != 6 {
        usage(prog);
        return ExitCode::from(2);
    }
    let manifest_path = Path::new(&args[1]);
    let registry_path = Path::new(&args[2]);
    let option_set_path = Path::new(&args[3]);
    let tor_executable = Path::new(&args[4]);
    let test_root = Path::new(&args[5]);

    if let Err(message) = run(
        manifest_path,
        registry_path,
        option_set_path,
        tor_executable,
        test_root,
    ) {
        eprintln!("provisioning failed: {message}");
        return ExitCode::from(1);
    }
    eprintln!("provisioning complete");
    ExitCode::SUCCESS
}

fn usage(prog: &str) {
    eprintln!(
        "usage: {prog} <manifest.cbor> <registry.cbor> <option-set.cbor> <tor.exe> <test-root>"
    );
    eprintln!();
    eprintln!("This binary starts the user-supplied tor.exe to discover the hidden-service");
    eprintln!("hostname, then stops it. Run it only for the controlled one-computer Tor test.");
    eprintln!();
    eprintln!("  --help    show this help and exit (no Tor is launched)");
}

fn run(
    manifest_path: &Path,
    registry_path: &Path,
    option_set_path: &Path,
    tor_executable: &Path,
    test_root: &Path,
) -> Result<(), String> {
    validate_tor_executable(tor_executable)?;
    if !test_root.is_absolute() {
        return Err("the test-root-directory must be an absolute path".to_owned());
    }
    std::fs::create_dir_all(test_root).map_err(|e| format!("test root: {e}"))?;
    let organizer_private_dir = test_root.join("organizer-private");
    let voter_public_bundle_path = test_root.join("voter-public-bundle.cbor");
    let tor_data_dir = test_root.join("organizer-tor-data");
    let hidden_service_dir = test_root.join("organizer-hidden-service");
    let torrc_path = test_root.join("organizer-torrc");
    std::fs::create_dir_all(&organizer_private_dir).map_err(|e| format!("organizer dir: {e}"))?;

    // 1. Load election artifacts so the descriptor binds the canonical manifest
    // hash and election id.
    let artifacts =
        GuiElectionArtifactsV1::from_paths(manifest_path, registry_path, option_set_path)
            .map_err(|e| format!("election artifacts: {}", e.code()))?;
    let binding = TransportElectionBindingV1 {
        election_id: artifacts.manifest().election_id().as_bytes().to_vec(),
        manifest_hash: *artifacts.manifest_hash().as_bytes(),
    };

    // 2. Write the organizer hidden-service torrc.
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: tor_data_dir.clone(),
        config_file: torrc_path.clone(),
        hidden_service_dir: hidden_service_dir.clone(),
        collector_port: ORGANIZER_COLLECTOR_PORT,
        startup_timeout: Duration::from_secs(90),
    };
    tor_config
        .write_config()
        .map_err(|_| "could not write the organizer torrc".to_owned())?;
    eprintln!("organizer torrc written to {}", torrc_path.display());

    // 3. Start tor.exe directly (argument vector, no shell) with the HS torrc.
    let mut child = SystemManagedTorSpawnerV1
        .spawn(tor_executable, &torrc_path)
        .map_err(|e| format!("could not start tor.exe: {e}"))?;
    eprintln!("tor.exe started; discovering hidden-service hostname...");

    // 4. Wait for the hostname file (bounded), checking the child is still alive.
    let timeout = DiscoveryTimeoutV1::new(Duration::from_secs(90));
    let child_alive = || {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    };
    let hostname = discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive)
        .map_err(|e| {
            // Best-effort cleanup before surfacing the error.
            let _ = child.kill();
            format!("hostname discovery: {e}")
        })?;
    eprintln!("organizer hidden service: {hostname}");

    // 5. Stop tor.exe. The hostname is persistent in the HiddenServiceDir.
    let _ = child.kill();
    let _ = child.wait();
    eprintln!("tor.exe stopped (hostname is persistent for the intake phase).");

    // 6. Sign the descriptor and write both bundles.
    let descriptor: TransportDescriptorV1 = provision_organizer_transport_bundles_v1(
        &organizer_private_dir,
        &voter_public_bundle_path,
        &generate_transport_authority_material_v1("test-root".to_owned())
            .map_err(|_| "could not generate test authority material".to_owned())?,
        &binding,
        hostname,
        &tor_data_dir,
        &hidden_service_dir,
    )
    .map_err(|e| format!("bundle provisioning: {e}"))?;

    eprintln!(
        "descriptor fingerprint: {}",
        hex_lower(
            &descriptor
                .fingerprint()
                .map_err(|_| "fingerprint".to_owned())?
        )
    );
    eprintln!(
        "organizer private bundle: {}",
        organizer_private_dir.display()
    );
    eprintln!(
        "voter public bundle: {}",
        voter_public_bundle_path.display()
    );
    eprintln!();
    eprintln!("Next: start the organizer intake (see docs/TOR_ONE_COMPUTER_TEST.md):");
    eprintln!("  1. start the loopback collector on 127.0.0.1:{ORGANIZER_COLLECTOR_PORT}");
    eprintln!(
        "  2. run: \"{}\" -f \"{}\"",
        tor_executable.display(),
        torrc_path.display()
    );
    Ok(())
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

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
