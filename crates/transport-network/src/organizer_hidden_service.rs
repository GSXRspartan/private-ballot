//! Organizer-side managed Tor hidden-service configuration and hostname
//! discovery.
//!
//! This produces the organizer torrc that exposes the loopback opaque-envelope
//! collector as a Tor v3 hidden service. It is the organizer counterpart to the
//! client [`ManagedTorConfigV1`]: the organizer runs Tor with `SocksPort 0`
//! (no client SOCKS listener) and a `HiddenServicePort` mapping the fixed
//! protocol virtual port [`ONION_VIRTUAL_PORT_V1`] (80) to the loopback
//! collector `127.0.0.1:<collector_port>`.
//!
//! Hard invariants enforced here:
//!
//!   * every path is absolute and contains no control characters (reusing the
//!     existing safe path-token serializer, which also rejects embedded `"`,
//!     CR, and LF so no torrc-line injection is possible, and doubles every
//!     backslash so Windows paths survive Tor's quoted-string escape parser);
//!   * the collector target is always an IP loopback literal with a non-zero
//!     port — never `0.0.0.0`, a LAN address, or a public IP;
//!   * the hidden-service virtual port is the fixed protocol constant, so it
//!     can never disagree with the verified descriptor;
//!   * the generated config contains no ControlPort, no non-loopback listener,
//!     no DNSPort, and no transparent-proxy directive.
//!
//! Hostname discovery waits for Tor to write `<HiddenServiceDir>\hostname`,
//! validates it is a regular bounded file, trims only the expected line
//! ending, and strictly validates the onion hostname with the existing
//! validator. It never treats hostname-file existence alone as proof of global
//! reachability — only proof that Tor created the service identity.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    ONION_VIRTUAL_PORT_V1, PrivateTransportNetworkErrorV1, has_control_path_component,
    tor_path_token, validate_onion_hostname_v1, write_atomic,
};

/// Bounded maximum size of the `hostname` file. The canonical Tor v3 hostname
/// is exactly 62 ASCII bytes plus one trailing line ending (63 bytes). We
/// accept up to a small bound and reject anything larger as non-canonical.
const MAX_HOSTNAME_FILE_BYTES: u64 = 256;

/// Fixed application-owned inputs for an organizer managed Tor process that
/// publishes a v3 hidden service fronting the loopback collector.
///
/// No caller can add arbitrary Tor command-line fragments or config lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizerHiddenServiceTorConfigV1 {
    /// Absolute path to an already-installed `tor.exe`.
    pub executable: PathBuf,
    /// Tor `DataDirectory` (organizer private runtime; never inside the repo).
    pub data_directory: PathBuf,
    /// Absolute path of the torrc file this config writes.
    pub config_file: PathBuf,
    /// Tor `HiddenServiceDir` (where Tor writes the private key + `hostname`).
    pub hidden_service_dir: PathBuf,
    /// Loopback collector TCP port the hidden service forwards to.
    pub collector_port: u16,
    /// Bounded startup timeout for hostname discovery.
    pub startup_timeout: Duration,
}

impl OrganizerHiddenServiceTorConfigV1 {
    /// Validates every field. The collector target is structurally loopback
    /// because the generated config only ever writes the literal
    /// `127.0.0.1:<collector_port>`; the port being non-zero is enforced here.
    pub fn validate(&self) -> Result<(), PrivateTransportNetworkErrorV1> {
        if !self.executable.is_absolute()
            || !self.data_directory.is_absolute()
            || !self.config_file.is_absolute()
            || !self.hidden_service_dir.is_absolute()
            || self.collector_port == 0
            || self.startup_timeout.is_zero()
            || has_control_path_component(&self.executable)
            || has_control_path_component(&self.data_directory)
            || has_control_path_component(&self.config_file)
            || has_control_path_component(&self.hidden_service_dir)
        {
            return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    /// Generates only the static, application-owned Tor configuration. The
    /// caller never supplies raw config lines or process arguments. The
    /// generated torrc contains exactly:
    ///
    /// ```text
    /// SocksPort 0
    /// DataDirectory "<data_directory>"
    /// HiddenServiceDir "<hidden_service_dir>"
    /// HiddenServiceVersion 3
    /// HiddenServicePort 80 127.0.0.1:<collector_port>
    /// ```
    ///
    /// There is no ControlPort, no non-loopback listener, no DNSPort, and no
    /// transparent-proxy directive. The hidden-service virtual port is the
    /// fixed protocol constant [`ONION_VIRTUAL_PORT_V1`].
    pub fn write_config(&self) -> Result<(), PrivateTransportNetworkErrorV1> {
        self.validate()?;
        fs::create_dir_all(&self.data_directory)
            .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
        fs::create_dir_all(&self.hidden_service_dir)
            .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
        let body = format!(
            "SocksPort 0\n\
             DataDirectory {data}\n\
             HiddenServiceDir {hsd}\n\
             HiddenServiceVersion 3\n\
             HiddenServicePort {virt} 127.0.0.1:{port}\n",
            data = tor_path_token(&self.data_directory)?,
            hsd = tor_path_token(&self.hidden_service_dir)?,
            virt = ONION_VIRTUAL_PORT_V1,
            port = self.collector_port,
        );
        write_atomic(&self.config_file, body.as_bytes())
    }

    /// Returns the expected `hostname` file path Tor writes inside the
    /// hidden-service directory.
    #[must_use]
    pub fn hostname_file(&self) -> PathBuf {
        self.hidden_service_dir.join("hostname")
    }
}

/// Why hostname discovery could not return a valid onion hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameDiscoveryErrorV1 {
    /// The configured paths are invalid.
    InvalidConfiguration,
    /// The bounded discovery timeout elapsed before a valid hostname appeared.
    Timeout,
    /// The managed Tor child exited before the hostname file appeared.
    ProcessExited,
    /// The hostname file is missing, indirected, oversized, or not a regular file.
    UnsafeFile,
    /// The file content is not exactly one canonical Tor v3 onion hostname.
    InvalidHostname,
}

impl std::fmt::Display for HostnameDiscoveryErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "organizer hidden-service configuration is invalid",
            Self::Timeout => "timed out waiting for the organizer hidden-service hostname",
            Self::ProcessExited => {
                "the managed Tor process exited before publishing the hidden service"
            }
            Self::UnsafeFile => "the hidden-service hostname file is missing or unsafe",
            Self::InvalidHostname => {
                "the hidden-service hostname is not a valid Tor v3 onion address"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for HostnameDiscoveryErrorV1 {}

/// Bounded timeout for hostname discovery. Kept separate from the controller's
/// startup timeout so a test can inject a fake clock without touching process
/// lifecycle. `remaining()` returns `None` once the budget is spent.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryTimeoutV1 {
    deadline: Instant,
}

impl DiscoveryTimeoutV1 {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
        }
    }

    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.remaining().is_none()
    }
}

/// Waits for Tor to publish the hidden-service hostname, then returns the
/// single validated Tor v3 onion address.
///
/// Requirements enforced:
///   * the config is valid before any polling;
///   * `process_alive` is polled each iteration — an early Tor exit is
///     surfaced as [`HostnameDiscoveryErrorV1::ProcessExited`];
///   * the `hostname` file must be a regular file (no symlink/reparse point
///     where the existing `symlink_metadata` helper can enforce it), bounded
///     in size, and non-empty;
///   * only the single trailing line ending (`\n` or `\r\n`) is trimmed —
///     any additional line or trailing whitespace is rejected;
///   * the trimmed value is strictly validated with the existing
///     [`validate_onion_hostname_v1`].
///
/// This never resolves DNS, never opens a network connection, and never reads
/// the hidden-service private key. It only reads the public `hostname` file
/// Tor writes.
pub fn discover_organizer_onion_hostname_v1(
    config: &OrganizerHiddenServiceTorConfigV1,
    timeout: &DiscoveryTimeoutV1,
    mut process_alive: impl FnMut() -> bool,
) -> Result<String, HostnameDiscoveryErrorV1> {
    config
        .validate()
        .map_err(|_| HostnameDiscoveryErrorV1::InvalidConfiguration)?;
    let hostname_path = config.hostname_file();
    loop {
        if !process_alive() {
            return Err(HostnameDiscoveryErrorV1::ProcessExited);
        }
        if timeout.is_expired() {
            return Err(HostnameDiscoveryErrorV1::Timeout);
        }
        match read_hostname_file(&hostname_path) {
            Ok(Some(raw)) => {
                let trimmed = trim_single_line_ending(&raw)?;
                validate_onion_hostname_v1(trimmed)
                    .map_err(|_| HostnameDiscoveryErrorV1::InvalidHostname)?;
                return Ok(trimmed.to_owned());
            }
            Ok(None) => {}
            Err(_) => return Err(HostnameDiscoveryErrorV1::UnsafeFile),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Reads the hostname file if it exists and is a safe regular bounded file.
/// Returns `Ok(None)` when the file does not exist yet (Tor has not written it).
fn read_hostname_file(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_HOSTNAME_FILE_BYTES
    {
        return Err(());
    }
    fs::read(path).map(Some).map_err(|_| ())
}

/// Accepts exactly one canonical Tor v3 hostname optionally followed by a
/// single `\n` or `\r\n` line ending. Anything else (multiple lines, trailing
/// whitespace, embedded NUL/control bytes) is rejected.
fn trim_single_line_ending(raw: &[u8]) -> Result<&str, HostnameDiscoveryErrorV1> {
    let stripped = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    if stripped.is_empty() || stripped.len() > MAX_HOSTNAME_FILE_BYTES as usize {
        return Err(HostnameDiscoveryErrorV1::InvalidHostname);
    }
    // Reject any embedded NUL, control character, or additional line.
    if stripped
        .iter()
        .any(|byte| *byte == 0 || (*byte < 0x20 && *byte != b'\t'))
    {
        return Err(HostnameDiscoveryErrorV1::InvalidHostname);
    }
    std::str::from_utf8(stripped).map_err(|_| HostnameDiscoveryErrorV1::InvalidHostname)
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn base_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tari-private-ballot-organizer-hs-test-{}",
            std::process::id()
        ))
    }

    fn unique_dir(label: &str) -> PathBuf {
        let dir = base_dir().join(label);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        dir
    }

    fn valid_config(dir: &Path, spaces: bool) -> OrganizerHiddenServiceTorConfigV1 {
        let data_dir = if spaces {
            dir.join("with spaces").join("tor data")
        } else {
            dir.join("tor-data")
        };
        OrganizerHiddenServiceTorConfigV1 {
            executable: dir.join("tor.exe"),
            data_directory: data_dir,
            config_file: dir.join("torrc"),
            hidden_service_dir: dir.join("hs-dir"),
            collector_port: 18080,
            startup_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn validate_rejects_non_absolute_paths_and_zero_port() {
        let dir = unique_dir("validate");
        let mut config = valid_config(&dir, false);
        config.executable = PathBuf::from("relative/tor.exe");
        assert!(config.validate().is_err());
        let mut config = valid_config(&dir, false);
        config.collector_port = 0;
        assert!(config.validate().is_err());
        let mut config = valid_config(&dir, false);
        config.startup_timeout = Duration::ZERO;
        assert!(config.validate().is_err());
    }

    #[test]
    fn write_config_produces_exact_loopback_hidden_service_lines() {
        let dir = unique_dir("write-config");
        let config = valid_config(&dir, false);
        config.write_config().expect("config writes");
        let torrc = std::fs::read_to_string(dir.join("torrc")).expect("read torrc");
        assert!(torrc.contains("SocksPort 0\n"));
        assert!(torrc.contains("HiddenServiceVersion 3\n"));
        assert!(torrc.contains("HiddenServicePort 80 127.0.0.1:18080\n"));
        assert!(!torrc.contains("ControlPort"));
        assert!(!torrc.contains("DNSPort"));
        assert!(!torrc.contains("0.0.0.0"));
        assert!(!torrc.contains("TransPort"));
        assert!(!torrc.contains("SocksPort 9050"));
    }

    #[test]
    fn write_config_safely_handles_paths_containing_spaces() {
        let dir = unique_dir("spaces");
        let config = valid_config(&dir, true);
        config.write_config().expect("config with spaces writes");
        let torrc = std::fs::read_to_string(dir.join("torrc")).expect("read torrc");
        // A path with spaces is quoted as one token; no line break is injected.
        assert!(torrc.contains("\""));
        assert!(torrc.contains("with spaces"));
        assert_eq!(torrc.matches('\n').count(), 5);
        // Windows regression guard: the emitted DataDirectory and HiddenServiceDir
        // lines must contain Tor-escaped (doubled) backslashes and must never
        // regress to the raw single-backslash form.
        #[cfg(windows)]
        {
            let data_dir = config.data_directory.to_string_lossy().into_owned();
            let hsd = config.hidden_service_dir.to_string_lossy().into_owned();
            let escaped_data = data_dir.replace('\\', r"\\");
            let escaped_hsd = hsd.replace('\\', r"\\");
            assert!(
                torrc.contains(&format!("DataDirectory \"{escaped_data}\"")),
                "DataDirectory must contain doubled backslashes on Windows: {torrc}"
            );
            assert!(
                torrc.contains(&format!("HiddenServiceDir \"{escaped_hsd}\"")),
                "HiddenServiceDir must contain doubled backslashes on Windows: {torrc}"
            );
            assert!(
                !torrc.contains(&format!("DataDirectory \"{data_dir}\"")),
                "DataDirectory regressed to raw unescaped backslashes on Windows: {torrc}"
            );
            assert!(
                !torrc.contains(&format!("HiddenServiceDir \"{hsd}\"")),
                "HiddenServiceDir regressed to raw unescaped backslashes on Windows: {torrc}"
            );
        }
    }

    #[test]
    fn write_config_rejects_newline_injection_in_paths() {
        let dir = unique_dir("inject");
        let mut config = valid_config(&dir, false);
        config.data_directory = dir.join("evil\nSocksPort 9050");
        assert!(config.write_config().is_err());
        let mut config = valid_config(&dir, false);
        config.hidden_service_dir = dir.join("bad\r\nControlPort 9051");
        assert!(config.write_config().is_err());
        let mut config = valid_config(&dir, false);
        config.data_directory = dir.join("quote\"injection");
        assert!(config.write_config().is_err());
    }

    #[test]
    fn write_config_rejects_control_characters_in_executable_path() {
        let dir = unique_dir("control-char");
        let mut config = valid_config(&dir, false);
        config.executable = dir.join("tor\x01.exe");
        assert!(config.write_config().is_err());
    }

    #[test]
    fn collector_target_is_loopback_only_by_construction() {
        let dir = unique_dir("loopback");
        let config = valid_config(&dir, false);
        config.write_config().expect("writes");
        let torrc = std::fs::read_to_string(dir.join("torrc")).expect("read");
        // The only address literal in the HiddenServicePort line is 127.0.0.1.
        assert!(torrc.contains("127.0.0.1:18080"));
        // No loopback alternative could be configured via the struct.
        let _addr = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, config.collector_port));
    }

    #[test]
    fn discover_hostname_accepts_valid_canonical_file() {
        let dir = unique_dir("discover-ok");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        let good = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        std::fs::write(hs_dir.join("hostname"), format!("{good}\n")).expect("write hostname");
        let timeout = DiscoveryTimeoutV1::new(Duration::from_secs(2));
        let found =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect("hostname");
        assert_eq!(found, good);
    }

    #[test]
    fn discover_hostname_accepts_crlf_line_ending() {
        let dir = unique_dir("discover-crlf");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        let good = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        std::fs::write(hs_dir.join("hostname"), format!("{good}\r\n")).expect("write hostname");
        let timeout = DiscoveryTimeoutV1::new(Duration::from_secs(2));
        let found =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect("hostname");
        assert_eq!(found, good);
    }

    #[test]
    fn discover_hostname_rejects_invalid_onion() {
        let dir = unique_dir("discover-invalid");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        std::fs::write(hs_dir.join("hostname"), b"example.com\n").expect("write hostname");
        let timeout = DiscoveryTimeoutV1::new(Duration::from_millis(50));
        let error =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect_err("reject");
        assert_eq!(error, HostnameDiscoveryErrorV1::InvalidHostname);
    }

    #[test]
    fn discover_hostname_rejects_multiple_lines() {
        let dir = unique_dir("discover-multiline");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        let good = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        std::fs::write(hs_dir.join("hostname"), format!("{good}\nextra\n")).expect("write");
        let timeout = DiscoveryTimeoutV1::new(Duration::from_millis(50));
        let error =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect_err("reject");
        assert_eq!(error, HostnameDiscoveryErrorV1::InvalidHostname);
    }

    #[test]
    fn discover_hostname_rejects_oversized_file() {
        let dir = unique_dir("discover-oversize");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        std::fs::write(hs_dir.join("hostname"), vec![b'a'; 512]).expect("write");
        let timeout = DiscoveryTimeoutV1::new(Duration::from_millis(50));
        let error =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect_err("reject");
        assert_eq!(error, HostnameDiscoveryErrorV1::UnsafeFile);
    }

    #[test]
    fn discover_hostname_reports_process_exit() {
        let dir = unique_dir("discover-exit");
        let config = valid_config(&dir, false);
        let timeout = DiscoveryTimeoutV1::new(Duration::from_secs(5));
        let error =
            discover_organizer_onion_hostname_v1(&config, &timeout, || false).expect_err("exit");
        assert_eq!(error, HostnameDiscoveryErrorV1::ProcessExited);
    }

    #[test]
    fn discover_hostname_times_out_when_file_never_appears() {
        let dir = unique_dir("discover-timeout");
        let config = valid_config(&dir, false);
        // hostname file is never written; process stays alive.
        let timeout = DiscoveryTimeoutV1::new(Duration::from_millis(150));
        let error =
            discover_organizer_onion_hostname_v1(&config, &timeout, || true).expect_err("timeout");
        assert_eq!(error, HostnameDiscoveryErrorV1::Timeout);
    }

    #[test]
    fn discover_hostname_rejects_symlink_hostname_file() {
        let dir = unique_dir("discover-symlink");
        let config = valid_config(&dir, false);
        let hs_dir = dir.join("hs-dir");
        std::fs::create_dir_all(&hs_dir).expect("hs dir");
        let good = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        let real = hs_dir.join("real-hostname");
        std::fs::write(&real, format!("{good}\n")).expect("write real");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, hs_dir.join("hostname")).expect("symlink");
        }
        #[cfg(windows)]
        {
            // On Windows a symlink requires privileges; instead prove a
            // non-regular file (a directory named `hostname`) is rejected.
            std::fs::create_dir_all(hs_dir.join("hostname")).expect("dir as hostname");
        }
        let timeout = DiscoveryTimeoutV1::new(Duration::from_millis(50));
        let result = discover_organizer_onion_hostname_v1(&config, &timeout, || true);
        assert!(result.is_err(), "non-regular hostname must be rejected");
    }
}
