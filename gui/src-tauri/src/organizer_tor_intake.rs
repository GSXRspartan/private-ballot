//! Organizer near-one-click private ballot intake (feature-gated).
//!
//! Compiled only under the `managed-tor` feature. This is the in-process
//! GUI equivalent of the controlled-test `private-ballot-tor-test-provision`
//! and `private-ballot-tor-test-intake` binaries: it runs the SAME reviewed
//! library orchestration on a Tauri-managed background worker so a ballot-office
//! operator never needs PowerShell, cargo, a torrc, a SOCKS/collector port, a
//! hidden-service key directory, a descriptor fingerprint, an onion hostname, or
//! an app-data-root lookup.
//!
//! It duplicates NO Tor descriptor construction, cryptographic validation,
//! ballot validation, receipt logic, or nullifier enforcement: every one of
//! those is a call into the already-reviewed transport-gateway / transport-
//! network / gui-core functions. It never spawns PowerShell, never invokes
//! cargo, and never constructs a shell command string (Tor is launched by the
//! reviewed `SystemManagedTorSpawnerV1`, an argument-vector spawn).
//!
//! Authoritative-writer boundary (unchanged): the in-process intake worker keeps
//! its OWN `GuiElectionSessionV1` (exactly like the binary) and hands accepted
//! canonical ballot-package bytes to the app-owned, election-scoped durable
//! inbox. The organizer GUI session remains the ONLY authoritative election
//! writer; it ingests the inbox through `sync_private_intake`.
//!
//! Fail-closed startup ordering (identical to the vetted binary): the collector
//! listener is bound but NOT serviced until the runtime onion hostname equals
//! the signed descriptor onion; the service loop worker is only started after
//! that equality; READY is reported only after the worker is confirmed alive.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_archive::TransportArchiveBindingV1;
use tari_cc_private_ballot_gui_core::{
    AuthoritativeLifecycleFenceV1, ElectionLifecycleStateV1, GuiElectionArtifactsV1,
    GuiElectionSessionV1, TransportDescriptorV1, ensure_private_intake_inbox_directory_v1,
    ensure_voter_election_status_directory_v1, private_intake_inbox_directory_v1,
    read_accepted_package_digests_v1, read_issued_status_generation_v1,
    reserve_next_status_generation_v1,
};
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, LoadedOrganizerPrivateBundleV1, OpaqueEnvelopeCollectorV1,
    OrganizerCollectorServiceLoopV1, TransportElectionBindingV1, ThreadSafeCollectorHandlerV1,
    TransportGatewaySimulatorV1, finalized_transport_archive_binding_from_accepted_digests_v1,
    generate_transport_authority_material_v1, load_organizer_private_bundle_v1,
    provision_organizer_transport_bundles_v1, validate_intake_startup_v1,
};
use tari_cc_private_ballot_transport_network::{
    DiscoveryTimeoutV1, ManagedTorSpawnerV1, OrganizerHiddenServiceTorConfigV1,
    RemoteSocksEndpointErrorV1, RemoteSocksEndpointV1, RemoteTorReadinessOutcomeV1,
    TorCarrierTimeoutsV1, discover_organizer_onion_hostname_v1,
    fetch_election_status_over_remote_tor_onion, probe_remote_onion_hostname_v1,
    validate_onion_hostname_v1,
};
use tauri::{AppHandle, Manager};

use crate::managed_tor::{
    DiagnosticTorSpawnerV1, classify_start_failure_from_log, fresh_run_directory,
    remove_stale_run_directories,
};
use crate::tor_support::{is_windows_reparse_point, resolve_tor_executable, validate_tor_exe};
use crate::{AppState, CommandError};

/// Backend-controlled directory name for app-owned organizer transport state.
const ORGANIZER_TOR_ROOT_DIRECTORY_NAME: &str = "private-tor";
/// Length in characters of a canonical lowercase Blake3 manifest-hash hex.
const MANIFEST_HASH_HEX_LEN: usize = 64;
/// Fixed loopback collector port used only while discovering the persistent
/// hidden-service hostname during first-time provisioning. No live collector is
/// serviced during that phase; the real intake collector uses an ephemeral port.
const PROVISION_COLLECTOR_PORT: u16 = 18080;
/// Bounded Tor startup / hostname-discovery timeout.
const TOR_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
/// Collector worker accept poll interval (bounds shutdown latency).
const COLLECTOR_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Bounded collector shutdown join budget.
const COLLECTOR_STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Which Tor hosting mode the ORGANIZER intake uses. `ManagedLocal` is the
/// default and recommended mode (this application starts, owns, and stops the
/// local Tor process that hosts the hidden service); `ExternalRemote` is the
/// advanced, opt-in mode (an EXTERNALLY managed Tor instance on another machine
/// already hosts the organizer onion service — this application never spawns,
/// owns, or stops it, and never creates a local hidden-service directory).
///
/// A missing/legacy persisted value resolves to [`Self::ManagedLocal`]; an
/// unknown or malformed token also resolves to [`Self::ManagedLocal`] (fail
/// SAFE toward the recommended, process-owned path — never silently toward the
/// advanced remote path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrganizerTorModeV1 {
    /// Default. The application owns the Tor process and the hidden-service
    /// directory (existing managed-organizer-Tor behaviour).
    #[default]
    ManagedLocal,
    /// Advanced/opt-in. The onion service is provisioned and hosted by an
    /// externally managed Tor instance; this application only validates the
    /// remote route and runs the collector it forwards to.
    ExternalRemote,
}

impl OrganizerTorModeV1 {
    /// Stable wire/persistence token, matching the repository's kebab-token
    /// conventions (`TorTransportModeV1`).
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::ManagedLocal => "managed-local",
            Self::ExternalRemote => "external-remote",
        }
    }

    /// Parses a persisted/UI token. Unknown/empty/legacy values resolve to the
    /// recommended managed-local default — never silently to remote.
    #[must_use]
    pub fn from_token_or_default(token: &str) -> Self {
        match token {
            "external-remote" => Self::ExternalRemote,
            _ => Self::ManagedLocal,
        }
    }
}

/// Serializable external-remote intake configuration supplied by the operator
/// (Advanced UI). All fields are non-secret: a SOCKS endpoint and a public
/// onion hostname are not credentials.
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteOrganizerIntakeInputV1 {
    /// Transport-mode token. Only `"external-remote"` selects remote hosting;
    /// anything else resolves to managed-local (fail safe).
    #[serde(default)]
    pub tor_mode: Option<String>,
    /// Externally managed Tor SOCKS proxy host (IPv4/IPv6/hostname).
    #[serde(default)]
    pub socks_host: Option<String>,
    /// Externally managed Tor SOCKS proxy port (1..=65535).
    #[serde(default)]
    pub socks_port: Option<u16>,
    /// The organizer onion hostname the EXTERNAL Tor instance hosts. It must be
    /// a valid Tor v3 onion and MUST equal the signed descriptor onion.
    #[serde(default)]
    pub onion_hostname: Option<String>,
    /// The fixed loopback collector port the remote Tor's `HiddenServicePort`
    /// forwards to. Modeled explicitly because a remote operator must be able
    /// to configure `HiddenServicePort 80 <this-host>:<port>` BEFORE intake
    /// starts; the managed mode's ephemeral port is invisible to them.
    #[serde(default)]
    pub collector_port: Option<u16>,
}

/// A fully validated external-remote organizer intake configuration. Every
/// field is re-validated here regardless of the frontend; a malformed value
/// fails closed with a bounded, specific error before ANY state is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOrganizerIntakeConfigV1 {
    /// Validated remote SOCKS endpoint (used ONLY for readiness probing —
    /// never for hosting, and never treated as an owned process).
    pub socks: RemoteSocksEndpointV1,
    /// Validated Tor v3 organizer onion hostname.
    pub onion_hostname: String,
    /// Non-zero loopback collector port for the remote `HiddenServicePort`.
    pub collector_port: u16,
}

impl RemoteOrganizerIntakeConfigV1 {
    /// Parses and validates the operator input. Ordering: mode token first
    /// (fail safe to managed-local), then each field with a bounded, specific
    /// error that never echoes the raw value.
    pub fn from_input(
        input: &RemoteOrganizerIntakeInputV1,
    ) -> Result<Option<Self>, CommandError> {
        let mode = OrganizerTorModeV1::from_token_or_default(
            input.tor_mode.as_deref().unwrap_or("").trim(),
        );
        if mode != OrganizerTorModeV1::ExternalRemote {
            return Ok(None);
        }
        let host = input.socks_host.as_deref().unwrap_or("").trim();
        let socks_port = input.socks_port.unwrap_or(0);
        let endpoint = if host.is_empty() {
            return Err(remote_config_error(
                "enter the remote SOCKS proxy host for the external remote Tor mode",
            ));
        } else {
            RemoteSocksEndpointV1::from_parts(host, socks_port).map_err(|error| {
                remote_config_error(match error {
                    RemoteSocksEndpointErrorV1::InvalidPort => {
                        "the remote SOCKS port must be a number between 1 and 65535"
                    }
                    RemoteSocksEndpointErrorV1::EmptyHost => {
                        "the remote SOCKS host must not be empty"
                    }
                    _ => {
                        "the remote SOCKS endpoint must be a bare host:port (no scheme, path, or credentials)"
                    }
                })
            })?
        };
        let onion = input.onion_hostname.as_deref().unwrap_or("").trim();
        if onion.is_empty() {
            return Err(remote_config_error(
                "enter the organizer onion hostname hosted by the external Tor instance",
            ));
        }
        // v3-only: the existing strict validator rejects non-v3 and malformed
        // hostnames, exactly like every other onion route in the application.
        validate_onion_hostname_v1(onion).map_err(|_| {
            remote_config_error(
                "the organizer onion hostname is not a valid Tor v3 onion address",
            )
        })?;
        let collector_port = input.collector_port.unwrap_or(0);
        if collector_port == 0 {
            return Err(remote_config_error(
                "enter the fixed loopback collector port (1-65535) the remote hidden service forwards to",
            ));
        }
        Ok(Some(Self {
            socks: endpoint,
            onion_hostname: onion.to_owned(),
            collector_port,
        }))
    }
}

/// Bounded, value-free error for a malformed remote intake configuration.
fn remote_config_error(message: &'static str) -> CommandError {
    CommandError::new("GUI_ORGANIZER_REMOTE_CONFIG_INVALID", "INVALID_INPUT", message)
}

/// The running organizer intake runtime state. Present only while intake is
/// active; dropped/cleared on stop. The worker's session is intentionally NOT
/// the authoritative GUI session.
///
/// Process-ownership separation: `tor_child` is `Some` ONLY in
/// [`OrganizerTorModeV1::ManagedLocal`] (the app's own Tor child). In
/// [`OrganizerTorModeV1::ExternalRemote`] it is always `None` — the externally
/// managed daemon is NEVER spawned, signalled, reaped, or owned here.
pub(crate) struct OrganizerIntakeState {
    /// The owned Tor child (managed-local mode only; `None` in external-remote
    /// mode, where the external daemon is explicitly not owned).
    tor_child: Option<Child>,
    /// Which hosting mode this running intake uses.
    mode: OrganizerTorModeV1,
    /// External-remote configuration (mode-scoped endpoint + onion + collector
    /// port). `None` in managed-local mode. Readiness is recorded ONLY against
    /// this exact configuration.
    remote: Option<RemoteOrganizerIntakeConfigV1>,
    /// External-remote mode: whether the readiness check against the EXACT
    /// `remote` configuration passed. Cleared on stop/reconfigure.
    remote_last_ready: bool,
    service_loop: OrganizerCollectorServiceLoopV1,
    descriptor: TransportDescriptorV1,
    /// The election (manifest hash) this running intake is bound to.
    manifest_hash_hex: String,
    collector_addr: SocketAddr,
    onion_hostname: String,
    /// The FRESH per-run Tor DataDirectory this start allocated (never the
    /// persistent hidden-service directory). Diagnostics only.
    tor_data_dir: PathBuf,
    /// The per-run captured Tor stderr log, used to classify a later early exit
    /// into a bounded, path-free failure reason.
    stderr_log: PathBuf,
    voter_bundle_path: PathBuf,
    durable_inbox_dir: PathBuf,
    /// AUTHORITATIVE lifecycle fence: the GUI publishes every committed
    /// transition here so admission and status answers reflect organizer truth,
    /// never the worker session's own substrate state. Crate-visible so the
    /// shell's shared publication primitive
    /// ([`reconcile_intake_lifecycle`]) can drive it directly.
    pub(crate) lifecycle_fence: AuthoritativeLifecycleFenceV1,
}

impl OrganizerIntakeState {
    /// True when this running intake belongs to the supplied election.
    #[must_use]
    pub(crate) fn is_bound_to_manifest(&self, manifest_hash_hex: &str) -> bool {
        self.manifest_hash_hex == manifest_hash_hex
    }

    pub(crate) fn accepted_unique_count(&self) -> u64 {
        self.service_loop.accepted_unique_count()
    }

    pub(crate) fn finalize_transport_archive_binding(
        &self,
    ) -> Result<Option<TransportArchiveBindingV1>, CommandError> {
        self.service_loop
            .finalize_transport_archive_binding(&self.descriptor)
            .map_err(|_| {
                CommandError::new(
                    "GUI_TRANSPORT_ARCHIVE_BINDING_UNAVAILABLE",
                    "ARCHIVE_INTEGRITY",
                    "the active private transport history could not produce a finalized archive binding",
                )
            })
    }
}

/// Reconciles one running intake's authoritative lifecycle fence with the
/// organizer GUI's AUTHORITATIVE session state.
///
/// WHY THIS EXISTS (two-computer physical failure,
/// `lifecycle-auto-refresh-01`): publications into the running collector's
/// fence are best-effort push, and a silently lost push left the ballot office
/// serving validly-signed but STALE lifecycle statements indefinitely — voters
/// never learned FROZEN -> OPEN through automatic polls, manual polls, or
/// restarts of either side's private connection, while offline export of the
/// same truth worked. This healer converges served truth to authoritative
/// truth using the SAME reviewed [`AuthoritativeLifecycleFenceV1::observe`]
/// primitive as every other publication — no second protocol, no new trust
/// root:
///
/// * unchanged state → pure in-memory compare, idempotent, NO ledger write;
/// * changed state → continues the durable issuance ledger when available
///   ([`reserve_next_status_generation_v1`]), so healed statements carry a
///   fresh generation strictly beyond everything already served or exported
///   (the fence seed is reserved too — see the step-8 note in
///   [`start_intake_worker`]); without a usable status directory it falls back
///   to the fence's internal monotonic bump.
///
/// Called from the read-only organizer status heartbeat while intake runs
/// (healing any lost push within one heartbeat), and shared by every lifecycle
/// publisher so there is exactly ONE publication path.
pub(crate) fn reconcile_intake_lifecycle(
    manifest_hash_hex: &str,
    fence: &AuthoritativeLifecycleFenceV1,
    authoritative: ElectionLifecycleStateV1,
    status_dir: Option<&Path>,
) {
    if fence.state() == authoritative {
        return;
    }
    let reserved =
        status_dir.and_then(|dir| reserve_next_status_generation_v1(dir, manifest_hash_hex).ok());
    fence.observe(authoritative, reserved);
}

/// Serializable organizer intake status (organizer-safe aggregates only). No
/// private key material is ever included; onion/fingerprint/ports/paths are
/// diagnostics the frontend surfaces only under an Advanced disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrganizerIntakeStatusV1 {
    /// A Tor executable can be resolved (allowlist or the supplied path).
    pub tor_found: bool,
    /// The current election already has an app-owned transport (descriptor +
    /// organizer-private bundle) provisioned.
    pub transport_provisioned: bool,
    /// An intake worker is currently running (for any election).
    pub intake_running: bool,
    /// The running intake worker is bound to the CURRENTLY loaded election.
    pub election_bound: bool,
    /// The running intake is fully ready (runtime onion verified, worker alive).
    pub ready: bool,
    /// A start attempt is recorded but a REQUIRED owned component (the Tor child
    /// or the collector worker) has since died. This is a terminal, recoverable
    /// failure — never an indefinite "starting" limbo. Restart clears it.
    pub failed: bool,
    /// Bounded, path-free, secret-free reason for [`Self::failed`] (e.g.
    /// `organizer-tor-datadir-lock`, `organizer-tor-exited-early`,
    /// `organizer-worker-exited`). `None` unless `failed` is true.
    pub failure_reason: Option<String>,
    /// Ballots this intake run has uniquely accepted (worker-side aggregate).
    pub accepted_ballots: u64,
    /// Stable hosting-mode token of the RUNNING intake
    /// (`"managed-local"` / `"external-remote"`). `"managed-local"` when no
    /// intake is running (the recommended default mode).
    pub tor_mode: &'static str,
    // ---- Served-vs-authoritative diagnostics (never secret) ----
    /// The lifecycle the RUNNING collector would sign into
    /// `GET /v1/election-status` answers right now (fence state). `None`
    /// while no intake is running. A value that disagrees with
    /// [`Self::authoritative_lifecycle`] means a publication was missed and
    /// is healed by the status heartbeat within seconds.
    pub published_lifecycle: Option<String>,
    /// The monotonic generation the running collector would currently sign.
    pub status_generation: Option<u64>,
    /// The authoritative GUI session lifecycle observed during this same
    /// status call (the truth every publication must converge to).
    pub authoritative_lifecycle: Option<String>,
    // ---- Advanced / diagnostics (never secret) ----
    pub onion_hostname: Option<String>,
    pub descriptor_fingerprint: Option<String>,
    pub collector_addr: Option<String>,
    pub tor_data_dir: Option<String>,
    pub voter_bundle_path: Option<String>,
    pub durable_inbox_dir: Option<String>,
    pub message: &'static str,
}

/// Result of exporting the voter-safe transport bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VoterBundleExportResultV1 {
    pub written_path: String,
}

// -------------------------------------------------------------------------
// App-owned, election-scoped storage (derived from the manifest hash only).
// -------------------------------------------------------------------------

/// Pure derivation of the app-owned election transport root under a given
/// app-data root: `<app-data>/private-tor/election-<manifest-hash>`. The hash is
/// the ONLY path input and is validated to be a canonical 64-char lowercase hex
/// digest, so no remote/arbitrary value can influence the path (defense in depth
/// even though the hash originates from the loaded manifest, never the network).
fn election_transport_subpath(
    app_data_root: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    if manifest_hash_hex.len() != MANIFEST_HASH_HEX_LEN
        || !manifest_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommandError::new(
            "GUI_ORGANIZER_TOR_INVALID_ELECTION",
            "INVALID_INPUT",
            "the election manifest hash is not a canonical lowercase hex digest",
        ));
    }
    Ok(app_data_root
        .join(ORGANIZER_TOR_ROOT_DIRECTORY_NAME)
        .join(format!("election-{manifest_hash_hex}")))
}

/// Validates a manifest-hash hex and returns the app-owned election transport
/// root. Resolves the app-data root from the Tauri handle (app-owned, never a
/// remote value).
pub(crate) fn election_transport_root(
    app: &AppHandle,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    election_transport_subpath(&app_data_root, manifest_hash_hex)
}

/// The app-owned organizer-private bundle directory for one election (holds
/// the root signing secret used to sign descriptors, receipts, and
/// election-status statements).
pub(crate) fn organizer_private_bundle_dir(
    app: &AppHandle,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    Ok(election_transport_root(app, manifest_hash_hex)?.join("organizer-private"))
}

/// Error for a durable transport archive-binding recovery that hit ambiguous or
/// internally inconsistent authoritative state. It is an integrity failure, not
/// a capability limitation: authoritative durable state exists but could not be
/// turned into a finalized binding safely, so the caller must fail closed rather
/// than fabricate one.
fn binding_recovery_unavailable() -> CommandError {
    CommandError::new(
        "GUI_TRANSPORT_ARCHIVE_BINDING_UNAVAILABLE",
        "ARCHIVE_INTEGRITY",
        "the durable private transport history could not produce a finalized archive binding",
    )
}

/// Fail-closed error for the durable-integrity gate: the recovered
/// content-addressed accepted-package set does not match the authoritative
/// accepted tally the archive workflow supplied. A DISTINCT code from
/// [`binding_recovery_unavailable`] so operators and diagnostics can tell a
/// partially-lost / internally-inconsistent durable inbox apart from a
/// descriptor that simply could not seal. Deterministic and sanitized: it names
/// the class of inconsistency without leaking any package bytes, secret, count,
/// or path.
fn binding_recovery_count_mismatch() -> CommandError {
    CommandError::new(
        "GUI_TRANSPORT_ARCHIVE_BINDING_COUNT_MISMATCH",
        "ARCHIVE_INTEGRITY",
        "the durable accepted-package set does not match the authoritative accepted count",
    )
}

/// Deterministically recovers the authoritative finalized transport archive
/// binding for one election from DURABLE state alone — the signed, election-
/// scoped organizer descriptor plus the content-addressed private-intake inbox —
/// with NO running intake worker.
///
/// This is the restart-safe / close-reopen recovery for the archive-binding
/// lifecycle. The collector's in-memory batch state is ephemeral, but the
/// descriptor is persisted and the inbox holds exactly the accepted canonical
/// packages (content-addressed by the same `BallotPackageV1` digest a live
/// finalize seals). Because sealing happens only at finalize (a single final
/// batch), the reconstructed binding is byte-identical to a live finalize over
/// the same accepted set.
///
/// Fails closed on ambiguity and NEVER invents evidence:
///   * no durable descriptor for this election -> `Ok(None)` (no authoritative
///     transport was ever provisioned; the archive command reports REQUIRED);
///   * a persisted descriptor that does not bind THIS election -> rejected;
///   * an inbox package that does not match its content-address -> rejected by
///     `read_accepted_package_digests_v1`;
///   * an empty inbox while the authoritative session recorded accepted ballots
///     -> rejected (never silently produce a binding over an empty set);
///   * a recovered unique accepted-package count that does not EQUAL the
///     authoritative accepted tally supplied by the archive workflow -> rejected
///     BEFORE any canonical archive is written (a partially-lost durable inbox
///     must never seal a smaller-but-valid binding that only the later anchor
///     gate would catch).
///
/// The `app_data_root`-based core keeps this unit-testable without a Tauri
/// runtime; [`recover_finalized_transport_binding_from_durable_state`] wraps it
/// with the live [`AppHandle`].
pub(crate) fn recover_finalized_transport_binding_from_durable_state_under(
    app_data_root: &Path,
    manifest_hash_hex: &str,
    authoritative_accepted_count: u64,
) -> Result<Option<TransportArchiveBindingV1>, CommandError> {
    let private_dir =
        election_transport_subpath(app_data_root, manifest_hash_hex)?.join("organizer-private");
    // Absent / unreadable bundle => no authoritative transport for this election.
    let Ok(bundle) = load_organizer_private_bundle_v1(&private_dir) else {
        return Ok(None);
    };
    // Defense in depth: the persisted, signed descriptor must bind THIS election.
    // (The path is already election-scoped, and the archive writer independently
    // rejects a mismatched binding, so this is a redundant early fail-closed.)
    if to_hex_lower_v1(bundle.descriptor.manifest_hash().as_bytes()) != manifest_hash_hex {
        return Err(binding_recovery_unavailable());
    }
    let inbox_dir = private_intake_inbox_directory_v1(app_data_root, manifest_hash_hex)
        .map_err(|_| binding_recovery_unavailable())?;
    let digests =
        read_accepted_package_digests_v1(&inbox_dir).map_err(|_| binding_recovery_unavailable())?;
    if digests.is_empty() {
        // An authoritative accepted tally with no durable accepted packages is
        // internally inconsistent: fail closed, never invent a binding.
        if authoritative_accepted_count > 0 {
            return Err(binding_recovery_unavailable());
        }
        return Ok(None);
    }
    // Durable-integrity gate (fail-closed, BEFORE any canonical archive write):
    // the recovered content-addressed accepted set MUST exactly match the
    // authoritative accepted tally the archive workflow supplied
    // (`session.accepted_count()` at the call site). A partially-lost durable
    // inbox — e.g. authoritative accepted = 100 but only 99 surviving package
    // digests — would otherwise seal a smaller-but-valid binding that ONLY the
    // later Ootle anchor-config gate would reject, after the canonical archive
    // was already written. Refuse here and never fabricate the missing package,
    // alter the tally, or mutate the inbox. `read_accepted_package_digests_v1`
    // already re-hashed, sorted, and de-duplicated by content address, so this
    // length is the UNIQUE accepted-package count and compares like-for-like
    // with the authoritative unique accepted tally (`ledger.len()`). The
    // `usize -> u64` widening is lossless on every supported target.
    if digests.len() as u64 != authoritative_accepted_count {
        return Err(binding_recovery_count_mismatch());
    }
    finalized_transport_archive_binding_from_accepted_digests_v1(&bundle.descriptor, &digests)
        .map_err(|_| binding_recovery_unavailable())
}

/// [`AppHandle`] wrapper around
/// [`recover_finalized_transport_binding_from_durable_state_under`].
pub(crate) fn recover_finalized_transport_binding_from_durable_state(
    app: &AppHandle,
    manifest_hash_hex: &str,
    authoritative_accepted_count: u64,
) -> Result<Option<TransportArchiveBindingV1>, CommandError> {
    let app_data_root = app_data_root(app)?;
    recover_finalized_transport_binding_from_durable_state_under(
        &app_data_root,
        manifest_hash_hex,
        authoritative_accepted_count,
    )
}

/// Lowercase hex of a byte slice (no allocation-heavy dependencies).
fn to_hex_lower_v1(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Ensures `dir` is an app-owned real directory (no symlink/reparse redirect).
fn ensure_app_owned_directory(dir: &Path) -> Result<(), CommandError> {
    std::fs::create_dir_all(dir).map_err(|_| CommandError::app_data_unavailable())?;
    let metadata =
        std::fs::symlink_metadata(dir).map_err(|_| CommandError::app_data_unavailable())?;
    if !metadata.is_dir() || is_windows_reparse_point(&metadata) {
        return Err(CommandError::new(
            "GUI_ORGANIZER_TOR_UNSAFE_PATH",
            "INVALID_INPUT",
            "refusing to use an organizer transport directory that is not an app-owned directory",
        ));
    }
    Ok(())
}

/// The fixed sub-paths inside one election transport root.
///
/// Two of these are PERSISTENT and election-scoped — they carry the onion
/// identity and the organizer-private material and MUST survive every restart so
/// already-distributed voter bundles stay valid: `hidden_service_dir` and
/// `organizer_private_dir`. The Tor runtime DataDirectory is deliberately NOT a
/// fixed persistent path: every start allocates a FRESH run directory under
/// `tor_runs_base` (see [`start_intake_worker`]). This mirrors the voter-side
/// hard-kill defence — an orphaned `tor.exe` that survives a Task-Manager kill of
/// the app keeps the lock of the run directory it was using, so a brand-new run
/// directory is immune to that stale lock while the SAME `hidden_service_dir`
/// keeps the onion address and descriptor fingerprint stable across restarts.
struct TransportPaths {
    organizer_private_dir: PathBuf,
    hidden_service_dir: PathBuf,
    /// Parent directory that holds the per-start `run-*` Tor DataDirectories.
    tor_runs_base: PathBuf,
    voter_bundle_path: PathBuf,
}

impl TransportPaths {
    fn under(root: &Path) -> Self {
        Self {
            organizer_private_dir: root.join("organizer-private"),
            hidden_service_dir: root.join("organizer-hidden-service"),
            tor_runs_base: root.join("organizer-tor-runs"),
            voter_bundle_path: root.join("voter-public-bundle.cbor"),
        }
    }

    /// True when an organizer-private bundle has already been provisioned.
    fn is_provisioned(&self) -> bool {
        load_organizer_private_bundle_v1(&self.organizer_private_dir).is_ok()
    }
}

// -------------------------------------------------------------------------
// Session snapshot (never held across the long Tor bootstrap).
// -------------------------------------------------------------------------

pub(crate) struct BoundElection {
    pub(crate) artifacts: GuiElectionArtifactsV1,
    pub(crate) manifest_hash_hex: String,
    pub(crate) election_id: Vec<u8>,
    pub(crate) manifest_hash: [u8; 32],
    /// The authoritative lifecycle at snapshot time.
    pub(crate) lifecycle: ElectionLifecycleStateV1,
}

pub(crate) fn bound_election(state: &AppState) -> Result<BoundElection, CommandError> {
    let guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let artifacts = session.artifacts().clone();
    let manifest_hash_hex = artifacts.summary().manifest_hash_hex.clone();
    let election_id = artifacts.manifest().election_id().as_bytes().to_vec();
    let manifest_hash = *artifacts.manifest_hash().as_bytes();
    let lifecycle = session.lifecycle_state_v1();
    Ok(BoundElection {
        artifacts,
        manifest_hash_hex,
        election_id,
        manifest_hash,
        lifecycle,
    })
}

// -------------------------------------------------------------------------
// Tauri commands
// -------------------------------------------------------------------------

/// Read-only organizer intake status for the currently loaded election. Never
/// starts Tor, provisions, or mutates any election/transport state.
///
/// ORGANIZER-AUTHORITATIVE: intake status discloses ballot-office transport
/// internals (onion endpoint, collector, inbox). An imported voter election
/// must never observe — let alone act on — this surface.
#[tauri::command]
pub async fn organizer_tor_status(
    tor_exe_path: Option<String>,
    app: AppHandle,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        organizer_tor_status_blocking(tor_exe_path, &app, state.inner())
    })
    .await
}

/// Blocking body of [`organizer_tor_status`], run on the blocking thread pool.
fn organizer_tor_status_blocking(
    tor_exe_path: Option<String>,
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    // Role boundary first: no organizer transport introspection for a session
    // that was merely imported from public artifacts.
    state.ensure_organizer_authority()?;
    let tor_found = resolve_tor_executable(tor_exe_path.as_deref()).is_ok();

    // Current election (if any) drives provisioned/bound reporting.
    let bound = bound_election(state).ok();
    let transport_provisioned = match &bound {
        Some(b) => match election_transport_root(app, &b.manifest_hash_hex) {
            Ok(root) => TransportPaths::under(&root).is_provisioned(),
            Err(_) => false,
        },
        None => false,
    };
    // Durable issuance ledger used ONLY when a reconciliation actually changes
    // the fence state (see `reconcile_intake_lifecycle`); resolved best-effort.
    let status_dir = app_data_root(app)
        .ok()
        .and_then(|root| ensure_voter_election_status_directory_v1(&root).ok());

    let mut managed = state
        .organizer_intake
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let running = managed.as_mut();
    let (
        intake_running,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted,
        diag,
        published,
        tor_mode,
    ) = match running {
        Some(m) => {
            let same_election = bound
                .as_ref()
                .is_some_and(|b| b.manifest_hash_hex == m.manifest_hash_hex);
            // AUTHORITATIVE RECONCILIATION HEARTBEAT: this read-only status
            // command runs every few seconds while the ballot-office screen is
            // open. Before reporting anything, converge the running collector's
            // fence to the authoritative session lifecycle so a silently lost
            // transition publication can never persist beyond one heartbeat.
            // Same state is a lock-free no-op; only a real change touches the
            // issuance ledger. No network, no Tor action, no clearnet.
            if same_election && let Some(b) = bound.as_ref() {
                reconcile_intake_lifecycle(
                    &m.manifest_hash_hex,
                    &m.lifecycle_fence,
                    b.lifecycle,
                    status_dir.as_deref(),
                );
            }
            let child_alive = m.tor_child.as_mut().is_some_and(|child| {
                child
                    .try_wait()
                    .map(|status| status.is_none())
                    .unwrap_or(false)
            });
            let worker_alive = m.service_loop.worker_is_alive();
            // Managed-local: ready requires the OWNED Tor child + worker.
            // External-remote: there is NO owned child; ready requires the
            // worker plus the recorded endpoint-scoped readiness result.
            let owned_ready = match m.mode {
                OrganizerTorModeV1::ManagedLocal => child_alive,
                OrganizerTorModeV1::ExternalRemote => m.remote_last_ready,
            };
            let ready = same_election && owned_ready && worker_alive;
            // A recorded intake whose owned Tor child or collector worker has
            // died is a bounded FAILED state — never an indefinite "starting".
            let failure_reason = intake_failure_reason(m, child_alive, worker_alive);
            let failed = failure_reason.is_some();
            let accepted = m.service_loop.accepted_unique_count();
            let published = Some((m.lifecycle_fence.state(), m.lifecycle_fence.generation()));
            let diag = Some((
                m.onion_hostname.clone(),
                descriptor_fingerprint_hex(&m.descriptor),
                m.collector_addr.to_string(),
                m.tor_data_dir.to_string_lossy().into_owned(),
                m.voter_bundle_path.to_string_lossy().into_owned(),
                m.durable_inbox_dir.to_string_lossy().into_owned(),
            ));
            let tor_mode = m.mode.as_token();
            (
                true,
                same_election,
                ready,
                failed,
                failure_reason,
                accepted,
                diag,
                published,
                tor_mode,
            )
        }
        None => (
            false,
            false,
            false,
            false,
            None,
            0,
            None,
            None,
            OrganizerTorModeV1::ManagedLocal.as_token(),
        ),
    };

    let message = status_message(
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        failed,
    );
    Ok(build_status(
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted,
        tor_mode,
        diag,
        published,
        bound.as_ref().map(|b| b.lifecycle),
        message,
    ))
}

/// Classifies why a recorded intake is unhealthy, or `None` when both the owned
/// Tor child and the collector worker are alive. A dead Tor child is classified
/// from its captured per-run stderr log (bounded, path-free); a dead worker with
/// a live child is reported as `organizer-worker-exited`.
fn intake_failure_reason(
    m: &OrganizerIntakeState,
    child_alive: bool,
    worker_alive: bool,
) -> Option<String> {
    if child_alive && worker_alive {
        return None;
    }
    // External-remote mode owns NO Tor child: a missing child is the NORMAL
    // state there, so only a dead WORKER is a failure.
    if m.mode == OrganizerTorModeV1::ExternalRemote {
        if !worker_alive {
            return Some("organizer-worker-exited".to_owned());
        }
        return None;
    }
    if child_alive && worker_alive {
        return None;
    }
    if !child_alive {
        let kind = classify_start_failure_from_log(&m.stderr_log);
        return Some(kind.as_organizer_context_label().to_owned());
    }
    // Child alive but the collector worker thread has exited.
    Some("organizer-worker-exited".to_owned())
}

/// Starts (or reuses) private ballot intake for the currently loaded election.
///
/// Provisions app-owned transport on first use, then runs the exact vetted
/// intake orchestration in-process. Fail-closed at every step. Does NOT open
/// voting or mutate the election lifecycle.
///
/// ORGANIZER-AUTHORITATIVE — and the gate fires FIRST, before the Tor lookup,
/// any filesystem write, transport provisioning, hidden-service identity
/// creation, or worker start. An imported voter election can never provision a
/// competing organizer transport/signing root for a legitimate frozen election.
#[tauri::command]
pub async fn start_private_intake(
    tor_exe_path: Option<String>,
    remote: Option<RemoteOrganizerIntakeInputV1>,
    app: AppHandle,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        start_private_intake_blocking(tor_exe_path, remote, &app, state.inner())
    })
    .await
}

/// Blocking body of [`start_private_intake`]: the multi-second Tor hidden-service
/// bootstrap and hostname discovery run on the blocking thread pool so the main
/// UI thread keeps pumping while intake comes up (managed-local mode). In
/// external-remote mode no Tor process is touched at all; the bounded remote
/// readiness check runs on the same blocking pool instead.
fn start_private_intake_blocking(
    tor_exe_path: Option<String>,
    remote_input: Option<RemoteOrganizerIntakeInputV1>,
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    // ORGANIZER-AUTHORITY GATE — before EVERYTHING (no Tor resolution, no
    // directory creation, no provisioning, no worker).
    state.ensure_organizer_authority()?;
    // Parse the requested mode FIRST (fail closed on a malformed remote config)
    // so a malformed remote request can never fall through to managed-local
    // and silently spawn a Tor process.
    let remote_config = match &remote_input {
        Some(input) => RemoteOrganizerIntakeConfigV1::from_input(input)?,
        None => None,
    };
    let requested_mode = if remote_config.is_some() {
        OrganizerTorModeV1::ExternalRemote
    } else {
        OrganizerTorModeV1::ManagedLocal
    };

    // Managed-local only: the Tor executable is resolved and validated here.
    // External-remote mode resolves and validates NO Tor binary: the remote
    // daemon is externally managed and must never be treated as owned.
    let tor_executable = match requested_mode {
        OrganizerTorModeV1::ManagedLocal => {
            let tor_executable = resolve_tor_executable(tor_exe_path.as_deref())?;
            validate_tor_exe(&tor_executable)?;
            Some(tor_executable)
        }
        OrganizerTorModeV1::ExternalRemote => None,
    };

    let bound = bound_election(state)?;

    // If an intake is already recorded, resolve it into exactly one of:
    //   * healthy + THIS election + the SAME mode → return its status
    //     (idempotent);
    //   * healthy + a DIFFERENT election, or a DIFFERENT hosting mode →
    //     require an explicit stop (a mode switch must never silently reuse or
    //     tear down the other mode's runtime);
    //   * unhealthy (owned Tor child or worker died, e.g. after a hard-kill
    //     restart) → REAP it and fall through to a single fresh start, so one
    //     Start click recovers a failed intake without ever stacking a second
    //     controller/child for the same app+election.
    let dead_intake = {
        let mut managed = state
            .organizer_intake
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(m) = managed.as_mut() {
            let child_alive = m.tor_child.as_mut().is_some_and(|child| {
                child
                    .try_wait()
                    .map(|status| status.is_none())
                    .unwrap_or(false)
            });
            let healthy = match m.mode {
                OrganizerTorModeV1::ManagedLocal => {
                    child_alive && m.service_loop.worker_is_alive()
                }
                OrganizerTorModeV1::ExternalRemote => {
                    m.remote_last_ready && m.service_loop.worker_is_alive()
                }
            };
            if healthy {
                if m.manifest_hash_hex == bound.manifest_hash_hex {
                    if m.mode == requested_mode {
                        return Ok(running_status(m, true, child_alive, bound.lifecycle));
                    }
                    return Err(CommandError::new(
                        "GUI_ORGANIZER_INTAKE_MODE_MISMATCH",
                        "INVALID_LIFECYCLE_TRANSITION",
                        "stop the running private intake before switching between managed-local and external-remote Tor hosting",
                    ));
                }
                return Err(CommandError::new(
                    "GUI_ORGANIZER_INTAKE_OTHER_ELECTION",
                    "INVALID_LIFECYCLE_TRANSITION",
                    "stop the running private intake before starting it for a different election",
                ));
            }
            // Unhealthy: take ownership out of the slot so the fresh start below
            // installs the ONLY current controller. Reap outside the lock.
            managed.take()
        } else {
            None
        }
    };
    if let Some(mut dead) = dead_intake {
        let _ = dead.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        // Only an OWNED child (managed-local) is ever signalled. An
        // external-remote intake has no child and the external daemon is left
        // completely untouched.
        if let Some(mut child) = dead.tor_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // Build app-owned, election-scoped storage.
    let root = election_transport_root(app, &bound.manifest_hash_hex)?;
    ensure_app_owned_directory(&root)?;
    let paths = TransportPaths::under(&root);
    ensure_app_owned_directory(&paths.organizer_private_dir)?;

    // Provision transport on first use (managed: persistent hidden-service
    // identity is created once and reused on later starts; remote: the
    // operator's externally provisioned onion hostname is signed in WITHOUT
    // any Tor process).
    match requested_mode {
        OrganizerTorModeV1::ManagedLocal => {
            let tor_executable = tor_executable.as_deref().ok_or_else(tor_start_failed)?;
            if !paths.is_provisioned() {
                provision_transport(tor_executable, &paths, &bound)?;
            }

            // Run the vetted intake orchestration; on success this returns the
            // running state to store. The AUTHORITATIVE lifecycle at start seeds
            // the admission fence so a FROZEN election never accepts ballots
            // even if intake starts before voting opens.
            let authoritative_lifecycle = authoritative_lifecycle_snapshot(state)?;
            let running =
                start_intake_worker(app, tor_executable, &paths, &bound, authoritative_lifecycle)?;
            // The worker was just confirmed alive (child liveness re-checked after
            // discovery, worker liveness checked in step 9), so report it as
            // running.
            let status = running_status(&running, true, true, authoritative_lifecycle);
            let mut managed = state
                .organizer_intake
                .lock()
                .map_err(|_| CommandError::state_poisoned())?;
            *managed = Some(running);
            Ok(status)
        }
        OrganizerTorModeV1::ExternalRemote => {
            let config = remote_config.as_ref().ok_or_else(|| {
                CommandError::new(
                    "GUI_ORGANIZER_REMOTE_CONFIG_INVALID",
                    "INVALID_INPUT",
                    "the external-remote Tor configuration is missing",
                )
            })?;
            if !paths.is_provisioned() {
                // Provision WITHOUT any Tor process: the operator's externally
                // provisioned onion hostname is what the descriptor signs.
                provision_transport_remote(config, &paths, &bound)?;
            }

            let authoritative_lifecycle = authoritative_lifecycle_snapshot(state)?;
            let running = start_remote_intake_worker(
                app,
                config,
                &paths,
                &bound,
                authoritative_lifecycle,
            )?;
            let status = running_status(&running, true, true, authoritative_lifecycle);
            let mut managed = state
                .organizer_intake
                .lock()
                .map_err(|_| CommandError::state_poisoned())?;
            *managed = Some(running);
            Ok(status)
        }
    }
}

/// Snapshot of the authoritative lifecycle used to seed the admission fence.
fn authoritative_lifecycle_snapshot(
    state: &AppState,
) -> Result<ElectionLifecycleStateV1, CommandError> {
    let guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    Ok(guard
        .as_ref()
        .map(|active| active.session.lifecycle_state_v1())
        .unwrap_or(ElectionLifecycleStateV1::Frozen))
}

/// Explicit external-remote connection test backing the Advanced UI "Test
/// connection" button. Validates the operator configuration and runs ONLY the
/// non-mutating, zero-application-byte SOCKS5 CONNECT probe to the literal
/// organizer onion through the external proxy. No collector is started, no
/// ballot bytes, no credential, no state mutation, and — critically — no Tor
/// process is spawned, signalled, or otherwise owned.
#[tauri::command]
pub async fn test_remote_organizer_tor(
    remote: RemoteOrganizerIntakeInputV1,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let config = RemoteOrganizerIntakeConfigV1::from_input(&remote)?;
        let config = config.ok_or_else(|| {
            CommandError::new(
                "GUI_ORGANIZER_REMOTE_CONFIG_INVALID",
                "INVALID_INPUT",
                "the connection test is only available in external-remote Tor mode",
            )
        })?;
        let timeouts = remote_organizer_readiness_timeouts();
        let outcome =
            probe_remote_onion_hostname_v1(&config.socks, &config.onion_hostname, &timeouts);
        Ok(OrganizerIntakeStatusV1 {
            tor_found: true,
            transport_provisioned: false,
            intake_running: false,
            election_bound: false,
            ready: outcome.is_ready(),
            failed: false,
            failure_reason: None,
            accepted_ballots: 0,
            tor_mode: OrganizerTorModeV1::ExternalRemote.as_token(),
            published_lifecycle: None,
            status_generation: None,
            authoritative_lifecycle: None,
            onion_hostname: Some(config.onion_hostname),
            descriptor_fingerprint: None,
            collector_addr: None,
            tor_data_dir: None,
            voter_bundle_path: None,
            durable_inbox_dir: None,
            message: remote_organizer_readiness_message(outcome),
        })
    })
    .await
}

/// Stops private ballot intake cleanly: bounded service-loop shutdown, reap the
/// owned Tor child, release the loopback collector. Preserves the hidden-service
/// identity and every accepted package; never mutates the election lifecycle.
///
/// ORGANIZER-AUTHORITATIVE: only the ballot office controls its intake worker.
#[tauri::command]
pub async fn stop_private_intake(app: AppHandle) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        stop_private_intake_blocking(&app, state.inner())
    })
    .await
}

/// Blocking body of [`stop_private_intake`], run on the blocking thread pool
/// (the bounded worker join + child reap can take up to a few seconds).
fn stop_private_intake_blocking(
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    // Role boundary first: an imported voter session must never be able to
    // tear down (or interfere with) a running ballot-office collector.
    state.ensure_organizer_authority()?;
    let taken = {
        let mut managed = state
            .organizer_intake
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        managed.take()
    };
    if let Some(mut m) = taken {
        // Stop the collector worker first (no new requests serviced), then reap
        // the owned Tor child (managed-local ONLY). In external-remote mode
        // there is no owned child and the external daemon is NEVER signalled —
        // only the app-side collector stops and the endpoint-scoped readiness
        // record is cleared.
        let _ = m.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        if let Some(mut child) = m.tor_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    // Recompute a fresh read-only status (no running worker now).
    organizer_tor_status_blocking(None, app, state)
}

/// Reaps a running organizer intake worker (collector service loop + owned Tor
/// child) on application teardown, preserving the persistent hidden-service
/// identity and every accepted package. Idempotent and best-effort.
pub(crate) fn shutdown_intake_on_exit(state: &AppState) {
    let taken = {
        match state.organizer_intake.lock() {
            Ok(mut managed) => managed.take(),
            Err(_) => None,
        }
    };
    if let Some(mut m) = taken {
        let _ = m.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        // Only an OWNED child (managed-local) is terminated. An external-remote
        // intake has no child; the externally managed Tor daemon — and any
        // remote infrastructure — is deliberately left untouched on shutdown.
        if let Some(mut child) = m.tor_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Exports ONLY the voter-safe public transport bundle for the loaded election
/// to a chosen directory (no-overwrite). Never exports organizer-private key
/// material.
///
/// ORGANIZER-AUTHORITATIVE — and the gate fires before the destination checks:
/// only the ballot office that provisioned a transport root may distribute its
/// voter bundle. An imported voter election can never export (and thereby
/// socially distribute) a bundle for an election it does not organize.
#[tauri::command]
pub async fn export_voter_transport_bundle(
    destination_dir: String,
    app: AppHandle,
) -> Result<VoterBundleExportResultV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        state.ensure_organizer_authority()?;
        let destination = PathBuf::from(&destination_dir);
        if !destination.is_absolute() {
            return Err(CommandError::new(
                "GUI_EXPORT_DIR_NOT_ABSOLUTE",
                "INVALID_INPUT",
                "the export destination directory must be absolute",
            ));
        }
        let dest_meta = std::fs::symlink_metadata(&destination).map_err(|_| {
            CommandError::new(
                "GUI_EXPORT_DIR_NOT_FOUND",
                "FILE_IO",
                "the export destination directory was not found",
            )
        })?;
        if !dest_meta.is_dir() || is_windows_reparse_point(&dest_meta) {
            return Err(CommandError::new(
                "GUI_EXPORT_DIR_UNSAFE",
                "INVALID_INPUT",
                "the export destination must be a real directory (no symlinks/reparse points)",
            ));
        }

        let bound = bound_election(state.inner())?;
        let root = election_transport_root(&app, &bound.manifest_hash_hex)?;
        let paths = TransportPaths::under(&root);
        // The source is the voter PUBLIC bundle only; organizer-private material is
        // never read here.
        let source = &paths.voter_bundle_path;
        let source_meta = std::fs::symlink_metadata(source).map_err(|_| {
            CommandError::new(
                "GUI_VOTER_BUNDLE_MISSING",
                "FILE_IO",
                "no voter transport bundle exists yet; start private intake first to provision it",
            )
        })?;
        if !source_meta.is_file() || is_windows_reparse_point(&source_meta) {
            return Err(CommandError::new(
                "GUI_VOTER_BUNDLE_UNSAFE",
                "INVALID_INPUT",
                "the voter transport bundle is not an app-owned regular file",
            ));
        }

        let target = destination.join("voter-public-bundle.cbor");
        // No-overwrite: refuse if a file already exists at the target.
        if std::fs::symlink_metadata(&target).is_ok() {
            return Err(CommandError::new(
                "GUI_EXPORT_TARGET_EXISTS",
                "INVALID_INPUT",
                "a voter-public-bundle.cbor already exists in that folder; choose another folder",
            ));
        }
        let bytes = std::fs::read(source).map_err(|_| CommandError::package_read_failed())?;
        std::fs::write(&target, &bytes).map_err(|_| {
            CommandError::new(
                "GUI_EXPORT_WRITE_FAILED",
                "FILE_IO",
                "the voter transport bundle could not be written to that folder",
            )
        })?;
        Ok(VoterBundleExportResultV1 {
            written_path: target.to_string_lossy().into_owned(),
        })
    })
    .await
}

// -------------------------------------------------------------------------
// Orchestration (reuses the vetted library functions; no protocol logic here).
// -------------------------------------------------------------------------

/// First-time transport provisioning: start Tor to discover the persistent
/// hidden-service hostname, stop Tor, then sign the descriptor and write both
/// bundles. Mirrors `private-ballot-tor-test-provision` step-for-step, calling
/// only reviewed library functions.
fn provision_transport(
    tor_executable: &Path,
    paths: &TransportPaths,
    bound: &BoundElection,
) -> Result<(), CommandError> {
    let binding = TransportElectionBindingV1 {
        election_id: bound.election_id.clone(),
        manifest_hash: bound.manifest_hash,
    };
    // A FRESH throwaway DataDirectory for the one-shot hostname-discovery run, so
    // even first-time provisioning can never collide with an orphaned tor.exe
    // that still holds a prior run directory's lock. The onion identity is
    // written to the PERSISTENT hidden-service directory, not this run directory.
    ensure_app_owned_directory(&paths.tor_runs_base)?;
    let run_dir = fresh_run_directory(&paths.tor_runs_base)?;
    remove_stale_run_directories(&paths.tor_runs_base, &run_dir);
    let provision_torrc = run_dir.join("organizer-provision-torrc");
    let stderr_log = run_dir.join("tor-stderr.log");
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: run_dir.clone(),
        config_file: provision_torrc.clone(),
        hidden_service_dir: paths.hidden_service_dir.clone(),
        collector_port: PROVISION_COLLECTOR_PORT,
        startup_timeout: TOR_STARTUP_TIMEOUT,
    };
    tor_config.write_config().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_TORRC_FAILED",
            "FILE_IO",
            "the organizer Tor configuration could not be written",
        )
    })?;

    let spawner = DiagnosticTorSpawnerV1 {
        stderr_log: stderr_log.clone(),
    };
    let mut child = spawner
        .spawn(tor_executable, &provision_torrc)
        .map_err(|_| tor_start_failed())?;
    let timeout = DiscoveryTimeoutV1::new(TOR_STARTUP_TIMEOUT);
    let hostname = {
        let child_alive = || {
            child
                .try_wait()
                .map(|status| status.is_none())
                .unwrap_or(false)
        };
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let kind = classify_start_failure_from_log(&stderr_log);
                return Err(hostname_discovery_failed()
                    .with_context(kind.as_organizer_context_label().to_owned()));
            }
        }
    };
    // Stop Tor: the hostname/identity persists in the hidden-service directory.
    let _ = child.kill();
    let _ = child.wait();

    let material = generate_transport_authority_material_v1("test-root".to_owned()).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_MATERIAL_FAILED",
            "INVALID_INPUT",
            "the organizer transport authority material could not be generated",
        )
    })?;
    provision_organizer_transport_bundles_v1(
        &paths.organizer_private_dir,
        &paths.voter_bundle_path,
        &material,
        &binding,
        hostname,
        // Recorded as inert bundle metadata only (never validated or reused at
        // runtime); the real DataDirectory is a fresh per-start run directory.
        &paths.tor_runs_base,
        &paths.hidden_service_dir,
    )
    .map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_PROVISION_FAILED",
            "INVALID_INPUT",
            "the organizer transport bundles could not be provisioned",
        )
    })?;
    Ok(())
}

/// First-time transport provisioning for EXTERNAL-REMOTE mode: sign the
/// descriptor against the operator's EXTERNALLY provisioned onion hostname and
/// write both bundles. NO Tor process is started, no local hidden-service
/// directory is created, and no SOCKS port is reserved — the onion identity is
/// owned and hosted entirely by the external Tor instance.
fn provision_transport_remote(
    config: &RemoteOrganizerIntakeConfigV1,
    paths: &TransportPaths,
    bound: &BoundElection,
) -> Result<(), CommandError> {
    let binding = TransportElectionBindingV1 {
        election_id: bound.election_id.clone(),
        manifest_hash: bound.manifest_hash,
    };
    let material = generate_transport_authority_material_v1("test-root".to_owned()).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_MATERIAL_FAILED",
            "INVALID_INPUT",
            "the organizer transport authority material could not be generated",
        )
    })?;
    provision_organizer_transport_bundles_v1(
        &paths.organizer_private_dir,
        &paths.voter_bundle_path,
        &material,
        &binding,
        config.onion_hostname.clone(),
        // Recorded as inert bundle metadata only (never validated or reused at
        // runtime, exactly like the managed mode's metadata): the external
        // remote daemon owns the real data directory and hidden-service dir.
        &paths.tor_runs_base,
        &paths.hidden_service_dir,
    )
    .map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_PROVISION_FAILED",
            "INVALID_INPUT",
            "the organizer transport bundles could not be provisioned",
        )
    })?;
    Ok(())
}

/// Shared intake service assembly for BOTH hosting modes: durable hand-off
/// inbox, worker session, authoritative admission fence seed, collector
/// handler, and service-loop start. Fails closed identically in both modes so
/// no protocol or admission logic can diverge between them.
///
/// Returns the running service loop, the durable inbox directory, and the
/// fence (for status publication). READY is only reported by callers AFTER the
/// worker is confirmed alive here.
fn start_collector_service_shared(
    app: &AppHandle,
    bound: &BoundElection,
    bundle: &LoadedOrganizerPrivateBundleV1,
    collector: OpaqueEnvelopeCollectorV1,
    authoritative_lifecycle: ElectionLifecycleStateV1,
) -> Result<
    (
        OrganizerCollectorServiceLoopV1,
        PathBuf,
        AuthoritativeLifecycleFenceV1,
    ),
    CommandError,
> {
    // App-owned, election-scoped durable hand-off inbox (manifest-hash path).
    let durable_inbox_dir =
        ensure_private_intake_inbox_directory_v1(&app_data_root(app)?, &bound.manifest_hash_hex)
            .map_err(CommandError::from)?;

    // Fresh intake worker session (NOT the authoritative GUI session).
    let mut session =
        GuiElectionSessionV1::new(bound.artifacts.clone()).map_err(CommandError::from)?;
    session.open().map_err(CommandError::from)?;

    // The AUTHORITATIVE lifecycle fence is initialized from the organizer GUI's
    // current state, so a FROZEN election fences ballots immediately and status
    // answers carry signed truth (never the worker session's own substrate
    // state).
    //
    // ROOT-CAUSE FIX (two-computer physical failure,
    // `lifecycle-auto-refresh-01`): the seed generation MUST be freshly
    // RESERVED into the durable issuance ledger, never merely re-read from it.
    // Reserving the seed writes it into the SAME ledger every publication and
    // export continues, so every served statement carries a unique, strictly
    // monotonic generation across restarts. A failed reservation degrades to
    // the legacy read-only seed instead of blocking ballot-office startup
    // (still monotonic within one run; the heartbeat reconciliation keeps
    // healing state truth).
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session_arc = Arc::new(Mutex::new(session));
    let descriptor_arc = Arc::new(bundle.descriptor.clone());
    let receiver_key_arc = reconstruct_receiver_key(bundle)?;
    let receipt_key_arc = Arc::new(bundle.material.receipt_signing_key.clone());
    let root_signing_key_arc = Arc::new(bundle.material.root_signing_key.clone());
    let status_dir = ensure_voter_election_status_directory_v1(&app_data_root(app)?)?;
    let seed_generation = reserve_next_status_generation_v1(&status_dir, &bound.manifest_hash_hex)
        .unwrap_or_else(|_| {
            read_issued_status_generation_v1(&status_dir, &bound.manifest_hash_hex).unwrap_or(0)
        });
    let lifecycle_fence =
        AuthoritativeLifecycleFenceV1::new(authoritative_lifecycle, seed_generation);
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway,
        descriptor_arc,
        receiver_key_arc,
        session_arc,
        receipt_key_arc,
        "organizer-receipt-key".to_owned(),
    )
    .with_accepted_package_inbox(durable_inbox_dir.clone())
    .with_lifecycle_fence(lifecycle_fence.clone())
    .with_election_status_signer(
        root_signing_key_arc,
        bundle.material.root.key_id().to_owned(),
    );
    let service_loop =
        OrganizerCollectorServiceLoopV1::start(collector, handler, COLLECTOR_POLL_INTERVAL)
            .map_err(|_| {
                CommandError::new(
                    "GUI_ORGANIZER_SERVICE_START_FAILED",
                    "UNAVAILABLE",
                    "the collector service loop could not be started",
                )
            })?;

    // READY only after the worker is confirmed alive.
    if !service_loop.worker_is_alive() {
        let _ = service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        return Err(CommandError::new(
            "GUI_ORGANIZER_WORKER_DEAD",
            "UNAVAILABLE",
            "the collector service worker exited immediately on start",
        ));
    }
    Ok((service_loop, durable_inbox_dir, lifecycle_fence))
}

/// Starts the intake worker for an already-provisioned election in
/// EXTERNAL-REMOTE mode. NO Tor process is spawned, validated, signalled, or
/// owned: the operator's external Tor instance already hosts the onion service
/// whose `HiddenServicePort` forwards to THIS machine's fixed loopback
/// collector port. Readiness is endpoint-scoped: the remote SOCKS route is
/// probed with ZERO application bytes and then one public, credential-free
/// election-status GET; only that exact endpoint + onion combination passing
/// both marks the run ready.
fn start_remote_intake_worker(
    app: &AppHandle,
    config: &RemoteOrganizerIntakeConfigV1,
    paths: &TransportPaths,
    bound: &BoundElection,
    authoritative_lifecycle: ElectionLifecycleStateV1,
) -> Result<OrganizerIntakeState, CommandError> {
    // 1. Load organizer private bundle and validate ALL bindings before any
    //    network activity. No local hostname file exists in remote mode (the
    //    hidden-service directory is external), so the persisted-hostname check
    //    is skipped and replaced by the explicit descriptor-onion equality
    //    gate below.
    let bundle = load_organizer_private_bundle_v1(&paths.organizer_private_dir).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_BUNDLE_MALFORMED",
            "INVALID_INPUT",
            "the organizer transport bundle could not be loaded",
        )
    })?;
    validate_intake_startup_v1(&bundle, &bound.artifacts, None).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_STARTUP_UNTRUSTED",
            "BINDING_MISMATCH",
            "the organizer transport bundle failed startup validation for this election",
        )
    })?;

    // 1b. Fail-closed binding gate: the configured external onion MUST equal
    //     the signed descriptor onion, so intake can never be pointed at (or
    //     advertised as) a different onion than the one voters' bundles bind.
    let descriptor_onion = bundle
        .descriptor
        .onion_endpoints()
        .first()
        .cloned()
        .ok_or_else(|| {
            CommandError::new(
                "GUI_ORGANIZER_NO_ONION",
                "BINDING_MISMATCH",
                "the transport descriptor has no onion endpoint",
            )
        })?;
    if descriptor_onion != config.onion_hostname {
        return Err(CommandError::new(
            "GUI_ORGANIZER_REMOTE_ONION_MISMATCH",
            "BINDING_MISMATCH",
            "the configured external onion hostname does not match this election's signed descriptor",
        ));
    }

    // 2. Bind the loopback collector on the FIXED configured port — the port
    //    the remote operator's `HiddenServicePort 80 <host>:<port>` targets.
    //    A busy port is a bounded, specific failure (the operator must free it
    //    or reconfigure the remote side); the application never silently picks
    //    a different port in remote mode.
    let collector =
        OpaqueEnvelopeCollectorV1::bind_loopback_port(config.collector_port).map_err(|_| {
            CommandError::new(
                "GUI_ORGANIZER_REMOTE_COLLECTOR_BIND_FAILED",
                "UNAVAILABLE",
                "the loopback collector port could not be bound; another program may be using it",
            )
        })?;
    let collector_addr = collector.local_addr().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_COLLECTOR_ADDR_FAILED",
            "UNAVAILABLE",
            "the loopback collector address could not be read",
        )
    })?;

    // 3. Shared service assembly (inbox, worker session, fence, handler, loop).
    let (service_loop, durable_inbox_dir, lifecycle_fence) = start_collector_service_shared(
        app,
        bound,
        &bundle,
        collector,
        authoritative_lifecycle,
    )?;

    // 4. Endpoint-scoped remote readiness. First the zero-application-byte
    //    SOCKS5 CONNECT probe to the literal onion through the external proxy;
    //    then ONE public, credential-free election-status GET over the same
    //    route (the minimum non-mutating organizer readiness check the protocol
    //    supports). NO ballot application bytes, credential, or nullifier ever
    //    leave during readiness. Any failure stops the just-started collector
    //    and fails closed — the external Tor is left untouched.
    let timeouts = remote_organizer_readiness_timeouts();
    let outcome = probe_remote_onion_hostname_v1(&config.socks, &config.onion_hostname, &timeouts);
    if !outcome.is_ready() {
        let _ = service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        return Err(CommandError::new(
            "GUI_ORGANIZER_REMOTE_NOT_READY",
            "UNAVAILABLE",
            remote_organizer_readiness_message(outcome),
        ));
    }
    let status_fetch =
        fetch_election_status_over_remote_tor_onion(&config.socks, &config.onion_hostname, &timeouts);
    if status_fetch.is_err() {
        let _ = service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        return Err(CommandError::new(
            "GUI_ORGANIZER_REMOTE_NOT_READY",
            "UNAVAILABLE",
            "the external onion is reachable but the organizer intake did not answer the readiness status check yet; retry shortly",
        ));
    }

    Ok(OrganizerIntakeState {
        tor_child: None,
        mode: OrganizerTorModeV1::ExternalRemote,
        remote: Some(config.clone()),
        remote_last_ready: true,
        service_loop,
        descriptor: bundle.descriptor.clone(),
        manifest_hash_hex: bound.manifest_hash_hex.clone(),
        collector_addr,
        onion_hostname: config.onion_hostname.clone(),
        // No local Tor runtime exists in remote mode: these managed-mode
        // diagnostics are recorded as empty (never fabricated).
        tor_data_dir: PathBuf::new(),
        stderr_log: PathBuf::new(),
        voter_bundle_path: paths.voter_bundle_path.clone(),
        durable_inbox_dir,
        lifecycle_fence,
    })
}

/// Bounded timeouts for the external-remote readiness check. The SOCKS/onion
/// path can traverse a full Tor circuit over a trusted network, so these are
/// generous but strictly bounded so a dead proxy cannot wedge the UI.
fn remote_organizer_readiness_timeouts() -> TorCarrierTimeoutsV1 {
    TorCarrierTimeoutsV1 {
        socks_connect: Duration::from_secs(10),
        socks_handshake: Duration::from_secs(15),
        http_write: Duration::from_secs(20),
        http_response: Duration::from_secs(30),
    }
}

/// Bounded, safe user-facing message for a remote organizer readiness outcome.
/// Never leaks the endpoint, the onion hostname, or a raw OS error.
const fn remote_organizer_readiness_message(outcome: RemoteTorReadinessOutcomeV1) -> &'static str {
    match outcome {
        RemoteTorReadinessOutcomeV1::Ready => {
            "External remote Tor intake is ready."
        }
        RemoteTorReadinessOutcomeV1::EndpointInvalid => {
            "The remote SOCKS endpoint or organizer onion hostname is invalid."
        }
        RemoteTorReadinessOutcomeV1::Unreachable => {
            "The remote SOCKS proxy could not be reached. Check the host/port and that the proxy is running on the trusted network."
        }
        RemoteTorReadinessOutcomeV1::SocksHandshakeFailed => {
            "The remote endpoint answered but is not a usable SOCKS5 proxy."
        }
        RemoteTorReadinessOutcomeV1::OnionUnreachable => {
            "The remote proxy works but could not reach the organizer onion service yet. Retry shortly."
        }
    }
}

/// Terminates and reaps the OWNED managed-local Tor child when a startup step
/// fails AFTER the child was spawned but BEFORE it is transferred into the
/// persistent intake state. This upholds the managed-local lifecycle invariant
/// — once the app owns a spawned Tor child, every post-spawn return path either
/// transfers it into state or terminates and reaps it — so a post-spawn startup
/// failure can never orphan a `tor.exe` that keeps publishing the hidden
/// service with no handle left to stop it.
///
/// The ORIGINAL startup `error` is returned UNCHANGED (cleanup never masks the
/// real cause), and cleanup is best-effort: a kill/wait that itself fails is
/// ignored so this can never panic. Used ONLY in managed-local mode;
/// external-remote mode owns no child and never calls this.
fn reap_owned_tor_child_on_startup_error(child: &mut Child, error: CommandError) -> CommandError {
    let _ = child.kill();
    let _ = child.wait();
    error
}

/// Starts the MANAGED-LOCAL intake worker for an already-provisioned election.
/// Mirrors `private-ballot-tor-test-intake` step-for-step with the SAME
/// fail-closed ordering, calling only reviewed library functions. This mode
/// OWNS the Tor child: it is spawned here, liveness-checked, and reaped on
/// stop/shutdown.
fn start_intake_worker(
    app: &AppHandle,
    tor_executable: &Path,
    paths: &TransportPaths,
    bound: &BoundElection,
    authoritative_lifecycle: ElectionLifecycleStateV1,
) -> Result<OrganizerIntakeState, CommandError> {
    // 1. Load organizer private bundle and validate ALL bindings before Tor.
    let bundle = load_organizer_private_bundle_v1(&paths.organizer_private_dir).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_BUNDLE_MALFORMED",
            "INVALID_INPUT",
            "the organizer transport bundle could not be loaded",
        )
    })?;
    let persisted_hostname = read_persisted_hostname(&paths.hidden_service_dir);
    validate_intake_startup_v1(&bundle, &bound.artifacts, persisted_hostname.as_deref()).map_err(
        |_| {
            CommandError::new(
                "GUI_ORGANIZER_STARTUP_UNTRUSTED",
                "BINDING_MISMATCH",
                "the organizer transport bundle failed startup validation for this election",
            )
        },
    )?;

    // 2. Bind the loopback collector (bound but not yet serviced).
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_COLLECTOR_BIND_FAILED",
            "UNAVAILABLE",
            "the loopback collector could not be bound",
        )
    })?;
    let collector_addr = collector.local_addr().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_COLLECTOR_ADDR_FAILED",
            "UNAVAILABLE",
            "the loopback collector address could not be read",
        )
    })?;

    // 5. Allocate a FRESH per-start Tor DataDirectory (never the persistent
    // hidden-service directory), so an orphaned tor.exe surviving a Task-Manager
    // hard-kill of a prior app instance — which still holds the lock of the run
    // directory it was using — can never block this start. The SAME persistent
    // `hidden_service_dir` keeps the onion address/fingerprint stable across
    // restarts. Then write the intake torrc (inside the run directory) with the
    // ACTUAL collector port and launch Tor with a per-run captured stderr log.
    ensure_app_owned_directory(&paths.tor_runs_base)?;
    let run_dir = fresh_run_directory(&paths.tor_runs_base)?;
    remove_stale_run_directories(&paths.tor_runs_base, &run_dir);
    let intake_torrc = run_dir.join("organizer-intake-torrc");
    let stderr_log = run_dir.join("tor-stderr.log");
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: run_dir.clone(),
        config_file: intake_torrc.clone(),
        hidden_service_dir: paths.hidden_service_dir.clone(),
        collector_port: collector_addr.port(),
        startup_timeout: TOR_STARTUP_TIMEOUT,
    };
    tor_config.write_config().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_TORRC_FAILED",
            "FILE_IO",
            "the organizer intake Tor configuration could not be written",
        )
    })?;
    let spawner = DiagnosticTorSpawnerV1 {
        stderr_log: stderr_log.clone(),
    };
    let mut child = spawner
        .spawn(tor_executable, &intake_torrc)
        .map_err(|_| tor_start_failed())?;

    // 6. Discover the runtime hostname (bounded), watching child liveness. The
    // liveness closure mutably borrows `child`; it is moved into the discovery
    // call, releasing the borrow before any later `child.kill()`/`wait()`. The
    // early-return branch must not touch `child` while the closure holds it.
    //
    // NOTE: the hidden-service `hostname` file is PERSISTENT — on a restart it is
    // already present from the prior run, so discovery can return immediately
    // while the freshly-spawned child is still bootstrapping. That is only safe
    // because the child now runs in its OWN fresh DataDirectory and therefore
    // stays alive; the post-discovery liveness recheck below plus the status
    // command's continuous child-liveness check catch any early exit and surface
    // a bounded FAILED state instead of an indefinite "starting".
    let timeout = DiscoveryTimeoutV1::new(TOR_STARTUP_TIMEOUT);
    let mut child_alive = || {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    };
    if !child_alive() {
        let kind = classify_start_failure_from_log(&stderr_log);
        return Err(tor_start_failed().with_context(kind.as_organizer_context_label().to_owned()));
    }
    let runtime_hostname =
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let kind = classify_start_failure_from_log(&stderr_log);
                return Err(hostname_discovery_failed()
                    .with_context(kind.as_organizer_context_label().to_owned()));
            }
        };

    // 6b. Post-discovery liveness recheck: discovery can succeed off the
    // PERSISTENT hostname file before the fresh child has fully settled, so
    // confirm the owned child did not exit immediately (e.g. a residual lock or
    // config fault). A dead child here is a bounded, classified start failure —
    // never a false "running".
    if child
        .try_wait()
        .map(|status| status.is_some())
        .unwrap_or(true)
    {
        let _ = child.wait();
        let kind = classify_start_failure_from_log(&stderr_log);
        return Err(tor_start_failed().with_context(kind.as_organizer_context_label().to_owned()));
    }

    // 7. Fail-closed: runtime onion MUST equal the signed descriptor onion
    // BEFORE any request can be serviced. This runs AFTER the child is spawned,
    // so a missing onion endpoint must reap the owned child (lifecycle
    // invariant) rather than return with a live, unreferenced tor.exe.
    let descriptor_onion = match bundle.descriptor.onion_endpoints().first().cloned() {
        Some(onion) => onion,
        None => {
            return Err(reap_owned_tor_child_on_startup_error(
                &mut child,
                CommandError::new(
                    "GUI_ORGANIZER_NO_ONION",
                    "BINDING_MISMATCH",
                    "the transport descriptor has no onion endpoint",
                ),
            ));
        }
    };
    if descriptor_onion != runtime_hostname {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CommandError::new(
            "GUI_ORGANIZER_ONION_MISMATCH",
            "BINDING_MISMATCH",
            "the runtime onion hostname does not match the signed descriptor",
        ));
    }

    // 8. Only now start the collector service loop (first point a ballot could
    //    be accepted) via the SHARED service assembly, so managed-local and
    //    external-remote modes use byte-identical admission/fence/receipt
    //    logic. Accepted canonical packages flow to the durable inbox.
    //
    //    LIFECYCLE INVARIANT (managed-local): the owned Tor child is live from
    //    the spawn above. Every startup return path after the spawn must either
    //    TRANSFER the child into persistent intake state (the `Ok` arm below)
    //    or TERMINATE and reap it. The shared assembly can fail AFTER the child
    //    is live (inbox/status-dir I/O, worker-session open, service-loop start,
    //    or an immediately dead worker), so reap the owned child here before
    //    returning — otherwise an orphaned tor.exe would keep publishing the
    //    hidden service with no handle left to stop it. The ORIGINAL startup
    //    error is preserved as primary; cleanup never masks it and never
    //    panics.
    let (service_loop, durable_inbox_dir, lifecycle_fence) = match start_collector_service_shared(
        app,
        bound,
        &bundle,
        collector,
        authoritative_lifecycle,
    ) {
        Ok(shared) => shared,
        Err(error) => {
            return Err(reap_owned_tor_child_on_startup_error(&mut child, error));
        }
    };

    Ok(OrganizerIntakeState {
        tor_child: Some(child),
        mode: OrganizerTorModeV1::ManagedLocal,
        remote: None,
        remote_last_ready: false,
        service_loop,
        descriptor: bundle.descriptor.clone(),
        manifest_hash_hex: bound.manifest_hash_hex.clone(),
        collector_addr,
        onion_hostname: runtime_hostname,
        tor_data_dir: run_dir,
        stderr_log,
        voter_bundle_path: paths.voter_bundle_path.clone(),
        durable_inbox_dir,
        lifecycle_fence,
    })
}

fn reconstruct_receiver_key(
    bundle: &LoadedOrganizerPrivateBundleV1,
) -> Result<Arc<GatewayReceiverKeyV1>, CommandError> {
    let secret = bundle.material.gateway_receiver_key.secret_bytes();
    let key = GatewayReceiverKeyV1::from_secret_bytes(secret).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_RECEIVER_KEY_FAILED",
            "INVALID_INPUT",
            "the gateway receiver key could not be reconstructed",
        )
    })?;
    Ok(Arc::new(key))
}

fn read_persisted_hostname(hidden_service_dir: &Path) -> Option<String> {
    let hostname_file = hidden_service_dir.join("hostname");
    match std::fs::read_to_string(&hostname_file) {
        Ok(content) => {
            let trimmed = content.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Err(_) => None,
    }
}

fn app_data_root(app: &AppHandle) -> Result<PathBuf, CommandError> {
    app.path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())
}

// -------------------------------------------------------------------------
// Status helpers
// -------------------------------------------------------------------------

/// Builds a status for a recorded running intake. `child_alive` MUST be the
/// caller's fresh `try_wait` observation of the owned Tor child, so a dead child
/// is reported as a bounded FAILED state and never a false "running".
/// `authoritative` is the caller's fresh authoritative session lifecycle so the
/// served-vs-authoritative diagnostics are truthful at build time.
fn running_status(
    m: &OrganizerIntakeState,
    election_bound: bool,
    child_alive: bool,
    authoritative: ElectionLifecycleStateV1,
) -> OrganizerIntakeStatusV1 {
    let accepted = m.service_loop.accepted_unique_count();
    let worker_alive = m.service_loop.worker_is_alive();
    let ready = election_bound && child_alive && worker_alive;
    let failure_reason = intake_failure_reason(m, child_alive, worker_alive);
    let failed = failure_reason.is_some();
    OrganizerIntakeStatusV1 {
        tor_found: true,
        transport_provisioned: true,
        intake_running: true,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted_ballots: accepted,
        tor_mode: m.mode.as_token(),
        published_lifecycle: Some(m.lifecycle_fence.state().as_str().to_owned()),
        status_generation: Some(m.lifecycle_fence.generation()),
        authoritative_lifecycle: Some(authoritative.as_str().to_owned()),
        onion_hostname: Some(m.onion_hostname.clone()),
        descriptor_fingerprint: descriptor_fingerprint_hex(&m.descriptor),
        collector_addr: Some(m.collector_addr.to_string()),
        tor_data_dir: Some(m.tor_data_dir.to_string_lossy().into_owned()),
        voter_bundle_path: Some(m.voter_bundle_path.to_string_lossy().into_owned()),
        durable_inbox_dir: Some(m.durable_inbox_dir.to_string_lossy().into_owned()),
        message: if failed {
            "Private intake could not start."
        } else if ready {
            "Private intake ready."
        } else {
            "Private intake is starting."
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn build_status(
    tor_found: bool,
    transport_provisioned: bool,
    intake_running: bool,
    election_bound: bool,
    ready: bool,
    failed: bool,
    failure_reason: Option<String>,
    accepted: u64,
    tor_mode: &'static str,
    diag: Option<(String, Option<String>, String, String, String, String)>,
    published: Option<(ElectionLifecycleStateV1, u64)>,
    authoritative: Option<ElectionLifecycleStateV1>,
    message: &'static str,
) -> OrganizerIntakeStatusV1 {
    let (onion, fingerprint, collector, data_dir, bundle, inbox) = match diag {
        Some((o, f, c, d, b, i)) => (Some(o), f, Some(c), Some(d), Some(b), Some(i)),
        None => (None, None, None, None, None, None),
    };
    let (published_lifecycle, status_generation) = match published {
        Some((state, generation)) => (Some(state.as_str().to_owned()), Some(generation)),
        None => (None, None),
    };
    OrganizerIntakeStatusV1 {
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted_ballots: accepted,
        tor_mode,
        published_lifecycle,
        status_generation,
        authoritative_lifecycle: authoritative.map(|state| state.as_str().to_owned()),
        onion_hostname: onion,
        descriptor_fingerprint: fingerprint,
        collector_addr: collector,
        tor_data_dir: data_dir,
        voter_bundle_path: bundle,
        durable_inbox_dir: inbox,
        message,
    }
}

fn status_message(
    tor_found: bool,
    transport_provisioned: bool,
    intake_running: bool,
    election_bound: bool,
    failed: bool,
) -> &'static str {
    if failed {
        "Private intake could not start. Restart it to try again."
    } else if intake_running && !election_bound {
        "Private intake is running for a different election. Stop it to switch."
    } else if intake_running {
        "Private intake is running."
    } else if !tor_found {
        "Tor was not found. Select a Tor executable to enable private intake."
    } else if transport_provisioned {
        "Ready to start private intake."
    } else {
        "Ready to provision and start private intake."
    }
}

fn descriptor_fingerprint_hex(descriptor: &TransportDescriptorV1) -> Option<String> {
    descriptor.fingerprint().ok().map(|fp| {
        use std::fmt::Write;
        let mut out = String::with_capacity(fp.len() * 2);
        for byte in fp {
            let _ = write!(out, "{byte:02x}");
        }
        out
    })
}

fn tor_start_failed() -> CommandError {
    CommandError::new(
        "GUI_ORGANIZER_TOR_START_FAILED",
        "UNAVAILABLE",
        "tor.exe failed to start for the organizer hidden service",
    )
}

fn hostname_discovery_failed() -> CommandError {
    CommandError::new(
        "GUI_ORGANIZER_HOSTNAME_FAILED",
        "UNAVAILABLE",
        "the organizer hidden-service hostname could not be discovered",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_tor::ManagedTorStartFailureKind;

    const VALID_HASH: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const VALID_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    fn remote_input(
        mode: Option<&str>,
        host: Option<&str>,
        port: Option<u16>,
        onion: Option<&str>,
        collector: Option<u16>,
    ) -> RemoteOrganizerIntakeInputV1 {
        RemoteOrganizerIntakeInputV1 {
            tor_mode: mode.map(str::to_owned),
            socks_host: host.map(str::to_owned),
            socks_port: port,
            onion_hostname: onion.map(str::to_owned),
            collector_port: collector,
        }
    }

    #[test]
    fn default_organizer_tor_mode_is_managed_local() {
        assert_eq!(
            OrganizerTorModeV1::default(),
            OrganizerTorModeV1::ManagedLocal
        );
    }

    #[test]
    fn legacy_or_unknown_mode_token_resolves_to_managed_local() {
        // A missing/legacy/unknown persisted value must resolve to the
        // recommended managed-local mode, never silently to remote.
        for token in ["", "managed-local", "remote", "unknown", "EXTERNAL", "true"] {
            assert_eq!(
                OrganizerTorModeV1::from_token_or_default(token),
                OrganizerTorModeV1::ManagedLocal,
                "token {token:?}"
            );
        }
        assert_eq!(
            OrganizerTorModeV1::from_token_or_default("external-remote"),
            OrganizerTorModeV1::ExternalRemote
        );
        assert_eq!(
            OrganizerTorModeV1::from_token_or_default(
                OrganizerTorModeV1::ExternalRemote.as_token()
            ),
            OrganizerTorModeV1::ExternalRemote
        );
    }

    #[test]
    fn valid_remote_config_is_accepted_and_normalized() {
        let config = RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some("192.168.1.50:9050".split(':').next().unwrap()),
            Some(9050),
            Some(VALID_ONION),
            Some(18081),
        ))
        .expect("valid remote config")
        .expect("remote mode selected");
        assert_eq!(config.socks.host(), "192.168.1.50");
        assert_eq!(config.socks.port(), 9050);
        assert_eq!(config.onion_hostname, VALID_ONION);
        assert_eq!(config.collector_port, 18081);
        // A hostname endpoint is also accepted (trusted LAN/VPN naming).
        let config = RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some("tor.internal.example"),
            Some(9050),
            Some(VALID_ONION),
            Some(18081),
        ))
        .expect("hostname endpoint")
        .expect("remote mode selected");
        assert_eq!(config.socks.host(), "tor.internal.example");
    }

    #[test]
    fn absent_or_non_remote_mode_resolves_to_no_remote_config() {
        // Legacy/absent token → managed-local (no remote config), so nothing
        // ever silently activates the advanced remote path.
        for mode in [None, Some(""), Some("managed-local"), Some("bogus")] {
            let parsed = RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
                mode,
                Some("127.0.0.1"),
                Some(9050),
                Some(VALID_ONION),
                Some(18081),
            ))
            .expect("parse ok");
            assert!(parsed.is_none(), "mode {mode:?} must not select remote");
        }
    }

    #[test]
    fn malformed_remote_config_fails_closed() {
        // Malformed SOCKS endpoint (scheme).
        assert!(RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some("socks5://127.0.0.1"),
            Some(9050),
            Some(VALID_ONION),
            Some(18081),
        ))
        .is_err());
        // Port 0.
        assert!(RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some("127.0.0.1"),
            Some(0),
            Some(VALID_ONION),
            Some(18081),
        ))
        .is_err());
        // Missing host.
        assert!(RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some(""),
            Some(9050),
            Some(VALID_ONION),
            Some(18081),
        ))
        .is_err());
        // Non-v3 / invalid onion hostname.
        for bad_onion in ["", "example.com", "foo.onion", "bad host.onion"] {
            assert!(
                RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
                    Some("external-remote"),
                    Some("127.0.0.1"),
                    Some(9050),
                    Some(bad_onion),
                    Some(18081),
                ))
                .is_err(),
                "onion {bad_onion:?} must be rejected"
            );
        }
        // Collector port 0 (the remote operator must target a real port).
        assert!(RemoteOrganizerIntakeConfigV1::from_input(&remote_input(
            Some("external-remote"),
            Some("127.0.0.1"),
            Some(9050),
            Some(VALID_ONION),
            Some(0),
        ))
        .is_err());
    }

    #[test]
    fn remote_mode_owns_no_tor_process_and_no_hidden_service_directory() {
        // Source-level ownership assertion: the remote code paths must contain
        // NO process spawn, NO child kill, NO torrc generation, NO local
        // hidden-service directory creation, and NO managed SOCKS port
        // reservation. Scan ONLY the implementation (before the test module).
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        let remote_provision = code
            .split("fn provision_transport_remote")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("remote provision body");
        for forbidden in [
            "spawn(",
            "write_config",
            "create_dir_all(&paths.hidden_service_dir)",
            "create_dir_all(&paths.tor_runs_base)",
            "fresh_run_directory",
            "reserve_loopback",
        ] {
            assert!(
                !remote_provision.contains(forbidden),
                "remote provisioning must never {forbidden}"
            );
        }
        let remote_worker = code
            .split("fn start_remote_intake_worker")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("remote worker body");
        for forbidden in [
            "spawn(",
            ".kill()",
            "OrganizerHiddenServiceTorConfigV1",
            "reserve_loopback",
            "fresh_run_directory",
        ] {
            assert!(
                !remote_worker.contains(forbidden),
                "the remote worker must never {forbidden}"
            );
        }
    }

    #[test]
    fn external_remote_daemon_is_never_signalled_on_stop_or_shutdown() {
        // Stop and app-exit reap only an OWNED child (Option::take on the
        // child handle, which is always None in external-remote mode).
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        assert!(
            code.matches(".tor_child.take()").count() >= 3,
            "every teardown path must take the OWNED child option, never signal external infrastructure"
        );
        // No global/name-based kill anywhere (existing invariant, re-asserted
        // for the remote-mode changes).
        for forbidden in ["taskkill", "Stop-Process", "pkill", "killall", "/IM "] {
            assert!(!code.contains(forbidden));
        }
    }

    #[test]
    fn remote_readiness_is_endpoint_scoped_and_zero_byte_first() {
        // Readiness ordering inside the remote worker: bind gate → descriptor
        // equality gate → zero-application-byte probe → public status GET, and
        // only then a ready state.
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        let worker_start = code
            .find("fn start_remote_intake_worker")
            .expect("remote worker");
        let worker = &code[worker_start..code
            .find("fn remote_organizer_readiness_timeouts")
            .expect("timeouts helper")];
        let bind_gate = worker
            .find("descriptor_onion != config.onion_hostname")
            .expect("descriptor onion equality gate");
        let probe = worker
            .find("probe_remote_onion_hostname_v1")
            .expect("zero-byte probe");
        let status = worker
            .find("fetch_election_status_over_remote_tor_onion")
            .expect("status fetch");
        assert!(bind_gate < probe && probe < status);
        // The state stores readiness against the EXACT validated config only.
        assert!(worker.contains("remote: Some(config.clone())"));
        assert!(worker.contains("remote_last_ready: true"));
    }

    /// Spawns a real, long-lived OS child to stand in for the owned Tor process
    /// in lifecycle tests. Portable: `ping` on Windows, `sleep` elsewhere. The
    /// test always reaps it, so the long duration is never actually waited.
    fn spawn_blocking_test_child() -> Child {
        let mut command = if cfg!(windows) {
            let mut c = std::process::Command::new("ping");
            c.args(["-n", "30", "127.0.0.1"]);
            c
        } else {
            let mut c = std::process::Command::new("sleep");
            c.arg("30");
            c
        };
        command.spawn().expect("spawn long-lived stand-in child process")
    }

    // MED-1 regression: a managed-local startup failure that occurs AFTER the
    // owned Tor child has spawned (e.g. durable-inbox/status-dir I/O failure,
    // worker-session open failure, service-loop start failure, or an
    // immediately dead worker surfaced by `start_collector_service_shared`)
    // must TERMINATE and REAP the owned child before returning — never orphan a
    // live `tor.exe`. Before the fix, the error arm dropped the live `Child`
    // (which does NOT kill on drop) without the child ever being stored in
    // intake state, so stop/shutdown could never recover it.
    #[test]
    fn managed_startup_error_after_spawn_reaps_owned_tor_child() {
        let mut child = spawn_blocking_test_child();
        // Sanity: the stand-in child is genuinely alive before cleanup.
        assert!(
            child
                .try_wait()
                .expect("try_wait before reap")
                .is_none(),
            "the stand-in owned child must be alive before the reap"
        );

        let original = CommandError::new(
            "GUI_ORGANIZER_WORKER_DEAD",
            "UNAVAILABLE",
            "the collector service worker exited immediately on start",
        );
        let returned = reap_owned_tor_child_on_startup_error(&mut child, original.clone());

        // 1. The ORIGINAL startup error is returned unchanged (cleanup never
        //    masks or rewrites the real cause).
        assert_eq!(returned, original);
        // 2. The owned child has been terminated and reaped — not orphaned.
        //    `wait()` inside the helper caches the exit status, so a follow-up
        //    `try_wait()` observes a concrete exit rather than `None`.
        assert!(
            child
                .try_wait()
                .expect("try_wait after reap")
                .is_some(),
            "a post-spawn startup failure must terminate and reap the owned Tor child"
        );
    }

    // Source-shape supplement to the behavioral test above: the managed-local
    // worker's shared-assembly error arm must route through the owned-child
    // reaper, and the only `Ok` arm transfers the child into intake state.
    #[test]
    fn managed_shared_assembly_error_arm_reaps_the_owned_child() {
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        let worker_start = code
            .find("fn start_intake_worker")
            .expect("managed worker");
        let worker = &code[worker_start..];
        // The post-spawn shared-assembly failure is handled by the reaper,
        // which returns the original error; the success path stores the child.
        assert!(
            worker.contains("reap_owned_tor_child_on_startup_error(&mut child, error)"),
            "the managed shared-assembly error arm must reap the owned child"
        );
        assert!(
            worker.contains("tor_child: Some(child)"),
            "the managed success path must transfer the owned child into state"
        );
    }

    fn app_root() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\app-data-root"
        } else {
            "/app-data-root"
        })
    }

    #[test]
    fn transport_root_is_app_owned_and_election_scoped() {
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("valid hash");
        assert!(root.starts_with(app_root()));
        assert!(
            root.ends_with(format!("election-{VALID_HASH}")),
            "root must be scoped to the election manifest hash: {}",
            root.display()
        );
        assert!(
            root.to_string_lossy()
                .contains(ORGANIZER_TOR_ROOT_DIRECTORY_NAME),
            "root must live under the app-owned private-tor directory"
        );
    }

    #[test]
    fn different_elections_get_different_roots() {
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        let a = election_transport_subpath(&app_root(), VALID_HASH).expect("a");
        let b = election_transport_subpath(&app_root(), other).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn non_hex_manifest_hash_cannot_control_storage() {
        // Uppercase, wrong length, path traversal, and separators all rejected —
        // no remote/arbitrary value can steer the storage path.
        for bad in [
            "..",
            "../../etc",
            "election-1/../../secret",
            "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
            "short",
            "zz112233445566778899001122334455667788990011223344556677889900",
            "aabb/ccdd",
        ] {
            let error = election_transport_subpath(&app_root(), bad)
                .expect_err("non-canonical hash must reject");
            assert_eq!(error.code, "GUI_ORGANIZER_TOR_INVALID_ELECTION");
        }
    }

    #[test]
    fn transport_paths_never_place_private_material_in_the_voter_bundle() {
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let paths = TransportPaths::under(&root);
        // The exported artifact is exactly the voter PUBLIC bundle; the private
        // material lives in a separate organizer-private directory.
        assert!(
            paths
                .voter_bundle_path
                .ends_with("voter-public-bundle.cbor")
        );
        assert!(paths.organizer_private_dir.ends_with("organizer-private"));
        assert_ne!(paths.voter_bundle_path, paths.organizer_private_dir);
        assert!(
            !paths
                .voter_bundle_path
                .starts_with(&paths.organizer_private_dir)
        );
    }

    #[test]
    fn tor_runtime_datadirectory_is_split_from_the_persistent_identity() {
        // The onion identity (hidden-service directory) MUST be a fixed,
        // election-scoped, persistent path so the onion address/fingerprint are
        // stable across restarts. The Tor runtime DataDirectory MUST NOT be that
        // same fixed path: it lives under a distinct per-start run base so an
        // orphaned tor.exe holding a prior run's lock cannot block the next start
        // (mirrors the voter-side hard-kill defence).
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let paths = TransportPaths::under(&root);
        assert!(
            paths
                .hidden_service_dir
                .ends_with("organizer-hidden-service")
        );
        assert!(paths.tor_runs_base.ends_with("organizer-tor-runs"));
        assert_ne!(paths.hidden_service_dir, paths.tor_runs_base);
        assert!(!paths.tor_runs_base.starts_with(&paths.hidden_service_dir));
        assert!(!paths.hidden_service_dir.starts_with(&paths.tor_runs_base));
    }

    #[test]
    fn organizer_failure_labels_are_bounded_prefixed_and_path_free() {
        use ManagedTorStartFailureKind::*;
        for kind in [
            DataDirectoryLock,
            PortBindFailure,
            ConfigError,
            ExitedEarly,
            ReadinessTimeout,
        ] {
            let label = kind.as_organizer_context_label();
            assert!(
                label.starts_with("organizer-"),
                "organizer-prefixed: {label}"
            );
            assert!(
                !label.contains('/') && !label.contains('\\'),
                "path-free: {label}"
            );
        }
        // A datadir-lock is the exact orphan-after-hard-kill signature.
        assert_eq!(
            DataDirectoryLock.as_organizer_context_label(),
            "organizer-tor-datadir-lock"
        );
    }

    #[test]
    fn status_message_guides_the_operator_through_each_state() {
        assert!(status_message(false, false, false, false, false).contains("Tor was not found"));
        assert_eq!(
            status_message(true, false, false, false, false),
            "Ready to provision and start private intake."
        );
        assert_eq!(
            status_message(true, true, false, false, false),
            "Ready to start private intake."
        );
        assert_eq!(
            status_message(true, true, true, true, false),
            "Private intake is running."
        );
        assert!(
            status_message(true, true, true, false, false).contains("different election"),
            "a running intake bound to another election must be called out"
        );
        // A failed intake must never read as "running" or "starting"; it is an
        // explicit, recoverable state — even when intake_running is still set.
        let failed = status_message(true, true, true, true, true);
        assert!(
            failed.contains("could not start"),
            "failed state is explicit: {failed}"
        );
        assert!(!failed.contains("running"));
    }

    #[test]
    fn descriptor_root_directory_name_is_backend_controlled() {
        // The only dynamic path component is the validated hash; the parent
        // directory name is a fixed backend constant.
        assert_eq!(ORGANIZER_TOR_ROOT_DIRECTORY_NAME, "private-tor");
    }

    #[test]
    fn orphan_datadir_lock_signature_maps_to_a_bounded_organizer_reason() {
        // The exact orphan-after-hard-kill diagnostic path: a fresh child whose
        // DataDirectory lock is still held by a surviving orphan writes a
        // "could not lock ... another Tor" stderr; classification must yield the
        // bounded, path-free organizer datadir-lock reason surfaced as the
        // FAILED status reason (never an indefinite "starting").
        let base = std::env::temp_dir().join(format!(
            "tari-organizer-intake-failreason-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp base");
        let log = base.join("tor-stderr.log");
        std::fs::write(
            &log,
            b"[warn] Could not lock data directory. Is another Tor process running?\n",
        )
        .expect("write stderr log");
        let reason = classify_start_failure_from_log(&log).as_organizer_context_label();
        assert_eq!(reason, "organizer-tor-datadir-lock");

        // A missing/empty stderr log is a bounded readiness-timeout reason, never
        // a panic and never an unbounded string.
        let missing = base.join("no-such-run").join("tor-stderr.log");
        assert_eq!(
            classify_start_failure_from_log(&missing).as_organizer_context_label(),
            "organizer-readiness-timeout"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn organizer_cleanup_is_ownership_scoped_never_a_global_tor_kill() {
        // Ownership-scope guarantee (defence against a regression that would kill
        // an unrelated Tor Browser / user Tor / another election): this module
        // must NEVER terminate Tor by process NAME or via a shell. Cleanup is
        // limited to the app-owned run directories and the app's OWN Child
        // handles (kill()/wait()), which target only processes this app spawned.
        // Scan ONLY the implementation (everything before the test module) so
        // this test's own list of forbidden literals below cannot match itself.
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        for forbidden in [
            "taskkill",
            "Stop-Process",
            "Get-Process",
            "/IM ",
            "/im ",
            "pkill",
            "killall",
        ] {
            assert!(
                !code.contains(forbidden),
                "organizer Tor lifecycle must never use `{forbidden}` (global/name-based kill)"
            );
        }
        // The only process termination is on an owned std::process::Child
        // handle, taken out of the Option so a remote-mode run (None) has
        // nothing to terminate.
        assert!(code.contains("tor_child.take()"));
        assert!(code.contains("child.kill()"));
    }

    #[test]
    fn restart_never_rotates_the_onion_identity() {
        // No-onion-rotation invariant: provisioning (which generates the onion
        // identity) is gated behind `!is_provisioned()`, so a restart of an
        // already-provisioned election reuses the persistent hidden-service
        // directory and NEVER creates a new identity. The hidden-service
        // directory is also a deterministic function of the election root, so two
        // "starts" resolve the SAME identity path.
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        assert!(
            code.contains("if !paths.is_provisioned()"),
            "the onion identity must be provisioned once, never regenerated on restart"
        );
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let a = TransportPaths::under(&root).hidden_service_dir;
        let b = TransportPaths::under(&root).hidden_service_dir;
        assert_eq!(
            a, b,
            "the hidden-service identity path is stable across starts"
        );
    }

    /// Creates a unique bounded temporary status directory for issuance-ledger
    /// assertions.
    fn temp_status_dir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tari-organizer-intake-reconcile-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp status dir");
        base
    }

    fn issued_generation(dir: &Path, hash: &str) -> u64 {
        read_issued_status_generation_v1(dir, hash).expect("issued generation readable")
    }

    fn seed_ledger(dir: &Path, hash: &str, through_generation: u64) {
        for expected in 1..=through_generation {
            let reserved = reserve_next_status_generation_v1(dir, hash).expect("seed reservation");
            assert_eq!(reserved, expected);
        }
    }

    #[test]
    fn reconcile_unchanged_state_is_a_no_op_without_ledger_growth() {
        // Heartbeat cost contract: the every-few-seconds reconciliation MUST be
        // a pure in-memory compare when authority already agrees with the fence
        // — no reservation write, no generation movement.
        let dir = temp_status_dir("noop");
        let hash = VALID_HASH;
        seed_ledger(&dir, hash, 3);
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 3);
        reconcile_intake_lifecycle(hash, &fence, ElectionLifecycleStateV1::Frozen, Some(&dir));
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Frozen);
        assert_eq!(fence.generation(), 3);
        assert_eq!(
            issued_generation(&dir, hash),
            3,
            "an unchanged reconcile must never touch the durable issuance ledger"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reconcile_heals_a_lost_open_publication_without_restart() {
        // Physical regression shape (`lifecycle-auto-refresh-01`): intake is
        // running FROZEN (seed generation durably reserved per the root-cause
        // fix), the organizer commits OPEN but the push publication is lost,
        // and the ballot office keeps serving signed FROZEN. The heartbeat
        // reconciliation must converge served truth to authoritative truth on
        // the SAME running collector, continuing the durable ledger.
        let dir = temp_status_dir("heal");
        let hash = VALID_HASH;
        seed_ledger(&dir, hash, 1);
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 1);

        // Lost publish: the organizer is OPEN but nothing observed it.
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Frozen);

        // Heartbeat heals: strictly past the served FROZEN generation.
        reconcile_intake_lifecycle(hash, &fence, ElectionLifecycleStateV1::Open, Some(&dir));
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Open);
        assert_eq!(fence.generation(), 2);
        assert_eq!(issued_generation(&dir, hash), 2);

        // Idempotent repeats stay stable (no churn while OPEN persists).
        reconcile_intake_lifecycle(hash, &fence, ElectionLifecycleStateV1::Open, Some(&dir));
        assert_eq!(fence.generation(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn startup_frozen_statement_generation_never_collides_with_the_first_transition() {
        // THE ROOT-CAUSE REGRESSION of the two-computer physical failure.
        // Before the fix, the intake fence was seeded from the RAW ledger value
        // N, so the first reserved transition minted read+1 == N and the served
        // OPEN statement repeated the FROZEN statement's generation. A voter
        // that had applied FROZEN@N then rejected every OPEN@N forever
        // (ConflictingGeneration), surviving all restarts. With the seed
        // reserved like any other issuance, the walk below must hold: the same
        // voter knowledge that consumed FROZEN@1 accepts the reconciled OPEN
        // statement, and the offline export that follows never repeats a
        // generation either.
        let dir = temp_status_dir("collision");
        let hash = VALID_HASH;
        // Intake start reserves its seed generation (the fix).
        let seed = reserve_next_status_generation_v1(&dir, hash).expect("seed reservation");
        assert_eq!(seed, 1);
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, seed);
        assert_eq!(fence.generation(), 1);

        // A voter consumed the served signed FROZEN@1 statement.
        let mut knowledge =
            tari_cc_private_ballot_gui_core::ElectionStatusKnowledgeV1::from_accepted(
                ElectionLifecycleStateV1::Frozen,
                fence.generation(),
            );

        // The organizer commits OPEN; the heartbeat/publisher continues the
        // ledger instead of repeating generation 1.
        reconcile_intake_lifecycle(hash, &fence, ElectionLifecycleStateV1::Open, Some(&dir));
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Open);
        let open_generation = fence.generation();
        assert!(
            open_generation > 1,
            "OPEN must carry a STRICTLY greater generation than the served FROZEN statement"
        );

        // That same voter must accept the newer statement (this exact plan()
        // call failed with ConflictingGeneration before the fix).
        let target = knowledge
            .plan(
                ElectionLifecycleStateV1::Open,
                open_generation,
                ElectionLifecycleStateV1::Frozen,
            )
            .expect("voter that applied FROZEN must accept the newer OPEN statement");
        assert_eq!(target, ElectionLifecycleStateV1::Open);

        // And a later offline export still continues the same ledger space.
        let export = reserve_next_status_generation_v1(&dir, hash).expect("export reservation");
        assert!(export > open_generation);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reconcile_sequence_frozen_open_closed_is_strictly_monotonic() {
        // Required lifecycle walk on ONE running intake: FROZEN -> OPEN ->
        // CLOSED without a restart; every newer state must carry a strictly
        // increasing generation so voter-side monotonic application accepts it.
        let dir = temp_status_dir("walk");
        let hash = VALID_HASH;
        seed_ledger(&dir, hash, 1);
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 1);
        let mut previous = fence.generation();
        for authoritative in [
            ElectionLifecycleStateV1::Open,
            ElectionLifecycleStateV1::Closed,
        ] {
            reconcile_intake_lifecycle(hash, &fence, authoritative, Some(&dir));
            assert_eq!(fence.state(), authoritative);
            assert!(
                fence.generation() > previous,
                "generations must strictly advance across reconciled transitions"
            );
            previous = fence.generation();
        }
        assert_eq!(previous, 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reconcile_without_a_status_directory_still_advances_monotonically() {
        // Fail-safe fallback: an unusable issuance ledger must not block the
        // heal — the fence's internal monotonic bump keeps statements signable
        // and forward-only.
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 5);
        reconcile_intake_lifecycle(VALID_HASH, &fence, ElectionLifecycleStateV1::Open, None);
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Open);
        assert_eq!(fence.generation(), 6);
    }

    #[test]
    fn reconcile_authority_wins_after_a_failed_close_commit() {
        // Inverse direction (safe-direction over-refusal): if CLOSE was fenced
        // before a commit that then failed, authority remains OPEN. A later
        // heartbeat must restore the served truth to OPEN so signed answers
        // never keep lying about a transition that never committed.
        let dir = temp_status_dir("authority");
        let hash = VALID_HASH;
        seed_ledger(&dir, hash, 5);
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Open, 4);
        fence.observe(ElectionLifecycleStateV1::Closed, Some(5));
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Closed);
        reconcile_intake_lifecycle(hash, &fence, ElectionLifecycleStateV1::Open, Some(&dir));
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Open);
        assert_eq!(fence.generation(), 6);
        std::fs::remove_dir_all(&dir).ok();
    }

    // -------------------------------------------------------------------------
    // Durable transport archive-binding recovery (Blocker B): reconstruct the
    // authoritative finalized binding from durable state alone (signed
    // election-scoped descriptor + content-addressed private-intake inbox), with
    // NO running intake worker. Fully offline; no Tor, no network.
    // -------------------------------------------------------------------------

    use tari_cc_private_ballot_gui_core::ballot_package_digest_hex_v1;

    /// Bytes of `VALID_HASH` — a valid 32-byte manifest hash whose lowercase hex
    /// is exactly `VALID_HASH`, so a provisioned descriptor binds this election.
    const VALID_HASH_BYTES: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];
    const RECOVERY_TEST_ONION: &str =
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    fn temp_app_data_root(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tari-organizer-binding-recovery-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp app-data root");
        base
    }

    /// Provisions a real signed organizer descriptor bundle for `VALID_HASH`
    /// under `app_data_root` (no Tor: the onion hostname is supplied directly).
    fn provision_election_descriptor(app_data_root: &Path) {
        let root = election_transport_subpath(app_data_root, VALID_HASH).expect("election root");
        let paths = TransportPaths::under(&root);
        std::fs::create_dir_all(&paths.organizer_private_dir).expect("private dir");
        std::fs::create_dir_all(paths.voter_bundle_path.parent().expect("parent")).expect("bundle parent");
        let binding = TransportElectionBindingV1 {
            election_id: b"recovery-test-election".to_vec(),
            manifest_hash: VALID_HASH_BYTES,
        };
        let material =
            generate_transport_authority_material_v1("test-root".to_owned()).expect("material");
        provision_organizer_transport_bundles_v1(
            &paths.organizer_private_dir,
            &paths.voter_bundle_path,
            &material,
            &binding,
            RECOVERY_TEST_ONION.to_owned(),
            &root.join("tor-data"),
            &paths.hidden_service_dir,
        )
        .expect("provision bundle");
    }

    /// Writes `count` synthetic accepted packages into the durable inbox,
    /// content-addressed exactly as the collector would.
    fn seed_inbox_packages(app_data_root: &Path, count: usize) {
        let inbox = private_intake_inbox_directory_v1(app_data_root, VALID_HASH).expect("inbox path");
        std::fs::create_dir_all(&inbox).expect("inbox dir");
        for index in 0..count {
            let bytes = format!("recovery-package-{index}").into_bytes();
            let digest_hex = ballot_package_digest_hex_v1(&bytes);
            std::fs::write(inbox.join(format!("{digest_hex}.package")), &bytes).expect("write pkg");
        }
    }

    #[test]
    fn durable_recovery_missing_descriptor_is_none() {
        // No provisioned transport for this election => no authoritative binding
        // provenance. The archive command reports REQUIRED (a capability limit),
        // never a fabricated binding.
        let root = temp_app_data_root("missing-descriptor");
        let recovered = recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 0)
            .expect("recovery must not error when nothing is provisioned");
        assert!(recovered.is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_reconstructs_binding_from_inbox() {
        // The forward + recovery invariant: a provisioned election with a durable
        // content-addressed inbox reconstructs the authoritative finalized binding
        // deterministically, with NO running intake worker.
        let root = temp_app_data_root("reconstruct");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 7);
        let binding = recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 7)
            .expect("recovery succeeds")
            .expect("a non-empty inbox yields a binding");
        assert_eq!(binding.manifest_hash().as_bytes(), &VALID_HASH_BYTES);
        let accepted: u64 = binding
            .batches()
            .iter()
            .map(|batch| batch.accepted_unique_count())
            .sum();
        assert_eq!(accepted, 7, "the binding must cover every durable accepted package");

        // Determinism: a second recovery over the same durable state is identical.
        let again = recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 7)
            .expect("second recovery succeeds")
            .expect("still a binding");
        assert_eq!(binding, again, "recovery is deterministic across calls");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_empty_inbox_with_accepted_count_fails_closed() {
        // Internally inconsistent authoritative state: the session recorded
        // accepted ballots but the durable inbox is empty. Never invent a binding.
        let root = temp_app_data_root("empty-inbox");
        provision_election_descriptor(&root);
        let inbox = private_intake_inbox_directory_v1(&root, VALID_HASH).expect("inbox path");
        std::fs::create_dir_all(&inbox).expect("empty inbox dir");
        let result = recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 5);
        assert!(result.is_err(), "an empty inbox with accepted>0 must fail closed");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_rejects_tampered_inbox_package() {
        // On-disk tampering: a package file whose bytes do not match its
        // content-address digest must fail closed (never reach the binding math).
        let root = temp_app_data_root("tampered");
        provision_election_descriptor(&root);
        let inbox = private_intake_inbox_directory_v1(&root, VALID_HASH).expect("inbox path");
        std::fs::create_dir_all(&inbox).expect("inbox dir");
        // A well-formed digest filename whose content hashes to something else.
        let honest = b"honest-bytes".to_vec();
        let name = format!("{}.package", ballot_package_digest_hex_v1(&honest));
        std::fs::write(inbox.join(name), b"TAMPERED-DIFFERENT-BYTES").expect("write tampered");
        let result = recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 1);
        assert!(result.is_err(), "a tampered inbox package must fail closed");
        std::fs::remove_dir_all(&root).ok();
    }

    /// Provisions a signed organizer descriptor under the `VALID_HASH` transport
    /// path whose INTERNAL binding commits to a DIFFERENT election manifest hash,
    /// so durable recovery for `VALID_HASH` loads a descriptor that does not bind
    /// this election (exercises the wrong-election fail-closed branch).
    fn provision_wrong_election_descriptor(app_data_root: &Path, foreign_manifest: [u8; 32]) {
        let root = election_transport_subpath(app_data_root, VALID_HASH).expect("election root");
        let paths = TransportPaths::under(&root);
        std::fs::create_dir_all(&paths.organizer_private_dir).expect("private dir");
        std::fs::create_dir_all(paths.voter_bundle_path.parent().expect("parent"))
            .expect("bundle parent");
        let binding = TransportElectionBindingV1 {
            election_id: b"wrong-election".to_vec(),
            manifest_hash: foreign_manifest,
        };
        let material =
            generate_transport_authority_material_v1("test-root".to_owned()).expect("material");
        provision_organizer_transport_bundles_v1(
            &paths.organizer_private_dir,
            &paths.voter_bundle_path,
            &material,
            &binding,
            RECOVERY_TEST_ONION.to_owned(),
            &root.join("tor-data"),
            &paths.hidden_service_dir,
        )
        .expect("provision wrong-election bundle");
    }

    #[test]
    fn durable_recovery_matching_count_100_succeeds() {
        // Authoritative accepted = 100 and recovered packages = 100: the durable
        // integrity gate passes and the authoritative binding is reconstructed.
        let root = temp_app_data_root("match-100");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 100);
        let binding =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 100)
                .expect("recovery succeeds when counts agree")
                .expect("a full inbox yields a binding");
        let accepted: u64 = binding
            .batches()
            .iter()
            .map(|batch| batch.accepted_unique_count())
            .sum();
        assert_eq!(accepted, 100, "the binding must cover every durable accepted package");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_undercount_100_vs_99_fails_closed() {
        // Partially-lost durable inbox: authoritative accepted = 100 but only 99
        // package digests survive. Recovery MUST fail closed BEFORE sealing so no
        // smaller-but-valid canonical archive can be written; the specific
        // count-mismatch code proves the durable-integrity gate fired (not the
        // generic seal-unavailable path).
        let root = temp_app_data_root("under-100-99");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 99);
        let error =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 100)
                .expect_err("99 recovered vs 100 authoritative must fail closed");
        assert_eq!(error.code, "GUI_TRANSPORT_ARCHIVE_BINDING_COUNT_MISMATCH");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_overcount_99_vs_100_fails_closed() {
        // The inverse inconsistency: authoritative accepted = 99 but 100 durable
        // package digests are present. Recovery MUST also fail closed — the
        // recovered set must EQUAL the authoritative tally, never merely bound it.
        let root = temp_app_data_root("over-99-100");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 100);
        let error =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 99)
                .expect_err("100 recovered vs 99 authoritative must fail closed");
        assert_eq!(error.code, "GUI_TRANSPORT_ARCHIVE_BINDING_COUNT_MISMATCH");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_zero_accepted_zero_packages_is_none() {
        // Preserved intended semantics: no accepted ballots and an empty durable
        // inbox is a valid "nothing to bind" result (Ok(None)), never an error and
        // never a fabricated binding. The count gate is not reached (empty inbox).
        let root = temp_app_data_root("zero-zero");
        provision_election_descriptor(&root);
        let inbox = private_intake_inbox_directory_v1(&root, VALID_HASH).expect("inbox path");
        std::fs::create_dir_all(&inbox).expect("empty inbox dir");
        let recovered =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 0)
                .expect("zero accepted with an empty inbox is not an error");
        assert!(recovered.is_none(), "nothing accepted => nothing to bind");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_positive_accepted_zero_packages_still_fails_closed() {
        // Existing fail-closed behavior is preserved by the count gate's sibling
        // empty-inbox branch: authoritative accepted > 0 with zero durable
        // packages must never produce a binding.
        let root = temp_app_data_root("positive-zero");
        provision_election_descriptor(&root);
        let inbox = private_intake_inbox_directory_v1(&root, VALID_HASH).expect("inbox path");
        std::fs::create_dir_all(&inbox).expect("empty inbox dir");
        let result =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 100);
        assert!(result.is_err(), "accepted>0 with an empty inbox must fail closed");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_count_mismatch_precedes_archive_seal() {
        // Evidence for "the mismatch is caught BEFORE canonical archive creation":
        // the recovery function is the fail-closed gate the archive-write path
        // depends on, and on a count mismatch it returns the COUNT_MISMATCH code
        // WITHOUT ever calling the seal primitive
        // (`finalized_transport_archive_binding_from_accepted_digests_v1`) that a
        // successful binding would flow into. Because the canonical archive is
        // only written by the caller AFTER a successful binding is returned, a
        // COUNT_MISMATCH error means no archive-eligible binding — and therefore
        // no canonical archive file — can be produced.
        let root = temp_app_data_root("precede-seal");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 5);
        let error =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 6)
                .expect_err("a count mismatch must fail closed before sealing");
        assert_eq!(
            error.code, "GUI_TRANSPORT_ARCHIVE_BINDING_COUNT_MISMATCH",
            "the gate must fire before the seal, not report a generic seal failure",
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_wrong_election_descriptor_fails_closed() {
        // Defense in depth preserved: a persisted descriptor that does not bind
        // THIS election is rejected, independent of the accepted-count gate.
        let mut foreign = VALID_HASH_BYTES;
        foreign[0] ^= 0xff; // any manifest hash distinct from VALID_HASH
        let root = temp_app_data_root("wrong-election");
        provision_wrong_election_descriptor(&root, foreign);
        seed_inbox_packages(&root, 3);
        let result =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 3);
        assert!(result.is_err(), "a wrong-election descriptor must fail closed");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn durable_recovery_matches_shared_finalize_when_counts_agree() {
        // Equivalence: when the count gate passes, recovery seals the SAME binding
        // the shared finalize primitive produces over the identical durably-read
        // accepted digest set (the same primitive proven digest-equivalent to a
        // live gateway finalize). The integrity gate is transparent on the
        // matching path — it only adds a fail-closed guard, never divergence.
        let root = temp_app_data_root("equiv-finalize");
        provision_election_descriptor(&root);
        seed_inbox_packages(&root, 4);
        let recovered =
            recover_finalized_transport_binding_from_durable_state_under(&root, VALID_HASH, 4)
                .expect("recovery succeeds")
                .expect("a non-empty inbox yields a binding");
        // Reconstruct the expected binding directly from the same durable inputs.
        let private_dir = election_transport_subpath(&root, VALID_HASH)
            .expect("election root")
            .join("organizer-private");
        let bundle = load_organizer_private_bundle_v1(&private_dir).expect("bundle loads");
        let inbox = private_intake_inbox_directory_v1(&root, VALID_HASH).expect("inbox path");
        let digests = read_accepted_package_digests_v1(&inbox).expect("digests read");
        let direct = finalized_transport_archive_binding_from_accepted_digests_v1(
            &bundle.descriptor,
            &digests,
        )
        .expect("shared finalize succeeds")
        .expect("a non-empty set yields a binding");
        assert_eq!(recovered, direct, "recovery must equal the shared live-finalize binding");
        std::fs::remove_dir_all(&root).ok();
    }
}
