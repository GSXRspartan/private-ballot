#![forbid(unsafe_code)]

//! Hosted/Web backend (Stage 2).
//!
//! Locally runnable end-to-end hosted Private Ballot prototype. The backend
//! independently verifies every submitted canonical ballot package using the
//! shared domain core (`verifier`/`crypto`/`ballot`/`protocol`), enforces
//! nullifier uniqueness and transport idempotency, persists only public
//! election packages and opaque canonical ballot packages (which by protocol
//! design use PUBLIC ballot confidentiality - selections are public in the
//! canonical package and in every Desktop archive; voter identity linkage is
//! protected by Triptych anonymous membership, and voter secret keys /
//! witnesses NEVER reach this backend), and finalizes elections into the
//! EXISTING canonical archive format verifiable by the Desktop verifier.
//!
//! Security posture: binds to `127.0.0.1` by default, never `0.0.0.0` unless
//! explicitly opted in; request bodies size-bounded; errors carry no secrets;
//! no request-body, secret, or full-IP logging; ballot/receipt responses are
//! `private, no-store`; no wildcard CORS (same-origin only, no CORS layer).
//!
//! Three control planes: the PUBLIC plane (`127.0.0.1:8788` by
//! default) serves voter-facing routes PLUS self-service organizer routes
//! authorized by election-scoped capability credentials (`POST
//! /api/v1/organizer/elections` and election-scoped lifecycle mutations
//! under `/api/v1/organizer/...`); an organizer credential authorizes only
//! its own election and never grants server-global administration. The
//! public plane is the only listener the Cloudflare Tunnel may route to.
//! The ADMIN plane (`127.0.0.1:8789` by default) serves the global
//! organizer/admin mutation routes, is always loopback-only, and must
//! never be routed through Cloudflare; it exists for
//! infrastructure/emergency/legacy operations. The public plane has no
//! global-admin routes at all (404), so public admin access fails even if
//! edge blocking fails. When `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN` is set,
//! the public plane additionally requires the Worker-injected
//! `x-private-ballot-origin` header (`/health` exempt for Tunnel checks);
//! the token is never in browser JavaScript. Unset token = local dev, no
//! header check.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderName, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use crate::authority_signer::{AuthoritySigner, LocalEd25519AuthoritySigner};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_anchor::{
    OotleAnchorPublicPayloadV2, OotleAnchorTallyEntryV2, OotleAnchorTemplateBindingV2,
    OotleNetworkIdV1,
};
use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveHashV1,
    ArchiveManifestV1, ArchivePathV1, CANDIDATE_SET_ARCHIVE_PATH, ELECTION_MANIFEST_ARCHIVE_PATH,
    SUBMISSIONS_ARCHIVE_DIR, TRANSPORT_ARCHIVE_BINDING_PATH_V1, TransportArchiveBindingV1,
    VOTER_REGISTRY_ARCHIVE_PATH, verify_archive_directory_v1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateId,
    CandidateSet, ElectionId, ElectionManifest, ElectionManifestV1, ElectionManifestV1Input,
    ElectionManifestV2, ElectionManifestV2Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    DesktopBindingHandoffV1, GOVERNANCE_PIN_PREFIX_BLAKE3, GuiElectionArtifactsV1,
    HostedBindingRequestV1, HostedDescriptorRequestV1, HostedDescriptorResponseV1,
    HostedOrganizerBootstrapV1, HostedVoterPublicBundleV2, TransportAuthorityRootV1,
    TransportDescriptorV1, production_transport_authority_root_v1,
    provision_production_transport_authority_root_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, HashProvider, MAX_CANDIDATE_ID_BYTES, MAX_CANDIDATES,
    PROTOCOL_VERSION_V1, RegistryCommitment, ValidationCode, hash_domain_separated,
};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
};
use tari_cc_private_ballot_tally::ApprovalTally;
use tari_cc_private_ballot_transport_gateway::finalized_transport_archive_binding_from_accepted_digests_v1;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, build_tari_triptych_verifier_from_registry_v1,
    ingest_approval_ballot_package_v1,
};

pub use tari_cc_private_ballot_deployment_registry as deployment_registry;

pub mod storage;
pub mod authority_signer;
pub use storage::{HostedStorage, InMemoryStorage, SqliteStorage, StorageError};

/// Loopback bind address used when no configuration overrides it.
pub const DEFAULT_BIND: &str = "127.0.0.1:8788";
/// Loopback bind address for the admin plane when no configuration overrides
/// it. Always loopback-only; never routed through Cloudflare.
pub const DEFAULT_ADMIN_BIND: &str = "127.0.0.1:8789";
/// Header the Cloudflare Worker injects on public-plane `/api/*` requests
/// when origin-token authentication is enabled. Never set by the browser.
pub const ORIGIN_TOKEN_HEADER: &str = "x-private-ballot-origin";
/// Maximum accepted request body (64 KiB).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Stricter per-route limit for ballot submissions.
pub const MAX_BALLOT_BODY_BYTES: usize = 32 * 1024;
pub const SCHEMA_VERSION: i64 = 5;
/// Domain separator for the election-scoped organizer capability verifier.
/// The verifier is BLAKE3 over `{domain}\0{election_id}\0{secret_bytes}`;
/// the plaintext organizer secret is never stored server-side.
pub const ORGANIZER_CAPABILITY_DOMAIN: &str = "private-ballot-organizer-capability-v1";
/// Header carrying the election-scoped organizer capability secret hex on
/// organizer routes of the public plane. Never used for the global admin
/// plane (which keeps `x-admin-token`), never logged, never persisted.
pub const ORGANIZER_CREDENTIAL_HEADER: &str = "x-private-ballot-organizer";
/// Default maximum voter-slot count for self-service (organizer-plane)
/// election creation. Much safer than the admin-plane 100,000 maximum;
/// operators may raise it via PRIVATE_BALLOT_HOSTED_ORGANIZER_MAX_SLOTS.
pub const DEFAULT_ORGANIZER_MAX_SLOTS: i64 = 1_000;
/// Hard upper bound for the self-service voter-slot limit regardless of
/// configuration (matches the admin-plane maximum).
pub const MAX_ORGANIZER_SLOTS_LIMIT: i64 = 100_000;

#[derive(Clone, PartialEq, Eq)]
pub struct HostedConfig {
    pub bind: String,
    pub admin_bind: String,
    pub service_name: String,
    pub api_version: String,
    pub db_path: PathBuf,
    pub admin_token: Option<String>,
    pub origin_token: Option<String>,
    pub allow_public_bind: bool,
    pub rate_limit_per_minute: u32,
    /// Maximum voter-slot count accepted on self-service (organizer-plane)
    /// election creation. Defaults to 1,000; bounded by MAX_ORGANIZER_SLOTS_LIMIT.
    pub organizer_max_slots: i64,
    /// Release-pinned public root used to authenticate transport descriptors.
    pub transport_authority_root: TransportAuthorityRootV1,
    /// Exact public transport environment accepted for descriptor issuance.
    /// This is not inferred from a browser-supplied artifact.
    pub transport_environment: String,
    /// Server-only Ed25519 seed supplied by deployment configuration. This is
    /// never serialized or returned through any API.
    authority_signing_key: Option<[u8; 32]>,
}

fn is_loopback_bind(bind: &str) -> Option<bool> {
    let host = bind.rsplit(':').nth(1)?;
    Some(host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]")
}

impl HostedConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = std::env::var("PRIVATE_BALLOT_HOSTED_BIND").unwrap_or_else(|_| {
            std::env::var("HOSTED_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        });
        let admin_bind = std::env::var("PRIVATE_BALLOT_HOSTED_ADMIN_BIND")
            .unwrap_or_else(|_| DEFAULT_ADMIN_BIND.to_owned());
        let service_name =
            std::env::var("PRIVATE_BALLOT_HOSTED_SERVICE").unwrap_or_else(|_| "hosted".to_owned());
        let api_version =
            std::env::var("PRIVATE_BALLOT_HOSTED_API_VERSION").unwrap_or_else(|_| "v1".to_owned());
        let db_path = PathBuf::from(
            std::env::var("PRIVATE_BALLOT_HOSTED_DB").unwrap_or_else(|_| "hosted.db".to_owned()),
        );
        let admin_token = std::env::var("PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let origin_token = std::env::var("PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let allow_public_bind =
            std::env::var("PRIVATE_BALLOT_HOSTED_ALLOW_PUBLIC_BIND").is_ok_and(|v| v == "1");
        let rate_limit_per_minute = std::env::var("PRIVATE_BALLOT_HOSTED_RATE_LIMIT_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let organizer_max_slots = std::env::var("PRIVATE_BALLOT_HOSTED_ORGANIZER_MAX_SLOTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_ORGANIZER_MAX_SLOTS);
        let transport_authority_root = match (
            std::env::var("PRIVATE_BALLOT_HOSTED_TRANSPORT_ROOT_KEY_ID").ok(),
            std::env::var("PRIVATE_BALLOT_HOSTED_TRANSPORT_ROOT_PUBLIC_KEY_HEX").ok(),
        ) {
            (Some(key_id), Some(public_key_hex)) => {
                let bytes = hex_decode(&public_key_hex).map_err(|_| ConfigError::InvalidBind)?;
                let public_key: [u8; 32] =
                    bytes.try_into().map_err(|_| ConfigError::InvalidBind)?;
                provision_production_transport_authority_root_v1(&key_id, public_key)
                    .map_err(|_| ConfigError::InvalidBind)?
            }
            (None, None) => production_transport_authority_root_v1(),
            _ => return Err(ConfigError::InvalidBind),
        };
        let authority_signing_key = match std::env::var("PRIVATE_BALLOT_HOSTED_AUTHORITY_SIGNING_KEY_HEX") {
            Ok(value) => Some(hex_decode(&value).map_err(|_| ConfigError::AuthoritySignerInvalid)?
                .try_into().map_err(|_| ConfigError::AuthoritySignerInvalid)?),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err(ConfigError::AuthoritySignerInvalid),
        };
        let transport_environment = std::env::var("PRIVATE_BALLOT_HOSTED_TRANSPORT_ENVIRONMENT")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if authority_signing_key.is_some() && transport_environment.is_none() {
            return Err(ConfigError::AuthorityEnvironmentMissing);
        }
        Self {
            bind,
            admin_bind,
            service_name,
            api_version,
            db_path,
            admin_token,
            origin_token,
            allow_public_bind,
            rate_limit_per_minute,
            organizer_max_slots,
            transport_authority_root,
            transport_environment: transport_environment.unwrap_or_else(|| "local".to_owned()),
            authority_signing_key,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, ConfigError> {
        let is_loopback = is_loopback_bind(&self.bind).ok_or(ConfigError::InvalidBind)?;
        if !is_loopback && !self.allow_public_bind {
            return Err(ConfigError::NonLoopbackBind);
        }
        // The admin plane must stay loopback-only with no opt-out.
        let admin_loopback = is_loopback_bind(&self.admin_bind).ok_or(ConfigError::InvalidBind)?;
        if !admin_loopback {
            return Err(ConfigError::AdminBindNotLoopback);
        }
        if self.bind == self.admin_bind {
            return Err(ConfigError::InvalidBind);
        }
        if self.service_name.trim().is_empty() || self.service_name.len() > 128 {
            return Err(ConfigError::InvalidBind);
        }
        if self.rate_limit_per_minute == 0 || self.rate_limit_per_minute > 10_000 {
            return Err(ConfigError::InvalidBind);
        }
        if self.organizer_max_slots < 1 || self.organizer_max_slots > MAX_ORGANIZER_SLOTS_LIMIT {
            return Err(ConfigError::InvalidBind);
        }
        if self.transport_environment.trim().is_empty() || self.transport_environment.len() > 128 {
            return Err(ConfigError::InvalidBind);
        }
        if let Some(seed) = self.authority_signing_key {
            let TransportAuthorityRootV1::Pinned { key_id, public_key } = &self.transport_authority_root else {
                return Err(ConfigError::AuthoritySignerMismatch);
            };
            LocalEd25519AuthoritySigner::new(key_id.clone(), seed, *public_key)
                .map_err(|_| ConfigError::AuthoritySignerMismatch)?;
        } else if matches!(self.transport_authority_root, TransportAuthorityRootV1::Pinned { .. }) {
            // A configured release root without its server-side signer must
            // never silently run as an issuing authority.
            return Err(ConfigError::AuthoritySignerMissing);
        }
        Ok(self)
    }

    /// Returns the authority signer only when explicit server-side key material
    /// is configured and matches the pinned public root. Issuance callers must
    /// treat `None` as an unavailable production authority, never as test-root.
    pub fn authority_signer(&self) -> Result<Box<dyn AuthoritySigner>, ConfigError> {
        let seed = self.authority_signing_key.ok_or(ConfigError::AuthoritySignerMissing)?;
        let TransportAuthorityRootV1::Pinned { key_id, public_key } = &self.transport_authority_root else {
            return Err(ConfigError::AuthoritySignerMissing);
        };
        Ok(Box::new(LocalEd25519AuthoritySigner::new(key_id.clone(), seed, *public_key)
            .map_err(|_| ConfigError::AuthoritySignerMismatch)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError {
    InvalidBind,
    NonLoopbackBind,
    AdminBindNotLoopback,
    AuthoritySignerInvalid,
    AuthoritySignerMissing,
    AuthoritySignerMismatch,
    AuthorityEnvironmentMissing,
}
impl ConfigError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBind => "HOSTED_CONFIG_INVALID_BIND",
            Self::NonLoopbackBind => "HOSTED_CONFIG_NON_LOOPBACK_BIND",
            Self::AdminBindNotLoopback => "HOSTED_CONFIG_ADMIN_BIND_NOT_LOOPBACK",
            Self::AuthoritySignerInvalid => "HOSTED_CONFIG_AUTHORITY_SIGNER_INVALID",
            Self::AuthoritySignerMissing => "HOSTED_CONFIG_AUTHORITY_SIGNER_MISSING",
            Self::AuthoritySignerMismatch => "HOSTED_CONFIG_AUTHORITY_SIGNER_MISMATCH",
            Self::AuthorityEnvironmentMissing => "HOSTED_CONFIG_AUTHORITY_ENVIRONMENT_MISSING",
        }
    }
}
impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for ConfigError {}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    let input = input.trim();
    if input.len() % 2 != 0 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16).ok_or(())?;
        let lo = char::from(bytes[i + 1]).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Generate a 16-byte CSPRNG opaque ID encoded as 32 lowercase hex chars.
pub fn new_opaque_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// Compute the invitation verifier from the raw secret bytes.
/// Only the verifier is stored server-side; the secret is returned once to the caller.
pub fn invitation_verifier(secret: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    let mut input = b"invitation-secret-verifier-v1\0".to_vec();
    input.extend_from_slice(secret);
    hex_encode(&p.hash(&input))
}

/// Compute the election-scoped organizer capability verifier from the raw
/// secret bytes. Domain-separated from invitation verifiers and bound to the
/// election id, so a credential for election A can never authorize election B.
/// Only the verifier is stored server-side; the plaintext secret stays with
/// the organizer (browser memory / downloaded access file).
#[must_use]
pub fn organizer_verifier(election_id: &str, secret: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    let mut input = Vec::with_capacity(
        ORGANIZER_CAPABILITY_DOMAIN.len() + election_id.len() + secret.len() + 2,
    );
    input.extend_from_slice(ORGANIZER_CAPABILITY_DOMAIN.as_bytes());
    input.push(0);
    input.extend_from_slice(election_id.as_bytes());
    input.push(0);
    input.extend_from_slice(secret);
    hex_encode(&p.hash(&input))
}

fn envelope_hash_hex(package: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    hex_encode(&hash_domain_separated(
        &p,
        HashDomain::BallotPackageV1,
        package,
    ))
}
fn package_binding_hash_hex(manifest: &[u8], registry: &[u8], candidates: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    let mut input = Vec::with_capacity(manifest.len() + registry.len() + candidates.len());
    input.extend_from_slice(manifest);
    input.extend_from_slice(registry);
    input.extend_from_slice(candidates);
    hex_encode(&p.hash(&input))
}

fn receipt_id_for(election_id: &str, client_receipt_id: &str, envelope_hash: &str) -> String {
    let p = Blake3HashProviderV1;
    let mut input = Vec::new();
    input.extend_from_slice(b"hosted-receipt-v1\0");
    input.extend_from_slice(election_id.as_bytes());
    input.push(0);
    input.extend_from_slice(client_receipt_id.as_bytes());
    input.push(0);
    input.extend_from_slice(envelope_hash.as_bytes());
    hex_encode(&p.hash(&input))
}

#[derive(Debug, Clone, Serialize)]
struct HealthBody {
    status: &'static str,
}
#[derive(Debug, Clone, Serialize)]
struct StatusBody {
    service: String,
    api_version: String,
    mode: &'static str,
}
#[derive(Debug, Clone, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}
#[derive(Debug, Clone, Serialize)]
struct ReceiptBody {
    election_id: String,
    receipt_id: String,
    stable_receipt: String,
    envelope_hash_hex: String,
    nullifier_hex: String,
    status: &'static str,
    replay: bool,
    seq: u64,
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ErrorBody { code, message })).into_response()
}

pub struct AppState {
    pub config: HostedConfig,
    pub storage: Arc<dyn HostedStorage>,
    pub ingest_lock: Mutex<()>,
    pub rate: Mutex<HashMap<(String, String), (u64, u32)>>,
}
impl AppState {
    pub fn new(config: HostedConfig, storage: Arc<dyn HostedStorage>) -> Self {
        Self {
            config,
            storage,
            ingest_lock: Mutex::new(()),
            rate: Mutex::new(HashMap::new()),
        }
    }
    fn check_rate(&self, election_id: &str, ip: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard
            .entry((election_id.to_owned(), ip.to_owned()))
            .or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60 {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.config.rate_limit_per_minute
    }
}

async fn health() -> Json<HealthBody> {
    Json(HealthBody { status: "ok" })
}
async fn status(State(state): State<Arc<AppState>>) -> Json<StatusBody> {
    Json(StatusBody {
        service: state.config.service_name.clone(),
        api_version: state.config.api_version.clone(),
        mode: "stage2",
    })
}

// ---------- Election helpers ----------
struct LoadedElection {
    record: storage::ElectionRecord,
    manifest: ElectionManifest,
    candidates: CandidateSet,
    registry: RegistrySnapshot,
    manifest_hash_hex: String,
}
impl LoadedElection {
    fn load(storage: &dyn HostedStorage, id: &str) -> Result<Self, Response> {
        let record = storage
            .get_election(id)
            .map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "storage unavailable",
                )
            })?
            .ok_or_else(|| {
                error_response(
                    StatusCode::NOT_FOUND,
                    "election_not_found",
                    "election not found",
                )
            })?;
        let manifest =
            ElectionManifest::from_canonical_cbor(&record.manifest_cbor).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored election is invalid",
                )
            })?;
        let candidates =
            CandidateSet::from_canonical_cbor(&record.candidate_cbor).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored election is invalid",
                )
            })?;
        let registry =
            RegistrySnapshot::from_canonical_cbor(&record.registry_cbor).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored election is invalid",
                )
            })?;
        let p = Blake3HashProviderV1;
        let manifest_hash = manifest.canonical_hash(&p).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            )
        })?;
        Ok(Self {
            record,
            manifest,
            candidates,
            registry,
            manifest_hash_hex: hex_encode(manifest_hash.as_bytes()),
        })
    }
    fn open_lifecycle(
        &self,
    ) -> Result<tari_cc_private_ballot_ballot::ElectionLifecycleV1, Response> {
        let p = Blake3HashProviderV1;
        let mh = self.manifest.canonical_hash(&p).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            )
        })?;
        let mut lc = tari_cc_private_ballot_ballot::ElectionLifecycleV1::new();
        lc.freeze(mh, self.manifest.registry_commitment())
            .map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored election is invalid",
                )
            })?;
        lc.open().map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            )
        })?;
        Ok(lc)
    }
    fn replay_ledger(
        &self,
        storage: &dyn HostedStorage,
    ) -> Result<(BallotAcceptanceLedger, Vec<storage::BallotRecord>), Response> {
        let ballots = storage.list_ballots(&self.record.id).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?;
        let lifecycle = self.open_lifecycle()?;
        let p = Blake3HashProviderV1;
        let verifier =
            build_tari_triptych_verifier_from_registry_v1(&self.registry, &p).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored election is invalid",
                )
            })?;
        let mut ledger = BallotAcceptanceLedger::new();
        for b in &ballots {
            ingest_approval_ballot_package_v1(
                &b.package_cbor,
                &self.manifest,
                &self.candidates,
                &lifecycle,
                &mut ledger,
                &p,
                &verifier,
            )
            .map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored ballot failed replay",
                )
            })?;
        }
        Ok((ledger, ballots))
    }
}

#[derive(Debug, Clone, Serialize)]
struct PublicPackageBody {
    election_id: String,
    state: String,
    manifest_cbor_hex: String,
    registry_cbor_hex: String,
    candidate_cbor_hex: String,
    manifest_hash_hex: String,
    registry_commitment_hex: String,
    candidate_commitment_hex: String,
    package_hash_hex: String,
    proof_suite_id: String,
    eligible_voter_count: u64,
    candidates: Vec<CandidateJson>,
}
#[derive(Debug, Clone, Serialize)]
struct CandidateJson {
    id_hex: String,
    id_text: String,
    display_name: String,
}

async fn public_package(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let p = Blake3HashProviderV1;
    let candidates: Vec<CandidateJson> = loaded
        .candidates
        .candidates()
        .iter()
        .map(|c| CandidateJson {
            id_hex: hex_encode(c.id().as_bytes()),
            id_text: String::from_utf8_lossy(c.id().as_bytes()).into_owned(),
            display_name: c.display_name().to_owned(),
        })
        .collect();
    let body = PublicPackageBody {
        election_id: id.clone(),
        state: loaded.record.state.clone(),
        manifest_cbor_hex: hex_encode(&loaded.record.manifest_cbor),
        registry_cbor_hex: hex_encode(&loaded.record.registry_cbor),
        candidate_cbor_hex: hex_encode(&loaded.record.candidate_cbor),
        manifest_hash_hex: loaded.manifest_hash_hex.clone(),
        registry_commitment_hex: hex_encode(loaded.manifest.registry_commitment().as_bytes()),
        candidate_commitment_hex: hex_encode(loaded.manifest.candidate_set_commitment().as_bytes()),
        package_hash_hex: package_binding_hash_hex(
            &loaded.record.manifest_cbor,
            &loaded.record.registry_cbor,
            &loaded.record.candidate_cbor,
        ),
        proof_suite_id: loaded.manifest.proof_suite_id().to_owned(),
        eligible_voter_count: loaded.registry.entries().len() as u64,
        candidates,
    };
    let _ = p;
    Json(body).into_response()
}

#[derive(Debug, Deserialize)]
struct BallotRequest {
    receipt_id: String,
    package_cbor_hex: String,
    api_version: String,
}

fn check_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct.starts_with("application/json") {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_content_type",
            "content type must be application/json",
        ))
    }
}

async fn submit_ballot(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    if body.len() > MAX_BALLOT_BODY_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ballot submission too large",
        );
    }
    let req: BallotRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "ballot_invalid",
                "malformed ballot request",
            );
        }
    };
    if req.api_version != "v1" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_api_version",
            "unsupported api version",
        );
    }
    if req.receipt_id.trim().is_empty() || req.receipt_id.len() > 128 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ballot_invalid",
            "invalid receipt id",
        );
    }
    let package = match hex_decode(&req.package_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "ballot_invalid",
                "invalid package encoding",
            );
        }
    };
    if package.len() > 32 * 1024 {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ballot submission too large",
        );
    }
    if !state.check_rate(&id, "transport") {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        );
    }

    let _guard = state.ingest_lock.lock().unwrap_or_else(|e| e.into_inner());
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if loaded.record.state != "open" {
        return error_response(
            StatusCode::CONFLICT,
            "election_closed",
            "election is not open for ballots",
        );
    }
    let env_hash = envelope_hash_hex(&package);
    if let Some(existing) = state
        .storage
        .get_ballot_by_receipt(&id, &req.receipt_id)
        .ok()
        .flatten()
    {
        if existing.envelope_hash_hex == env_hash {
            let body = ReceiptBody {
                election_id: id.clone(),
                receipt_id: req.receipt_id.clone(),
                stable_receipt: receipt_id_for(&id, &req.receipt_id, &env_hash),
                envelope_hash_hex: env_hash,
                nullifier_hex: hex_encode(&existing.nullifier),
                status: "accepted",
                replay: true,
                seq: existing.seq,
            };
            return (
                StatusCode::OK,
                [(
                    HeaderName::from_static("cache-control"),
                    "private, no-store",
                )],
                Json(body),
            )
                .into_response();
        }
        return error_response(
            StatusCode::CONFLICT,
            "duplicate_receipt",
            "receipt id already used with a different envelope",
        );
    }
    let (mut ledger, existing_ballots) = match loaded.replay_ledger(state.storage.as_ref()) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lifecycle = match loaded.open_lifecycle() {
        Ok(v) => v,
        Err(r) => return r,
    };
    let p = Blake3HashProviderV1;
    let verifier = match build_tari_triptych_verifier_from_registry_v1(&loaded.registry, &p) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            );
        }
    };
    let before = ledger.len();
    match ingest_approval_ballot_package_v1(
        &package,
        &loaded.manifest,
        &loaded.candidates,
        &lifecycle,
        &mut ledger,
        &p,
        &verifier,
    ) {
        Ok(()) => {}
        Err(e) => {
            let code = e.code();
            return match code {
                ValidationCode::DuplicateNullifier => error_response(
                    StatusCode::CONFLICT,
                    "duplicate_nullifier",
                    "nullifier already counted",
                ),
                ValidationCode::WrongManifestHash => error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "wrong_election",
                    "ballot is bound to a different election",
                ),
                ValidationCode::ElectionNotOpen => error_response(
                    StatusCode::CONFLICT,
                    "election_closed",
                    "election is not open for ballots",
                ),
                _ => error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "ballot_invalid",
                    "ballot verification failed",
                ),
            };
        }
    }
    if ledger.len() != before + 1 {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ballot_invalid",
            "ballot verification failed",
        );
    }
    let nullifier = ledger
        .accepted_ballots()
        .last()
        .map(|b| b.verified_nullifier().as_bytes().to_vec())
        .unwrap_or_default();
    let seq = (existing_ballots.len() + 1) as u64;
    let record = storage::BallotRecord {
        election_id: id.clone(),
        receipt_id: req.receipt_id.clone(),
        package_cbor: package.clone(),
        envelope_hash_hex: env_hash.clone(),
        nullifier: nullifier.clone(),
        seq,
    };
    match state.storage.insert_ballot(record) {
        Ok(()) => {}
        Err(storage::StorageError::DuplicateNullifier) => {
            return error_response(
                StatusCode::CONFLICT,
                "duplicate_nullifier",
                "nullifier already counted",
            );
        }
        Err(storage::StorageError::DuplicateReceipt) => {
            return error_response(
                StatusCode::CONFLICT,
                "duplicate_receipt",
                "receipt id already used",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    }
    let body = ReceiptBody {
        election_id: id.clone(),
        receipt_id: req.receipt_id.clone(),
        stable_receipt: receipt_id_for(&id, &req.receipt_id, &env_hash),
        envelope_hash_hex: env_hash,
        nullifier_hex: hex_encode(&nullifier),
        status: "accepted",
        replay: false,
        seq,
    };
    (
        StatusCode::CREATED,
        [(
            HeaderName::from_static("cache-control"),
            "private, no-store",
        )],
        Json(body),
    )
        .into_response()
}

async fn get_receipt(
    State(state): State<Arc<AppState>>,
    AxumPath((id, receipt_id)): AxumPath<(String, String)>,
) -> Response {
    let existing = match state.storage.get_ballot_by_receipt(&id, &receipt_id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    match existing {
        Some(b) => {
            let body = ReceiptBody {
                election_id: id.clone(),
                receipt_id: receipt_id.clone(),
                stable_receipt: receipt_id_for(&id, &receipt_id, &b.envelope_hash_hex),
                envelope_hash_hex: b.envelope_hash_hex,
                nullifier_hex: hex_encode(&b.nullifier),
                status: "accepted",
                replay: false,
                seq: b.seq,
            };
            (
                StatusCode::OK,
                [(
                    HeaderName::from_static("cache-control"),
                    "private, no-store",
                )],
                Json(body),
            )
                .into_response()
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            "receipt_not_found",
            "receipt not found",
        ),
    }
}

#[derive(Debug, Serialize)]
struct ResultsBody {
    election_id: String,
    state: String,
    accepted_ballots: u64,
    abstentions: u64,
    counts: Vec<CountJson>,
    leading: String,
}
#[derive(Debug, Serialize)]
struct CountJson {
    candidate_id_hex: String,
    candidate_id_text: String,
    display_name: String,
    approvals: u64,
}

async fn get_results(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if loaded.record.state != "finalized" {
        return error_response(
            StatusCode::CONFLICT,
            "election_not_finalized",
            "results are available only after finalization",
        );
    }
    let (ledger, _) = match loaded.replay_ledger(state.storage.as_ref()) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let payloads: Vec<ApprovalBallotPayload> = ledger
        .accepted_ballots()
        .iter()
        .map(|b| b.payload().clone())
        .collect();
    let tally = match ApprovalTally::from_ballots(&loaded.candidates, payloads.iter()) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "tally failed",
            );
        }
    };
    let mut counts = Vec::new();
    for c in tally.counts() {
        let text = String::from_utf8_lossy(c.candidate_id().as_bytes()).into_owned();
        let display = loaded
            .candidates
            .candidates()
            .iter()
            .find(|x| x.id() == c.candidate_id())
            .map(|x| x.display_name().to_owned())
            .unwrap_or_default();
        counts.push(CountJson {
            candidate_id_hex: hex_encode(c.candidate_id().as_bytes()),
            candidate_id_text: text,
            display_name: display,
            approvals: c.approvals(),
        });
    }
    let leading = match tally.leading_result() {
        tari_cc_private_ballot_tally::LeadingResult::NoApprovals => "NO_APPROVALS".to_owned(),
        tari_cc_private_ballot_tally::LeadingResult::SingleLeader {
            candidate_id,
            approvals,
        } => format!(
            "SINGLE_LEADER:{}:{}",
            hex_encode(candidate_id.as_bytes()),
            approvals
        ),
        tari_cc_private_ballot_tally::LeadingResult::Tie {
            candidate_ids,
            approvals,
        } => format!(
            "TIE:{}:{}",
            candidate_ids
                .iter()
                .map(|c| hex_encode(c.as_bytes()))
                .collect::<Vec<_>>()
                .join(","),
            approvals
        ),
    };
    Json(ResultsBody {
        election_id: id,
        state: loaded.record.state.clone(),
        accepted_ballots: tally.accepted_ballots(),
        abstentions: tally.abstentions(),
        counts,
        leading,
    })
    .into_response()
}

/// Complete canonical finalized archive.  This is the single archive value
/// exported by Hosted: consumers must use the serialized manifest here rather
/// than re-creating one from the listed members.
#[derive(Debug, Clone)]
pub struct FinalizedArchiveV1 {
    pub files: BTreeMap<String, Vec<u8>>,
    pub archive_manifest_cbor: Vec<u8>,
    pub archive_hash_hex: String,
    /// A legacy archive can remain readable without pretending it has the
    /// transport provenance required by the V2 anchor flow.
    pub anchor_eligible: bool,
}

fn build_finalized_archive(
    loaded: &LoadedElection,
    ballots: &[storage::BallotRecord],
    transport_binding_cbor: Option<&[u8]>,
) -> Result<FinalizedArchiveV1, Response> {
    let p = Blake3HashProviderV1;
    let manifest_hash = loaded.manifest.canonical_hash(&p).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "archive failed",
        )
    })?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(
        ELECTION_MANIFEST_ARCHIVE_PATH.to_owned(),
        loaded.record.manifest_cbor.clone(),
    );
    files.insert(
        CANDIDATE_SET_ARCHIVE_PATH.to_owned(),
        loaded.record.candidate_cbor.clone(),
    );
    files.insert(
        VOTER_REGISTRY_ARCHIVE_PATH.to_owned(),
        loaded.record.registry_cbor.clone(),
    );
    for (i, b) in ballots.iter().enumerate() {
        files.insert(
            format!("{SUBMISSIONS_ARCHIVE_DIR}/{i:08}.cbor"),
            b.package_cbor.clone(),
        );
    }
    if let Some(binding) = transport_binding_cbor {
        files.insert(
            TRANSPORT_ARCHIVE_BINDING_PATH_V1.to_owned(),
            binding.to_vec(),
        );
    }
    let entries: Vec<ArchiveFileEntryV1> = files
        .iter()
        .map(|(path, bytes)| {
            let ap = ArchivePathV1::new(path.clone()).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "archive failed",
                )
            })?;
            Ok(ArchiveFileEntryV1::for_bytes(ap, &p, bytes))
        })
        .collect::<Result<Vec<_>, Response>>()?;
    let catalog = ArchiveFileCatalogV1::new(entries).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "archive failed",
        )
    })?;
    let manifest =
        ArchiveManifestV1::finalized_for_provider(manifest_hash, catalog, &p).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "archive failed",
            )
        })?;
    let hash = manifest.canonical_hash(&p).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "archive failed",
        )
    })?;
    let archive_manifest_cbor = manifest.to_canonical_cbor().map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "archive failed",
        )
    })?;
    Ok(FinalizedArchiveV1 {
        files,
        archive_manifest_cbor,
        archive_hash_hex: hex_encode(hash.as_bytes()),
        anchor_eligible: transport_binding_cbor.is_some(),
    })
}

fn build_archive_files(
    loaded: &LoadedElection,
    ballots: &[storage::BallotRecord],
    transport_binding_cbor: &[u8],
) -> Result<(BTreeMap<String, Vec<u8>>, String), Response> {
    let archive = build_finalized_archive(loaded, ballots, Some(transport_binding_cbor))?;
    Ok((archive.files, archive.archive_hash_hex))
}

fn binding_error(message: &'static str) -> Response {
    error_response(StatusCode::CONFLICT, "transport_binding_required", message)
}

/// The Desktop organizer is the authoritative transport-binding producer. This
/// service only accepts its canonical public bytes after proving that they bind
/// the same election, manifest, and accepted ballot count that Hosted holds.
fn validate_transport_binding_bytes(
    loaded: &LoadedElection,
    binding_cbor: &[u8],
    accepted_ballot_count: u64,
) -> Result<(), Response> {
    let binding = TransportArchiveBindingV1::from_canonical_cbor(binding_cbor)
        .map_err(|_| binding_error("the supplied transport binding is not canonical"))?;
    let manifest_hash = loaded
        .manifest
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "archive identity unavailable",
            )
        })?;
    if binding.election_id() != loaded.manifest.election_id().as_bytes()
        || binding.manifest_hash() != manifest_hash
    {
        return Err(binding_error(
            "the supplied transport binding belongs to another election",
        ));
    }
    let binding_count = binding
        .batches()
        .iter()
        .try_fold(0_u64, |total, batch| {
            total.checked_add(batch.accepted_unique_count())
        })
        .ok_or_else(|| {
            binding_error("the supplied transport binding has an invalid accepted count")
        })?;
    if binding_count != accepted_ballot_count {
        return Err(binding_error(
            "the supplied transport binding does not match the finalized accepted ballot count",
        ));
    }
    Ok(())
}

fn authoritative_transport_binding_bytes(
    loaded: &LoadedElection,
    storage: &dyn HostedStorage,
    accepted_ballot_count: u64,
) -> Result<Vec<u8>, Response> {
    let record = storage
        .get_finalized_transport_binding(&loaded.record.id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "transport binding unavailable",
            )
        })?
        .ok_or_else(|| binding_error("an authoritative finalized transport binding is required"))?;
    validate_transport_binding_bytes(loaded, &record.binding_cbor, accepted_ballot_count)?;
    Ok(record.binding_cbor)
}

pub fn write_archive_directory(
    loaded_files: &BTreeMap<String, Vec<u8>>,
    archive_manifest_bytes: &[u8],
    target_dir: &Path,
) -> Result<String, String> {
    std::fs::create_dir_all(target_dir).map_err(|_| "archive_dir_failed".to_owned())?;
    let submissions = target_dir.join(SUBMISSIONS_ARCHIVE_DIR);
    if loaded_files
        .keys()
        .any(|k| k.starts_with(SUBMISSIONS_ARCHIVE_DIR))
    {
        std::fs::create_dir_all(&submissions).map_err(|_| "archive_dir_failed".to_owned())?;
    }
    for (path, bytes) in loaded_files {
        let fp = target_dir.join(path);
        if let Some(parent) = fp.parent() {
            std::fs::create_dir_all(parent).map_err(|_| "archive_dir_failed".to_owned())?;
        }
        std::fs::write(&fp, bytes).map_err(|_| "archive_write_failed".to_owned())?;
    }
    std::fs::write(
        target_dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH),
        archive_manifest_bytes,
    )
    .map_err(|_| "archive_write_failed".to_owned())?;
    Ok("ok".to_owned())
}

#[derive(Debug, Serialize)]
struct ArchiveBody {
    election_id: String,
    archive_hash_hex: String,
    archive_manifest_cbor_hex: String,
    anchor_eligible: bool,
    files: Vec<ArchiveFileJson>,
}
#[derive(Debug, Serialize)]
struct ArchiveFileJson {
    path: String,
    cbor_hex: String,
}

fn get_archive_response(state: &AppState, id: &str) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if loaded.record.state != "finalized" {
        return error_response(
            StatusCode::CONFLICT,
            "election_not_finalized",
            "archive is available only after finalization",
        );
    }
    let (ledger, ballots) = match loaded.replay_ledger(state.storage.as_ref()) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let binding = match state
        .storage
        .get_finalized_transport_binding(&loaded.record.id)
    {
        Ok(Some(record)) => match validate_transport_binding_bytes(
            &loaded,
            &record.binding_cbor,
            ledger.accepted_ballots().len() as u64,
        ) {
            Ok(()) => Some(record.binding_cbor),
            Err(response) => return response,
        },
        // V4 finalized elections had no binding table row.  Preserve their
        // original archive identity and make their missing V2 provenance
        // explicit instead of making the election unreadable after upgrade.
        Ok(None) => None,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "transport binding unavailable",
            );
        }
    };
    let archive = match build_finalized_archive(&loaded, &ballots, binding.as_deref()) {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(ArchiveBody {
        election_id: id.to_owned(),
        archive_hash_hex: archive.archive_hash_hex,
        archive_manifest_cbor_hex: hex_encode(&archive.archive_manifest_cbor),
        anchor_eligible: archive.anchor_eligible,
        files: archive
            .files
            .into_iter()
            .map(|(path, bytes)| ArchiveFileJson {
                path,
                cbor_hex: hex_encode(&bytes),
            })
            .collect(),
    })
    .into_response()
}

async fn get_archive(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    get_archive_response(state.as_ref(), &id)
}

/// Organizer-authenticated archive download. Identical content to the public
/// `get_archive` endpoint but gated on the election-scoped organizer credential,
/// so the Desktop can retrieve the canonical finalized archive without exposing
/// it to unauthenticated callers on a public route.
async fn organizer_get_archive(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    get_archive_response(state.as_ref(), &id)
}

async fn ootle_status(State(state): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({"network": "ootle-v0.51.0-cohort", "deployment_registry": "present", "anchor_publication": "not_configured_in_stage2_prototype", "service": state.config.service_name})).into_response()
}

// ---------- Enrollment admin handlers ----------

#[derive(Debug, Deserialize)]
struct CreateDraftRequest {
    election_id: String,
    candidate_cbor_hex: String,
    proof_suite_id: String,
    min_approvals: Option<i64>,
    max_approvals: Option<i64>,
    allow_abstention: Option<bool>,
    governance_revision: Option<String>,
    authorized_slot_count: i64,
    external_roster_commitment_hex: Option<String>,
}

async fn admin_create_draft(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    let req: CreateDraftRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed create-draft request",
            );
        }
    };
    if req.election_id.trim().is_empty() || req.election_id.len() > 128 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid election_id",
        );
    }
    if req.authorized_slot_count < 1 || req.authorized_slot_count > 100_000 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorized_slot_count must be 1..100000",
        );
    }
    let candidate_cbor = match hex_decode(&req.candidate_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid candidate_cbor_hex",
            );
        }
    };
    // Validate candidate set decodes
    if CandidateSet::from_canonical_cbor(&candidate_cbor).is_err() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "candidate set does not decode",
        );
    }
    if req.proof_suite_id.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "proof_suite_id required",
        );
    }
    let now_ms = now_ms();
    let record = storage::ElectionDraftRecord {
        election_id: req.election_id.clone(),
        candidate_cbor,
        proof_suite_id: req.proof_suite_id.clone(),
        min_approvals: req.min_approvals.unwrap_or(1),
        max_approvals: req.max_approvals.unwrap_or(1),
        allow_abstention: req.allow_abstention.unwrap_or(true),
        governance_revision: req.governance_revision.clone().unwrap_or_default(),
        proposal_question: String::new(),
        authorized_slot_count: req.authorized_slot_count,
        external_roster_commitment_hex: req.external_roster_commitment_hex.clone(),
        eligibility_state: "DRAFT".to_owned(),
        created_at_ms: now_ms,
    };
    match state.storage.put_election_draft(record) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "election_id": req.election_id,
                "eligibility_state": "DRAFT",
                "authorized_slot_count": req.authorized_slot_count,
            })),
        )
            .into_response(),
        Err(storage::StorageError::ElectionExists) => error_response(
            StatusCode::CONFLICT,
            "election_exists",
            "draft already exists for this election_id",
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        ),
    }
}

fn do_open_enrollment(state: &AppState, id: &str) -> Result<Response, Response> {
    let draft = state
        .storage
        .get_election_draft(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "draft election not found",
            )
        })?;
    if draft.eligibility_state != "DRAFT" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "draft is not in DRAFT state",
        ));
    }
    // Create slots
    state
        .storage
        .create_slots(id, draft.authorized_slot_count as usize, now_ms())
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "slot creation failed",
            )
        })?;
    // Transition state
    match state
        .storage
        .set_draft_eligibility_state(id, "DRAFT", "ENROLLMENT_OPEN")
    {
        Ok(true) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "election_id": id,
                "eligibility_state": "ENROLLMENT_OPEN",
                "authorized_slot_count": draft.authorized_slot_count,
            })),
        )
            .into_response()),
        Ok(false) => Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "state transition race",
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )),
    }
}

async fn admin_open_enrollment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_open_enrollment(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
struct IssueInvitationRequest {
    slot_id: String,
}

#[derive(Debug, Serialize)]
struct InvitationResponse {
    election_id: String,
    slot_id: String,
    invitation_id: String,
    /// The invitation secret (plaintext, 64 hex chars). Present only on issuance/reissuance.
    /// Never stored server-side; deliver to the voter and discard.
    invitation_secret_hex: String,
    state: String,
}

/// Issue (or reissue) an invitation for an unconsumed slot of `id`.
/// When `slot_id` is `None`, an available slot is chosen automatically
/// (first unconsumed slot with no ACTIVE invitation), so self-service
/// organizers never need to know storage-level slot identifiers.
fn do_issue_invitation(
    state: &AppState,
    id: &str,
    slot_id: Option<String>,
) -> Result<InvitationResponse, Response> {
    let draft = state
        .storage
        .get_election_draft(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "draft election not found",
            )
        })?;
    if draft.eligibility_state != "ENROLLMENT_OPEN" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "enrollment is not open",
        ));
    }
    let slots = state.storage.list_slots(id).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )
    })?;
    let slot = match slot_id {
        Some(requested) => {
            let slot = slots
                .iter()
                .find(|s| s.slot_id == requested)
                .cloned()
                .ok_or_else(|| {
                    error_response(
                        StatusCode::NOT_FOUND,
                        "slot_not_found",
                        "slot not found for this election",
                    )
                })?;
            if slot.consumed {
                return Err(error_response(
                    StatusCode::CONFLICT,
                    "slot_consumed",
                    "slot already consumed; cannot issue another invitation",
                ));
            }
            slot
        }
        None => {
            let mut available: Vec<&storage::EligibilitySlotRecord> =
                slots.iter().filter(|s| !s.consumed).collect();
            available.sort_by(|a, b| a.slot_id.cmp(&b.slot_id));
            // Prefer a slot with no ACTIVE invitation so reissuance stays an
            // explicit action rather than an accident of ordering.
            let mut chosen: Option<String> = None;
            for s in &available {
                let has_active = state
                    .storage
                    .get_active_invitation_for_slot(&s.slot_id)
                    .map_err(|_| {
                        error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "service_unavailable",
                            "storage unavailable",
                        )
                    })?
                    .is_some();
                if !has_active {
                    chosen = Some(s.slot_id.clone());
                    break;
                }
            }
            let chosen = match chosen {
                Some(c) => c,
                None => match available.first() {
                    Some(s) => s.slot_id.clone(),
                    None => {
                        return Err(error_response(
                            StatusCode::CONFLICT,
                            "no_available_slot",
                            "no unconsumed voter slots remain",
                        ));
                    }
                },
            };
            match slots.iter().find(|s| s.slot_id == chosen) {
                Some(s) => s.clone(),
                None => {
                    return Err(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "service_unavailable",
                        "storage unavailable",
                    ));
                }
            }
        }
    };
    // Void any existing ACTIVE invitation for this slot (reissuance)
    if state
        .storage
        .void_active_slot_invitations(&slot.slot_id)
        .is_err()
    {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        ));
    }
    // Generate 32-byte CSPRNG secret; compute verifier; never store secret
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let verifier_hex = invitation_verifier(&secret);
    let secret_hex = hex_encode(&secret);
    let invitation_id = new_opaque_id();
    let now_ms = now_ms();
    let record = storage::InvitationRecord {
        invitation_id: invitation_id.clone(),
        slot_id: slot.slot_id.clone(),
        election_id: id.to_owned(),
        verifier_hex,
        state: "ACTIVE".to_owned(),
        created_at_ms: now_ms,
    };
    if state.storage.insert_invitation(record).is_err() {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        ));
    }
    Ok(InvitationResponse {
        election_id: id.to_owned(),
        slot_id: slot.slot_id,
        invitation_id,
        invitation_secret_hex: secret_hex,
        state: "ACTIVE".to_owned(),
    })
}

async fn admin_issue_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    let req: IssueInvitationRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed issue-invitation request",
            );
        }
    };
    match do_issue_invitation(state.as_ref(), &id, Some(req.slot_id)) {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(r) => r,
    }
}

async fn admin_void_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((id, invitation_id)): AxumPath<(String, String)>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    // Void ACTIVE → VOIDED; ignore if already voided/consumed
    match state.storage.set_invitation_state(&invitation_id, "ACTIVE", "VOIDED") {
        Ok(true) => Json(serde_json::json!({"election_id": id, "invitation_id": invitation_id, "state": "VOIDED"})).into_response(),
        Ok(false) => error_response(StatusCode::CONFLICT, "invalid_state", "invitation is not ACTIVE"),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
    }
}

#[derive(Debug, Serialize)]
struct EnrollmentStatusBody {
    election_id: String,
    eligibility_state: String,
    authorized_slot_count: i64,
    total_slots: i64,
    consumed_slots: i64,
    available_slots: i64,
    enrolled_count: i64,
}

fn do_enrollment_status(state: &AppState, id: &str) -> Result<EnrollmentStatusBody, Response> {
    let draft = state
        .storage
        .get_election_draft(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "draft election not found",
            )
        })?;
    let slots = state.storage.list_slots(id).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )
    })?;
    let consumed = slots.iter().filter(|s| s.consumed).count() as i64;
    let total = slots.len() as i64;
    let enrolled = state.storage.count_enrolled_credentials(id).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )
    })?;
    Ok(EnrollmentStatusBody {
        election_id: id.to_owned(),
        eligibility_state: draft.eligibility_state,
        authorized_slot_count: draft.authorized_slot_count,
        total_slots: total,
        consumed_slots: consumed,
        available_slots: total - consumed,
        enrolled_count: enrolled,
    })
}

async fn admin_enrollment_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_enrollment_status(state.as_ref(), &id) {
        Ok(body) => Json(body).into_response(),
        Err(r) => r,
    }
}

fn do_freeze_registry(state: &AppState, id: &str) -> Result<Response, Response> {
    let draft = state
        .storage
        .get_election_draft(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "draft not found",
            )
        })?;
    if draft.eligibility_state != "ENROLLMENT_OPEN" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "enrollment must be ENROLLMENT_OPEN to freeze",
        ));
    }
    // Collect enrolled credentials → build RegistrySnapshot
    let creds = state.storage.list_enrolled_credentials(id).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )
    })?;
    if creds.is_empty() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "empty_registry",
            "cannot freeze with zero enrolled credentials",
        ));
    }
    let entries: Result<Vec<RegistryEntry>, ()> = creds
        .iter()
        .map(|c| {
            let key_bytes = hex_decode(&c.public_key_hex).map_err(|_| ())?;
            let gk = GovernancePublicKey::new(key_bytes).map_err(|_| ())?;
            let reg =
                VoterGovernanceKeyRegistrationV1::new(gk, VoterKeyProvisioningV1::GeneratedByVoter);
            Ok(RegistryEntry::from_voter_registration(reg))
        })
        .collect();
    let entries = match entries {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "enrolled key encoding invalid",
            ));
        }
    };
    let registry = match RegistrySnapshot::new(entries) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "registry_invalid",
                "registry construction failed",
            ));
        }
    };
    let p = Blake3HashProviderV1;
    let registry_cbor = match registry.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "registry serialization failed",
            ));
        }
    };
    let registry_commitment = match registry.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "registry commitment failed",
            ));
        }
    };
    let enrolled_count = creds.len() as i64;
    let now_ms = now_ms();
    let frozen = storage::FrozenRegistryRecord {
        election_id: id.to_owned(),
        registry_cbor_hex: hex_encode(&registry_cbor),
        registry_commitment_hex: hex_encode(registry_commitment.as_bytes()),
        authorized_slot_count: draft.authorized_slot_count,
        enrolled_count,
        frozen_at_ms: now_ms,
        external_roster_commitment_hex: draft.external_roster_commitment_hex.clone(),
    };
    if let Err(storage::StorageError::AlreadyFrozen) = state.storage.put_frozen_registry(frozen) {
        return Err(error_response(
            StatusCode::CONFLICT,
            "already_frozen",
            "registry already frozen",
        ));
    }
    // Scrub enrollment linkage (slot_id and invitation_id from credentials)
    let _ = state.storage.scrub_enrollment_linkage(id);
    // Transition state
    match state
        .storage
        .set_draft_eligibility_state(id, "ENROLLMENT_OPEN", "REGISTRY_FROZEN")
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(error_response(
                StatusCode::CONFLICT,
                "invalid_state",
                "state transition race",
            ));
        }
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            ));
        }
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "election_id": id,
            "eligibility_state": "REGISTRY_FROZEN",
            "enrolled_count": enrolled_count,
            "authorized_slot_count": draft.authorized_slot_count,
            "registry_commitment_hex": hex_encode(registry_commitment.as_bytes()),
        })),
    )
        .into_response())
}

async fn admin_freeze_registry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_freeze_registry(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

fn do_open_voting(state: &AppState, id: &str) -> Result<Response, Response> {
    let draft = state
        .storage
        .get_election_draft(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "draft not found",
            )
        })?;
    if draft.eligibility_state != "REGISTRY_FROZEN" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "registry must be frozen before opening voting",
        ));
    }
    let frozen = state
        .storage
        .get_frozen_registry(id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "frozen registry not found",
            )
        })?;
    // Reconstruct registry commitment from stored hex
    let commit_bytes: [u8; 32] = match hex_decode(&frozen.registry_commitment_hex) {
        Ok(v) if v.len() == 32 => v.try_into().unwrap(),
        _ => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored commitment invalid",
            ));
        }
    };
    let registry_commitment = RegistryCommitment::new(commit_bytes);
    // Decode candidate set and compute its commitment
    let candidates = match CandidateSet::from_canonical_cbor(&draft.candidate_cbor) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored candidate set invalid",
            ));
        }
    };
    let p = Blake3HashProviderV1;
    let candidate_commitment = match candidates.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "candidate commitment failed",
            ));
        }
    };
    // Build manifest
    let election_id_bytes = id.as_bytes().to_vec();
    let election_id_obj = match ElectionId::new(election_id_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid election_id for manifest",
            ));
        }
    };
    let approval_limits = match ApprovalLimits::new(
        draft.min_approvals as usize,
        draft.max_approvals as usize,
        draft.allow_abstention,
    ) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "invalid approval limits",
            ));
        }
    };
    let manifest_input = ElectionManifestV2Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: election_id_obj,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment: candidate_commitment,
        proof_suite_id: draft.proof_suite_id.clone(),
        approval_limits,
        governance_source_revision: draft.governance_revision.clone(),
        proposal_question: draft.proposal_question.clone(),
    };
    let manifest_v2 = if draft.proposal_question.is_empty() {
        None
    } else {
        Some(ElectionManifestV2::new(manifest_input).map_err(|_| {
            error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "manifest construction failed",
            )
        })?)
    };
    let manifest = if draft.proposal_question.is_empty() {
        // Drafts written before V2 self-service creation are legacy V1. Their
        // canonical identity must not change during a later lifecycle action.
        let legacy_input = ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: ElectionId::new(id.as_bytes().to_vec()).map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored legacy election id is invalid",
                )
            })?,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment: candidate_commitment,
            proof_suite_id: draft.proof_suite_id.clone(),
            approval_limits: ApprovalLimits::new(
                draft.min_approvals as usize,
                draft.max_approvals as usize,
                draft.allow_abstention,
            )
            .map_err(|_| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "stored legacy approval limits are invalid",
                )
            })?,
            governance_source_revision: draft.governance_revision.clone(),
        };
        ElectionManifest::V1(ElectionManifestV1::new(legacy_input).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored legacy manifest is invalid",
            )
        })?)
    } else {
        ElectionManifest::V2(manifest_v2.expect("V2 manifest is present for non-legacy drafts"))
    };
    let manifest_cbor = match manifest.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "manifest serialization failed",
            ));
        }
    };
    let registry_cbor = match hex_decode(&frozen.registry_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored registry invalid",
            ));
        }
    };
    let manifest_hash_hex = match manifest.canonical_hash(&p) {
        Ok(h) => hex_encode(h.as_bytes()),
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "manifest hash failed",
            ));
        }
    };
    // Validate verifier can be constructed from registry
    let registry = match RegistrySnapshot::from_canonical_cbor(&registry_cbor) {
        Ok(v) => v,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored registry does not decode",
            ));
        }
    };
    if build_tari_triptych_verifier_from_registry_v1(&registry, &p).is_err() {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "registry verifier construction failed",
        ));
    }
    let record = storage::ElectionRecord {
        id: id.to_owned(),
        manifest_cbor,
        registry_cbor,
        candidate_cbor: draft.candidate_cbor.clone(),
        state: "open".to_owned(),
        manifest_hash_hex: manifest_hash_hex.clone(),
    };
    match state.storage.put_election(record) {
        Ok(()) => {}
        Err(storage::StorageError::ElectionExists) => {
            return Err(error_response(
                StatusCode::CONFLICT,
                "election_exists",
                "voting already opened for this election",
            ));
        }
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            ));
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "election_id": id,
            "state": "open",
            "manifest_hash_hex": manifest_hash_hex,
            "registry_commitment_hex": frozen.registry_commitment_hex,
            "enrolled_count": frozen.enrolled_count,
        })),
    )
        .into_response())
}

async fn admin_open_voting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_open_voting(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

// ---------- Public enrollment status (read-only, no secrets exposed) ----------

#[derive(Debug, Serialize)]
struct PublicEnrollmentInfoBody {
    election_id: String,
    /// "DRAFT" | "ENROLLMENT_OPEN" | "REGISTRY_FROZEN"
    eligibility_state: String,
    /// Only present when REGISTRY_FROZEN; enables browser-side commitment verification.
    registry_commitment_hex: Option<String>,
    /// Canonical frozen registry bytes for independent browser/WASM verification.
    registry_cbor_hex: Option<String>,
    enrolled_count: Option<i64>,
    authorized_slot_count: i64,
}

async fn public_enrollment_info(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let draft = match state.storage.get_election_draft(&id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "election not found",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    let (registry_commitment_hex, registry_cbor_hex, enrolled_count) =
        if draft.eligibility_state == "REGISTRY_FROZEN" {
            match state.storage.get_frozen_registry(&id) {
                Ok(Some(f)) => (
                    Some(f.registry_commitment_hex),
                    Some(f.registry_cbor_hex),
                    Some(f.enrolled_count),
                ),
                _ => (None, None, None),
            }
        } else {
            (None, None, None)
        };
    Json(PublicEnrollmentInfoBody {
        election_id: id,
        eligibility_state: draft.eligibility_state,
        registry_commitment_hex,
        registry_cbor_hex,
        enrolled_count,
        authorized_slot_count: draft.authorized_slot_count,
    })
    .into_response()
}

// ---------- Public enrollment endpoint ----------

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    invitation_secret_hex: String,
    public_key_hex: String,
}

#[derive(Debug, Serialize)]
struct EnrollResponse {
    election_id: String,
    public_key_hex: String,
    enrolled_at_ms: i64,
    idempotent: bool,
}

async fn enroll_voter(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    if body.len() > MAX_BODY_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "request too large",
        );
    }
    let req: EnrollRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed enrollment request",
            );
        }
    };
    // Validate secret is 64 hex chars (32 bytes)
    let secret_bytes = match hex_decode(&req.invitation_secret_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invitation_secret_hex must be 64 hex chars (32 bytes)",
            );
        }
    };
    let public_key_bytes = match hex_decode(&req.public_key_hex) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid public_key_hex",
            );
        }
    };
    // Validate public key fits as GovernancePublicKey
    if GovernancePublicKey::new(public_key_bytes.clone()).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "public_key_hex is not a valid governance key",
        );
    }
    let verifier_hex = invitation_verifier(&secret_bytes);
    let norm_key = hex_encode(&public_key_bytes);
    // SQLite enforces cross-process atomicity; this also keeps the in-memory test
    // storage's independently locked collections coherent.
    let _guard = state.ingest_lock.lock().unwrap_or_else(|e| e.into_inner());
    let completion =
        match state
            .storage
            .complete_enrollment(&id, &verifier_hex, &norm_key, now_ms())
        {
            Ok(value) => value,
            Err(_) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "storage unavailable",
                );
            }
        };
    match completion {
        storage::EnrollmentCompletion::Created(credential) => (
            StatusCode::CREATED,
            Json(EnrollResponse {
                election_id: id,
                public_key_hex: norm_key,
                enrolled_at_ms: credential.enrolled_at_ms,
                idempotent: false,
            }),
        )
            .into_response(),
        storage::EnrollmentCompletion::Idempotent(credential) => (
            StatusCode::OK,
            Json(EnrollResponse {
                election_id: id,
                public_key_hex: norm_key,
                enrolled_at_ms: credential.enrolled_at_ms,
                idempotent: true,
            }),
        )
            .into_response(),
        storage::EnrollmentCompletion::ElectionNotFound => error_response(
            StatusCode::NOT_FOUND,
            "election_not_found",
            "election not found",
        ),
        storage::EnrollmentCompletion::InvitationNotFound
        | storage::EnrollmentCompletion::WrongElection
        | storage::EnrollmentCompletion::InvitationVoided => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_invitation",
            "invitation not found, invalid, or voided",
        ),
        storage::EnrollmentCompletion::EnrollmentClosed => error_response(
            StatusCode::CONFLICT,
            "enrollment_closed",
            "enrollment is not open",
        ),
        storage::EnrollmentCompletion::CredentialConflict => error_response(
            StatusCode::CONFLICT,
            "credential_conflict",
            "invitation or credential is already enrolled",
        ),
        storage::EnrollmentCompletion::EnrollmentRace => error_response(
            StatusCode::CONFLICT,
            "enrollment_race",
            "concurrent enrollment; retry",
        ),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------- Admin (localhost, token-gated when configured) ----------
fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if let Some(token) = &state.config.admin_token {
        let provided = headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !token_equals(provided, token) {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "admin token required",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ImportRequest {
    election_id: String,
    manifest_cbor_hex: String,
    registry_cbor_hex: String,
    candidate_cbor_hex: String,
}

async fn admin_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    let req: ImportRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_election",
                "malformed import request",
            );
        }
    };
    let manifest_cbor = match hex_decode(&req.manifest_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_election",
                "invalid manifest encoding",
            );
        }
    };
    let registry_cbor = match hex_decode(&req.registry_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_election",
                "invalid registry encoding",
            );
        }
    };
    let candidate_cbor = match hex_decode(&req.candidate_cbor_hex) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_election",
                "invalid candidate encoding",
            );
        }
    };
    let manifest = match ElectionManifest::from_canonical_cbor(&manifest_cbor) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "manifest does not decode",
            );
        }
    };
    let candidates = match CandidateSet::from_canonical_cbor(&candidate_cbor) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "candidate set does not decode",
            );
        }
    };
    let registry = match RegistrySnapshot::from_canonical_cbor(&registry_cbor) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "registry does not decode",
            );
        }
    };
    if manifest.election_id().as_bytes() != req.election_id.as_bytes() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "election id does not match manifest",
        );
    }
    let p = Blake3HashProviderV1;
    let reg_commit = match registry.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "registry commitment failed",
            );
        }
    };
    let cand_commit = match candidates.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "candidate commitment failed",
            );
        }
    };
    if reg_commit != manifest.registry_commitment()
        || cand_commit != manifest.candidate_set_commitment()
    {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "manifest commitments do not match supplied artifacts",
        );
    }
    if build_tari_triptych_verifier_from_registry_v1(&registry, &p).is_err() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "registry verifier construction failed",
        );
    }
    // Canonical round-trip check (rejects non-canonical encodings).
    if manifest.to_canonical_cbor().ok() != Some(manifest_cbor.clone())
        || candidates.to_canonical_cbor().ok() != Some(candidate_cbor.clone())
        || registry.to_canonical_cbor().ok() != Some(registry_cbor.clone())
    {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_election",
            "artifacts are not canonical",
        );
    }
    let mh = manifest
        .canonical_hash(&p)
        .map(|h| hex_encode(h.as_bytes()))
        .unwrap_or_default();
    let record = storage::ElectionRecord {
        id: req.election_id.clone(),
        manifest_cbor,
        registry_cbor,
        candidate_cbor,
        state: "open".to_owned(),
        manifest_hash_hex: mh,
    };
    match state.storage.put_election(record) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"election_id": req.election_id, "state": "open"})),
        )
            .into_response(),
        Err(storage::StorageError::ElectionExists) => error_response(
            StatusCode::CONFLICT,
            "election_exists",
            "election already imported",
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        ),
    }
}

fn do_close(state: &AppState, id: &str) -> Result<Response, Response> {
    match state.storage.set_election_state(id, "open", "closed") {
        Ok(true) => {
            Ok(Json(serde_json::json!({"election_id": id, "state": "closed"})).into_response())
        }
        Ok(false) => Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "election is not open",
        )),
        Err(storage::StorageError::ElectionNotFound) => Err(error_response(
            StatusCode::NOT_FOUND,
            "election_not_found",
            "election not found",
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "storage unavailable",
        )),
    }
}

async fn admin_close(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_close(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

fn do_finalize(state: &AppState, id: &str) -> Result<Response, Response> {
    let loaded = match LoadedElection::load(state.storage.as_ref(), id) {
        Ok(v) => v,
        Err(r) => return Err(r),
    };
    if loaded.record.state != "closed" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "election is not closed",
        ));
    }
    // Replay through canonical ledger (no secret needed; packages are public by protocol).
    let (ledger, ballots) = loaded.replay_ledger(state.storage.as_ref())?;
    // Never let Hosted finalize an archive it cannot make bit-for-bit equal to
    // the Desktop's verified, transport-bound archive.
    let binding = authoritative_transport_binding_bytes(
        &loaded,
        state.storage.as_ref(),
        ledger.accepted_ballots().len() as u64,
    )?;
    let (_, archive_hash) = build_archive_files(&loaded, &ballots, &binding)?;
    match state.storage.set_election_state(id, "closed", "finalized") {
        Ok(true) => Ok(Json(serde_json::json!({"election_id": id, "state": "finalized", "archive_hash_hex": archive_hash, "accepted_ballots": ballots.len()})).into_response()),
        Ok(false) => Err(error_response(StatusCode::CONFLICT, "invalid_state", "election is not closed")),
        Err(_) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable")),
    }
}

async fn admin_finalize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_admin(&state, &headers) {
        return r;
    }
    match do_finalize(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

// ---------- Self-service organizer plane (public router, election-scoped) ----------
//
// Anyone can create an election and manage ONLY that election with an
// election-scoped capability credential. The plaintext organizer secret is
// generated client-side (WebCrypto), sent once over the request body here,
// and afterwards only in the `x-private-ballot-organizer` header. The server
// stores a domain-separated verifier only. These routes never grant
// server-global administration: the localhost admin plane keeps its own
// token and stays off this router entirely.

/// Election-scoped organizer authorization. Missing, malformed, wrong, or
/// foreign-election credentials all fail closed with the same generic 401
/// (no information about which part failed). Comparison of verifier bytes
/// is constant-time.
fn check_organizer(
    state: &AppState,
    headers: &HeaderMap,
    election_id: &str,
) -> Result<(), Response> {
    let invalid = || {
        error_response(
            StatusCode::UNAUTHORIZED,
            "organizer_credential_required",
            "valid organizer credential required",
        )
    };
    let provided = headers
        .get(ORGANIZER_CREDENTIAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let secret = match hex_decode(provided) {
        Ok(v) if v.len() == 32 => v,
        _ => return Err(invalid()),
    };
    let stored = state
        .storage
        .get_organizer_credential(election_id)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        })?
        .ok_or_else(invalid)?;
    let verifier = organizer_verifier(election_id, &secret);
    if !token_equals(&verifier, &stored.organizer_verifier_hex) {
        return Err(invalid());
    }
    Ok(())
}

fn organizer_rate(state: &AppState, election_id: &str) -> Result<(), Response> {
    if state.check_rate(election_id, "organizer") {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        ))
    }
}

fn is_valid_self_service_election_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Validates one ballot option display name for self-service creation and
/// derives the canonical candidate ID from the trimmed name. Rejects empty,
/// oversized, or control-character names. Returns `None` when invalid.
fn normalize_ballot_option(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_CANDIDATE_ID_BYTES {
        return None;
    }
    if trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return None;
    }
    Some(trimmed.to_owned())
}

#[derive(Debug, Deserialize)]
struct OrganizerCreateElectionRequest {
    election_id: String,
    options: Vec<String>,
    organizer_secret_hex: String,
    min_approvals: Option<i64>,
    max_approvals: Option<i64>,
    allow_abstention: Option<bool>,
    authorized_slot_count: i64,
    governance_revision: Option<String>,
    proposal_question: String,
}

#[derive(Debug, Serialize)]
struct OrganizerCreateElectionBody {
    election_id: String,
    eligibility_state: String,
    authorized_slot_count: i64,
    proof_suite_id: String,
    created_at_ms: i64,
    candidates: Vec<CandidateJson>,
}

#[derive(Debug, Deserialize)]
struct OrganizerIssueInvitationRequest {
    slot_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OrganizerSlotBody {
    slot_id: String,
    consumed: bool,
    invitation_id: Option<String>,
    invitation_state: Option<String>,
}

#[derive(Debug, Serialize)]
struct OrganizerElectionBody {
    election_id: String,
    eligibility_state: String,
    election_state: Option<String>,
    authorized_slot_count: i64,
    total_slots: i64,
    consumed_slots: i64,
    available_slots: i64,
    enrolled_count: i64,
    registry_commitment_hex: Option<String>,
    proof_suite_id: String,
    created_at_ms: i64,
    candidates: Vec<CandidateJson>,
    /// Recomputed only for a finalized election; this is the archive identity
    /// the hosted anchor panel must bind before it contacts a wallet.
    finalized_archive_hash_hex: Option<String>,
    /// Native-derived identity that the browser must match byte-for-byte. It
    /// prevents an imported bundle from substituting a different digest or
    /// merely well-formed public summary for this managed finalized election.
    finalized_anchor_digest_hex: Option<String>,
    finalized_public_summary_json: Option<String>,
    transport_binding_status: String,
}

struct FinalizedAnchorIdentity {
    archive_hash_hex: String,
    anchor_digest_hex: String,
    public_summary_json: String,
}

fn finalized_anchor_identity(
    loaded: &LoadedElection,
    storage: &dyn HostedStorage,
) -> Result<FinalizedAnchorIdentity, Response> {
    let (ledger, ballots) = loaded.replay_ledger(storage)?;
    let binding = authoritative_transport_binding_bytes(
        loaded,
        storage,
        ledger.accepted_ballots().len() as u64,
    )?;
    let (_, archive_hash_hex) = build_archive_files(loaded, &ballots, &binding)?;
    let archive_hash: [u8; 32] = hex_decode(&archive_hash_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "archive identity unavailable",
            )
        })?;
    let payloads: Vec<ApprovalBallotPayload> = ledger
        .accepted_ballots()
        .iter()
        .map(|ballot| ballot.payload().clone())
        .collect();
    let tally = ApprovalTally::from_ballots(&loaded.candidates, payloads.iter()).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "anchor identity unavailable",
        )
    })?;
    let mut entries = Vec::with_capacity(tally.counts().len());
    for count in tally.counts() {
        let candidate = loaded
            .candidates
            .candidates()
            .iter()
            .find(|candidate| candidate.id() == count.candidate_id())
            .ok_or_else(|| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "service_unavailable",
                    "anchor identity unavailable",
                )
            })?;
        entries.push(OotleAnchorTallyEntryV2 {
            display_label: candidate.display_name().to_owned(),
            machine_id: count.candidate_id().as_bytes().to_vec(),
            count: count.approvals(),
        });
    }
    let artifact_digest: [u8; 32] = hex_decode(deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor deployment unavailable",
            )
        })?;
    let manifest_hash = loaded
        .manifest
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor identity unavailable",
            )
        })?;
    let payload = OotleAnchorPublicPayloadV2 {
        network: OotleNetworkIdV1::new("mainnet".to_owned()).map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor identity unavailable",
            )
        })?,
        election_id: loaded.manifest.election_id().as_bytes().to_vec(),
        ballot_question: loaded
            .manifest
            .proposal_question()
            .unwrap_or_default()
            .to_owned(),
        ballot_kind: loaded.manifest.ballot_kind().as_str().to_owned(),
        confidentiality_mode: loaded.manifest.ballot_confidentiality().as_str().to_owned(),
        proof_suite: loaded.manifest.proof_suite_id().to_owned(),
        manifest_hash,
        archive_hash: ArchiveHashV1::new(archive_hash),
        registry_commitment: *loaded.manifest.registry_commitment().as_bytes(),
        option_set_commitment: *loaded.manifest.candidate_set_commitment().as_bytes(),
        eligible_voter_count: loaded.registry.entries().len() as u64,
        accepted_ballot_count: tally.accepted_ballots(),
        rejected_ballot_count: 0,
        tally: entries,
        archive_finalized: true,
        finalized_timestamp_unix_secs: None,
        template: OotleAnchorTemplateBindingV2 {
            template_address: deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
            template_module: "tari_private_ballot_anchor_v2".to_owned(),
            template_function: deployment_registry::ABI_FUNCTION_V2.to_owned(),
            event_topic: format!(
                "tari_private_ballot_anchor_v2.{}",
                deployment_registry::ABI_EVENT_TOPIC_V2
            ),
            artifact_digest,
        },
    };
    let public_summary_json =
        String::from_utf8(payload.to_canonical_json_bytes().map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor identity unavailable",
            )
        })?)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor identity unavailable",
            )
        })?;
    let anchor_digest_hex = hex_encode(&payload.canonical_digest(&Blake3HashProviderV1).map_err(
        |_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "anchor identity unavailable",
            )
        },
    )?);
    Ok(FinalizedAnchorIdentity {
        archive_hash_hex,
        anchor_digest_hex,
        public_summary_json,
    })
}

async fn organizer_create_election(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    if body.len() > MAX_BODY_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "request too large",
        );
    }
    if !state.check_rate("__organizer_create__", "public") {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        );
    }
    let req: OrganizerCreateElectionRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed create-election request",
            );
        }
    };
    if !is_valid_self_service_election_id(&req.election_id) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "election_id must be 1..128 chars of [A-Za-z0-9._-]",
        );
    }
    if ElectionId::new(req.election_id.as_bytes().to_vec()).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "election_id exceeds protocol limits",
        );
    }
    let secret_bytes = match hex_decode(&req.organizer_secret_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "organizer_secret_hex must be 64 hex chars (32 bytes)",
            );
        }
    };
    if req.options.is_empty() || req.options.len() > MAX_CANDIDATES {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "options must contain 1..256 entries",
        );
    }
    let mut names: Vec<String> = Vec::with_capacity(req.options.len());
    for option in &req.options {
        let name = match normalize_ballot_option(option) {
            Some(v) => v,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "each option name must be non-empty, <=128 bytes, without control characters",
                );
            }
        };
        if names.iter().any(|n| n == &name) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicate option names are not allowed",
            );
        }
        names.push(name);
    }
    let option_count = names.len();
    let min_approvals = req.min_approvals.unwrap_or(1);
    let max_approvals = req.max_approvals.unwrap_or(1);
    if min_approvals < 1 || max_approvals < min_approvals || max_approvals as usize > option_count {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "approval limits must satisfy 1 <= min <= max <= option count",
        );
    }
    let allow_abstention = req.allow_abstention.unwrap_or(true);
    if req.authorized_slot_count < 1 || req.authorized_slot_count > state.config.organizer_max_slots
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorized_slot_count exceeds the self-service limit",
        );
    }
    let governance_revision = match req.governance_revision.as_deref().map(str::trim) {
        Some("") | None => "hosted-self-service-v1".to_owned(),
        Some(v) => v.to_owned(),
    };
    if governance_revision.len() > 256 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "governance_revision must be <= 256 bytes",
        );
    }
    // Hosted self-service archives do not contain governance source bytes, so
    // accepting a content-digest pin would advertise evidence the archive
    // cannot prove. Keep that creation path on reference-only revisions until
    // governance source bytes are included in the Hosted canonical archive.
    if governance_revision.starts_with(GOVERNANCE_PIN_PREFIX_BLAKE3) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_governance_content_pin",
            "Hosted self-service elections do not yet archive governance content for blake3 pins",
        );
    }
    let proposal_question = req.proposal_question.trim().to_owned();
    if proposal_question.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "proposal_question is required for V2 elections",
        );
    }
    // Build the canonical CandidateSet server-side from validated display
    // names; candidate IDs are the trimmed names so duplicate names would
    // already have been rejected above.
    let definitions: Vec<tari_cc_private_ballot_ballot::CandidateDefinition> = match names
        .iter()
        .map(|name| {
            CandidateId::new(name.as_bytes().to_vec()).and_then(|id| {
                tari_cc_private_ballot_ballot::CandidateDefinition::new(id, name.clone())
            })
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "candidate definitions rejected by protocol",
            );
        }
    };
    let candidates = match CandidateSet::new(definitions) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_election",
                "candidate set rejected by protocol",
            );
        }
    };
    let candidate_cbor = match candidates.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "candidate serialization failed",
            );
        }
    };
    let now_ms = now_ms();
    let draft = storage::ElectionDraftRecord {
        election_id: req.election_id.clone(),
        candidate_cbor,
        // Proof suite is pinned server-side; the browser never selects crypto.
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        min_approvals,
        max_approvals,
        allow_abstention,
        governance_revision,
        proposal_question,
        authorized_slot_count: req.authorized_slot_count,
        external_roster_commitment_hex: None,
        eligibility_state: "DRAFT".to_owned(),
        created_at_ms: now_ms,
    };
    match state.storage.put_election_draft(draft) {
        Ok(()) => {}
        Err(storage::StorageError::ElectionExists) => {
            return error_response(
                StatusCode::CONFLICT,
                "election_exists",
                "an election with this id already exists",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    }
    let credential = storage::OrganizerCredentialRecord {
        election_id: req.election_id.clone(),
        // Only the domain-separated verifier is stored; never the plaintext secret.
        organizer_verifier_hex: organizer_verifier(&req.election_id, &secret_bytes),
        created_at_ms: now_ms,
    };
    match state.storage.put_organizer_credential(credential) {
        Ok(()) => {}
        Err(storage::StorageError::ElectionExists) => {
            return error_response(
                StatusCode::CONFLICT,
                "election_exists",
                "an election with this id already exists",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    }
    let body = OrganizerCreateElectionBody {
        election_id: req.election_id,
        eligibility_state: "DRAFT".to_owned(),
        authorized_slot_count: req.authorized_slot_count,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        created_at_ms: now_ms,
        candidates: candidates
            .candidates()
            .iter()
            .map(|c| CandidateJson {
                id_hex: hex_encode(c.id().as_bytes()),
                id_text: String::from_utf8_lossy(c.id().as_bytes()).into_owned(),
                display_name: c.display_name().to_owned(),
            })
            .collect(),
    };
    (StatusCode::CREATED, Json(body)).into_response()
}

async fn organizer_get_election(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    let draft = match state.storage.get_election_draft(&id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "election_not_found",
                "election not found",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    let slots = match state.storage.list_slots(&id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    let consumed = slots.iter().filter(|s| s.consumed).count() as i64;
    let enrolled = match state.storage.count_enrolled_credentials(&id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    let election = state.storage.get_election(&id).ok().flatten();
    let registry_commitment_hex = if draft.eligibility_state == "REGISTRY_FROZEN" {
        state
            .storage
            .get_frozen_registry(&id)
            .ok()
            .flatten()
            .map(|f| f.registry_commitment_hex)
    } else {
        None
    };
    let candidates = match CandidateSet::from_canonical_cbor(&draft.candidate_cbor) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            );
        }
    };
    let transport_binding_status = match state.storage.get_finalized_transport_binding(&id) {
        Ok(Some(_)) => "verified".to_owned(),
        Ok(None) => "missing".to_owned(),
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "transport binding unavailable",
            );
        }
    };
    let finalized_anchor_identity = match election.as_ref().filter(|e| e.state == "finalized") {
        Some(_) => {
            let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
                Ok(loaded) => loaded,
                Err(response) => return response,
            };
            let has_binding = match transport_binding_status.as_str() {
                "verified" => true,
                // A V4 finalized election legitimately has no V5 transport
                // provenance.  It remains viewable and downloadable, but is
                // deliberately not exposed to the browser-anchor workflow.
                "missing" => false,
                _ => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "service_unavailable",
                        "transport binding unavailable",
                    );
                }
            };
            if has_binding {
                match finalized_anchor_identity(&loaded, state.storage.as_ref()) {
                    Ok(identity) => Some(identity),
                    Err(response) => return response,
                }
            } else {
                None
            }
        }
        None => None,
    };
    let body = OrganizerElectionBody {
        election_id: id,
        eligibility_state: draft.eligibility_state,
        election_state: election.map(|e| e.state),
        authorized_slot_count: draft.authorized_slot_count,
        total_slots: slots.len() as i64,
        consumed_slots: consumed,
        available_slots: slots.len() as i64 - consumed,
        enrolled_count: enrolled,
        registry_commitment_hex,
        proof_suite_id: draft.proof_suite_id,
        created_at_ms: draft.created_at_ms,
        candidates: candidates
            .candidates()
            .iter()
            .map(|c| CandidateJson {
                id_hex: hex_encode(c.id().as_bytes()),
                id_text: String::from_utf8_lossy(c.id().as_bytes()).into_owned(),
                display_name: c.display_name().to_owned(),
            })
            .collect(),
        finalized_archive_hash_hex: finalized_anchor_identity
            .as_ref()
            .map(|identity| identity.archive_hash_hex.clone()),
        finalized_anchor_digest_hex: finalized_anchor_identity
            .as_ref()
            .map(|identity| identity.anchor_digest_hex.clone()),
        finalized_public_summary_json: finalized_anchor_identity
            .map(|identity| identity.public_summary_json),
        transport_binding_status,
    };
    Json(body).into_response()
}

async fn organizer_open_enrollment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_open_enrollment(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

async fn organizer_enrollment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_enrollment_status(state.as_ref(), &id) {
        Ok(body) => Json(body).into_response(),
        Err(r) => r,
    }
}

async fn organizer_slots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    let slots = match state.storage.list_slots(&id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    let invitations = match state.storage.list_invitations(&id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    // Newest invitation per slot (any state); exposes election-scoped opaque
    // ids and invitation state only — never invitation secrets or voter keys.
    let mut per_slot: std::collections::HashMap<String, &storage::InvitationRecord> =
        std::collections::HashMap::new();
    for inv in &invitations {
        let entry = per_slot.entry(inv.slot_id.clone());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(inv);
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if inv.created_at_ms >= o.get().created_at_ms {
                    o.insert(inv);
                }
            }
        }
    }
    let mut ordered = slots;
    ordered.sort_by_key(|s| s.created_at_ms);
    let body: Vec<OrganizerSlotBody> = ordered
        .into_iter()
        .map(|s| {
            let inv = per_slot.get(&s.slot_id);
            OrganizerSlotBody {
                slot_id: s.slot_id,
                consumed: s.consumed,
                invitation_id: inv.map(|i| i.invitation_id.clone()),
                invitation_state: inv.map(|i| i.state.clone()),
            }
        })
        .collect();
    Json(body).into_response()
}

async fn organizer_issue_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    if body.len() > MAX_BODY_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "request too large",
        );
    }
    let req: OrganizerIssueInvitationRequest = if body.is_empty() {
        OrganizerIssueInvitationRequest { slot_id: None }
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "malformed issue-invitation request",
                );
            }
        }
    };
    match do_issue_invitation(state.as_ref(), &id, req.slot_id) {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(r) => r,
    }
}

async fn organizer_void_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((id, invitation_id)): AxumPath<(String, String)>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    // The invitation must belong to THIS election; anything else fails
    // closed as not-found without distinguishing foreign elections.
    let invitation = match state.storage.get_invitation_by_id(&invitation_id) {
        Ok(Some(i)) if i.election_id == id => i,
        Ok(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "invitation_not_found",
                "invitation not found for this election",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            );
        }
    };
    match state.storage.set_invitation_state(&invitation.invitation_id, "ACTIVE", "VOIDED") {
        Ok(true) => Json(serde_json::json!({"election_id": id, "invitation_id": invitation_id, "state": "VOIDED"})).into_response(),
        Ok(false) => error_response(StatusCode::CONFLICT, "invalid_state", "invitation is not ACTIVE"),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
    }
}

async fn organizer_freeze(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_freeze_registry(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

async fn organizer_open_voting(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_open_voting(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

async fn organizer_close(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_close(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

fn do_store_finalized_transport_binding(
    state: &AppState,
    id: &str,
    req: DesktopBindingHandoffV1,
) -> Result<Response, Response> {
    let loaded = LoadedElection::load(state.storage.as_ref(), id)?;
    if loaded.record.state != "closed" {
        return Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "transport binding can be recorded only after voting closes",
        ));
    }
    req.validate()
        .map_err(|_| binding_error("the Desktop binding handoff is invalid"))?;
    let manifest_hash = loaded
        .manifest
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "archive identity unavailable",
            )
        })?;
    if req.election_id != id || req.manifest_hash_hex != hex_encode(manifest_hash.as_bytes()) {
        return Err(binding_error(
            "the Desktop binding handoff belongs to another election",
        ));
    }
    let binding_cbor = hex_decode(&req.transport_binding_cbor_hex).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_transport_binding",
            "transport binding must be lowercase-or-uppercase hexadecimal",
        )
    })?;
    let descriptor_cbor = hex_decode(&req.transport_descriptor_cbor_hex).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_transport_binding",
            "transport descriptor must be hexadecimal",
        )
    })?;
    let descriptor = TransportDescriptorV1::from_canonical_cbor(&descriptor_cbor)
        .map_err(|_| binding_error("the supplied transport descriptor is not canonical"))?;
    descriptor.verify(&state.config.transport_authority_root, manifest_hash)
        .map_err(|_| binding_error("the supplied transport descriptor is not authenticated by the configured transport authority"))?;
    if descriptor.election_id() != loaded.manifest.election_id().as_bytes() {
        return Err(binding_error(
            "the supplied transport descriptor belongs to another election",
        ));
    }
    // The supplied descriptor must be byte-for-byte identical to the one issued
    // by the authoritative descriptor endpoint — not merely signed by the same key.
    let issued = state
        .storage
        .get_any_descriptor_issuance(id)
        .map_err(|_| {
            binding_error("authoritative descriptor lookup failed")
        })?
        .ok_or_else(|| {
            binding_error("no authoritative descriptor has been issued for this election")
        })?;
    let issued_descriptor_cbor = HostedDescriptorResponseV1::from_canonical_cbor(&issued.response_cbor)
        .map_err(|_| binding_error("the authoritative descriptor record is invalid"))?
        .descriptor()
        .to_canonical_cbor()
        .map_err(|_| binding_error("the authoritative descriptor cannot be serialized"))?;
    if issued_descriptor_cbor != descriptor_cbor {
        return Err(binding_error(
            "the supplied transport descriptor does not match the authoritative issued descriptor",
        ));
    }
    let (ledger, ballots) = loaded.replay_ledger(state.storage.as_ref())?;
    validate_transport_binding_bytes(
        &loaded,
        &binding_cbor,
        ledger.accepted_ballots().len() as u64,
    )?;
    let accepted_digests: Vec<[u8; 32]> = ballots
        .iter()
        .map(|ballot| {
            hash_domain_separated(
                &Blake3HashProviderV1,
                HashDomain::BallotPackageV1,
                &ballot.package_cbor,
            )
        })
        .collect();
    let expected = finalized_transport_archive_binding_from_accepted_digests_v1(
        &descriptor,
        &accepted_digests,
    )
    .map_err(|_| binding_error("the authoritative transport history cannot be reconstructed"))?
    .ok_or_else(|| {
        binding_error("the authoritative transport history contains no accepted packages")
    })?;
    let expected_cbor = expected
        .to_canonical_cbor()
        .map_err(|_| binding_error("the authoritative transport binding is unavailable"))?;
    if expected_cbor != binding_cbor {
        return Err(binding_error(
            "the supplied transport binding does not match the authenticated transport history",
        ));
    }
    match state
        .storage
        .put_finalized_transport_binding(storage::FinalizedTransportBindingRecord {
            election_id: id.to_owned(),
            binding_cbor,
        }) {
        Ok(()) => Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({
                "election_id": id,
                "state": "transport_binding_recorded",
            })),
        )
            .into_response()),
        Err(storage::StorageError::ElectionNotFound) => Err(error_response(
            StatusCode::NOT_FOUND,
            "election_not_found",
            "election not found",
        )),
        Err(storage::StorageError::InvalidState) => Err(error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "transport binding can be recorded only while the election is closed",
        )),
        // Binding bytes are an immutable archive constituent. Replacing them
        // after inspection would make the election identity mutable.
        Err(storage::StorageError::ElectionExists) => Err(error_response(
            StatusCode::CONFLICT,
            "transport_binding_already_recorded",
            "the finalized transport binding is immutable",
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "transport binding storage unavailable",
        )),
    }
}

async fn organizer_store_transport_binding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    if let Err(r) = check_content_type(&headers) {
        return r;
    }
    if body.len() > MAX_BODY_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "request too large",
        );
    }
    let req: DesktopBindingHandoffV1 = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "malformed transport-binding request",
            );
        }
    };
    match do_store_finalized_transport_binding(state.as_ref(), &id, req) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

/// Produces the public request file that a Desktop organizer uses to prove it
/// is deriving a binding for this exact closed Hosted election.  The request
/// is capability-protected here; the returned response is capability-protected
/// again on import, and contains no organizer secret.
async fn organizer_get_binding_handoff_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    if loaded.record.state != "closed" {
        return error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "Desktop binding handoff is available only while the election is closed",
        );
    }
    let manifest_hash = match loaded.manifest.canonical_hash(&Blake3HashProviderV1) {
        Ok(hash) => hash,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "archive identity unavailable",
            );
        }
    };
    Json(HostedBindingRequestV1::new(
        id,
        hex_encode(manifest_hash.as_bytes()),
    ))
    .into_response()
}

/// Issues the signed, exact-election organizer bootstrap for an authenticated
/// organizer. This is intentionally unavailable for mutable drafts and legacy
/// V1 elections. The browser receives no authority private material.
async fn organizer_download_desktop_bootstrap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    if !matches!(loaded.manifest, ElectionManifest::V2(_))
        || !matches!(
            loaded.record.state.as_str(),
            "open" | "closed" | "finalized"
        )
    {
        return error_response(
            StatusCode::CONFLICT,
            "bootstrap_not_available",
            "Desktop organizer bootstrap is available only for a persisted V2 election",
        );
    }
    let artifacts = match GuiElectionArtifactsV1::from_bytes(
        &loaded.record.manifest_cbor,
        &loaded.record.registry_cbor,
        &loaded.record.candidate_cbor,
    ) {
        Ok(artifacts) => artifacts,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            );
        }
    };
    let signer = match state.config.authority_signer() {
        Ok(signer) => signer,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority_unavailable",
                "release authority is unavailable",
            );
        }
    };
    let payload = match HostedOrganizerBootstrapV1::signing_payload(signer.key_id(), &artifacts) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "bootstrap payload is unavailable",
            );
        }
    };
    let signature = match signer.sign_canonical(&payload) {
        Ok(signature) => signature,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority_unavailable",
                "release authority is unavailable",
            );
        }
    };
    let artifact = match HostedOrganizerBootstrapV1::new_signed(
        signer.key_id().to_owned(),
        &artifacts,
        signature,
    )
    .and_then(|artifact| artifact.to_canonical_cbor())
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "bootstrap artifact is unavailable",
            );
        }
    };
    (
        [
            (header::CONTENT_TYPE, "application/cbor"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"private-ballot-organizer-bootstrap-v1.cbor\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        artifact,
    )
        .into_response()
}

/// Authenticated browser-mediated descriptor issuance. The uploaded artifact
/// is public Desktop-generated data, not an organizer credential; authorization
/// always comes from the existing election-scoped Hosted capability header.
async fn organizer_issue_transport_descriptor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = check_organizer(&state, &headers, &id) {
        return response;
    }
    if let Err(response) = organizer_rate(&state, &id) {
        return response;
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().is_some_and(|value| value.trim() == "application/cbor"))
        != Some(true)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_descriptor_request",
            "descriptor request must be canonical CBOR",
        );
    }
    let request = match HostedDescriptorRequestV1::from_canonical_cbor(&body) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_descriptor_request",
                "descriptor request is invalid",
            );
        }
    };
    let canonical_request = match request.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_descriptor_request", "descriptor request is invalid"),
    };
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    if !matches!(loaded.manifest, ElectionManifest::V2(_)) || loaded.record.state != "open" {
        return error_response(
            StatusCode::CONFLICT,
            "descriptor_not_available",
            "descriptor issuance is available only for an open persisted V2 election",
        );
    }
    let manifest_hash = match loaded.manifest.canonical_hash(&Blake3HashProviderV1) {
        Ok(hash) => hash,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"),
    };
    if request.election_id() != loaded.manifest.election_id().as_bytes()
        || request.manifest_hash() != manifest_hash
        || request.network() != state.config.transport_environment
    {
        return error_response(
            StatusCode::CONFLICT,
            "descriptor_request_mismatch",
            "descriptor request does not match the authoritative election",
        );
    }
    // One authoritative descriptor per election: idempotent replay on the same
    // request_id, hard reject on a different request_id.
    match state.storage.get_any_descriptor_issuance(&loaded.record.id) {
        Ok(Some(existing)) if existing.request_id == request.request_id() => {
            if existing.request_cbor == canonical_request {
                return (
                    [
                        (header::CONTENT_TYPE, "application/cbor"),
                        (header::CONTENT_DISPOSITION, "attachment; filename=\"private-ballot-descriptor-response-v1.cbor\""),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    existing.response_cbor,
                )
                    .into_response();
            } else {
                return error_response(
                    StatusCode::CONFLICT,
                    "descriptor_request_conflict",
                    "descriptor request ID was previously used with different content",
                );
            }
        }
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                "descriptor_already_issued",
                "an authoritative descriptor has already been issued for this election",
            );
        }
        Ok(None) => {}
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "descriptor issuance lookup failed",
            );
        }
    }
    let signer = match state.config.authority_signer() {
        Ok(signer) => signer,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable", "release authority is unavailable"),
    };
    if request.descriptor_draft().root_key_id() != signer.key_id() {
        return error_response(
            StatusCode::CONFLICT,
            "descriptor_request_mismatch",
            "descriptor request names an unexpected authority key",
        );
    }
    let signature = match request
        .descriptor_draft()
        .authority_signing_payload()
        .and_then(|payload| signer.sign_canonical(&payload).map_err(|_| tari_cc_private_ballot_gui_core::TransportError::InvalidDescriptor))
    {
        Ok(signature) => signature,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable", "release authority is unavailable"),
    };
    let descriptor = match request.descriptor_draft().with_authority_signature(signature) {
        Ok(descriptor) => descriptor,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_descriptor_request", "descriptor request is invalid"),
    };
    let response = match HostedDescriptorResponseV1::new(&request, descriptor)
        .and_then(|response| response.to_canonical_cbor().map(|bytes| (response, bytes)))
    {
        Ok(response) => response,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "descriptor response is unavailable"),
    };
    let recorded = match state.storage.record_descriptor_issuance(storage::DescriptorIssuanceRecord {
        election_id: id,
        request_id: request.request_id(),
        request_cbor: canonical_request,
        response_cbor: response.1,
    }) {
        Ok(record) => record,
        Err(StorageError::DescriptorRequestConflict) => {
            return error_response(
                StatusCode::CONFLICT,
                "descriptor_request_conflict",
                "descriptor request ID was previously used with different content",
            );
        }
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "descriptor issuance persistence is unavailable"),
    };
    (
        [
            (header::CONTENT_TYPE, "application/cbor"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"private-ballot-descriptor-response-v1.cbor\""),
            (header::CACHE_CONTROL, "no-store"),
        ],
        recorded.response_cbor,
    )
        .into_response()
}

async fn public_voter_bundle(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    if loaded.record.state != "open" {
        return error_response(
            StatusCode::CONFLICT,
            "voter_bundle_not_available",
            "voter bundle is available only for an open election",
        );
    }
    if !matches!(loaded.manifest, ElectionManifest::V2(_)) {
        return error_response(
            StatusCode::CONFLICT,
            "voter_bundle_not_available",
            "voter bundle is available only for a V2 election",
        );
    }
    let manifest_hash = match loaded.manifest.canonical_hash(&Blake3HashProviderV1) {
        Ok(hash) => hash,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "stored election is invalid",
            )
        }
    };
    let issuance = match state.storage.get_any_descriptor_issuance(&id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return error_response(
                StatusCode::CONFLICT,
                "voter_bundle_not_available",
                "no transport descriptor has been issued for this election",
            )
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "storage unavailable",
            )
        }
    };
    let (authority_key_id, authority_public_key) =
        match &state.config.transport_authority_root {
            TransportAuthorityRootV1::Pinned { key_id, public_key } => {
                (key_id.clone(), *public_key)
            }
            TransportAuthorityRootV1::ProductionNotProvisioned { .. } => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority_unavailable",
                    "transport authority is not provisioned",
                )
            }
        };
    // Decode the persisted descriptor response to extract the authority-signed
    // TransportDescriptorV1 and re-serialize it as the bundle's descriptor_cbor.
    let descriptor_response = match HostedDescriptorResponseV1::from_canonical_cbor(&issuance.response_cbor) {
        Ok(response) => response,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "persisted descriptor response is invalid",
            )
        }
    };
    let descriptor_cbor = match descriptor_response.descriptor().to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "descriptor serialization failed",
            )
        }
    };
    let election_id = loaded.manifest.election_id().as_bytes().to_vec();
    let bundle = match HostedVoterPublicBundleV2::new(
        authority_key_id,
        authority_public_key,
        election_id,
        *manifest_hash.as_bytes(),
        loaded.record.manifest_cbor.clone(),
        loaded.record.registry_cbor.clone(),
        loaded.record.candidate_cbor.clone(),
        descriptor_cbor,
    ) {
        Ok(bundle) => bundle,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "voter bundle construction failed",
            )
        }
    };
    if bundle.verify().is_err() {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "service_unavailable",
            "voter bundle self-verification failed",
        );
    }
    let cbor = match bundle.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "service_unavailable",
                "voter bundle serialization failed",
            )
        }
    };
    (
        [
            (header::CONTENT_TYPE, "application/cbor"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"voter-bundle-v2.cbor\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        cbor,
    )
        .into_response()
}

async fn organizer_finalize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(r) = check_organizer(&state, &headers, &id) {
        return r;
    }
    if let Err(r) = organizer_rate(&state, &id) {
        return r;
    }
    match do_finalize(state.as_ref(), &id) {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

#[cfg(test)]
static TEST_LOG_LINES: std::sync::OnceLock<Mutex<Vec<String>>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn push_test_log_line(line: String) {
    let cell = TEST_LOG_LINES.get_or_init(|| Mutex::new(Vec::new()));
    cell.lock().unwrap_or_else(|e| e.into_inner()).push(line);
}

#[cfg(test)]
pub(crate) fn take_test_log_lines() -> Vec<String> {
    match TEST_LOG_LINES.get() {
        Some(cell) => std::mem::take(&mut cell.lock().unwrap_or_else(|e| e.into_inner())),
        None => Vec::new(),
    }
}

fn logging_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl std::future::Future<Output = Response> {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let start = std::time::Instant::now();
    async move {
        let response = next.run(request).await;
        let status = response.status();
        // Only method/path/status/duration are logged. Request headers
        // (organizer/admin credentials), query strings, and bodies are
        // never logged.
        let line = format!(
            "hosted method={method} path={path} status={} duration_ms={}",
            status.as_u16(),
            start.elapsed().as_millis()
        );
        #[cfg(test)]
        push_test_log_line(line.clone());
        eprintln!("{line}");
        response
    }
}

/// Constant-time comparison for bearer-style tokens (no new dependency).
fn token_equals(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Edge-origin authentication for the public plane. No-op when no origin
/// token is configured (local development). When configured, every
/// `/api/*` request must carry the Worker-injected `x-private-ballot-origin`
/// header; `/health` is exempt so Cloudflare Tunnel health checks work.
/// The browser never knows this token; the Worker injects it.
async fn origin_token_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    if let Some(expected) = &state.config.origin_token {
        let provided = request
            .headers()
            .get(ORIGIN_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !token_equals(provided, expected) {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "origin authentication required",
            );
        }
    }
    next.run(request).await
}

fn public_router_with_state(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/elections/{id}", get(public_package))
        .route("/api/v1/elections/{id}/public-package", get(public_package))
        .route("/api/v1/elections/{id}/ballots", post(submit_ballot))
        .route("/api/v1/elections/{id}/receipt/{receipt_id}", get(get_receipt))
        .route("/api/v1/elections/{id}/results", get(get_results))
        .route("/api/v1/elections/{id}/archive", get(get_archive))
        .route("/api/v1/elections/{id}/enrollment-info", get(public_enrollment_info))
        .route("/api/v1/elections/{id}/voter-bundle", get(public_voter_bundle))
        .route("/api/v1/elections/{id}/enroll", post(enroll_voter))
        .route("/api/v1/ootle/status", get(ootle_status))
        // Self-service organizer plane: election-scoped capability
        // credentials only. Separate namespace from /api/v1/admin (which
        // exists only on the loopback admin plane and is never routed here).
        .route("/api/v1/organizer/elections", post(organizer_create_election))
        .route("/api/v1/organizer/elections/{id}", get(organizer_get_election))
        .route("/api/v1/organizer/elections/{id}/open-enrollment", post(organizer_open_enrollment))
        .route("/api/v1/organizer/elections/{id}/enrollment", get(organizer_enrollment))
        .route("/api/v1/organizer/elections/{id}/slots", get(organizer_slots))
        .route("/api/v1/organizer/elections/{id}/invitations", post(organizer_issue_invitation))
        .route("/api/v1/organizer/elections/{id}/invitations/{invitation_id}/void", post(organizer_void_invitation))
        .route("/api/v1/organizer/elections/{id}/freeze", post(organizer_freeze))
        .route("/api/v1/organizer/elections/{id}/open-voting", post(organizer_open_voting))
        .route("/api/v1/organizer/elections/{id}/close", post(organizer_close))
        .route("/api/v1/organizer/elections/{id}/desktop-bootstrap", get(organizer_download_desktop_bootstrap))
        .route("/api/v1/organizer/elections/{id}/descriptor-issuance", post(organizer_issue_transport_descriptor))
        .route("/api/v1/organizer/elections/{id}/binding-handoff", get(organizer_get_binding_handoff_request))
        .route("/api/v1/organizer/elections/{id}/transport-binding", post(organizer_store_transport_binding))
        .route("/api/v1/organizer/elections/{id}/finalize", post(organizer_finalize))
        .route(
            "/api/v1/organizer/elections/{id}/archive",
            get(organizer_get_archive),
        )
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(state, origin_token_middleware))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(logging_middleware))
}

/// Admin plane: organizer mutations only, loopback-only listener, never
/// routed through Cloudflare. Token-gated when configured.
pub fn admin_router_with_state(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin-health", get(health))
        // Legacy import (pre-enrollment flow, sets state=open directly)
        .route("/api/v1/admin/elections/import", post(admin_import))
        .route("/api/v1/admin/elections/{id}/close", post(admin_close))
        .route("/api/v1/admin/elections/{id}/finalize", post(admin_finalize))
        // Invitation enrollment flow
        .route("/api/v1/admin/elections/draft", post(admin_create_draft))
        .route("/api/v1/admin/elections/{id}/open-enrollment", post(admin_open_enrollment))
        .route("/api/v1/admin/elections/{id}/invitations", post(admin_issue_invitation))
        .route("/api/v1/admin/elections/{id}/invitations/{invitation_id}/void", post(admin_void_invitation))
        .route("/api/v1/admin/elections/{id}/enrollment", get(admin_enrollment_status))
        .route("/api/v1/admin/elections/{id}/freeze", post(admin_freeze_registry))
        .route("/api/v1/admin/elections/{id}/open-voting", post(admin_open_voting))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(logging_middleware))
}

/// Public plane only: voter-facing routes, no admin routes. This is the
/// only router the Cloudflare Tunnel may route to.
pub fn router_with_state(state: Arc<AppState>) -> Router {
    public_router_with_state(state)
}

#[must_use]
pub fn router(config: HostedConfig) -> Router {
    let state = Arc::new(AppState::new(config, Arc::new(InMemoryStorage::new())));
    public_router_with_state(state)
}

pub fn test_config() -> HostedConfig {
    HostedConfig {
        bind: "127.0.0.1:8788".to_owned(),
        admin_bind: "127.0.0.1:8789".to_owned(),
        service_name: "test".to_owned(),
        api_version: "v1".to_owned(),
        db_path: PathBuf::from(":memory:"),
        admin_token: Some("test-admin-token".to_owned()),
        origin_token: None,
        allow_public_bind: false,
        rate_limit_per_minute: 10_000,
        organizer_max_slots: DEFAULT_ORGANIZER_MAX_SLOTS,
        transport_authority_root: production_transport_authority_root_v1(),
        transport_environment: "test".to_owned(),
        authority_signing_key: None,
    }
}

async fn shutdown_signal(shutdown: impl Future<Output = ()> + Send + 'static) {
    shutdown.await;
}

pub async fn serve_with_state(
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let public_bind = state.config.bind.clone();
    let admin_bind = state.config.admin_bind.clone();
    let public_listener = tokio::net::TcpListener::bind(&public_bind)
        .await
        .map_err(|_| "HOSTED_BIND_FAILED".to_owned())?;
    let admin_listener = tokio::net::TcpListener::bind(&admin_bind)
        .await
        .map_err(|_| "HOSTED_BIND_FAILED".to_owned())?;
    let public_app = public_router_with_state(state.clone());
    let admin_app = admin_router_with_state(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal(shutdown).await;
        let _ = shutdown_tx.send(true);
    });
    let mut public_rx = shutdown_rx.clone();
    let public_server =
        axum::serve(public_listener, public_app).with_graceful_shutdown(async move {
            loop {
                if *public_rx.borrow() {
                    break;
                }
                if public_rx.changed().await.is_err() {
                    break;
                }
            }
        });
    let mut admin_rx = shutdown_rx;
    let admin_server = axum::serve(admin_listener, admin_app).with_graceful_shutdown(async move {
        loop {
            if *admin_rx.borrow() {
                break;
            }
            if admin_rx.changed().await.is_err() {
                break;
            }
        }
    });
    tokio::select! {
        result = public_server => result.map_err(|_| "HOSTED_SERVE_FAILED".to_owned()),
        result = admin_server => result.map_err(|_| "HOSTED_SERVE_FAILED".to_owned()),
    }
}

pub async fn serve(
    config: HostedConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let storage = SqliteStorage::open(&config.db_path).map_err(|e| e.as_str().to_owned())?;
    let state = Arc::new(AppState::new(config, Arc::new(storage)));
    serve_with_state(state, shutdown).await
}

pub fn verify_archive_dir_for_test(dir: &Path) -> bool {
    verify_archive_directory_v1(dir)
        .map(|v| v.verified && v.finalized)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests;
