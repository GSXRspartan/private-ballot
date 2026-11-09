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
//! Two control planes (Stage 3): the PUBLIC plane (`127.0.0.1:8788` by
//! default) serves only voter-facing routes and is the only listener the
//! Cloudflare Tunnel may route to. The ADMIN plane (`127.0.0.1:8789` by
//! default) serves only organizer/admin mutation routes, is always
//! loopback-only, and must never be routed through Cloudflare. The public
//! plane has no admin routes at all (404), so public admin access fails
//! even if edge blocking fails. When `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN`
//! is set, the public plane additionally requires the Worker-injected
//! `x-private-ballot-origin` header (`/health` exempt for Tunnel checks);
//! the token is never in browser JavaScript. Unset token = local dev, no
//! header check.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderName, StatusCode},
    routing::{get, post},
    response::{IntoResponse, Response},
    extract::DefaultBodyLimit,
};
use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1,
    ArchiveManifestV1, ArchivePathV1, verify_archive_directory_v1,
    ELECTION_MANIFEST_ARCHIVE_PATH, CANDIDATE_SET_ARCHIVE_PATH, VOTER_REGISTRY_ARCHIVE_PATH,
    SUBMISSIONS_ARCHIVE_DIR,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, CandidateSet,
    ElectionManifest,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, HashProvider, ValidationCode,
    hash_domain_separated,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_tally::ApprovalTally;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, build_tari_triptych_verifier_from_registry_v1,
    ingest_approval_ballot_package_v1,
};

pub use tari_cc_private_ballot_deployment_registry as deployment_registry;

pub mod storage;
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
pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

fn is_loopback_bind(bind: &str) -> Option<bool> {
    let host = bind.rsplit(':').nth(1)?;
    Some(host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]")
}

impl HostedConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = std::env::var("PRIVATE_BALLOT_HOSTED_BIND")
            .unwrap_or_else(|_| std::env::var("HOSTED_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned()));
        let admin_bind = std::env::var("PRIVATE_BALLOT_HOSTED_ADMIN_BIND")
            .unwrap_or_else(|_| DEFAULT_ADMIN_BIND.to_owned());
        let service_name = std::env::var("PRIVATE_BALLOT_HOSTED_SERVICE").unwrap_or_else(|_| "hosted".to_owned());
        let api_version = std::env::var("PRIVATE_BALLOT_HOSTED_API_VERSION").unwrap_or_else(|_| "v1".to_owned());
        let db_path = PathBuf::from(std::env::var("PRIVATE_BALLOT_HOSTED_DB").unwrap_or_else(|_| "hosted.db".to_owned()));
        let admin_token = std::env::var("PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN").ok().filter(|v| !v.trim().is_empty());
        let origin_token = std::env::var("PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN").ok().filter(|v| !v.trim().is_empty());
        let allow_public_bind = std::env::var("PRIVATE_BALLOT_HOSTED_ALLOW_PUBLIC_BIND").is_ok_and(|v| v == "1");
        let rate_limit_per_minute = std::env::var("PRIVATE_BALLOT_HOSTED_RATE_LIMIT_PER_MIN")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(120);
        Self { bind, admin_bind, service_name, api_version, db_path, admin_token, origin_token, allow_public_bind, rate_limit_per_minute }.validate()
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
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError { InvalidBind, NonLoopbackBind, AdminBindNotLoopback }
impl ConfigError {
    #[must_use] pub const fn as_str(self) -> &'static str {
        match self { Self::InvalidBind => "HOSTED_CONFIG_INVALID_BIND", Self::NonLoopbackBind => "HOSTED_CONFIG_NON_LOOPBACK_BIND", Self::AdminBindNotLoopback => "HOSTED_CONFIG_ADMIN_BIND_NOT_LOOPBACK" }
    }
}
impl core::fmt::Display for ConfigError { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(self.as_str()) } }
impl std::error::Error for ConfigError {}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { out.push_str(&format!("{b:02x}")); }
    out
}
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    let input = input.trim();
    if input.len() % 2 != 0 || !input.chars().all(|c| c.is_ascii_hexdigit()) { return Err(()); }
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

fn envelope_hash_hex(package: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    hex_encode(&hash_domain_separated(&p, HashDomain::BallotPackageV1, package))
}
fn package_binding_hash_hex(manifest: &[u8], registry: &[u8], candidates: &[u8]) -> String {
    let p = Blake3HashProviderV1;
    let mut input = Vec::with_capacity(manifest.len() + registry.len() + candidates.len());
    input.extend_from_slice(manifest); input.extend_from_slice(registry); input.extend_from_slice(candidates);
    hex_encode(&p.hash(&input))
}

fn receipt_id_for(election_id: &str, client_receipt_id: &str, envelope_hash: &str) -> String {
    let p = Blake3HashProviderV1;
    let mut input = Vec::new();
    input.extend_from_slice(b"hosted-receipt-v1\0");
    input.extend_from_slice(election_id.as_bytes()); input.push(0);
    input.extend_from_slice(client_receipt_id.as_bytes()); input.push(0);
    input.extend_from_slice(envelope_hash.as_bytes());
    hex_encode(&p.hash(&input))
}

#[derive(Debug, Clone, Serialize)]
struct HealthBody { status: &'static str }
#[derive(Debug, Clone, Serialize)]
struct StatusBody { service: String, api_version: String, mode: &'static str }
#[derive(Debug, Clone, Serialize)]
struct ErrorBody { code: &'static str, message: &'static str }
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
        Self { config, storage, ingest_lock: Mutex::new(()), rate: Mutex::new(HashMap::new()) }
    }
    fn check_rate(&self, election_id: &str, ip: &str) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry((election_id.to_owned(), ip.to_owned())).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60 { *entry = (now, 0); }
        entry.1 += 1;
        entry.1 <= self.config.rate_limit_per_minute
    }
}

async fn health() -> Json<HealthBody> { Json(HealthBody { status: "ok" }) }
async fn status(State(state): State<Arc<AppState>>) -> Json<StatusBody> {
    Json(StatusBody { service: state.config.service_name.clone(), api_version: state.config.api_version.clone(), mode: "stage2" })
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
        let record = storage.get_election(id).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "election_not_found", "election not found"))?;
        let manifest = ElectionManifest::from_canonical_cbor(&record.manifest_cbor)
            .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        let candidates = CandidateSet::from_canonical_cbor(&record.candidate_cbor)
            .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        let registry = RegistrySnapshot::from_canonical_cbor(&record.registry_cbor)
            .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        let p = Blake3HashProviderV1;
        let manifest_hash = manifest.canonical_hash(&p).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        Ok(Self { record, manifest, candidates, registry, manifest_hash_hex: hex_encode(manifest_hash.as_bytes()) })
    }
    fn open_lifecycle(&self) -> Result<tari_cc_private_ballot_ballot::ElectionLifecycleV1, Response> {
        let p = Blake3HashProviderV1;
        let mh = self.manifest.canonical_hash(&p).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        let mut lc = tari_cc_private_ballot_ballot::ElectionLifecycleV1::new();
        lc.freeze(mh, self.manifest.registry_commitment()).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        lc.open().map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        Ok(lc)
    }
    fn replay_ledger(&self, storage: &dyn HostedStorage) -> Result<(BallotAcceptanceLedger, Vec<storage::BallotRecord>), Response> {
        let ballots = storage.list_ballots(&self.record.id).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"))?;
        let lifecycle = self.open_lifecycle()?;
        let p = Blake3HashProviderV1;
        let verifier = build_tari_triptych_verifier_from_registry_v1(&self.registry, &p)
            .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid"))?;
        let mut ledger = BallotAcceptanceLedger::new();
        for b in &ballots {
            ingest_approval_ballot_package_v1(&b.package_cbor, &self.manifest, &self.candidates, &lifecycle, &mut ledger, &p, &verifier)
                .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored ballot failed replay"))?;
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
struct CandidateJson { id_hex: String, id_text: String, display_name: String }

async fn public_package(State(state): State<Arc<AppState>>, AxumPath(id): AxumPath<String>) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) { Ok(v) => v, Err(r) => return r };
    let p = Blake3HashProviderV1;
    let candidates: Vec<CandidateJson> = loaded.candidates.candidates().iter().map(|c| CandidateJson {
        id_hex: hex_encode(c.id().as_bytes()),
        id_text: String::from_utf8_lossy(c.id().as_bytes()).into_owned(),
        display_name: c.display_name().to_owned(),
    }).collect();
    let body = PublicPackageBody {
        election_id: id.clone(),
        state: loaded.record.state.clone(),
        manifest_cbor_hex: hex_encode(&loaded.record.manifest_cbor),
        registry_cbor_hex: hex_encode(&loaded.record.registry_cbor),
        candidate_cbor_hex: hex_encode(&loaded.record.candidate_cbor),
        manifest_hash_hex: loaded.manifest_hash_hex.clone(),
        registry_commitment_hex: hex_encode(loaded.manifest.registry_commitment().as_bytes()),
        candidate_commitment_hex: hex_encode(loaded.manifest.candidate_set_commitment().as_bytes()),
        package_hash_hex: package_binding_hash_hex(&loaded.record.manifest_cbor, &loaded.record.registry_cbor, &loaded.record.candidate_cbor),
        proof_suite_id: loaded.manifest.proof_suite_id().to_owned(),
        eligible_voter_count: loaded.registry.entries().len() as u64,
        candidates,
    };
    let _ = p;
    Json(body).into_response()
}

#[derive(Debug, Deserialize)]
struct BallotRequest { receipt_id: String, package_cbor_hex: String, api_version: String }

fn check_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let ct = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    if ct.starts_with("application/json") { Ok(()) } else { Err(error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type", "content type must be application/json")) }
}

async fn submit_ballot(State(state): State<Arc<AppState>>, AxumPath(id): AxumPath<String>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = check_content_type(&headers) { return r; }
    if body.len() > MAX_BALLOT_BODY_BYTES { return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "ballot submission too large"); }
    let req: BallotRequest = match serde_json::from_slice(&body) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "ballot_invalid", "malformed ballot request") };
    if req.api_version != "v1" { return error_response(StatusCode::BAD_REQUEST, "unsupported_api_version", "unsupported api version"); }
    if req.receipt_id.trim().is_empty() || req.receipt_id.len() > 128 { return error_response(StatusCode::BAD_REQUEST, "ballot_invalid", "invalid receipt id"); }
    let package = match hex_decode(&req.package_cbor_hex) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "ballot_invalid", "invalid package encoding") };
    if package.len() > 32 * 1024 { return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "ballot submission too large"); }
    if !state.check_rate(&id, "transport") { return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "rate limit exceeded"); }

    let _guard = state.ingest_lock.lock().unwrap_or_else(|e| e.into_inner());
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) { Ok(v) => v, Err(r) => return r };
    if loaded.record.state != "open" { return error_response(StatusCode::CONFLICT, "election_closed", "election is not open for ballots"); }
    let env_hash = envelope_hash_hex(&package);
    if let Some(existing) = state.storage.get_ballot_by_receipt(&id, &req.receipt_id).ok().flatten() {
        if existing.envelope_hash_hex == env_hash {
            let body = ReceiptBody { election_id: id.clone(), receipt_id: req.receipt_id.clone(), stable_receipt: receipt_id_for(&id, &req.receipt_id, &env_hash), envelope_hash_hex: env_hash, nullifier_hex: hex_encode(&existing.nullifier), status: "accepted", replay: true, seq: existing.seq };
            return (StatusCode::OK, [(HeaderName::from_static("cache-control"), "private, no-store")], Json(body)).into_response();
        }
        return error_response(StatusCode::CONFLICT, "duplicate_receipt", "receipt id already used with a different envelope");
    }
    let (mut ledger, existing_ballots) = match loaded.replay_ledger(state.storage.as_ref()) { Ok(v) => v, Err(r) => return r };
    let lifecycle = match loaded.open_lifecycle() { Ok(v) => v, Err(r) => return r };
    let p = Blake3HashProviderV1;
    let verifier = match build_tari_triptych_verifier_from_registry_v1(&loaded.registry, &p) { Ok(v) => v, Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "stored election is invalid") };
    let before = ledger.len();
    match ingest_approval_ballot_package_v1(&package, &loaded.manifest, &loaded.candidates, &lifecycle, &mut ledger, &p, &verifier) {
        Ok(()) => {}
        Err(e) => {
            let code = e.code();
            return match code {
                ValidationCode::DuplicateNullifier => error_response(StatusCode::CONFLICT, "duplicate_nullifier", "nullifier already counted"),
                ValidationCode::WrongManifestHash => error_response(StatusCode::UNPROCESSABLE_ENTITY, "wrong_election", "ballot is bound to a different election"),
                ValidationCode::ElectionNotOpen => error_response(StatusCode::CONFLICT, "election_closed", "election is not open for ballots"),
                _ => error_response(StatusCode::UNPROCESSABLE_ENTITY, "ballot_invalid", "ballot verification failed"),
            };
        }
    }
    if ledger.len() != before + 1 { return error_response(StatusCode::UNPROCESSABLE_ENTITY, "ballot_invalid", "ballot verification failed"); }
    let nullifier = ledger.accepted_ballots().last().map(|b| b.verified_nullifier().as_bytes().to_vec()).unwrap_or_default();
    let seq = (existing_ballots.len() + 1) as u64;
    let record = storage::BallotRecord { election_id: id.clone(), receipt_id: req.receipt_id.clone(), package_cbor: package.clone(), envelope_hash_hex: env_hash.clone(), nullifier: nullifier.clone(), seq };
    match state.storage.insert_ballot(record) {
        Ok(()) => {}
        Err(storage::StorageError::DuplicateNullifier) => return error_response(StatusCode::CONFLICT, "duplicate_nullifier", "nullifier already counted"),
        Err(storage::StorageError::DuplicateReceipt) => return error_response(StatusCode::CONFLICT, "duplicate_receipt", "receipt id already used"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
    }
    let body = ReceiptBody { election_id: id.clone(), receipt_id: req.receipt_id.clone(), stable_receipt: receipt_id_for(&id, &req.receipt_id, &env_hash), envelope_hash_hex: env_hash, nullifier_hex: hex_encode(&nullifier), status: "accepted", replay: false, seq };
    (StatusCode::CREATED, [(HeaderName::from_static("cache-control"), "private, no-store")], Json(body)).into_response()
}

async fn get_receipt(State(state): State<Arc<AppState>>, AxumPath((id, receipt_id)): AxumPath<(String, String)>) -> Response {
    let existing = match state.storage.get_ballot_by_receipt(&id, &receipt_id) { Ok(v) => v, Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable") };
    match existing {
        Some(b) => {
            let body = ReceiptBody { election_id: id.clone(), receipt_id: receipt_id.clone(), stable_receipt: receipt_id_for(&id, &receipt_id, &b.envelope_hash_hex), envelope_hash_hex: b.envelope_hash_hex, nullifier_hex: hex_encode(&b.nullifier), status: "accepted", replay: false, seq: b.seq };
            (StatusCode::OK, [(HeaderName::from_static("cache-control"), "private, no-store")], Json(body)).into_response()
        }
        None => error_response(StatusCode::NOT_FOUND, "receipt_not_found", "receipt not found"),
    }
}

#[derive(Debug, Serialize)]
struct ResultsBody { election_id: String, state: String, accepted_ballots: u64, abstentions: u64, counts: Vec<CountJson>, leading: String }
#[derive(Debug, Serialize)]
struct CountJson { candidate_id_hex: String, candidate_id_text: String, display_name: String, approvals: u64 }

async fn get_results(State(state): State<Arc<AppState>>, AxumPath(id): AxumPath<String>) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) { Ok(v) => v, Err(r) => return r };
    if loaded.record.state != "finalized" { return error_response(StatusCode::CONFLICT, "election_not_finalized", "results are available only after finalization"); }
    let (ledger, _) = match loaded.replay_ledger(state.storage.as_ref()) { Ok(v) => v, Err(r) => return r };
    let payloads: Vec<ApprovalBallotPayload> = ledger.accepted_ballots().iter().map(|b| b.payload().clone()).collect();
    let tally = match ApprovalTally::from_ballots(&loaded.candidates, payloads.iter()) { Ok(v) => v, Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "tally failed") };
    let mut counts = Vec::new();
    for c in tally.counts() {
        let text = String::from_utf8_lossy(c.candidate_id().as_bytes()).into_owned();
        let display = loaded.candidates.candidates().iter().find(|x| x.id() == c.candidate_id()).map(|x| x.display_name().to_owned()).unwrap_or_default();
        counts.push(CountJson { candidate_id_hex: hex_encode(c.candidate_id().as_bytes()), candidate_id_text: text, display_name: display, approvals: c.approvals() });
    }
    let leading = match tally.leading_result() {
        tari_cc_private_ballot_tally::LeadingResult::NoApprovals => "NO_APPROVALS".to_owned(),
        tari_cc_private_ballot_tally::LeadingResult::SingleLeader { candidate_id, approvals } => format!("SINGLE_LEADER:{}:{}", hex_encode(candidate_id.as_bytes()), approvals),
        tari_cc_private_ballot_tally::LeadingResult::Tie { candidate_ids, approvals } => format!("TIE:{}:{}", candidate_ids.iter().map(|c| hex_encode(c.as_bytes())).collect::<Vec<_>>().join(","), approvals),
    };
    Json(ResultsBody { election_id: id, state: loaded.record.state.clone(), accepted_ballots: tally.accepted_ballots(), abstentions: tally.abstentions(), counts, leading }).into_response()
}

fn build_archive_files(loaded: &LoadedElection, ballots: &[storage::BallotRecord]) -> Result<(BTreeMap<String, Vec<u8>>, String), Response> {
    let p = Blake3HashProviderV1;
    let manifest_hash = loaded.manifest.canonical_hash(&p).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "archive failed"))?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(ELECTION_MANIFEST_ARCHIVE_PATH.to_owned(), loaded.record.manifest_cbor.clone());
    files.insert(CANDIDATE_SET_ARCHIVE_PATH.to_owned(), loaded.record.candidate_cbor.clone());
    files.insert(VOTER_REGISTRY_ARCHIVE_PATH.to_owned(), loaded.record.registry_cbor.clone());
    for (i, b) in ballots.iter().enumerate() { files.insert(format!("{SUBMISSIONS_ARCHIVE_DIR}/{i:08}.cbor"), b.package_cbor.clone()); }
    let entries: Vec<ArchiveFileEntryV1> = files.iter().map(|(path, bytes)| {
        let ap = ArchivePathV1::new(path.clone()).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "archive failed"))?;
        Ok(ArchiveFileEntryV1::for_bytes(ap, &p, bytes))
    }).collect::<Result<Vec<_>, Response>>()?;
    let catalog = ArchiveFileCatalogV1::new(entries).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "archive failed"))?;
    let manifest = ArchiveManifestV1::finalized_for_provider(manifest_hash, catalog, &p).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "archive failed"))?;
    let hash = manifest.canonical_hash(&p).map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "archive failed"))?;
    Ok((files, hex_encode(hash.as_bytes())))
}

pub fn write_archive_directory(loaded_files: &BTreeMap<String, Vec<u8>>, archive_manifest_bytes: &[u8], target_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(target_dir).map_err(|_| "archive_dir_failed".to_owned())?;
    let submissions = target_dir.join(SUBMISSIONS_ARCHIVE_DIR);
    if loaded_files.keys().any(|k| k.starts_with(SUBMISSIONS_ARCHIVE_DIR)) { std::fs::create_dir_all(&submissions).map_err(|_| "archive_dir_failed".to_owned())?; }
    for (path, bytes) in loaded_files { let fp = target_dir.join(path); if let Some(parent) = fp.parent() { std::fs::create_dir_all(parent).map_err(|_| "archive_dir_failed".to_owned())?; } std::fs::write(&fp, bytes).map_err(|_| "archive_write_failed".to_owned())?; }
    std::fs::write(target_dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH), archive_manifest_bytes).map_err(|_| "archive_write_failed".to_owned())?;
    Ok("ok".to_owned())
}

#[derive(Debug, Serialize)]
struct ArchiveBody { election_id: String, archive_hash_hex: String, files: Vec<ArchiveFileJson> }
#[derive(Debug, Serialize)]
struct ArchiveFileJson { path: String, cbor_hex: String }

async fn get_archive(State(state): State<Arc<AppState>>, AxumPath(id): AxumPath<String>) -> Response {
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) { Ok(v) => v, Err(r) => return r };
    if loaded.record.state != "finalized" { return error_response(StatusCode::CONFLICT, "election_not_finalized", "archive is available only after finalization"); }
    let ballots = match state.storage.list_ballots(&id) { Ok(v) => v, Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable") };
    let (files, archive_hash) = match build_archive_files(&loaded, &ballots) { Ok(v) => v, Err(r) => return r };
    Json(ArchiveBody { election_id: id, archive_hash_hex: archive_hash, files: files.into_iter().map(|(path, bytes)| ArchiveFileJson { path, cbor_hex: hex_encode(&bytes) }).collect() }).into_response()
}

async fn ootle_status(State(state): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({"network": "ootle-v0.51.0-cohort", "deployment_registry": "present", "anchor_publication": "not_configured_in_stage2_prototype", "service": state.config.service_name})).into_response()
}

// ---------- Admin (localhost, token-gated when configured) ----------
fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if let Some(token) = &state.config.admin_token {
        let provided = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !token_equals(provided, token) { return Err(error_response(StatusCode::UNAUTHORIZED, "unauthorized", "admin token required")); }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ImportRequest { election_id: String, manifest_cbor_hex: String, registry_cbor_hex: String, candidate_cbor_hex: String }

async fn admin_import(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = check_admin(&state, &headers) { return r; }
    if let Err(r) = check_content_type(&headers) { return r; }
    let req: ImportRequest = match serde_json::from_slice(&body) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_election", "malformed import request") };
    let manifest_cbor = match hex_decode(&req.manifest_cbor_hex) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_election", "invalid manifest encoding") };
    let registry_cbor = match hex_decode(&req.registry_cbor_hex) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_election", "invalid registry encoding") };
    let candidate_cbor = match hex_decode(&req.candidate_cbor_hex) { Ok(v) => v, Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_election", "invalid candidate encoding") };
    let manifest = match ElectionManifest::from_canonical_cbor(&manifest_cbor) { Ok(v) => v, Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "manifest does not decode") };
    let candidates = match CandidateSet::from_canonical_cbor(&candidate_cbor) { Ok(v) => v, Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "candidate set does not decode") };
    let registry = match RegistrySnapshot::from_canonical_cbor(&registry_cbor) { Ok(v) => v, Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "registry does not decode") };
    if manifest.election_id().as_bytes() != req.election_id.as_bytes() { return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "election id does not match manifest"); }
    let p = Blake3HashProviderV1;
    let reg_commit = match registry.canonical_commitment(&p) { Ok(v) => v, Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "registry commitment failed") };
    let cand_commit = match candidates.canonical_commitment(&p) { Ok(v) => v, Err(_) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "candidate commitment failed") };
    if reg_commit != manifest.registry_commitment() || cand_commit != manifest.candidate_set_commitment() {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "manifest commitments do not match supplied artifacts");
    }
    if build_tari_triptych_verifier_from_registry_v1(&registry, &p).is_err() { return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "registry verifier construction failed"); }
    // Canonical round-trip check (rejects non-canonical encodings).
    if manifest.to_canonical_cbor().ok() != Some(manifest_cbor.clone()) || candidates.to_canonical_cbor().ok() != Some(candidate_cbor.clone()) || registry.to_canonical_cbor().ok() != Some(registry_cbor.clone()) {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_election", "artifacts are not canonical");
    }
    let mh = manifest.canonical_hash(&p).map(|h| hex_encode(h.as_bytes())).unwrap_or_default();
    let record = storage::ElectionRecord { id: req.election_id.clone(), manifest_cbor, registry_cbor, candidate_cbor, state: "open".to_owned(), manifest_hash_hex: mh };
    match state.storage.put_election(record) {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!({"election_id": req.election_id, "state": "open"}))).into_response(),
        Err(storage::StorageError::ElectionExists) => error_response(StatusCode::CONFLICT, "election_exists", "election already imported"),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
    }
}

async fn admin_close(State(state): State<Arc<AppState>>, headers: HeaderMap, AxumPath(id): AxumPath<String>) -> Response {
    if let Err(r) = check_admin(&state, &headers) { return r; }
    match state.storage.set_election_state(&id, "open", "closed") {
        Ok(true) => Json(serde_json::json!({"election_id": id, "state": "closed"})).into_response(),
        Ok(false) => error_response(StatusCode::CONFLICT, "invalid_state", "election is not open"),
        Err(storage::StorageError::ElectionNotFound) => error_response(StatusCode::NOT_FOUND, "election_not_found", "election not found"),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
    }
}

async fn admin_finalize(State(state): State<Arc<AppState>>, headers: HeaderMap, AxumPath(id): AxumPath<String>) -> Response {
    if let Err(r) = check_admin(&state, &headers) { return r; }
    let loaded = match LoadedElection::load(state.storage.as_ref(), &id) { Ok(v) => v, Err(r) => return r };
    if loaded.record.state != "closed" { return error_response(StatusCode::CONFLICT, "invalid_state", "election is not closed"); }
    // Replay through canonical ledger (no secret needed; packages are public by protocol).
    if let Err(r) = loaded.replay_ledger(state.storage.as_ref()) { return r; }
    match state.storage.set_election_state(&id, "closed", "finalized") {
        Ok(true) => {
            let ballots = state.storage.list_ballots(&id).unwrap_or_default();
            let (_, archive_hash) = build_archive_files(&loaded, &ballots).unwrap_or((BTreeMap::new(), String::new()));
            Json(serde_json::json!({"election_id": id, "state": "finalized", "archive_hash_hex": archive_hash, "accepted_ballots": ballots.len()})).into_response()
        }
        Ok(false) => error_response(StatusCode::CONFLICT, "invalid_state", "election is not closed"),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "service_unavailable", "storage unavailable"),
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
        eprintln!("hosted method={method} path={path} status={} duration_ms={}", status.as_u16(), start.elapsed().as_millis());
        response
    }
}

/// Constant-time comparison for bearer-style tokens (no new dependency).
fn token_equals(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
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
        let provided = request.headers().get(ORIGIN_TOKEN_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
        if !token_equals(provided, expected) {
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "origin authentication required");
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
        .route("/api/v1/ootle/status", get(ootle_status))
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
        .route("/api/v1/admin/elections/import", post(admin_import))
        .route("/api/v1/admin/elections/{id}/close", post(admin_close))
        .route("/api/v1/admin/elections/{id}/finalize", post(admin_finalize))
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
    HostedConfig { bind: "127.0.0.1:8788".to_owned(), admin_bind: "127.0.0.1:8789".to_owned(), service_name: "test".to_owned(), api_version: "v1".to_owned(), db_path: PathBuf::from(":memory:"), admin_token: Some("test-admin-token".to_owned()), origin_token: None, allow_public_bind: false, rate_limit_per_minute: 10_000 }
}

async fn shutdown_signal(shutdown: impl Future<Output = ()> + Send + 'static) {
    shutdown.await;
}

pub async fn serve_with_state(state: Arc<AppState>, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<(), String> {
    let public_bind = state.config.bind.clone();
    let admin_bind = state.config.admin_bind.clone();
    let public_listener = tokio::net::TcpListener::bind(&public_bind).await.map_err(|_| "HOSTED_BIND_FAILED".to_owned())?;
    let admin_listener = tokio::net::TcpListener::bind(&admin_bind).await.map_err(|_| "HOSTED_BIND_FAILED".to_owned())?;
    let public_app = public_router_with_state(state.clone());
    let admin_app = admin_router_with_state(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal(shutdown).await;
        let _ = shutdown_tx.send(true);
    });
    let mut public_rx = shutdown_rx.clone();
    let public_server = axum::serve(public_listener, public_app).with_graceful_shutdown(async move {
        loop {
            if *public_rx.borrow() { break; }
            if public_rx.changed().await.is_err() { break; }
        }
    });
    let mut admin_rx = shutdown_rx;
    let admin_server = axum::serve(admin_listener, admin_app).with_graceful_shutdown(async move {
        loop {
            if *admin_rx.borrow() { break; }
            if admin_rx.changed().await.is_err() { break; }
        }
    });
    tokio::select! {
        result = public_server => result.map_err(|_| "HOSTED_SERVE_FAILED".to_owned()),
        result = admin_server => result.map_err(|_| "HOSTED_SERVE_FAILED".to_owned()),
    }
}

pub async fn serve(config: HostedConfig, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<(), String> {
    let storage = SqliteStorage::open(&config.db_path).map_err(|e| e.as_str().to_owned())?;
    let state = Arc::new(AppState::new(config, Arc::new(storage)));
    serve_with_state(state, shutdown).await
}

pub fn verify_archive_dir_for_test(dir: &Path) -> bool {
    verify_archive_directory_v1(dir).map(|v| v.verified && v.finalized).unwrap_or(false)
}

#[cfg(test)]
mod tests;
