#![forbid(unsafe_code)]

//! Hosted/Web backend skeleton (Stage 1).
//!
//! This crate provides only the minimal surface Stage 2 needs: configuration
//! loading, startup validation, a loopback-only HTTP server with `/health` and
//! `/api/v1/status`, graceful shutdown, and a storage abstraction. It does
//! **not** implement ballot ingestion, cryptographic verification, or any
//! Ootle interaction. The domain core and Ootle adapter are dependency
//! boundaries for later stages (see `docs/hosted/`).
//!
//! Security posture: binds to `127.0.0.1` by default, never `0.0.0.0`;
//! request bodies are size-bounded; errors carry no secrets; no request-body
//! logging (see `docs/hosted/HOSTED_API_V1.md`).

use std::collections::HashMap;
use std::sync::Mutex;

use axum::{Json, Router, extract::DefaultBodyLimit, routing::get};
use serde::Serialize;

pub use tari_cc_private_ballot_deployment_registry as deployment_registry;

/// Loopback bind address used when no configuration overrides it.
pub const DEFAULT_BIND: &str = "127.0.0.1:8788";

/// Maximum accepted request body (64 KiB). Ballot envelopes will use a stricter
/// per-route limit in Stage 2; this is the global transport ceiling.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Service configuration. Loaded from environment at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedConfig {
    /// `host:port` to bind. Must be a loopback address.
    pub bind: String,
    /// Service name reported in `/api/v1/status`.
    pub service_name: String,
    /// API version reported in `/api/v1/status`.
    pub api_version: String,
}

impl HostedConfig {
    /// Loads configuration from the environment, validating the bind address.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = std::env::var("PRIVATE_BALLOT_HOSTED_BIND").unwrap_or_else(|_| {
            std::env::var("HOSTED_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        });
        let service_name =
            std::env::var("PRIVATE_BALLOT_HOSTED_SERVICE").unwrap_or_else(|_| "hosted".to_owned());
        let api_version =
            std::env::var("PRIVATE_BALLOT_HOSTED_API_VERSION").unwrap_or_else(|_| "v1".to_owned());
        Self {
            bind,
            service_name,
            api_version,
        }
        .validate()
    }

    /// Validates the configuration. Fail-closed on non-loopback binds.
    pub fn validate(self) -> Result<Self, ConfigError> {
        let host = self
            .bind
            .rsplit(':')
            .nth(1)
            .ok_or(ConfigError::InvalidBind)?;
        if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "[::1]" {
            return Err(ConfigError::NonLoopbackBind);
        }
        if self.service_name.trim().is_empty() || self.service_name.len() > 128 {
            return Err(ConfigError::InvalidBind);
        }
        Ok(self)
    }
}

/// Configuration rejection categories (fixed codes, no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// The bind string is malformed.
    InvalidBind,
    /// The bind is not loopback. The service must never default to a public
    /// interface; Cloudflare Tunnel connects to the loopback service.
    NonLoopbackBind,
}

impl ConfigError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBind => "HOSTED_CONFIG_INVALID_BIND",
            Self::NonLoopbackBind => "HOSTED_CONFIG_NON_LOOPBACK_BIND",
        }
    }
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ConfigError {}

/// Storage semantic categories (see `docs/hosted/HOSTED_STORAGE_MODEL.md`).
/// This skeleton ships only the in-memory test implementation; no persistence
/// is wired yet. Ballot plaintext, voter keys, witness material, and wallet
/// keys must never be stored.
pub trait HostedStorage: Send + Sync {
    /// Appends an opaque ballot envelope (never plaintext) for `election_id`.
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>);
    /// Returns the count of stored envelopes for `election_id`.
    fn ballot_envelope_count(&self, election_id: &str) -> usize;
}

/// In-memory storage used by the skeleton and its tests.
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    envelopes: Mutex<HashMap<String, Vec<Vec<u8>>>>,
}

impl InMemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl HostedStorage for InMemoryStorage {
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>) {
        let mut guard = match self.envelopes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .entry(election_id.to_owned())
            .or_default()
            .push(envelope);
    }

    fn ballot_envelope_count(&self, election_id: &str) -> usize {
        let guard = match self.envelopes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(election_id).map_or(0, Vec::len)
    }
}

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
}

#[derive(Serialize, Clone)]
struct StatusBody {
    service: String,
    api_version: String,
    mode: &'static str,
}

async fn health() -> Json<HealthBody> {
    Json(HealthBody { status: "ok" })
}

async fn status(
    axum::extract::State(config): axum::extract::State<HostedConfig>,
) -> Json<StatusBody> {
    Json(StatusBody {
        service: config.service_name,
        api_version: config.api_version,
        mode: "skeleton",
    })
}

/// Builds the skeleton router (used by the binary and the tests).
#[must_use]
pub fn router(config: HostedConfig) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
        .with_state(config)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Serves until `shutdown` fires (or the listener fails).
pub async fn serve(
    config: HostedConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .map_err(|_| "HOSTED_BIND_FAILED".to_owned())?;
    let app = router(config);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| "HOSTED_SERVE_FAILED".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigError, HostedConfig, HostedStorage, InMemoryStorage, MAX_BODY_BYTES, router,
    };
    use axum::body::Body;
    use tower::ServiceExt;

    #[test]
    fn default_bind_is_loopback() {
        assert_eq!(super::DEFAULT_BIND, "127.0.0.1:8788");
        assert!(MAX_BODY_BYTES <= 64 * 1024);
    }

    #[test]
    fn rejects_public_bind() {
        let config = HostedConfig {
            bind: "0.0.0.0:8788".to_owned(),
            service_name: "hosted".to_owned(),
            api_version: "v1".to_owned(),
        };
        assert_eq!(config.validate(), Err(ConfigError::NonLoopbackBind));
    }

    #[test]
    fn accepts_loopback_bind() {
        let config = HostedConfig {
            bind: "127.0.0.1:8788".to_owned(),
            service_name: "hosted".to_owned(),
            api_version: "v1".to_owned(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn in_memory_storage_counts_envelopes_without_plaintext_model() {
        let storage = InMemoryStorage::new();
        storage.append_ballot_envelope("e1", vec![1, 2, 3]);
        assert_eq!(storage.ballot_envelope_count("e1"), 1);
        assert_eq!(storage.ballot_envelope_count("missing"), 0);
    }

    #[tokio::test]
    async fn health_and_status_endpoints_respond() {
        let config = HostedConfig {
            bind: "127.0.0.1:8788".to_owned(),
            service_name: "test".to_owned(),
            api_version: "v1".to_owned(),
        };
        let app = router(config);
        let health = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("health responds");
        assert!(health.status().is_success());
        let status = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("status responds");
        assert!(status.status().is_success());
    }
}
