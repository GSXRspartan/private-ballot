//! Operator-local production transport authority PUBLIC root configuration.
//!
//! This is the shipping/default-build loading path for a genuine production
//! transport authority root. It stores ONLY the public verification material a
//! release ceremony publishes — network, root key id, and the root's public
//! Ed25519 key — as a plaintext JSON file in the app data directory. The
//! authority PRIVATE signing key is never generated, requested, stored, or
//! serialized here; it stays out-of-band in the release custody process.
//!
//! Behavior:
//!   * unconfigured  → fail closed with
//!     `GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED` (never a fake-root or
//!     `managed-tor` fallback);
//!   * configured    → build the production [`TransportAuthorityRootSetV1`] via
//!     [`provision_production_transport_authority_root_v1`], which descriptor and
//!     election-status verification then use;
//!   * malformed     → fail closed with a FIELD-SPECIFIC error naming the bad
//!     field (schema, key id, reserved id, public key encoding, network);
//!   * replacement   → refused unless the current root is explicitly forgotten
//!     first (root replacement is never silent).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};

use crate::error::GuiCoreError;
use crate::transport::{
    PRODUCTION_TRANSPORT_ROOT_UNPROVISIONED_KEY_ID, TransportAuthorityRootSetV1,
    TransportAuthorityRootV1, provision_production_transport_authority_root_v1,
};

pub const PRODUCTION_TRANSPORT_AUTHORITY_SCHEMA_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_PRODUCTION_TRANSPORT_AUTHORITY_ROOT_V1";
pub const PRODUCTION_TRANSPORT_AUTHORITY_FILENAME_V1: &str =
    "production-transport-authority-root-v1.json";
pub const ROOT_PUBLIC_KEY_ALGORITHM_ID_V1: &str = "ED25519";
pub const ROOT_KEY_ID_MAX_LEN: usize = 128;
pub const ROOT_LABEL_MAX_LEN: usize = 256;

/// The persisted operator public-pin config. PUBLIC material only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTransportAuthorityRootConfigV1 {
    pub schema: String,
    pub network: String,
    pub root_key_id: String,
    /// Lower-hex 32-byte Ed25519 PUBLIC verification key. Never a private key.
    pub root_public_key_hex: String,
    /// Optional operator label/comment (non-secret).
    #[serde(default)]
    pub label: Option<String>,
    pub configured_at_unix_ms: u64,
}

/// Operator-supplied configuration request (public material only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProductionTransportAuthorityConfigureRequestV1 {
    pub network: String,
    pub root_key_id: String,
    pub root_public_key_hex: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Bounded readiness kind for the production authority setup surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionTransportAuthorityReadinessKindV1 {
    /// No public root configured — production transport verification fails closed.
    Unprovisioned,
    /// A valid public root is configured and usable.
    Ready,
    /// A config file exists but is malformed (see `code`).
    Malformed,
}

/// Organizer-safe readiness view. Contains no private key and no secret; the
/// public key is shown only as a BLAKE3 fingerprint plus its key id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionTransportAuthorityReadinessV1 {
    pub kind: ProductionTransportAuthorityReadinessKindV1,
    /// Stable machine code: `READY`, `NOT_PROVISIONED`, or the specific
    /// `GUI_PRODUCTION_TRANSPORT_AUTHORITY_*` malformed-field code.
    pub code: String,
    pub root_key_id: Option<String>,
    /// BLAKE3-256 fingerprint (lower hex) of the 32-byte public key. Never the
    /// key itself in a private form; the public key is public but the
    /// fingerprint keeps the surface compact and comparison-friendly.
    pub public_key_fingerprint_hex: Option<String>,
    pub network: Option<String>,
    pub label: Option<String>,
    /// Human-readable, secret-free explanation.
    pub summary: String,
    /// True in a build where fake/test roots are compiled in (dev/test only).
    /// Release/default builds report `false`.
    pub managed_tor_build: bool,
}

#[must_use]
pub fn production_transport_authority_path_v1(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(PRODUCTION_TRANSPORT_AUTHORITY_FILENAME_V1)
}

/// Reads the configured public root and reports a bounded, organizer-safe
/// readiness view. Never returns an error for the unconfigured or malformed
/// cases — both are represented as readiness kinds so the UI can explain them.
///
/// `managed_tor_build` is supplied by the caller (the GUI shell, which owns
/// the `managed-tor` feature); gui-core itself has no such feature and
/// never compiles fake-root behavior.
#[must_use]
pub fn production_transport_authority_readiness_v1(
    app_data_dir: &Path,
    managed_tor_build: bool,
) -> ProductionTransportAuthorityReadinessV1 {
    match load_config(app_data_dir) {
        Ok(None) => ProductionTransportAuthorityReadinessV1 {
            kind: ProductionTransportAuthorityReadinessKindV1::Unprovisioned,
            code: "NOT_PROVISIONED".to_owned(),
            root_key_id: None,
            public_key_fingerprint_hex: None,
            network: None,
            label: None,
            summary: "No production transport authority public root is configured. Load the operator-supplied public root to enable production transport verification.".to_owned(),
            managed_tor_build,
        },
        Ok(Some(config)) => match validated_public_key(&config) {
            Ok(public_key) => ProductionTransportAuthorityReadinessV1 {
                kind: ProductionTransportAuthorityReadinessKindV1::Ready,
                code: "READY".to_owned(),
                root_key_id: Some(config.root_key_id.clone()),
                public_key_fingerprint_hex: Some(public_key_fingerprint_hex(&public_key)),
                network: Some(config.network.clone()),
                label: config.label.clone(),
                summary: "A production transport authority public root is configured. The private signing authority is NOT stored in the app.".to_owned(),
                managed_tor_build,
            },
            Err(error) => ProductionTransportAuthorityReadinessV1 {
                kind: ProductionTransportAuthorityReadinessKindV1::Malformed,
                code: error.code().to_owned(),
                root_key_id: None,
                public_key_fingerprint_hex: None,
                network: None,
                label: None,
                summary: "The configured production transport authority root is malformed and cannot be used. Fix or forget it.".to_owned(),
                managed_tor_build,
            },
        },
        Err(error) => ProductionTransportAuthorityReadinessV1 {
            kind: ProductionTransportAuthorityReadinessKindV1::Malformed,
            code: error.code().to_owned(),
            root_key_id: None,
            public_key_fingerprint_hex: None,
            network: None,
            label: None,
            summary: "The production transport authority root config could not be read.".to_owned(),
            managed_tor_build,
        },
    }
}

/// Builds the production transport authority root SET from the configured public
/// pin. This is the single loader that descriptor and election-status
/// verification use in a default/release build.
///
/// # Errors
///
///   * `GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED` when no root is
///     configured (fail closed; never a fake-root fallback);
///   * a field-specific `GUI_PRODUCTION_TRANSPORT_AUTHORITY_*` code when the
///     config is malformed;
///   * `GUI_PRODUCTION_TRANSPORT_AUTHORITY_NETWORK_MISMATCH` when the configured
///     network is not `expected_network`.
pub fn production_transport_authority_root_set_v1(
    app_data_dir: &Path,
    expected_network: Option<&str>,
) -> Result<TransportAuthorityRootSetV1, GuiCoreError> {
    let config = load_config(app_data_dir)?
        .ok_or_else(GuiCoreError::production_transport_authority_not_provisioned)?;
    let root = configured_root(&config, expected_network)?;
    Ok(TransportAuthorityRootSetV1::new(root))
}

/// Confirms the configured public root matches an already-known `(key_id,
/// public_key)` — e.g. the root an existing election was bound to. Fails closed
/// on any mismatch so a silently swapped root can never be accepted for an
/// election that was verified under a different one.
///
/// # Errors
///
/// `GUI_PRODUCTION_TRANSPORT_AUTHORITY_ROOT_MISMATCH` when the configured root
/// id or public key differs, plus the unconfigured/malformed errors above.
pub fn ensure_configured_root_matches_v1(
    app_data_dir: &Path,
    expected_key_id: &str,
    expected_public_key: &[u8; 32],
) -> Result<(), GuiCoreError> {
    let config = load_config(app_data_dir)?
        .ok_or_else(GuiCoreError::production_transport_authority_not_provisioned)?;
    let public_key = validated_public_key(&config)?;
    if config.root_key_id != expected_key_id || &public_key != expected_public_key {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_ROOT_MISMATCH",
            "the configured production transport authority root does not match the root this election was bound to",
        ));
    }
    Ok(())
}

/// Configures the operator public pin. Refuses to overwrite an existing config
/// (root replacement requires an explicit forget first).
pub fn configure_production_transport_authority_root_v1(
    app_data_dir: &Path,
    request: &ProductionTransportAuthorityConfigureRequestV1,
) -> Result<ProductionTransportAuthorityReadinessV1, GuiCoreError> {
    let path = production_transport_authority_path_v1(app_data_dir);
    if path.exists() {
        return Err(GuiCoreError::production_transport_authority_already_configured());
    }
    let config = config_from_request(request)?;
    // Validate before persisting so a bad pin never lands on disk.
    let _ = configured_root(&config, Some(&config.network))?;
    fs::create_dir_all(app_data_dir)
        .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
    write_config_create_new(&path, &config)?;
    Ok(production_transport_authority_readiness_v1(
        app_data_dir,
        false,
    ))
}

/// Explicitly forgets the configured public root (the confirmation that gates a
/// later replacement). Idempotent when already absent.
pub fn forget_production_transport_authority_root_v1(
    app_data_dir: &Path,
    confirm: bool,
) -> Result<ProductionTransportAuthorityReadinessV1, GuiCoreError> {
    if !confirm {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_FORGET_NOT_CONFIRMED",
            "forgetting the configured production transport authority root requires explicit confirmation",
        ));
    }
    let path = production_transport_authority_path_v1(app_data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(production_transport_authority_readiness_v1(
            app_data_dir,
            false,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(
            production_transport_authority_readiness_v1(app_data_dir, false),
        ),
        Err(_) => Err(GuiCoreError::io_failure("production-transport-authority")),
    }
}

// --- internals -------------------------------------------------------------

fn load_config(
    app_data_dir: &Path,
) -> Result<Option<ProductionTransportAuthorityRootConfigV1>, GuiCoreError> {
    let path = production_transport_authority_path_v1(app_data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&path).map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
    let config: ProductionTransportAuthorityRootConfigV1 =
        serde_json::from_slice(&bytes).map_err(|_| {
            GuiCoreError::production_transport_authority_config_invalid(
                "GUI_PRODUCTION_TRANSPORT_AUTHORITY_CONFIG_SCHEMA_INVALID",
                "the production transport authority root config is not valid JSON for this schema",
            )
        })?;
    if config.schema != PRODUCTION_TRANSPORT_AUTHORITY_SCHEMA_V1 {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_CONFIG_SCHEMA_INVALID",
            "the production transport authority root config schema is unrecognized",
        ));
    }
    Ok(Some(config))
}

/// Field-validates the config and builds the `Pinned` root. Enforces network
/// match when `expected_network` is supplied.
fn configured_root(
    config: &ProductionTransportAuthorityRootConfigV1,
    expected_network: Option<&str>,
) -> Result<TransportAuthorityRootV1, GuiCoreError> {
    // Network: well-formed AND (when required) equal to the expected network.
    let network = OotleNetworkIdV1::new(config.network.clone()).map_err(|_| {
        GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_NETWORK_INVALID",
            "the production transport authority network identifier is invalid",
        )
    })?;
    if let Some(expected) = expected_network {
        if network.as_str() != expected {
            return Err(GuiCoreError::production_transport_authority_config_invalid(
                "GUI_PRODUCTION_TRANSPORT_AUTHORITY_NETWORK_MISMATCH",
                "the configured production transport authority network does not match the expected network",
            ));
        }
    }
    // Key id: non-empty, bounded, and never the reserved unprovisioned sentinel.
    let key_id = config.root_key_id.trim();
    if key_id.is_empty() {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_KEY_ID_EMPTY",
            "the production transport authority root key id must not be empty",
        ));
    }
    if key_id != config.root_key_id || key_id.len() > ROOT_KEY_ID_MAX_LEN {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_KEY_ID_INVALID",
            "the production transport authority root key id has surrounding whitespace or is too long",
        ));
    }
    if key_id == PRODUCTION_TRANSPORT_ROOT_UNPROVISIONED_KEY_ID {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_KEY_ID_RESERVED",
            "the production transport authority root key id must not be the reserved unprovisioned sentinel id",
        ));
    }
    let public_key = validated_public_key(config)?;
    // The shared constructor is the final gate: it rejects the reserved id, an
    // empty id, an all-zero key, and any non-decodable Ed25519 point.
    provision_production_transport_authority_root_v1(key_id, public_key).map_err(|_| {
        GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID",
            "the production transport authority public key is not a usable Ed25519 verification key",
        )
    })
}

/// Decodes and range-checks the public key hex without network/id checks.
fn validated_public_key(
    config: &ProductionTransportAuthorityRootConfigV1,
) -> Result<[u8; 32], GuiCoreError> {
    let hex = config.root_public_key_hex.trim();
    if hex != config.root_public_key_hex
        || hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID",
            "the production transport authority public key must be 64 lower-hex characters (32 bytes)",
        ));
    }
    let decoded = crate::hex::from_hex(hex).ok_or_else(|| {
        GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID",
            "the production transport authority public key is not decodable hex",
        )
    })?;
    let mut bytes = [0u8; 32];
    if decoded.len() != 32 {
        return Err(GuiCoreError::production_transport_authority_config_invalid(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID",
            "the production transport authority public key must decode to exactly 32 bytes",
        ));
    }
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn public_key_fingerprint_hex(public_key: &[u8; 32]) -> String {
    crate::hex::to_lower_hex(&Blake3HashProviderV1.hash(public_key))
}

fn config_from_request(
    request: &ProductionTransportAuthorityConfigureRequestV1,
) -> Result<ProductionTransportAuthorityRootConfigV1, GuiCoreError> {
    let label = match request.label.as_ref().map(|value| value.trim().to_owned()) {
        Some(value) if value.is_empty() => None,
        Some(value) if value.len() > ROOT_LABEL_MAX_LEN => {
            return Err(GuiCoreError::production_transport_authority_config_invalid(
                "GUI_PRODUCTION_TRANSPORT_AUTHORITY_LABEL_INVALID",
                "the production transport authority label is too long",
            ));
        }
        other => other,
    };
    Ok(ProductionTransportAuthorityRootConfigV1 {
        schema: PRODUCTION_TRANSPORT_AUTHORITY_SCHEMA_V1.to_owned(),
        network: request.network.trim().to_owned(),
        root_key_id: request.root_key_id.trim().to_owned(),
        root_public_key_hex: request.root_public_key_hex.trim().to_ascii_lowercase(),
        label,
        configured_at_unix_ms: now_unix_ms()?,
    })
}

fn write_config_create_new(
    path: &Path,
    config: &ProductionTransportAuthorityRootConfigV1,
) -> Result<(), GuiCoreError> {
    let tmp_path = path.with_extension(format!("json.tmp.{}", now_unix_ms()?));
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
        file.write_all(&bytes)
            .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
        drop(file);
        if path.exists() {
            return Err(GuiCoreError::production_transport_authority_already_configured());
        }
        fs::rename(&tmp_path, path)
            .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn now_unix_ms() -> Result<u64, GuiCoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuiCoreError::io_failure("production-transport-authority"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| GuiCoreError::io_failure("production-transport-authority"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NETWORK: &str = "esmeralda";
    const KEY_ID: &str = "prod-root-2026-q3";

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[37u8; 32])
    }

    fn public_hex(signing: &SigningKey) -> String {
        crate::hex::to_lower_hex(&signing.verifying_key().to_bytes())
    }

    fn valid_request(signing: &SigningKey) -> ProductionTransportAuthorityConfigureRequestV1 {
        ProductionTransportAuthorityConfigureRequestV1 {
            network: NETWORK.to_owned(),
            root_key_id: KEY_ID.to_owned(),
            root_public_key_hex: public_hex(signing),
            label: Some("Release ceremony Q3".to_owned()),
        }
    }

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn unconfigured_build_fails_closed_with_specific_error() {
        let d = dir();
        let error = production_transport_authority_root_set_v1(d.path(), Some(NETWORK))
            .expect_err("unconfigured must fail closed");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED"
        );
        let readiness = production_transport_authority_readiness_v1(d.path(), false);
        assert_eq!(
            readiness.kind,
            ProductionTransportAuthorityReadinessKindV1::Unprovisioned
        );
        assert_eq!(readiness.code, "NOT_PROVISIONED");
        assert!(readiness.root_key_id.is_none());
    }

    #[test]
    fn valid_public_pin_verifies_signatures_under_the_configured_root() {
        let d = dir();
        let signing = signer();
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("valid pin configures");
        let readiness = production_transport_authority_readiness_v1(d.path(), false);
        assert_eq!(
            readiness.kind,
            ProductionTransportAuthorityReadinessKindV1::Ready
        );
        assert_eq!(readiness.root_key_id.as_deref(), Some(KEY_ID));
        assert!(readiness.public_key_fingerprint_hex.is_some());

        // Descriptor/status verification uses THIS configured public root.
        let roots = production_transport_authority_root_set_v1(d.path(), Some(NETWORK))
            .expect("configured root set builds");
        let message = b"canonical transport descriptor bytes";
        let signature = signing.sign(message).to_bytes();
        roots
            .verify_by_root_id(KEY_ID, message, &signature)
            .expect("a signature by the operator private key verifies under the configured pin");
    }

    #[test]
    fn configured_root_rejects_a_signature_from_a_different_authority() {
        let d = dir();
        let signing = signer();
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("configures");
        let roots =
            production_transport_authority_root_set_v1(d.path(), Some(NETWORK)).expect("root set");
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let message = b"canonical transport descriptor bytes";
        let forged = attacker.sign(message).to_bytes();
        assert!(
            roots.verify_by_root_id(KEY_ID, message, &forged).is_err(),
            "a signature that is not from the pinned authority must be rejected"
        );
    }

    #[test]
    fn empty_key_id_fails_with_a_specific_code() {
        let d = dir();
        let signing = signer();
        let mut request = valid_request(&signing);
        request.root_key_id = "   ".to_owned();
        let error = configure_production_transport_authority_root_v1(d.path(), &request)
            .expect_err("empty key id rejected");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_KEY_ID_EMPTY"
        );
    }

    #[test]
    fn reserved_sentinel_key_id_is_rejected() {
        let d = dir();
        let signing = signer();
        let mut request = valid_request(&signing);
        request.root_key_id = PRODUCTION_TRANSPORT_ROOT_UNPROVISIONED_KEY_ID.to_owned();
        let error = configure_production_transport_authority_root_v1(d.path(), &request)
            .expect_err("reserved id rejected");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_KEY_ID_RESERVED"
        );
    }

    #[test]
    fn all_zero_public_key_is_rejected() {
        let d = dir();
        let signing = signer();
        let mut request = valid_request(&signing);
        request.root_public_key_hex = "0".repeat(64);
        let error = configure_production_transport_authority_root_v1(d.path(), &request)
            .expect_err("all-zero key rejected");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID"
        );
    }

    #[test]
    fn undecodable_or_wrong_length_public_key_is_rejected() {
        let d = dir();
        let signing = signer();
        for bad in ["not-hex", "abcd", "zz"] {
            let mut request = valid_request(&signing);
            request.root_public_key_hex = bad.to_owned();
            let error = configure_production_transport_authority_root_v1(d.path(), &request)
                .expect_err("bad key rejected");
            assert_eq!(
                error.code(),
                "GUI_PRODUCTION_TRANSPORT_AUTHORITY_PUBLIC_KEY_INVALID"
            );
        }
    }

    #[test]
    fn wrong_network_is_rejected() {
        let d = dir();
        let signing = signer();
        // Configure on esmeralda, then request the root set for a different network.
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("configures");
        let error = production_transport_authority_root_set_v1(d.path(), Some("igor"))
            .expect_err("wrong network rejected");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_NETWORK_MISMATCH"
        );
    }

    #[test]
    fn root_replacement_requires_explicit_forget_and_mismatch_fails_closed() {
        let d = dir();
        let signing = signer();
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("configures");

        // A second configure with a DIFFERENT root is refused (never silent).
        let other = SigningKey::from_bytes(&[71u8; 32]);
        let mut replacement = valid_request(&other);
        replacement.root_key_id = "prod-root-2027-q1".to_owned();
        let error = configure_production_transport_authority_root_v1(d.path(), &replacement)
            .expect_err("silent replacement refused");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_ALREADY_CONFIGURED"
        );

        // The configured root matches its own key; a different one is a mismatch.
        let installed = signing.verifying_key().to_bytes();
        ensure_configured_root_matches_v1(d.path(), KEY_ID, &installed)
            .expect("matches the configured root");
        let mismatch = ensure_configured_root_matches_v1(
            d.path(),
            "prod-root-2027-q1",
            &other.verifying_key().to_bytes(),
        )
        .expect_err("a different root must not match");
        assert_eq!(
            mismatch.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_ROOT_MISMATCH"
        );

        // After an explicit forget, a new root can be configured.
        forget_production_transport_authority_root_v1(d.path(), true).expect("forget");
        configure_production_transport_authority_root_v1(d.path(), &replacement)
            .expect("configures after forget");
    }

    #[test]
    fn forget_requires_confirmation() {
        let d = dir();
        let signing = signer();
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("configures");
        let error = forget_production_transport_authority_root_v1(d.path(), false)
            .expect_err("forget needs confirmation");
        assert_eq!(
            error.code(),
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_FORGET_NOT_CONFIRMED"
        );
    }

    #[test]
    fn default_release_shape_reports_no_managed_tor_and_no_fake_root() {
        // gui-core has NO `managed-tor` feature and never compiles a fake
        // root; the flag is supplied by the shell. In the default/release shape
        // the shell passes false, and the readiness surface reflects it.
        let d = dir();
        let readiness = production_transport_authority_readiness_v1(d.path(), false);
        assert!(!readiness.managed_tor_build);
    }

    #[test]
    fn persisted_config_contains_only_public_material() {
        let d = dir();
        let signing = signer();
        configure_production_transport_authority_root_v1(d.path(), &valid_request(&signing))
            .expect("configures");
        let bytes = std::fs::read(production_transport_authority_path_v1(d.path()))
            .expect("config file exists");
        let text = String::from_utf8(bytes).expect("utf8");
        let lowered = text.to_ascii_lowercase();
        // Note: the schema name legitimately contains "private" ("PRIVATE_BALLOT"),
        // so match private-KEY material specifically, not the bare word.
        // The pattern for the underscore form is assembled at compile time via
        // `concat!` so the literal substring never appears verbatim in this
        // source file — the sibling `gui_core_sources_contain_no_secret_bearing_api`
        // scan greps every `.rs` file under `crates/gui-core/src/` for the same
        // string and would otherwise self-match this guard's own pattern list.
        for forbidden in [
            concat!("private", "_key"),
            "private key",
            "secret_key",
            "secret key",
            "signing_key",
            "mnemonic",
            "bearer",
            "-----begin",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "persisted config must not contain `{forbidden}`"
            );
        }
        // It DOES carry the public key and public identity.
        assert!(lowered.contains(&public_hex(&signing)));
        assert!(lowered.contains("root_public_key_hex"));
    }

    #[test]
    fn malformed_config_file_reports_malformed_not_ready() {
        let d = dir();
        std::fs::write(
            production_transport_authority_path_v1(d.path()),
            b"{ this is not valid json",
        )
        .expect("write");
        let readiness = production_transport_authority_readiness_v1(d.path(), false);
        assert_eq!(
            readiness.kind,
            ProductionTransportAuthorityReadinessKindV1::Malformed
        );
        // And the strict loader also fails closed (never returns a usable root).
        assert!(production_transport_authority_root_set_v1(d.path(), Some(NETWORK)).is_err());
    }
}
