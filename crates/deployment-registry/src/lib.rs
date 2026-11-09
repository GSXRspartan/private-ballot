#![forbid(unsafe_code)]

//! Reset-safe Ootle template deployment registry.
//!
//! The registry replaces the assumption that one template address is permanent
//! with a first-class record. Historical deployments are never deleted: the
//! current application resolves the `CURRENT` deployment for a selected
//! network from this registry and fails closed when the selection is missing,
//! ambiguous, or mismatched (network, ABI, or artifact hash).
//!
//! The `GuiTrustedOotleDeploymentV2` lock (`crates/gui-core/src/trusted_anchor_deployment.rs`)
//! is the older single-`CURRENT` form. [`DeploymentRegistry::import_trusted_lock_v2`]
//! migrates that lock into a registry entry without rewriting the historical
//! lock file.

pub const REGISTRY_SCHEMA_V1: &str = "TARI_CC_PRIVATE_BALLOT_DEPLOYMENT_REGISTRY_V1";

/// V2 anchor ABI identity shared by every deployment in this registry.
/// A registry entry with any other ABI never resolves as `CURRENT`.
pub const ABI_NAME_V2: &str = "TariPrivateBallotAnchorV2";
pub const ABI_FUNCTION_V2: &str = "publish_anchor_v2";
pub const ABI_EVENT_TOPIC_V2: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";

/// Application status of a deployment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentStatus {
    /// The single resolvable deployment for its network.
    Current,
    /// A previously `CURRENT` deployment replaced by a newer one.
    Superseded,
    /// A deployment from a past network generation (evidence, never resolved).
    Historical,
    /// Recorded but not yet qualified (never resolved).
    Unverified,
}

/// One template deployment record. All fields are public deployment identity;
/// no wallet secrets, bearer tokens, or election artifacts are stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeploymentEntry {
    /// Ootle network identifier (e.g. `esmeralda`).
    pub network: String,
    /// Network generation / reset generation (e.g. `protocol-v1`).
    pub network_generation: String,
    /// Ootle protocol / release cohort (e.g. `v0.51.0`).
    pub ootle_version: String,
    /// Template logical name.
    pub logical_name: String,
    /// Template ABI version (must equal [`ABI_NAME_V2`] to resolve).
    pub abi_version: String,
    /// Deployed template address (`template_<64 hex>`).
    pub template_address: String,
    /// Source WASM artifact SHA-256 (lowercase hex, 64 chars), when measured.
    pub artifact_sha256: Option<String>,
    /// Source WASM artifact BLAKE3-256 (lowercase hex, 64 chars), when measured.
    pub artifact_blake3: Option<String>,
    /// Optimized/deployed artifact hashes, when known. Kept opaque.
    pub deployed_artifact_hashes: Vec<String>,
    /// Deployment transaction identifier, when the deployment was observed.
    pub deployment_tx_id: Option<String>,
    /// Activation time (Unix seconds), when known.
    pub activated_at_unix_secs: Option<u64>,
    /// Application status.
    pub status: DeploymentStatus,
    /// Qualification transaction identifier, when a synthetic anchor was verified.
    pub qualification_tx_id: Option<String>,
    /// Qualification digest (anchor digest), when verified.
    pub qualification_digest: Option<String>,
    /// Free-form operator notes (no secrets).
    pub notes: String,
}

/// Fail-closed rejection categories. Every error is a fixed code; no third-party
/// text or secret is preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryError {
    /// No `CURRENT` deployment exists for the requested network.
    NoCurrentDeployment,
    /// More than one `CURRENT` deployment exists for the requested network.
    MultipleCurrentDeployments,
    /// The single `CURRENT` deployment names a different network.
    NetworkMismatch,
    /// The single `CURRENT` deployment names a different ABI.
    AbiMismatch,
    /// The single `CURRENT` deployment's artifact hash does not match the
    /// caller-supplied expected hash.
    HashMismatch,
    /// The registry carries an unsupported schema identifier.
    UnsupportedSchema,
    /// An entry failed structural validation (empty network, malformed address).
    InvalidEntry,
}

impl RegistryError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCurrentDeployment => "DEPLOYMENT_NO_CURRENT",
            Self::MultipleCurrentDeployments => "DEPLOYMENT_MULTIPLE_CURRENT",
            Self::NetworkMismatch => "DEPLOYMENT_NETWORK_MISMATCH",
            Self::AbiMismatch => "DEPLOYMENT_ABI_MISMATCH",
            Self::HashMismatch => "DEPLOYMENT_HASH_MISMATCH",
            Self::UnsupportedSchema => "DEPLOYMENT_UNSUPPORTED_SCHEMA",
            Self::InvalidEntry => "DEPLOYMENT_INVALID_ENTRY",
        }
    }
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for RegistryError {}

/// An ordered collection of deployment records.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeploymentRegistry {
    /// Schema tag; must equal [`REGISTRY_SCHEMA_V1`].
    pub schema: String,
    /// All records, in insertion order.
    pub entries: Vec<DeploymentEntry>,
}

impl DeploymentRegistry {
    /// Creates an empty registry with the current schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: REGISTRY_SCHEMA_V1.to_owned(),
            entries: Vec::new(),
        }
    }

    /// Validates the schema and every entry structurally. Fail-closed.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema != REGISTRY_SCHEMA_V1 {
            return Err(RegistryError::UnsupportedSchema);
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }

    /// Appends a validated entry.
    pub fn push(&mut self, entry: DeploymentEntry) -> Result<(), RegistryError> {
        entry.validate()?;
        self.entries.push(entry);
        Ok(())
    }

    /// Resolves the `CURRENT` deployment for `network` and `abi_version`.
    /// When `expected_artifact_hash_hex` is `Some`, the resolved entry must
    /// carry that hash in `artifact_sha256` or `artifact_blake3`.
    pub fn resolve_current(
        &self,
        network: &str,
        abi_version: &str,
        expected_artifact_hash_hex: Option<&str>,
    ) -> Result<&DeploymentEntry, RegistryError> {
        self.validate()?;
        let currents: Vec<&DeploymentEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.status == DeploymentStatus::Current)
            .collect();
        if currents.is_empty() {
            return Err(RegistryError::NoCurrentDeployment);
        }
        if currents.len() > 1 {
            return Err(RegistryError::MultipleCurrentDeployments);
        }
        let entry = currents[0];
        if entry.network != network {
            return Err(RegistryError::NetworkMismatch);
        }
        if entry.abi_version != abi_version {
            return Err(RegistryError::AbiMismatch);
        }
        if let Some(expected) = expected_artifact_hash_hex {
            let matches = entry.artifact_sha256.as_deref() == Some(expected)
                || entry.artifact_blake3.as_deref() == Some(expected);
            if !matches {
                return Err(RegistryError::HashMismatch);
            }
        }
        Ok(entry)
    }

    /// Migrates the older trusted-lock V2 shape into a `CURRENT` entry.
    /// The historical lock file is not modified; the caller records the
    /// returned entry in a registry.
    pub fn import_trusted_lock_v2(
        network: &str,
        template_address: &str,
        artifact_digest_hex: &str,
        network_generation: &str,
        ootle_version: &str,
        locked_at_unix_secs: u64,
    ) -> Result<DeploymentEntry, RegistryError> {
        let entry = DeploymentEntry {
            network: network.to_owned(),
            network_generation: network_generation.to_owned(),
            ootle_version: ootle_version.to_owned(),
            logical_name: "TariPrivateBallotAnchorV2".to_owned(),
            abi_version: ABI_NAME_V2.to_owned(),
            template_address: template_address.to_owned(),
            artifact_sha256: None,
            artifact_blake3: Some(artifact_digest_hex.to_owned()),
            deployed_artifact_hashes: Vec::new(),
            deployment_tx_id: None,
            activated_at_unix_secs: Some(locked_at_unix_secs),
            status: DeploymentStatus::Current,
            qualification_tx_id: None,
            qualification_digest: None,
            notes: "Migrated from GuiTrustedOotleDeploymentV2; historical lock preserved."
                .to_owned(),
        };
        entry.validate()?;
        Ok(entry)
    }
}

impl DeploymentEntry {
    /// Structural validation: non-empty network, `template_<64 hex>` address,
    /// and (when present) 64-char lowercase-hex artifact hashes.
    fn validate(&self) -> Result<(), RegistryError> {
        if self.network.is_empty() {
            return Err(RegistryError::InvalidEntry);
        }
        let hash_hex = self
            .template_address
            .strip_prefix("template_")
            .ok_or(RegistryError::InvalidEntry)?;
        if hash_hex.len() != 64
            || !hash_hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(RegistryError::InvalidEntry);
        }
        for hash in [&self.artifact_sha256, &self.artifact_blake3]
            .into_iter()
            .flatten()
        {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(RegistryError::InvalidEntry);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ABI_NAME_V2, DeploymentEntry, DeploymentRegistry, DeploymentStatus, REGISTRY_SCHEMA_V1,
        RegistryError,
    };

    fn entry(network: &str, address_hex: char) -> DeploymentEntry {
        DeploymentEntry {
            network: network.to_owned(),
            network_generation: "protocol-v1".to_owned(),
            ootle_version: "v0.51.0".to_owned(),
            logical_name: "TariPrivateBallotAnchorV2".to_owned(),
            abi_version: ABI_NAME_V2.to_owned(),
            template_address: format!("template_{}", address_hex.to_string().repeat(64)),
            artifact_sha256: Some("a".repeat(64)),
            artifact_blake3: Some("b".repeat(64)),
            deployed_artifact_hashes: Vec::new(),
            deployment_tx_id: None,
            activated_at_unix_secs: Some(1),
            status: DeploymentStatus::Current,
            qualification_tx_id: None,
            qualification_digest: None,
            notes: String::new(),
        }
    }

    #[test]
    fn resolves_single_current() {
        let mut registry = DeploymentRegistry::new();
        registry.push(entry("esmeralda", '1')).expect("valid");
        let resolved = registry
            .resolve_current("esmeralda", ABI_NAME_V2, Some(&"a".repeat(64)))
            .expect("resolves");
        assert_eq!(resolved.network, "esmeralda");
        assert_eq!(registry.schema, REGISTRY_SCHEMA_V1);
    }

    #[test]
    fn fails_closed_without_current() {
        let registry = DeploymentRegistry::new();
        assert_eq!(
            registry.resolve_current("esmeralda", ABI_NAME_V2, None),
            Err(RegistryError::NoCurrentDeployment)
        );
    }

    #[test]
    fn fails_closed_with_multiple_current() {
        let mut registry = DeploymentRegistry::new();
        registry.push(entry("esmeralda", '1')).expect("valid");
        registry.push(entry("esmeralda", '2')).expect("valid");
        assert_eq!(
            registry.resolve_current("esmeralda", ABI_NAME_V2, None),
            Err(RegistryError::MultipleCurrentDeployments)
        );
    }

    #[test]
    fn fails_closed_on_network_abi_and_hash_mismatch() {
        let mut registry = DeploymentRegistry::new();
        registry.push(entry("esmeralda", '1')).expect("valid");
        assert_eq!(
            registry.resolve_current("igor", ABI_NAME_V2, None),
            Err(RegistryError::NetworkMismatch)
        );
        assert_eq!(
            registry.resolve_current("esmeralda", "OtherAbi", None),
            Err(RegistryError::AbiMismatch)
        );
        assert_eq!(
            registry.resolve_current("esmeralda", ABI_NAME_V2, Some(&"f".repeat(64))),
            Err(RegistryError::HashMismatch)
        );
    }

    #[test]
    fn rejects_malformed_address_and_hash() {
        let mut registry = DeploymentRegistry::new();
        let mut bad = entry("esmeralda", '1');
        bad.template_address = "not_a_template_address".to_owned();
        assert_eq!(registry.push(bad), Err(RegistryError::InvalidEntry));
        let mut bad_hash = entry("esmeralda", '1');
        bad_hash.artifact_blake3 = Some("XYZ".to_owned());
        assert_eq!(registry.push(bad_hash), Err(RegistryError::InvalidEntry));
    }

    #[test]
    fn imports_trusted_lock_without_touching_history() {
        let imported = DeploymentRegistry::import_trusted_lock_v2(
            "esmeralda",
            &format!("template_{}", "9".repeat(64)),
            &"c".repeat(64),
            "protocol-v1",
            "v0.51.0",
            42,
        )
        .expect("imports");
        assert_eq!(imported.status, DeploymentStatus::Current);
        let mut registry = DeploymentRegistry::new();
        registry.push(imported).expect("valid");
        assert!(
            registry
                .resolve_current("esmeralda", ABI_NAME_V2, None)
                .is_ok()
        );
    }

    #[test]
    fn registry_round_trips_through_json() {
        let mut registry = DeploymentRegistry::new();
        registry.push(entry("esmeralda", '1')).expect("valid");
        let json = serde_json::to_string(&registry).expect("serializes");
        let back: DeploymentRegistry = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, registry);
    }
}
