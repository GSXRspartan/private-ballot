//! Durable pre-create intent for the walletd request-creation boundary.
//!
//! Walletd only assigns its opaque request id *after* it accepts a create
//! request. The currently supported API offers no lookup by the project's
//! deterministic request id or transaction fingerprint. Consequently a lost
//! create response cannot be retried safely. Before the wire call, the driver
//! atomically writes this non-secret record. If it remains while the lifecycle
//! snapshot is still `NotPrepared`, the driver fails closed and requires
//! operator reconciliation rather than issuing a second create.

use std::io::Write;
use std::path::{Path, PathBuf};

use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdCreateAnchorRequestV1;

use crate::config::AnchorAppConfig;

// V1 records (`…_PRECREATE_INTENT_V1`) are still read for fail-closed
// recovery via their sidecar path, but only V2 records are written now, so the
// V1 record-type marker is intentionally no longer referenced in code.
const CREATE_INTENT_RECORD_TYPE_V2: &str =
    "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PRECREATE_INTENT_V2";

/// Bounded failure while maintaining the durable pre-create intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateIntentFileError {
    /// A filesystem read, write, flush, or sync operation failed.
    IoFailure,
    /// The atomic replacement could not complete.
    AtomicRenameFailure,
}

impl CreateIntentFileError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoFailure => "CREATE_INTENT_IO_FAILURE",
            Self::AtomicRenameFailure => "CREATE_INTENT_ATOMIC_RENAME_FAILURE",
        }
    }
}

impl core::fmt::Display for CreateIntentFileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for CreateIntentFileError {}

/// Returns the durable pre-create-intent path associated with `snapshot_path`.
///
/// It is deliberately a detached sibling, never a file inside the finalized
/// archive directory.
#[must_use]
pub fn create_intent_path(snapshot_path: &Path) -> PathBuf {
    let mut value = snapshot_path.as_os_str().to_os_string();
    value.push(".create-intent-v2");
    PathBuf::from(value)
}

/// Returns the legacy V1 sidecar path. It remains a read-only compatibility
/// input: an unresolved historical intent blocks a V4 create exactly as an
/// unresolved V2 intent does.
fn create_intent_v1_path(snapshot_path: &Path) -> PathBuf {
    let mut value = snapshot_path.as_os_str().to_os_string();
    value.push(".create-intent-v1");
    PathBuf::from(value)
}

/// Returns whether a pre-create intent exists. An unreadable path is an error
/// so callers can fail closed rather than assuming a create is safe to retry.
pub fn exists(snapshot_path: &Path) -> Result<bool, CreateIntentFileError> {
    for path in [
        create_intent_path(snapshot_path),
        create_intent_v1_path(snapshot_path),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CreateIntentFileError::IoFailure),
        }
    }
    Ok(false)
}

/// Atomically persists the exact deterministic identifiers and binding
/// fingerprint for a walletd create before the network call is issued.
///
/// The record deliberately excludes wallet bearer credentials, keys, ballots,
/// and the unsigned transaction. It contains the project request id and the
/// binding fields an operator needs to reconcile manually once walletd exposes
/// a suitable lookup surface.
pub fn write_atomic(
    snapshot_path: &Path,
    config: &AnchorAppConfig,
    create: &WalletdCreateAnchorRequestV1,
) -> Result<(), CreateIntentFileError> {
    let path = create_intent_path(snapshot_path);
    let bytes = encode(config, create);
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = Path::new(&tmp);

    let result = (|| -> Result<(), CreateIntentFileError> {
        let mut file =
            std::fs::File::create(tmp_path).map_err(|_| CreateIntentFileError::IoFailure)?;
        file.write_all(&bytes)
            .map_err(|_| CreateIntentFileError::IoFailure)?;
        file.flush().map_err(|_| CreateIntentFileError::IoFailure)?;
        file.sync_all()
            .map_err(|_| CreateIntentFileError::IoFailure)?;
        drop(file);
        std::fs::rename(tmp_path, path).map_err(|_| CreateIntentFileError::AtomicRenameFailure)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp_path);
    }
    result
}

/// Removes the intent only after the prepared lifecycle snapshot is durable.
pub fn clear(snapshot_path: &Path) -> Result<(), CreateIntentFileError> {
    for path in [
        create_intent_path(snapshot_path),
        create_intent_v1_path(snapshot_path),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CreateIntentFileError::IoFailure),
        }
    }
    Ok(())
}

fn encode(config: &AnchorAppConfig, create: &WalletdCreateAnchorRequestV1) -> Vec<u8> {
    let binding = create.binding();
    let template = binding.template_binding();
    let epoch = binding.epoch_binding();
    format!(
        "record_type={CREATE_INTENT_RECORD_TYPE_V2}\nproject_request_id={}\nnetwork={}\naccount={}\nmanifest_hash={}\narchive_hash={}\nanchor_digest={}\ntransaction_fingerprint={}\nmax_fee_units={}\nfee_component={}\nttl_secs={}\ntemplate_address={}\ntemplate_module={}\ntemplate_function={}\nevent_topic={}\ntemplate_artifact_digest={}\nobserved_epoch={}\nmax_epoch={}\n",
        create.project_request_id().as_str(),
        binding.network().as_str(),
        binding.account().as_str(),
        hex(binding_bytes(config.archive_manifest_hash().as_bytes())),
        hex(binding_bytes(config.archive_hash().as_bytes())),
        hex(binding_bytes(binding.anchor_digest().as_bytes())),
        hex(binding_bytes(binding.fingerprint().as_bytes())),
        binding.max_fee().value(),
        config.network_adapter().fee_component().display_string(),
        config
            .ttl_secs()
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        template.map_or("missing", |value| value.template_address()),
        template.map_or("missing", |value| value.module()),
        template.map_or("missing", |value| value.function()),
        template.map_or("missing", |value| value.full_event_topic()),
        template.map_or_else(|| "missing".to_owned(), |value| hex(value.artifact_digest())),
        epoch.map_or_else(|| "missing".to_owned(), |value| value.observed_epoch().to_string()),
        epoch.map_or_else(|| "missing".to_owned(), |value| value.max_epoch().to_string()),
    )
    .into_bytes()
}

fn binding_bytes(bytes: &[u8; 32]) -> &[u8; 32] {
    bytes
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::create_intent_path;

    #[test]
    fn intent_path_is_a_detached_snapshot_sibling() {
        let snapshot = std::path::Path::new("C:/anchor/archive-anchor-snapshot.cbor");
        assert_eq!(
            create_intent_path(snapshot),
            std::path::PathBuf::from("C:/anchor/archive-anchor-snapshot.cbor.create-intent-v2")
        );
    }
}
