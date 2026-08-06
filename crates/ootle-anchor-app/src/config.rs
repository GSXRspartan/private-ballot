//! Canonical, versioned, digest-bearing application configuration (Slice
//! 4A10).
//!
//! The configuration file uses canonical CBOR (not TOML, JSON, or YAML) with a
//! fixed record type / version, a fixed field order, a digest-bearing envelope,
//! and a dedicated config hash domain. The canonical config carries only
//! public locator data and bounded policy values; walletd auth is never
//! persisted in the canonical config and is loaded separately (see
//! [`AnchorAppConfig::with_walletd_auth`]).

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::{OOTLE_ANCHOR_PURPOSE_ID_V1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::AnchorAccountReference;
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, NetworkAdapterConfig, NetworkAdapterConfigError, WalletdAuthSecret,
    WalletdEndpoint,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdFeeComponentRef, WalletdSealSignerRef,
};
use tari_cc_private_ballot_protocol::ManifestHash;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborReader,
    CanonicalCborWriter, HashProvider, ProtocolError, ValidationCode,
};

/// Maximum encoded config file size (envelope + body).
pub const MAX_CONFIG_FILE_BYTES: usize = 16_384;

/// Stable record-type / version identifier for the config envelope.
pub const CONFIG_RECORD_TYPE_ID_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_APP_CONFIG_V1";

/// Hash-algorithm identifier written into the config envelope.
pub const CONFIG_HASH_ALGORITHM_ID_V1: &str = BLAKE3_256_HASH_ALGORITHM_ID_V1;

/// Domain-separation frame prefix for config body digests.
pub const CONFIG_FRAME_PREFIX_V1: &[u8] =
    b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_APP_CONFIG_FRAME_V1";

/// Domain label for config body digests.
pub const CONFIG_DOMAIN_LABEL_V1: &str = "tari-cc-private-ballot/ootle-anchor-app-config/v1";

const ENVELOPE_FIELD_COUNT: usize = 4;
const BODY_FIELD_COUNT: usize = 16;
const MAX_PATH_BYTES: usize = 4_096;

const SEAL_TAG_ACCOUNT_KEY: u64 = 0;
const SEAL_TAG_TRANSACTION_KEY: u64 = 1;
const SEAL_TAG_IMPORTED_KEY: u64 = 2;

/// Bounded failure while loading or writing a canonical config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileError {
    /// No config file was present at the path.
    FileNotFound,
    /// A filesystem I/O failure occurred.
    IoFailure,
    /// The atomic rename could not complete.
    AtomicRenameFailure,
    /// The record-type / version string was unsupported.
    UnsupportedProtocolVersion,
    /// The hash-algorithm identifier was unsupported.
    UnsupportedHashAlgorithm,
    /// The CBOR was structurally invalid.
    InvalidCbor,
    /// The CBOR used a non-canonical encoding.
    NonCanonicalCbor,
    /// An unexpected CBOR major type was encountered.
    UnexpectedCborType,
    /// Trailing bytes remained after the decoded value.
    TrailingCborData,
    /// The encoded size exceeded [`MAX_CONFIG_FILE_BYTES`].
    ProtocolLimitExceeded,
    /// The recorded body digest did not match the recomputed digest.
    DigestMismatch,
    /// A field value was invalid (bad identifier, bad endpoint, etc.).
    InvalidData,
    /// The selected testnet is not supported.
    UnsupportedNetwork,
    /// The maximum fee was zero.
    InvalidMaxFee,
    /// The receipt-query attempt count was zero.
    InvalidReceiptQueryAttempts,
    /// The backoff base was zero or the cap was below the base.
    InvalidBackoff,
    /// A path was not absolute or exceeded the bounded length.
    InvalidPath,
    /// The anchor-record network did not equal the adapter network.
    NetworkMismatch,
}

impl ConfigFileError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileNotFound => "CONFIG_FILE_NOT_FOUND",
            Self::IoFailure => "CONFIG_IO_FAILURE",
            Self::AtomicRenameFailure => "CONFIG_ATOMIC_RENAME_FAILURE",
            Self::UnsupportedProtocolVersion => "CONFIG_UNSUPPORTED_PROTOCOL_VERSION",
            Self::UnsupportedHashAlgorithm => "CONFIG_UNSUPPORTED_HASH_ALGORITHM",
            Self::InvalidCbor => "CONFIG_INVALID_CBOR",
            Self::NonCanonicalCbor => "CONFIG_NON_CANONICAL_CBOR",
            Self::UnexpectedCborType => "CONFIG_UNEXPECTED_CBOR_TYPE",
            Self::TrailingCborData => "CONFIG_TRAILING_CBOR_DATA",
            Self::ProtocolLimitExceeded => "CONFIG_PROTOCOL_LIMIT_EXCEEDED",
            Self::DigestMismatch => "CONFIG_DIGEST_MISMATCH",
            Self::InvalidData => "CONFIG_INVALID_DATA",
            Self::UnsupportedNetwork => "CONFIG_UNSUPPORTED_NETWORK",
            Self::InvalidMaxFee => "CONFIG_INVALID_MAX_FEE",
            Self::InvalidReceiptQueryAttempts => "CONFIG_INVALID_RECEIPT_QUERY_ATTEMPTS",
            Self::InvalidBackoff => "CONFIG_INVALID_BACKOFF",
            Self::InvalidPath => "CONFIG_INVALID_PATH",
            Self::NetworkMismatch => "CONFIG_NETWORK_MISMATCH",
        }
    }
}

impl core::fmt::Display for ConfigFileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ConfigFileError {}

fn from_protocol(error: ProtocolError) -> ConfigFileError {
    match error.code() {
        ValidationCode::UnsupportedProtocolVersion => ConfigFileError::UnsupportedProtocolVersion,
        ValidationCode::UnsupportedHashAlgorithm => ConfigFileError::UnsupportedHashAlgorithm,
        ValidationCode::InvalidCbor => ConfigFileError::InvalidCbor,
        ValidationCode::NonCanonicalCbor => ConfigFileError::NonCanonicalCbor,
        ValidationCode::UnexpectedCborType => ConfigFileError::UnexpectedCborType,
        ValidationCode::TrailingCborData => ConfigFileError::TrailingCborData,
        ValidationCode::ProtocolLimitExceeded => ConfigFileError::ProtocolLimitExceeded,
        _ => ConfigFileError::InvalidData,
    }
}

fn from_adapter(error: NetworkAdapterConfigError) -> ConfigFileError {
    match error {
        NetworkAdapterConfigError::UnsupportedNetwork => ConfigFileError::UnsupportedNetwork,
        NetworkAdapterConfigError::InvalidMaxFee => ConfigFileError::InvalidMaxFee,
        NetworkAdapterConfigError::InvalidReceiptQueryAttempts => {
            ConfigFileError::InvalidReceiptQueryAttempts
        }
    }
}

/// Canonical application configuration.
///
/// The canonical config file carries only public locator data and bounded
/// policy values. Walletd auth is never persisted in the canonical config; it
/// is loaded separately and injected via
/// [`AnchorAppConfig::with_walletd_auth`].
#[derive(Debug, Clone)]
pub struct AnchorAppConfig {
    network_adapter: NetworkAdapterConfig,
    account_reference: AnchorAccountReference,
    archive_manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
    anchor_record_network: OotleNetworkIdV1,
    snapshot_path: PathBuf,
    evidence_path: PathBuf,
    backoff_base_secs: u64,
    backoff_cap_secs: u64,
    ttl_secs: Option<u64>,
}

impl AnchorAppConfig {
    /// Assembles a configuration from its already-validated parts.
    ///
    /// This is the programmatic constructor used by tests and tooling; the
    /// binary loads the canonical file form via [`Self::from_canonical_file`].
    /// The `network_adapter` must already have been constructed (which
    /// validates the network, maximum fee, and receipt-query attempts and
    /// delegates endpoint validation).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_adapter: NetworkAdapterConfig,
        account_reference: AnchorAccountReference,
        archive_manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
        anchor_record_network: OotleNetworkIdV1,
        snapshot_path: PathBuf,
        evidence_path: PathBuf,
        backoff_base_secs: u64,
        backoff_cap_secs: u64,
        ttl_secs: Option<u64>,
    ) -> Self {
        Self {
            network_adapter,
            account_reference,
            archive_manifest_hash,
            archive_hash,
            anchor_record_network,
            snapshot_path,
            evidence_path,
            backoff_base_secs,
            backoff_cap_secs,
            ttl_secs,
        }
    }

    /// Loads a canonical config from `path`.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`ConfigFileError`] on any failure; no OS or
    /// third-party error text is leaked.
    pub fn from_canonical_file(path: &Path) -> Result<Self, ConfigFileError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigFileError::FileNotFound);
            }
            Err(_) => return Err(ConfigFileError::IoFailure),
        };
        if bytes.len() > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigFileError::ProtocolLimitExceeded);
        }
        Self::from_canonical_bytes(&bytes)
    }

    /// Decodes a canonical config from already-read bytes.
    ///
    /// Exposed for the binary's `--dry-run` path and for tests.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`ConfigFileError`] on any failure.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConfigFileError> {
        decode_envelope(bytes)
    }

    /// Encodes this config to its canonical envelope bytes.
    ///
    /// Useful for operator tooling and tests. The canonical config never
    /// includes walletd auth.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`ConfigFileError`] on encoding failure.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ConfigFileError> {
        let body = encode_body(self)?;
        let framed = config_domain_input(&body);
        let digest = Blake3HashProviderV1.hash(&framed);
        let envelope = encode_envelope(&body, &digest)?;
        if envelope.len() > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigFileError::ProtocolLimitExceeded);
        }
        Ok(envelope)
    }

    /// Writes this config to `path` atomically.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`ConfigFileError`] on any failure.
    pub fn write_canonical_file(&self, path: &Path) -> Result<(), ConfigFileError> {
        let bytes = self.to_canonical_bytes()?;
        let mut tmp = std::ffi::OsString::from(path.as_os_str());
        tmp.push(".tmp");
        let tmp_path = Path::new(&tmp);
        let cleanup = |p: &Path| {
            let _ = std::fs::remove_file(p);
        };
        let result = (|| -> Result<(), ConfigFileError> {
            let mut file =
                std::fs::File::create(tmp_path).map_err(|_| ConfigFileError::IoFailure)?;
            use std::io::Write;
            file.write_all(&bytes)
                .map_err(|_| ConfigFileError::IoFailure)?;
            file.flush().map_err(|_| ConfigFileError::IoFailure)?;
            file.sync_all().map_err(|_| ConfigFileError::IoFailure)?;
            drop(file);
            std::fs::rename(tmp_path, path).map_err(|_| ConfigFileError::AtomicRenameFailure)
        })();
        if result.is_err() {
            cleanup(tmp_path);
        }
        result
    }

    /// Returns a copy of this config with walletd auth injected.
    ///
    /// The canonical config file never carries auth; the binary loads it
    /// separately (e.g. from an environment variable) and injects it here
    /// before constructing the driver. The returned config re-validates the
    /// network adapter with the auth present.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigFileError`] if reconstruction fails (it cannot fail
    /// for a config that already validated once, but the `Result` keeps the
    /// binary panic-free).
    pub fn with_walletd_auth(
        self,
        auth: Option<WalletdAuthSecret>,
    ) -> Result<Self, ConfigFileError> {
        let adapter = NetworkAdapterConfig::new(
            self.network_adapter.network().clone(),
            self.network_adapter.walletd_endpoint().clone(),
            self.network_adapter.indexer_endpoint().clone(),
            *self.network_adapter.fee_component(),
            self.network_adapter.seal_signer(),
            self.network_adapter.max_fee(),
            self.network_adapter.request_timeout_secs(),
            self.network_adapter.receipt_query_max_attempts(),
            auth,
        )
        .map_err(from_adapter)?;
        Ok(Self {
            network_adapter: adapter,
            account_reference: self.account_reference,
            archive_manifest_hash: self.archive_manifest_hash,
            archive_hash: self.archive_hash,
            anchor_record_network: self.anchor_record_network,
            snapshot_path: self.snapshot_path,
            evidence_path: self.evidence_path,
            backoff_base_secs: self.backoff_base_secs,
            backoff_cap_secs: self.backoff_cap_secs,
            ttl_secs: self.ttl_secs,
        })
    }

    /// Returns the network adapter configuration.
    #[must_use]
    pub fn network_adapter(&self) -> &NetworkAdapterConfig {
        &self.network_adapter
    }

    /// Returns the fee account reference bound into the anchor.
    #[must_use]
    pub fn account_reference(&self) -> &AnchorAccountReference {
        &self.account_reference
    }

    /// Returns the election manifest hash.
    #[must_use]
    pub fn archive_manifest_hash(&self) -> ManifestHash {
        self.archive_manifest_hash
    }

    /// Returns the archive hash.
    #[must_use]
    pub fn archive_hash(&self) -> ArchiveHashV1 {
        self.archive_hash
    }

    /// Returns the anchor-record network id.
    #[must_use]
    pub fn anchor_record_network(&self) -> &OotleNetworkIdV1 {
        &self.anchor_record_network
    }

    /// Returns the snapshot file path.
    #[must_use]
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    /// Returns the evidence file path.
    #[must_use]
    pub fn evidence_path(&self) -> &Path {
        &self.evidence_path
    }

    /// Returns the backoff base in seconds.
    #[must_use]
    pub fn backoff_base_secs(&self) -> u64 {
        self.backoff_base_secs
    }

    /// Returns the backoff cap in seconds.
    #[must_use]
    pub fn backoff_cap_secs(&self) -> u64 {
        self.backoff_cap_secs
    }

    /// Returns the optional transaction TTL in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> Option<u64> {
        self.ttl_secs
    }
}

fn encode_envelope(body: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, ConfigFileError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(ENVELOPE_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(CONFIG_RECORD_TYPE_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_text_string(CONFIG_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    writer.write_byte_string(digest).map_err(from_protocol)?;
    writer.write_byte_string(body).map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

fn decode_envelope(bytes: &[u8]) -> Result<AnchorAppConfig, ConfigFileError> {
    let mut reader = CanonicalCborReader::new(bytes);
    if reader.read_array_len().map_err(from_protocol)? != ENVELOPE_FIELD_COUNT {
        return Err(ConfigFileError::InvalidCbor);
    }
    if reader.read_text_string().map_err(from_protocol)? != CONFIG_RECORD_TYPE_ID_V1 {
        return Err(ConfigFileError::UnsupportedProtocolVersion);
    }
    if reader.read_text_string().map_err(from_protocol)? != CONFIG_HASH_ALGORITHM_ID_V1 {
        return Err(ConfigFileError::UnsupportedHashAlgorithm);
    }
    let recorded_digest = read_digest(&mut reader)?;
    let body = reader.read_byte_string().map_err(from_protocol)?;
    reader.finish().map_err(from_protocol)?;
    if body.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigFileError::ProtocolLimitExceeded);
    }
    let framed = config_domain_input(body);
    let recomputed = Blake3HashProviderV1.hash(&framed);
    if recomputed != recorded_digest {
        return Err(ConfigFileError::DigestMismatch);
    }
    decode_body(body)
}

fn encode_body(config: &AnchorAppConfig) -> Result<Vec<u8>, ConfigFileError> {
    let adapter = config.network_adapter();
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(BODY_FIELD_COUNT)
        .map_err(from_protocol)?;

    // 1. network
    writer
        .write_text_string(config.anchor_record_network().as_str())
        .map_err(from_protocol)?;
    // 2. walletd endpoint
    writer
        .write_text_string(adapter.walletd_endpoint().as_str())
        .map_err(from_protocol)?;
    // 3. indexer endpoint
    writer
        .write_text_string(adapter.indexer_endpoint().as_str())
        .map_err(from_protocol)?;
    // 4. fee account reference
    writer
        .write_text_string(config.account_reference().as_str())
        .map_err(from_protocol)?;
    // 5. fee component address
    writer
        .write_text_string(&adapter.fee_component().display_string())
        .map_err(from_protocol)?;
    // 6. seal signer
    encode_seal_signer(&mut writer, adapter.seal_signer())?;
    // 7. max fee
    writer.write_unsigned(adapter.max_fee().value());
    // 8. request timeout (optional u64)
    encode_option_u64(&mut writer, adapter.request_timeout_secs())?;
    // 9. receipt-query attempts
    writer.write_unsigned(u64::from(adapter.receipt_query_max_attempts()));
    // 10. manifest hash
    writer
        .write_byte_string(config.archive_manifest_hash().as_bytes())
        .map_err(from_protocol)?;
    // 11. archive hash
    writer
        .write_byte_string(config.archive_hash().as_bytes())
        .map_err(from_protocol)?;
    // 12. snapshot path
    write_path_text(&mut writer, config.snapshot_path())?;
    // 13. evidence path
    write_path_text(&mut writer, config.evidence_path())?;
    // 14. backoff base
    writer.write_unsigned(config.backoff_base_secs());
    // 15. backoff cap
    writer.write_unsigned(config.backoff_cap_secs());
    // 16. ttl (optional u64)
    encode_option_u64(&mut writer, config.ttl_secs())?;

    Ok(writer.into_bytes())
}

fn decode_body(body: &[u8]) -> Result<AnchorAppConfig, ConfigFileError> {
    let mut reader = CanonicalCborReader::new(body);
    if reader.read_array_len().map_err(from_protocol)? != BODY_FIELD_COUNT {
        return Err(ConfigFileError::InvalidCbor);
    }

    let network =
        OotleNetworkIdV1::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| ConfigFileError::InvalidData)?;
    let walletd_endpoint =
        WalletdEndpoint::parse(reader.read_text_string().map_err(from_protocol)?)
            .map_err(|_| ConfigFileError::InvalidData)?;
    let indexer_endpoint =
        IndexerEndpoint::parse(reader.read_text_string().map_err(from_protocol)?)
            .map_err(|_| ConfigFileError::InvalidData)?;
    let account_reference =
        AnchorAccountReference::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| ConfigFileError::InvalidData)?;
    let fee_component =
        WalletdFeeComponentRef::parse(reader.read_text_string().map_err(from_protocol)?)
            .map_err(|_| ConfigFileError::InvalidData)?;
    let seal_signer = decode_seal_signer(&mut reader)?;
    let max_fee = AnchorMaxFeeV1::from_units(reader.read_unsigned().map_err(from_protocol)?);
    let request_timeout_secs = decode_option_u64(&mut reader)?;
    let receipt_query_max_attempts = read_u32(&mut reader)?;
    let manifest_hash = ManifestHash::new(read_digest(&mut reader)?);
    let archive_hash = ArchiveHashV1::new(read_digest(&mut reader)?);
    let snapshot_path = read_path_text(&mut reader)?;
    let evidence_path = read_path_text(&mut reader)?;
    let backoff_base_secs = reader.read_unsigned().map_err(from_protocol)?;
    let backoff_cap_secs = reader.read_unsigned().map_err(from_protocol)?;
    let ttl_secs = decode_option_u64(&mut reader)?;

    reader.finish().map_err(from_protocol)?;

    // Validate paths.
    validate_path(&snapshot_path)?;
    validate_path(&evidence_path)?;

    // Validate backoff.
    if backoff_base_secs == 0 || backoff_cap_secs < backoff_base_secs {
        return Err(ConfigFileError::InvalidBackoff);
    }

    // Build the network adapter (validates network, max fee, receipt attempts;
    // endpoint validation happened at parse time above).
    let network_adapter = NetworkAdapterConfig::new(
        network.clone(),
        walletd_endpoint,
        indexer_endpoint,
        fee_component,
        seal_signer,
        max_fee,
        request_timeout_secs,
        receipt_query_max_attempts,
        None,
    )
    .map_err(from_adapter)?;

    // Validate anchor-record network equals the adapter network.
    if &network != network_adapter.network() {
        return Err(ConfigFileError::NetworkMismatch);
    }

    Ok(AnchorAppConfig {
        network_adapter,
        account_reference,
        archive_manifest_hash: manifest_hash,
        archive_hash,
        anchor_record_network: network,
        snapshot_path,
        evidence_path,
        backoff_base_secs,
        backoff_cap_secs,
        ttl_secs,
    })
}

fn encode_seal_signer(
    writer: &mut CanonicalCborWriter,
    seal: WalletdSealSignerRef,
) -> Result<(), ConfigFileError> {
    writer.write_array_len(2).map_err(from_protocol)?;
    let (tag, index) = match seal {
        WalletdSealSignerRef::AccountKey { index } => (SEAL_TAG_ACCOUNT_KEY, index),
        WalletdSealSignerRef::TransactionKey { index } => (SEAL_TAG_TRANSACTION_KEY, index),
        WalletdSealSignerRef::ImportedKey { local_key_id } => (SEAL_TAG_IMPORTED_KEY, local_key_id),
    };
    writer.write_unsigned(tag);
    writer.write_unsigned(index);
    Ok(())
}

fn decode_seal_signer(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<WalletdSealSignerRef, ConfigFileError> {
    if reader.read_array_len().map_err(from_protocol)? != 2 {
        return Err(ConfigFileError::InvalidCbor);
    }
    let tag = reader.read_unsigned().map_err(from_protocol)?;
    let index = reader.read_unsigned().map_err(from_protocol)?;
    match tag {
        SEAL_TAG_ACCOUNT_KEY => Ok(WalletdSealSignerRef::AccountKey { index }),
        SEAL_TAG_TRANSACTION_KEY => Ok(WalletdSealSignerRef::TransactionKey { index }),
        SEAL_TAG_IMPORTED_KEY => Ok(WalletdSealSignerRef::ImportedKey {
            local_key_id: index,
        }),
        _ => Err(ConfigFileError::InvalidData),
    }
}

fn encode_option_u64(
    writer: &mut CanonicalCborWriter,
    value: Option<u64>,
) -> Result<(), ConfigFileError> {
    match value {
        Some(value) => {
            writer.write_array_len(1).map_err(from_protocol)?;
            writer.write_unsigned(value);
        }
        None => {
            writer.write_array_len(0).map_err(from_protocol)?;
        }
    }
    Ok(())
}

fn decode_option_u64(reader: &mut CanonicalCborReader<'_>) -> Result<Option<u64>, ConfigFileError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(reader.read_unsigned().map_err(from_protocol)?)),
        _ => Err(ConfigFileError::InvalidCbor),
    }
}

fn write_path_text(writer: &mut CanonicalCborWriter, path: &Path) -> Result<(), ConfigFileError> {
    let text = path.to_str().ok_or(ConfigFileError::InvalidPath)?;
    if text.len() > MAX_PATH_BYTES {
        return Err(ConfigFileError::InvalidPath);
    }
    writer.write_text_string(text).map_err(from_protocol)?;
    Ok(())
}

fn read_path_text(reader: &mut CanonicalCborReader<'_>) -> Result<PathBuf, ConfigFileError> {
    let text = reader.read_text_string().map_err(from_protocol)?;
    if text.len() > MAX_PATH_BYTES {
        return Err(ConfigFileError::InvalidPath);
    }
    Ok(PathBuf::from(text))
}

fn validate_path(path: &Path) -> Result<(), ConfigFileError> {
    if !path.is_absolute() {
        return Err(ConfigFileError::InvalidPath);
    }
    if let Some(text) = path.to_str() {
        if text.len() > MAX_PATH_BYTES {
            return Err(ConfigFileError::InvalidPath);
        }
    } else {
        return Err(ConfigFileError::InvalidPath);
    }
    Ok(())
}

fn read_digest(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], ConfigFileError> {
    <[u8; 32]>::try_from(reader.read_byte_string().map_err(from_protocol)?)
        .map_err(|_| ConfigFileError::InvalidCbor)
}

fn read_u32(reader: &mut CanonicalCborReader<'_>) -> Result<u32, ConfigFileError> {
    let value = reader.read_unsigned().map_err(from_protocol)?;
    u32::try_from(value).map_err(|_| ConfigFileError::InvalidData)
}

fn config_domain_input(body: &[u8]) -> Vec<u8> {
    let label = CONFIG_DOMAIN_LABEL_V1.as_bytes();
    let mut framed =
        Vec::with_capacity(CONFIG_FRAME_PREFIX_V1.len() + 1 + label.len() + 1 + body.len());
    framed.extend_from_slice(CONFIG_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(body);
    framed
}

// Suppress unused-import warning for the purpose constant if downstream
// modules do not reference it directly.
#[allow(dead_code)]
const _PURPOSE_ID: &str = OOTLE_ANCHOR_PURPOSE_ID_V1;
