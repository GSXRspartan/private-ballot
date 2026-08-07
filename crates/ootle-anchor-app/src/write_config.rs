//! `--write-config` operator mode (Phase 4 operator-tooling slice).
//!
//! This module parses validated string arguments from [`crate::cli::WriteConfigArgs`]
//! into existing project-owned types, constructs an [`AnchorAppConfig`] through
//! the existing public [`NetworkAdapterConfig`] constructor, calls the existing
//! [`AnchorAppConfig::write_canonical_file`], reads the file back through
//! [`AnchorAppConfig::from_canonical_file`], verifies the decoded config matches
//! the intended config, and prints a stable machine-readable summary.
//!
//! It never manually serializes CBOR, never contacts walletd or the indexer,
//! never loads auth, never creates a runtime, never creates a snapshot, never
//! creates evidence, and never submits or signs.

use std::path::PathBuf;

use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{AnchorAccountReference, AnchorMaxFeeV1};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, NetworkAdapterConfig, WalletdEndpoint,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdFeeComponentRef, WalletdSealSignerRef,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider, ManifestHash};

use crate::cli::WriteConfigArgs;
use crate::config::AnchorAppConfig;
use crate::report::MachineReportCode;

const CONFIG_WRITTEN: &str = "ANCHOR_APP_CONFIG_WRITTEN";
const CONFIG_WRITE_FAILED: &str = "ANCHOR_APP_CONFIG_WRITE_FAILED";

/// Runs the `--write-config` mode.
///
/// Returns `Ok(())` on success (exit 0) and `Err(code)` on failure (non-zero
/// exit). The stable machine code is printed to stdout on success and to
/// stderr on failure (the binary handles stderr printing).
///
/// The destination file is never touched until every validation passes:
///
/// 1. field-level parsing and construction through project-owned constructors;
/// 2. path safety (absolute output/snapshot/evidence, pairwise distinct);
/// 3. in-memory canonical round-trip (`to_canonical_bytes` →
///    `from_canonical_bytes`) which enforces absolute snapshot/evidence paths,
///    backoff ordering, and all decoder invariants;
/// 4. output-file existence and regular-file checks (with `--force`).
pub fn run(args: &WriteConfigArgs) -> Result<(), String> {
    let config = build_config(args).map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;

    // Path safety: output must be absolute and distinct from snapshot/evidence.
    validate_output_path(&args.output, &args.snapshot_path, &args.evidence_path)?;

    // In-memory canonical round-trip validation. This runs the full decoder
    // (which enforces absolute snapshot/evidence paths, backoff ordering,
    // network consistency, and all field invariants) *before* the destination
    // is touched. A relative path or invalid backoff therefore fails here
    // without creating or clobbering any file.
    let canonical_bytes = config
        .to_canonical_bytes()
        .map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;
    let decoded = AnchorAppConfig::from_canonical_bytes(&canonical_bytes)
        .map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;
    if !configs_equal(&config, &decoded) {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }

    // Fail closed if the output file already exists and --force was not
    // supplied.
    let output_path = std::path::Path::new(&args.output);
    if output_path.exists() {
        if !args.force {
            return Err(CONFIG_WRITE_FAILED.to_owned());
        }
        // --force: only overwrite an existing regular file. A directory or
        // special file is rejected to avoid corrupting a non-file target.
        let metadata =
            std::fs::symlink_metadata(output_path).map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;
        if !metadata.is_file() {
            return Err(CONFIG_WRITE_FAILED.to_owned());
        }
    }

    // Write the canonical config through the existing atomic writer.
    config
        .write_canonical_file(output_path)
        .map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;

    // Read back and verify the decoded config equals the intended config.
    let decoded = AnchorAppConfig::from_canonical_file(output_path)
        .map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;
    if !configs_equal(&config, &decoded) {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }

    // Read the written file bytes for hashing and size reporting.
    let file_bytes = std::fs::read(output_path).map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;

    // Compute a whole-file BLAKE3-256 hash using the existing hash provider
    // (no new dependency introduced; SHA-256 is intentionally avoided to keep
    // Cargo.lock unchanged). The runbook records a separate SHA-256 via
    // Get-FileHash for external tooling; the two values are intentionally
    // different.
    let file_blake3 = Blake3HashProviderV1.hash(&file_bytes);

    // Print the stable machine-readable output.
    println!("machine_code={CONFIG_WRITTEN}");
    println!("config_path={}", args.output);
    println!("network={}", config.anchor_record_network().as_str());
    println!(
        "manifest_hash={}",
        to_lower_hex(config.archive_manifest_hash().as_bytes())
    );
    println!(
        "archive_hash={}",
        to_lower_hex(config.archive_hash().as_bytes())
    );
    let record = OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    );
    let anchor_digest = record
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|_| CONFIG_WRITE_FAILED.to_owned())?;
    println!("anchor_digest={}", to_lower_hex(anchor_digest.as_bytes()));
    println!("snapshot_path={}", config.snapshot_path().display());
    println!("evidence_path={}", config.evidence_path().display());
    println!("config_file_blake3_256={}", to_lower_hex(&file_blake3));
    println!("config_file_bytes={}", file_bytes.len());

    Ok(())
}

fn build_config(args: &WriteConfigArgs) -> Result<AnchorAppConfig, ()> {
    let network = OotleNetworkIdV1::new(args.network.clone()).map_err(|_| ())?;
    let walletd_endpoint = WalletdEndpoint::parse(&args.walletd_endpoint).map_err(|_| ())?;
    let indexer_endpoint = IndexerEndpoint::parse(&args.indexer_endpoint).map_err(|_| ())?;
    let account_reference =
        AnchorAccountReference::new(args.account_reference.clone()).map_err(|_| ())?;
    let fee_component = WalletdFeeComponentRef::parse(&args.fee_component).map_err(|_| ())?;
    let seal_signer = parse_seal_signer(&args.seal_signer_kind, &args.seal_signer_id)?;
    let max_fee_value: u64 = args.max_fee.parse().map_err(|_| ())?;
    let max_fee = AnchorMaxFeeV1::from_units(max_fee_value);
    if max_fee.value() == 0 {
        return Err(());
    }
    let manifest_hash = ManifestHash::new(parse_hash(&args.manifest_hash)?);
    let archive_hash = ArchiveHashV1::new(parse_hash(&args.archive_hash)?);
    let snapshot_path = PathBuf::from(&args.snapshot_path);
    let evidence_path = PathBuf::from(&args.evidence_path);
    let backoff_base_secs: u64 = args.backoff_base_secs.parse().map_err(|_| ())?;
    let backoff_cap_secs: u64 = args.backoff_cap_secs.parse().map_err(|_| ())?;
    let receipt_query_attempts: u32 = args.receipt_query_attempts.parse().map_err(|_| ())?;
    let request_timeout_secs: Option<u64> = match &args.request_timeout_secs {
        Some(s) => Some(s.parse().map_err(|_| ())?),
        None => None,
    };
    let ttl_secs: Option<u64> = match &args.ttl_secs {
        Some(s) => Some(s.parse().map_err(|_| ())?),
        None => None,
    };

    let network_adapter = NetworkAdapterConfig::new(
        network.clone(),
        walletd_endpoint,
        indexer_endpoint,
        fee_component,
        seal_signer,
        max_fee,
        request_timeout_secs,
        receipt_query_attempts,
        None,
    )
    .map_err(|_| ())?;

    Ok(AnchorAppConfig::new(
        network_adapter,
        account_reference,
        manifest_hash,
        archive_hash,
        network,
        snapshot_path,
        evidence_path,
        backoff_base_secs,
        backoff_cap_secs,
        ttl_secs,
    ))
}

fn parse_seal_signer(kind: &str, id: &str) -> Result<WalletdSealSignerRef, ()> {
    let index: u64 = id.parse().map_err(|_| ())?;
    match kind {
        "account" => Ok(WalletdSealSignerRef::AccountKey { index }),
        "transaction" => Ok(WalletdSealSignerRef::TransactionKey { index }),
        "imported" => Ok(WalletdSealSignerRef::ImportedKey {
            local_key_id: index,
        }),
        _ => Err(()),
    }
}

fn parse_hash(hex: &str) -> Result<[u8; 32], ()> {
    let bytes = hex_to_bytes_32(hex)?;
    Ok(bytes)
}

fn hex_to_bytes_32(hex: &str) -> Result<[u8; 32], ()> {
    if hex.len() != 64 {
        return Err(());
    }
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

fn configs_equal(a: &AnchorAppConfig, b: &AnchorAppConfig) -> bool {
    a.anchor_record_network() == b.anchor_record_network()
        && a.archive_manifest_hash() == b.archive_manifest_hash()
        && a.archive_hash() == b.archive_hash()
        && a.account_reference() == b.account_reference()
        && a.network_adapter().walletd_endpoint() == b.network_adapter().walletd_endpoint()
        && a.network_adapter().indexer_endpoint() == b.network_adapter().indexer_endpoint()
        && a.network_adapter().fee_component() == b.network_adapter().fee_component()
        && a.network_adapter().seal_signer() == b.network_adapter().seal_signer()
        && a.network_adapter().max_fee() == b.network_adapter().max_fee()
        && a.network_adapter().request_timeout_secs() == b.network_adapter().request_timeout_secs()
        && a.network_adapter().receipt_query_max_attempts()
            == b.network_adapter().receipt_query_max_attempts()
        && a.snapshot_path() == b.snapshot_path()
        && a.evidence_path() == b.evidence_path()
        && a.backoff_base_secs() == b.backoff_base_secs()
        && a.backoff_cap_secs() == b.backoff_cap_secs()
        && a.ttl_secs() == b.ttl_secs()
}

/// Validates that the output path is absolute and pairwise distinct from the
/// snapshot and evidence paths. Uses lexical normalization only (no filesystem
/// access), suitable for Windows where `\` and `/` are both valid separators
/// and paths are case-insensitive.
fn validate_output_path(
    output: &str,
    snapshot_path: &str,
    evidence_path: &str,
) -> Result<(), String> {
    let output_p = std::path::Path::new(output);
    if !output_p.is_absolute() {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }

    let norm_output = normalize_path_for_comparison(output);
    let norm_snapshot = normalize_path_for_comparison(snapshot_path);
    let norm_evidence = normalize_path_for_comparison(evidence_path);

    if norm_output == norm_snapshot {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }
    if norm_output == norm_evidence {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }
    if norm_snapshot == norm_evidence {
        return Err(CONFIG_WRITE_FAILED.to_owned());
    }

    Ok(())
}

/// Lexically normalizes a path string for comparison: replaces `\` with `/`,
/// trims trailing separators, and lowercases (Windows is case-insensitive).
/// This does not touch the filesystem and does not resolve symlinks or `.`/`..`
/// components, so it catches only literal path collisions, not semantic ones.
fn normalize_path_for_comparison(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    trimmed.to_lowercase()
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Returns the stable success code for the writer mode.
#[must_use]
pub fn success_code() -> &'static str {
    CONFIG_WRITTEN
}

/// Returns the stable failure code for the writer mode.
#[must_use]
pub fn failure_code() -> &'static str {
    CONFIG_WRITE_FAILED
}

/// Returns the stable machine report code for the writer success.
#[must_use]
pub fn success_report_code() -> MachineReportCode {
    MachineReportCode::ConfigWritten
}

/// Returns the stable machine report code for the writer failure.
#[must_use]
pub fn failure_report_code() -> MachineReportCode {
    MachineReportCode::ConfigWriteFailed
}
