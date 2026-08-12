//! `--inspect-snapshot <path>` operator mode (Phase 4 operator-tooling slice).
//!
//! This module calls the existing [`read_snapshot`] and [`snapshot_digest`]
//! functions, then runs the existing lifecycle semantic reconstruction
//! validation through [`AnchorLifecycleOrchestrator::from_snapshot`] before
//! printing a bounded read-only summary of the decoded fields. It returns
//! exit 0 only when the snapshot verifies, decodes, and is semantically
//! consistent with the declared lifecycle phase.
//!
//! It never reconstructs a driver, never contacts a transport, never mutates
//! the snapshot, and never writes evidence.

use std::path::Path;

use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleOrchestrator;

use crate::report::MachineReportCode;
use crate::snapshot_store::{MAX_SNAPSHOT_FILE_BYTES, read_snapshot, snapshot_digest};

const SNAPSHOT_VERIFIED: &str = "ANCHOR_APP_SNAPSHOT_VERIFIED";
const SNAPSHOT_VERIFY_FAILED: &str = "ANCHOR_APP_SNAPSHOT_VERIFY_FAILED";

/// Runs the `--inspect-snapshot <path>` mode.
///
/// Returns `Ok(())` on success (exit 0) and `Err(code)` on failure (non-zero
/// exit).
///
/// The snapshot must pass four validation stages before
/// `ANCHOR_APP_SNAPSHOT_VERIFIED` is printed:
///
/// 1. canonical envelope validation (record type, hash algorithm);
/// 2. snapshot digest validation (recomputed body digest matches recorded);
/// 3. structural body decoding (all CBOR fields and enum variants valid);
/// 4. lifecycle semantic reconstruction validation
///    ([`AnchorLifecycleOrchestrator::from_snapshot`]).
pub fn run(path: &str) -> Result<(), String> {
    let p = Path::new(path);

    // Enforce the size cap and regular-file check before read_snapshot
    // allocates the full file into memory.
    let metadata = std::fs::symlink_metadata(p).map_err(|_| SNAPSHOT_VERIFY_FAILED.to_owned())?;
    if !metadata.is_file() {
        return Err(SNAPSHOT_VERIFY_FAILED.to_owned());
    }
    if metadata.len() > MAX_SNAPSHOT_FILE_BYTES as u64 {
        return Err(SNAPSHOT_VERIFY_FAILED.to_owned());
    }

    let snapshot = read_snapshot(p).map_err(|_| SNAPSHOT_VERIFY_FAILED.to_owned())?;
    let digest = snapshot_digest(&snapshot).map_err(|_| SNAPSHOT_VERIFY_FAILED.to_owned())?;

    // Semantic reconstruction validation: the snapshot's declared phase must
    // be derivable from and consistent with the contained walletd snapshots,
    // receipt snapshots, submitted handle, and polling policy. This prevents a
    // digest-consistent but semantically impossible snapshot from being
    // labelled "verified". The orchestrator performs no network call and no
    // mutation; it only validates and discards its copy.
    AnchorLifecycleOrchestrator::from_snapshot(snapshot.clone())
        .map_err(|_| SNAPSHOT_VERIFY_FAILED.to_owned())?;

    println!("machine_code={SNAPSHOT_VERIFIED}");
    println!("snapshot_path={path}");
    println!("snapshot_digest={}", to_lower_hex(&digest));
    println!("phase={}", snapshot.phase().as_str());
    println!(
        "poll_attempts_consumed={}",
        snapshot.policy().attempts_consumed()
    );
    println!(
        "poll_attempts_max={}",
        snapshot.policy().max_query_attempts()
    );
    match snapshot.transaction_id() {
        Some(tx) => println!("submitted_transaction_id={}", tx.as_str()),
        None => println!("submitted_transaction_id=none"),
    }
    println!(
        "walletd_snapshot_count={}",
        snapshot.walletd_snapshots().len()
    );
    println!(
        "receipt_snapshot_count={}",
        snapshot.receipt_snapshots().len()
    );

    for (i, ws) in snapshot.walletd_snapshots().iter().enumerate() {
        println!(
            "walletd_snapshot[{i}].project_request_id={}",
            ws.project_request_id().as_str()
        );
        println!(
            "walletd_snapshot[{i}].walletd_request_id={}",
            ws.walletd_request_id().value()
        );
        let binding = ws.binding();
        println!(
            "walletd_snapshot[{i}].network={}",
            binding.network().as_str()
        );
        println!(
            "walletd_snapshot[{i}].account_reference={}",
            binding.account().as_str()
        );
        println!(
            "walletd_snapshot[{i}].anchor_digest={}",
            to_lower_hex(binding.anchor_digest().as_bytes())
        );
        println!(
            "walletd_snapshot[{i}].anchor_payload={}",
            binding.payload().to_encoded_string()
        );
        println!(
            "walletd_snapshot[{i}].max_fee={}",
            binding.max_fee().value()
        );
        println!(
            "walletd_snapshot[{i}].transaction_fingerprint={}",
            to_lower_hex(binding.fingerprint().as_bytes())
        );
        println!("walletd_snapshot[{i}].decision={}", ws.decision().as_str());
        println!(
            "walletd_snapshot[{i}].submission_state={}",
            ws.submission().as_str()
        );
        match ws.transaction_id() {
            Some(tx) => println!("walletd_snapshot[{i}].transaction_id={}", tx.as_str()),
            None => println!("walletd_snapshot[{i}].transaction_id=none"),
        }
        match ws.last_effective_status() {
            Some(s) => println!("walletd_snapshot[{i}].effective_status={}", s.as_str()),
            None => println!("walletd_snapshot[{i}].effective_status=none"),
        }
        println!("walletd_snapshot[{i}].retry_count={}", ws.retry_count());
        println!("walletd_snapshot[{i}].sequence={}", ws.sequence());
        match ws.last_diagnostic() {
            Some(d) => println!("walletd_snapshot[{i}].diagnostic={d}"),
            None => println!("walletd_snapshot[{i}].diagnostic=none"),
        }
    }

    for (i, rs) in snapshot.receipt_snapshots().iter().enumerate() {
        println!(
            "receipt_snapshot[{i}].project_request_id={}",
            rs.project_request_id().as_str()
        );
        println!(
            "receipt_snapshot[{i}].walletd_request_id={}",
            rs.walletd_request_id().value()
        );
        println!(
            "receipt_snapshot[{i}].transaction_id={}",
            rs.transaction_id().as_str()
        );
        println!("receipt_snapshot[{i}].network={}", rs.network().as_str());
        println!(
            "receipt_snapshot[{i}].account_reference={}",
            rs.account().as_str()
        );
        println!(
            "receipt_snapshot[{i}].anchor_digest={}",
            to_lower_hex(rs.anchor_digest().as_bytes())
        );
        println!(
            "receipt_snapshot[{i}].anchor_payload={}",
            rs.payload().to_encoded_string()
        );
        println!(
            "receipt_snapshot[{i}].transaction_fingerprint={}",
            to_lower_hex(rs.fingerprint().as_bytes())
        );
        println!("receipt_snapshot[{i}].query_state={}", rs.state().as_str());
        match rs.last_final_status() {
            Some(s) => println!("receipt_snapshot[{i}].final_status={}", s.as_str()),
            None => println!("receipt_snapshot[{i}].final_status=none"),
        }
        println!("receipt_snapshot[{i}].verified={}", rs.verified());
        println!("receipt_snapshot[{i}].sequence={}", rs.sequence());
        match rs.last_diagnostic() {
            Some(d) => println!("receipt_snapshot[{i}].diagnostic={d}"),
            None => println!("receipt_snapshot[{i}].diagnostic=none"),
        }
    }

    Ok(())
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

/// Returns the stable success report code for the snapshot inspector.
#[must_use]
pub fn success_report_code() -> MachineReportCode {
    MachineReportCode::SnapshotVerified
}

/// Returns the stable failure report code for the snapshot inspector.
#[must_use]
pub fn failure_report_code() -> MachineReportCode {
    MachineReportCode::SnapshotVerifyFailed
}
