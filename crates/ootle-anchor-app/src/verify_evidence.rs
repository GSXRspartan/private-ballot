//! `--verify-evidence <path>` operator mode (Phase 4 operator-tooling slice).
//!
//! This module reads a canonical evidence file, calls the existing
//! [`AnchorEvidenceRecordV1::from_canonical_bytes`] (which verifies the
//! envelope record-type, hash-algorithm identifier, and the embedded body
//! digest before trusting any decoded field), prints the decoded fields and
//! the existing human-review summary, and returns exit 0 only when decoding
//! and digest verification succeed.
//!
//! It never contacts the network, never opens a socket, never mutates the
//! file, and never performs signing.

use std::path::Path;

use crate::evidence::{AnchorEvidenceRecordV1, MAX_EVIDENCE_FILE_BYTES};
use crate::report::MachineReportCode;

const EVIDENCE_VERIFIED: &str = "ANCHOR_APP_EVIDENCE_VERIFIED";
const EVIDENCE_VERIFY_FAILED: &str = "ANCHOR_APP_EVIDENCE_VERIFY_FAILED";

/// Runs the `--verify-evidence <path>` mode.
///
/// Returns `Ok(())` on success (exit 0) and `Err(code)` on failure (non-zero
/// exit).
pub fn run(path: &str) -> Result<(), String> {
    let p = Path::new(path);

    // Enforce the size cap before allocating the full file. This rejects an
    // oversized or non-regular file without reading it into memory.
    let metadata = std::fs::symlink_metadata(p).map_err(|_| EVIDENCE_VERIFY_FAILED.to_owned())?;
    if !metadata.is_file() {
        return Err(EVIDENCE_VERIFY_FAILED.to_owned());
    }
    if metadata.len() > MAX_EVIDENCE_FILE_BYTES as u64 {
        return Err(EVIDENCE_VERIFY_FAILED.to_owned());
    }

    let bytes = std::fs::read(p).map_err(|_| EVIDENCE_VERIFY_FAILED.to_owned())?;

    if bytes.len() > MAX_EVIDENCE_FILE_BYTES {
        return Err(EVIDENCE_VERIFY_FAILED.to_owned());
    }

    let record = AnchorEvidenceRecordV1::from_canonical_bytes(&bytes)
        .map_err(|_| EVIDENCE_VERIFY_FAILED.to_owned())?;

    println!("machine_code={EVIDENCE_VERIFIED}");
    println!("evidence_path={path}");
    println!("record_digest={}", to_lower_hex(&record.digest()));
    println!("final_status={}", record.final_status());
    println!("receipt_source={}", record.receipt_source());
    println!("phase={}", record.phase().as_str());
    println!("network={}", record.network().as_str());
    println!(
        "manifest_hash={}",
        to_lower_hex(record.manifest_hash().as_bytes())
    );
    println!(
        "archive_hash={}",
        to_lower_hex(record.archive_hash().as_bytes())
    );
    println!(
        "anchor_digest={}",
        to_lower_hex(record.anchor_digest().as_bytes())
    );
    match record.transaction_id() {
        Some(tx) => println!("transaction_id={}", tx.as_str()),
        None => println!("transaction_id=none"),
    }
    match record.ledger_position() {
        Some(pos) => println!("ledger_position={pos}"),
        None => println!("ledger_position=none"),
    }
    println!(
        "snapshot_digest={}",
        to_lower_hex(&record.snapshot_digest())
    );
    // Collapse newlines and carriage returns to spaces so the summary remains
    // a single physical machine-readable line. The canonical evidence record
    // and its fixed semantic wording are not altered — only the presentation.
    let summary = sanitize_single_line(&record.human_review_summary());
    println!("human_review_summary={summary}");

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

/// Replaces `\n`, `\r`, and other control characters with spaces so the value
/// fits on a single physical line. This prevents machine-output injection
/// where a multi-line value could insert fake `key=value` lines.
#[must_use]
pub fn sanitize_single_line(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Returns the stable success report code for the evidence verifier.
#[must_use]
pub fn success_report_code() -> MachineReportCode {
    MachineReportCode::EvidenceVerified
}

/// Returns the stable failure report code for the evidence verifier.
#[must_use]
pub fn failure_report_code() -> MachineReportCode {
    MachineReportCode::EvidenceVerifyFailed
}
