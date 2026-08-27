//! Durable receipt-poll backoff gate for stepped (interactive) execution
//! (MEDIUM-1).
//!
//! The looped [`crate::driver::AnchorAppDriver::run`] enforces the receipt-poll
//! backoff by sleeping between polls. The interactive
//! [`crate::driver::AnchorAppDriver::run_single_step`] must NOT sleep inside a
//! GUI request, yet repeated immediate calls must not poll faster than `run`
//! would — otherwise a caller could burn receipt attempts and reach
//! `PollExhaustedUnknown` prematurely.
//!
//! This module persists the earliest-eligible next-poll wall-clock instant in a
//! small sidecar next to the lifecycle snapshot. A stepped poll consults the
//! gate first and, when the deadline has not passed, returns a bounded
//! "retry after N seconds" WITHOUT polling and WITHOUT consuming an attempt.
//! The gate survives process restart, so a restart cannot reset or bypass the
//! backoff.
//!
//! Wall-clock movement is handled defensively: a remaining wait larger than the
//! configured backoff cap (a backward clock jump, or a corrupt/foreign file)
//! is treated as eligible rather than trusted, so the gate can never wedge the
//! lifecycle indefinitely.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const POLL_GATE_MAGIC_V1: &[u8] = b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_POLL_GATE_V1";
const POLL_GATE_FILE_SUFFIX: &str = ".pollgate";

/// Returns the poll-gate sidecar path for a snapshot path (`<snapshot>.pollgate`).
#[must_use]
pub fn poll_gate_path(snapshot_path: &Path) -> PathBuf {
    let mut raw: OsString = snapshot_path.as_os_str().to_owned();
    raw.push(POLL_GATE_FILE_SUFFIX);
    PathBuf::from(raw)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persists a not-before deadline of `now + delay_secs` for the next poll,
/// recording `backoff_cap_secs` so a later read can clamp a jumped clock.
///
/// Best-effort and atomic: the poll has already happened and its snapshot is
/// persisted before this is written, so a write failure only means the next
/// stepped call may poll slightly sooner — never a safety regression.
pub fn write_poll_gate(snapshot_path: &Path, delay_secs: u64, backoff_cap_secs: u64) {
    let not_before = now_unix_secs().saturating_add(delay_secs);
    let mut bytes = Vec::with_capacity(POLL_GATE_MAGIC_V1.len() + 16);
    bytes.extend_from_slice(POLL_GATE_MAGIC_V1);
    bytes.extend_from_slice(&not_before.to_le_bytes());
    bytes.extend_from_slice(&backoff_cap_secs.to_le_bytes());
    let path = poll_gate_path(snapshot_path);
    let _ = write_atomic(&path, &bytes);
}

/// Removes the poll gate (best-effort), e.g. once a poll becomes eligible or a
/// terminal state is reached.
pub fn clear_poll_gate(snapshot_path: &Path) {
    let _ = std::fs::remove_file(poll_gate_path(snapshot_path));
}

/// Returns the remaining seconds before the next poll is eligible, or `None`
/// when a poll is eligible now (no gate, corrupt/foreign gate, deadline passed,
/// or an implausibly large remaining wait indicating clock movement).
#[must_use]
pub fn poll_gate_remaining_secs(snapshot_path: &Path) -> Option<u64> {
    let path = poll_gate_path(snapshot_path);
    let bytes = std::fs::read(&path).ok()?;
    let expected_len = POLL_GATE_MAGIC_V1.len() + 16;
    if bytes.len() != expected_len || !bytes.starts_with(POLL_GATE_MAGIC_V1) {
        return None;
    }
    let not_before = read_u64(&bytes, POLL_GATE_MAGIC_V1.len())?;
    let backoff_cap = read_u64(&bytes, POLL_GATE_MAGIC_V1.len() + 8)?;
    let remaining = not_before.saturating_sub(now_unix_secs());
    if remaining == 0 {
        return None;
    }
    // Defensive clock-movement clamp: never trust a remaining wait larger than
    // the recorded backoff cap (a backward clock jump or a tampered file).
    if remaining > backoff_cap {
        return None;
    }
    Some(remaining)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp: OsString = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp_path);
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    if let Err(error) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_snapshot(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tari-anchor-pollgate-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("snapshot.cbor")
    }

    #[test]
    fn future_deadline_reports_remaining_and_survives_reread() {
        let snapshot = temp_snapshot("future");
        write_poll_gate(&snapshot, 30, 60);
        let remaining = poll_gate_remaining_secs(&snapshot).expect("gate active");
        assert!(remaining > 0 && remaining <= 30);
        // Re-read (simulating a restart) still sees the gate.
        assert!(poll_gate_remaining_secs(&snapshot).is_some());
    }

    #[test]
    fn past_deadline_is_eligible() {
        let snapshot = temp_snapshot("past");
        write_poll_gate(&snapshot, 0, 60);
        assert_eq!(poll_gate_remaining_secs(&snapshot), None);
    }

    #[test]
    fn missing_gate_is_eligible() {
        let snapshot = temp_snapshot("missing");
        assert_eq!(poll_gate_remaining_secs(&snapshot), None);
    }

    #[test]
    fn remaining_larger_than_cap_is_treated_as_eligible() {
        let snapshot = temp_snapshot("clockjump");
        // Deadline far in the future but a tiny cap: a backward clock jump.
        write_poll_gate(&snapshot, 100_000, 10);
        assert_eq!(poll_gate_remaining_secs(&snapshot), None);
    }

    #[test]
    fn clear_removes_the_gate() {
        let snapshot = temp_snapshot("clear");
        write_poll_gate(&snapshot, 30, 60);
        assert!(poll_gate_remaining_secs(&snapshot).is_some());
        clear_poll_gate(&snapshot);
        assert_eq!(poll_gate_remaining_secs(&snapshot), None);
    }
}
