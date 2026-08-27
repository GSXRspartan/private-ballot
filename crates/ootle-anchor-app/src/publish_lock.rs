//! Two-layer serialization for the live anchor publish lifecycle (HIGH-1).
//!
//! Each live publish step (restore → floor/binding checks → walletd
//! create/approve/submit → receipt poll → evidence → terminal index) must never
//! run concurrently for the SAME logical anchor. UI button disabling is not a
//! security boundary, and each Tauri invocation constructs an independent driver
//! from the same on-disk snapshot, so serialization lives in this SHARED layer
//! and protects the GUI, the CLI, and any direct driver invocation identically.
//!
//! Two composed locks, keyed by the election manifest hash (unrelated elections
//! never block each other):
//!
//! 1. **In-process** — a process-global keyed `Mutex`. Two concurrent steps for
//!    the same anchor inside one process are serialized (blocking), so the
//!    second observes the first's persisted post-submit snapshot and recovers
//!    instead of blind-resubmitting.
//! 2. **Durable / cross-process** — an OS advisory lock ([`std::fs::File::try_lock`])
//!    on a per-anchor lock file under the machine-global terminal-index root.
//!    A second process (e.g. the CLI while the GUI runs) is rejected with a
//!    bounded busy error rather than racing. The OS releases the lock when the
//!    holding process exits, so a crash can never permanently brick the anchor
//!    (the leftover lock file is re-lockable on the next attempt).
//!
//! Acquisition is bounded and non-blocking across processes (try-lock → busy
//! error); within a process it is a short blocking wait that always makes
//! progress because each step is bounded and never sleeps under the lock.

use std::collections::HashMap;
use std::fs::{OpenOptions, TryLockError};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// Backend-owned directory (under the terminal-index root) holding per-anchor
/// durable publish locks.
const PUBLISH_LOCKS_DIR_V1: &str = "publish-locks-v1";

/// Bounded failure while acquiring a publish lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishLockError {
    /// Another publish step already holds the lock for this anchor.
    Busy,
    /// The durable lock file could not be created or locked (I/O failure).
    Unavailable,
}

/// Process-global registry of per-anchor in-process mutexes, keyed by manifest
/// hash. Entries persist for the process lifetime (bounded by the small number
/// of distinct elections an operator publishes).
fn inproc_registry() -> &'static Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns the shared in-process mutex for `key`, creating it on first use.
fn inproc_mutex_for(key: &[u8; 32]) -> Arc<Mutex<()>> {
    let mut registry = inproc_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        registry
            .entry(*key)
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

/// RAII guard for the durable, cross-process advisory lock. The OS releases the
/// lock when this handle is dropped (or when the process exits/crashes).
#[derive(Debug)]
struct DurableLockGuard {
    file: std::fs::File,
}

impl Drop for DurableLockGuard {
    fn drop(&mut self) {
        // Explicit release for clarity; the OS also releases on handle close.
        let _ = self.file.unlock();
    }
}

/// Acquires the durable cross-process lock for `key` under `terminal_index_root`.
fn acquire_durable_lock(
    terminal_index_root: &Path,
    key: &[u8; 32],
) -> Result<DurableLockGuard, PublishLockError> {
    let locks_dir = terminal_index_root.join(PUBLISH_LOCKS_DIR_V1);
    std::fs::create_dir_all(&locks_dir).map_err(|_| PublishLockError::Unavailable)?;
    let path = locks_dir.join(format!("anchor-{}.lock", to_lower_hex(key)));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|_| PublishLockError::Unavailable)?;
    match file.try_lock() {
        Ok(()) => Ok(DurableLockGuard { file }),
        Err(TryLockError::WouldBlock) => Err(PublishLockError::Busy),
        Err(TryLockError::Error(_)) => Err(PublishLockError::Unavailable),
    }
}

/// Runs `body` while holding BOTH the in-process and durable publish locks for
/// `key`, scoped under `terminal_index_root`.
///
/// The in-process mutex is acquired first (a short blocking wait), then the
/// durable OS lock (non-blocking: a concurrent process yields
/// [`PublishLockError::Busy`]). Both are released when this function returns —
/// including on an error or panic within `body` — so no lock is ever leaked
/// across steps, and a crash releases the durable lock at the OS level.
pub fn with_publish_lock<T, E>(
    terminal_index_root: &Path,
    key: &[u8; 32],
    map_lock_error: impl FnOnce(PublishLockError) -> E,
    body: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let inproc = inproc_mutex_for(key);
    // Poison-tolerant: a prior panic under the lock must not brick every future
    // publish. The durable lock and the persisted snapshot remain the
    // authority; recover the guard and continue.
    let _inproc_guard = inproc
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _durable_guard = acquire_durable_lock(terminal_index_root, key).map_err(map_lock_error)?;
    body()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_root(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tari-anchor-publishlock-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp root must create");
        base
    }

    #[test]
    fn durable_lock_is_exclusive_while_held_and_reusable_after_release() {
        let root = temp_root("durable");
        let key = [7u8; 32];
        {
            let guard = acquire_durable_lock(&root, &key).expect("first acquire");
            // A second acquire on the SAME handle path is refused while held.
            assert_eq!(
                acquire_durable_lock(&root, &key).err(),
                Some(PublishLockError::Busy)
            );
            drop(guard);
        }
        // After release the lock is reusable — a crash-left lock file never
        // bricks the anchor.
        let reacquired = acquire_durable_lock(&root, &key).expect("reacquire after release");
        drop(reacquired);
    }

    #[test]
    fn unrelated_keys_do_not_block_each_other() {
        let root = temp_root("unrelated");
        let a = acquire_durable_lock(&root, &[1u8; 32]).expect("acquire a");
        let b = acquire_durable_lock(&root, &[2u8; 32]).expect("acquire b");
        drop(a);
        drop(b);
    }

    #[test]
    fn leftover_lock_file_without_active_lock_is_acquirable() {
        let root = temp_root("leftover");
        let key = [9u8; 32];
        // Simulate a crash-left lock FILE (present but not actively locked).
        let locks_dir = root.join(PUBLISH_LOCKS_DIR_V1);
        std::fs::create_dir_all(&locks_dir).expect("locks dir");
        let path = locks_dir.join(format!("anchor-{}.lock", to_lower_hex(&key)));
        std::fs::write(&path, b"stale").expect("write stale lock file");
        // The file existing must not brick acquisition.
        let guard = acquire_durable_lock(&root, &key).expect("acquire over leftover file");
        drop(guard);
    }
}
