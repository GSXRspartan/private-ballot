//! Bounded multicore historical ballot verification (Slice 4B).
//!
//! Cold durable reconstruction replays every stored ballot package through
//! Triptych proof verification. This module accelerates ONLY that legitimate
//! historical replay by verifying the cryptographic validity of many packages
//! concurrently — and never touches the ordered election semantics.
//!
//! # Security separation (mandatory)
//!
//! * **Parallel, order-independent:** "is this proof cryptographically valid for
//!   this election?" Computed here across a bounded worker pool over homogeneous
//!   batches, reusing one immutable election verifier context. Each package's
//!   result is a pure function of `(package_bytes, manifest, candidates,
//!   verifier)` and is identical to verifying it individually
//!   ([`verify_approval_ballot_packages_batch_v1`]).
//! * **Serial, canonical:** "given all previous accepted/rejected ballots, does
//!   this ballot become authoritative?" Applied by the caller
//!   ([`crate::session::GuiElectionSessionV1`]) sequentially in canonical
//!   package order. Nullifier insertion, first-valid-wins, duplicate rejection,
//!   transcript sequencing, and tally are never parallelized.
//!
//! Completion order therefore cannot change the authoritative session: results
//! are indexed by package position and applied in that order regardless of which
//! worker finished first, or how many workers ran.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ProtocolError};
use tari_cc_private_ballot_verifier::{
    VerifiedApprovalBallotV1, verify_approval_ballot_packages_batch_v1,
};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::{GuiCoreError, GuiErrorCategory};

/// Default number of proofs verified together in one shared multiscalar batch.
///
/// Batching is the primary single-threaded lever (the Slice 4A audit measured
/// ~2.4–4× amortization, improving with ring size). A moderate size keeps the
/// per-batch memory small, isolates failures to a small group (full-blame is
/// linear in batch size), and preserves enough batches for the worker pool to
/// load-balance over.
pub const DEFAULT_HISTORICAL_REPLAY_BATCH_SIZE_V1: usize = 16;

/// Below this stored-package count, reconstruction stays fully serial.
///
/// Small elections replay in well under a second; the thread/batch machinery
/// would only add overhead, so the legacy serial path is used unchanged.
pub const DEFAULT_HISTORICAL_REPLAY_PARALLEL_THRESHOLD_V1: usize = 24;

/// Absolute ceiling on worker threads for one reconstruction, independent of the
/// machine's core count. Prevents a many-core host from launching absurd
/// parallelism for a modest election and bounds peak memory (each worker holds
/// one batch of proofs/transcripts plus a shared read-only context).
pub const HISTORICAL_REPLAY_HARD_WORKER_CAP_V1: usize = 8;

/// Configuration for one historical reconstruction.
///
/// The production default (`worker_count: None`) applies the bounded policy and
/// draws workers from a process-global CPU budget so concurrent reconstructions
/// cannot oversubscribe the machine. Tests and benchmarks may force an exact
/// worker count and batch size.
#[derive(Debug, Clone, Copy)]
pub struct HistoricalReplayConfigV1 {
    /// `None` = bounded policy within the global CPU budget (production).
    /// `Some(n)` = force exactly `min(n, batch_count)` workers, bypassing the
    /// global budget (deterministic tests and benchmarks only).
    pub worker_count: Option<usize>,
    /// Proofs per shared verification batch (clamped to at least 1).
    pub batch_size: usize,
    /// Stored-package count at or above which the parallel path engages.
    pub parallel_threshold: usize,
}

impl Default for HistoricalReplayConfigV1 {
    fn default() -> Self {
        Self {
            worker_count: None,
            batch_size: DEFAULT_HISTORICAL_REPLAY_BATCH_SIZE_V1,
            parallel_threshold: DEFAULT_HISTORICAL_REPLAY_PARALLEL_THRESHOLD_V1,
        }
    }
}

impl HistoricalReplayConfigV1 {
    /// Whether the parallel path should engage for `package_count` packages.
    #[must_use]
    pub fn uses_parallel_path(&self, package_count: usize) -> bool {
        package_count >= self.parallel_threshold.max(1) && self.effective_worker_hint() != 1
    }

    /// A quick hint for whether a single worker was explicitly requested (which
    /// is equivalent to the serial path).
    fn effective_worker_hint(&self) -> usize {
        match self.worker_count {
            Some(count) => count.max(1),
            None => 2,
        }
    }
}

/// Verifies the cryptographic validity of every package, returning one result
/// per package in canonical package order.
///
/// The returned inner `Result` is the exact per-package verification outcome
/// (identical to individual ingestion up to, but excluding, ledger acceptance).
/// The outer `Result` fails closed on an executor/infrastructure fault so no
/// partially verified state is ever trusted.
pub(crate) fn parallel_verify_packages(
    packages: &[Vec<u8>],
    artifacts: &GuiElectionArtifactsV1,
    verifier: &tari_cc_private_ballot_crypto::TariTriptychPrototypeVerifierV1,
    config: &HistoricalReplayConfigV1,
) -> Result<Vec<Result<VerifiedApprovalBallotV1, ProtocolError>>, GuiCoreError> {
    let manifest = artifacts.manifest();
    let candidates = artifacts.candidates();
    let provider = Blake3HashProviderV1;
    let batch_size = config.batch_size.max(1);

    let batches = batch_ranges(packages.len(), batch_size);
    if batches.is_empty() {
        return Ok(Vec::new());
    }

    let (workers, _permit) = resolve_workers(batches.len(), config);
    crate::instrumentation::record_historical_crypto_workers_used(workers as u64);

    let verify_batch =
        |batch_index: usize| -> Vec<Result<VerifiedApprovalBallotV1, ProtocolError>> {
            let Some(&(start, end)) = batches.get(batch_index) else {
                return Vec::new();
            };
            let slice: Vec<&[u8]> = packages[start..end].iter().map(Vec::as_slice).collect();
            verify_approval_ballot_packages_batch_v1(
                &slice, manifest, candidates, &provider, verifier,
            )
        };

    let per_batch = run_bounded(batches.len(), workers, &verify_batch)?;

    let mut flat = Vec::with_capacity(packages.len());
    for batch_results in per_batch {
        flat.extend(batch_results);
    }
    Ok(flat)
}

/// Splits `0..package_count` into contiguous `[start, end)` batch ranges.
fn batch_ranges(package_count: usize, batch_size: usize) -> Vec<(usize, usize)> {
    let batch_size = batch_size.max(1);
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < package_count {
        let end = start.saturating_add(batch_size).min(package_count);
        ranges.push((start, end));
        start = end;
    }
    ranges
}

/// Resolves the worker count and (for the production policy) acquires a
/// transient share of the global CPU budget.
///
/// Forced mode (`Some(n)`, tests/benchmarks) uses exactly `min(n, batch_count)`
/// workers and holds no global permit. Policy mode caps the desire at the
/// hard cap and draws work-conserving permits from the global budget so two
/// concurrent reconstructions together never exceed the machine's crypto CPU
/// budget.
fn resolve_workers(
    batch_count: usize,
    config: &HistoricalReplayConfigV1,
) -> (usize, Option<HistoricalCryptoPermitV1<'_>>) {
    match config.worker_count {
        Some(forced) => (forced.max(1).min(batch_count.max(1)), None),
        None => {
            let desired = batch_count.clamp(1, HISTORICAL_REPLAY_HARD_WORKER_CAP_V1);
            let permit = global_crypto_budget().acquire_up_to(desired);
            let workers = permit.count().min(batch_count.max(1)).max(1);
            (workers, Some(permit))
        }
    }
}

/// Runs `work(0..unit_count)` across at most `workers` bounded scoped threads and
/// returns the results indexed by unit. Completion order does not affect the
/// returned ordering: each unit's result is stored at its own index.
fn run_bounded<T, F>(unit_count: usize, workers: usize, work: &F) -> Result<Vec<T>, GuiCoreError>
where
    F: Fn(usize) -> T + Sync,
    T: Send,
{
    let slots: Vec<Mutex<Option<T>>> = (0..unit_count).map(|_| Mutex::new(None)).collect();
    let workers = workers.max(1).min(unit_count.max(1));

    if workers <= 1 {
        // Single worker: run inline on the calling thread. This is the exact
        // path that reproduces legacy serial verification order.
        for index in 0..unit_count {
            store_slot(&slots, index, work(index))?;
        }
    } else {
        let cursor = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let index = cursor.fetch_add(1, Ordering::Relaxed);
                        if index >= unit_count {
                            break;
                        }
                        // A store failure here means a poisoned slot mutex; the
                        // final collection below turns that into a fail-closed
                        // reconstruction error.
                        let _ = store_slot(&slots, index, work(index));
                    }
                });
            }
        });
    }

    let mut results = Vec::with_capacity(unit_count);
    for slot in slots {
        let value = slot
            .into_inner()
            .map_err(|_| executor_unavailable())?
            .ok_or_else(executor_unavailable)?;
        results.push(value);
    }
    Ok(results)
}

fn store_slot<T>(slots: &[Mutex<Option<T>>], index: usize, value: T) -> Result<(), GuiCoreError> {
    let Some(slot) = slots.get(index) else {
        return Err(executor_unavailable());
    };
    let mut guard = slot.lock().map_err(|_| executor_unavailable())?;
    *guard = Some(value);
    Ok(())
}

/// Process-global bound on concurrent historical-crypto worker threads.
///
/// Sized to `max(1, available_parallelism - 1)` so at least one logical CPU is
/// reserved for the GUI/event loop. Every production reconstruction draws its
/// workers from here, so even when the verified-session cache permits two
/// elections to reconstruct at once they share this single budget and cannot
/// oversubscribe the machine.
struct GlobalCryptoBudgetV1 {
    available: Mutex<usize>,
    released: Condvar,
    total: usize,
}

static GLOBAL_CRYPTO_BUDGET: OnceLock<GlobalCryptoBudgetV1> = OnceLock::new();

fn global_crypto_budget() -> &'static GlobalCryptoBudgetV1 {
    GLOBAL_CRYPTO_BUDGET.get_or_init(|| {
        let total = std::thread::available_parallelism()
            .map(|count| count.get().saturating_sub(1).max(1))
            .unwrap_or(1);
        GlobalCryptoBudgetV1 {
            available: Mutex::new(total),
            released: Condvar::new(),
            total,
        }
    })
}

/// The configured global crypto worker budget for this process.
#[must_use]
pub fn global_crypto_worker_budget_v1() -> usize {
    global_crypto_budget().total
}

impl GlobalCryptoBudgetV1 {
    /// Grants at least one and up to `desired` permits, blocking only until at
    /// least one is free. Work-conserving and deadlock-free: every grant is
    /// released after a bounded amount of verification, and acquisition never
    /// requires more than one permit to make progress.
    fn acquire_up_to(&self, desired: usize) -> HistoricalCryptoPermitV1<'_> {
        let desired = desired.max(1);
        let Ok(mut available) = self.available.lock() else {
            // Poisoned budget: fall back to a single inline worker rather than
            // block reconstruction. Correctness is unaffected (serial verify).
            return HistoricalCryptoPermitV1 {
                budget: self,
                granted: 0,
            };
        };
        while *available == 0 {
            match self.released.wait(available) {
                Ok(next) => available = next,
                Err(_) => {
                    return HistoricalCryptoPermitV1 {
                        budget: self,
                        granted: 0,
                    };
                }
            }
        }
        let granted = desired.min(*available);
        *available -= granted;
        HistoricalCryptoPermitV1 {
            budget: self,
            granted,
        }
    }

    fn release(&self, count: usize) {
        if count == 0 {
            return;
        }
        if let Ok(mut available) = self.available.lock() {
            *available = available.saturating_add(count).min(self.total);
            self.released.notify_all();
        }
    }
}

/// RAII guard for a transient share of the global crypto budget.
struct HistoricalCryptoPermitV1<'a> {
    budget: &'a GlobalCryptoBudgetV1,
    granted: usize,
}

impl HistoricalCryptoPermitV1<'_> {
    /// The number of worker threads this permit authorizes. Always at least 1
    /// (a permit of zero still runs one inline worker).
    fn count(&self) -> usize {
        self.granted.max(1)
    }
}

impl Drop for HistoricalCryptoPermitV1<'_> {
    fn drop(&mut self) {
        self.budget.release(self.granted);
    }
}

fn executor_unavailable() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_HISTORICAL_REPLAY_EXECUTOR_UNAVAILABLE",
        GuiErrorCategory::Unavailable,
        Some("historical-replay"),
        "the bounded historical-verification executor failed; reconstruction fails closed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_ranges_partitions_contiguously_and_covers_every_index() {
        assert_eq!(batch_ranges(0, 4), Vec::new());
        assert_eq!(batch_ranges(4, 4), vec![(0, 4)]);
        assert_eq!(batch_ranges(5, 2), vec![(0, 2), (2, 4), (4, 5)]);
        assert_eq!(batch_ranges(3, 16), vec![(0, 3)]);
    }

    #[test]
    fn run_bounded_preserves_index_order_regardless_of_worker_count() {
        for workers in [1_usize, 2, 3, 8] {
            let square = |index: usize| index * index;
            let Ok(results) = run_bounded(64, workers, &square) else {
                panic!("bounded run must succeed for {workers} workers");
            };
            let expected: Vec<usize> = (0..64).map(|index| index * index).collect();
            assert_eq!(results, expected, "worker count {workers} must not reorder");
        }
    }

    #[test]
    fn forced_worker_count_is_bounded_by_batch_count() {
        let config = HistoricalReplayConfigV1 {
            worker_count: Some(16),
            batch_size: 4,
            parallel_threshold: 0,
        };
        let (workers, permit) = resolve_workers(3, &config);
        assert_eq!(workers, 3, "workers never exceed the number of batches");
        assert!(permit.is_none(), "forced mode holds no global permit");
    }

    #[test]
    fn policy_worker_count_never_exceeds_the_global_budget() {
        let config = HistoricalReplayConfigV1 {
            worker_count: None,
            batch_size: 1,
            parallel_threshold: 0,
        };
        let (workers, permit) = resolve_workers(1024, &config);
        assert!(
            workers <= global_crypto_worker_budget_v1(),
            "policy workers stay within the reserved CPU budget",
        );
        assert!(workers >= 1);
        assert!(permit.is_some(), "policy mode holds a global permit");
        drop(permit);
    }
}
