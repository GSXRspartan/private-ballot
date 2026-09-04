//! Aggregate-only archive-verification counters (Slice 4D).
//!
//! # Privacy contract (mandatory)
//!
//! These counters record **numbers only**. They never observe, store, or expose
//! archive paths, hashes, ballot packages, proofs, nullifiers, voter data, or
//! any identifier. They exist so a test can prove that reusing an unchanged
//! archive in the same process performs zero repeated historical Triptych proof
//! replay, while the mandatory current-content catalog revalidation still runs.
//!
//! # No protocol effect
//!
//! Incrementing a relaxed atomic changes no verification decision, ordering, or
//! output. `reset()` only zeroes the dev counters and is intended for test
//! setup.

use core::sync::atomic::{AtomicU64, Ordering};

static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static FULL_VERIFICATION_COUNT: AtomicU64 = AtomicU64::new(0);
static CATALOG_REVALIDATIONS: AtomicU64 = AtomicU64::new(0);
static HISTORICAL_REPLAY_COUNT: AtomicU64 = AtomicU64::new(0);
static HISTORICAL_TRIPTYCH_VERIFIES: AtomicU64 = AtomicU64::new(0);
static CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static CACHE_IDENTITY_DRIFT: AtomicU64 = AtomicU64::new(0);
static SINGLE_FLIGHT_WAITS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) fn record_cache_hit() {
    CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_cache_miss() {
    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_full_verification() {
    FULL_VERIFICATION_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Records one complete current-content catalog revalidation (a full
/// bounded-read + per-file digest recomputation of every catalog file). This
/// runs on every memo request, including a hit.
#[inline]
pub(crate) fn record_catalog_revalidation() {
    CATALOG_REVALIDATIONS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_historical_replay() {
    HISTORICAL_REPLAY_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_historical_triptych_verifies(count: u64) {
    HISTORICAL_TRIPTYCH_VERIFIES.fetch_add(count, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_cache_eviction() {
    CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_cache_identity_drift() {
    CACHE_IDENTITY_DRIFT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_single_flight_wait() {
    SINGLE_FLIGHT_WAITS.fetch_add(1, Ordering::Relaxed);
}

/// Aggregate snapshot of the Slice 4D archive-verification counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArchiveVerificationCountersSnapshotV1 {
    pub archive_verification_cache_hits: u64,
    pub archive_verification_cache_misses: u64,
    pub archive_full_verification_count: u64,
    pub archive_catalog_revalidations: u64,
    pub archive_historical_replay_count: u64,
    pub archive_historical_triptych_verifies: u64,
    pub archive_cache_evictions: u64,
    pub archive_cache_identity_drift: u64,
    pub archive_single_flight_waits: u64,
}

/// Returns a copy of every archive-verification counter. Diagnostic use only.
#[must_use]
pub fn archive_verification_snapshot() -> ArchiveVerificationCountersSnapshotV1 {
    ArchiveVerificationCountersSnapshotV1 {
        archive_verification_cache_hits: CACHE_HITS.load(Ordering::Relaxed),
        archive_verification_cache_misses: CACHE_MISSES.load(Ordering::Relaxed),
        archive_full_verification_count: FULL_VERIFICATION_COUNT.load(Ordering::Relaxed),
        archive_catalog_revalidations: CATALOG_REVALIDATIONS.load(Ordering::Relaxed),
        archive_historical_replay_count: HISTORICAL_REPLAY_COUNT.load(Ordering::Relaxed),
        archive_historical_triptych_verifies: HISTORICAL_TRIPTYCH_VERIFIES.load(Ordering::Relaxed),
        archive_cache_evictions: CACHE_EVICTIONS.load(Ordering::Relaxed),
        archive_cache_identity_drift: CACHE_IDENTITY_DRIFT.load(Ordering::Relaxed),
        archive_single_flight_waits: SINGLE_FLIGHT_WAITS.load(Ordering::Relaxed),
    }
}

/// Zeroes every archive-verification counter. Test setup only; no protocol effect.
pub fn reset_archive_verification_counters() {
    CACHE_HITS.store(0, Ordering::Relaxed);
    CACHE_MISSES.store(0, Ordering::Relaxed);
    FULL_VERIFICATION_COUNT.store(0, Ordering::Relaxed);
    CATALOG_REVALIDATIONS.store(0, Ordering::Relaxed);
    HISTORICAL_REPLAY_COUNT.store(0, Ordering::Relaxed);
    HISTORICAL_TRIPTYCH_VERIFIES.store(0, Ordering::Relaxed);
    CACHE_EVICTIONS.store(0, Ordering::Relaxed);
    CACHE_IDENTITY_DRIFT.store(0, Ordering::Relaxed);
    SINGLE_FLIGHT_WAITS.store(0, Ordering::Relaxed);
}
