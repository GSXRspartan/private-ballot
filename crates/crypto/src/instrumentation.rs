//! Dev/test-only observational counter for Triptych verification invocations.
//!
//! This counts calls to the application's own Triptych verifier adapter
//! ([`crate::TariTriptychPrototypeVerifierV1::verify`]) so a test can prove that
//! a code path (e.g. workspace listing) performs ZERO proof verification, even
//! if some future caller bypassed the higher-level session pipeline and invoked
//! the verifier directly.
//!
//! # Privacy and scope
//!
//! It records a single aggregate count of invocations and NOTHING else — no
//! proof bytes, statement, ring members, linking tag/nullifier, registry keys,
//! or any voter-linkable material. It does not touch the vendored
//! `third_party/tari-triptych` cryptography or curve25519-dalek; the increment
//! lives only in this crate's adapter. A relaxed atomic add changes no
//! verification decision, so there is no protocol effect. `reset()` only zeroes
//! the dev counter and is intended for test setup.

use core::sync::atomic::{AtomicU64, Ordering};

static VERIFY_INVOCATIONS: AtomicU64 = AtomicU64::new(0);

// Slice 4B batched-verification counters (aggregate numbers only; no proof,
// ring, nullifier, or voter material). They make the batching/context-reuse
// behavior falsifiable from a test without exposing any sensitive value.
static HISTORICAL_CRYPTO_BATCHES: AtomicU64 = AtomicU64::new(0);
static HISTORICAL_CRYPTO_PROOFS: AtomicU64 = AtomicU64::new(0);
static HISTORICAL_CRYPTO_BATCH_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static HISTORICAL_CRYPTO_INDIVIDUAL_FALLBACK_VERIFIES: AtomicU64 = AtomicU64::new(0);
static VERIFIER_CONTEXT_BUILDS: AtomicU64 = AtomicU64::new(0);
static VERIFIER_CONTEXT_REUSES: AtomicU64 = AtomicU64::new(0);
static BATCH_VERIFY_MICROS_TOTAL: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) fn record_verify_invocation() {
    VERIFY_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_historical_crypto_batch() {
    HISTORICAL_CRYPTO_BATCHES.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_historical_crypto_proofs(count: u64) {
    HISTORICAL_CRYPTO_PROOFS.fetch_add(count, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_historical_crypto_batch_fallback() {
    HISTORICAL_CRYPTO_BATCH_FALLBACKS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_historical_crypto_individual_fallback_verifies(count: u64) {
    HISTORICAL_CRYPTO_INDIVIDUAL_FALLBACK_VERIFIES.fetch_add(count, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_verifier_context_build() {
    VERIFIER_CONTEXT_BUILDS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_verifier_context_reuse() {
    VERIFIER_CONTEXT_REUSES.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_batch_verify_micros(micros: u64) {
    BATCH_VERIFY_MICROS_TOTAL.fetch_add(micros, Ordering::Relaxed);
}

/// Aggregate snapshot of the Slice 4B batched-verification counters.
///
/// Plain `u64`s so a test can compute deltas across one reconstruction. Carries
/// no ballot, proof, ring, nullifier, or voter-linkable material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchVerificationCountersSnapshotV1 {
    pub historical_crypto_batches: u64,
    pub historical_crypto_proofs: u64,
    pub historical_crypto_batch_fallbacks: u64,
    pub historical_crypto_individual_fallback_verifies: u64,
    pub verifier_context_build_count: u64,
    pub verifier_context_reuse_count: u64,
    pub batch_verify_micros_total: u64,
}

/// Returns a copy of the batched-verification counters. Diagnostic use only.
#[must_use]
pub fn batch_verification_snapshot() -> BatchVerificationCountersSnapshotV1 {
    BatchVerificationCountersSnapshotV1 {
        historical_crypto_batches: HISTORICAL_CRYPTO_BATCHES.load(Ordering::Relaxed),
        historical_crypto_proofs: HISTORICAL_CRYPTO_PROOFS.load(Ordering::Relaxed),
        historical_crypto_batch_fallbacks: HISTORICAL_CRYPTO_BATCH_FALLBACKS
            .load(Ordering::Relaxed),
        historical_crypto_individual_fallback_verifies:
            HISTORICAL_CRYPTO_INDIVIDUAL_FALLBACK_VERIFIES.load(Ordering::Relaxed),
        verifier_context_build_count: VERIFIER_CONTEXT_BUILDS.load(Ordering::Relaxed),
        verifier_context_reuse_count: VERIFIER_CONTEXT_REUSES.load(Ordering::Relaxed),
        batch_verify_micros_total: BATCH_VERIFY_MICROS_TOTAL.load(Ordering::Relaxed),
    }
}

/// Returns the number of Triptych verifier-adapter invocations since the last
/// reset (or process start). Development/diagnostic use.
#[must_use]
pub fn verify_invocation_count() -> u64 {
    VERIFY_INVOCATIONS.load(Ordering::Relaxed)
}

/// Zeroes the invocation counter. Intended for test setup; no protocol effect.
pub fn reset_verify_invocation_count() {
    VERIFY_INVOCATIONS.store(0, Ordering::Relaxed);
    HISTORICAL_CRYPTO_BATCHES.store(0, Ordering::Relaxed);
    HISTORICAL_CRYPTO_PROOFS.store(0, Ordering::Relaxed);
    HISTORICAL_CRYPTO_BATCH_FALLBACKS.store(0, Ordering::Relaxed);
    HISTORICAL_CRYPTO_INDIVIDUAL_FALLBACK_VERIFIES.store(0, Ordering::Relaxed);
    VERIFIER_CONTEXT_BUILDS.store(0, Ordering::Relaxed);
    VERIFIER_CONTEXT_REUSES.store(0, Ordering::Relaxed);
    BATCH_VERIFY_MICROS_TOTAL.store(0, Ordering::Relaxed);
}
