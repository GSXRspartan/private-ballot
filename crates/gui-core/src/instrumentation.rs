//! Development/test-oriented reconstruction and verification counters.
//!
//! This module exists to make the performance-remediation work in this crate
//! *falsifiable*: a test can assert that listing N workspaces performs ZERO
//! historical ballot replays, or that opening an election performs exactly the
//! required number of proof verifications. It records only aggregate counts and
//! elapsed-time totals.
//!
//! # Privacy contract (mandatory)
//!
//! These counters record **numbers only**. They never observe, store, or
//! expose ballot contents, voter secrets, private keys, proof bytes, nullifier
//! or linkability material, credentials, manifest hashes, workspace ids, or
//! file paths. A per-workspace breakdown is deliberately NOT provided, because
//! cross-election counts could leak correlation; only process-wide aggregates
//! are kept.
//!
//! # No protocol effect
//!
//! Incrementing a relaxed atomic changes no decision, ordering, or output. The
//! counters are always compiled (so integration tests can read them through the
//! public API) but nothing in the production decision path branches on them.
//! `reset()` only zeroes the dev counters and is intended for test setup.

use core::sync::atomic::{AtomicU64, Ordering};

/// Process-wide reconstruction/verification counters.
///
/// All fields are monotonic counters or elapsed-microsecond totals unless the
/// name says otherwise. `Relaxed` ordering is sufficient: these values carry no
/// happens-before obligation for any protocol decision.
#[derive(Debug)]
pub struct ReconstructionCountersV1 {
    /// Calls to `list_election_workspaces_v1` (a whole discovery pass).
    workspace_list_calls: AtomicU64,
    /// Calls to the per-workspace summariser (metadata-only after Slice 1).
    workspace_summarize_calls: AtomicU64,
    /// Calls to `GuiElectionSessionV1::from_durable_snapshot` (a full durable
    /// session reconstruction that replays every stored package through proof
    /// verification).
    from_durable_snapshot_calls: AtomicU64,
    /// Historical ballot packages replayed by durable reconstruction. One unit
    /// here is one package fed back through the full intake/verify pipeline.
    historical_ballots_replayed: AtomicU64,
    /// Calls to the gui-core intake pipeline (`process_intake_package`). Each
    /// call performs exactly one approval-proof verification, which performs
    /// exactly one Triptych `verify` (a batch of one), so this is the
    /// authoritative count of Triptych verifier invocations reachable from
    /// gui-core intake and durable replay.
    triptych_verify_calls: AtomicU64,
    /// Total time spent inside `from_durable_snapshot`, in microseconds.
    reconstruction_micros_total: AtomicU64,
    /// Total time spent inside the intake/verify pipeline, in microseconds.
    proof_verification_micros_total: AtomicU64,
    /// Verified-session cache lookup and outcome counters (aggregate only).
    verified_session_cache_lookups: AtomicU64,
    verified_session_cache_hits: AtomicU64,
    verified_session_cache_misses: AtomicU64,
    verified_session_cache_insertions: AtomicU64,
    verified_session_cache_evictions: AtomicU64,
    verified_session_cache_invalidations: AtomicU64,
    verified_session_single_flight_owners: AtomicU64,
    verified_session_single_flight_waiters: AtomicU64,
    verified_session_single_flight_failures: AtomicU64,
    /// Durable-append fast-path (Slice 3B) counters. Aggregate numbers only.
    ///
    /// A durable append either takes the process-local validated-head FAST path
    /// (skips re-reading revisions behind the confirmed head) or the FULL
    /// `load_committed_history` walk. `revision_files_read_on_append` is the
    /// cumulative count of prior revision files opened+read while choosing the
    /// append head: the full walk adds one per committed revision, the fast path
    /// adds exactly one (the head), genesis adds zero. It is the falsifiable
    /// signal that a warm append does not re-read the whole chain.
    workspace_append_calls: AtomicU64,
    workspace_append_fast_path_hits: AtomicU64,
    workspace_append_full_history_validations: AtomicU64,
    workspace_append_revision_files_read: AtomicU64,
    workspace_append_trusted_head_invalidations: AtomicU64,
    workspace_append_identity_drift: AtomicU64,
    workspace_append_lock_contention: AtomicU64,
    /// Slice 4B bounded-multicore historical-verification counters (aggregate
    /// numbers only). A reconstruction takes either the bounded PARALLEL path
    /// (crypto validity computed across workers, then applied serially in
    /// canonical order) or, for small elections, the serial path.
    /// `historical_serial_order_apply` counts packages whose validity was
    /// applied to the authoritative session in canonical order (the ordered
    /// phase runs for every parallel reconstruction). `historical_crypto_workers_used`
    /// is a gauge of the most recent parallel worker count.
    historical_parallel_reconstruction_count: AtomicU64,
    historical_serial_order_apply_count: AtomicU64,
    historical_crypto_workers_used: AtomicU64,
    parallel_crypto_micros_total: AtomicU64,
    ordered_apply_micros_total: AtomicU64,
    /// Slice 4C private-intake acceleration counters. The transcript remains
    /// authoritative; these record only aggregate lookup/file operation counts.
    private_intake_digest_index_hits: AtomicU64,
    private_intake_digest_index_misses: AtomicU64,
    private_intake_linear_transcript_scans: AtomicU64,
    private_inbox_files_read: AtomicU64,
    private_inbox_files_hashed: AtomicU64,
    private_inbox_files_skipped_unchanged: AtomicU64,
    /// Slice 4E incremental verified-session advancement counters. An advance
    /// installs the already-verified post-mutation session under the newly
    /// committed durable head identity instead of invalidating and later
    /// replaying history. `advances` counts confirmed advances;
    /// `advance_identity_drift` counts advances refused because the re-read
    /// committed head did not match the expected new head; `advance_fallback_replays`
    /// counts every fall-back to plain invalidation (drift, unsupported, or error).
    verified_session_cache_advances: AtomicU64,
    verified_session_cache_advance_failures: AtomicU64,
    verified_session_cache_advance_identity_drift: AtomicU64,
    verified_session_cache_advance_unsupported_mutation: AtomicU64,
    verified_session_cache_advance_fallback_replays: AtomicU64,
    /// Slice 4F warm durable-head body cache counters. The head revision file is
    /// still READ and re-HASHED on every warm append (the Slice 3B tamper check),
    /// so `disk_reads` is not reduced; the cache eliminates the repeated CBOR
    /// DECODE of an unchanged head, so `decodes` drops on a cache hit.
    /// `durable_head_body_cache_bytes` is a gauge of currently cached bytes.
    durable_head_body_cache_hits: AtomicU64,
    durable_head_body_cache_misses: AtomicU64,
    durable_head_body_cache_bytes: AtomicU64,
    durable_head_body_cache_evictions: AtomicU64,
    durable_head_body_identity_drift: AtomicU64,
    durable_head_body_disk_reads: AtomicU64,
    durable_head_body_decodes: AtomicU64,
}

impl ReconstructionCountersV1 {
    const fn new() -> Self {
        Self {
            workspace_list_calls: AtomicU64::new(0),
            workspace_summarize_calls: AtomicU64::new(0),
            from_durable_snapshot_calls: AtomicU64::new(0),
            historical_ballots_replayed: AtomicU64::new(0),
            triptych_verify_calls: AtomicU64::new(0),
            reconstruction_micros_total: AtomicU64::new(0),
            proof_verification_micros_total: AtomicU64::new(0),
            verified_session_cache_lookups: AtomicU64::new(0),
            verified_session_cache_hits: AtomicU64::new(0),
            verified_session_cache_misses: AtomicU64::new(0),
            verified_session_cache_insertions: AtomicU64::new(0),
            verified_session_cache_evictions: AtomicU64::new(0),
            verified_session_cache_invalidations: AtomicU64::new(0),
            verified_session_single_flight_owners: AtomicU64::new(0),
            verified_session_single_flight_waiters: AtomicU64::new(0),
            verified_session_single_flight_failures: AtomicU64::new(0),
            workspace_append_calls: AtomicU64::new(0),
            workspace_append_fast_path_hits: AtomicU64::new(0),
            workspace_append_full_history_validations: AtomicU64::new(0),
            workspace_append_revision_files_read: AtomicU64::new(0),
            workspace_append_trusted_head_invalidations: AtomicU64::new(0),
            workspace_append_identity_drift: AtomicU64::new(0),
            workspace_append_lock_contention: AtomicU64::new(0),
            historical_parallel_reconstruction_count: AtomicU64::new(0),
            historical_serial_order_apply_count: AtomicU64::new(0),
            historical_crypto_workers_used: AtomicU64::new(0),
            parallel_crypto_micros_total: AtomicU64::new(0),
            ordered_apply_micros_total: AtomicU64::new(0),
            private_intake_digest_index_hits: AtomicU64::new(0),
            private_intake_digest_index_misses: AtomicU64::new(0),
            private_intake_linear_transcript_scans: AtomicU64::new(0),
            private_inbox_files_read: AtomicU64::new(0),
            private_inbox_files_hashed: AtomicU64::new(0),
            private_inbox_files_skipped_unchanged: AtomicU64::new(0),
            verified_session_cache_advances: AtomicU64::new(0),
            verified_session_cache_advance_failures: AtomicU64::new(0),
            verified_session_cache_advance_identity_drift: AtomicU64::new(0),
            verified_session_cache_advance_unsupported_mutation: AtomicU64::new(0),
            verified_session_cache_advance_fallback_replays: AtomicU64::new(0),
            durable_head_body_cache_hits: AtomicU64::new(0),
            durable_head_body_cache_misses: AtomicU64::new(0),
            durable_head_body_cache_bytes: AtomicU64::new(0),
            durable_head_body_cache_evictions: AtomicU64::new(0),
            durable_head_body_identity_drift: AtomicU64::new(0),
            durable_head_body_disk_reads: AtomicU64::new(0),
            durable_head_body_decodes: AtomicU64::new(0),
        }
    }
}

static COUNTERS: ReconstructionCountersV1 = ReconstructionCountersV1::new();

/// A point-in-time copy of every counter, safe to serialize and compare.
///
/// Plain `u64`s so tests can compute deltas across a single operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct ReconstructionCountersSnapshotV1 {
    pub workspace_list_calls: u64,
    pub workspace_summarize_calls: u64,
    pub from_durable_snapshot_calls: u64,
    pub historical_ballots_replayed: u64,
    /// Gui-core intake-pipeline entries (`process_intake_package`). Each entry
    /// performs exactly one approval-proof verification.
    pub triptych_verify_calls: u64,
    /// Invocations counted at the crypto Triptych verifier ADAPTER boundary
    /// (`TariTriptychPrototypeVerifierV1::verify`). This is independent of the
    /// gui-core session path: it catches ANY verifier call, including one that
    /// bypassed the session pipeline. For valid ballots the two counts agree.
    pub triptych_adapter_verify_calls: u64,
    pub reconstruction_micros_total: u64,
    pub proof_verification_micros_total: u64,
    pub verified_session_cache_lookups: u64,
    pub verified_session_cache_hits: u64,
    pub verified_session_cache_misses: u64,
    pub verified_session_cache_insertions: u64,
    pub verified_session_cache_evictions: u64,
    pub verified_session_cache_invalidations: u64,
    pub verified_session_single_flight_owners: u64,
    pub verified_session_single_flight_waiters: u64,
    pub verified_session_single_flight_failures: u64,
    /// Durable-append fast-path (Slice 3B) aggregates.
    pub workspace_append_calls: u64,
    pub workspace_append_fast_path_hits: u64,
    pub workspace_append_full_history_validations: u64,
    pub workspace_append_revision_files_read: u64,
    pub workspace_append_trusted_head_invalidations: u64,
    pub workspace_append_identity_drift: u64,
    pub workspace_append_lock_contention: u64,
    /// Slice 4B bounded-multicore historical-verification aggregates.
    pub historical_parallel_reconstruction_count: u64,
    pub historical_serial_order_apply_count: u64,
    pub historical_crypto_workers_used: u64,
    pub parallel_crypto_micros_total: u64,
    pub ordered_apply_micros_total: u64,
    /// Batched-verification counters read from the crypto crate's own boundary
    /// so a single snapshot cross-checks the whole reconstruction pipeline.
    pub historical_crypto_batches: u64,
    pub historical_crypto_proofs: u64,
    pub historical_crypto_batch_fallbacks: u64,
    pub historical_crypto_individual_fallback_verifies: u64,
    pub verifier_context_build_count: u64,
    pub verifier_context_reuse_count: u64,
    pub batch_verify_micros_total: u64,
    /// Slice 4C private-intake acceleration counters.
    pub private_intake_digest_index_hits: u64,
    pub private_intake_digest_index_misses: u64,
    pub private_intake_linear_transcript_scans: u64,
    pub private_inbox_files_read: u64,
    pub private_inbox_files_hashed: u64,
    pub private_inbox_files_skipped_unchanged: u64,
    /// Slice 4E incremental verified-session advancement aggregates.
    pub verified_session_cache_advances: u64,
    pub verified_session_cache_advance_failures: u64,
    pub verified_session_cache_advance_identity_drift: u64,
    pub verified_session_cache_advance_unsupported_mutation: u64,
    pub verified_session_cache_advance_fallback_replays: u64,
    /// Slice 4F warm durable-head body cache aggregates.
    pub durable_head_body_cache_hits: u64,
    pub durable_head_body_cache_misses: u64,
    pub durable_head_body_cache_bytes: u64,
    pub durable_head_body_cache_evictions: u64,
    pub durable_head_body_identity_drift: u64,
    pub durable_head_body_disk_reads: u64,
    pub durable_head_body_decodes: u64,
}

#[inline]
pub(crate) fn record_workspace_list_call() {
    COUNTERS
        .workspace_list_calls
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_workspace_summarize_call() {
    COUNTERS
        .workspace_summarize_calls
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_from_durable_snapshot_call() {
    COUNTERS
        .from_durable_snapshot_calls
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_historical_ballot_replayed() {
    COUNTERS
        .historical_ballots_replayed
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_triptych_verify_call() {
    COUNTERS
        .triptych_verify_calls
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_reconstruction_micros(micros: u64) {
    COUNTERS
        .reconstruction_micros_total
        .fetch_add(micros, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_proof_verification_micros(micros: u64) {
    COUNTERS
        .proof_verification_micros_total
        .fetch_add(micros, Ordering::Relaxed);
}

macro_rules! cache_counter {
    ($name:ident, $field:ident) => {
        #[inline]
        pub(crate) fn $name() {
            COUNTERS.$field.fetch_add(1, Ordering::Relaxed);
        }
    };
}

cache_counter!(
    record_verified_session_cache_lookup,
    verified_session_cache_lookups
);
cache_counter!(
    record_verified_session_cache_hit,
    verified_session_cache_hits
);
cache_counter!(
    record_verified_session_cache_miss,
    verified_session_cache_misses
);
cache_counter!(
    record_verified_session_cache_insertion,
    verified_session_cache_insertions
);
cache_counter!(
    record_verified_session_cache_eviction,
    verified_session_cache_evictions
);
cache_counter!(
    record_verified_session_cache_invalidation,
    verified_session_cache_invalidations
);
cache_counter!(
    record_verified_session_single_flight_owner,
    verified_session_single_flight_owners
);
cache_counter!(
    record_verified_session_single_flight_waiter,
    verified_session_single_flight_waiters
);
cache_counter!(
    record_verified_session_single_flight_failure,
    verified_session_single_flight_failures
);
cache_counter!(record_workspace_append_call, workspace_append_calls);
cache_counter!(
    record_workspace_append_fast_path_hit,
    workspace_append_fast_path_hits
);
cache_counter!(
    record_workspace_append_full_history_validation,
    workspace_append_full_history_validations
);
cache_counter!(
    record_workspace_append_trusted_head_invalidation,
    workspace_append_trusted_head_invalidations
);
cache_counter!(
    record_workspace_append_identity_drift,
    workspace_append_identity_drift
);
cache_counter!(
    record_workspace_append_lock_contention,
    workspace_append_lock_contention
);

/// Adds the number of prior revision files read while choosing the append head.
#[inline]
pub(crate) fn add_workspace_append_revision_files_read(count: u64) {
    COUNTERS
        .workspace_append_revision_files_read
        .fetch_add(count, Ordering::Relaxed);
}

#[inline]
pub(crate) fn record_historical_parallel_reconstruction() {
    COUNTERS
        .historical_parallel_reconstruction_count
        .fetch_add(1, Ordering::Relaxed);
}

/// Adds the number of packages applied to the authoritative session in canonical
/// order during one ordered-apply phase.
#[inline]
pub(crate) fn add_historical_serial_order_applies(count: u64) {
    COUNTERS
        .historical_serial_order_apply_count
        .fetch_add(count, Ordering::Relaxed);
}

/// Records the worker count of the most recent parallel reconstruction (gauge).
#[inline]
pub(crate) fn record_historical_crypto_workers_used(count: u64) {
    COUNTERS
        .historical_crypto_workers_used
        .store(count, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_parallel_crypto_micros(micros: u64) {
    COUNTERS
        .parallel_crypto_micros_total
        .fetch_add(micros, Ordering::Relaxed);
}

#[inline]
pub(crate) fn add_ordered_apply_micros(micros: u64) {
    COUNTERS
        .ordered_apply_micros_total
        .fetch_add(micros, Ordering::Relaxed);
}

macro_rules! private_intake_counter {
    ($name:ident, $field:ident) => {
        #[inline]
        pub(crate) fn $name() {
            COUNTERS.$field.fetch_add(1, Ordering::Relaxed);
        }
    };
}

private_intake_counter!(
    record_private_intake_digest_index_hit,
    private_intake_digest_index_hits
);
private_intake_counter!(
    record_private_intake_digest_index_miss,
    private_intake_digest_index_misses
);
private_intake_counter!(record_private_inbox_file_read, private_inbox_files_read);
private_intake_counter!(record_private_inbox_file_hashed, private_inbox_files_hashed);
private_intake_counter!(
    record_private_inbox_file_skipped_unchanged,
    private_inbox_files_skipped_unchanged
);
private_intake_counter!(
    record_verified_session_cache_advance,
    verified_session_cache_advances
);
private_intake_counter!(
    record_verified_session_cache_advance_failure,
    verified_session_cache_advance_failures
);
private_intake_counter!(
    record_verified_session_cache_advance_identity_drift,
    verified_session_cache_advance_identity_drift
);
private_intake_counter!(
    record_verified_session_cache_advance_fallback_replay,
    verified_session_cache_advance_fallback_replays
);

/// Reserved for a future durable mutation class that deliberately opts out of
/// incremental advancement and always falls back to cold reconstruction. No
/// current mutation path is unsupported, so this is not yet incremented; the
/// field is still surfaced in the snapshot for completeness.
#[inline]
#[allow(dead_code)]
pub(crate) fn record_verified_session_cache_advance_unsupported_mutation() {
    COUNTERS
        .verified_session_cache_advance_unsupported_mutation
        .fetch_add(1, Ordering::Relaxed);
}

private_intake_counter!(
    record_durable_head_body_cache_hit,
    durable_head_body_cache_hits
);
private_intake_counter!(
    record_durable_head_body_cache_miss,
    durable_head_body_cache_misses
);
private_intake_counter!(
    record_durable_head_body_cache_eviction,
    durable_head_body_cache_evictions
);
private_intake_counter!(
    record_durable_head_body_identity_drift,
    durable_head_body_identity_drift
);
private_intake_counter!(
    record_durable_head_body_disk_read,
    durable_head_body_disk_reads
);
private_intake_counter!(record_durable_head_body_decode, durable_head_body_decodes);

/// Records the current total bytes held by the warm durable-head body cache
/// (a gauge, not a monotonic counter).
#[inline]
pub(crate) fn set_durable_head_body_cache_bytes(bytes: u64) {
    COUNTERS
        .durable_head_body_cache_bytes
        .store(bytes, Ordering::Relaxed);
}

/// Returns a copy of every counter. Development/diagnostic use.
#[must_use]
pub fn snapshot() -> ReconstructionCountersSnapshotV1 {
    let crypto_batch = tari_cc_private_ballot_crypto::batch_verification_snapshot();
    ReconstructionCountersSnapshotV1 {
        workspace_list_calls: COUNTERS.workspace_list_calls.load(Ordering::Relaxed),
        workspace_summarize_calls: COUNTERS.workspace_summarize_calls.load(Ordering::Relaxed),
        from_durable_snapshot_calls: COUNTERS.from_durable_snapshot_calls.load(Ordering::Relaxed),
        historical_ballots_replayed: COUNTERS.historical_ballots_replayed.load(Ordering::Relaxed),
        triptych_verify_calls: COUNTERS.triptych_verify_calls.load(Ordering::Relaxed),
        // Read the count from the crypto crate's own adapter boundary so a
        // single snapshot cross-checks the gui-core path against the actual
        // verifier calls.
        triptych_adapter_verify_calls: tari_cc_private_ballot_crypto::verify_invocation_count(),
        reconstruction_micros_total: COUNTERS.reconstruction_micros_total.load(Ordering::Relaxed),
        proof_verification_micros_total: COUNTERS
            .proof_verification_micros_total
            .load(Ordering::Relaxed),
        verified_session_cache_lookups: COUNTERS
            .verified_session_cache_lookups
            .load(Ordering::Relaxed),
        verified_session_cache_hits: COUNTERS.verified_session_cache_hits.load(Ordering::Relaxed),
        verified_session_cache_misses: COUNTERS
            .verified_session_cache_misses
            .load(Ordering::Relaxed),
        verified_session_cache_insertions: COUNTERS
            .verified_session_cache_insertions
            .load(Ordering::Relaxed),
        verified_session_cache_evictions: COUNTERS
            .verified_session_cache_evictions
            .load(Ordering::Relaxed),
        verified_session_cache_invalidations: COUNTERS
            .verified_session_cache_invalidations
            .load(Ordering::Relaxed),
        verified_session_single_flight_owners: COUNTERS
            .verified_session_single_flight_owners
            .load(Ordering::Relaxed),
        verified_session_single_flight_waiters: COUNTERS
            .verified_session_single_flight_waiters
            .load(Ordering::Relaxed),
        verified_session_single_flight_failures: COUNTERS
            .verified_session_single_flight_failures
            .load(Ordering::Relaxed),
        workspace_append_calls: COUNTERS.workspace_append_calls.load(Ordering::Relaxed),
        workspace_append_fast_path_hits: COUNTERS
            .workspace_append_fast_path_hits
            .load(Ordering::Relaxed),
        workspace_append_full_history_validations: COUNTERS
            .workspace_append_full_history_validations
            .load(Ordering::Relaxed),
        workspace_append_revision_files_read: COUNTERS
            .workspace_append_revision_files_read
            .load(Ordering::Relaxed),
        workspace_append_trusted_head_invalidations: COUNTERS
            .workspace_append_trusted_head_invalidations
            .load(Ordering::Relaxed),
        workspace_append_identity_drift: COUNTERS
            .workspace_append_identity_drift
            .load(Ordering::Relaxed),
        workspace_append_lock_contention: COUNTERS
            .workspace_append_lock_contention
            .load(Ordering::Relaxed),
        historical_parallel_reconstruction_count: COUNTERS
            .historical_parallel_reconstruction_count
            .load(Ordering::Relaxed),
        historical_serial_order_apply_count: COUNTERS
            .historical_serial_order_apply_count
            .load(Ordering::Relaxed),
        historical_crypto_workers_used: COUNTERS
            .historical_crypto_workers_used
            .load(Ordering::Relaxed),
        parallel_crypto_micros_total: COUNTERS
            .parallel_crypto_micros_total
            .load(Ordering::Relaxed),
        ordered_apply_micros_total: COUNTERS.ordered_apply_micros_total.load(Ordering::Relaxed),
        historical_crypto_batches: crypto_batch.historical_crypto_batches,
        historical_crypto_proofs: crypto_batch.historical_crypto_proofs,
        historical_crypto_batch_fallbacks: crypto_batch.historical_crypto_batch_fallbacks,
        historical_crypto_individual_fallback_verifies: crypto_batch
            .historical_crypto_individual_fallback_verifies,
        verifier_context_build_count: crypto_batch.verifier_context_build_count,
        verifier_context_reuse_count: crypto_batch.verifier_context_reuse_count,
        batch_verify_micros_total: crypto_batch.batch_verify_micros_total,
        private_intake_digest_index_hits: COUNTERS
            .private_intake_digest_index_hits
            .load(Ordering::Relaxed),
        private_intake_digest_index_misses: COUNTERS
            .private_intake_digest_index_misses
            .load(Ordering::Relaxed),
        private_intake_linear_transcript_scans: COUNTERS
            .private_intake_linear_transcript_scans
            .load(Ordering::Relaxed),
        private_inbox_files_read: COUNTERS.private_inbox_files_read.load(Ordering::Relaxed),
        private_inbox_files_hashed: COUNTERS.private_inbox_files_hashed.load(Ordering::Relaxed),
        private_inbox_files_skipped_unchanged: COUNTERS
            .private_inbox_files_skipped_unchanged
            .load(Ordering::Relaxed),
        verified_session_cache_advances: COUNTERS
            .verified_session_cache_advances
            .load(Ordering::Relaxed),
        verified_session_cache_advance_failures: COUNTERS
            .verified_session_cache_advance_failures
            .load(Ordering::Relaxed),
        verified_session_cache_advance_identity_drift: COUNTERS
            .verified_session_cache_advance_identity_drift
            .load(Ordering::Relaxed),
        verified_session_cache_advance_unsupported_mutation: COUNTERS
            .verified_session_cache_advance_unsupported_mutation
            .load(Ordering::Relaxed),
        verified_session_cache_advance_fallback_replays: COUNTERS
            .verified_session_cache_advance_fallback_replays
            .load(Ordering::Relaxed),
        durable_head_body_cache_hits: COUNTERS
            .durable_head_body_cache_hits
            .load(Ordering::Relaxed),
        durable_head_body_cache_misses: COUNTERS
            .durable_head_body_cache_misses
            .load(Ordering::Relaxed),
        durable_head_body_cache_bytes: COUNTERS
            .durable_head_body_cache_bytes
            .load(Ordering::Relaxed),
        durable_head_body_cache_evictions: COUNTERS
            .durable_head_body_cache_evictions
            .load(Ordering::Relaxed),
        durable_head_body_identity_drift: COUNTERS
            .durable_head_body_identity_drift
            .load(Ordering::Relaxed),
        durable_head_body_disk_reads: COUNTERS
            .durable_head_body_disk_reads
            .load(Ordering::Relaxed),
        durable_head_body_decodes: COUNTERS.durable_head_body_decodes.load(Ordering::Relaxed),
    }
}

/// Zeroes every counter, including the crypto crate's adapter counter.
/// Intended for test setup so a test can measure the exact cost of one
/// operation. Changing dev counters has no protocol effect.
pub fn reset() {
    tari_cc_private_ballot_crypto::reset_verify_invocation_count();
    COUNTERS.workspace_list_calls.store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_summarize_calls
        .store(0, Ordering::Relaxed);
    COUNTERS
        .from_durable_snapshot_calls
        .store(0, Ordering::Relaxed);
    COUNTERS
        .historical_ballots_replayed
        .store(0, Ordering::Relaxed);
    COUNTERS.triptych_verify_calls.store(0, Ordering::Relaxed);
    COUNTERS
        .reconstruction_micros_total
        .store(0, Ordering::Relaxed);
    COUNTERS
        .proof_verification_micros_total
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_lookups
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_hits
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_misses
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_insertions
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_evictions
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_invalidations
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_single_flight_owners
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_single_flight_waiters
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_single_flight_failures
        .store(0, Ordering::Relaxed);
    COUNTERS.workspace_append_calls.store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_fast_path_hits
        .store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_full_history_validations
        .store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_revision_files_read
        .store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_trusted_head_invalidations
        .store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_identity_drift
        .store(0, Ordering::Relaxed);
    COUNTERS
        .workspace_append_lock_contention
        .store(0, Ordering::Relaxed);
    COUNTERS
        .historical_parallel_reconstruction_count
        .store(0, Ordering::Relaxed);
    COUNTERS
        .historical_serial_order_apply_count
        .store(0, Ordering::Relaxed);
    COUNTERS
        .historical_crypto_workers_used
        .store(0, Ordering::Relaxed);
    COUNTERS
        .parallel_crypto_micros_total
        .store(0, Ordering::Relaxed);
    COUNTERS
        .ordered_apply_micros_total
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_intake_digest_index_hits
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_intake_digest_index_misses
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_intake_linear_transcript_scans
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_inbox_files_read
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_inbox_files_hashed
        .store(0, Ordering::Relaxed);
    COUNTERS
        .private_inbox_files_skipped_unchanged
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_advances
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_advance_failures
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_advance_identity_drift
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_advance_unsupported_mutation
        .store(0, Ordering::Relaxed);
    COUNTERS
        .verified_session_cache_advance_fallback_replays
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_cache_hits
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_cache_misses
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_cache_bytes
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_cache_evictions
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_identity_drift
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_disk_reads
        .store(0, Ordering::Relaxed);
    COUNTERS
        .durable_head_body_decodes
        .store(0, Ordering::Relaxed);
}
