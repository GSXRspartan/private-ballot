//! Process-local, memory-only memoization of full archive verification (Slice 4D).
//!
//! # What is memoized, and what is never skipped
//!
//! The expensive part of [`crate::verify_archive_directory_v1`] is the
//! authoritative historical **ballot replay** (one Triptych proof verification
//! per archived submission) plus the archive-hash rebuild. That work is a pure
//! function of the exact catalog bytes, which the archive manifest's own hash
//! commits (format version, election hash, algorithm, ordered paths, and every
//! file's domain-separated digest).
//!
//! Every request — hit or miss — still **re-establishes the current on-disk
//! identity**: it re-reads and strictly decodes the current manifest, enforces
//! catalog set equality, and bounded-reads and re-digests every catalog file
//! ([`crate::verifier::establish_identity_and_catalog`]). Only after that
//! revalidation succeeds and produces the same `(canonical directory, archive
//! hash)` may a cached verified result be returned. A memo hit therefore never
//! skips content revalidation; it only skips repeated proof replay.
//!
//! This is not an mtime/size cache. Metadata is never a trust input. Any
//! missing, unexpected, non-regular, oversized, reparse/symlink, digest, or
//! read anomaly fails closed exactly as the full verifier does.
//!
//! # Properties
//!
//! Process-local, memory-only, bounded LRU (default four immutable successful
//! reports), per-key single-flight, identity-bound, fail-closed, nonpersistent.
//! Failed or non-verified results are never cached. Different archives never
//! cross-hit.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};

use crate::instrumentation;
use crate::manifest::ArchiveHashV1;
use crate::verifier::{
    ArchiveDirectoryVerificationV1, ArchiveVerifierError, EstablishOutcomeV1,
    EstablishedIdentityV1, establish_identity_and_catalog, finish_verification,
};

/// Default bounded capacity: four immutable successful verification reports.
/// Values are bounded reports, never archive bytes.
pub const ARCHIVE_VERIFICATION_MEMO_CAPACITY_V1: usize = 4;

/// Identity of one memoized archive verification: the canonical directory scope
/// plus the archive hash freshly derived from the current manifest bytes.
///
/// The archive hash commits the whole catalog identity; the canonical directory
/// partitions distinct archives and prevents cross-hits. A hit additionally
/// requires that every current catalog file re-digested to the committed value
/// (performed by the caller before this key is consulted).
#[derive(Clone, PartialEq, Eq, Hash)]
struct ArchiveMemoKeyV1 {
    canonical_dir: String,
    archive_hash: ArchiveHashV1,
}

struct InFlightV1 {
    outcome: Mutex<Option<Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError>>>,
    ready: Condvar,
}

impl InFlightV1 {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            ready: Condvar::new(),
        }
    }
}

struct MemoStateV1 {
    entries: HashMap<ArchiveMemoKeyV1, Arc<ArchiveDirectoryVerificationV1>>,
    recency: VecDeque<ArchiveMemoKeyV1>,
    in_flight: HashMap<ArchiveMemoKeyV1, Arc<InFlightV1>>,
}

impl MemoStateV1 {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            recency: VecDeque::new(),
            in_flight: HashMap::new(),
        }
    }

    fn touch(&mut self, key: &ArchiveMemoKeyV1) {
        self.recency.retain(|existing| existing != key);
        self.recency.push_back(key.clone());
    }
}

/// A bounded, memory-only archive-verification memo with per-key single-flight.
pub struct ArchiveVerificationMemoV1 {
    capacity: usize,
    state: Mutex<MemoStateV1>,
}

impl Default for ArchiveVerificationMemoV1 {
    fn default() -> Self {
        Self::new(ARCHIVE_VERIFICATION_MEMO_CAPACITY_V1)
    }
}

impl ArchiveVerificationMemoV1 {
    /// Creates a memory-only memo with the requested bounded capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(MemoStateV1::new()),
        }
    }

    /// Verifies an archive directory, reusing a cached verified result only when
    /// the current on-disk identity and full catalog rehash re-establish the
    /// exact same `(canonical directory, archive hash)`.
    ///
    /// Integrity failures are returned as an `Ok` result with `verified=false`
    /// (never cached); filesystem-level failures return [`ArchiveVerifierError`].
    pub fn verify(
        &self,
        dir: &Path,
    ) -> Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError> {
        // Mandatory revalidation runs on every request, before any reuse: read
        // and decode the current manifest, enforce catalog set equality, and
        // re-digest every catalog file against the freshly decoded manifest.
        let established = match establish_identity_and_catalog(dir)? {
            EstablishOutcomeV1::Failed(result) => return Ok(Arc::new(result)),
            EstablishOutcomeV1::Established(established) => established,
        };
        let key = ArchiveMemoKeyV1 {
            canonical_dir: canonical_dir_string(dir),
            archive_hash: established.archive_hash(),
        };
        self.get_or_finish(key, established)
    }

    fn get_or_finish(
        &self,
        key: ArchiveMemoKeyV1,
        established: EstablishedIdentityV1,
    ) -> Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError> {
        let (flight, is_owner) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ArchiveVerifierError::IoFailure)?;
            if let Some(entry) = state.entries.get(&key).cloned() {
                state.touch(&key);
                instrumentation::record_cache_hit();
                return Ok(entry);
            }
            instrumentation::record_cache_miss();
            // Same directory, different current archive hash: the content under
            // this path changed since a prior cached verification. Record the
            // drift and drop the stale entries; the fresh identity fully
            // re-verifies below.
            if state
                .entries
                .keys()
                .any(|existing| existing.canonical_dir == key.canonical_dir)
            {
                instrumentation::record_cache_identity_drift();
                let directory = key.canonical_dir.clone();
                state
                    .entries
                    .retain(|existing, _| existing.canonical_dir != directory);
                state
                    .recency
                    .retain(|existing| existing.canonical_dir != directory);
            }
            if let Some(flight) = state.in_flight.get(&key).cloned() {
                instrumentation::record_single_flight_wait();
                (flight, false)
            } else {
                let flight = Arc::new(InFlightV1::new());
                state.in_flight.insert(key.clone(), Arc::clone(&flight));
                (flight, true)
            }
        };

        if !is_owner {
            return wait_for_in_flight(&flight);
        }

        // The owner runs the expensive replay with NO memo lock held, so
        // different archives (and unrelated work) proceed concurrently.
        let result = finish_verification(established).map(Arc::new);
        self.publish_completion(key, &flight, result)
    }

    fn publish_completion(
        &self,
        key: ArchiveMemoKeyV1,
        flight: &Arc<InFlightV1>,
        result: Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError>,
    ) -> Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ArchiveVerifierError::IoFailure)?;
            state.in_flight.remove(&key);
            // Only immutable, fully verified successes enter the cache. A
            // non-verified integrity result or a filesystem error is never
            // cached, so a later request re-verifies from scratch.
            if let Ok(report) = &result {
                if report.verified {
                    state.entries.insert(key.clone(), Arc::clone(report));
                    state.touch(&key);
                    while state.entries.len() > self.capacity {
                        if let Some(evicted) = state.recency.pop_front() {
                            if state.entries.remove(&evicted).is_some() {
                                instrumentation::record_cache_eviction();
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        let mut outcome = flight
            .outcome
            .lock()
            .map_err(|_| ArchiveVerifierError::IoFailure)?;
        *outcome = Some(result.clone());
        flight.ready.notify_all();
        result
    }

    /// Returns a privacy-safe count of cached entries (diagnostics/tests).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }
}

fn wait_for_in_flight(
    flight: &InFlightV1,
) -> Result<Arc<ArchiveDirectoryVerificationV1>, ArchiveVerifierError> {
    let mut outcome = flight
        .outcome
        .lock()
        .map_err(|_| ArchiveVerifierError::IoFailure)?;
    while outcome.is_none() {
        outcome = flight
            .ready
            .wait(outcome)
            .map_err(|_| ArchiveVerifierError::IoFailure)?;
    }
    match outcome.as_ref() {
        Some(result) => result.clone(),
        None => Err(ArchiveVerifierError::IoFailure),
    }
}

/// Canonicalizes the directory for the memo key partition only. Security does
/// not depend on this: every request independently re-reads and re-digests the
/// full catalog. If canonicalization fails, the lossy path string is used, which
/// can only reduce deduplication, never grant an unsafe hit.
fn canonical_dir_string(dir: &Path) -> String {
    std::fs::canonicalize(dir)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| dir.to_string_lossy().into_owned())
}
