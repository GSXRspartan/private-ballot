//! Process-local cache for replay-verified durable election sessions.
//!
//! The cache deliberately accepts only [`VerifiedElectionSessionV1`] values,
//! whose constructor is private to the durable reconstruction boundary. It is
//! memory-only: dropping the [`VerifiedElectionSessionCacheV1`] drops every
//! verification result, so process restart always replays durable ballots.

use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::session::GuiElectionSessionV1;

/// Bump when a code change alters durable-session reconstruction or verifier
/// policy without changing the committed workspace bytes.
pub const VERIFIED_SESSION_CACHE_EPOCH_V1: u32 = 1;

/// A deliberately small process-local LRU. Each entry owns a fully replayed
/// session, including its verification transcript and acceptance ledger.
pub const DEFAULT_VERIFIED_SESSION_CACHE_CAPACITY_V1: usize = 4;

/// Identity of one verified durable workspace head.
///
/// The revision digest is calculated over the serialized durable record. The
/// workspace loader additionally validates the full predecessor chain before
/// it constructs this key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedSessionKeyV1 {
    workspace_id: String,
    head_revision: u64,
    head_revision_digest_hex: String,
    verifier_epoch: u32,
}

impl VerifiedSessionKeyV1 {
    /// Creates one immutable cache identity from loader-validated values.
    #[must_use]
    pub fn new(workspace_id: String, head_revision: u64, head_revision_digest_hex: String) -> Self {
        Self {
            workspace_id,
            head_revision,
            head_revision_digest_hex,
            verifier_epoch: VERIFIED_SESSION_CACHE_EPOCH_V1,
        }
    }

    /// The opaque workspace identifier this entry belongs to.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
}

/// A session that reached this wrapper only through full durable replay.
///
/// There is intentionally no public constructor. Callers may obtain a clone
/// for a local mutation, but the cache itself never exposes a globally mutable
/// session object.
pub struct VerifiedElectionSessionV1 {
    session: GuiElectionSessionV1,
}

impl VerifiedElectionSessionV1 {
    pub(crate) fn from_reconstruction(session: GuiElectionSessionV1) -> Self {
        Self { session }
    }

    /// Wraps an already-verified session that was advanced in-memory after a
    /// successful durable commit (Slice 4E).
    ///
    /// This is intentionally as privileged as [`Self::from_reconstruction`] and
    /// nothing more: the wrapper only holds the session. The trust boundary is
    /// the workspace-layer advance path
    /// ([`crate::workspace::advance_verified_session_after_commit_v1`]), which
    /// independently re-reads and confirms the new committed durable head
    /// identity before this wrapper may enter the cache. There is no public
    /// "trust this session" constructor.
    pub(crate) fn from_incremental_advance(session: GuiElectionSessionV1) -> Self {
        Self { session }
    }

    pub(crate) fn session_clone(&self) -> GuiElectionSessionV1 {
        self.session.transactional_clone()
    }
}

/// A privacy-safe cache shape for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct VerifiedSessionCacheSnapshotV1 {
    pub entries: usize,
    pub in_flight: usize,
}

struct CacheStateV1 {
    entries: HashMap<VerifiedSessionKeyV1, Arc<VerifiedElectionSessionV1>>,
    recency: VecDeque<VerifiedSessionKeyV1>,
    in_flight: HashMap<VerifiedSessionKeyV1, Arc<InFlightV1>>,
}

impl CacheStateV1 {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            recency: VecDeque::new(),
            in_flight: HashMap::new(),
        }
    }

    fn touch(&mut self, key: &VerifiedSessionKeyV1) {
        self.recency.retain(|existing| existing != key);
        self.recency.push_back(key.clone());
    }
}

struct InFlightV1 {
    outcome: Mutex<Option<Result<Arc<VerifiedElectionSessionV1>, GuiCoreError>>>,
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

/// A small, process-local cache with per-key single-flight reconstruction.
///
/// Different durable workspace heads may reconstruct independently, but the
/// CPU-bound replay count is bounded so duplicate UI work cannot monopolize
/// the Tauri blocking pool.
pub struct VerifiedElectionSessionCacheV1 {
    capacity: usize,
    state: Mutex<CacheStateV1>,
    permits: ReconstructionPermitsV1,
}

impl Default for VerifiedElectionSessionCacheV1 {
    fn default() -> Self {
        Self::new(DEFAULT_VERIFIED_SESSION_CACHE_CAPACITY_V1)
    }
}

impl VerifiedElectionSessionCacheV1 {
    /// Creates a memory-only cache with the requested bounded capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(CacheStateV1::new()),
            permits: ReconstructionPermitsV1::new(default_reconstruction_parallelism()),
        }
    }

    /// Returns the cached verified session or lets exactly one caller build it.
    ///
    /// The reconstruction closure executes with no cache mutex held. A panic
    /// is converted to a bounded failure, wakes every waiter, and never enters
    /// the trusted cache.
    pub fn get_or_reconstruct<F>(
        &self,
        key: VerifiedSessionKeyV1,
        reconstruct: F,
    ) -> Result<Arc<VerifiedElectionSessionV1>, GuiCoreError>
    where
        F: FnOnce() -> Result<VerifiedElectionSessionV1, GuiCoreError>,
    {
        crate::instrumentation::record_verified_session_cache_lookup();
        let (flight, is_owner) = {
            let mut state = self.lock_state()?;
            if let Some(entry) = state.entries.get(&key).cloned() {
                state.touch(&key);
                crate::instrumentation::record_verified_session_cache_hit();
                return Ok(entry);
            }
            crate::instrumentation::record_verified_session_cache_miss();
            if let Some(flight) = state.in_flight.get(&key).cloned() {
                crate::instrumentation::record_verified_session_single_flight_waiter();
                (flight, false)
            } else {
                let flight = Arc::new(InFlightV1::new());
                state.in_flight.insert(key.clone(), Arc::clone(&flight));
                crate::instrumentation::record_verified_session_single_flight_owner();
                (flight, true)
            }
        };

        if !is_owner {
            return wait_for_in_flight(&flight);
        }

        let result = match self.permits.acquire() {
            Ok(_permit) => match catch_unwind(AssertUnwindSafe(reconstruct)) {
                Ok(result) => result.map(Arc::new),
                Err(_) => Err(reconstruction_panicked()),
            },
            Err(error) => Err(error),
        };
        self.publish_completion(key, &flight, result)
    }

    /// Installs an already-verified, incrementally-advanced session under its
    /// newly committed durable head identity (Slice 4E), so an immediate resume
    /// of that head is a cache hit with zero historical replay.
    ///
    /// The caller (the workspace advance path) MUST have independently re-read
    /// the committed durable head and confirmed that `key` is exactly that head
    /// and that the advanced session's durable snapshot equals the committed
    /// body. This method performs no verification of its own; it is a bounded,
    /// LRU-managed insert that supersedes any prior entry for this workspace.
    pub(crate) fn install_advanced(
        &self,
        workspace_id: &str,
        key: VerifiedSessionKeyV1,
        session: VerifiedElectionSessionV1,
    ) -> Result<(), GuiCoreError> {
        let mut state = self.lock_state()?;
        // Drop any older heads for this workspace: the advance supersedes them,
        // and keeping a stale prior head would only waste capacity.
        state
            .entries
            .retain(|existing, _| existing.workspace_id() != workspace_id || *existing == key);
        state
            .recency
            .retain(|existing| existing.workspace_id() != workspace_id || *existing == key);
        state.entries.insert(key.clone(), Arc::new(session));
        state.touch(&key);
        while state.entries.len() > self.capacity {
            if let Some(evicted) = state.recency.pop_front() {
                if state.entries.remove(&evicted).is_some() {
                    crate::instrumentation::record_verified_session_cache_eviction();
                }
            } else {
                break;
            }
        }
        crate::instrumentation::record_verified_session_cache_advance();
        Ok(())
    }

    /// Removes every cached head for one workspace after a successful durable
    /// mutation or deletion. In-flight work is left to its verify-after check,
    /// which will fail closed rather than insert a stale result.
    pub fn invalidate_workspace(&self, workspace_id: &str) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let before = state.entries.len();
        state
            .entries
            .retain(|key, _| key.workspace_id() != workspace_id);
        if state.entries.len() != before {
            state
                .recency
                .retain(|key| key.workspace_id() != workspace_id);
            crate::instrumentation::record_verified_session_cache_invalidation();
        }
    }

    /// Returns a privacy-safe cache shape for diagnostics and tests.
    #[must_use]
    pub fn snapshot(&self) -> VerifiedSessionCacheSnapshotV1 {
        let Ok(state) = self.state.lock() else {
            return VerifiedSessionCacheSnapshotV1::default();
        };
        VerifiedSessionCacheSnapshotV1 {
            entries: state.entries.len(),
            in_flight: state.in_flight.len(),
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, CacheStateV1>, GuiCoreError> {
        self.state.lock().map_err(|_| cache_state_poisoned())
    }

    fn publish_completion(
        &self,
        key: VerifiedSessionKeyV1,
        flight: &Arc<InFlightV1>,
        result: Result<Arc<VerifiedElectionSessionV1>, GuiCoreError>,
    ) -> Result<Arc<VerifiedElectionSessionV1>, GuiCoreError> {
        let published = (|| {
            let mut state = self.lock_state()?;
            state.in_flight.remove(&key);
            if let Ok(session) = &result {
                state.entries.insert(key.clone(), Arc::clone(session));
                state.touch(&key);
                crate::instrumentation::record_verified_session_cache_insertion();
                while state.entries.len() > self.capacity {
                    if let Some(evicted) = state.recency.pop_front() {
                        if state.entries.remove(&evicted).is_some() {
                            crate::instrumentation::record_verified_session_cache_eviction();
                        }
                    } else {
                        break;
                    }
                }
            } else {
                crate::instrumentation::record_verified_session_single_flight_failure();
            }
            Ok(())
        })();
        let final_result = match published {
            Ok(()) => result,
            Err(error) => Err(error),
        };
        let mut outcome = flight.outcome.lock().map_err(|_| cache_state_poisoned())?;
        *outcome = Some(final_result.clone());
        flight.ready.notify_all();
        final_result
    }
}

fn wait_for_in_flight(flight: &InFlightV1) -> Result<Arc<VerifiedElectionSessionV1>, GuiCoreError> {
    let mut outcome = flight.outcome.lock().map_err(|_| cache_state_poisoned())?;
    while outcome.is_none() {
        outcome = flight
            .ready
            .wait(outcome)
            .map_err(|_| cache_state_poisoned())?;
    }
    match outcome.as_ref() {
        // The loop above only exits once the owner has stored an outcome.
        Some(result) => result.clone(),
        None => Err(cache_state_poisoned()),
    }
}

struct ReconstructionPermitsV1 {
    available: Mutex<usize>,
    released: Condvar,
}

impl ReconstructionPermitsV1 {
    fn new(maximum: usize) -> Self {
        Self {
            available: Mutex::new(maximum.max(1)),
            released: Condvar::new(),
        }
    }

    fn acquire(&self) -> Result<ReconstructionPermitV1<'_>, GuiCoreError> {
        let mut available = self.available.lock().map_err(|_| cache_state_poisoned())?;
        while *available == 0 {
            available = self
                .released
                .wait(available)
                .map_err(|_| cache_state_poisoned())?;
        }
        *available -= 1;
        Ok(ReconstructionPermitV1 { permits: self })
    }
}

struct ReconstructionPermitV1<'a> {
    permits: &'a ReconstructionPermitsV1,
}

impl Drop for ReconstructionPermitV1<'_> {
    fn drop(&mut self) {
        if let Ok(mut available) = self.permits.available.lock() {
            *available += 1;
            self.permits.released.notify_one();
        }
    }
}

fn default_reconstruction_parallelism() -> usize {
    // Leave CPU capacity for the GUI/event loop. A desktop with one available
    // CPU reconstructs one election at a time; larger machines still cap this
    // expensive proof replay at two concurrent elections.
    std::thread::available_parallelism()
        .map(|count| count.get().saturating_sub(1).clamp(1, 2))
        .unwrap_or(1)
}

fn cache_state_poisoned() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_VERIFIED_SESSION_CACHE_UNAVAILABLE",
        GuiErrorCategory::Unavailable,
        Some("verified-session-cache"),
        "the verified-session cache is unavailable",
    )
}

fn reconstruction_panicked() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_VERIFIED_SESSION_RECONSTRUCTION_PANICKED",
        GuiErrorCategory::Unavailable,
        Some("verified-session-cache"),
        "verified election reconstruction did not complete",
    )
}
