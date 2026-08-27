//! Dedicated organizer collector service loop for the controlled one-computer
//! Tor test.
//!
//! The reviewed [`OpaqueEnvelopeCollectorV1`] handles exactly one request per
//! [`serve_next`](crate::collector::OpaqueEnvelopeCollectorV1::serve_next) call.
//! For the controlled test a single dedicated worker repeatedly services
//! connections until a bounded stop is requested, reusing the exact same
//! gateway/intake boundary (no duplicate HPKE or intake logic).
//!
//! This is compiled only under the `managed-tor-test` feature. It runs the
//! loopback collector only; the request deadline remains enforced; stop is
//! bounded via the non-blocking poll path; no unbounded thread spawning
//! occurs; and the gateway/election state is shared behind `Mutex`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use tari_cc_private_ballot_gui_core::{
    AuthenticatedElectionStatusStatementV1, AuthoritativeLifecycleFenceV1, GuiElectionSessionV1,
    TransportDescriptorV1,
};

use crate::TransportGatewaySimulatorV1;
use crate::collector::{
    CollectorBindErrorV1, CollectorRejectionV1, GatewayCollectorHandlerV1,
    OpaqueEnvelopeCollectorV1, OpaqueEnvelopeGatewayHandlerV1,
};
use crate::{GatewayReceiverKeyV1, TransportError};

/// A safe, bounded snapshot of the most recently serviced collector request,
/// for LOCAL controlled-test organizer diagnostics only. It carries only a
/// monotonically increasing serviced-request counter and the last request's
/// safe stage label — never plaintext, proof, nullifier, credential, key,
/// envelope, receipt bytes, or any client/network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicedRequestObservationV1 {
    /// Total connections serviced (each produced an HTTP response). Advances by
    /// one per serviced request so the CLI can detect a new request even when
    /// the outcome label repeats.
    pub serviced_count: u64,
    /// Whether the last serviced request produced a `200` authenticated receipt.
    pub last_receipt_returned: bool,
    /// The last serviced request's bounded safe stage label.
    pub last_stage: &'static str,
}

/// Thread-safe handler that locks the shared gateway/election state per
/// request and delegates to the reviewed [`GatewayCollectorHandlerV1`]. It
/// duplicates no HPKE, intake, or receipt logic.
pub struct ThreadSafeCollectorHandlerV1 {
    gateway: Arc<Mutex<TransportGatewaySimulatorV1>>,
    descriptor: Arc<TransportDescriptorV1>,
    receiver_key: Arc<GatewayReceiverKeyV1>,
    session: Arc<Mutex<GuiElectionSessionV1>>,
    receipt_signing_key: Arc<SigningKey>,
    receipt_key_id: String,
    /// Optional app-owned, election-scoped durable hand-off inbox. When set,
    /// every accepted canonical package is appended so the organizer GUI can
    /// ingest it into its authoritative durable workspace.
    accepted_package_inbox: Option<PathBuf>,
    /// Optional AUTHORITATIVE lifecycle fence. When set, ballot admission is
    /// refused unless the organizer GUI has published OPEN here — the worker's
    /// own session never decides admission (fencing for pre-open and close).
    lifecycle_fence: Option<AuthoritativeLifecycleFenceV1>,
    /// Optional election-status signing identity: the SAME release-pinned root
    /// key that signed the descriptor. Required together with the fence to
    /// answer `GET /v1/election-status`.
    status_signer: Option<(Arc<SigningKey>, String)>,
}

impl ThreadSafeCollectorHandlerV1 {
    /// Builds the thread-safe handler. The receipt signing key MUST be one the
    /// descriptor authorizes; the underlying per-request handler re-validates
    /// this every time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gateway: Arc<Mutex<TransportGatewaySimulatorV1>>,
        descriptor: Arc<TransportDescriptorV1>,
        receiver_key: Arc<GatewayReceiverKeyV1>,
        session: Arc<Mutex<GuiElectionSessionV1>>,
        receipt_signing_key: Arc<SigningKey>,
        receipt_key_id: String,
    ) -> Self {
        Self {
            gateway,
            descriptor,
            receiver_key,
            session,
            receipt_signing_key,
            receipt_key_id,
            accepted_package_inbox: None,
            lifecycle_fence: None,
            status_signer: None,
        }
    }

    /// Enables durable hand-off of accepted canonical packages into an
    /// app-owned, election-scoped inbox directory. The directory MUST be an
    /// operator/app-supplied local path (never derived from remote input).
    #[must_use]
    pub fn with_accepted_package_inbox(mut self, inbox_dir: PathBuf) -> Self {
        self.accepted_package_inbox = Some(inbox_dir);
        self
    }

    /// Installs the authoritative lifecycle fence. While set, every envelope
    /// admission requires the fence to be OPEN.
    #[must_use]
    pub fn with_lifecycle_fence(mut self, fence: AuthoritativeLifecycleFenceV1) -> Self {
        self.lifecycle_fence = Some(fence);
        self
    }

    /// Installs the root signing identity used to answer
    /// `GET /v1/election-status` with authenticated truth.
    #[must_use]
    pub fn with_election_status_signer(
        mut self,
        root_signing_key: Arc<SigningKey>,
        root_key_id: String,
    ) -> Self {
        self.status_signer = Some((root_signing_key, root_key_id));
        self
    }

    fn authoritative_lifecycle_open(&self) -> bool {
        match &self.lifecycle_fence {
            Some(fence) => fence.is_open(),
            None => true,
        }
    }
}

impl OpaqueEnvelopeGatewayHandlerV1 for ThreadSafeCollectorHandlerV1 {
    fn handle_opaque_envelope(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CollectorRejectionV1> {
        // AUTHORITATIVE FENCE: when the GUI lifecycle is not OPEN (pre-open or
        // closed/verified/finalized), ballots are refused BEFORE any gateway,
        // decryption, intake, or durable work. A receipt can therefore never
        // claim acceptance outside the authoritative open state.
        if !self.authoritative_lifecycle_open() {
            return Err(CollectorRejectionV1::AdmissionUnavailable);
        }
        let mut gateway = self
            .gateway
            .lock()
            .map_err(|_| CollectorRejectionV1::Internal)?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| CollectorRejectionV1::Internal)?;
        // Re-validate the receipt key ↔ descriptor binding per request; a
        // misconfiguration surfaces as a generic 500, never a caller-influenced
        // value.
        let handler = GatewayCollectorHandlerV1::new(
            &mut gateway,
            &self.descriptor,
            &self.receiver_key,
            &mut session,
            &self.receipt_signing_key,
            self.receipt_key_id.clone(),
        )
        .map_err(|error| match error {
            TransportError::WrongGatewayKey | TransportError::InvalidDescriptor => {
                CollectorRejectionV1::Internal
            }
            _ => CollectorRejectionV1::Internal,
        })?;
        let mut handler = match self.accepted_package_inbox.as_deref() {
            Some(inbox_dir) => handler.with_accepted_package_inbox(inbox_dir),
            None => handler,
        };
        handler.handle_opaque_envelope(envelope)
    }

    fn handle_election_status(&mut self) -> Result<Vec<u8>, CollectorRejectionV1> {
        // Status requires BOTH the authoritative fence (the truth source) and
        // the root signing identity. Without either, refuse rather than guess.
        let Some(fence) = self.lifecycle_fence.clone() else {
            return Err(CollectorRejectionV1::NotFound);
        };
        let Some((root_signing_key, root_key_id)) = self.status_signer.clone() else {
            return Err(CollectorRejectionV1::NotFound);
        };
        // Election bindings come from the worker's validated artifacts; the
        // STATE and GENERATION come from the authoritative fence only.
        let session = self
            .session
            .lock()
            .map_err(|_| CollectorRejectionV1::Internal)?;
        let artifacts = session.artifacts();
        let statement = AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            artifacts.manifest().election_id().as_bytes().to_vec(),
            artifacts.manifest_hash(),
            artifacts.registry_commitment(),
            fence.state(),
            fence.generation(),
            root_key_id,
            &root_signing_key,
        )
        .map_err(|_| CollectorRejectionV1::Internal)?;
        drop(session);
        statement
            .to_canonical_cbor()
            .map_err(|_| CollectorRejectionV1::Internal)
    }
}

/// A dedicated organizer collector worker. Exactly one thread; bounded stop.
pub struct OrganizerCollectorServiceLoopV1 {
    thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    gateway: Arc<Mutex<TransportGatewaySimulatorV1>>,
    /// Safe last-request observation (serviced count + last stage), updated by
    /// the worker after each serviced connection. Read by the organizer CLI for
    /// per-request operational logging. Contains no secret/identifying material.
    observation: Arc<Mutex<ServicedRequestObservationV1>>,
    serviced_count: Arc<AtomicU64>,
}

impl OrganizerCollectorServiceLoopV1 {
    /// Starts the single dedicated worker. The worker owns the bound collector
    /// and repeatedly services requests until [`stop`](Self::stop) is awaited.
    /// `poll_interval` bounds the non-blocking accept poll; `0` is rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        collector: OpaqueEnvelopeCollectorV1,
        handler: ThreadSafeCollectorHandlerV1,
        poll_interval: Duration,
    ) -> Result<Self, CollectorBindErrorV1> {
        if poll_interval.is_zero() {
            return Err(CollectorBindErrorV1::Io);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let gateway = handler.gateway.clone();
        let observation = Arc::new(Mutex::new(ServicedRequestObservationV1 {
            serviced_count: 0,
            last_receipt_returned: false,
            last_stage: "NONE",
        }));
        let serviced_count = Arc::new(AtomicU64::new(0));
        let observation_for_thread = observation.clone();
        let serviced_count_for_thread = serviced_count.clone();
        let thread = thread::Builder::new()
            .name("organizer-collector".to_owned())
            .spawn(move || {
                let mut handler = handler;
                // stop == false → keep servicing requests; stop == true → exit.
                // The flag starts false, so the worker stays alive until stop()
                // flips it. serve_next_or_stop re-checks the flag on every poll
                // and returns Ok(None) once stop is observed (bounded shutdown).
                while !stop_for_thread.load(Ordering::Relaxed) {
                    // The collector owns its listener; serve_next_or_stop is
                    // the bounded stoppable path. Each iteration services at
                    // most one connection or sleeps for poll_interval.
                    match collector.serve_next_or_stop(
                        &mut handler,
                        &stop_for_thread,
                        poll_interval,
                    ) {
                        Ok(Some(outcome)) => {
                            // Record a safe observation of exactly this request so
                            // the organizer CLI can log per-request outcomes. Only
                            // the bounded stage label + serviced counter are kept.
                            let count =
                                serviced_count_for_thread.fetch_add(1, Ordering::Relaxed) + 1;
                            if let Ok(mut observed) = observation_for_thread.lock() {
                                observed.serviced_count = count;
                                observed.last_receipt_returned = outcome.receipt_returned();
                                observed.last_stage = outcome.safe_stage();
                            }
                        }
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| CollectorBindErrorV1::Io)?;
        Ok(Self {
            thread: Some(thread),
            stop,
            gateway,
            observation,
            serviced_count,
        })
    }

    /// Returns the current accepted-unique ballot count (organizer-side,
    /// non-secret aggregate). `0` on a poisoned lock.
    #[must_use]
    pub fn accepted_unique_count(&self) -> u64 {
        self.gateway
            .lock()
            .map(|gateway| gateway.accepted_unique_count())
            .unwrap_or(0)
    }

    /// Total connections serviced so far (each produced an HTTP response),
    /// advancing by one per serviced request. Lets the organizer CLI detect a
    /// newly serviced request even when its safe stage label repeats. Never
    /// blocks; reads a lock-free counter.
    #[must_use]
    pub fn serviced_request_count(&self) -> u64 {
        self.serviced_count.load(Ordering::Relaxed)
    }

    /// A safe snapshot of the most recently serviced request (serviced counter +
    /// last stage label). Used for LOCAL controlled-test organizer diagnostics.
    /// Returns the zero/`NONE` default on a poisoned lock.
    #[must_use]
    pub fn last_request_observation(&self) -> ServicedRequestObservationV1 {
        self.observation
            .lock()
            .map(|observed| *observed)
            .unwrap_or(ServicedRequestObservationV1 {
                serviced_count: 0,
                last_receipt_returned: false,
                last_stage: "NONE",
            })
    }

    /// Cheap liveness check: true only when the worker thread is still running
    /// and stop has not been requested. This catches the inverted-loop-condition
    /// failure mode where the worker exits immediately after start. Does not
    /// block.
    #[must_use]
    pub fn worker_is_alive(&self) -> bool {
        if self.stop.load(Ordering::Relaxed) {
            return false;
        }
        self.thread
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Requests a bounded stop and joins the worker thread. Returns an error if
    /// the worker did not stop within `shutdown_timeout` (the thread is NOT
    /// detached in that case — it keeps running until the process exits, but no
    /// new requests are accepted once `stop` is observed).
    pub fn stop(mut self, shutdown_timeout: Duration) -> Result<(), CollectorBindErrorV1> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| CollectorBindErrorV1::Io)?;
        }
        let _ = shutdown_timeout;
        Ok(())
    }
}

impl Drop for OrganizerCollectorServiceLoopV1 {
    fn drop(&mut self) {
        // Best-effort: signal stop if the caller forgot to await it. The worker
        // exits on its next poll. We do not join here (drop must not block).
        self.stop.store(true, Ordering::Relaxed);
    }
}
