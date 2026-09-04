//! A real Tokio-backed implementation of the Slice 4A9 [`BlockingExecutor`]
//! trait.
//!
//! The application constructs exactly one current-thread Tokio runtime per
//! run, wraps it in [`TokioBlockingExecutor`], and drives the existing Slice
//! 4A9 real network adapters through it. The driver needs to hand an executor
//! to *both* the walletd and the indexer transport, so
//! [`TokioBlockingExecutor`] is [`Clone`]: cloning shares the single owned
//! runtime through an [`Arc`](std::sync::Arc). No second async runtime is
//! created and no background task is started. The current-thread runtime is
//! built with the Tokio `time` and `net`/I/O drivers (no `rt-multi-thread`):
//! the I/O driver is what lets `reqwest` reach walletd and the indexer, and the
//! time driver bounds each request.

use std::sync::Arc;

use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    BlockingExecutor, BlockingExecutorError,
};

/// A [`BlockingExecutor`] backed by an owned current-thread Tokio runtime.
///
/// The runtime is constructed by the caller (see
/// [`TokioBlockingExecutor::new`] or
/// [`TokioBlockingExecutor::new_current_thread`]) and shared via
/// [`Arc`](std::sync::Arc) so that [`Clone`] can hand the same runtime to both
/// the walletd and the indexer transport. The executor stores no secret
/// material and performs no I/O of its own; it only drives futures the
/// network adapters hand to it.
#[derive(Debug, Clone)]
pub struct TokioBlockingExecutor {
    runtime: Arc<tokio::runtime::Runtime>,
}

/// Failure while constructing the owned current-thread Tokio runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokioRuntimeBuildError {
    /// The runtime builder rejected the configuration.
    Build,
}

impl TokioRuntimeBuildError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "TOKIO_RUNTIME_BUILD",
        }
    }
}

impl core::fmt::Display for TokioRuntimeBuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TokioRuntimeBuildError {}

impl TokioBlockingExecutor {
    /// Wraps an already-constructed Tokio runtime.
    ///
    /// The caller is responsible for constructing exactly one current-thread
    /// runtime per run; see [`TokioBlockingExecutor::new_current_thread`] for
    /// the convenience builder used by the application binary.
    #[must_use]
    pub fn new(runtime: tokio::runtime::Runtime) -> Self {
        Self {
            runtime: Arc::new(runtime),
        }
    }

    /// Constructs a fresh current-thread Tokio runtime and wraps it.
    ///
    /// This is the construction path used by the application binary. It builds
    /// a current-thread runtime with the I/O and time drivers enabled (no
    /// multi-thread worker). The I/O driver is required for real HTTP I/O to
    /// walletd/indexer; the time driver bounds each request.
    ///
    /// # Errors
    ///
    /// Returns [`TokioRuntimeBuildError::Build`] if the Tokio runtime builder
    /// rejects the configuration. In practice this never fires for the
    /// current-thread flavor on a supported platform, but the `Result` keeps
    /// the binary panic-free.
    pub fn new_current_thread() -> Result<Self, TokioRuntimeBuildError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            // The I/O driver is required so `reqwest` can open sockets to
            // walletd and the indexer: without it, every real HTTP request fails
            // at the reactor before a connection is attempted, which the
            // readiness probe would misreport as "walletd unreachable". The time
            // driver is required so `block_on_bounded` can enforce the configured
            // per-request timeout via `tokio::time::timeout`. Still a
            // single-threaded, current-thread runtime — no multi-thread worker.
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| TokioRuntimeBuildError::Build)?;
        Ok(Self::new(runtime))
    }

    /// Returns a handle to the owned runtime.
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use std::time::Instant;

    fn executor() -> TokioBlockingExecutor {
        match TokioBlockingExecutor::new_current_thread() {
            Ok(executor) => executor,
            Err(_) => panic!("current-thread runtime must build"),
        }
    }

    #[test]
    fn bounded_block_returns_elapsed_for_a_never_completing_future() {
        let started = Instant::now();
        let outcome: Result<(), BlockingExecutorError> = executor().block_on_bounded(
            std::future::pending::<()>(),
            Some(Duration::from_millis(50)),
        );
        let elapsed = started.elapsed();
        assert_eq!(outcome, Err(BlockingExecutorError::Elapsed));
        // The deadline must actually bound the wait (well under any test timeout).
        assert!(
            elapsed < Duration::from_secs(5),
            "bounded wait exceeded the deadline: {elapsed:?}"
        );
    }

    #[test]
    fn bounded_block_returns_ready_output_before_the_deadline() {
        let outcome = executor().block_on_bounded(async { 7_u32 }, Some(Duration::from_secs(30)));
        assert_eq!(outcome, Ok(7));
    }

    #[test]
    fn none_timeout_runs_unbounded_to_completion() {
        let outcome = executor().block_on_bounded(async { 9_u32 }, None);
        assert_eq!(outcome, Ok(9));
    }

    // Regression guard for the walletd-connection bug: the runtime MUST have the
    // Tokio I/O driver enabled, or `reqwest` cannot open a socket to walletd and
    // every live RPC fails at the reactor (misreported as "walletd
    // unreachable"). Binding a real `TcpListener` requires that driver; without
    // `enable_io()` this call panics/errors and the test fails. This is the
    // cheapest observable proxy for "the runtime can do network I/O at all".
    #[test]
    fn runtime_has_the_io_driver_enabled() {
        let bound = executor().block_on_bounded(
            async {
                tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .map(|listener| listener.local_addr().is_ok())
                    .unwrap_or(false)
            },
            Some(Duration::from_secs(5)),
        );
        assert_eq!(
            bound,
            Ok(true),
            "current-thread runtime must have the I/O driver enabled for reqwest"
        );
    }
}

impl BlockingExecutor for TokioBlockingExecutor {
    fn block_on<F, T>(&self, future: F) -> Result<T, BlockingExecutorError>
    where
        F: core::future::Future<Output = T>,
    {
        // `spawn_blocking` workers can still have a current Tokio handle, so
        // `Handle::try_current()` is too broad here. Drive the owned runtime
        // and convert Tokio's true nested-entry panic into the bounded executor
        // error instead.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.runtime.block_on(future)
        }))
        .map_err(|_| BlockingExecutorError::AlreadyInsideAsyncRuntime)
    }

    fn block_on_bounded<F, T>(
        &self,
        future: F,
        timeout: Option<core::time::Duration>,
    ) -> Result<T, BlockingExecutorError>
    where
        F: core::future::Future<Output = T>,
    {
        match timeout {
            None => self.block_on(future),
            Some(deadline) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.runtime.block_on(async move {
                    // The time driver (enabled in `new_current_thread`) bounds the
                    // wait. An elapsed deadline surfaces as `Elapsed`, which the
                    // real transport maps to a transport timeout (state unknown →
                    // recover, never a blind resubmit) — it never silently drops
                    // the request result.
                    match tokio::time::timeout(deadline, future).await {
                        Ok(output) => Ok(output),
                        Err(_elapsed) => Err(BlockingExecutorError::Elapsed),
                    }
                })
            }))
            .map_err(|_| BlockingExecutorError::AlreadyInsideAsyncRuntime)?,
        }
    }
}
