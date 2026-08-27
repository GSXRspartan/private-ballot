//! A real Tokio-backed implementation of the Slice 4A9 [`BlockingExecutor`]
//! trait.
//!
//! The application constructs exactly one current-thread Tokio runtime per
//! run, wraps it in [`TokioBlockingExecutor`], and drives the existing Slice
//! 4A9 real network adapters through it. The driver needs to hand an executor
//! to *both* the walletd and the indexer transport, so
//! [`TokioBlockingExecutor`] is [`Clone`]: cloning shares the single owned
//! runtime through an [`Arc`](std::sync::Arc). No second async runtime is
//! created; no background task is started; no `rt-multi-thread`, `time`, or
//! `net` feature is required from Tokio.

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
    /// This is the construction path used by the application binary. It
    /// enables only the `rt` feature of Tokio: no multi-thread worker, no
    /// `time` driver, no `net` driver.
    ///
    /// # Errors
    ///
    /// Returns [`TokioRuntimeBuildError::Build`] if the Tokio runtime builder
    /// rejects the configuration. In practice this never fires for the
    /// current-thread flavor on a supported platform, but the `Result` keeps
    /// the binary panic-free.
    pub fn new_current_thread() -> Result<Self, TokioRuntimeBuildError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            // The time driver is required so `block_on_bounded` can enforce the
            // configured per-request timeout via `tokio::time::timeout`. Only
            // the `rt` and `time` Tokio features are enabled: still no
            // multi-thread worker and no `net` driver.
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
}

impl BlockingExecutor for TokioBlockingExecutor {
    fn block_on<F, T>(&self, future: F) -> Result<T, BlockingExecutorError>
    where
        F: core::future::Future<Output = T>,
    {
        // Reject nested runtime entry without panicking. If the calling
        // thread is already inside an active Tokio runtime context, driving a
        // second `Runtime::block_on` would panic inside Tokio; instead
        // surface the bounded `AlreadyInsideAsyncRuntime` error.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(BlockingExecutorError::AlreadyInsideAsyncRuntime);
        }
        Ok(self.runtime.block_on(future))
    }

    fn block_on_bounded<F, T>(
        &self,
        future: F,
        timeout: Option<core::time::Duration>,
    ) -> Result<T, BlockingExecutorError>
    where
        F: core::future::Future<Output = T>,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(BlockingExecutorError::AlreadyInsideAsyncRuntime);
        }
        match timeout {
            None => Ok(self.runtime.block_on(future)),
            Some(deadline) => self.runtime.block_on(async move {
                // The time driver (enabled in `new_current_thread`) bounds the
                // wait. An elapsed deadline surfaces as `Elapsed`, which the
                // real transport maps to a transport timeout (state unknown →
                // recover, never a blind resubmit) — it never silently drops
                // the request result.
                match tokio::time::timeout(deadline, future).await {
                    Ok(output) => Ok(output),
                    Err(_elapsed) => Err(BlockingExecutorError::Elapsed),
                }
            }),
        }
    }
}
