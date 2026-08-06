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
}
