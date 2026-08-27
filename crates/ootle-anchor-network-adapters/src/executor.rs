//! Async-to-sync execution seam (Sections A, G).
//!
//! The confirmed walletd and indexer client methods are `async` and
//! reqwest-backed. The network-adapter crate owns no runtime and starts no
//! background task. The real transports bridge async-to-sync through a
//! caller-provided [`BlockingExecutor`]: a future application command supplies a
//! tokio-based executor; the offline test suites use scripted transports that
//! require no executor and open no socket.
//!
//! # Runtime ownership
//!
//! The selected strategy is **option 2** (application-owned executor trait)
//! combined with **option 3** (explicit caller-owned runtime handle wrapper):
//!
//! 1. The real transport holds a pinned client and a `BlockingExecutor`.
//! 2. The transport trait [`WalletdWireTransport`] /
//!    [`IndexerReceiptWireTransport`] is **synchronous** — it returns bounded
//!    `Result<_, TransportError>` values, matching the existing 4A6/4A7
//!    client-traits.
//! 3. The real transport calls the pinned client's `async` method and blocks
//!    on the resulting future through the executor.
//! 4. The executor is provided by the application (e.g. a tokio `Handle`
//!    wrapper). The crate does not create a process-global runtime.
//! 5. [`SimpleBlockingExecutor`] is a test-only executor that polls once and
//!    returns `Err(WouldBlock)` if the future is not immediately ready — scripted
//!    transports are synchronous and never produce a future, so this executor is
//!    never exercised by the offline test suites.
//!
//! The lifecycle orchestrator remains synchronous and deterministic; it is
//! never modified.

use core::future::Future;
use core::time::Duration;
use std::task::{Context, Poll, Waker};

/// Bounded error returned when a [`BlockingExecutor`] cannot drive a future to
/// completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingExecutorError {
    /// The future was not immediately ready (a test-only executor polled once
    /// and the future was still pending).
    WouldBlock,
    /// The executor detected it was called from inside an incompatible active
    /// async runtime.
    AlreadyInsideAsyncRuntime,
    /// The future did not complete within the caller-supplied deadline. The
    /// observable state is now unknown (mirrors a transport timeout), so the
    /// transport surfaces this as [`crate::TransportErrorCategory::Timeout`]
    /// rather than an executor failure — a submit that times out must recover,
    /// never blind-resubmit.
    Elapsed,
}

impl BlockingExecutorError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WouldBlock => "EXECUTOR_WOULD_BLOCK",
            Self::AlreadyInsideAsyncRuntime => "EXECUTOR_ALREADY_INSIDE_ASYNC_RUNTIME",
            Self::Elapsed => "EXECUTOR_ELAPSED",
        }
    }
}

impl core::fmt::Display for BlockingExecutorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for BlockingExecutorError {}

/// Application-owned executor that can synchronously block on one future.
///
/// The real transport uses this to bridge the pinned client's `async` methods to
/// the synchronous transport trait. The application supplies a tokio-based
/// implementation (e.g. wrapping `Handle::block_on`); the crate does not create
/// a runtime.
pub trait BlockingExecutor {
    /// Drives `future` to completion and returns its output, or a bounded
    /// [`BlockingExecutorError`] if the executor cannot block.
    fn block_on<F: Future<Output = T>, T>(&self, future: F) -> Result<T, BlockingExecutorError>;

    /// Drives `future` to completion but no longer than `timeout`.
    ///
    /// When `timeout` is `None`, this is exactly [`Self::block_on`]. When it is
    /// `Some(deadline)`, an implementation that owns a real reactor bounds the
    /// wait and returns [`BlockingExecutorError::Elapsed`] if the deadline
    /// passes first. The default implementation ignores the deadline (it is
    /// suitable only for the test-only [`SimpleBlockingExecutor`], whose futures
    /// are already resolved); every production executor overrides it so the
    /// configured request timeout is enforced at the real network boundary.
    fn block_on_bounded<F: Future<Output = T>, T>(
        &self,
        future: F,
        timeout: Option<Duration>,
    ) -> Result<T, BlockingExecutorError> {
        let _ = timeout;
        self.block_on(future)
    }
}

/// A test-only executor that polls a future once.
///
/// If the future is immediately ready, returns `Ok(output)`. Otherwise returns
/// `Err(WouldBlock)`. This is sufficient for unit-testing conversion logic
/// through the real transport when the pinned client's future is not actually
/// driven (the offline test suites use scripted transports that are fully
/// synchronous and never invoke this executor).
pub struct SimpleBlockingExecutor;

impl BlockingExecutor for SimpleBlockingExecutor {
    #[allow(clippy::needless_borrow)]
    fn block_on<F: Future<Output = T>, T>(&self, future: F) -> Result<T, BlockingExecutorError> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(future);
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => Ok(output),
            Poll::Pending => Err(BlockingExecutorError::WouldBlock),
        }
    }
}
