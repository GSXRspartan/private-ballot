//! Tokio blocking executor tests (Slice 4A10 §16.3).

mod common;

use tari_cc_private_ballot_ootle_anchor_app::TokioBlockingExecutor;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    BlockingExecutor, BlockingExecutorError,
};

#[test]
fn ready_future_completes() {
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let result = executor.block_on(async { 42_u32 });
    match result {
        Ok(value) => assert_eq!(value, 42),
        Err(error) => panic!("ready future failed: {error}"),
    }
}

#[test]
fn future_returning_value_completes() {
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let result: Result<String, BlockingExecutorError> = executor.block_on(async {
        let value = 7_u32 + 35;
        value.to_string()
    });
    match result {
        Ok(text) => assert_eq!(text, "42"),
        Err(error) => panic!("future failed: {error}"),
    }
}

#[test]
fn nested_runtime_returns_already_inside_error() {
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let inner = executor.clone();
    let outer = executor.block_on(async move { inner.block_on(async {}) });
    match outer {
        Ok(Err(BlockingExecutorError::AlreadyInsideAsyncRuntime)) => {}
        other => panic!("expected nested AlreadyInsideAsyncRuntime, got {other:?}"),
    }
}

#[test]
fn handle_returns_working_handle() {
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let handle = executor.handle();
    let result = executor.block_on(async {
        let _ = handle;
        1_u32 + 1
    });
    match result {
        Ok(value) => assert_eq!(value, 2),
        Err(error) => panic!("handle test failed: {error}"),
    }
}

// Compile-time proof that `TokioBlockingExecutor` implements `BlockingExecutor`.
const _: fn() = || {
    fn _assert_blocking_executor<E: BlockingExecutor>() {}
    _assert_blocking_executor::<TokioBlockingExecutor>();
};

fn ok(
    result: Result<
        TokioBlockingExecutor,
        tari_cc_private_ballot_ootle_anchor_app::TokioRuntimeBuildError,
    >,
) -> TokioBlockingExecutor {
    match result {
        Ok(executor) => executor,
        Err(error) => panic!("executor construction failed: {error}"),
    }
}
