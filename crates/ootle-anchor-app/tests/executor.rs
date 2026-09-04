//! Tokio blocking executor tests (Slice 4A10 §16.3).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;
use tari_cc_private_ballot_ootle_anchor_app::TokioBlockingExecutor;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    BlockingExecutor, BlockingExecutorError, PinnedWalletDaemonClient,
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
fn spawn_blocking_worker_can_drive_owned_executor() {
    let outer = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => panic!("outer runtime construction failed: {error}"),
    };
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let result = outer.block_on(async move {
        tokio::task::spawn_blocking(move || {
            executor.block_on_bounded(async { 11_u32 }, Some(core::time::Duration::from_secs(5)))
        })
        .await
    });
    match result {
        Ok(Ok(value)) => assert_eq!(value, 11),
        other => panic!("spawn_blocking executor path failed: {other:?}"),
    }
}

#[test]
fn production_executor_and_wallet_client_perform_loopback_http() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) => panic!("loopback listener bind failed: {error}"),
    };
    let endpoint = format!(
        "http://{}/json_rpc",
        listener
            .local_addr()
            .expect("loopback listener has local address")
    );
    let (request_tx, request_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one HTTP request");
        let request = read_http_request(&mut stream);
        request_tx
            .send(request.clone())
            .expect("send captured request bytes");
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"version":"test","network":"esmeralda","network_byte":34}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write HTTP response");
    });

    let mut client = match PinnedWalletDaemonClient::connect(&endpoint, None) {
        Ok(client) => client,
        Err(error) => panic!("walletd client construction failed: {error}"),
    };
    let executor = ok(TokioBlockingExecutor::new_current_thread());
    let info = match executor.block_on_bounded(
        async { client.get_wallet_info().await },
        Some(Duration::from_secs(5)),
    ) {
        Ok(Ok(info)) => info,
        other => panic!("production wallet client loopback request failed: {other:?}"),
    };
    let request = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("listener received request bytes");
    server.join().expect("server thread completed");

    assert_eq!(info.network, "esmeralda");
    assert!(
        request.contains("POST /json_rpc HTTP/1.1"),
        "request used JSON-RPC path: {request}"
    );
    assert!(
        request.contains(r#""method":"wallet.get_info""#),
        "request body must contain wallet.get_info: {request}"
    );
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

fn read_http_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut content_length = None;
    loop {
        let read = stream.read(&mut buffer).expect("read HTTP request");
        assert_ne!(read, 0, "client closed before sending a complete request");
        bytes.extend_from_slice(&buffer[..read]);
        if content_length.is_none() {
            if let Some(header_end) = find_header_end(&bytes) {
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                content_length = headers.lines().find_map(|line| {
                    line.strip_prefix("content-length:")
                        .or_else(|| line.strip_prefix("Content-Length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                });
            }
        }
        if let (Some(header_end), Some(length)) = (find_header_end(&bytes), content_length) {
            if bytes.len() >= header_end + length {
                return String::from_utf8_lossy(&bytes).into_owned();
            }
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}
