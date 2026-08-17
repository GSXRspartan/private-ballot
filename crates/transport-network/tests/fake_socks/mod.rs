//! Deterministic loopback fake SOCKS5 server for network-primitive tests.
//!
//! It requires no installed Tor, no internet, and no DNS. It captures the exact
//! SOCKS greeting, the exact SOCKS `CONNECT` request (so tests can assert the
//! literal onion hostname was sent with `ATYP = DOMAINNAME`), and the exact HTTP
//! request bytes, then produces a scripted HTTP response — or transparently
//! tunnels the established stream to a real loopback collector.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::JoinHandle;

/// A one-shot HTTP responder that maps the captured request bytes to a response.
pub type HttpResponder = Box<dyn FnOnce(&[u8]) -> Vec<u8> + Send>;

/// What the fake server should do once a SOCKS `CONNECT` has been established.
pub enum HttpBehavior {
    /// Read the full HTTP request, then send these exact response bytes.
    Respond(Vec<u8>),
    /// Read the full HTTP request, then send the bytes the closure returns.
    RespondWith(HttpResponder),
    /// Read the full HTTP request, send these exact response bytes, flush, then
    /// hold the connection open (WITHOUT closing) for the given duration before
    /// returning. This reproduces a peer whose `Connection: close` teardown is
    /// delayed — as a real Tor v3 circuit's RELAY_END can be — so a client that
    /// insists on a trailing clean-EOF read would block on its response timeout
    /// even though the response body is already complete.
    RespondThenHold(Vec<u8>, std::time::Duration),
    /// Bridge the established SOCKS stream to a real loopback target (collector).
    TunnelTo(SocketAddr),
}

/// Scripted fake-server behavior.
pub struct FakeSocks5Config {
    /// Bytes sent in reply to the SOCKS greeting (usually `[0x05, 0x00]`).
    pub method_reply: Vec<u8>,
    /// Close the connection immediately after sending `method_reply`.
    pub stop_after_method: bool,
    /// Bytes sent in reply to the SOCKS `CONNECT` (usually a success reply).
    pub connect_reply: Vec<u8>,
    /// Close the connection immediately after sending `connect_reply`.
    pub stop_after_connect: bool,
    /// HTTP-stage behavior.
    pub behavior: HttpBehavior,
}

impl FakeSocks5Config {
    /// A fully successful SOCKS5 negotiation + fixed HTTP response.
    pub fn success(http_response: Vec<u8>) -> Self {
        Self {
            method_reply: vec![0x05, 0x00],
            stop_after_method: false,
            connect_reply: success_connect_reply(),
            stop_after_connect: false,
            behavior: HttpBehavior::Respond(http_response),
        }
    }

    /// A fully successful negotiation whose HTTP response is computed from the
    /// captured request bytes.
    pub fn success_with(callback: HttpResponder) -> Self {
        Self {
            method_reply: vec![0x05, 0x00],
            stop_after_method: false,
            connect_reply: success_connect_reply(),
            stop_after_connect: false,
            behavior: HttpBehavior::RespondWith(callback),
        }
    }

    /// A successful negotiation that tunnels to a real loopback collector.
    pub fn tunnel(target: SocketAddr) -> Self {
        Self {
            method_reply: vec![0x05, 0x00],
            stop_after_method: false,
            connect_reply: success_connect_reply(),
            stop_after_connect: false,
            behavior: HttpBehavior::TunnelTo(target),
        }
    }
}

/// Standard SOCKS5 success reply: `05 00 00 01 0.0.0.0 0` (IPv4 BND).
#[must_use]
pub fn success_connect_reply() -> Vec<u8> {
    vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Everything the fake server observed on the wire.
#[derive(Default, Debug, Clone)]
pub struct Capture {
    pub greeting: Vec<u8>,
    pub connect_request: Vec<u8>,
    pub http_request: Vec<u8>,
}

/// A running fake server bound to an ephemeral loopback port.
pub struct FakeSocks5Server {
    addr: SocketAddr,
    handle: Option<JoinHandle<Capture>>,
}

impl FakeSocks5Server {
    /// Binds the fake server on `127.0.0.1:0` and services exactly one client.
    pub fn start(config: FakeSocks5Config) -> Self {
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind fake socks");
        let addr = listener.local_addr().expect("fake socks addr");
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = ready_tx.send(());
            serve(&listener, config)
        });
        // Ensure the listener thread is running before returning the address.
        let _ = ready_rx.recv();
        Self {
            addr,
            handle: Some(handle),
        }
    }

    /// The loopback address a carrier should point at as its SOCKS endpoint.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Joins the server thread and returns everything it captured.
    #[must_use]
    pub fn join(mut self) -> Capture {
        self.handle
            .take()
            .expect("server handle")
            .join()
            .expect("fake socks thread")
    }
}

fn serve(listener: &TcpListener, config: FakeSocks5Config) -> Capture {
    let mut capture = Capture::default();
    let Ok((mut stream, _)) = listener.accept() else {
        return capture;
    };

    // --- SOCKS greeting: VER NMETHODS METHODS... ---
    let mut header = [0u8; 2];
    if stream.read_exact(&mut header).is_err() {
        return capture;
    }
    let mut methods = vec![0u8; usize::from(header[1])];
    if stream.read_exact(&mut methods).is_err() {
        return capture;
    }
    capture.greeting.extend_from_slice(&header);
    capture.greeting.extend_from_slice(&methods);

    if stream.write_all(&config.method_reply).is_err() || config.stop_after_method {
        return capture;
    }

    // --- SOCKS CONNECT: VER CMD RSV ATYP <addr> <port> ---
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).is_err() {
        return capture;
    }
    capture.connect_request.extend_from_slice(&head);
    match head[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            let _ = stream.read_exact(&mut addr);
            capture.connect_request.extend_from_slice(&addr);
        }
        0x03 => {
            let mut len = [0u8; 1];
            let _ = stream.read_exact(&mut len);
            capture.connect_request.extend_from_slice(&len);
            let mut host = vec![0u8; usize::from(len[0])];
            let _ = stream.read_exact(&mut host);
            capture.connect_request.extend_from_slice(&host);
        }
        0x04 => {
            let mut addr = [0u8; 16];
            let _ = stream.read_exact(&mut addr);
            capture.connect_request.extend_from_slice(&addr);
        }
        _ => {}
    }
    let mut port = [0u8; 2];
    let _ = stream.read_exact(&mut port);
    capture.connect_request.extend_from_slice(&port);

    if stream.write_all(&config.connect_reply).is_err() || config.stop_after_connect {
        return capture;
    }

    match config.behavior {
        HttpBehavior::TunnelTo(target) => {
            tunnel(stream, target);
        }
        HttpBehavior::Respond(response) => {
            capture.http_request = read_http_request(&mut stream);
            let _ = stream.write_all(&response);
        }
        HttpBehavior::RespondWith(callback) => {
            capture.http_request = read_http_request(&mut stream);
            let response = callback(&capture.http_request);
            let _ = stream.write_all(&response);
        }
        HttpBehavior::RespondThenHold(response, hold) => {
            capture.http_request = read_http_request(&mut stream);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            // Hold the connection open without closing; the client must not need
            // the close to treat a complete exact-length response as delivered.
            std::thread::sleep(hold);
        }
    }
    capture
}

/// Reads one HTTP/1.1 request (headers + exact `Content-Length` body).
fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 512];
    let header_end = loop {
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return buffer,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
        if buffer.len() > 64 * 1024 {
            return buffer;
        }
    };
    let length = content_length(&buffer[..header_end]).unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    buffer
}

fn content_length(header_bytes: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header_bytes).ok()?;
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

fn tunnel(mut client_write: TcpStream, target: SocketAddr) {
    let Ok(mut server_write) = TcpStream::connect(target) else {
        return;
    };
    let Ok(mut client_read) = client_write.try_clone() else {
        return;
    };
    let Ok(mut server_read) = server_write.try_clone() else {
        return;
    };
    let upstream = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut server_write);
        let _ = server_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut server_read, &mut client_write);
    let _ = client_write.shutdown(std::net::Shutdown::Write);
    let _ = upstream.join();
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Builds a minimal HTTP/1.1 response with the fixed octet-stream content type.
#[must_use]
pub fn http_response(status_line: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "{status_line}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A standard `200 OK` response carrying `body`.
#[must_use]
pub fn http_ok(body: &[u8]) -> Vec<u8> {
    http_response("HTTP/1.1 200 OK", body)
}
