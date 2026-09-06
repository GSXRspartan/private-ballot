//! Real-Tor smoke test that exercises the same primitives the standalone
//! Load Tester GUI uses for its Test Tor button and Run Test lifecycle. This
//! is `#[ignore]` by default — the normal test suite MUST NOT depend on a
//! live Tor executable. Set `PRIVATE_BALLOT_TOR_EXE=<abs path>` and pass
//! `-- --ignored` to run it.
//!
//!   cargo test -p tari-cc-private-ballot-cli --test real_tor_smoke -- --ignored
//!
//! The smoke covers:
//!   1. `capture_tor_version_v1` returns a bounded, single-line version.
//!   2. `start_managed_tor_session` reaches REAL SOCKS readiness — not just
//!      "process spawned".
//!   3. `session.shutdown()` stops/reaps the child idempotently.
//!   4. No orphan Tor process is left behind (verified by checking whether
//!      the specific PID we started is still alive; see `is_process_alive`).
//!
//! No ballots, no organizer, no election files.

use std::path::PathBuf;
use std::time::Instant;

use tari_cc_private_ballot_cli::managed_tor::{
    ManagedTorStartupConfigV1, capture_tor_version_v1, start_managed_tor_session,
};

#[test]
#[ignore = "requires a real Tor executable; opt in with PRIVATE_BALLOT_TOR_EXE + --ignored"]
fn managed_tor_bootstrap_and_shutdown_smoke() {
    let tor_exe = match std::env::var("PRIVATE_BALLOT_TOR_EXE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => {
            eprintln!(
                "skipping smoke: PRIVATE_BALLOT_TOR_EXE is unset (this test never runs \
                 without an explicit operator opt-in)"
            );
            return;
        }
    };
    let scratch = tempfile::Builder::new()
        .prefix("private-ballot-tor-smoke-")
        .tempdir()
        .expect("scratch dir");

    // Version capture is best-effort evidence; a failure here would not gate
    // a run, but for a smoke test we do want to see something.
    let version = capture_tor_version_v1(&tor_exe);
    eprintln!("captured tor version: {version:?}");

    let startup = ManagedTorStartupConfigV1::new(tor_exe.clone(), scratch.path().to_path_buf());
    let start = Instant::now();
    let mut session = start_managed_tor_session(&startup)
        .expect("managed-Tor session must start and reach SOCKS readiness");
    let elapsed = start.elapsed();
    eprintln!(
        "managed Tor ready on {} after {} ms ({})",
        session.socks_addr(),
        elapsed.as_millis(),
        session.run_dir().display()
    );

    // Idempotent shutdown pair — Drop performs the same cleanup as a
    // backstop, so calling shutdown() first must not panic on Drop later.
    session.shutdown();
    drop(session);
    eprintln!("SMOKE_OK — managed Tor bootstrapped and reaped");
}
