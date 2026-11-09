#![forbid(unsafe_code)]

//! Hosted backend binary (Stage 3).
//!
//! Public plane: `127.0.0.1:8788` by default (override only to another
//! loopback address unless PRIVATE_BALLOT_HOSTED_ALLOW_PUBLIC_BIND=1);
//! this is the only listener Cloudflare may route to. Admin plane:
//! `127.0.0.1:8789` loopback-only, never routed through Cloudflare. Both
//! serve the same SQLite database (PRIVATE_BALLOT_HOSTED_DB, default
//! hosted.db) and shut down gracefully on Ctrl-C / SIGTERM. No
//! request-body, secret, or full-IP logging.

use std::sync::Arc;

use tari_cc_private_ballot_hosted::{AppState, HostedConfig, SqliteStorage, serve_with_state};

#[tokio::main]
async fn main() {
    let config = match HostedConfig::from_env() {
        Ok(c) => c,
        Err(e) => { eprintln!("{}", e.as_str()); std::process::exit(2); }
    };
    let storage = match SqliteStorage::open(&config.db_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("{}", e.as_str()); std::process::exit(1); }
    };
    eprintln!("private-ballot-hosted starting (service={}, api_version={}, public_bind={}, admin_bind={}, db={})", config.service_name, config.api_version, config.bind, config.admin_bind, config.db_path.display());
    let state = Arc::new(AppState::new(config, Arc::new(storage)));
    let shutdown = async { let _ = tokio::signal::ctrl_c().await; };
    if let Err(code) = serve_with_state(state, shutdown).await { eprintln!("{code}"); std::process::exit(1); }
}
