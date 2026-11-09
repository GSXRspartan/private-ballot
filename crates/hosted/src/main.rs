#![forbid(unsafe_code)]

//! Hosted backend binary (Stage 1 skeleton).
//!
//! Binds to `127.0.0.1:8788` by default (override only to another loopback
//! address), serves `/health` and `/api/v1/status`, and shuts down gracefully
//! on Ctrl-C / SIGTERM. No request-body logging.

use tari_cc_private_ballot_hosted::{HostedConfig, serve};

#[tokio::main]
async fn main() {
    let config = match HostedConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error.as_str());
            std::process::exit(2);
        }
    };
    eprintln!(
        "private-ballot-hosted starting (service={}, api_version={})",
        config.service_name, config.api_version
    );
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    if let Err(code) = serve(config, shutdown).await {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
