//! `tari-cc-private-ballot-anchor` — application binary (Slice 4A10, extended
//! by the Phase 4 operator-tooling slice).
//!
//! Thin wrapper that parses the manual flag set, dispatches to the selected
//! mode, and for the lifecycle mode loads the canonical config, verifies the
//! walletd endpoint and indexer endpoint policy, optionally loads walletd auth
//! from the one fixed backend environment variable, constructs one
//! current-thread Tokio runtime, builds the real Slice 4A9 transports, creates
//! or restores the driver, runs it, and prints the human-review summary plus
//! the stable machine code and locator paths.
//!
//! Exit codes:
//!
//! * `0` for finalized acceptance (lifecycle mode), successful config write,
//!   successful evidence verification, or successful snapshot inspection;
//! * non-zero for every non-success or incomplete outcome.
//!
//! The binary accepts no private key, mnemonic, seed, wallet password, raw
//! `KeyId`, or signer secret. Dry-run constructs no transport and submits
//! nothing.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, DriverRunOutcome, MachineReportCode, OperatorDecision,
    TokioBlockingExecutor, WALLETD_AUTH_TOKEN_ENV_VAR_V1, cli,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, RealIndexerTransport, RealWalletdTransport,
    WalletdAnchorNetworkAdapter, WalletdAuthSecret, indexer_endpoint_allowed_for_network_v1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

const EXIT_SUCCESS: ExitCode = ExitCode::SUCCESS;
const EXIT_FAILURE: ExitCode = ExitCode::FAILURE;

fn main() -> ExitCode {
    match run() {
        Ok(()) => EXIT_SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            EXIT_FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    // Parse and validate the argument set before any config loading, transport
    // construction, runtime construction, snapshot mutation, evidence
    // read/write, or transaction submission.
    let mode = cli::parse(&args)?;

    match mode {
        cli::CliMode::WriteConfig(write_args) => {
            tari_cc_private_ballot_ootle_anchor_app::write_config::run(&write_args)
        }
        cli::CliMode::VerifyEvidence { path } => {
            tari_cc_private_ballot_ootle_anchor_app::verify_evidence::run(&path)
        }
        cli::CliMode::InspectSnapshot { path } => {
            tari_cc_private_ballot_ootle_anchor_app::inspect_snapshot::run(&path)
        }
        cli::CliMode::Lifecycle(lifecycle) => run_lifecycle(lifecycle),
    }
}

fn run_lifecycle(lifecycle: cli::LifecycleArgs) -> Result<(), String> {
    let cli::LifecycleArgs {
        config_path,
        archive_path,
        approve,
        reject,
        dry_run,
    } = lifecycle;

    let Some(config_path) = config_path else {
        return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
    };

    let config = AnchorAppConfig::from_canonical_file(std::path::Path::new(&config_path))
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;

    if dry_run {
        return print_dry_run(&config)
            .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned());
    }

    // Refuse caller-controlled remote endpoints before resolving any bearer
    // token. This CLI shares the GUI/Tauri fixed loopback policy and never
    // accepts an environment-variable selector from its caller.
    ensure_loopback_endpoints(&config)?;

    let Some(archive_path) = archive_path else {
        return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
    };

    // Resolve the optional bearer only after endpoint validation, from the
    // single backend-owned variable shared with the GUI/Tauri path. Its value
    // never enters canonical config bytes, Debug output, snapshots, evidence,
    // logs, or error strings.
    let auth = load_loopback_walletd_auth(&config, env::var)?;
    let config = config
        .with_walletd_auth(auth)
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;

    let executor = TokioBlockingExecutor::new_current_thread()
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;
    let network = config.anchor_record_network().clone();
    let walletd_endpoint = config.network_adapter().walletd_endpoint().clone();
    let indexer_endpoint = config.network_adapter().indexer_endpoint().clone();
    // Apply the configured per-request timeout at the real network boundary.
    let request_timeout = config
        .network_adapter()
        .request_timeout_secs()
        .map(std::time::Duration::from_secs);

    let walletd_transport = RealWalletdTransport::new(
        &walletd_endpoint,
        config.network_adapter().auth(),
        request_timeout,
        executor.clone(),
    )
    .map_err(|_| MachineReportCode::TransportFailure.as_str().to_owned())?;
    let indexer_transport =
        RealIndexerTransport::new(&indexer_endpoint, request_timeout, executor.clone())
            .map_err(|_| MachineReportCode::TransportFailure.as_str().to_owned())?;

    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd_transport, network.clone());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer_transport);

    let decision = if approve {
        OperatorDecision::Approve
    } else if reject {
        OperatorDecision::Reject
    } else {
        OperatorDecision::NoDecision
    };

    let mut driver = AnchorAppDriver::restore_live(
        config,
        walletd_adapter,
        indexer_adapter,
        Path::new(&archive_path),
    )
    .map_err(|error| error.as_str().to_owned())?;
    let outcome = driver
        .run(decision)
        .map_err(|error| error.as_str().to_owned())?;

    print_outcome(&outcome, driver.phase(), driver.transaction_id());
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => Ok(()),
        _ => Err(outcome.report_code().as_str().to_owned()),
    }
}

fn ensure_loopback_endpoints(config: &AnchorAppConfig) -> Result<(), String> {
    let adapter = config.network_adapter();
    if !adapter.walletd_endpoint().is_loopback()
        || !indexer_endpoint_allowed_for_network_v1(adapter.network(), adapter.indexer_endpoint())
    {
        return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
    }
    Ok(())
}

fn load_loopback_walletd_auth(
    config: &AnchorAppConfig,
    read_env: impl FnOnce(&'static str) -> Result<String, env::VarError>,
) -> Result<Option<WalletdAuthSecret>, String> {
    ensure_loopback_endpoints(config)?;
    match read_env(WALLETD_AUTH_TOKEN_ENV_VAR_V1) {
        Ok(raw) => WalletdAuthSecret::new(raw)
            .map(Some)
            .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned()),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(MachineReportCode::ConfigurationFailure.as_str().to_owned())
        }
    }
}

fn print_dry_run(config: &AnchorAppConfig) -> Result<(), ()> {
    let record = OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    );
    let digest = record
        .canonical_hash(&Blake3HashProviderV1)
        .map_err(|_| ())?;
    println!("mode=dry-run");
    println!("purpose=NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR");
    println!("network={}", config.anchor_record_network().as_str());
    println!(
        "manifest_hash={}",
        to_lower_hex(config.archive_manifest_hash().as_bytes())
    );
    println!(
        "archive_hash={}",
        to_lower_hex(config.archive_hash().as_bytes())
    );
    println!("anchor_digest={}", to_lower_hex(digest.as_bytes()));
    println!("snapshot_path={}", config.snapshot_path().display());
    println!("evidence_path={}", config.evidence_path().display());
    Ok(())
}

fn print_outcome(
    outcome: &DriverRunOutcome,
    phase: tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase,
    transaction_id: Option<&tari_cc_private_ballot_anchor_transport::AnchorTransactionId>,
) {
    let code = outcome.report_code();
    println!("machine_code={}", code.as_str());
    println!("phase={}", phase.as_str());
    if let Some(tx) = transaction_id {
        println!("transaction_id={}", tx.as_str());
    } else {
        println!("transaction_id=none");
    }
    if let Some(evidence) = outcome.evidence() {
        println!("incident_kind={}", evidence.incident_kind().as_str());
        println!("{}", evidence.human_review_summary());
    } else {
        println!("no_evidence_non_terminal");
    }
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;

    use super::{
        WALLETD_AUTH_TOKEN_ENV_VAR_V1, ensure_loopback_endpoints, load_loopback_walletd_auth,
    };
    use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
    use tari_cc_private_ballot_anchor_transport::{AnchorAccountReference, AnchorMaxFeeV1};
    use tari_cc_private_ballot_archive::ArchiveHashV1;
    use tari_cc_private_ballot_ootle_anchor_app::{AnchorAppConfig, AnchorLiveApprovalFactsV1};
    use tari_cc_private_ballot_ootle_anchor_network_adapters::{
        IndexerEndpoint, NetworkAdapterConfig, WalletdEndpoint,
    };
    use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
        WalletdFeeComponentRef, WalletdSealSignerRef,
    };
    use tari_cc_private_ballot_protocol::ManifestHash;

    fn config(walletd: &str, indexer: &str) -> AnchorAppConfig {
        let network = OotleNetworkIdV1::new("esmeralda".to_owned()).expect("network");
        let component =
            WalletdFeeComponentRef::parse(&("component_".to_owned() + &"11".repeat(32)))
                .expect("fee component");
        let adapter = NetworkAdapterConfig::new(
            network.clone(),
            WalletdEndpoint::parse(walletd).expect("walletd endpoint"),
            IndexerEndpoint::parse(indexer).expect("indexer endpoint"),
            component,
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(1_000),
            Some(30),
            8,
            None,
        )
        .expect("network adapter");
        let facts = AnchorLiveApprovalFactsV1::new(
            2,
            2,
            false,
            false,
            "seal-public-key-attested".to_owned(),
            true,
            true,
        )
        .expect("facts");
        AnchorAppConfig::new_archive_verified_with_live_approval_facts(
            adapter,
            AnchorAccountReference::new("fee-account".to_owned()).expect("account"),
            ManifestHash::new([0x11; 32]),
            ArchiveHashV1::new([0x22; 32]),
            network,
            PathBuf::from("C:/tmp/snapshot.cbor"),
            PathBuf::from("C:/tmp/evidence.cbor"),
            1,
            1,
            None,
            facts,
        )
    }

    #[test]
    fn nonloopback_endpoint_is_rejected_before_auth_resolution() {
        let config = config("http://10.0.0.5:12009", "http://127.0.0.1:12500");
        let read = Cell::new(false);
        let result = load_loopback_walletd_auth(&config, |_| {
            read.set(true);
            Ok("must-not-be-read".to_owned())
        });
        assert!(result.is_err());
        assert!(
            !read.get(),
            "endpoint rejection must precede secret resolution"
        );
        assert!(ensure_loopback_endpoints(&config).is_err());
    }

    #[test]
    fn loopback_cli_resolves_only_the_shared_fixed_auth_variable() {
        let config = config("http://127.0.0.1:12009", "http://127.0.0.1:12500");
        let mut selected = String::new();
        let auth = load_loopback_walletd_auth(&config, |name| {
            selected = name.to_owned();
            Ok("fixed-walletd-token".to_owned())
        })
        .expect("loopback auth read");
        assert_eq!(selected, WALLETD_AUTH_TOKEN_ENV_VAR_V1);
        assert!(auth.is_some());
    }
}
