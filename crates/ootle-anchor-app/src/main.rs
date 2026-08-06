//! `tari-cc-private-ballot-anchor` — application binary (Slice 4A10).
//!
//! Thin wrapper that parses a small manual flag set, loads the canonical
//! config, optionally loads walletd auth from an environment variable,
//! constructs one current-thread Tokio runtime, builds the real Slice 4A9
//! transports, creates or restores the driver, runs it, and prints the
//! human-review summary plus the stable machine code and locator paths.
//!
//! Exit codes:
//!
//! * `0` only for finalized acceptance;
//! * non-zero for every non-success or incomplete outcome.
//!
//! The binary accepts no private key, mnemonic, seed, wallet password, raw
//! `KeyId`, or signer secret. Dry-run constructs no transport and submits
//! nothing.

use std::env;
use std::process::ExitCode;

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, DriverRunOutcome, MachineReportCode, OperatorDecision,
    TokioBlockingExecutor,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, RealIndexerTransport, RealWalletdTransport,
    WalletdAnchorNetworkAdapter, WalletdAuthSecret,
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
    let config_path = find_flag_value(&args, "--config");
    let auth_env = find_flag_value(&args, "--auth-env");
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    let dry_run = args.iter().any(|a| a == "--dry-run");

    let Some(config_path) = config_path else {
        return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
    };

    let config = AnchorAppConfig::from_canonical_file(std::path::Path::new(&config_path))
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;

    if dry_run {
        return print_dry_run(&config)
            .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned());
    }

    // Load optional walletd auth from the named environment variable. The
    // auth never enters the canonical config, Debug output, snapshots, or
    // evidence.
    let auth = match auth_env {
        Some(name) => env::var(&name)
            .ok()
            .and_then(|raw| WalletdAuthSecret::new(raw).ok()),
        None => None,
    };
    let config = config
        .with_walletd_auth(auth)
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;

    let executor = TokioBlockingExecutor::new_current_thread()
        .map_err(|_| MachineReportCode::ConfigurationFailure.as_str().to_owned())?;
    let network = config.anchor_record_network().clone();
    let walletd_endpoint = config.network_adapter().walletd_endpoint().clone();
    let indexer_endpoint = config.network_adapter().indexer_endpoint().clone();

    let walletd_transport = RealWalletdTransport::new(
        &walletd_endpoint,
        config.network_adapter().auth(),
        executor.clone(),
    )
    .map_err(|_| MachineReportCode::TransportFailure.as_str().to_owned())?;
    let indexer_transport = RealIndexerTransport::new(&indexer_endpoint, executor.clone())
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

    let mut driver = AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter)
        .map_err(|_| MachineReportCode::SnapshotFailure.as_str().to_owned())?;
    let outcome = driver
        .run(decision)
        .map_err(|_| MachineReportCode::TransportFailure.as_str().to_owned())?;

    print_outcome(&outcome, driver.phase(), driver.transaction_id());
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => Ok(()),
        _ => Err(outcome.report_code().as_str().to_owned()),
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

fn find_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
    }
    None
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
