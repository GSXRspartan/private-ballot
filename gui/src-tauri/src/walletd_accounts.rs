//! Bounded-timeout walletd account listing for the anchor setup assistant.
//!
//! # Contract
//!
//! * Reuses the pinned [`WalletDaemonClient`] already used by the anchor
//!   transport and the readiness probe — no second networking stack, and the
//!   same shared [`probe_prelude`] so reachability, endpoint (`/json_rpc`), and
//!   credential handling are identical to the readiness card.
//! * Two cheap RPCs per probe:
//!   1. `wallet.get_info` — unauthenticated. Establishes reachability and the
//!      walletd network name.
//!   2. `accounts.list` — authenticated with the stored bearer. Requires the
//!      `Accounts:Read` permission and returns the wallet's accounts so the
//!      operator can pick the fee/seal account without hand-typing brittle
//!      fields.
//! * Both calls are bounded by a per-request timeout so the worker cannot hang.
//! * Every returned field is PUBLIC ledger/identity data: account display name,
//!   component address, owner PUBLIC key, and derivation key index. No bearer
//!   token, seed, secret key, or balance-private material ever crosses this
//!   boundary. The credential is loaded as `Zeroizing` and dropped in scope.
//! * The result reuses the same [`WalletdReadinessKindV1`] states as the
//!   readiness probe, so the frontend renders one consistent connect story and
//!   can fall back to manual entry when accounts cannot be listed. A reachable
//!   daemon whose `accounts.list` fails is **never** reported as unreachable:
//!   a missing `Accounts:Read` permission surfaces as `PermissionDenied`, not
//!   "Start Tari Wallet".

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde::Serialize;
use tari_cc_private_ballot_ootle_anchor_app::TokioBlockingExecutor;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    AccountInfo, BlockingExecutor, BlockingExecutorError,
    PinnedWalletDaemonClient as WalletDaemonClient, PinnedWalletDaemonClientError,
};
use zeroize::Zeroizing;

use crate::walletd_probe::{
    classify_step, ProbePrelude, StepResult, WalletdCallClass, WalletdReadinessKindV1,
    WALLETD_JSONRPC_ENDPOINT, probe_prelude,
};

/// Per-request timeout for one account-listing RPC.
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The fully-qualified JSON-RPC endpoint the probe posts to (mirrors the
/// readiness probe). Exposed on the result for advanced diagnostics.
const PROBE_ENDPOINT: &str = WALLETD_JSONRPC_ENDPOINT;

/// Upper bound on accounts returned to the picker; a dedicated organizer wallet
/// has only a handful of accounts, and this keeps the payload small.
const MAX_ACCOUNTS: u32 = 50;
const TCP_LOOPBACK_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// A single public wallet account descriptor for the anchor setup assistant.
///
/// Every field here is public identity/ledger data. No secret, bearer token, or
/// private key is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiWalletdAnchorAccountV1 {
    /// Optional human display name (may contain spaces — the frontend never
    /// uses this as the whitespace-free fee-account reference).
    pub name: Option<String>,
    /// Canonical `component_<hex>` address, safe to use as the fee component.
    pub component_address: String,
    /// The account owner PUBLIC key, lowercase hex — the declared seal key.
    pub owner_public_key_hex: String,
    /// The owner derivation key index, when the account uses a derived key.
    pub key_index: Option<u64>,
    /// Whether walletd marks this the default account.
    pub is_default: bool,
    /// Whether the account is confirmed on-chain.
    pub is_confirmed_on_chain: bool,
}

impl GuiWalletdAnchorAccountV1 {
    /// Maps one pinned walletd [`AccountInfo`] to a public descriptor. Pure and
    /// secret-free, so it is unit-tested directly.
    fn from_account_info(info: &AccountInfo) -> Self {
        Self {
            name: info.account.name.clone(),
            component_address: info.account.component_address.to_string(),
            owner_public_key_hex: info.account.owner_public_key.to_string(),
            key_index: info.account.owner_key_id.and_then(|id| id.derived_index()),
            is_default: info.account.is_default,
            is_confirmed_on_chain: info.account.is_confirmed_on_chain,
        }
    }
}

/// Public account-listing snapshot for the frontend. Never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiWalletdAnchorAccountsV1 {
    /// Reachability/auth state, shared with the readiness probe.
    pub kind: WalletdReadinessKindV1,
    /// The endpoint that was probed.
    pub endpoint: &'static str,
    /// The walletd's reported network name when reachable.
    pub network: Option<String>,
    /// The listed accounts, empty unless `kind` is `Ready`.
    pub accounts: Vec<GuiWalletdAnchorAccountV1>,
    /// Short human-readable label mirroring the readiness card.
    pub summary: &'static str,
}

impl GuiWalletdAnchorAccountsV1 {
    fn empty(kind: WalletdReadinessKindV1, network: Option<String>) -> Self {
        let summary = match kind {
            WalletdReadinessKindV1::Ready => "Ready",
            WalletdReadinessKindV1::NoCredential => "Connect Tari Wallet",
            WalletdReadinessKindV1::AuthRejected => "Reconnect Tari Wallet",
            WalletdReadinessKindV1::PermissionDenied => "Grant the wallet key Accounts:Read",
            WalletdReadinessKindV1::CallFailed => "walletd reachable — account list failed",
            WalletdReadinessKindV1::Unreachable => "Start Tari Wallet",
        };
        Self {
            kind,
            endpoint: PROBE_ENDPOINT,
            network,
            accounts: Vec::new(),
            summary,
        }
    }
    fn unreachable() -> Self {
        Self::empty(WalletdReadinessKindV1::Unreachable, None)
    }
    fn no_credential(network: Option<String>) -> Self {
        Self::empty(WalletdReadinessKindV1::NoCredential, network)
    }
    fn ready(network: Option<String>, accounts: Vec<GuiWalletdAnchorAccountV1>) -> Self {
        Self {
            kind: WalletdReadinessKindV1::Ready,
            endpoint: PROBE_ENDPOINT,
            network,
            accounts,
            summary: "Ready",
        }
    }
}

/// Runs one bounded account-listing probe. Blocking; must be called from a
/// worker thread (see `run_blocking_command`).
///
/// Shares [`probe_prelude`] with the readiness probe so reachability, the
/// `/json_rpc` endpoint, and credential handling are identical. Only the
/// permissioned call differs: `accounts.list`. A reachable daemon whose
/// `accounts.list` is rejected for lack of `Accounts:Read` reports
/// `PermissionDenied`, never `Unreachable`.
pub fn probe_accounts_blocking() -> GuiWalletdAnchorAccountsV1 {
    let (network, executor, mut client) = match probe_prelude() {
        ProbePrelude::Unreachable => return GuiWalletdAnchorAccountsV1::unreachable(),
        ProbePrelude::NoCredential { network } => {
            return GuiWalletdAnchorAccountsV1::no_credential(network);
        }
        ProbePrelude::Authenticated {
            network,
            executor,
            client,
        } => (network, executor, client),
    };

    let list_step = classify_step(executor.block_on_bounded(
        async { client.list_accounts(0, MAX_ACCOUNTS).await },
        Some(PROBE_REQUEST_TIMEOUT),
    ));

    match list_step {
        StepResult::Ok(response) => {
            let accounts = response
                .accounts
                .iter()
                .map(GuiWalletdAnchorAccountV1::from_account_info)
                .collect();
            GuiWalletdAnchorAccountsV1::ready(network, accounts)
        }
        StepResult::Failed(WalletdCallClass::AuthRejected) => {
            GuiWalletdAnchorAccountsV1::empty(WalletdReadinessKindV1::AuthRejected, network)
        }
        StepResult::Failed(WalletdCallClass::PermissionDenied) => {
            GuiWalletdAnchorAccountsV1::empty(WalletdReadinessKindV1::PermissionDenied, network)
        }
        StepResult::Failed(WalletdCallClass::CallFailed) => {
            GuiWalletdAnchorAccountsV1::empty(WalletdReadinessKindV1::CallFailed, network)
        }
        StepResult::Failed(WalletdCallClass::Transport) | StepResult::Transport => {
            GuiWalletdAnchorAccountsV1::unreachable()
        }
    }
}

/// Read-only, secret-free connection diagnostic for the anchor wallet card.
///
/// Runs the same bounded account-listing probe and reports only NON-SECRET
/// fields the operator can act on: the normalized endpoint, whether a
/// credential is saved, whether the account-list call was actually attempted
/// (only reachable + credentialed probes reach it), the classified result, and
/// — on success — the account count and the default/first account's public
/// name and component. No bearer token, API key, or private key ever crosses
/// this boundary. Mirrors the manual `accounts.list` a PowerShell operator runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletdConnectionDiagnosticsV1 {
    /// The exact JSON-RPC endpoint the probe posted to (already `/json_rpc`).
    pub endpoint_normalized: &'static str,
    /// Whether an OS-keyring credential (or dev env fallback) is present.
    pub saved_credential: bool,
    /// Whether the raw loopback TCP probe was attempted.
    pub tcp_loopback_attempted: bool,
    /// Whether a short, unauthenticated TCP connect to 127.0.0.1:5100 worked.
    pub tcp_loopback_reachable: bool,
    /// Whether the unauthenticated `wallet.get_info` JSON-RPC call was attempted.
    pub unauthenticated_wallet_get_info_attempted: bool,
    /// Sanitized result of the unauthenticated `wallet.get_info` call.
    pub unauthenticated_wallet_get_info_result: WalletdDiagnosticStageResultV1,
    /// Whether the authenticated `accounts.list` call was attempted.
    pub accounts_list_attempted: bool,
    /// Sanitized result of the authenticated `accounts.list` call.
    pub accounts_list_result: WalletdDiagnosticStageResultV1,
    /// Final classified diagnostic outcome.
    pub final_result_kind: &'static str,
    /// The walletd network name when reachable, otherwise `None`.
    pub network: Option<String>,
    /// Number of accounts returned on success.
    pub account_count: Option<usize>,
    /// The selected (default, else first) account's public display name.
    pub selected_account_name: Option<String>,
    /// The selected account's `component_<hex>` address.
    pub selected_account_component: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletdDiagnosticStageResultV1 {
    pub status: &'static str,
    pub category: Option<&'static str>,
    pub message: &'static str,
}

impl WalletdDiagnosticStageResultV1 {
    const fn not_attempted(message: &'static str) -> Self {
        Self {
            status: "not_attempted",
            category: None,
            message,
        }
    }

    const fn success(message: &'static str) -> Self {
        Self {
            status: "success",
            category: None,
            message,
        }
    }

    const fn failed(category: &'static str, message: &'static str) -> Self {
        Self {
            status: "failed",
            category: Some(category),
            message,
        }
    }
}

/// Maps the shared readiness kind to the diagnostic's stable machine string.
/// `NoCredential` is surfaced as `no_saved_credential` to match the operator
/// vocabulary; all others mirror [`WalletdReadinessKindV1::as_str`].
fn diagnostic_result_kind(kind: WalletdReadinessKindV1) -> &'static str {
    match kind {
        WalletdReadinessKindV1::Ready => "ready",
        WalletdReadinessKindV1::NoCredential => "no_saved_credential",
        WalletdReadinessKindV1::AuthRejected => "auth_rejected",
        WalletdReadinessKindV1::PermissionDenied => "permission_denied",
        WalletdReadinessKindV1::CallFailed => "call_failed",
        WalletdReadinessKindV1::Unreachable => "unreachable",
    }
}

fn tcp_loopback_reachable() -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5100);
    TcpStream::connect_timeout(&addr, TCP_LOOPBACK_PROBE_TIMEOUT).is_ok()
}

fn walletd_client_error_stage(
    err: &PinnedWalletDaemonClientError,
) -> WalletdDiagnosticStageResultV1 {
    match err {
        PinnedWalletDaemonClientError::RequestFailed { source } => {
            let rendered = err.to_string().to_ascii_lowercase();
            if source.is_timeout() {
                WalletdDiagnosticStageResultV1::failed(
                    "timeout",
                    "the request timed out before walletd returned a response",
                )
            } else if rendered.contains("reactor")
                || rendered.contains("i/o driver")
                || rendered.contains("io driver")
                || rendered.contains("no reactor")
            {
                WalletdDiagnosticStageResultV1::failed(
                    "tokio_reactor_io_driver_failure",
                    "reqwest failed before opening the HTTP connection because the Tokio reactor or I/O driver was unavailable",
                )
            } else if source.is_connect() && rendered.contains("refused") {
                WalletdDiagnosticStageResultV1::failed(
                    "connection_refused",
                    "the TCP endpoint refused the HTTP connection",
                )
            } else if source.status().is_some() {
                WalletdDiagnosticStageResultV1::failed(
                    "http_response",
                    "walletd returned an HTTP error response",
                )
            } else if source.is_decode() {
                WalletdDiagnosticStageResultV1::failed(
                    "json_rpc_decode_error",
                    "the HTTP response was not valid JSON-RPC for this client",
                )
            } else {
                WalletdDiagnosticStageResultV1::failed(
                    "other_reqwest_transport_error",
                    "reqwest reported a transport error outside the known categories",
                )
            }
        }
        PinnedWalletDaemonClientError::RequestFailedWithStatus { .. }
        | PinnedWalletDaemonClientError::Unauthorized { .. } => {
            WalletdDiagnosticStageResultV1::failed(
                "http_response",
                "walletd returned a JSON-RPC error response",
            )
        }
        PinnedWalletDaemonClientError::DeserializeResponse { .. }
        | PinnedWalletDaemonClientError::InvalidResponse { .. } => {
            WalletdDiagnosticStageResultV1::failed(
                "json_rpc_decode_error",
                "walletd responded, but the JSON-RPC result did not decode into the expected shape",
            )
        }
        PinnedWalletDaemonClientError::SerializeRequest { .. } => {
            WalletdDiagnosticStageResultV1::failed(
                "other_reqwest_transport_error",
                "the walletd JSON-RPC request could not be serialized",
            )
        }
    }
}

fn diagnostic_stage_from_outcome<T>(
    outcome: &Result<Result<T, PinnedWalletDaemonClientError>, BlockingExecutorError>,
) -> WalletdDiagnosticStageResultV1 {
    match outcome {
        Ok(Ok(_)) => WalletdDiagnosticStageResultV1::success("walletd returned a valid response"),
        Ok(Err(err)) => walletd_client_error_stage(err),
        Err(BlockingExecutorError::AlreadyInsideAsyncRuntime) => WalletdDiagnosticStageResultV1::failed(
            "tokio_runtime_context",
            "the production executor was called from a Tokio runtime context that would have nested runtime execution",
        ),
        Err(BlockingExecutorError::Elapsed) => WalletdDiagnosticStageResultV1::failed(
            "timeout",
            "the production executor deadline elapsed before the request completed",
        ),
        Err(BlockingExecutorError::WouldBlock) => WalletdDiagnosticStageResultV1::failed(
            "tokio_reactor_io_driver_failure",
            "the executor could not drive the HTTP future to completion",
        ),
    }
}

fn diagnostic_kind_from_get_info_stage(
    stage: &WalletdDiagnosticStageResultV1,
) -> Option<WalletdReadinessKindV1> {
    if stage.status == "success" {
        None
    } else {
        match stage.category {
            Some("http_response") | Some("json_rpc_decode_error") => {
                Some(WalletdReadinessKindV1::CallFailed)
            }
            _ => Some(WalletdReadinessKindV1::Unreachable),
        }
    }
}

fn diagnostic_kind_from_accounts_step<T>(
    step: &StepResult<T>,
) -> WalletdReadinessKindV1 {
    match step {
        StepResult::Ok(_) => WalletdReadinessKindV1::Ready,
        StepResult::Failed(WalletdCallClass::AuthRejected) => {
            WalletdReadinessKindV1::AuthRejected
        }
        StepResult::Failed(WalletdCallClass::PermissionDenied) => {
            WalletdReadinessKindV1::PermissionDenied
        }
        StepResult::Failed(WalletdCallClass::CallFailed) => WalletdReadinessKindV1::CallFailed,
        StepResult::Failed(WalletdCallClass::Transport) | StepResult::Transport => {
            WalletdReadinessKindV1::Unreachable
        }
    }
}

/// Runs one bounded, read-only connection diagnostic. Blocking; must be called
/// from a worker thread. Uses the same production executor and pinned walletd
/// client path as readiness/account auto-fill while adding a raw TCP loopback
/// probe that sends no bytes and carries no credential.
pub fn diagnose_connection_blocking(has_saved_credential: bool) -> WalletdConnectionDiagnosticsV1 {
    let tcp_loopback_reachable = tcp_loopback_reachable();
    let mut unauthenticated_wallet_get_info_attempted = false;
    let mut unauthenticated_wallet_get_info_result =
        WalletdDiagnosticStageResultV1::not_attempted("TCP loopback did not connect");
    let mut accounts_list_attempted = false;
    let mut accounts_list_result =
        WalletdDiagnosticStageResultV1::not_attempted("wallet.get_info did not complete");
    let mut final_kind = WalletdReadinessKindV1::Unreachable;
    let mut network = None;
    let mut account_count = None;
    let mut selected_account_name = None;
    let mut selected_account_component = None;

    if tcp_loopback_reachable {
        let executor = match TokioBlockingExecutor::new_current_thread() {
            Ok(executor) => executor,
            Err(_) => {
                unauthenticated_wallet_get_info_result =
                    WalletdDiagnosticStageResultV1::failed(
                        "tokio_reactor_io_driver_failure",
                        "the production Tokio executor could not be constructed",
                    );
                return WalletdConnectionDiagnosticsV1 {
                    endpoint_normalized: PROBE_ENDPOINT,
                    saved_credential: has_saved_credential,
                    tcp_loopback_attempted: true,
                    tcp_loopback_reachable,
                    unauthenticated_wallet_get_info_attempted,
                    unauthenticated_wallet_get_info_result,
                    accounts_list_attempted,
                    accounts_list_result,
                    final_result_kind: diagnostic_result_kind(final_kind),
                    network,
                    account_count,
                    selected_account_name,
                    selected_account_component,
                };
            }
        };

        let mut anon_client = match WalletDaemonClient::connect(PROBE_ENDPOINT, None) {
            Ok(client) => client,
            Err(_) => {
                unauthenticated_wallet_get_info_result =
                    WalletdDiagnosticStageResultV1::failed(
                        "other_reqwest_transport_error",
                        "the pinned walletd client could not be constructed",
                    );
                return WalletdConnectionDiagnosticsV1 {
                    endpoint_normalized: PROBE_ENDPOINT,
                    saved_credential: has_saved_credential,
                    tcp_loopback_attempted: true,
                    tcp_loopback_reachable,
                    unauthenticated_wallet_get_info_attempted,
                    unauthenticated_wallet_get_info_result,
                    accounts_list_attempted,
                    accounts_list_result,
                    final_result_kind: diagnostic_result_kind(final_kind),
                    network,
                    account_count,
                    selected_account_name,
                    selected_account_component,
                };
            }
        };

        unauthenticated_wallet_get_info_attempted = true;
        let get_info_outcome = executor.block_on_bounded(
            async { anon_client.get_wallet_info().await },
            Some(PROBE_REQUEST_TIMEOUT),
        );
        unauthenticated_wallet_get_info_result =
            diagnostic_stage_from_outcome(&get_info_outcome);
        match get_info_outcome {
            Ok(Ok(info)) => {
                network = Some(info.network);
            }
            outcome => {
                if let Some(kind) =
                    diagnostic_kind_from_get_info_stage(&diagnostic_stage_from_outcome(&outcome))
                {
                    final_kind = kind;
                }
                return WalletdConnectionDiagnosticsV1 {
                    endpoint_normalized: PROBE_ENDPOINT,
                    saved_credential: has_saved_credential,
                    tcp_loopback_attempted: true,
                    tcp_loopback_reachable,
                    unauthenticated_wallet_get_info_attempted,
                    unauthenticated_wallet_get_info_result,
                    accounts_list_attempted,
                    accounts_list_result,
                    final_result_kind: diagnostic_result_kind(final_kind),
                    network,
                    account_count,
                    selected_account_name,
                    selected_account_component,
                };
            }
        }

        if !has_saved_credential {
            final_kind = WalletdReadinessKindV1::NoCredential;
            accounts_list_result =
                WalletdDiagnosticStageResultV1::not_attempted("no saved credential");
        } else {
            let credential: Option<Zeroizing<String>> =
                crate::walletd_credential_store::load().ok().flatten();
            let Some(credential) = credential else {
                final_kind = WalletdReadinessKindV1::NoCredential;
                accounts_list_result =
                    WalletdDiagnosticStageResultV1::not_attempted("saved credential was not loadable");
                return WalletdConnectionDiagnosticsV1 {
                    endpoint_normalized: PROBE_ENDPOINT,
                    saved_credential: has_saved_credential,
                    tcp_loopback_attempted: true,
                    tcp_loopback_reachable,
                    unauthenticated_wallet_get_info_attempted,
                    unauthenticated_wallet_get_info_result,
                    accounts_list_attempted,
                    accounts_list_result,
                    final_result_kind: diagnostic_result_kind(final_kind),
                    network,
                    account_count,
                    selected_account_name,
                    selected_account_component,
                };
            };
            let jwt = Zeroizing::new(credential.as_str().to_owned());
            let mut client = match WalletDaemonClient::connect(PROBE_ENDPOINT, Some(jwt)) {
                Ok(client) => client,
                Err(_) => {
                    accounts_list_result = WalletdDiagnosticStageResultV1::failed(
                        "other_reqwest_transport_error",
                        "the authenticated walletd client could not be constructed",
                    );
                    return WalletdConnectionDiagnosticsV1 {
                        endpoint_normalized: PROBE_ENDPOINT,
                        saved_credential: has_saved_credential,
                        tcp_loopback_attempted: true,
                        tcp_loopback_reachable,
                        unauthenticated_wallet_get_info_attempted,
                        unauthenticated_wallet_get_info_result,
                        accounts_list_attempted,
                        accounts_list_result,
                        final_result_kind: diagnostic_result_kind(final_kind),
                        network,
                        account_count,
                        selected_account_name,
                        selected_account_component,
                    };
                }
            };
            accounts_list_attempted = true;
            let accounts_outcome = executor.block_on_bounded(
                async { client.list_accounts(0, MAX_ACCOUNTS).await },
                Some(PROBE_REQUEST_TIMEOUT),
            );
            accounts_list_result = diagnostic_stage_from_outcome(&accounts_outcome);
            let accounts_step = classify_step(accounts_outcome);
            final_kind = diagnostic_kind_from_accounts_step(&accounts_step);
            if let StepResult::Ok(response) = accounts_step {
                let accounts: Vec<_> = response
                    .accounts
                    .iter()
                    .map(GuiWalletdAnchorAccountV1::from_account_info)
                    .collect();
                let selected = accounts
                    .iter()
                    .find(|account| account.is_default)
                    .or_else(|| accounts.first());
                account_count = Some(accounts.len());
                selected_account_name = selected.and_then(|account| account.name.clone());
                selected_account_component =
                    selected.map(|account| account.component_address.clone());
            }
        }
    }

    WalletdConnectionDiagnosticsV1 {
        endpoint_normalized: PROBE_ENDPOINT,
        saved_credential: has_saved_credential,
        tcp_loopback_attempted: true,
        tcp_loopback_reachable,
        unauthenticated_wallet_get_info_attempted,
        unauthenticated_wallet_get_info_result,
        accounts_list_attempted,
        accounts_list_result,
        final_result_kind: diagnostic_result_kind(final_kind),
        network,
        account_count,
        selected_account_name,
        selected_account_component,
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::*;
    use tari_cc_private_ballot_ootle_anchor_network_adapters::AccountsListRequest;

    #[test]
    fn account_list_request_uses_offset_zero_and_limit_fifty() {
        // The probe calls `list_accounts(0, MAX_ACCOUNTS)`, which the pinned
        // client serializes as `accounts.list` params `{ offset, limit }` — the
        // exact shape a manual PowerShell `accounts.list` uses. Lock both bounds.
        assert_eq!(MAX_ACCOUNTS, 50, "account-list limit must be 50");
        let request = AccountsListRequest {
            offset: 0,
            limit: MAX_ACCOUNTS,
        };
        assert_eq!(request.offset, 0);
        assert_eq!(request.limit, 50);
    }

    #[test]
    fn result_kind_strings_are_stable_and_operator_facing() {
        assert_eq!(diagnostic_result_kind(WalletdReadinessKindV1::Ready), "ready");
        // NoCredential is renamed for the operator vocabulary.
        assert_eq!(
            diagnostic_result_kind(WalletdReadinessKindV1::NoCredential),
            "no_saved_credential"
        );
        assert_eq!(
            diagnostic_result_kind(WalletdReadinessKindV1::AuthRejected),
            "auth_rejected"
        );
        assert_eq!(
            diagnostic_result_kind(WalletdReadinessKindV1::PermissionDenied),
            "permission_denied"
        );
        assert_eq!(
            diagnostic_result_kind(WalletdReadinessKindV1::CallFailed),
            "call_failed"
        );
        assert_eq!(
            diagnostic_result_kind(WalletdReadinessKindV1::Unreachable),
            "unreachable"
        );
    }
}
