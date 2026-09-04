//! Bounded-timeout walletd readiness probe.
//!
//! # Contract
//!
//! * Reuses the pinned [`WalletDaemonClient`] already used by the anchor
//!   transport — no second networking stack.
//! * The probe targets the walletd **JSON-RPC route** (`/json_rpc`). Pinned
//!   walletd v0.39.2 only mounts JSON-RPC at `/json_rpc` (and `/json-rpc`); a
//!   bare `http://host:port` posts to `/`, hits no route, and the pinned client
//!   surfaces a transport/decode error that looks — falsely — like "walletd is
//!   not reachable". [`ensure_walletd_jsonrpc_path`] normalizes the base URL.
//! * Two cheap RPCs per probe:
//!   1. `wallet.get_info` — unauthenticated. Establishes reachability and
//!      returns the walletd's network name for a diagnostic hint.
//!   2. `transaction_requests.list` — authenticated with the stored bearer.
//!      Requires only the `TransactionRequests:Read` permission that
//!      publishing already needs. Empty response is a success signal.
//! * Both calls are bounded by a per-request timeout so the worker cannot
//!   hang. The whole probe runs off-thread through `run_blocking_command`
//!   in the caller, never on the UI thread.
//! * Reachability is decided by whether walletd **answered as a JSON-RPC
//!   server**, not by whether a call succeeded: a JSON-RPC error response
//!   (401, permission denial, application error) proves the daemon is
//!   reachable. Only a real transport failure (connection refused, timeout,
//!   non-JSON response) becomes [`WalletdReadinessKindV1::Unreachable`].
//! * The credential itself is loaded through
//!   [`walletd_credential_store::load`] and dropped as `Zeroizing` inside
//!   this function's scope; it never appears in the returned status.

use std::time::Duration;

use serde::Serialize;
use tari_cc_private_ballot_ootle_anchor_app::TokioBlockingExecutor;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    BlockingExecutor, BlockingExecutorError, PinnedWalletDaemonClient as WalletDaemonClient,
    PinnedWalletDaemonClientError, TransactionRequestListRequest,
};
use zeroize::Zeroizing;

use crate::walletd_credential_store;

/// Per-request timeout for one probe RPC. Small so a hung walletd cannot
/// keep the readiness worker busy, large enough to survive normal cold
/// SQLite reads on a first-launch wallet.
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The loopback base the app probes. Kept in this module so the frontend never
/// chooses a URL for the probe.
pub const WALLETD_PROBE_BASE: &str = "http://127.0.0.1:5100";

/// The fully-qualified JSON-RPC endpoint the probe posts to. Pinned walletd
/// serves JSON-RPC at `/json_rpc`; derived from the shared normalizer so the
/// probe and the anchor Prepare/publish path can never diverge.
pub const WALLETD_JSONRPC_ENDPOINT: &str = "http://127.0.0.1:5100/json_rpc";

/// How one walletd JSON-RPC call resolved, once transport-versus-application
/// failures have been separated. Every raw client error collapses into exactly
/// one of these, and only [`WalletdCallClass::Transport`] means "not reachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletdCallClass {
    /// The daemon did not answer as a JSON-RPC server (connection refused,
    /// timeout, or a non-JSON response such as posting to the wrong path).
    Transport,
    /// walletd answered 401 for an invalid / expired / revoked credential.
    AuthRejected,
    /// walletd answered 401 whose message reports insufficient permissions: the
    /// credential authenticated but lacks the required scope.
    PermissionDenied,
    /// walletd answered, but this call failed for some other reason (non-401
    /// status, malformed response). Reachable; the specific call did not work.
    CallFailed,
}

/// Classifies a raw pinned-client error. `Unauthorized` covers both a bad token
/// and an insufficient-permission rejection (walletd returns 401 for both); the
/// message string is the only signal that separates them, so we inspect it for
/// the daemon's "Insufficient permissions" wording.
#[must_use]
pub fn classify_walletd_client_error(err: &PinnedWalletDaemonClientError) -> WalletdCallClass {
    use PinnedWalletDaemonClientError as E;
    match err {
        E::RequestFailed { .. } => WalletdCallClass::Transport,
        E::Unauthorized { message } => {
            if message.to_ascii_lowercase().contains("insufficient permission") {
                WalletdCallClass::PermissionDenied
            } else {
                WalletdCallClass::AuthRejected
            }
        }
        E::RequestFailedWithStatus { .. }
        | E::DeserializeResponse { .. }
        | E::SerializeRequest { .. }
        | E::InvalidResponse { .. } => WalletdCallClass::CallFailed,
    }
}

/// Outcome of one bounded probe RPC.
pub enum StepResult<T> {
    /// The call succeeded.
    Ok(T),
    /// The daemon is reachable, but the call itself failed. The class is never
    /// [`WalletdCallClass::Transport`].
    Failed(WalletdCallClass),
    /// The daemon could not be reached at all.
    Transport,
}

/// Splits a bounded-executor outcome into reachability plus call class. An
/// elapsed deadline or executor failure is treated as unreachable/hung so the
/// UI shows "Start Tari Wallet" rather than a false Ready.
#[must_use]
pub fn classify_step<T>(
    outcome: Result<Result<T, PinnedWalletDaemonClientError>, BlockingExecutorError>,
) -> StepResult<T> {
    match outcome {
        Ok(Ok(value)) => StepResult::Ok(value),
        Ok(Err(err)) => match classify_walletd_client_error(&err) {
            WalletdCallClass::Transport => StepResult::Transport,
            other => StepResult::Failed(other),
        },
        Err(_) => StepResult::Transport,
    }
}

/// Maps the authenticated permissioned call's outcome to the final readiness
/// kind. A successful call is [`WalletdReadinessKindV1::Ready`]; every failure
/// keeps the truthful distinction between an auth problem, a permission gap, a
/// reachable-but-failed call, and true unreachability.
#[must_use]
pub fn kind_from_authed_call<T>(step: &StepResult<T>) -> WalletdReadinessKindV1 {
    match step {
        StepResult::Ok(_) => WalletdReadinessKindV1::Ready,
        StepResult::Failed(WalletdCallClass::AuthRejected) => WalletdReadinessKindV1::AuthRejected,
        StepResult::Failed(WalletdCallClass::PermissionDenied) => {
            WalletdReadinessKindV1::PermissionDenied
        }
        StepResult::Failed(WalletdCallClass::CallFailed) => WalletdReadinessKindV1::CallFailed,
        // Transport never appears inside `Failed`, but map defensively.
        StepResult::Failed(WalletdCallClass::Transport) | StepResult::Transport => {
            WalletdReadinessKindV1::Unreachable
        }
    }
}

/// Bounded, human-oriented readiness state for the Tari Anchor card.
/// Every raw walletd error collapses into exactly one of these variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletdReadinessKindV1 {
    /// The walletd JSON-RPC endpoint responded and the stored credential
    /// authenticated successfully.
    Ready,
    /// The walletd JSON-RPC endpoint responded but no walletd credential
    /// is stored yet. The frontend renders **Connect Tari Wallet**.
    NoCredential,
    /// The walletd JSON-RPC endpoint responded but the stored credential
    /// was rejected. The frontend renders **Reconnect Tari Wallet**.
    /// Never surface the raw HTTP status.
    AuthRejected,
    /// The walletd JSON-RPC endpoint responded and the credential
    /// authenticated, but it lacks the permission the call requires. The
    /// frontend renders **Reconnect with the missing permission**.
    PermissionDenied,
    /// The walletd JSON-RPC endpoint responded and the credential
    /// authenticated, but the call itself failed (non-401 status or a
    /// malformed response). Reachable, so never **Start Tari Wallet**.
    CallFailed,
    /// The walletd JSON-RPC endpoint could not be reached at all
    /// (connection refused, timeout, non-JSON response). The frontend renders
    /// **Start Tari Wallet**.
    Unreachable,
}

impl WalletdReadinessKindV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoCredential => "no_credential",
            Self::AuthRejected => "auth_rejected",
            Self::PermissionDenied => "permission_denied",
            Self::CallFailed => "call_failed",
            Self::Unreachable => "unreachable",
        }
    }
}

/// Public readiness snapshot for the frontend. Never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletdReadinessV1 {
    pub kind: WalletdReadinessKindV1,
    /// The endpoint that was probed, for advanced diagnostics.
    pub endpoint: &'static str,
    /// The walletd's reported network name when reachable, otherwise
    /// `None`. Read from `wallet.get_info`.
    pub network: Option<String>,
    /// Short human-readable label for the Tari Anchor card. Never leaks a
    /// raw HTTP status or bearer material.
    pub summary: &'static str,
}

impl WalletdReadinessV1 {
    fn unreachable() -> Self {
        Self {
            kind: WalletdReadinessKindV1::Unreachable,
            endpoint: WALLETD_JSONRPC_ENDPOINT,
            network: None,
            summary: "Start Tari Wallet",
        }
    }
    fn no_credential(network: Option<String>) -> Self {
        Self {
            kind: WalletdReadinessKindV1::NoCredential,
            endpoint: WALLETD_JSONRPC_ENDPOINT,
            network,
            summary: "Connect Tari Wallet",
        }
    }
    fn from_kind(kind: WalletdReadinessKindV1, network: Option<String>) -> Self {
        let summary = match kind {
            WalletdReadinessKindV1::Ready => "Ready",
            WalletdReadinessKindV1::NoCredential => "Connect Tari Wallet",
            WalletdReadinessKindV1::AuthRejected => "Reconnect Tari Wallet",
            WalletdReadinessKindV1::PermissionDenied => "Reconnect Tari Wallet with publishing permission",
            WalletdReadinessKindV1::CallFailed => "walletd reachable — request failed",
            WalletdReadinessKindV1::Unreachable => "Start Tari Wallet",
        };
        Self {
            kind,
            endpoint: WALLETD_JSONRPC_ENDPOINT,
            network,
            summary,
        }
    }
}

/// Steps 1–3 shared by both the readiness probe and the account-listing probe:
/// build the executor, confirm reachability with the unauthenticated
/// `wallet.get_info`, and load the stored credential. Returns the authenticated
/// client and the walletd network on success.
pub enum ProbePrelude {
    /// walletd could not be reached at all.
    Unreachable,
    /// walletd is reachable but no credential is stored yet.
    NoCredential { network: Option<String> },
    /// walletd is reachable and a credential is present; ready for the
    /// permissioned call.
    Authenticated {
        network: Option<String>,
        executor: TokioBlockingExecutor,
        client: WalletDaemonClient,
    },
}

/// Runs the shared reachability + credential prelude against the JSON-RPC
/// endpoint. Blocking; must be called from a worker thread.
pub fn probe_prelude() -> ProbePrelude {
    let executor = match TokioBlockingExecutor::new_current_thread() {
        Ok(executor) => executor,
        Err(_) => return ProbePrelude::Unreachable,
    };

    // Step 1: unauthenticated wallet.get_info against the JSON-RPC route. This
    // has no permission requirement; a JSON-RPC error still proves reachability.
    let mut anon_client = match WalletDaemonClient::connect(WALLETD_JSONRPC_ENDPOINT, None) {
        Ok(client) => client,
        Err(_) => return ProbePrelude::Unreachable,
    };
    let info_step = classify_step(executor.block_on_bounded(
        async { anon_client.get_wallet_info().await },
        Some(PROBE_REQUEST_TIMEOUT),
    ));
    let network = match info_step {
        StepResult::Transport => return ProbePrelude::Unreachable,
        StepResult::Ok(info) => Some(info.network),
        // Reachable (walletd answered), but get_info reported an error. Unusual
        // for an unauthenticated call, yet the daemon is clearly up.
        StepResult::Failed(_) => None,
    };

    // Step 2: load the stored credential; if none, the frontend needs Connect.
    let credential: Option<Zeroizing<String>> = walletd_credential_store::load().ok().flatten();
    let Some(credential) = credential else {
        return ProbePrelude::NoCredential { network };
    };

    // Step 3: authenticated client for the permissioned call.
    let jwt = Zeroizing::new(credential.as_str().to_owned());
    let client = match WalletDaemonClient::connect(WALLETD_JSONRPC_ENDPOINT, Some(jwt)) {
        Ok(client) => client,
        Err(_) => return ProbePrelude::Unreachable,
    };
    ProbePrelude::Authenticated {
        network,
        executor,
        client,
    }
}

/// Runs one bounded readiness probe. Blocking; must be called from a
/// worker thread (see `run_blocking_command`).
pub fn probe_blocking() -> WalletdReadinessV1 {
    let (network, executor, mut client) = match probe_prelude() {
        ProbePrelude::Unreachable => return WalletdReadinessV1::unreachable(),
        ProbePrelude::NoCredential { network } => {
            return WalletdReadinessV1::no_credential(network);
        }
        ProbePrelude::Authenticated {
            network,
            executor,
            client,
        } => (network, executor, client),
    };

    // Authenticated cheap RPC that uses only the same TransactionRequests:Read
    // permission publishing already needs.
    let list_step = classify_step(executor.block_on_bounded(
        async {
            client
                .list_transaction_requests(&TransactionRequestListRequest { status: None })
                .await
        },
        Some(PROBE_REQUEST_TIMEOUT),
    ));
    WalletdReadinessV1::from_kind(kind_from_authed_call(&list_step), network)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The normalizer is centralized in the network-adapters crate (shared with
    // the anchor Prepare/publish path); the shell re-tests it here to lock the
    // probe's endpoint constant to that single source of truth.
    use tari_cc_private_ballot_ootle_anchor_network_adapters::ensure_walletd_jsonrpc_path;

    #[test]
    fn readiness_kind_str_labels_are_stable() {
        assert_eq!(WalletdReadinessKindV1::Ready.as_str(), "ready");
        assert_eq!(WalletdReadinessKindV1::NoCredential.as_str(), "no_credential");
        assert_eq!(WalletdReadinessKindV1::AuthRejected.as_str(), "auth_rejected");
        assert_eq!(
            WalletdReadinessKindV1::PermissionDenied.as_str(),
            "permission_denied"
        );
        assert_eq!(WalletdReadinessKindV1::CallFailed.as_str(), "call_failed");
        assert_eq!(WalletdReadinessKindV1::Unreachable.as_str(), "unreachable");
    }

    #[test]
    fn from_kind_maps_to_expected_summaries() {
        assert_eq!(WalletdReadinessV1::unreachable().summary, "Start Tari Wallet");
        assert_eq!(
            WalletdReadinessV1::no_credential(None).summary,
            "Connect Tari Wallet"
        );
        assert_eq!(
            WalletdReadinessV1::from_kind(
                WalletdReadinessKindV1::AuthRejected,
                Some("esmeralda".into())
            )
            .summary,
            "Reconnect Tari Wallet",
        );
        assert_eq!(
            WalletdReadinessV1::from_kind(WalletdReadinessKindV1::Ready, None).summary,
            "Ready"
        );
    }

    // -- Endpoint normalization: localhost and 127.0.0.1 both target /json_rpc.

    #[test]
    fn ensure_jsonrpc_path_appends_route_for_both_loopback_forms() {
        assert_eq!(
            ensure_walletd_jsonrpc_path("http://127.0.0.1:5100"),
            "http://127.0.0.1:5100/json_rpc"
        );
        assert_eq!(
            ensure_walletd_jsonrpc_path("http://localhost:5100"),
            "http://localhost:5100/json_rpc"
        );
        assert_eq!(
            ensure_walletd_jsonrpc_path("http://127.0.0.1:5100/"),
            "http://127.0.0.1:5100/json_rpc"
        );
    }

    #[test]
    fn ensure_jsonrpc_path_is_idempotent() {
        assert_eq!(
            ensure_walletd_jsonrpc_path("http://127.0.0.1:5100/json_rpc"),
            "http://127.0.0.1:5100/json_rpc"
        );
        assert_eq!(
            ensure_walletd_jsonrpc_path("http://localhost:5100/json-rpc"),
            "http://localhost:5100/json-rpc"
        );
    }

    #[test]
    fn probe_endpoint_constant_targets_the_jsonrpc_route() {
        assert_eq!(
            WALLETD_JSONRPC_ENDPOINT,
            ensure_walletd_jsonrpc_path(WALLETD_PROBE_BASE)
        );
        assert!(WALLETD_JSONRPC_ENDPOINT.ends_with("/json_rpc"));
    }

    // -- Error classification: only a transport failure is "unreachable".

    #[test]
    fn invalid_token_is_auth_rejected_not_unreachable() {
        let err = PinnedWalletDaemonClientError::Unauthorized {
            message: "Access denied. API key is invalid or revoked".to_owned(),
        };
        assert_eq!(
            classify_walletd_client_error(&err),
            WalletdCallClass::AuthRejected
        );
    }

    #[test]
    fn insufficient_permission_is_permission_denied_not_unreachable() {
        let err = PinnedWalletDaemonClientError::Unauthorized {
            message: "Insufficient permissions. Required 'Accounts(Read)'".to_owned(),
        };
        assert_eq!(
            classify_walletd_client_error(&err),
            WalletdCallClass::PermissionDenied
        );
    }

    #[test]
    fn non_401_status_is_call_failed_not_unreachable() {
        let err = PinnedWalletDaemonClientError::RequestFailedWithStatus {
            code: 500,
            message: "internal".to_owned(),
        };
        assert_eq!(classify_walletd_client_error(&err), WalletdCallClass::CallFailed);
        let malformed = PinnedWalletDaemonClientError::InvalidResponse {
            message: "missing result".to_owned(),
        };
        assert_eq!(
            classify_walletd_client_error(&malformed),
            WalletdCallClass::CallFailed
        );
    }

    #[test]
    fn authed_call_failures_never_report_unreachable_when_reachable() {
        // A reachable-but-failed authed call maps to a truthful kind, never
        // Unreachable — that is the regression the whole fix targets.
        assert_eq!(
            kind_from_authed_call(&StepResult::<()>::Failed(WalletdCallClass::PermissionDenied)),
            WalletdReadinessKindV1::PermissionDenied
        );
        assert_eq!(
            kind_from_authed_call(&StepResult::<()>::Failed(WalletdCallClass::AuthRejected)),
            WalletdReadinessKindV1::AuthRejected
        );
        assert_eq!(
            kind_from_authed_call(&StepResult::<()>::Failed(WalletdCallClass::CallFailed)),
            WalletdReadinessKindV1::CallFailed
        );
        assert_eq!(
            kind_from_authed_call(&StepResult::<()>::Ok(())),
            WalletdReadinessKindV1::Ready
        );
        // Only a real transport failure is unreachable.
        assert_eq!(
            kind_from_authed_call(&StepResult::<()>::Transport),
            WalletdReadinessKindV1::Unreachable
        );
    }

    #[test]
    fn classify_step_executor_timeout_is_transport() {
        let outcome: Result<Result<(), PinnedWalletDaemonClientError>, BlockingExecutorError> =
            Err(BlockingExecutorError::Elapsed);
        assert!(matches!(classify_step(outcome), StepResult::Transport));
    }
}
