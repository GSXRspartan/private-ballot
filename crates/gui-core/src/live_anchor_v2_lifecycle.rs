//! Durable, manually-gated V2 walletd lifecycle.
//!
//! V2 intentionally does not deserialize or reuse a V1 anchor application
//! config. Its lifecycle, evidence, and failure sidecars live under an
//! application-owned root (see [`v2_lifecycle_sidecar_path`],
//! [`v2_evidence_sidecar_path`], [`v2_failure_sidecar_path`]) so authoritative
//! election archives are never mutated by optional V2 anchor state. Every
//! sidecar carries only public transaction/evidence bindings.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorMaxFeeV1, AnchorTemplateBindingV2, AnchorTransactionId, verify_v2_event_receipt,
};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    build_fee_bearing_v2_anchor_transaction, inspect_detected_fee_bearing_v2_anchor_transaction,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, IndexerReceiptWireTransport,
    OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1, V2IndexerReceiptFetchV1, WalletdAnchorNetworkAdapter,
    WalletdWireTransport,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorAdapterError, WalletdEffectiveStatusV1, WalletdFeeComponentRef, WalletdRequestId,
    WalletdSealSignerRef,
};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::live_anchor_v2::v2_event_payload_from_verified_evidence_v1;

const V2_LIFECYCLE_SCHEMA: &str = "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_LIFECYCLE_V1";
const V2_EVIDENCE_SCHEMA: &str = "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V1";
const V2_FAILURE_SCHEMA: &str = "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_FAILURE_EVIDENCE_V1";
const V2_FEE_HEADROOM_NUMERATOR: u64 = 11;
const V2_FEE_HEADROOM_DENOMINATOR: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GuiV2LiveAnchorStepRequestV1 {
    pub archive_directory: String,
    pub payload_hex: String,
    pub expected_digest_hex: String,
    pub fee_component: String,
    pub seal_signer_kind: String,
    pub seal_signer_id: String,
    pub max_fee: u64,
    pub max_epoch_delta: u64,
    pub walletd_endpoint: String,
    pub indexer_endpoint: String,
    #[serde(default)]
    pub use_walletd_auth: bool,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiV2LiveAnchorStepResultV1 {
    pub phase: String,
    pub waiting_for_wallet_approval: bool,
    pub transaction_id: Option<String>,
    pub walletd_request_id: Option<i32>,
    pub estimated_required_fee: Option<u64>,
    pub selected_max_fee: Option<u64>,
    pub wallet_request_status: String,
    pub rejection_reason: Option<String>,
    pub retry_required: bool,
    pub lifecycle_path: String,
    pub evidence_path: String,
    pub failure_path: String,
    pub receipt_verified: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct V2LifecycleSnapshotV1 {
    schema: String,
    archive_directory: String,
    payload_hex: String,
    expected_digest_hex: String,
    network: String,
    template_address: String,
    template_module: String,
    template_function: String,
    template_topic: String,
    template_artifact_digest_hex: String,
    fee_component: String,
    seal_signer_kind: String,
    seal_signer_id: String,
    max_fee: u64,
    #[serde(default)]
    estimated_required_fee: Option<u64>,
    #[serde(default)]
    selected_max_fee: Option<u64>,
    max_epoch: u64,
    walletd_request_id: i32,
    #[serde(default)]
    prior_rejected_walletd_request_ids: Vec<i32>,
    phase: String,
    transaction_id: Option<String>,
    failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct V2AnchorEvidenceSidecarV1 {
    schema: String,
    archive_directory: String,
    transaction_id: String,
    network: String,
    template_address: String,
    template_module: String,
    template_function: String,
    template_topic: String,
    template_artifact_digest_hex: String,
    anchor_digest_hex: String,
    payload_hex: String,
}

/// Immutable failure/debug artifact written beside the archive when a V2
/// receipt is retrieved but does not verify, or when the transaction was
/// rejected. It records only public binding fields and a bounded reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct V2AnchorFailureSidecarV1 {
    schema: String,
    archive_directory: String,
    phase: String,
    network: String,
    template_address: String,
    template_topic: String,
    template_artifact_digest_hex: String,
    anchor_digest_hex: String,
    transaction_id: Option<String>,
    failure_reason: String,
}

/// Returns the V2 lifecycle sidecar path under the app-owned sidecar root,
/// deterministically keyed by the archive directory. Sidecars live OUTSIDE the
/// authoritative archive tree so an authoritative election archive is never
/// mutated by optional V2 anchor lifecycle files.
pub fn v2_lifecycle_sidecar_path(archive_directory: &Path) -> Result<PathBuf, GuiCoreError> {
    app_owned_sidecar_path(archive_directory, "v2-anchor-lifecycle.json")
}

pub fn v2_evidence_sidecar_path(archive_directory: &Path) -> Result<PathBuf, GuiCoreError> {
    app_owned_sidecar_path(archive_directory, "v2-anchor-evidence.json")
}

pub fn v2_failure_sidecar_path(archive_directory: &Path) -> Result<PathBuf, GuiCoreError> {
    app_owned_sidecar_path(archive_directory, "v2-anchor-failure.json")
}

/// Derives a deterministic sidecar path under [`default_app_sidecar_root`],
/// keyed by a stable sanitized projection of the archive directory. The
/// application never writes V2 anchor sidecars inside the archive tree, so any
/// authoritative election archive — regardless of its folder name, path, or
/// location — is left byte-for-byte untouched by the optional V2 lifecycle.
///
/// The derived layout is `<sidecar_root>/<key>/<key>.<suffix>` where `<key>` is
/// [`sanitize_sidecar_component`] applied to the full archive path. Deriving
/// the same key from the same archive path yields the same sidecar directory
/// on every call, so evidence and lifecycle files are rediscovered
/// deterministically on subsequent inspections and application restarts.
fn app_owned_sidecar_path(
    archive_directory: &Path,
    suffix: &str,
) -> Result<PathBuf, GuiCoreError> {
    let archive_str = archive_directory.to_string_lossy();
    if archive_str.trim().is_empty() {
        return Err(v2_path_error());
    }
    let key = sanitize_sidecar_component(&archive_str);
    Ok(default_app_sidecar_root()
        .join(&key)
        .join(format!("{key}.{suffix}")))
}

/// Process-wide override for the app-owned sidecar root, populated only by
/// integration tests through [`__set_v2_anchor_sidecar_root_test_override`].
/// Shipping builds never call the setter, so the real
/// `%LOCALAPPDATA%\Private Ballot\v2-anchor-sidecars\` root is always used
/// in production.
static V2_ANCHOR_SIDECAR_ROOT_TEST_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Test-only hook that redirects the app-owned V2 anchor sidecar root to a
/// caller-supplied directory. Idempotent: only the first call takes effect,
/// so parallel integration tests share one deterministic base while each
/// test's own unique archive path keeps their sanitized keys non-colliding.
/// Shipping code paths never invoke this and it has no effect once set.
#[doc(hidden)]
pub fn __set_v2_anchor_sidecar_root_test_override(root: PathBuf) {
    let _ = V2_ANCHOR_SIDECAR_ROOT_TEST_OVERRIDE.set(root);
}

fn default_app_sidecar_root() -> PathBuf {
    if let Some(override_root) = V2_ANCHOR_SIDECAR_ROOT_TEST_OVERRIDE.get() {
        return override_root.clone();
    }
    if let Some(configured) = std::env::var_os("PRIVATE_BALLOT_V2_ANCHOR_SIDECAR_DIR") {
        return PathBuf::from(configured);
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("Private Ballot")
            .join("v2-anchor-sidecars");
    }
    std::env::current_dir()
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("private-ballot-v2-anchor-sidecars")
}

fn sanitize_sidecar_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(120));
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
        if out.len() >= 120 {
            break;
        }
    }
    if out.is_empty() {
        "archive".to_owned()
    } else {
        out
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_v2_live_anchor_step_with_transports<W, I>(
    request: &GuiV2LiveAnchorStepRequestV1,
    deployment: &AnchorTemplateBindingV2,
    walletd: &mut WalletdAnchorNetworkAdapter<W>,
    indexer: &mut IndexerReceiptNetworkAdapter<I>,
) -> Result<GuiV2LiveAnchorStepResultV1, GuiCoreError>
where
    W: WalletdWireTransport,
    I: IndexerReceiptWireTransport,
{
    let archive_directory = Path::new(&request.archive_directory);
    let lifecycle_path = v2_lifecycle_sidecar_path(archive_directory)?;
    let evidence_path = v2_evidence_sidecar_path(archive_directory)?;
    let failure_path = v2_failure_sidecar_path(archive_directory)?;
    let decision = parse_decision(&request.decision)?;
    let mut snapshot = match load_snapshot(&lifecycle_path)? {
        Some(snapshot) => snapshot,
        None => {
            // No lifecycle snapshot. If a success-evidence sidecar is present, a
            // fully successful publish's snapshot was lost after the evidence
            // write — recover it as terminal success rather than preparing (and
            // creating) a duplicate walletd request. Absent evidence, prepare.
            if evidence_path.exists() {
                let recovered =
                    recover_from_existing_evidence(request, deployment, indexer, &evidence_path)?;
                save_snapshot(&lifecycle_path, &recovered)?;
                return Ok(result(&recovered, &evidence_path, true));
            }
            return prepare(
                request,
                deployment,
                walletd,
                indexer,
                &lifecycle_path,
                &evidence_path,
                Vec::new(),
            );
        }
    };
    ensure_snapshot_matches(&snapshot, request, deployment)?;
    if snapshot.phase == "REJECTED" && decision == "none" {
        let mut prior = snapshot.prior_rejected_walletd_request_ids.clone();
        prior.push(snapshot.walletd_request_id);
        return prepare(
            request,
            deployment,
            walletd,
            indexer,
            &lifecycle_path,
            &evidence_path,
            prior,
        );
    }
    if snapshot.phase == "FAILED" && failed_after_verifier_topic_mismatch(&snapshot) {
        snapshot.phase = "POLLING_RECEIPT".to_owned();
        snapshot.failure_reason = None;
        return poll_receipt(
            &mut snapshot,
            deployment,
            indexer,
            &lifecycle_path,
            &evidence_path,
            &failure_path,
        );
    }
    let request_id = WalletdRequestId::from_walletd(snapshot.walletd_request_id);
    match snapshot.phase.as_str() {
        "WAITING_FOR_WALLET_APPROVAL" => {
            // Reconcile against walletd first so a crash-interrupted or
            // out-of-band approval/submission is recovered rather than repeated.
            let (status, txid) =
                walletd
                    .get_v2_anchor_request_status(request_id)
                    .map_err(|_| {
                        v2_error(
                            "GUI_ANCHOR_V2_WALLETD_STATUS_FAILED",
                            "the walletd V2 request status could not be read",
                        )
                    })?;
            match status {
                WalletdEffectiveStatusV1::Expired => {
                    fail(
                        &mut snapshot,
                        "the walletd approval window expired before the V2 request was approved",
                    );
                    write_failure_evidence(&failure_path, &snapshot);
                }
                WalletdEffectiveStatusV1::Rejected => {
                    reject(
                        &mut snapshot,
                        "Transaction rejected. Prepare a new transaction with an updated fee.",
                    );
                    write_failure_evidence(&failure_path, &snapshot);
                }
                WalletdEffectiveStatusV1::Submitting | WalletdEffectiveStatusV1::Submitted => {
                    // Already advanced past approval (crash after submit, or an
                    // out-of-band submitter). Adopt the sealed id and poll; never
                    // resubmit. If no id is recorded yet, sealing is still in
                    // flight — report progress and let the operator poll again.
                    if txid.is_some() {
                        adopt_submitted(&mut snapshot, txid);
                    } else {
                        return Ok(result(&snapshot, &evidence_path, false));
                    }
                }
                WalletdEffectiveStatusV1::Approved => {
                    snapshot.phase = "APPROVED".to_owned();
                    snapshot.failure_reason = None;
                }
                WalletdEffectiveStatusV1::Pending => {
                    if decision != "approve" {
                        // A poll while still awaiting the explicit approval gate.
                        return Ok(result(&snapshot, &evidence_path, false));
                    }
                    match walletd.approve_v2_anchor_request(request_id) {
                        Ok(outcome) if outcome.status() == WalletdEffectiveStatusV1::Approved => {
                            snapshot.phase = "APPROVED".to_owned();
                            snapshot.failure_reason = None;
                        }
                        Ok(outcome) if outcome.status() == WalletdEffectiveStatusV1::Rejected => {
                            reject(
                                &mut snapshot,
                                "Transaction rejected. Prepare a new transaction with an updated fee.",
                            );
                            write_failure_evidence(&failure_path, &snapshot);
                        }
                        Ok(outcome) if outcome.status() == WalletdEffectiveStatusV1::Expired => {
                            fail(
                                &mut snapshot,
                                "the walletd approval window expired before the V2 request was approved",
                            );
                            write_failure_evidence(&failure_path, &snapshot);
                        }
                        Ok(_) => {
                            fail(
                                &mut snapshot,
                                "walletd returned an invalid approval state for the V2 request",
                            );
                            write_failure_evidence(&failure_path, &snapshot);
                        }
                        Err(error) => fail(&mut snapshot, error.to_string()),
                    }
                }
            }
            save_snapshot(&lifecycle_path, &snapshot)?;
            Ok(result(&snapshot, &evidence_path, false))
        }
        "APPROVED" => {
            let (status, txid) =
                walletd
                    .get_v2_anchor_request_status(request_id)
                    .map_err(|_| {
                        v2_error(
                            "GUI_ANCHOR_V2_WALLETD_STATUS_FAILED",
                            "the walletd V2 request status could not be read",
                        )
                    })?;
            match status {
                WalletdEffectiveStatusV1::Expired => {
                    fail(
                        &mut snapshot,
                        "the walletd approval window expired before the approved V2 request was submitted",
                    );
                    write_failure_evidence(&failure_path, &snapshot);
                }
                WalletdEffectiveStatusV1::Rejected => {
                    reject(
                        &mut snapshot,
                        "Transaction rejected. Prepare a new transaction with an updated fee.",
                    );
                    write_failure_evidence(&failure_path, &snapshot);
                }
                WalletdEffectiveStatusV1::Submitting | WalletdEffectiveStatusV1::Submitted => {
                    // A prior submit already sealed the transaction (or is in
                    // flight); never resubmit — adopt the sealed id and poll.
                    if txid.is_some() {
                        adopt_submitted(&mut snapshot, txid);
                    } else {
                        // Sealing is in progress but no id yet; stay approved and
                        // let the operator poll again without a second submit.
                        return Ok(result(&snapshot, &evidence_path, false));
                    }
                }
                WalletdEffectiveStatusV1::Pending => {
                    fail(
                        &mut snapshot,
                        "the walletd V2 request unexpectedly reverted to pending after approval",
                    );
                    write_failure_evidence(&failure_path, &snapshot);
                }
                WalletdEffectiveStatusV1::Approved => {
                    match walletd.submit_v2_anchor_request(request_id) {
                        Ok(outcome) => {
                            snapshot.transaction_id =
                                Some(outcome.transaction_id().as_str().to_owned());
                            snapshot.phase = "POLLING_RECEIPT".to_owned();
                            snapshot.failure_reason = None;
                        }
                        Err(error @ WalletdAnchorAdapterError::InsufficientFeesPaid { .. }) => {
                            reject(&mut snapshot, walletd_error_reason(&error));
                            write_failure_evidence(&failure_path, &snapshot);
                        }
                        Err(error) => fail(&mut snapshot, error.to_string()),
                    }
                }
            }
            save_snapshot(&lifecycle_path, &snapshot)?;
            Ok(result(&snapshot, &evidence_path, false))
        }
        "POLLING_RECEIPT" => poll_receipt(
            &mut snapshot,
            deployment,
            indexer,
            &lifecycle_path,
            &evidence_path,
            &failure_path,
        ),
        _ => Ok(result(
            &snapshot,
            &evidence_path,
            snapshot.phase == "RECEIPT_VERIFIED",
        )),
    }
}

fn prepare<W, I>(
    request: &GuiV2LiveAnchorStepRequestV1,
    deployment: &AnchorTemplateBindingV2,
    walletd: &mut WalletdAnchorNetworkAdapter<W>,
    indexer: &mut IndexerReceiptNetworkAdapter<I>,
    lifecycle_path: &Path,
    evidence_path: &Path,
    prior_rejected_walletd_request_ids: Vec<i32>,
) -> Result<GuiV2LiveAnchorStepResultV1, GuiCoreError>
where
    W: WalletdWireTransport,
    I: IndexerReceiptWireTransport,
{
    if parse_decision(&request.decision)? != "none" {
        return Err(v2_error(
            "GUI_ANCHOR_V2_PREPARE_DECISION_INVALID",
            "prepare V2 with no decision, then explicitly approve it",
        ));
    }
    let payload_cbor = decode_hex(&request.payload_hex)?;
    let event_payload = v2_event_payload_from_verified_evidence_v1(
        Path::new(&request.archive_directory),
        &payload_cbor,
        &request.expected_digest_hex,
        deployment,
    )?;
    let network = OotleNetworkIdV1::new(event_payload.network().to_owned())
        .map_err(|_| v2_error("GUI_ANCHOR_V2_NETWORK_INVALID", "the V2 network is invalid"))?;
    if walletd.network() != &network {
        return Err(v2_error(
            "GUI_ANCHOR_V2_WALLETD_NETWORK_MISMATCH",
            "walletd is configured for a different network",
        ));
    }
    let observed_epoch = indexer.observed_network_epoch(&network).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_INDEXER_EPOCH_UNAVAILABLE",
            "the indexer did not confirm the V2 network and current epoch",
        )
    })?;
    let max_epoch = observed_epoch
        .checked_add(request.max_epoch_delta)
        .ok_or_else(|| {
            v2_error(
                "GUI_ANCHOR_V2_MAX_EPOCH_INVALID",
                "the V2 max epoch overflows",
            )
        })?;
    let fee_component = WalletdFeeComponentRef::parse(&request.fee_component).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_FEE_COMPONENT_INVALID",
            "the V2 fee component is invalid",
        )
    })?;
    let signer = parse_signer(&request.seal_signer_kind, &request.seal_signer_id)?;
    let dry_run_fee = AnchorMaxFeeV1::from_units(request.max_fee);
    let dry_run_transaction = build_fee_bearing_v2_anchor_transaction(
        &network,
        max_epoch,
        fee_component.component_address(),
        dry_run_fee,
        deployment,
        &event_payload,
    )
    .map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_TRANSACTION_CONSTRUCTION_FAILED",
            "the verified V2 transaction could not be constructed",
        )
    })?;
    let dry_run_detected = walletd
        .detect_v2_anchor_inputs(&dry_run_transaction)
        .map_err(|_| {
            v2_error(
                "GUI_ANCHOR_V2_INPUT_DETECTION_FAILED",
                "walletd input detection failed for the V2 transaction",
            )
        })?;
    inspect_detected_fee_bearing_v2_anchor_transaction(
        &dry_run_detected,
        &network,
        max_epoch,
        fee_component.component_address(),
        dry_run_fee,
        deployment,
        &event_payload,
    )
    .map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_TRANSACTION_MUTATED",
            "walletd input detection changed a bound V2 transaction field",
        )
    })?;
    let estimated_required_fee = walletd
        .estimate_v2_anchor_fee(&dry_run_detected, signer)
        .map_err(|_| {
            v2_error(
                "GUI_ANCHOR_V2_FEE_ESTIMATE_FAILED",
                "walletd dry-run fee estimation failed for the V2 transaction",
            )
        })?;
    let selected_max_fee = select_v2_anchor_fee(estimated_required_fee)?;
    let max_fee = AnchorMaxFeeV1::from_units(selected_max_fee);
    let transaction = build_fee_bearing_v2_anchor_transaction(
        &network,
        max_epoch,
        fee_component.component_address(),
        max_fee,
        deployment,
        &event_payload,
    )
    .map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_TRANSACTION_CONSTRUCTION_FAILED",
            "the verified V2 transaction could not be constructed",
        )
    })?;
    let detected = walletd.detect_v2_anchor_inputs(&transaction).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_INPUT_DETECTION_FAILED",
            "walletd input detection failed for the V2 transaction",
        )
    })?;
    inspect_detected_fee_bearing_v2_anchor_transaction(
        &detected,
        &network,
        max_epoch,
        fee_component.component_address(),
        max_fee,
        deployment,
        &event_payload,
    )
    .map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_TRANSACTION_MUTATED",
            "walletd input detection changed a bound V2 transaction field",
        )
    })?;
    let created = walletd
        .create_v2_anchor_request(&detected, signer, None)
        .map_err(|_| {
            v2_error(
                "GUI_ANCHOR_V2_WALLETD_CREATE_FAILED",
                "walletd did not create the V2 approval request",
            )
        })?;
    let snapshot = V2LifecycleSnapshotV1 {
        schema: V2_LIFECYCLE_SCHEMA.to_owned(),
        archive_directory: request.archive_directory.clone(),
        payload_hex: request.payload_hex.clone(),
        expected_digest_hex: request.expected_digest_hex.clone(),
        network: network.as_str().to_owned(),
        template_address: deployment.template_address().to_owned(),
        template_module: deployment.module().to_owned(),
        template_function: deployment.function().to_owned(),
        template_topic: deployment.full_event_topic(),
        template_artifact_digest_hex: crate::hex::to_lower_hex(deployment.artifact_digest()),
        fee_component: request.fee_component.clone(),
        seal_signer_kind: request.seal_signer_kind.clone(),
        seal_signer_id: request.seal_signer_id.clone(),
        max_fee: selected_max_fee,
        estimated_required_fee: Some(estimated_required_fee),
        selected_max_fee: Some(selected_max_fee),
        max_epoch,
        walletd_request_id: created.walletd_request_id().value(),
        phase: "WAITING_FOR_WALLET_APPROVAL".to_owned(),
        prior_rejected_walletd_request_ids,
        transaction_id: None,
        failure_reason: None,
    };
    save_snapshot(lifecycle_path, &snapshot)?;
    Ok(result(&snapshot, evidence_path, false))
}

fn select_v2_anchor_fee(required_fee: u64) -> Result<u64, GuiCoreError> {
    if required_fee == 0 {
        return Err(v2_error(
            "GUI_ANCHOR_V2_FEE_ESTIMATE_INVALID",
            "walletd returned an invalid zero V2 fee estimate",
        ));
    }
    let headroom = required_fee
        .saturating_mul(V2_FEE_HEADROOM_NUMERATOR)
        .saturating_add(V2_FEE_HEADROOM_DENOMINATOR - 1)
        / V2_FEE_HEADROOM_DENOMINATOR;
    if headroom == 0 || headroom > OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1 {
        return Err(v2_error(
            "GUI_ANCHOR_V2_FEE_ESTIMATE_OUT_OF_POLICY",
            "walletd's V2 fee estimate exceeds the anchor fee policy ceiling",
        ));
    }
    Ok(headroom)
}

fn poll_receipt<I>(
    snapshot: &mut V2LifecycleSnapshotV1,
    deployment: &AnchorTemplateBindingV2,
    indexer: &mut IndexerReceiptNetworkAdapter<I>,
    lifecycle_path: &Path,
    evidence_path: &Path,
    failure_path: &Path,
) -> Result<GuiV2LiveAnchorStepResultV1, GuiCoreError>
where
    I: IndexerReceiptWireTransport,
{
    let transaction_id = snapshot
        .transaction_id
        .as_ref()
        .and_then(|id| AnchorTransactionId::new(id.clone()).ok())
        .ok_or_else(|| {
            v2_error(
                "GUI_ANCHOR_V2_TRANSACTION_ID_MISSING",
                "the submitted V2 transaction id is missing",
            )
        })?;
    let network = OotleNetworkIdV1::new(snapshot.network.clone()).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_NETWORK_INVALID",
            "the stored V2 network is invalid",
        )
    })?;
    let payload = decode_hex(&snapshot.payload_hex)?;
    let event_payload = v2_event_payload_from_verified_evidence_v1(
        Path::new(&snapshot.archive_directory),
        &payload,
        &snapshot.expected_digest_hex,
        deployment,
    )?;
    match indexer.fetch_v2_anchor_receipt(&transaction_id, &network) {
        Ok(V2IndexerReceiptFetchV1::Finalized(receipt)) => match verify_v2_event_receipt(
            &transaction_id,
            &network,
            deployment,
            &event_payload,
            &receipt,
        ) {
            Ok(_) => {
                // Only a receipt that verifies against the locked V2 deployment
                // binding writes the immutable success-evidence sidecar. If a
                // prior crash already wrote identical evidence but did not persist
                // the phase, adopt it idempotently instead of failing closed.
                write_or_adopt_evidence(evidence_path, snapshot)?;
                snapshot.phase = "RECEIPT_VERIFIED".to_owned();
                snapshot.failure_reason = None;
            }
            Err(error) => {
                fail(snapshot, error.to_string());
                write_failure_evidence(failure_path, snapshot);
            }
        },
        Ok(V2IndexerReceiptFetchV1::Rejected(_)) => {
            fail(
                snapshot,
                "the V2 transaction was rejected before a receipt event was available",
            );
            write_failure_evidence(failure_path, snapshot);
        }
        Ok(V2IndexerReceiptFetchV1::Pending) => {
            snapshot.failure_reason = None;
        }
        Ok(V2IndexerReceiptFetchV1::NotFound) => {
            snapshot.failure_reason =
                Some("the submitted V2 transaction receipt is not yet available".to_owned());
        }
        Err(_) => {
            snapshot.failure_reason =
                Some("the indexer could not retrieve the V2 transaction receipt".to_owned());
        }
    }
    save_snapshot(lifecycle_path, snapshot)?;
    Ok(result(
        snapshot,
        evidence_path,
        snapshot.phase == "RECEIPT_VERIFIED",
    ))
}

/// Marks the snapshot as terminally failed with a bounded reason.
fn fail(snapshot: &mut V2LifecycleSnapshotV1, reason: impl Into<String>) {
    snapshot.phase = "FAILED".to_owned();
    snapshot.failure_reason = Some(reason.into());
}

/// Marks the snapshot as terminally rejected by walletd.
fn reject(snapshot: &mut V2LifecycleSnapshotV1, reason: impl Into<String>) {
    snapshot.phase = "REJECTED".to_owned();
    snapshot.failure_reason = Some(reason.into());
}

/// Adopts a walletd-sealed transaction id observed during recovery and advances
/// to receipt polling without ever resubmitting.
fn adopt_submitted(
    snapshot: &mut V2LifecycleSnapshotV1,
    transaction_id: Option<AnchorTransactionId>,
) {
    if let Some(id) = transaction_id {
        snapshot.transaction_id = Some(id.as_str().to_owned());
    }
    snapshot.phase = "POLLING_RECEIPT".to_owned();
    snapshot.failure_reason = None;
}

fn failed_after_verifier_topic_mismatch(snapshot: &V2LifecycleSnapshotV1) -> bool {
    snapshot.transaction_id.is_some()
        && snapshot
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ANCHOR_RECEIPT_WRONG_EVENT_TOPIC"))
}

fn ensure_snapshot_matches(
    snapshot: &V2LifecycleSnapshotV1,
    request: &GuiV2LiveAnchorStepRequestV1,
    deployment: &AnchorTemplateBindingV2,
) -> Result<(), GuiCoreError> {
    if snapshot.schema != V2_LIFECYCLE_SCHEMA
        || snapshot.archive_directory != request.archive_directory
        || snapshot.payload_hex != request.payload_hex
        || snapshot.expected_digest_hex != request.expected_digest_hex
        || snapshot.template_address != deployment.template_address()
        || snapshot.template_module != deployment.module()
        || snapshot.template_function != deployment.function()
        || snapshot.template_topic != deployment.full_event_topic()
        || snapshot.template_artifact_digest_hex
            != crate::hex::to_lower_hex(deployment.artifact_digest())
    {
        return Err(v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_BINDING_MISMATCH",
            "the V2 lifecycle snapshot does not match the verified V2 lock and evidence",
        ));
    }
    Ok(())
}

fn parse_decision(raw: &str) -> Result<&str, GuiCoreError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        value @ ("none" | "approve") => Ok(if value == "approve" {
            "approve"
        } else {
            "none"
        }),
        _ => Err(v2_error(
            "GUI_ANCHOR_V2_DECISION_INVALID",
            "the V2 decision must be none or approve",
        )),
    }
}

fn parse_signer(kind: &str, id: &str) -> Result<WalletdSealSignerRef, GuiCoreError> {
    let id = id.parse::<u64>().map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_SIGNER_INVALID",
            "the V2 wallet signer id is invalid",
        )
    })?;
    match kind {
        "account" => Ok(WalletdSealSignerRef::AccountKey { index: id }),
        "transaction" => Ok(WalletdSealSignerRef::TransactionKey { index: id }),
        "imported" => Ok(WalletdSealSignerRef::ImportedKey { local_key_id: id }),
        _ => Err(v2_error(
            "GUI_ANCHOR_V2_SIGNER_INVALID",
            "the V2 wallet signer kind is invalid",
        )),
    }
}

fn load_snapshot(path: &Path) -> Result<Option<V2LifecycleSnapshotV1>, GuiCoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_READ_FAILED",
            "the V2 lifecycle sidecar could not be read",
        )
    })?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_INVALID",
            "the V2 lifecycle sidecar is invalid",
        )
    })
}

/// Persists the mutable lifecycle snapshot with a crash-safe atomic replace:
/// the JSON is written to a unique sibling temp file, flushed and `fsync`-ed,
/// then renamed over the destination (an atomic replace on both POSIX and
/// Windows), and finally the directory entry is `fsync`-ed. A crash therefore
/// leaves either the previous snapshot or the new one — never a torn file.
fn save_snapshot(path: &Path, snapshot: &V2LifecycleSnapshotV1) -> Result<(), GuiCoreError> {
    let bytes = serde_json::to_vec_pretty(snapshot).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_WRITE_FAILED",
            "the V2 lifecycle sidecar could not be encoded",
        )
    })?;
    write_bytes_atomic_replace(path, &bytes).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_WRITE_FAILED",
            "the V2 lifecycle sidecar could not be written",
        )
    })
}

/// Builds the immutable success-evidence record from a verified snapshot.
fn build_evidence(
    snapshot: &V2LifecycleSnapshotV1,
) -> Result<V2AnchorEvidenceSidecarV1, GuiCoreError> {
    Ok(V2AnchorEvidenceSidecarV1 {
        schema: V2_EVIDENCE_SCHEMA.to_owned(),
        archive_directory: snapshot.archive_directory.clone(),
        transaction_id: snapshot.transaction_id.clone().ok_or_else(|| {
            v2_error(
                "GUI_ANCHOR_V2_TRANSACTION_ID_MISSING",
                "the submitted V2 transaction id is missing",
            )
        })?,
        network: snapshot.network.clone(),
        template_address: snapshot.template_address.clone(),
        template_module: snapshot.template_module.clone(),
        template_function: snapshot.template_function.clone(),
        template_topic: snapshot.template_topic.clone(),
        template_artifact_digest_hex: snapshot.template_artifact_digest_hex.clone(),
        anchor_digest_hex: snapshot.expected_digest_hex.clone(),
        payload_hex: snapshot.payload_hex.clone(),
    })
}

/// Reads and parses an existing evidence sidecar. A malformed record is a
/// fail-closed error, never silently ignored.
fn load_evidence(path: &Path) -> Result<V2AnchorEvidenceSidecarV1, GuiCoreError> {
    let bytes = fs::read(path).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_READ_FAILED",
            "the V2 evidence sidecar could not be read",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_INVALID",
            "the V2 evidence sidecar beside this archive is not a valid V2 evidence record",
        )
    })
}

/// Finalizes success by writing the evidence sidecar, OR — if one already exists
/// (a crash after the evidence write but before the snapshot advanced to
/// RECEIPT_VERIFIED) — adopting it only when it is byte-for-byte the record this
/// verified snapshot would have written. A different existing record fails
/// closed and is never overwritten.
fn write_or_adopt_evidence(
    path: &Path,
    snapshot: &V2LifecycleSnapshotV1,
) -> Result<(), GuiCoreError> {
    let intended = build_evidence(snapshot)?;
    if path.exists() {
        let existing = load_evidence(path)?;
        if existing == intended {
            // Idempotent recovery: the prior write already persisted this exact
            // verified evidence. Adopt it without overwriting.
            return Ok(());
        }
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
            "a different V2 evidence sidecar already exists beside this archive; refusing to overwrite valid evidence",
        ));
    }
    let bytes = serde_json::to_vec_pretty(&intended).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_WRITE_FAILED",
            "the V2 evidence sidecar could not be encoded",
        )
    })?;
    write_bytes_create_new_sync(path, &bytes).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_WRITE_FAILED",
            "the V2 evidence sidecar could not be written",
        )
    })
}

/// Recovers a lost/absent lifecycle snapshot when a success-evidence sidecar is
/// present (a crash after a fully successful publish). The existing evidence is
/// re-validated against the request bindings, the locked V2 deployment, an
/// independent archive replay, and a freshly re-fetched, re-verified on-chain
/// receipt before it is adopted as terminal success. This never creates a new
/// walletd request, so it cannot double-publish. Returns the reconstructed
/// terminal snapshot on success.
fn recover_from_existing_evidence<I>(
    request: &GuiV2LiveAnchorStepRequestV1,
    deployment: &AnchorTemplateBindingV2,
    indexer: &mut IndexerReceiptNetworkAdapter<I>,
    evidence_path: &Path,
) -> Result<V2LifecycleSnapshotV1, GuiCoreError>
where
    I: IndexerReceiptWireTransport,
{
    let evidence = load_evidence(evidence_path)?;
    // Bind the evidence to this request and the locked deployment.
    if evidence.schema != V2_EVIDENCE_SCHEMA
        || evidence.archive_directory != request.archive_directory
        || evidence.payload_hex != request.payload_hex
        || evidence.anchor_digest_hex != request.expected_digest_hex
        || evidence.template_address != deployment.template_address()
        || evidence.template_module != deployment.module()
        || evidence.template_function != deployment.function()
        || evidence.template_topic != deployment.full_event_topic()
        || evidence.template_artifact_digest_hex
            != crate::hex::to_lower_hex(deployment.artifact_digest())
    {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
            "the existing V2 evidence does not match this request and locked deployment",
        ));
    }
    // Independent archive + lock replay of the detached evidence.
    let payload_cbor = decode_hex(&request.payload_hex)?;
    let event_payload = v2_event_payload_from_verified_evidence_v1(
        Path::new(&request.archive_directory),
        &payload_cbor,
        &request.expected_digest_hex,
        deployment,
    )?;
    let network = OotleNetworkIdV1::new(evidence.network.clone()).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
            "the existing V2 evidence carries an invalid network",
        )
    })?;
    if network.as_str() != event_payload.network() {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
            "the existing V2 evidence network does not match the replayed payload",
        ));
    }
    let transaction_id =
        AnchorTransactionId::new(evidence.transaction_id.clone()).map_err(|_| {
            v2_error(
                "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
                "the existing V2 evidence carries an invalid transaction id",
            )
        })?;
    // Re-fetch and re-verify the on-chain receipt (read-only). A transient
    // indexer condition is recoverable (retry later); a definitive mismatch or a
    // rejected/absent transaction fails closed.
    match indexer.fetch_v2_anchor_receipt(&transaction_id, &network) {
        Ok(V2IndexerReceiptFetchV1::Finalized(receipt)) => {
            verify_v2_event_receipt(
                &transaction_id,
                &network,
                deployment,
                &event_payload,
                &receipt,
            )
            .map_err(|_| {
                v2_error(
                    "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
                    "the existing V2 evidence does not match the on-chain receipt",
                )
            })?;
        }
        Ok(V2IndexerReceiptFetchV1::Rejected(_)) | Ok(V2IndexerReceiptFetchV1::NotFound) => {
            return Err(v2_error(
                "GUI_ANCHOR_V2_EVIDENCE_CONFLICT",
                "the existing V2 evidence claims success but the transaction is rejected or absent on-chain",
            ));
        }
        Ok(V2IndexerReceiptFetchV1::Pending) => {
            return Err(v2_error(
                "GUI_ANCHOR_V2_EVIDENCE_RECHECK_UNAVAILABLE",
                "the V2 receipt is not yet final; retry to confirm the existing evidence",
            ));
        }
        Err(_) => {
            return Err(v2_error(
                "GUI_ANCHOR_V2_EVIDENCE_RECHECK_UNAVAILABLE",
                "the indexer could not re-verify the existing V2 evidence; retry",
            ));
        }
    }
    // Adopt: reconstruct a terminal, verified snapshot from the request +
    // deployment + evidence transaction id. No walletd request is created.
    Ok(V2LifecycleSnapshotV1 {
        schema: V2_LIFECYCLE_SCHEMA.to_owned(),
        archive_directory: request.archive_directory.clone(),
        payload_hex: request.payload_hex.clone(),
        expected_digest_hex: request.expected_digest_hex.clone(),
        network: network.as_str().to_owned(),
        template_address: deployment.template_address().to_owned(),
        template_module: deployment.module().to_owned(),
        template_function: deployment.function().to_owned(),
        template_topic: deployment.full_event_topic(),
        template_artifact_digest_hex: crate::hex::to_lower_hex(deployment.artifact_digest()),
        fee_component: request.fee_component.clone(),
        seal_signer_kind: request.seal_signer_kind.clone(),
        seal_signer_id: request.seal_signer_id.clone(),
        max_fee: request.max_fee,
        estimated_required_fee: None,
        selected_max_fee: Some(request.max_fee),
        max_epoch: 0,
        walletd_request_id: 0,
        prior_rejected_walletd_request_ids: Vec::new(),
        phase: "RECEIPT_VERIFIED".to_owned(),
        transaction_id: Some(evidence.transaction_id.clone()),
        failure_reason: None,
    })
}

/// Best-effort immutable failure/debug artifact written beside the archive when
/// a receipt is retrieved but does not verify, or the transaction was rejected.
///
/// It is written once (create-new); a pre-existing failure artifact from an
/// earlier attempt is preserved. Because it is only debugging evidence and the
/// terminal reason is already recorded durably in the lifecycle snapshot, an I/O
/// or already-exists condition must not mask the terminal state, so this is
/// intentionally infallible from the caller's perspective.
fn write_failure_evidence(path: &Path, snapshot: &V2LifecycleSnapshotV1) {
    let failure = V2AnchorFailureSidecarV1 {
        schema: V2_FAILURE_SCHEMA.to_owned(),
        archive_directory: snapshot.archive_directory.clone(),
        phase: snapshot.phase.clone(),
        network: snapshot.network.clone(),
        template_address: snapshot.template_address.clone(),
        template_topic: snapshot.template_topic.clone(),
        template_artifact_digest_hex: snapshot.template_artifact_digest_hex.clone(),
        anchor_digest_hex: snapshot.expected_digest_hex.clone(),
        transaction_id: snapshot.transaction_id.clone(),
        failure_reason: snapshot
            .failure_reason
            .clone()
            .unwrap_or_else(|| "the V2 anchor lifecycle failed".to_owned()),
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&failure) {
        let _ = write_bytes_create_new_sync(path, &bytes);
    }
}

/// Atomically replaces `path` with `bytes` (temp write + fsync + rename + dir
/// fsync). Any partial state is confined to a temp file that is removed on
/// failure.
fn write_bytes_atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let tmp_path = unique_temp_sibling(path)?;
    let _ = fs::remove_file(&tmp_path);
    let result = (|| -> Result<(), std::io::Error> {
        write_bytes_create_new_sync(&tmp_path, bytes)?;
        fs::rename(&tmp_path, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Creates `path` fresh (fails if it exists), writes `bytes`, and `fsync`s the
/// file before returning.
fn write_bytes_create_new_sync(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Builds a unique temp sibling of `path` in the same directory, so the later
/// rename is a same-filesystem atomic replace.
fn unique_temp_sibling(path: &Path) -> Result<PathBuf, std::io::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"))?;
    Ok(parent.join(format!("{name}.tmp.{now}")))
}

fn result(
    snapshot: &V2LifecycleSnapshotV1,
    evidence_path: &Path,
    receipt_verified: bool,
) -> GuiV2LiveAnchorStepResultV1 {
    let archive_directory = Path::new(&snapshot.archive_directory);
    let lifecycle_path = v2_lifecycle_sidecar_path(archive_directory).unwrap_or_default();
    let failure_path = v2_failure_sidecar_path(archive_directory).unwrap_or_default();
    GuiV2LiveAnchorStepResultV1 {
        phase: snapshot.phase.clone(),
        waiting_for_wallet_approval: snapshot.phase == "WAITING_FOR_WALLET_APPROVAL",
        transaction_id: snapshot.transaction_id.clone(),
        walletd_request_id: Some(snapshot.walletd_request_id),
        estimated_required_fee: snapshot.estimated_required_fee,
        selected_max_fee: snapshot.selected_max_fee.or(Some(snapshot.max_fee)),
        wallet_request_status: wallet_request_status(snapshot),
        rejection_reason: if snapshot.phase == "REJECTED" {
            snapshot.failure_reason.clone()
        } else {
            None
        },
        retry_required: snapshot.phase == "REJECTED",
        lifecycle_path: lifecycle_path.to_string_lossy().into_owned(),
        evidence_path: evidence_path.to_string_lossy().into_owned(),
        receipt_verified,
        failure_path: failure_path.to_string_lossy().into_owned(),
        failure_reason: snapshot.failure_reason.clone(),
    }
}

fn wallet_request_status(snapshot: &V2LifecycleSnapshotV1) -> String {
    match snapshot.phase.as_str() {
        "WAITING_FOR_WALLET_APPROVAL" => "waiting_for_wallet_approval",
        "APPROVED" => "approved",
        "POLLING_RECEIPT" => "submitted_polling_receipt",
        "RECEIPT_VERIFIED" => "receipt_verified",
        "REJECTED" => "rejected",
        "FAILED" => "failed",
        _ => "unknown",
    }
    .to_owned()
}

fn walletd_error_reason(error: &WalletdAnchorAdapterError) -> String {
    match error {
        WalletdAnchorAdapterError::InsufficientFeesPaid { paid, required } => format!(
            "Transaction rejected. Fee too low: paid {paid}, required {required}. Prepare a new transaction with an updated fee."
        ),
        other => other.to_string(),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, GuiCoreError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID",
            "the V2 detached evidence is not valid hex",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        bytes.push(
            (nibble(pair[0]).ok_or_else(|| {
                v2_error(
                    "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID",
                    "the V2 detached evidence is not valid hex",
                )
            })? << 4)
                | nibble(pair[1]).ok_or_else(|| {
                    v2_error(
                        "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID",
                        "the V2 detached evidence is not valid hex",
                    )
                })?,
        );
    }
    Ok(bytes)
}

fn decode_hash32(value: &str) -> Result<[u8; 32], GuiCoreError> {
    let bytes = decode_hex(value)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID",
            "the V2 detached evidence is not valid hex",
        )
    })
}

fn v2_path_error() -> GuiCoreError {
    v2_error(
        "GUI_ANCHOR_V2_SIDECAR_PATH_INVALID",
        "the V2 sidecar must be beside the archive",
    )
}

/// Read-only view of the persisted V2 anchor state for an archive directory.
///
/// This is a HYDRATION-only projection: it never contacts walletd, never
/// contacts the indexer, and never mutates any sidecar. It is intended to be
/// called once when the operator's Manage Election screen mounts on a
/// finalized-and-verified archive, so the UI can render the existing lifecycle
/// (including a FAILED-but-recoverable state with an already-submitted
/// transaction) instead of falling back to a fresh Build/Prepare/Submit flow
/// that would create a duplicate wallet request and republish a new anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiV2LiveAnchorHydratedStateV1 {
    /// True when a lifecycle sidecar is persisted for this archive.
    pub lifecycle_present: bool,
    /// True when the immutable success-evidence sidecar exists.
    pub evidence_present: bool,
    /// True when the failure-evidence sidecar exists.
    pub failure_present: bool,
    pub archive_directory: String,
    pub lifecycle_path: String,
    pub evidence_path: String,
    pub failure_path: String,
    pub payload_hex: Option<String>,
    pub expected_digest_hex: Option<String>,
    pub network: Option<String>,
    pub template_address: Option<String>,
    pub template_module: Option<String>,
    pub template_function: Option<String>,
    pub template_topic: Option<String>,
    pub template_artifact_digest_hex: Option<String>,
    pub fee_component: Option<String>,
    pub seal_signer_kind: Option<String>,
    pub seal_signer_id: Option<String>,
    pub max_fee: Option<u64>,
    pub estimated_required_fee: Option<u64>,
    pub selected_max_fee: Option<u64>,
    pub max_epoch: Option<u64>,
    pub walletd_request_id: Option<i32>,
    pub phase: Option<String>,
    pub transaction_id: Option<String>,
    pub failure_reason: Option<String>,
    /// True when the lifecycle carries an already-submitted transaction whose
    /// receipt has not (yet) been verified and can be advanced by re-polling
    /// the indexer only (no walletd write).
    pub recoverable: bool,
    /// True when a fresh Build/Prepare/Submit flow must be suppressed because
    /// an existing on-chain transaction (or verified evidence) already exists.
    pub blocks_fresh_publish: bool,
    /// True when the lifecycle already terminated with a verified receipt.
    pub receipt_verified: bool,
}

/// Public read-only projection of a V2 evidence JSON file. Every field is
/// public binding data derived from the on-chain V2 anchor record; the file
/// contains no secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiV2AnchorEvidenceFileV1 {
    pub schema: String,
    pub archive_directory: String,
    pub transaction_id: String,
    pub network: String,
    pub template_address: String,
    pub template_module: String,
    pub template_function: String,
    pub template_topic: String,
    pub template_artifact_digest_hex: String,
    pub anchor_digest_hex: String,
    pub payload_hex: String,
}

/// Read and schema-validate one V2 public-anchor evidence JSON file
/// (`*.v2-anchor-evidence.json`). Fail-closed on missing/unreadable file,
/// malformed JSON, and unsupported schema. Read-only; never contacts the
/// network. Returned data is safe to display; callers must still run the
/// cryptographic verifier ([`verify_v2_public_payload_against_archive_v1`])
/// before displaying any "verified" claim.
pub fn read_v2_public_anchor_evidence_file(
    path: &Path,
) -> Result<GuiV2AnchorEvidenceFileV1, GuiCoreError> {
    if !path.exists() {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_FILE_MISSING",
            "the V2 evidence file does not exist at the given path",
        ));
    }
    let sidecar = load_evidence(path)?;
    if sidecar.schema != V2_EVIDENCE_SCHEMA {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_SCHEMA_UNSUPPORTED",
            "the V2 evidence file uses an unsupported schema",
        ));
    }
    validate_evidence_sidecar_public_fields(&sidecar)?;
    Ok(GuiV2AnchorEvidenceFileV1 {
        schema: sidecar.schema,
        archive_directory: sidecar.archive_directory,
        transaction_id: sidecar.transaction_id,
        network: sidecar.network,
        template_address: sidecar.template_address,
        template_module: sidecar.template_module,
        template_function: sidecar.template_function,
        template_topic: sidecar.template_topic,
        template_artifact_digest_hex: sidecar.template_artifact_digest_hex,
        anchor_digest_hex: sidecar.anchor_digest_hex,
        payload_hex: sidecar.payload_hex,
    })
}

fn validate_evidence_sidecar_public_fields(
    sidecar: &V2AnchorEvidenceSidecarV1,
) -> Result<(), GuiCoreError> {
    AnchorTransactionId::new(sidecar.transaction_id.clone()).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_TRANSACTION_INVALID",
            "the V2 evidence file carries an invalid transaction id",
        )
    })?;
    OotleNetworkIdV1::new(sidecar.network.clone()).map_err(|_| {
        v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_NETWORK_INVALID",
            "the V2 evidence file carries an invalid network",
        )
    })?;
    decode_hash32(&sidecar.template_artifact_digest_hex)?;
    decode_hash32(&sidecar.anchor_digest_hex)?;
    let payload = decode_hex(&sidecar.payload_hex)?;
    if payload.is_empty() {
        return Err(v2_error(
            "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID",
            "the V2 detached evidence is not valid hex",
        ));
    }
    Ok(())
}

/// Read the persisted V2 lifecycle and evidence sidecars for `archive_directory`
/// and project them into [`GuiV2LiveAnchorHydratedStateV1`]. Never writes and
/// never contacts the network.
pub fn inspect_v2_live_anchor_state(
    archive_directory: &Path,
) -> Result<GuiV2LiveAnchorHydratedStateV1, GuiCoreError> {
    let lifecycle_path = v2_lifecycle_sidecar_path(archive_directory)?;
    let evidence_path = v2_evidence_sidecar_path(archive_directory)?;
    let failure_path = v2_failure_sidecar_path(archive_directory)?;
    let snapshot = load_snapshot(&lifecycle_path)?;
    let evidence_present = evidence_path.exists();
    let failure_present = failure_path.exists();
    let archive_directory_str = archive_directory.to_string_lossy().into_owned();
    let mut out = GuiV2LiveAnchorHydratedStateV1 {
        lifecycle_present: snapshot.is_some(),
        evidence_present,
        failure_present,
        archive_directory: archive_directory_str,
        lifecycle_path: lifecycle_path.to_string_lossy().into_owned(),
        evidence_path: evidence_path.to_string_lossy().into_owned(),
        failure_path: failure_path.to_string_lossy().into_owned(),
        payload_hex: None,
        expected_digest_hex: None,
        network: None,
        template_address: None,
        template_module: None,
        template_function: None,
        template_topic: None,
        template_artifact_digest_hex: None,
        fee_component: None,
        seal_signer_kind: None,
        seal_signer_id: None,
        max_fee: None,
        estimated_required_fee: None,
        selected_max_fee: None,
        max_epoch: None,
        walletd_request_id: None,
        phase: None,
        transaction_id: None,
        failure_reason: None,
        recoverable: false,
        blocks_fresh_publish: evidence_present,
        receipt_verified: false,
    };
    if let Some(snapshot) = snapshot {
        let receipt_verified = snapshot.phase == "RECEIPT_VERIFIED";
        let has_transaction = snapshot.transaction_id.is_some();
        // Recovery re-runs indexer polling and re-verification. A snapshot is
        // recoverable when a transaction has already been submitted but the
        // receipt has not (yet) been verified. FAILED with the specific verifier
        // topic-mismatch code is explicitly recoverable in
        // `run_v2_live_anchor_step_with_transports`.
        let recoverable_phase = has_transaction
            && (snapshot.phase == "POLLING_RECEIPT"
                || (snapshot.phase == "FAILED" && failed_after_verifier_topic_mismatch(&snapshot)));
        // A submitted transaction (or written evidence) means Build/Prepare/
        // Submit must not be the primary path — the existing transaction must
        // be resolved before a replacement is ever considered.
        let blocks_fresh_publish = evidence_present || has_transaction;
        out.payload_hex = Some(snapshot.payload_hex.clone());
        out.expected_digest_hex = Some(snapshot.expected_digest_hex.clone());
        out.network = Some(snapshot.network.clone());
        out.template_address = Some(snapshot.template_address.clone());
        out.template_module = Some(snapshot.template_module.clone());
        out.template_function = Some(snapshot.template_function.clone());
        out.template_topic = Some(snapshot.template_topic.clone());
        out.template_artifact_digest_hex = Some(snapshot.template_artifact_digest_hex.clone());
        out.fee_component = Some(snapshot.fee_component.clone());
        out.seal_signer_kind = Some(snapshot.seal_signer_kind.clone());
        out.seal_signer_id = Some(snapshot.seal_signer_id.clone());
        out.max_fee = Some(snapshot.max_fee);
        out.estimated_required_fee = snapshot.estimated_required_fee;
        out.selected_max_fee = snapshot.selected_max_fee;
        out.max_epoch = Some(snapshot.max_epoch);
        out.walletd_request_id = Some(snapshot.walletd_request_id);
        out.phase = Some(snapshot.phase.clone());
        out.transaction_id = snapshot.transaction_id.clone();
        out.failure_reason = snapshot.failure_reason.clone();
        out.recoverable = recoverable_phase;
        out.blocks_fresh_publish = blocks_fresh_publish;
        out.receipt_verified = receipt_verified;
    }
    Ok(out)
}

/// Advance a persisted, already-submitted V2 lifecycle by re-polling the
/// indexer and re-verifying the receipt. This path NEVER contacts walletd, so
/// it cannot create a wallet approval request, cannot approve or submit, and
/// cannot mint a duplicate on-chain transaction.
///
/// Preconditions:
/// - a lifecycle sidecar exists for `archive_directory`;
/// - the persisted template binding matches the currently locked V2
///   deployment binding;
/// - the persisted snapshot carries a transaction id.
///
/// Effects:
/// - `FAILED` with the specific verifier `ANCHOR_RECEIPT_WRONG_EVENT_TOPIC`
///   reason transitions to `POLLING_RECEIPT` before polling;
/// - `POLLING_RECEIPT` polls the indexer once; a verified receipt writes the
///   immutable success-evidence sidecar and advances to `RECEIPT_VERIFIED`;
/// - `RECEIPT_VERIFIED` returns terminal success without polling.
pub fn run_v2_live_anchor_recovery_step_with_indexer<I>(
    archive_directory: &Path,
    deployment: &AnchorTemplateBindingV2,
    indexer: &mut IndexerReceiptNetworkAdapter<I>,
) -> Result<GuiV2LiveAnchorStepResultV1, GuiCoreError>
where
    I: IndexerReceiptWireTransport,
{
    let lifecycle_path = v2_lifecycle_sidecar_path(archive_directory)?;
    let evidence_path = v2_evidence_sidecar_path(archive_directory)?;
    let failure_path = v2_failure_sidecar_path(archive_directory)?;
    let mut snapshot = load_snapshot(&lifecycle_path)?.ok_or_else(|| {
        v2_error(
            "GUI_ANCHOR_V2_RECOVERY_LIFECYCLE_MISSING",
            "no persisted V2 lifecycle to recover",
        )
    })?;
    // Bind recovery to the currently locked deployment. A tampered / rotated
    // deployment must fail closed rather than silently poll with a mismatched
    // verifier binding.
    if snapshot.template_address != deployment.template_address()
        || snapshot.template_module != deployment.module()
        || snapshot.template_function != deployment.function()
        || snapshot.template_topic != deployment.full_event_topic()
        || snapshot.template_artifact_digest_hex
            != crate::hex::to_lower_hex(deployment.artifact_digest())
    {
        return Err(v2_error(
            "GUI_ANCHOR_V2_LIFECYCLE_BINDING_MISMATCH",
            "the persisted V2 lifecycle binding does not match the locked V2 deployment",
        ));
    }
    if snapshot.transaction_id.is_none() {
        return Err(v2_error(
            "GUI_ANCHOR_V2_RECOVERY_INAPPLICABLE",
            "the persisted V2 lifecycle has no submitted transaction to recover",
        ));
    }
    if snapshot.phase == "FAILED" && failed_after_verifier_topic_mismatch(&snapshot) {
        snapshot.phase = "POLLING_RECEIPT".to_owned();
        snapshot.failure_reason = None;
    }
    match snapshot.phase.as_str() {
        "RECEIPT_VERIFIED" => Ok(result(&snapshot, &evidence_path, true)),
        "POLLING_RECEIPT" => poll_receipt(
            &mut snapshot,
            deployment,
            indexer,
            &lifecycle_path,
            &evidence_path,
            &failure_path,
        ),
        _ => Err(v2_error(
            "GUI_ANCHOR_V2_RECOVERY_REQUIRES_WALLETD",
            "the persisted V2 lifecycle phase can only be advanced by the walletd lifecycle step",
        )),
    }
}

fn v2_error(code: &'static str, message: &'static str) -> GuiCoreError {
    GuiCoreError::new(
        code,
        GuiErrorCategory::AnchorArtifactIntegrity,
        Some("anchor-v2-live"),
        message,
    )
}
