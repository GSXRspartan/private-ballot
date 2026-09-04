//! Read-only, field-specific preflight for live Ootle anchor config generation.
//!
//! This module is the single source of truth for validating the *public*
//! operator inputs to [`crate::live_anchor_config`]. It exists to replace the
//! historical generic `GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID` funnel: instead
//! of collapsing nine-plus distinct failure reasons into one opaque code, every
//! field is validated independently and reported with a stable, field-specific
//! machine code, a human-readable message, a normalized value, and a
//! remediation hint.
//!
//! # Guarantees
//!
//! * **Read-only**: preflight writes NO config, snapshot, or evidence, creates
//!   NO transaction, calls NO publish, spends NO fees, requires NO wallet
//!   approval, and touches NO secret. It performs only archive verification
//!   (which reads the archive directory) and filesystem *metadata* reads for the
//!   output sidecar paths — it never creates or mutates a file.
//! * **Shared validators**: the exact same field validators are used by the real
//!   Prepare path ([`crate::live_anchor_config`]). A green preflight therefore
//!   proves Prepare will not fail on any of these fields, and a red field name
//!   in preflight is the *same* code Prepare would surface.
//! * **No live wallet calls**: distinguishing "walletd not running /
//!   unauthenticated / ready" and confirming that a fee component, signer id, or
//!   declared seal key actually belongs to the wallet account requires network
//!   access and is a shell-layer concern (see the Tauri `walletd_readiness`
//!   probe and the wallet auto-fill flow). Those items are reported here as
//!   structurally valid but *not offline-verifiable* so the frontend can layer
//!   the live readiness state on top.

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_TEMPLATE_MODULE_V1, AnchorAccountReference, AnchorMaxFeeV1,
    AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_ootle_anchor_app::{
    MAX_DECLARED_SEAL_PUBLIC_KEY_BYTES, path_guard::path_is_within_archive,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1, WalletdEndpoint,
    indexer_endpoint_allowed_for_network_v1,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdFeeComponentRef, WalletdSealSignerRef,
};

use crate::archive_verify::{
    GuiArchiveVerificationV1, verify_archive_directory_v1, verify_archive_directory_with_memo_v1,
};
use crate::error::GuiCoreError;
use crate::live_anchor_config::{
    GuiLiveAnchorConfigRequestV1, fixed_anchor_template_event_topic_v1,
};

// ---------------------------------------------------------------------------
// Stable field identifiers.
// ---------------------------------------------------------------------------

/// Stable identifier for one operator config field or precondition, used by the
/// frontend to attach a status to the correct control.
pub mod field {
    pub const NETWORK: &str = "network";
    pub const WALLETD_ENDPOINT: &str = "walletd_endpoint";
    pub const INDEXER_ENDPOINT: &str = "indexer_endpoint";
    pub const ACCOUNT_REFERENCE: &str = "account_reference";
    pub const FEE_COMPONENT: &str = "fee_component";
    pub const SEAL_SIGNER_KIND: &str = "seal_signer_kind";
    pub const SEAL_SIGNER_ID: &str = "seal_signer_id";
    pub const DECLARED_SEAL_PUBLIC_KEY: &str = "declared_seal_public_key";
    pub const TEMPLATE_ADDRESS: &str = "template_address";
    pub const TEMPLATE_ARTIFACT_DIGEST: &str = "template_artifact_digest_hex";
    pub const MAX_FEE: &str = "max_fee";
    pub const MAX_EPOCH_DELTA: &str = "max_epoch_delta";
    pub const ACCEPTED_BALLOT_FLOOR: &str = "required_accepted_ballot_floor";
    pub const DEDICATED_ORGANIZER_WALLET: &str = "dedicated_organizer_wallet_attested";
    pub const REDUCED_ANONYMITY_ACK: &str = "reduced_anonymity_acknowledged";
    pub const ARCHIVE_DIRECTORY: &str = "archive_directory";
    pub const TRANSPORT_BINDING: &str = "transport_binding";
    pub const ACCEPTED_BALLOT_COUNT: &str = "accepted_ballot_count";
    pub const OUTPUT_CONFIG_PATH: &str = "output_config_path";
    pub const SNAPSHOT_PATH: &str = "snapshot_path";
    pub const EVIDENCE_PATH: &str = "evidence_path";
}

// ---------------------------------------------------------------------------
// Shared field rejection (single source of truth for codes and messages).
// ---------------------------------------------------------------------------

/// A field-specific rejection produced by a shared validator. Both `code` and
/// `message` are `&'static` so they can bridge losslessly into a
/// [`GuiCoreError`] on the real Prepare path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuiFieldRejectionV1 {
    /// Stable machine code (`GUI_LIVE_ANCHOR_*`).
    pub code: &'static str,
    /// Human-readable, secret-free explanation.
    pub message: &'static str,
    /// Actionable remediation hint.
    pub remediation: &'static str,
}

impl GuiFieldRejectionV1 {
    const fn new(code: &'static str, message: &'static str, remediation: &'static str) -> Self {
        Self {
            code,
            message,
            remediation,
        }
    }

    /// Bridges this field rejection into a bounded [`GuiCoreError`] carrying the
    /// specific code (never the generic operator-config-invalid funnel).
    #[must_use]
    pub fn into_gui_error(self) -> GuiCoreError {
        GuiCoreError::live_anchor_field_invalid(self.code, self.message)
    }
}

/// Machine status of a single validated field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiLiveAnchorFieldStatusV1 {
    /// Stable field identifier (see [`field`]).
    pub field: &'static str,
    /// Whether this field passed offline validation.
    pub ok: bool,
    /// Stable machine code: `OK`, a `GUI_LIVE_ANCHOR_*` rejection code, or a
    /// `*_NEEDS_LIVE_CHECK` advisory code for items only verifiable online.
    pub code: String,
    /// Human-readable, secret-free explanation.
    pub message: String,
    /// Actionable remediation hint, when the field is not ok.
    pub remediation: Option<String>,
    /// Normalized, non-secret representation of the accepted value, when
    /// available (e.g. canonical component address, canonical endpoint URL).
    pub normalized: Option<String>,
    /// Whether a definitive verdict requires a live walletd/indexer call that
    /// preflight deliberately does not make.
    pub needs_live_check: bool,
}

impl GuiLiveAnchorFieldStatusV1 {
    fn ok(field: &'static str, message: &str, normalized: Option<String>) -> Self {
        Self {
            field,
            ok: true,
            code: "OK".to_owned(),
            message: message.to_owned(),
            remediation: None,
            normalized,
            needs_live_check: false,
        }
    }

    fn ok_needs_live(field: &'static str, message: &str, normalized: Option<String>) -> Self {
        Self {
            field,
            ok: true,
            code: "OK_NEEDS_LIVE_CHECK".to_owned(),
            message: message.to_owned(),
            remediation: None,
            normalized,
            needs_live_check: true,
        }
    }

    fn rejected(field: &'static str, rejection: GuiFieldRejectionV1) -> Self {
        Self {
            field,
            ok: false,
            code: rejection.code.to_owned(),
            message: rejection.message.to_owned(),
            remediation: Some(rejection.remediation.to_owned()),
            normalized: None,
            needs_live_check: false,
        }
    }
}

/// Structured, read-only preflight result for the whole operator config.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiLiveAnchorPreflightResultV1 {
    /// True only when every field passed offline validation.
    pub ok: bool,
    /// Per-field statuses in a stable order.
    pub fields: Vec<GuiLiveAnchorFieldStatusV1>,
    /// The first failing field's code, for a compact banner.
    pub first_error_code: Option<String>,
    /// The first failing field's identifier.
    pub first_error_field: Option<&'static str>,
    /// Verified accepted-ballot count, when the archive verified.
    pub accepted_ballot_count: Option<u64>,
    /// Whether the verified final transport binding reports reduced anonymity.
    pub reduced_anonymity: Option<bool>,
    /// Whether any field needs a live walletd/indexer check to be definitive.
    pub any_needs_live_check: bool,
}

impl GuiLiveAnchorPreflightResultV1 {
    fn from_fields(
        fields: Vec<GuiLiveAnchorFieldStatusV1>,
        accepted_ballot_count: Option<u64>,
        reduced_anonymity: Option<bool>,
    ) -> Self {
        let first = fields.iter().find(|status| !status.ok);
        let ok = first.is_none();
        let any_needs_live_check = fields.iter().any(|status| status.needs_live_check);
        Self {
            ok,
            first_error_code: first.map(|status| status.code.clone()),
            first_error_field: first.map(|status| status.field),
            accepted_ballot_count,
            reduced_anonymity,
            any_needs_live_check,
            fields,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points.
// ---------------------------------------------------------------------------

/// Runs the full read-only field-specific preflight, verifying the archive
/// directory directly.
///
/// # Errors
///
/// Never returns a hard error for operator input; invalid fields are reported
/// inside the structured result. It returns [`GuiCoreError`] only if the archive
/// directory is unreadable at the filesystem level, in which case the archive
/// field carries the specific reason and the caller may still render the result.
#[must_use]
pub fn validate_live_anchor_operator_config_v1(
    request: &GuiLiveAnchorConfigRequestV1,
) -> GuiLiveAnchorPreflightResultV1 {
    let verification = verify_archive_directory_v1(Path::new(&request.archive_directory));
    build_preflight(request, verification)
}

/// Runs the full read-only field-specific preflight, reusing a same-process
/// memoized archive verification for an unchanged archive.
#[must_use]
pub fn validate_live_anchor_operator_config_with_memo_v1(
    memo: &tari_cc_private_ballot_archive::ArchiveVerificationMemoV1,
    request: &GuiLiveAnchorConfigRequestV1,
) -> GuiLiveAnchorPreflightResultV1 {
    let verification =
        verify_archive_directory_with_memo_v1(memo, Path::new(&request.archive_directory));
    build_preflight(request, verification)
}

fn build_preflight(
    request: &GuiLiveAnchorConfigRequestV1,
    verification: Result<GuiArchiveVerificationV1, GuiCoreError>,
) -> GuiLiveAnchorPreflightResultV1 {
    let mut fields: Vec<GuiLiveAnchorFieldStatusV1> = Vec::new();

    // Network first, because the indexer allow-list depends on it.
    let network = match validate_network(&request.network) {
        Ok(network) => {
            fields.push(GuiLiveAnchorFieldStatusV1::ok(
                field::NETWORK,
                "supported Ootle network",
                Some(network.as_str().to_owned()),
            ));
            Some(network)
        }
        Err(rejection) => {
            fields.push(GuiLiveAnchorFieldStatusV1::rejected(
                field::NETWORK,
                rejection,
            ));
            None
        }
    };

    fields.push(status(
        field::WALLETD_ENDPOINT,
        validate_walletd_endpoint(&request.walletd_endpoint)
            .map(|endpoint| endpoint.as_str().to_owned()),
        "organizer-local loopback walletd endpoint",
    ));

    fields.push(
        match validate_indexer_endpoint(&request.indexer_endpoint, network.as_ref()) {
            IndexerVerdict::Ok(normalized) => GuiLiveAnchorFieldStatusV1::ok(
                field::INDEXER_ENDPOINT,
                "allowed indexer endpoint",
                Some(normalized),
            ),
            IndexerVerdict::Rejected(rejection) => {
                GuiLiveAnchorFieldStatusV1::rejected(field::INDEXER_ENDPOINT, rejection)
            }
        },
    );

    fields.push(status(
        field::ACCOUNT_REFERENCE,
        validate_account_reference(&request.account_reference)
            .map(|reference| reference.as_str().to_owned()),
        "bounded public fee-account reference",
    ));

    fields.push(match validate_fee_component(&request.fee_component) {
        Ok(component) => GuiLiveAnchorFieldStatusV1::ok_needs_live(
            field::FEE_COMPONENT,
            "valid Ootle component address (wallet membership confirmed online)",
            Some(component.display_string()),
        ),
        Err(rejection) => GuiLiveAnchorFieldStatusV1::rejected(field::FEE_COMPONENT, rejection),
    });

    fields.push(status_unit(
        field::SEAL_SIGNER_KIND,
        validate_seal_signer_kind(&request.seal_signer_kind),
        "seal signer kind (account, transaction, or imported)",
    ));
    fields.push(
        match validate_seal_signer(&request.seal_signer_kind, &request.seal_signer_id) {
            Ok(_signer) => GuiLiveAnchorFieldStatusV1::ok_needs_live(
                field::SEAL_SIGNER_ID,
                "numeric signer id (confirmation in wallet is online)",
                Some(request.seal_signer_id.trim().to_owned()),
            ),
            Err(rejection) => {
                GuiLiveAnchorFieldStatusV1::rejected(field::SEAL_SIGNER_ID, rejection)
            }
        },
    );

    fields.push(
        match validate_declared_seal_public_key(&request.declared_seal_public_key) {
            Ok(normalized) => GuiLiveAnchorFieldStatusV1::ok_needs_live(
                field::DECLARED_SEAL_PUBLIC_KEY,
                "well-formed declared seal public key (match to wallet account is online)",
                Some(normalized),
            ),
            Err(rejection) => {
                GuiLiveAnchorFieldStatusV1::rejected(field::DECLARED_SEAL_PUBLIC_KEY, rejection)
            }
        },
    );

    fields.push(status(
        field::TEMPLATE_ADDRESS,
        validate_template_address(
            &request.template_address,
            &request.template_artifact_digest_hex,
        )
        .map(|()| request.template_address.clone()),
        "pinned event-template address binding",
    ));
    fields.push(status_unit(
        field::TEMPLATE_ARTIFACT_DIGEST,
        validate_template_artifact_digest(&request.template_artifact_digest_hex),
        "lowercase BLAKE3-256 template artifact digest",
    ));

    fields.push(status_unit(
        field::MAX_FEE,
        validate_max_fee(request.max_fee).map(|_| ()),
        "max fee within policy",
    ));
    fields.push(status_unit(
        field::MAX_EPOCH_DELTA,
        validate_max_epoch_delta(request.max_epoch_delta),
        "bounded max epoch window",
    ));
    fields.push(status_unit(
        field::ACCEPTED_BALLOT_FLOOR,
        validate_accepted_floor(request.required_accepted_ballot_floor),
        "explicit accepted-ballot floor",
    ));

    fields.push(status_unit(
        field::DEDICATED_ORGANIZER_WALLET,
        validate_dedicated_wallet(request.dedicated_organizer_wallet_attested),
        "dedicated organizer wallet attested",
    ));

    // Archive preconditions, transport binding, accepted count/floor, and the
    // reduced-anonymity acknowledgement all derive from the verification.
    let (accepted, reduced) = push_archive_fields(
        &mut fields,
        request,
        Path::new(&request.archive_directory),
        &verification,
    );

    push_path_fields(&mut fields, request);

    GuiLiveAnchorPreflightResultV1::from_fields(fields, accepted, reduced)
}

fn status(
    field: &'static str,
    result: Result<String, GuiFieldRejectionV1>,
    ok_message: &str,
) -> GuiLiveAnchorFieldStatusV1 {
    match result {
        Ok(normalized) => GuiLiveAnchorFieldStatusV1::ok(field, ok_message, Some(normalized)),
        Err(rejection) => GuiLiveAnchorFieldStatusV1::rejected(field, rejection),
    }
}

fn status_unit(
    field: &'static str,
    result: Result<(), GuiFieldRejectionV1>,
    ok_message: &str,
) -> GuiLiveAnchorFieldStatusV1 {
    match result {
        Ok(()) => GuiLiveAnchorFieldStatusV1::ok(field, ok_message, None),
        Err(rejection) => GuiLiveAnchorFieldStatusV1::rejected(field, rejection),
    }
}

// ---------------------------------------------------------------------------
// Shared field validators (used by BOTH preflight and the real Prepare path).
// ---------------------------------------------------------------------------

/// Validates the Ootle network id.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the network is not a supported id.
pub fn validate_network(raw: &str) -> Result<OotleNetworkIdV1, GuiFieldRejectionV1> {
    OotleNetworkIdV1::new(raw.to_owned()).map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_NETWORK_INVALID",
            "the Ootle network id is not a supported network",
            "use the network from the locked deployment (for example, esmeralda)",
        )
    })
}

/// Validates the walletd endpoint: parseable and organizer-local loopback.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the endpoint cannot be parsed or is
/// not a loopback host.
pub fn validate_walletd_endpoint(raw: &str) -> Result<WalletdEndpoint, GuiFieldRejectionV1> {
    let endpoint = WalletdEndpoint::parse(raw).map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_WALLETD_ENDPOINT_INVALID",
            "the walletd endpoint is not a valid http/https URL",
            "enter the local walletd base URL, e.g. http://127.0.0.1:5100 or http://localhost:5100 (the app adds the /json_rpc route for you)",
        )
    })?;
    if !endpoint.is_loopback() {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_WALLETD_ENDPOINT_NOT_LOOPBACK",
            "the walletd endpoint must be an organizer-local loopback address",
            "walletd carries signing authority; use a 127.0.0.1 or localhost URL",
        ));
    }
    Ok(endpoint)
}

enum IndexerVerdict {
    Ok(String),
    Rejected(GuiFieldRejectionV1),
}

fn validate_indexer_endpoint(raw: &str, network: Option<&OotleNetworkIdV1>) -> IndexerVerdict {
    let endpoint = match IndexerEndpoint::parse(raw) {
        Ok(endpoint) => endpoint,
        Err(_) => {
            return IndexerVerdict::Rejected(GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_INDEXER_ENDPOINT_INVALID",
                "the indexer endpoint is not a valid http/https URL",
                "enter the indexer URL, for example https://ootle-indexer-a.tari.com/",
            ));
        }
    };
    match network {
        Some(network) if indexer_endpoint_allowed_for_network_v1(network, &endpoint) => {
            IndexerVerdict::Ok(endpoint.as_str().to_owned())
        }
        Some(_) => IndexerVerdict::Rejected(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_INDEXER_NETWORK_MISMATCH",
            "the indexer endpoint is not allowed for the selected network",
            "use a loopback indexer or the trusted hosted Esmeralda indexer for this network",
        )),
        // Network could not be parsed; the format is valid but the allow-list
        // verdict is blocked on the network field being fixed first.
        None => IndexerVerdict::Rejected(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_INDEXER_NETWORK_MISMATCH",
            "the indexer allow-list cannot be checked until the network is valid",
            "fix the network field first, then re-check the indexer endpoint",
        )),
    }
}

/// Shared indexer validator returning a strongly-typed endpoint for Prepare.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] for a malformed URL or a network mismatch.
pub fn validate_indexer_endpoint_typed(
    raw: &str,
    network: &OotleNetworkIdV1,
) -> Result<IndexerEndpoint, GuiFieldRejectionV1> {
    let endpoint = IndexerEndpoint::parse(raw).map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_INDEXER_ENDPOINT_INVALID",
            "the indexer endpoint is not a valid http/https URL",
            "enter the indexer URL, for example https://ootle-indexer-a.tari.com/",
        )
    })?;
    if !indexer_endpoint_allowed_for_network_v1(network, &endpoint) {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_INDEXER_NETWORK_MISMATCH",
            "the indexer endpoint is not allowed for the selected network",
            "use a loopback indexer or the trusted hosted Esmeralda indexer for this network",
        ));
    }
    Ok(endpoint)
}

/// Validates the public fee-account reference.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] describing whether the reference was empty,
/// too long, or contained a forbidden character (most commonly a space, which
/// happens when the wallet's display name is pasted here).
pub fn validate_account_reference(
    raw: &str,
) -> Result<AnchorAccountReference, GuiFieldRejectionV1> {
    use tari_cc_private_ballot_anchor_transport::AnchorIdentifierError;
    AnchorAccountReference::new(raw.to_owned()).map_err(|error| match error {
        AnchorIdentifierError::Empty => GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_EMPTY",
            "the fee-account reference is empty",
            "enter a short reference such as organizer-fee-account",
        ),
        AnchorIdentifierError::TooLong => GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_TOO_LONG",
            "the fee-account reference exceeds the maximum length",
            "use a short reference of at most 128 bytes",
        ),
        AnchorIdentifierError::ForbiddenCharacter => GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_FORBIDDEN_CHARACTER",
            "the fee-account reference contains whitespace or a control character",
            "do not paste the wallet display name; use a no-space reference such as organizer-fee-account",
        ),
    })
}

/// Validates the resolved fee component address.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the value is not a valid Ootle
/// component address. Whether the component belongs to the wallet is an online
/// check performed elsewhere.
pub fn validate_fee_component(raw: &str) -> Result<WalletdFeeComponentRef, GuiFieldRejectionV1> {
    WalletdFeeComponentRef::parse(raw).map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_FEE_COMPONENT_INVALID",
            "the fee component is not a valid Ootle component address",
            "paste the account's component_<hex> address exactly as walletd prints it",
        )
    })
}

fn validate_seal_signer_kind(kind: &str) -> Result<(), GuiFieldRejectionV1> {
    match kind {
        "account" | "transaction" | "imported" => Ok(()),
        _ => Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_SEAL_SIGNER_KIND_INVALID",
            "the seal signer kind must be account, transaction, or imported",
            "select one of: account, transaction, imported",
        )),
    }
}

/// Validates the seal signer kind and numeric id together.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] for an unknown kind or a non-numeric id.
pub fn validate_seal_signer(
    kind: &str,
    id: &str,
) -> Result<WalletdSealSignerRef, GuiFieldRejectionV1> {
    validate_seal_signer_kind(kind)?;
    let index: u64 = id.trim().parse().map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_SEAL_SIGNER_ID_INVALID",
            "the seal signer id must be a non-negative whole number",
            "enter the wallet key index, for example 0",
        )
    })?;
    Ok(match kind {
        "account" => WalletdSealSignerRef::AccountKey { index },
        "transaction" => WalletdSealSignerRef::TransactionKey { index },
        "imported" => WalletdSealSignerRef::ImportedKey {
            local_key_id: index,
        },
        // Unreachable: kind already validated above.
        _ => WalletdSealSignerRef::AccountKey { index },
    })
}

/// Validates the operator-declared seal public key format.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the value is empty, too long, or
/// contains whitespace. Whether it matches the selected wallet account is an
/// online check performed elsewhere.
pub fn validate_declared_seal_public_key(raw: &str) -> Result<String, GuiFieldRejectionV1> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_DECLARED_SEAL_PUBLIC_KEY_EMPTY",
            "the declared seal public key is empty",
            "paste the owner public key of the selected wallet account",
        ));
    }
    if trimmed.len() > MAX_DECLARED_SEAL_PUBLIC_KEY_BYTES {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_DECLARED_SEAL_PUBLIC_KEY_TOO_LONG",
            "the declared seal public key exceeds the maximum length",
            "paste only the account owner public key, without extra text",
        ));
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_DECLARED_SEAL_PUBLIC_KEY_WHITESPACE",
            "the declared seal public key contains whitespace",
            "paste the owner public key with no embedded spaces or line breaks",
        ));
    }
    Ok(trimmed.to_owned())
}

/// Validates that the template address forms a valid binding with the fixed
/// module/function/topic and the supplied artifact digest.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the address (or resulting binding) is
/// invalid.
pub fn validate_template_address(
    address: &str,
    artifact_digest_hex: &str,
) -> Result<(), GuiFieldRejectionV1> {
    let digest = validate_template_artifact_digest_bytes(artifact_digest_hex)?;
    AnchorTemplateBindingV1::new(
        address.to_owned(),
        ANCHOR_TEMPLATE_MODULE_V1.to_owned(),
        ANCHOR_EVENT_FUNCTION_V1.to_owned(),
        fixed_anchor_template_event_topic_v1(),
        digest,
    )
    .map(|_| ())
    .map_err(|_| {
        GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_TEMPLATE_ADDRESS_INVALID",
            "the event-template address does not form a valid deployment binding",
            "re-lock the trusted Ootle deployment so the template address is canonical",
        )
    })
}

fn validate_template_artifact_digest(hex: &str) -> Result<(), GuiFieldRejectionV1> {
    validate_template_artifact_digest_bytes(hex).map(|_| ())
}

/// Validates and decodes the lowercase BLAKE3-256 template artifact digest.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the digest is not exactly 64 lowercase
/// hex characters.
pub fn validate_template_artifact_digest_bytes(hex: &str) -> Result<[u8; 32], GuiFieldRejectionV1> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_TEMPLATE_ARTIFACT_DIGEST_INVALID",
            "the template artifact digest is not 64 lowercase hex characters",
            "re-lock the trusted Ootle deployment to recompute the canonical digest",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Validates the max fee against the shared policy ceiling.
///
/// # Errors
///
/// Returns a [`GuiFieldRejectionV1`] when the fee is zero or above the ceiling.
pub fn validate_max_fee(units: u64) -> Result<AnchorMaxFeeV1, GuiFieldRejectionV1> {
    let max_fee = AnchorMaxFeeV1::from_units(units);
    if max_fee.value() == 0 || max_fee.value() > OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1 {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_MAX_FEE_OUT_OF_POLICY",
            "the max fee must be greater than zero and within the fee policy ceiling",
            "enter a positive max fee within the allowed anchor fee budget",
        ));
    }
    Ok(max_fee)
}

fn validate_max_epoch_delta(delta: u64) -> Result<(), GuiFieldRejectionV1> {
    if delta == 0 {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_MAX_EPOCH_DELTA_INVALID",
            "the max epoch delta must be at least one",
            "enter a small positive epoch window, for example 12",
        ));
    }
    Ok(())
}

fn validate_accepted_floor(floor: u64) -> Result<(), GuiFieldRejectionV1> {
    if floor == 0 {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_REQUIRED",
            "an explicit accepted-ballot floor is required (zero is rejected)",
            "set the minimum accepted-ballot floor (at least 2 for publishing)",
        ));
    }
    Ok(())
}

fn validate_dedicated_wallet(attested: bool) -> Result<(), GuiFieldRejectionV1> {
    if !attested {
        return Err(GuiFieldRejectionV1::new(
            "GUI_LIVE_ANCHOR_DEDICATED_WALLET_REQUIRED",
            "a dedicated organizer wallet must be attested",
            "confirm the anchor is published from a dedicated organizer-only wallet",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive preconditions and paths.
// ---------------------------------------------------------------------------

fn push_archive_fields(
    fields: &mut Vec<GuiLiveAnchorFieldStatusV1>,
    request: &GuiLiveAnchorConfigRequestV1,
    archive_dir: &Path,
    verification: &Result<GuiArchiveVerificationV1, GuiCoreError>,
) -> (Option<u64>, Option<bool>) {
    let verification = match verification {
        Ok(verification) => verification,
        Err(error) => {
            let (code, message, remediation): (&'static str, &'static str, &'static str) =
                if !archive_dir.is_dir() {
                    (
                        "GUI_LIVE_ANCHOR_ARCHIVE_MISSING",
                        "the archive directory does not exist",
                        "select the finalized, verified archive directory",
                    )
                } else {
                    (
                        error.code(),
                        "the archive directory could not be read for verification",
                        "confirm the archive directory is readable and not in use",
                    )
                };
            fields.push(GuiLiveAnchorFieldStatusV1::rejected(
                field::ARCHIVE_DIRECTORY,
                GuiFieldRejectionV1::new(code, message, remediation),
            ));
            return (None, None);
        }
    };

    if !verification.verified {
        fields.push(GuiLiveAnchorFieldStatusV1::rejected(
            field::ARCHIVE_DIRECTORY,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_ARCHIVE_NOT_VERIFIED",
                "the archive failed independent verification",
                "re-run archive verification and resolve the reported stage before anchoring",
            ),
        ));
        return (None, None);
    }
    if !verification.finalized {
        fields.push(GuiLiveAnchorFieldStatusV1::rejected(
            field::ARCHIVE_DIRECTORY,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_ARCHIVE_NOT_FINALIZED",
                "the archive is verified but not finalized",
                "finalize the election archive before anchoring",
            ),
        ));
        return (None, None);
    }
    fields.push(GuiLiveAnchorFieldStatusV1::ok(
        field::ARCHIVE_DIRECTORY,
        "archive verified and finalized",
        verification.archive_hash_hex.clone(),
    ));

    // Transport binding.
    if !verification.transport_binding_verified {
        fields.push(GuiLiveAnchorFieldStatusV1::rejected(
            field::TRANSPORT_BINDING,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_TRANSPORT_BINDING_REQUIRED",
                "the archive lacks a verified final transport binding",
                "anchor only archives produced through the private transport path",
            ),
        ));
        return (None, None);
    }

    let accepted = match u64::try_from(verification.accepted_count) {
        Ok(accepted) => accepted,
        Err(_) => {
            fields.push(GuiLiveAnchorFieldStatusV1::rejected(
                field::ACCEPTED_BALLOT_COUNT,
                GuiFieldRejectionV1::new(
                    "GUI_LIVE_ANCHOR_ACCEPTED_COUNT_INVALID",
                    "the verified accepted-ballot count is out of range",
                    "re-verify the archive; the accepted count is implausibly large",
                ),
            ));
            return (None, None);
        }
    };

    match verification.transport_accepted_count {
        Some(transport_accepted) if transport_accepted == accepted => {
            fields.push(GuiLiveAnchorFieldStatusV1::ok(
                field::TRANSPORT_BINDING,
                "verified transport binding matches the replayed accepted count",
                Some(accepted.to_string()),
            ));
        }
        Some(_) => {
            fields.push(GuiLiveAnchorFieldStatusV1::rejected(
                field::TRANSPORT_BINDING,
                GuiFieldRejectionV1::new(
                    "GUI_LIVE_ANCHOR_TRANSPORT_COUNT_MISMATCH",
                    "the transport binding accepted count does not match the archive replay",
                    "re-verify the archive; transport and replay counts must agree",
                ),
            ));
            return (None, None);
        }
        None => {
            fields.push(GuiLiveAnchorFieldStatusV1::rejected(
                field::TRANSPORT_BINDING,
                GuiFieldRejectionV1::new(
                    "GUI_LIVE_ANCHOR_TRANSPORT_BINDING_REQUIRED",
                    "the verified transport binding did not report an accepted count",
                    "anchor only archives produced through the private transport path",
                ),
            ));
            return (None, None);
        }
    }

    // Accepted count vs floor.
    if request.required_accepted_ballot_floor > 0
        && accepted < request.required_accepted_ballot_floor
    {
        fields.push(GuiLiveAnchorFieldStatusV1::rejected(
            field::ACCEPTED_BALLOT_COUNT,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_NOT_MET",
                "the verified accepted-ballot count is below the requested floor",
                "lower the floor to the real cohort size or verify the correct archive",
            ),
        ));
    } else {
        fields.push(GuiLiveAnchorFieldStatusV1::ok(
            field::ACCEPTED_BALLOT_COUNT,
            "accepted-ballot count meets the requested floor",
            Some(accepted.to_string()),
        ));
    }

    let reduced = verification.transport_reduced_anonymity;
    if reduced == Some(true) && !request.reduced_anonymity_acknowledged {
        fields.push(GuiLiveAnchorFieldStatusV1::rejected(
            field::REDUCED_ANONYMITY_ACK,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_REDUCED_ANONYMITY_ACK_REQUIRED",
                "the transport binding reports reduced anonymity, which must be acknowledged",
                "explicitly acknowledge reduced anonymity before anchoring",
            ),
        ));
    } else {
        fields.push(GuiLiveAnchorFieldStatusV1::ok(
            field::REDUCED_ANONYMITY_ACK,
            "reduced-anonymity acknowledgement satisfied",
            None,
        ));
    }

    (Some(accepted), reduced)
}

fn push_path_fields(
    fields: &mut Vec<GuiLiveAnchorFieldStatusV1>,
    request: &GuiLiveAnchorConfigRequestV1,
) {
    let archive_dir = PathBuf::from(&request.archive_directory);
    let entries = [
        (field::OUTPUT_CONFIG_PATH, &request.output_config_path),
        (field::SNAPSHOT_PATH, &request.snapshot_path),
        (field::EVIDENCE_PATH, &request.evidence_path),
    ];
    for (field_id, raw) in entries {
        fields.push(validate_output_path(field_id, raw, &archive_dir));
    }
}

fn validate_output_path(
    field_id: &'static str,
    raw: &str,
    archive_dir: &Path,
) -> GuiLiveAnchorFieldStatusV1 {
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return GuiLiveAnchorFieldStatusV1::rejected(
            field_id,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_CONFIG_PATH_INVALID",
                "the output path must be absolute",
                "choose an absolute output path outside the archive directory",
            ),
        );
    }
    if path_is_within_archive(&path, archive_dir) {
        return GuiLiveAnchorFieldStatusV1::rejected(
            field_id,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_OUTPUT_WITHIN_ARCHIVE",
                "the output path is inside the finalized archive directory",
                "write anchor sidecars beside the archive, never inside it",
            ),
        );
    }
    if path.exists() {
        return GuiLiveAnchorFieldStatusV1::rejected(
            field_id,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_CONFIG_OUTPUT_EXISTS",
                "the output file already exists",
                "remove or rename the existing sidecar, or choose a fresh path",
            ),
        );
    }
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() || parent.is_dir() => {
            GuiLiveAnchorFieldStatusV1::ok(
                field_id,
                "output path is writable and fresh",
                Some(raw.to_owned()),
            )
        }
        _ => GuiLiveAnchorFieldStatusV1::rejected(
            field_id,
            GuiFieldRejectionV1::new(
                "GUI_LIVE_ANCHOR_OUTPUT_PATH_NOT_WRITABLE",
                "the output path's parent directory does not exist",
                "choose an output path whose parent directory already exists",
            ),
        ),
    }
}

#[cfg(test)]
mod walletd_endpoint_normalization_tests {
    use super::validate_walletd_endpoint;
    use tari_cc_private_ballot_ootle_anchor_network_adapters::ensure_walletd_jsonrpc_path;

    // Preflight accepts the bare loopback base (127.0.0.1 or localhost) and an
    // explicit /json_rpc URL; the effective RPC endpoint the anchor path uses is
    // always the normalized /json_rpc route, never doubled.
    #[test]
    fn preflight_accepted_endpoints_normalize_to_jsonrpc() {
        for raw in [
            "http://127.0.0.1:5100",
            "http://localhost:5100",
            "http://127.0.0.1:5100/json_rpc",
        ] {
            let endpoint = validate_walletd_endpoint(raw)
                .unwrap_or_else(|_| panic!("{raw} must pass preflight"));
            let rpc = ensure_walletd_jsonrpc_path(endpoint.as_str());
            assert!(rpc.ends_with("/json_rpc"), "{raw} -> {rpc}");
            assert!(!rpc.contains("/json_rpc/json_rpc"), "{raw} -> {rpc}");
        }
    }
}
