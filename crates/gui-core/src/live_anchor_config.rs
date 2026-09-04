//! Safe live anchor config producer from a verified finalized archive.
//!
//! This module is the Rust authority for deriving live Ootle anchor config
//! hashes from archive bytes. Operator/GUI input supplies only public network
//! locators, fee/seal references, output paths, and policy acknowledgements.

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_EVENT_TOPIC_SUFFIX_V1, ANCHOR_TEMPLATE_MODULE_V1,
    AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_archive::{ArchiveHashV1, ArchiveVerificationMemoV1};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorConfigInputProvenanceV1, AnchorLiveApprovalFactsV1,
    SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED, path_guard::path_is_within_archive,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::NetworkAdapterConfig;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider, ManifestHash};

use crate::archive_verify::{
    GuiArchiveVerificationV1, verify_archive_directory_v1, verify_archive_directory_with_memo_v1,
};
use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::live_anchor_preflight::GuiFieldRejectionV1;

/// Public operator inputs for archive-derived live anchor config generation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GuiLiveAnchorConfigRequestV1 {
    /// Final archive directory to verify and derive hashes from.
    pub archive_directory: String,
    /// Fresh output path for the canonical anchor-app config file.
    pub output_config_path: String,
    /// Public Ootle network id.
    pub network: String,
    /// Public walletd endpoint.
    pub walletd_endpoint: String,
    /// Public indexer endpoint.
    pub indexer_endpoint: String,
    /// Immutable published v0.39.2 event-template address for this network.
    pub template_address: String,
    /// Immutable event-template module name.
    pub template_module: String,
    /// Full stored event topic; it must equal the module-derived contract topic.
    pub template_event_topic: String,
    /// Lowercase BLAKE3-256 digest of the compiled template artifact.
    pub template_artifact_digest_hex: String,
    /// Bounded number of epochs after the indexer's observed epoch.
    pub max_epoch_delta: u64,
    /// Public fee-account reference.
    pub account_reference: String,
    /// Public fee component address.
    pub fee_component: String,
    /// Public seal signer kind: account, transaction, or imported.
    pub seal_signer_kind: String,
    /// Public seal signer local id.
    pub seal_signer_id: String,
    /// Operator-declared public seal key. This slice records it as ATTESTED.
    pub declared_seal_public_key: String,
    /// Operator attestation that this is a dedicated organizer-only wallet.
    pub dedicated_organizer_wallet_attested: bool,
    /// Maximum fee units for the anchor transaction.
    pub max_fee: u64,
    /// Explicit accepted-ballot floor. Zero is rejected to avoid silent defaulting.
    pub required_accepted_ballot_floor: u64,
    /// Required acknowledgement when the verified final transport binding reports reduced anonymity.
    pub reduced_anonymity_acknowledged: bool,
    /// Fresh snapshot path for the standalone anchor app.
    pub snapshot_path: String,
    /// Fresh evidence path for the standalone anchor app.
    pub evidence_path: String,
    /// Backoff base seconds.
    pub backoff_base_secs: u64,
    /// Backoff cap seconds.
    pub backoff_cap_secs: u64,
    /// Receipt query attempts.
    pub receipt_query_attempts: u32,
    /// Optional request timeout seconds.
    pub request_timeout_secs: Option<u64>,
    /// Optional transaction TTL seconds.
    pub ttl_secs: Option<u64>,
}

/// Safe public result for generated live anchor config.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiLiveAnchorConfigResultV1 {
    /// Written config path.
    pub config_path: String,
    /// Canonical config input provenance.
    pub input_provenance: String,
    /// Derived election manifest hash, lowercase hex.
    pub manifest_hash_hex: String,
    /// Derived finalized archive hash, lowercase hex.
    pub archive_hash_hex: String,
    /// Derived anchor digest, lowercase hex.
    pub anchor_digest_hex: String,
    /// Verified archive accepted count.
    pub accepted_ballot_count: u64,
    /// Explicit operator floor that was enforced.
    pub required_accepted_ballot_floor: u64,
    /// Whether the verified final transport binding reported reduced anonymity.
    pub reduced_anonymity: bool,
    /// Whether reduced anonymity was explicitly acknowledged.
    pub reduced_anonymity_acknowledged: bool,
    /// Bound fee component.
    pub fee_component: String,
    /// Operator-declared seal public key.
    pub declared_seal_public_key: String,
    /// Seal-key assurance in this slice.
    pub seal_assurance: &'static str,
    /// Dedicated organizer wallet attestation.
    pub dedicated_organizer_wallet_attested: bool,
    /// Whole config file BLAKE3-256 digest, lowercase hex.
    pub config_file_blake3_256: String,
    /// Config file byte size.
    pub config_file_bytes: usize,
    /// Pinned event-template address in the V4 config.
    pub template_address: String,
    /// Pinned full event topic in the V4 config.
    pub template_event_topic: String,
    /// Configured max-epoch window.
    pub max_epoch_delta: u64,
}

/// Generates a live anchor config from a verified finalized archive.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] if archive verification, finality,
/// transport-binding, accepted-floor, acknowledgement, path, or public
/// operator config checks fail.
pub fn write_live_anchor_config_from_verified_archive_v1(
    request: &GuiLiveAnchorConfigRequestV1,
) -> Result<GuiLiveAnchorConfigResultV1, GuiCoreError> {
    prevalidate_live_anchor_config_request(request)?;
    let verification = verify_archive_directory_v1(Path::new(&request.archive_directory))?;
    write_live_anchor_config_from_verification_v1(&verification, request)
}

/// Generates a live anchor config, reusing a same-process memoized archive
/// verification for an unchanged archive (Slice 4D).
///
/// Every gate, derived value, and error is identical to
/// [`write_live_anchor_config_from_verified_archive_v1`]; only repeated archive
/// proof replay is avoided on a memo hit.
///
/// # Errors
///
/// See [`write_live_anchor_config_from_verified_archive_v1`].
pub fn write_live_anchor_config_from_verified_archive_with_memo_v1(
    memo: &ArchiveVerificationMemoV1,
    request: &GuiLiveAnchorConfigRequestV1,
) -> Result<GuiLiveAnchorConfigResultV1, GuiCoreError> {
    prevalidate_live_anchor_config_request(request)?;
    let verification =
        verify_archive_directory_with_memo_v1(memo, Path::new(&request.archive_directory))?;
    write_live_anchor_config_from_verification_v1(&verification, request)
}

fn prevalidate_live_anchor_config_request(
    request: &GuiLiveAnchorConfigRequestV1,
) -> Result<(), GuiCoreError> {
    if request.required_accepted_ballot_floor == 0 {
        return Err(GuiCoreError::live_anchor_floor_required());
    }
    if request.max_epoch_delta == 0 {
        return Err(GuiCoreError::live_anchor_field_invalid(
            "GUI_LIVE_ANCHOR_MAX_EPOCH_DELTA_INVALID",
            "the max epoch delta must be at least one",
        ));
    }
    if !request.dedicated_organizer_wallet_attested {
        return Err(GuiCoreError::live_anchor_dedicated_wallet_required());
    }
    crate::live_anchor_preflight::validate_declared_seal_public_key(
        &request.declared_seal_public_key,
    )
    .map(|_| ())
    .map_err(GuiFieldRejectionV1::into_gui_error)
}

fn write_live_anchor_config_from_verification_v1(
    verification: &GuiArchiveVerificationV1,
    request: &GuiLiveAnchorConfigRequestV1,
) -> Result<GuiLiveAnchorConfigResultV1, GuiCoreError> {
    if !verification.verified {
        return Err(GuiCoreError::live_anchor_archive_not_verified());
    }
    if !verification.finalized {
        return Err(GuiCoreError::live_anchor_archive_not_finalized());
    }
    if !verification.transport_binding_verified {
        return Err(GuiCoreError::live_anchor_transport_binding_required());
    }

    let accepted_ballot_count = u64::try_from(verification.accepted_count)
        .map_err(|_| GuiCoreError::live_anchor_operator_config_invalid())?;
    let transport_accepted_count = verification
        .transport_accepted_count
        .ok_or_else(GuiCoreError::live_anchor_transport_binding_required)?;
    if transport_accepted_count != accepted_ballot_count {
        return Err(GuiCoreError::live_anchor_transport_count_mismatch());
    }
    if accepted_ballot_count < request.required_accepted_ballot_floor {
        return Err(GuiCoreError::live_anchor_accepted_floor_not_met());
    }

    let reduced_anonymity = verification
        .transport_reduced_anonymity
        .ok_or_else(GuiCoreError::live_anchor_transport_binding_required)?;
    if reduced_anonymity && !request.reduced_anonymity_acknowledged {
        return Err(GuiCoreError::live_anchor_reduced_anonymity_ack_required());
    }

    let manifest_hash = ManifestHash::new(parse_hash(
        verification
            .election_manifest_hash_hex
            .as_deref()
            .ok_or_else(GuiCoreError::live_anchor_archive_not_verified)?,
    )?);
    let archive_hash = ArchiveHashV1::new(parse_hash(
        verification
            .archive_hash_hex
            .as_deref()
            .ok_or_else(GuiCoreError::live_anchor_archive_not_verified)?,
    )?);

    let output_path = PathBuf::from(&request.output_config_path);
    let snapshot_path = PathBuf::from(&request.snapshot_path);
    let evidence_path = PathBuf::from(&request.evidence_path);
    validate_paths(
        &output_path,
        &snapshot_path,
        &evidence_path,
        Path::new(&request.archive_directory),
    )?;
    if output_path.exists() {
        return Err(GuiCoreError::live_anchor_config_output_exists());
    }

    // Every operator field is parsed through the shared field validators so a
    // failure surfaces the SAME specific machine code the read-only preflight
    // reports (see `crate::live_anchor_preflight`), never the historical generic
    // `GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID` funnel.
    use crate::live_anchor_preflight as preflight;
    let network = preflight::validate_network(&request.network)
        .map_err(GuiFieldRejectionV1::into_gui_error)?;
    // HIGH-3 endpoint policy: walletd stays loopback-only because it may carry
    // bearer authentication and signing state. The indexer may be loopback for
    // advanced/local use or the explicitly trusted hosted HTTPS Esmeralda
    // endpoint for the normal application path.
    let walletd_endpoint = preflight::validate_walletd_endpoint(&request.walletd_endpoint)
        .map_err(GuiFieldRejectionV1::into_gui_error)?;
    let indexer_endpoint =
        preflight::validate_indexer_endpoint_typed(&request.indexer_endpoint, &network)
            .map_err(GuiFieldRejectionV1::into_gui_error)?;
    let template_digest =
        preflight::validate_template_artifact_digest_bytes(&request.template_artifact_digest_hex)
            .map_err(GuiFieldRejectionV1::into_gui_error)?;
    let template_binding = AnchorTemplateBindingV1::new(
        request.template_address.clone(),
        ANCHOR_TEMPLATE_MODULE_V1.to_owned(),
        ANCHOR_EVENT_FUNCTION_V1.to_owned(),
        fixed_anchor_template_event_topic_v1(),
        template_digest,
    )
    .map_err(|_| {
        GuiCoreError::live_anchor_field_invalid(
            "GUI_LIVE_ANCHOR_TEMPLATE_ADDRESS_INVALID",
            "the event-template address does not form a valid deployment binding",
        )
    })?;
    let account_reference = preflight::validate_account_reference(&request.account_reference)
        .map_err(GuiFieldRejectionV1::into_gui_error)?;
    let fee_component = preflight::validate_fee_component(&request.fee_component)
        .map_err(GuiFieldRejectionV1::into_gui_error)?;
    let seal_signer =
        preflight::validate_seal_signer(&request.seal_signer_kind, &request.seal_signer_id)
            .map_err(GuiFieldRejectionV1::into_gui_error)?;
    // MEDIUM-3 fee policy: zero is rejected, and an over-large budget is capped
    // by the shared policy ceiling (also enforced in NetworkAdapterConfig::new).
    let max_fee = preflight::validate_max_fee(request.max_fee)
        .map_err(GuiFieldRejectionV1::into_gui_error)?;

    let network_adapter = NetworkAdapterConfig::new(
        network.clone(),
        walletd_endpoint,
        indexer_endpoint,
        fee_component,
        seal_signer,
        max_fee,
        request.request_timeout_secs,
        request.receipt_query_attempts,
        None,
    )
    .map_err(|_| GuiCoreError::live_anchor_operator_config_invalid())?;

    let live_approval_facts = AnchorLiveApprovalFactsV1::new(
        accepted_ballot_count,
        request.required_accepted_ballot_floor,
        reduced_anonymity,
        request.reduced_anonymity_acknowledged,
        request.declared_seal_public_key.clone(),
        request.dedicated_organizer_wallet_attested,
        true,
    )
    .map_err(GuiCoreError::from)?;

    let config = AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter,
        account_reference,
        manifest_hash,
        archive_hash,
        network,
        snapshot_path,
        evidence_path,
        request.backoff_base_secs,
        request.backoff_cap_secs,
        request.ttl_secs,
        live_approval_facts,
    )
    .with_event_template_binding(template_binding.clone(), request.max_epoch_delta)
    .map_err(GuiCoreError::from)?;
    let canonical_bytes = config.to_canonical_bytes().map_err(GuiCoreError::from)?;
    let decoded =
        AnchorAppConfig::from_canonical_bytes(&canonical_bytes).map_err(GuiCoreError::from)?;
    if decoded.input_provenance() != AnchorConfigInputProvenanceV1::ArchiveVerified {
        return Err(GuiCoreError::live_anchor_operator_config_invalid());
    }
    let Some(decoded_facts) = decoded.live_approval_facts() else {
        return Err(GuiCoreError::live_anchor_operator_config_invalid());
    };
    if decoded_facts.accepted_ballot_count() != accepted_ballot_count
        || decoded_facts.required_accepted_ballot_floor() != request.required_accepted_ballot_floor
        || decoded_facts.reduced_anonymity() != reduced_anonymity
        || decoded_facts.reduced_anonymity_acknowledged() != request.reduced_anonymity_acknowledged
        || decoded_facts.declared_seal_public_key() != request.declared_seal_public_key.as_str()
        || !decoded_facts.finalized_archive()
        || !decoded_facts.dedicated_organizer_wallet_attested()
        || decoded_facts.seal_public_key_assurance() != SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED
    {
        return Err(GuiCoreError::live_anchor_operator_config_invalid());
    }
    if decoded.event_template() != Some(&template_binding)
        || decoded.max_epoch_delta() != Some(request.max_epoch_delta)
    {
        return Err(GuiCoreError::live_anchor_operator_config_invalid());
    }
    config
        .write_canonical_file(&output_path)
        .map_err(GuiCoreError::from)?;

    let file_bytes =
        std::fs::read(&output_path).map_err(|_| GuiCoreError::io_failure("live-anchor-config"))?;
    let config_file_hash = Blake3HashProviderV1.hash(&file_bytes);
    let anchor_digest = OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    )
    .canonical_hash(&Blake3HashProviderV1)
    .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-record"))?;

    Ok(GuiLiveAnchorConfigResultV1 {
        config_path: output_path.to_string_lossy().into_owned(),
        input_provenance: config.input_provenance().as_str().to_owned(),
        manifest_hash_hex: crate::hex::to_lower_hex(manifest_hash.as_bytes()),
        archive_hash_hex: crate::hex::to_lower_hex(archive_hash.as_bytes()),
        anchor_digest_hex: crate::hex::to_lower_hex(anchor_digest.as_bytes()),
        accepted_ballot_count,
        required_accepted_ballot_floor: request.required_accepted_ballot_floor,
        reduced_anonymity,
        reduced_anonymity_acknowledged: request.reduced_anonymity_acknowledged,
        fee_component: request.fee_component.clone(),
        declared_seal_public_key: request.declared_seal_public_key.clone(),
        seal_assurance: SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED,
        dedicated_organizer_wallet_attested: request.dedicated_organizer_wallet_attested,
        config_file_blake3_256: crate::hex::to_lower_hex(&config_file_hash),
        config_file_bytes: file_bytes.len(),
        template_address: request.template_address.clone(),
        template_event_topic: template_binding.full_event_topic().to_owned(),
        max_epoch_delta: request.max_epoch_delta,
    })
}

#[must_use]
pub fn fixed_anchor_template_event_topic_v1() -> String {
    format!("{ANCHOR_TEMPLATE_MODULE_V1}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}")
}

fn parse_hash(hex: &str) -> Result<[u8; 32], GuiCoreError> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GuiCoreError::live_anchor_archive_not_verified());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, GuiCoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(GuiCoreError::live_anchor_archive_not_verified()),
    }
}

fn validate_paths(
    output: &Path,
    snapshot: &Path,
    evidence: &Path,
    archive_dir: &Path,
) -> Result<(), GuiCoreError> {
    for path in [output, snapshot, evidence] {
        if !path.is_absolute() {
            return Err(GuiCoreError::new(
                "GUI_LIVE_ANCHOR_CONFIG_PATH_INVALID",
                GuiErrorCategory::InvalidInput,
                Some("live-anchor-config"),
                "live anchor config paths must be absolute",
            ));
        }
        // HIGH-2 containment guard: no mutable Ootle output/state file may equal
        // or descend from the finalized archive directory. Writing there after
        // archive verification would mutate the "finalized" archive and break
        // later independent verification. The default detached sidecar layout
        // (siblings next to the archive dir) stays non-self-referential.
        if path_is_within_archive(path, archive_dir) {
            return Err(GuiCoreError::live_anchor_output_within_archive());
        }
    }

    let output = normalize_path_for_comparison(output);
    let snapshot = normalize_path_for_comparison(snapshot);
    let evidence = normalize_path_for_comparison(evidence);
    if output == snapshot || output == evidence || snapshot == evidence {
        return Err(GuiCoreError::new(
            "GUI_LIVE_ANCHOR_CONFIG_PATH_COLLISION",
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            "live anchor config output, snapshot, and evidence paths must be distinct",
        ));
    }
    Ok(())
}

fn normalize_path_for_comparison(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    text.trim_end_matches('/').to_lowercase()
}
