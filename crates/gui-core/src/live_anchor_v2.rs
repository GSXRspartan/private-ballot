//! V2 richer public anchor: build the canonical public payload from a verified
//! finalized archive, and verify a detached payload back against the archive.
//!
//! The V2 anchor publishes an election *summary* (question, per-option tally,
//! commitments, counts) derived solely from the independently verified,
//! finalized archive — never per-voter data. Corrected V2 on-chain shape: the
//! full canonical public-summary bytes go on-chain verbatim, so the emitted
//! event is directly readable. The on-chain `anchor_digest_v2` is the
//! domain-separated BLAKE3 of exactly those bytes, so an independent observer
//! can display and cryptographically re-verify the event without the detached
//! archive. [`verify_v2_public_payload_against_archive_v1`] additionally proves
//! that the detached payload was re-derived from an authoritative archive
//! replay.

use std::path::Path;

use tari_cc_private_ballot_anchor::{
    OotleAnchorPublicPayloadV2, OotleAnchorTallyEntryV2, OotleAnchorTemplateBindingV2,
    OotleNetworkIdV1, assert_v2_public_payload_is_leak_free,
};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    AnchorEventPayloadV3, AnchorTemplateBindingV2,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_archive::ArchiveVerificationMemoV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash};

use crate::archive_verify::{
    GuiArchiveVerificationV1, verify_archive_directory_v1, verify_archive_directory_with_memo_v1,
};
use crate::error::{GuiCoreError, GuiErrorCategory};

/// Public inputs for building or verifying a V2 public payload. The template
/// identity fields come from the locked V2 deployment; the network mirrors it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GuiLiveAnchorV2RequestV1 {
    pub archive_directory: String,
    pub network: String,
    pub template_address: String,
    pub template_module: String,
    pub template_function: String,
    pub template_event_topic: String,
    pub template_artifact_digest_hex: String,
}

/// One public tally row in the V2 result (safe for display and evidence).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiV2TallyRowV1 {
    pub display_label: String,
    pub machine_id_hex: String,
    pub count: u64,
}

/// Safe public result of building a V2 payload from a verified archive.
///
/// * `payload_hex` — lowercase-hex of the canonical public-summary bytes, used
///   as the ASCII-safe transport form for evidence sidecars and lifecycle
///   requests.
/// * `public_summary_json` — the same canonical bytes rendered as a UTF-8
///   string. This is exactly what the corrected V2 template puts on-chain in
///   the `public_summary` metadata field, so displaying this locally matches
///   what an indexer will show.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiLiveAnchorV2ResultV1 {
    /// Domain-separated V2 public-payload digest, lowercase hex (goes on-chain).
    pub v2_anchor_digest_hex: String,
    /// Hex-encoded canonical public-summary bytes (for evidence transport).
    pub payload_hex: String,
    /// Canonical public-summary UTF-8 string (exact on-chain metadata value).
    pub public_summary_json: String,
    pub network: String,
    /// Exact canonical election identifier text (e.g. "500-votertest-01") —
    /// the same UTF-8 string that appears verbatim inside `public_summary_json`
    /// and as the on-chain `election_id` metadata value.
    pub election_id: String,
    /// Lowercase-hex encoding of the election identifier bytes, kept for
    /// evidence-transport backward compatibility (existing consumers may
    /// serialize the raw bytes as hex). The two representations are two
    /// views of the same bytes.
    pub election_id_hex: String,
    pub ballot_question: String,
    pub ballot_kind: String,
    pub confidentiality_mode: String,
    pub proof_suite: String,
    pub manifest_hash_hex: String,
    pub archive_hash_hex: String,
    pub registry_commitment_hex: String,
    pub option_set_commitment_hex: String,
    pub eligible_voter_count: u64,
    pub accepted_ballot_count: u64,
    pub rejected_ballot_count: u64,
    pub tally: Vec<GuiV2TallyRowV1>,
    pub archive_finalized: bool,
    pub template_address: String,
    pub template_module: String,
    pub template_function: String,
    pub template_event_topic: String,
    pub template_artifact_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GuiV2AnchorPublishPreparationRequestV1 {
    pub archive_directory: String,
    pub payload_hex: String,
    pub expected_digest_hex: String,
}

/// Public review record for the exact V2 CallFunction constructed offline.
/// It deliberately contains no walletd credential, signer, or voter material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiV2AnchorPublishPreparationV1 {
    pub template_address: String,
    pub template_module: String,
    pub template_function: String,
    pub template_event_topic: String,
    pub anchor_digest_hex: String,
    pub arguments: Vec<String>,
    /// The exact readable `public_summary` argument that the V2 template will
    /// put on-chain — surfaced separately so the preview does not have to slice
    /// it out of the argument list.
    pub public_summary_json: String,
}

pub fn prepare_v2_anchor_publish_from_verified_evidence_v1(
    request: &GuiV2AnchorPublishPreparationRequestV1,
    deployment: &AnchorTemplateBindingV2,
) -> Result<GuiV2AnchorPublishPreparationV1, GuiCoreError> {
    let payload_bytes = decode_hex(&request.payload_hex)?;
    let event_payload = v2_event_payload_from_verified_evidence_v1(
        Path::new(&request.archive_directory),
        &payload_bytes,
        &request.expected_digest_hex,
        deployment,
    )?;
    tari_cc_private_ballot_ootle_anchor_adapter::build_v2_anchor_call_function(
        deployment,
        &event_payload,
    )
    .map_err(|_| {
        GuiCoreError::new(
            "GUI_ANCHOR_V2_TRANSACTION_CONSTRUCTION_FAILED",
            GuiErrorCategory::BindingMismatch,
            Some("anchor-v2-publish"),
            "the verified V2 payload could not construct the required template call",
        )
    })?;
    Ok(GuiV2AnchorPublishPreparationV1 {
        template_address: deployment.template_address().to_owned(),
        template_module: deployment.module().to_owned(),
        template_function: deployment.function().to_owned(),
        template_event_topic: deployment.full_event_topic(),
        anchor_digest_hex: event_payload.digest_hex(),
        arguments: vec![
            event_payload.digest_hex(),
            event_payload.network().to_owned(),
            event_payload.election_id().to_owned(),
            event_payload.public_summary().to_owned(),
        ],
        public_summary_json: event_payload.public_summary().to_owned(),
    })
}

/// Produces the exact four template arguments only after the detached
/// payload has been recomputed and matched against the finalized archive.
pub fn v2_event_payload_from_verified_evidence_v1(
    archive_directory: &Path,
    payload_bytes: &[u8],
    expected_digest_hex: &str,
    expected_template: &AnchorTemplateBindingV2,
) -> Result<AnchorEventPayloadV3, GuiCoreError> {
    let result = verify_v2_public_payload_against_archive_v1(
        archive_directory,
        payload_bytes,
        expected_digest_hex,
    )?;
    if result.template_address != expected_template.template_address()
        || result.template_module != expected_template.module()
        || result.template_function != expected_template.function()
        || result.template_event_topic != expected_template.full_event_topic()
        || decode_hash32(&result.template_artifact_digest_hex)
            .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?
            != *expected_template.artifact_digest()
    {
        return Err(GuiCoreError::new(
            "GUI_ANCHOR_V2_DEPLOYMENT_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("anchor-v2-payload"),
            "the detached V2 payload is not bound to the locked V2 deployment",
        ));
    }
    AnchorEventPayloadV3::new(
        decode_hash32(&result.v2_anchor_digest_hex).map_err(|_| {
            GuiCoreError::new(
                "GUI_ANCHOR_V2_DIGEST_INVALID",
                GuiErrorCategory::InvalidInput,
                Some("anchor-v2-payload"),
                "the V2 digest is invalid",
            )
        })?,
        result.network,
        // The V2 template + verifier accept the exact canonical election
        // identifier text from the archive — never a hex re-encoding of it.
        result.election_id,
        result.public_summary_json,
    )
    .map_err(|_| {
        GuiCoreError::new(
            "GUI_ANCHOR_V2_EVENT_ARGUMENT_INVALID",
            GuiErrorCategory::BindingMismatch,
            Some("anchor-v2-payload"),
            "the verified V2 payload cannot be represented by the V2 template ABI",
        )
    })
}

/// Builds the canonical V2 public payload from a verified finalized archive.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] if archive verification, finality,
/// transport binding, field derivation, the privacy guard, or digest
/// computation fails.
pub fn build_v2_public_payload_from_verified_archive_v1(
    request: &GuiLiveAnchorV2RequestV1,
) -> Result<GuiLiveAnchorV2ResultV1, GuiCoreError> {
    let verification = verify_archive_directory_v1(Path::new(&request.archive_directory))?;
    build_from_verification(&verification, request)
}

/// Builds the V2 payload, reusing a same-process memoized archive verification.
///
/// # Errors
///
/// See [`build_v2_public_payload_from_verified_archive_v1`].
pub fn build_v2_public_payload_from_verified_archive_with_memo_v1(
    memo: &ArchiveVerificationMemoV1,
    request: &GuiLiveAnchorV2RequestV1,
) -> Result<GuiLiveAnchorV2ResultV1, GuiCoreError> {
    let verification =
        verify_archive_directory_with_memo_v1(memo, Path::new(&request.archive_directory))?;
    build_from_verification(&verification, request)
}

fn build_from_verification(
    verification: &GuiArchiveVerificationV1,
    request: &GuiLiveAnchorV2RequestV1,
) -> Result<GuiLiveAnchorV2ResultV1, GuiCoreError> {
    let payload = payload_from_verification(verification, request)?;
    assert_v2_public_payload_is_leak_free(&payload)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    let payload_bytes = payload
        .to_canonical_json_bytes()
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    let digest = payload
        .canonical_digest(&Blake3HashProviderV1)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    Ok(result_from_payload(&payload, &payload_bytes, &digest))
}

fn payload_from_verification(
    verification: &GuiArchiveVerificationV1,
    request: &GuiLiveAnchorV2RequestV1,
) -> Result<OotleAnchorPublicPayloadV2, GuiCoreError> {
    if !verification.verified {
        return Err(GuiCoreError::live_anchor_archive_not_verified());
    }
    if !verification.finalized {
        return Err(GuiCoreError::live_anchor_archive_not_finalized());
    }
    if !verification.transport_binding_verified {
        return Err(GuiCoreError::live_anchor_transport_binding_required());
    }
    if request.template_module != ANCHOR_TEMPLATE_MODULE_V2
        || request.template_function != ANCHOR_EVENT_FUNCTION_V2
        || request.template_event_topic
            != format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}")
    {
        return Err(GuiCoreError::trusted_ootle_deployment_invalid());
    }
    AnchorTemplateBindingV2::new(
        request.template_address.clone(),
        request.template_module.clone(),
        request.template_function.clone(),
        request.template_event_topic.clone(),
        decode_hash32(&request.template_artifact_digest_hex)
            .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?,
    )
    .map_err(|_| GuiCoreError::trusted_ootle_deployment_invalid())?;

    let network = OotleNetworkIdV1::new(request.network.clone())
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    let election_id = decode_hex(field(
        verification.election_id_hex.as_deref(),
        "election id",
    )?)?;
    let manifest_hash = ManifestHash::new(decode_hash32(field(
        verification.election_manifest_hash_hex.as_deref(),
        "manifest hash",
    )?)?);
    let archive_hash = ArchiveHashV1::new(decode_hash32(field(
        verification.archive_hash_hex.as_deref(),
        "archive hash",
    )?)?);
    let registry_commitment = decode_hash32(field(
        verification.registry_commitment_hex.as_deref(),
        "registry commitment",
    )?)?;
    let option_set_commitment = decode_hash32(field(
        verification.option_set_commitment_hex.as_deref(),
        "option-set commitment",
    )?)?;
    let ballot_kind = field(verification.ballot_kind_id.as_deref(), "ballot kind")?.to_owned();
    let confidentiality_mode = field(
        verification.ballot_confidentiality_id.as_deref(),
        "confidentiality mode",
    )?
    .to_owned();
    let proof_suite = field(verification.proof_suite_id.as_deref(), "proof suite")?.to_owned();
    let eligible_voter_count = verification
        .eligible_voter_count
        .ok_or_else(|| missing("eligible voter count"))?;
    let ballot_question = verification.proposal_question.clone().unwrap_or_default();

    let accepted_ballot_count =
        u64::try_from(verification.accepted_count).map_err(|_| missing("accepted ballot count"))?;
    let rejected_ballot_count =
        u64::try_from(verification.rejected_count).map_err(|_| missing("rejected ballot count"))?;

    let tally = tally_from_verification(verification)?;

    let template_artifact_digest =
        decode_hash32(&request.template_artifact_digest_hex).map_err(|_| {
            GuiCoreError::live_anchor_field_invalid(
                "GUI_LIVE_ANCHOR_TEMPLATE_ARTIFACT_DIGEST_INVALID",
                "the V2 template artifact digest is not 64 hex characters",
            )
        })?;

    Ok(OotleAnchorPublicPayloadV2 {
        network,
        election_id,
        ballot_question,
        ballot_kind,
        confidentiality_mode,
        proof_suite,
        manifest_hash,
        archive_hash,
        registry_commitment,
        option_set_commitment,
        eligible_voter_count,
        accepted_ballot_count,
        rejected_ballot_count,
        tally,
        archive_finalized: verification.finalized,
        finalized_timestamp_unix_secs: None,
        template: OotleAnchorTemplateBindingV2 {
            template_address: request.template_address.clone(),
            template_module: request.template_module.clone(),
            template_function: request.template_function.clone(),
            event_topic: request.template_event_topic.clone(),
            artifact_digest: template_artifact_digest,
        },
    })
}

fn tally_from_verification(
    verification: &GuiArchiveVerificationV1,
) -> Result<Vec<OotleAnchorTallyEntryV2>, GuiCoreError> {
    let tally = verification
        .tally
        .as_ref()
        .ok_or_else(|| missing("tally"))?;
    let mut entries = Vec::with_capacity(tally.counts.len());
    for count in &tally.counts {
        entries.push(OotleAnchorTallyEntryV2 {
            display_label: count.display_name.clone(),
            machine_id: decode_hex(&count.candidate_id_hex)?,
            count: count.approvals,
        });
    }
    Ok(entries)
}

fn result_from_payload(
    payload: &OotleAnchorPublicPayloadV2,
    payload_bytes: &[u8],
    digest: &[u8; 32],
) -> GuiLiveAnchorV2ResultV1 {
    // The canonical payload bytes are guaranteed to be valid UTF-8 (the writer
    // never emits anything else); render them once for the readable field.
    let public_summary_json = std::str::from_utf8(payload_bytes)
        .expect("canonical V2 payload bytes are valid UTF-8 by construction")
        .to_owned();
    // The election_id text is guaranteed to be valid UTF-8 by
    // `OotleAnchorPublicPayloadV2::validate` before we ever reach here.
    let election_id_text = std::str::from_utf8(&payload.election_id)
        .expect("validate() guarantees election_id is UTF-8")
        .to_owned();
    GuiLiveAnchorV2ResultV1 {
        v2_anchor_digest_hex: crate::hex::to_lower_hex(digest),
        payload_hex: crate::hex::to_lower_hex(payload_bytes),
        public_summary_json,
        network: payload.network.as_str().to_owned(),
        election_id: election_id_text,
        election_id_hex: crate::hex::to_lower_hex(&payload.election_id),
        ballot_question: payload.ballot_question.clone(),
        ballot_kind: payload.ballot_kind.clone(),
        confidentiality_mode: payload.confidentiality_mode.clone(),
        proof_suite: payload.proof_suite.clone(),
        manifest_hash_hex: crate::hex::to_lower_hex(payload.manifest_hash.as_bytes()),
        archive_hash_hex: crate::hex::to_lower_hex(payload.archive_hash.as_bytes()),
        registry_commitment_hex: crate::hex::to_lower_hex(&payload.registry_commitment),
        option_set_commitment_hex: crate::hex::to_lower_hex(&payload.option_set_commitment),
        eligible_voter_count: payload.eligible_voter_count,
        accepted_ballot_count: payload.accepted_ballot_count,
        rejected_ballot_count: payload.rejected_ballot_count,
        tally: payload
            .tally
            .iter()
            .map(|entry| GuiV2TallyRowV1 {
                display_label: entry.display_label.clone(),
                machine_id_hex: crate::hex::to_lower_hex(&entry.machine_id),
                count: entry.count,
            })
            .collect(),
        archive_finalized: payload.archive_finalized,
        template_address: payload.template.template_address.clone(),
        template_module: payload.template.template_module.clone(),
        template_function: payload.template.template_function.clone(),
        template_event_topic: payload.template.event_topic.clone(),
        template_artifact_digest_hex: crate::hex::to_lower_hex(&payload.template.artifact_digest),
    }
}

/// Verifies a detached V2 public payload against an archive and expected digest.
///
/// This is the offline V2 verifier (Task I): it decodes `payload_bytes` as
/// canonical JSON, confirms its digest equals `expected_digest_hex` (the
/// on-chain/receipt value), then independently rebuilds the payload from the
/// archive replay and asserts every field matches, and finally runs the
/// privacy guard. Any tamper — a changed question, tally, commitment, count,
/// archive/manifest hash, or template binding — fails.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] describing the first mismatch.
pub fn verify_v2_public_payload_against_archive_v1(
    archive_directory: &Path,
    payload_bytes: &[u8],
    expected_digest_hex: &str,
) -> Result<GuiLiveAnchorV2ResultV1, GuiCoreError> {
    let payload = OotleAnchorPublicPayloadV2::from_canonical_json_bytes(payload_bytes)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    assert_v2_public_payload_is_leak_free(&payload)
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;

    let expected = decode_hash32(expected_digest_hex).map_err(|_| {
        GuiCoreError::new(
            "GUI_ANCHOR_V2_DIGEST_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("anchor-v2-payload"),
            "the expected V2 digest is not 64 hex characters",
        )
    })?;
    payload
        .verify_digest(&Blake3HashProviderV1, &expected)
        .map_err(|_| {
            GuiCoreError::new(
                "GUI_ANCHOR_V2_DIGEST_MISMATCH",
                GuiErrorCategory::BindingMismatch,
                Some("anchor-v2-payload"),
                "the V2 payload does not hash to the expected on-chain digest",
            )
        })?;

    // Independently rebuild from the archive and require an exact match.
    let verification = verify_archive_directory_v1(archive_directory)?;
    let request = GuiLiveAnchorV2RequestV1 {
        archive_directory: archive_directory.to_string_lossy().into_owned(),
        network: payload.network.as_str().to_owned(),
        template_address: payload.template.template_address.clone(),
        template_module: payload.template.template_module.clone(),
        template_function: payload.template.template_function.clone(),
        template_event_topic: payload.template.event_topic.clone(),
        template_artifact_digest_hex: crate::hex::to_lower_hex(&payload.template.artifact_digest),
    };
    let rebuilt = payload_from_verification(&verification, &request)?;
    if rebuilt != payload {
        return Err(GuiCoreError::new(
            "GUI_ANCHOR_V2_ARCHIVE_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("anchor-v2-payload"),
            "the V2 payload does not match an independent archive replay",
        ));
    }

    let payload_bytes_canonical = payload
        .to_canonical_json_bytes()
        .map_err(|error| GuiCoreError::from_protocol(&error, "anchor-v2-payload"))?;
    Ok(result_from_payload(
        &payload,
        &payload_bytes_canonical,
        &expected,
    ))
}

fn field<'a>(value: Option<&'a str>, name: &'static str) -> Result<&'a str, GuiCoreError> {
    value.ok_or_else(|| missing_named(name))
}

fn missing(_name: &'static str) -> GuiCoreError {
    GuiCoreError::new(
        "GUI_ANCHOR_V2_ARCHIVE_FIELD_MISSING",
        GuiErrorCategory::ArchiveIntegrity,
        Some("anchor-v2-payload"),
        "a required public field could not be derived from the archive",
    )
}

fn missing_named(name: &'static str) -> GuiCoreError {
    let _ = name;
    missing(name)
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, GuiCoreError> {
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(missing("hex field"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        out.push((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?);
    }
    Ok(out)
}

fn decode_hash32(hex: &str) -> Result<[u8; 32], GuiCoreError> {
    let bytes = decode_hex(hex)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| missing("32-byte field"))
}

fn hex_nibble(byte: u8) -> Result<u8, GuiCoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(missing("hex digit")),
    }
}
