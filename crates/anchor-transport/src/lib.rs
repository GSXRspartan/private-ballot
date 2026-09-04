#![forbid(unsafe_code)]

//! Offline, dependency-free anchor-transport boundaries.
//!
//! This leaf crate defines the project-owned application contract for taking a
//! completed [`OotleAnchorRecordHashV1`] through the confirmed Tari Ootle
//! anchoring lifecycle — canonical `EmitLog` payload, walletd request
//! preparation, approval, submission, finality polling, independent receipt
//! retrieval, receipt/log verification, and persistent recovery — **without
//! importing any Tari Ootle, walletd-client, indexer-client, HTTP, RPC, or
//! async-runtime dependency**. It ships a deterministic in-memory fake so the
//! whole contract is testable offline before any real network adapter exists.
//!
//! The crate depends only on the offline [`tari_cc_private_ballot_anchor`]
//! record/digest types and the [`tari_cc_private_ballot_protocol`] production
//! hash provider. It exposes no private-key material and cannot mutate the
//! authoritative offline archive: preparing, approving, submitting, or verifying
//! an anchor is a pure transformation of already-frozen commitments, so a
//! failure at any step leaves [`OotleAnchorRecordV1`] and the archive unchanged.
//!
//! [`OotleAnchorRecordHashV1`]: tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1
//! [`OotleAnchorRecordV1`]: tari_cc_private_ballot_anchor::OotleAnchorRecordV1

mod agreement;
mod errors;
mod event;
mod fake;
mod identifiers;
mod model;
mod payload;
mod traits;
mod verification;

pub use agreement::compare_receipt_observations;
pub use errors::{
    AnchorApprovalError, AnchorIdentifierError, AnchorLogPayloadError,
    AnchorObservationAgreementError, AnchorPreparationError, AnchorReceiptQueryError,
    AnchorReceiptVerificationError, AnchorRequestLookupError, AnchorSubmissionError,
};
pub use event::{
    ANCHOR_EVENT_DIGEST_KEY_V1, ANCHOR_EVENT_DIGEST_KEY_V2, ANCHOR_EVENT_ELECTION_ID_KEY_V2,
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_NETWORK_KEY_V2,
    ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V1, ANCHOR_EVENT_TOPIC_SUFFIX_V2,
    ANCHOR_TEMPLATE_MODULE_V1, ANCHOR_TEMPLATE_MODULE_V2, ANCHOR_TEMPLATE_RECEIPT_TOPIC_PREFIX_V2,
    AnchorEpochBindingV1, AnchorEventBindingError, AnchorEventPayloadV2, AnchorEventPayloadV3,
    AnchorEventProofV2, AnchorTemplateBindingV1, AnchorTemplateBindingV2,
    DEFAULT_ANCHOR_MAX_EPOCH_DELTA_V1, MAX_ANCHOR_EVENT_METADATA_BYTES_V2,
    MAX_ANCHOR_EVENT_METADATA_FIELDS_V2, OOTLE_MAX_EPOCH_WINDOW_V1,
};
pub use fake::{DeterministicAnchorFake, FakeFinality};
pub use identifiers::{
    AnchorAccountReference, AnchorClientReferenceV1, AnchorRequestId, AnchorTransactionId,
    MAX_ANCHOR_IDENTIFIER_BYTES,
};
pub use model::{
    AnchorBindingV1, AnchorFinalStatusV1, AnchorLifecycleSnapshotV1, AnchorLifecycleState,
    AnchorLogEntryV1, AnchorLogLevelV1, AnchorMaxFeeV1, AnchorPreparationRequest,
    AnchorQueryOutcomeV1, AnchorReceiptSourceKindV1, AnchorReceiptV1, AnchorRequestDecisionV1,
    ApprovedAnchorTransaction, PreparedAnchorTransaction, SubmittedAnchorTransaction,
};
pub use payload::{
    ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1, ANCHOR_LOG_PAYLOAD_DIGEST_HEX_LEN,
    ANCHOR_LOG_PAYLOAD_PREFIX_V1, ANCHOR_LOG_PAYLOAD_SEPARATOR, AnchorLogPayloadV1,
};
pub use traits::{
    AnchorReceiptSource, AnchorTransactionApprover, AnchorTransactionRequestStore,
    AnchorTransactionSubmitter,
};
pub use verification::{
    VerifiedAnchorEvidenceV1, VerifiedAnchorEvidenceV2, verify_anchor_receipt,
    verify_query_outcome, verify_v2_event_receipt, verify_v39_event_receipt,
};

/// Re-exported bounded network identifier, reused unchanged from the anchor
/// crate so the transport layer commits to the same network-name validation.
pub use tari_cc_private_ballot_anchor::OotleNetworkIdV1;

/// Project-owned alias for the reused network identifier.
pub type AnchorNetworkId = OotleNetworkIdV1;
