//! Version-two event transport primitives for the v0.39.2 Ootle anchor path.
//!
//! These project-owned values describe the narrow public event contract without
//! importing Tari Ootle types. They deliberately preserve `AnchorLogPayloadV1`
//! for reading historical V1 evidence; new anchor construction uses this module.

use tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1;

/// Event topic supplied by the template before the runtime prefixes its module.
pub const ANCHOR_EVENT_TOPIC_SUFFIX_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1";
/// The fixed event-template module that owns the anchor publish function.
pub const ANCHOR_TEMPLATE_MODULE_V1: &str = "tari_private_ballot_anchor";
/// The sole metadata key allowed in an anchor event.
pub const ANCHOR_EVENT_DIGEST_KEY_V1: &str = "anchor_digest";
/// The template's sole callable anchor function.
pub const ANCHOR_EVENT_FUNCTION_V1: &str = "publish_anchor";
/// Maximum validity window accepted by the stock v0.39.2 transaction protocol.
pub const OOTLE_MAX_EPOCH_WINDOW_V1: u64 = 2_160;
/// Project's bounded default validity window; the configured value is pinned.
pub const DEFAULT_ANCHOR_MAX_EPOCH_DELTA_V1: u64 = 12;
/// Maximum metadata pairs copied into detached event evidence.
pub const MAX_ANCHOR_EVENT_METADATA_FIELDS_V2: usize = 8;
/// Maximum byte length of a copied metadata key or value.
pub const MAX_ANCHOR_EVENT_METADATA_BYTES_V2: usize = 256;

/// Bounded validation failure for the event-template identity or epoch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorEventBindingError {
    /// A configured template address is absent or outside the bounded format.
    InvalidTemplateAddress,
    /// A configured module name is absent or contains an unsupported character.
    InvalidModule,
    /// The template exposed a function other than the one narrow ABI entrypoint.
    InvalidFunction,
    /// The configured full stored event topic is not deterministic.
    InvalidEventTopic,
    /// The epoch window is zero, expired, or exceeds the stock bound.
    InvalidEpochWindow,
}

impl AnchorEventBindingError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTemplateAddress => "ANCHOR_EVENT_INVALID_TEMPLATE_ADDRESS",
            Self::InvalidModule => "ANCHOR_EVENT_INVALID_MODULE",
            Self::InvalidFunction => "ANCHOR_EVENT_INVALID_FUNCTION",
            Self::InvalidEventTopic => "ANCHOR_EVENT_INVALID_TOPIC",
            Self::InvalidEpochWindow => "ANCHOR_EVENT_INVALID_EPOCH_WINDOW",
        }
    }
}

impl core::fmt::Display for AnchorEventBindingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for AnchorEventBindingError {}

/// Exact public event payload for a version-two anchor.
///
/// The payload contains one and only one public value: the pre-existing
/// 32-byte aggregate anchor digest rendered as 64 lowercase hexadecimal
/// characters. It cannot carry an archive, ballot, credential, voter data, or
/// free-form metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorEventPayloadV2 {
    digest: OotleAnchorRecordHashV1,
}

/// Detached facts for one event observed in a v0.39.2 transaction receipt.
///
/// It intentionally records the complete (small, bounded) metadata map rather
/// than only the anchor value. That lets an offline verifier reject an event
/// that carried extra public fields after indexer retention has expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEventProofV2 {
    template_address: String,
    topic: String,
    metadata: Vec<(String, String)>,
    event_index: u16,
    receipt_epoch: u64,
    intent_commitment: [u8; 32],
}

impl AnchorEventProofV2 {
    /// Records one bounded event exactly as returned in a transaction receipt.
    pub fn new(
        template_address: String,
        topic: String,
        metadata: Vec<(String, String)>,
        event_index: u16,
        receipt_epoch: u64,
        intent_commitment: [u8; 32],
    ) -> Result<Self, AnchorEventBindingError> {
        if template_address.is_empty()
            || topic.is_empty()
            || metadata.len() > MAX_ANCHOR_EVENT_METADATA_FIELDS_V2
            || metadata.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > MAX_ANCHOR_EVENT_METADATA_BYTES_V2
                    || value.len() > MAX_ANCHOR_EVENT_METADATA_BYTES_V2
            })
        {
            return Err(AnchorEventBindingError::InvalidEventTopic);
        }
        Ok(Self {
            template_address,
            topic,
            metadata,
            event_index,
            receipt_epoch,
            intent_commitment,
        })
    }

    #[must_use]
    pub fn template_address(&self) -> &str {
        &self.template_address
    }
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
    #[must_use]
    pub fn metadata(&self) -> &[(String, String)] {
        &self.metadata
    }
    #[must_use]
    pub const fn event_index(&self) -> u16 {
        self.event_index
    }
    #[must_use]
    pub const fn receipt_epoch(&self) -> u64 {
        self.receipt_epoch
    }
    #[must_use]
    pub const fn intent_commitment(&self) -> &[u8; 32] {
        &self.intent_commitment
    }
}

impl AnchorEventPayloadV2 {
    /// Creates the exact event payload from the existing canonical digest.
    #[must_use]
    pub const fn from_digest(digest: OotleAnchorRecordHashV1) -> Self {
        Self { digest }
    }

    /// Returns the bound aggregate anchor digest.
    #[must_use]
    pub const fn digest(self) -> OotleAnchorRecordHashV1 {
        self.digest
    }

    /// Renders the only permitted payload value as 64 lowercase hex characters.
    #[must_use]
    pub fn digest_hex(self) -> String {
        to_lower_hex(self.digest.as_bytes())
    }
}

/// Immutable deployment and ABI identity for the event-only template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorTemplateBindingV1 {
    template_address: String,
    module: String,
    function: String,
    full_event_topic: String,
    artifact_digest: [u8; 32],
}

impl AnchorTemplateBindingV1 {
    /// Creates a validated immutable template identity.
    ///
    /// `full_event_topic` must be exactly `<module>.<topic-suffix>` because the
    /// Ootle runtime prefixes custom event topics with the active template
    /// module. Only the approved `publish_anchor` ABI function is accepted.
    pub fn new(
        template_address: String,
        module: String,
        function: String,
        full_event_topic: String,
        artifact_digest: [u8; 32],
    ) -> Result<Self, AnchorEventBindingError> {
        if !(9..=128).contains(&template_address.len())
            || !template_address.starts_with("template_")
            || template_address
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            return Err(AnchorEventBindingError::InvalidTemplateAddress);
        }
        if module.is_empty()
            || module.len() > 128
            || !module
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(AnchorEventBindingError::InvalidModule);
        }
        if function != ANCHOR_EVENT_FUNCTION_V1 {
            return Err(AnchorEventBindingError::InvalidFunction);
        }
        let expected_topic = format!("{module}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}");
        if full_event_topic != expected_topic || full_event_topic.len() > 255 {
            return Err(AnchorEventBindingError::InvalidEventTopic);
        }
        Ok(Self {
            template_address,
            module,
            function,
            full_event_topic,
            artifact_digest,
        })
    }

    /// Returns the published template address in Ootle's textual form.
    #[must_use]
    pub fn template_address(&self) -> &str {
        &self.template_address
    }

    /// Returns the fixed template module name.
    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns the sole permitted function name.
    #[must_use]
    pub fn function(&self) -> &str {
        &self.function
    }

    /// Returns the exact stored event topic expected in a receipt.
    #[must_use]
    pub fn full_event_topic(&self) -> &str {
        &self.full_event_topic
    }

    /// Returns the compiled template artifact's BLAKE3-256 digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }
}

/// Persisted epoch observation and frozen bounded transaction expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorEpochBindingV1 {
    observed_epoch: u64,
    max_epoch: u64,
}

impl AnchorEpochBindingV1 {
    /// Creates a bounded expiry binding from an observed indexer epoch and
    /// configured delta.
    pub fn from_observed_epoch(
        observed_epoch: u64,
        max_epoch_delta: u64,
    ) -> Result<Self, AnchorEventBindingError> {
        if max_epoch_delta == 0 || max_epoch_delta > OOTLE_MAX_EPOCH_WINDOW_V1 {
            return Err(AnchorEventBindingError::InvalidEpochWindow);
        }
        let max_epoch = observed_epoch
            .checked_add(max_epoch_delta)
            .ok_or(AnchorEventBindingError::InvalidEpochWindow)?;
        Ok(Self {
            observed_epoch,
            max_epoch,
        })
    }

    /// Recreates an already-persisted epoch binding while validating it.
    pub fn new(observed_epoch: u64, max_epoch: u64) -> Result<Self, AnchorEventBindingError> {
        let Some(delta) = max_epoch.checked_sub(observed_epoch) else {
            return Err(AnchorEventBindingError::InvalidEpochWindow);
        };
        Self::from_observed_epoch(observed_epoch, delta)
    }

    /// Returns the epoch observed from the configured indexer before CREATE.
    #[must_use]
    pub const fn observed_epoch(self) -> u64 {
        self.observed_epoch
    }

    /// Returns the frozen transaction expiration epoch.
    #[must_use]
    pub const fn max_epoch(self) -> u64 {
        self.max_epoch
    }
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
