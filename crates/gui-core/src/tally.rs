//! Deterministic tally facade over the existing [`ApprovalTally`] logic.
//!
//! This module performs no tally arithmetic of its own; it only renders the
//! existing tally result into a GUI-facing summary. A tie is always reported
//! as a tie; no winner is ever invented.

use tari_cc_private_ballot_ballot::CandidateSet;
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};

/// One candidate's approval count with its display name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiTallyCountV1 {
    /// Stable machine candidate identifier, lowercase hex.
    pub candidate_id_hex: String,
    /// Machine identifier as UTF-8 text, when it is valid UTF-8.
    pub candidate_id_text: Option<String>,
    /// Human-facing display name.
    pub display_name: String,
    /// Number of approvals.
    pub approvals: u64,
}

/// The leading outcome, mirroring [`LeadingResult`] exactly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum GuiLeadingResultV1 {
    /// No candidate received any approval.
    NoApprovals,
    /// Exactly one candidate holds the highest approval count.
    SingleLeader {
        /// Stable machine candidate identifier, lowercase hex.
        candidate_id_hex: String,
        /// Human-facing display name.
        display_name: String,
        /// The leading approval count.
        approvals: u64,
    },
    /// Multiple candidates share the highest approval count. Unresolved.
    Tie {
        /// Tied machine candidate identifiers (canonical order), lowercase hex.
        candidate_ids_hex: Vec<String>,
        /// The shared approval count.
        approvals: u64,
    },
}

/// GUI-facing deterministic tally summary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiTallySummaryV1 {
    /// Number of accepted ballots included in the tally.
    pub accepted_ballots: u64,
    /// Number of accepted abstentions.
    pub abstentions: u64,
    /// Per-candidate counts in canonical machine-ID order.
    pub counts: Vec<GuiTallyCountV1>,
    /// The leading outcome (never an invented winner).
    pub leading: GuiLeadingResultV1,
}

/// Renders an existing [`ApprovalTally`] into the GUI-facing summary.
///
/// Display names are resolved from the supplied authoritative candidate set;
/// a count whose candidate ID is absent from the set (impossible for a tally
/// built by [`ApprovalTally::from_ballots`]) renders with an empty display
/// name rather than failing.
#[must_use]
pub fn summarize_tally(tally: &ApprovalTally, candidates: &CandidateSet) -> GuiTallySummaryV1 {
    let display_name_of = |id_bytes: &[u8]| -> String {
        candidates
            .candidates()
            .iter()
            .find(|candidate| candidate.id().as_bytes() == id_bytes)
            .map(|candidate| candidate.display_name().to_owned())
            .unwrap_or_default()
    };

    let counts = tally
        .counts()
        .iter()
        .map(|count| {
            let id_bytes = count.candidate_id().as_bytes();
            GuiTallyCountV1 {
                candidate_id_hex: crate::hex::to_lower_hex(id_bytes),
                candidate_id_text: core::str::from_utf8(id_bytes).ok().map(str::to_owned),
                display_name: display_name_of(id_bytes),
                approvals: count.approvals(),
            }
        })
        .collect();

    let leading = match tally.leading_result() {
        LeadingResult::NoApprovals => GuiLeadingResultV1::NoApprovals,
        LeadingResult::SingleLeader {
            candidate_id,
            approvals,
        } => GuiLeadingResultV1::SingleLeader {
            candidate_id_hex: crate::hex::to_lower_hex(candidate_id.as_bytes()),
            display_name: display_name_of(candidate_id.as_bytes()),
            approvals,
        },
        LeadingResult::Tie {
            candidate_ids,
            approvals,
        } => GuiLeadingResultV1::Tie {
            candidate_ids_hex: candidate_ids
                .iter()
                .map(|id| crate::hex::to_lower_hex(id.as_bytes()))
                .collect(),
            approvals,
        },
    };

    GuiTallySummaryV1 {
        accepted_ballots: tally.accepted_ballots(),
        abstentions: tally.abstentions(),
        counts,
        leading,
    }
}
