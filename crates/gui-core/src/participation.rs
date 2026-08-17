//! Privacy-aware participation metrics and disclosure policy (Slice 5A5).
//!
//! This module derives a bounded, application-facing participation summary from
//! authoritative backend state only: the frozen registry size (eligible voters)
//! and the ballot-acceptance ledger length (accepted ballots). It performs no
//! tally arithmetic and never discloses per-option results.
//!
//! ## Disclosure policy is application-local, not canonical
//!
//! The version-one election manifest carries no participation-visibility,
//! quorum, or privacy-mode field. The visibility policy computed here is
//! therefore **local application policy**, not part of the signed/canonical
//! election manifest. It is never serialized into canonical election files or
//! the offline archive. The conservative default is [`ParticipationVisibility::SealedUntilClose`]
//! while voting is open: exact accepted counts, percentages, and any trend
//! data are hidden until voting closes, after which exact participation is
//! shown.
//!
//! ## No authoritative timestamps
//!
//! The archive's [`IngestSequenceV1`] is ordering metadata only and is
//! explicitly not a wall-clock timestamp. There is no authoritative event-time
//! source for a turnout-over-time series. This module therefore exposes a
//! single current participation snapshot and no time series; the frontend
//! renders a progress track rather than a fabricated chart.

use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;

/// Conservative threshold below which a live participation timeline could
/// leak metadata in small electorates. The default policy is already
/// `SealedUntilClose` while open, so small electorates are inherently
/// protected; this flag is exposed for transparency and defense-in-depth.
pub const SMALL_ELECTORATE_THRESHOLD: usize = 25;

/// Application-local participation-visibility policy.
///
/// This is not a canonical manifest field. The backend resolves the current
/// variant from lifecycle state (and, in the future, an operator or manifest
/// policy when one exists). The conservative default while open is
/// [`Self::SealedUntilClose`].
// The JSON projection uses the stable SCREAMING_SNAKE_CASE identifiers (the
// same strings [`Self::as_str`] documents and the frontend DTO mirror
// expects), not the serde-default variant names. Without this rename the
// wire value would be `"SealedUntilClose"` while the frontend looks for
// `"SEALED_UNTIL_CLOSE"`, silently defeating every visibility comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParticipationVisibility {
    /// Exact accepted count and percentage may be shown (post-close only by
    /// default).
    Live,
    /// Only a coarse participation bucket is shown while open; the exact count
    /// and percentage are hidden.
    Coarse,
    /// While open, no participation numerics are disclosed. After close, exact
    /// participation is shown.
    SealedUntilClose,
}

impl ParticipationVisibility {
    /// Returns the stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "LIVE",
            Self::Coarse => "COARSE",
            Self::SealedUntilClose => "SEALED_UNTIL_CLOSE",
        }
    }
}

/// Result-disclosure state, mirroring the 5A4 tally gate.
// See [`ParticipationVisibility`]: serialize as the stable
// SCREAMING_SNAKE_CASE identifiers the frontend DTO mirror expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultVisibility {
    /// Per-option results are sealed (DRAFT/FROZEN/OPEN).
    Sealed,
    /// Per-option results may be disclosed (CLOSED/VERIFIED/FINALIZED).
    Disclosed,
}

impl ResultVisibility {
    /// Returns the stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "SEALED",
            Self::Disclosed => "DISCLOSED",
        }
    }
}

/// Coarse participation bucket used when the visibility policy is
/// [`ParticipationVisibility::Coarse`]. The exact accepted count and
/// percentage are not disclosed; only the bucket label is.
///
/// Buckets are inclusive of their lower bound and exclusive of their upper
/// bound, except `OneHundred`, which represents exactly 100%.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CoarseParticipationBucket {
    /// 0–24%.
    ZeroToTwentyFour,
    /// 25–49%.
    TwentyFiveToFortyNine,
    /// 50–74%.
    FiftyToSeventyFour,
    /// 75–99%.
    SeventyFiveToNinetyNine,
    /// 100%.
    OneHundred,
}

impl CoarseParticipationBucket {
    /// Returns a concise, calm display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroToTwentyFour => "0–24%",
            Self::TwentyFiveToFortyNine => "25–49%",
            Self::FiftyToSeventyFour => "50–74%",
            Self::SeventyFiveToNinetyNine => "75–99%",
            Self::OneHundred => "100%",
        }
    }

    /// Maps a participation value in basis points (0..=10000) onto a bucket.
    #[must_use]
    pub const fn from_basis_points(bps: u32) -> Self {
        if bps >= 10_000 {
            Self::OneHundred
        } else if bps >= 7_500 {
            Self::SeventyFiveToNinetyNine
        } else if bps >= 5_000 {
            Self::FiftyToSeventyFour
        } else if bps >= 2_500 {
            Self::TwentyFiveToFortyNine
        } else {
            Self::ZeroToTwentyFour
        }
    }
}

/// Privacy-aware participation summary derived from authoritative backend
/// state.
///
/// Numeric participation fields are `None` while the visibility policy seals
/// them, so a modified frontend cannot retrieve sealed counts by calling the
/// command. `eligible_voters` is always present because it is public registry
/// information already exposed by [`crate::summary::GuiElectionSummaryV1`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiParticipationSummaryV1 {
    /// Lifecycle state code (`DRAFT`..`FINALIZED`).
    pub lifecycle_state: &'static str,
    /// Application-local participation-visibility policy (non-canonical).
    pub participation_visibility: ParticipationVisibility,
    /// Result-disclosure state (mirrors the 5A4 tally gate).
    pub result_visibility: ResultVisibility,
    /// Number of registered eligible voters (always present; public).
    pub eligible_voters: u64,
    /// Number of accepted ballots. `None` while participation is sealed.
    pub accepted_ballots: Option<u64>,
    /// Participation in basis points (0..=10000). `None` while sealed.
    pub participation_basis_points: Option<u32>,
    /// Remaining eligible capacity (`eligible_voters - accepted_ballots`).
    /// `None` while sealed.
    pub remaining_eligible_capacity: Option<u64>,
    /// Coarse bucket label, present only when the policy is `Coarse`.
    pub coarse_bucket: Option<CoarseParticipationBucket>,
    /// True when the electorate is below [`SMALL_ELECTORATE_THRESHOLD`].
    /// Informational; the default policy already seals live participation
    /// while open, so small electorates are inherently protected.
    pub small_electorate: bool,
}

/// Computes participation in basis points (0..=10000) with no divide-by-zero.
///
/// Returns 0 when `eligible_voters == 0`. Saturates at 10000 if the numerator
/// somehow exceeds the denominator (not possible through the acceptance
/// ledger, which enforces one acceptance per registry-scoped nullifier).
#[must_use]
pub fn participation_basis_points(accepted: u64, eligible: u64) -> u32 {
    if eligible == 0 {
        return 0;
    }
    if accepted >= eligible {
        return 10_000;
    }
    // u64 intermediate: accepted * 10000 <= (eligible-1) * 10000 < 2^64 for any
    // realistic eligible size well below 2^60.
    let bps = (accepted.saturating_mul(10_000)) / eligible;
    if bps > 10_000 {
        10_000
    } else {
        u32::try_from(bps).unwrap_or(10_000)
    }
}

/// Resolves the application-local participation-visibility policy from the
/// lifecycle state.
///
/// Conservative default: `SealedUntilClose` while voting is open (DRAFT,
/// FROZEN, OPEN). After close (CLOSED, VERIFIED, FINALIZED) exact participation
/// is permitted (`Live`).
#[must_use]
pub fn participation_visibility_for(state: ElectionLifecycleStateV1) -> ParticipationVisibility {
    match state {
        ElectionLifecycleStateV1::Closed
        | ElectionLifecycleStateV1::Verified
        | ElectionLifecycleStateV1::Finalized => ParticipationVisibility::Live,
        ElectionLifecycleStateV1::Draft
        | ElectionLifecycleStateV1::Frozen
        | ElectionLifecycleStateV1::Open => ParticipationVisibility::SealedUntilClose,
    }
}

/// Resolves the result-disclosure state from the lifecycle state, mirroring
/// the 5A4 tally gate.
#[must_use]
pub fn result_visibility_for(state: ElectionLifecycleStateV1) -> ResultVisibility {
    match state {
        ElectionLifecycleStateV1::Closed
        | ElectionLifecycleStateV1::Verified
        | ElectionLifecycleStateV1::Finalized => ResultVisibility::Disclosed,
        ElectionLifecycleStateV1::Draft
        | ElectionLifecycleStateV1::Frozen
        | ElectionLifecycleStateV1::Open => ResultVisibility::Sealed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_eligible_voters_yields_zero_basis_points() {
        assert_eq!(participation_basis_points(0, 0), 0);
        assert_eq!(participation_basis_points(7, 0), 0);
    }

    #[test]
    fn zero_accepted_yields_zero_basis_points() {
        assert_eq!(participation_basis_points(0, 250), 0);
    }

    #[test]
    fn full_participation_yields_ten_thousand_basis_points() {
        assert_eq!(participation_basis_points(250, 250), 10_000);
    }

    #[test]
    fn rounding_truncates_toward_zero() {
        // 163 / 250 = 0.652 -> 6520 bps
        assert_eq!(participation_basis_points(163, 250), 6_520);
        // 1 / 3 = 0.333... -> 3333 bps
        assert_eq!(participation_basis_points(1, 3), 3_333);
    }

    #[test]
    fn accepted_exceeding_eligible_saturates_at_full() {
        assert_eq!(participation_basis_points(300, 250), 10_000);
    }

    #[test]
    fn coarse_buckets_partition_basis_points() {
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(0),
            CoarseParticipationBucket::ZeroToTwentyFour
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(2_499),
            CoarseParticipationBucket::ZeroToTwentyFour
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(2_500),
            CoarseParticipationBucket::TwentyFiveToFortyNine
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(4_999),
            CoarseParticipationBucket::TwentyFiveToFortyNine
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(5_000),
            CoarseParticipationBucket::FiftyToSeventyFour
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(7_499),
            CoarseParticipationBucket::FiftyToSeventyFour
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(7_500),
            CoarseParticipationBucket::SeventyFiveToNinetyNine
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(9_999),
            CoarseParticipationBucket::SeventyFiveToNinetyNine
        );
        assert_eq!(
            CoarseParticipationBucket::from_basis_points(10_000),
            CoarseParticipationBucket::OneHundred
        );
    }

    #[test]
    fn visibility_defaults_seal_until_close_before_close() {
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Draft),
            ParticipationVisibility::SealedUntilClose
        );
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Frozen),
            ParticipationVisibility::SealedUntilClose
        );
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Open),
            ParticipationVisibility::SealedUntilClose
        );
    }

    #[test]
    fn visibility_is_live_after_close() {
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Closed),
            ParticipationVisibility::Live
        );
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Verified),
            ParticipationVisibility::Live
        );
        assert_eq!(
            participation_visibility_for(ElectionLifecycleStateV1::Finalized),
            ParticipationVisibility::Live
        );
    }

    #[test]
    fn result_visibility_sealed_before_close() {
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Draft),
            ResultVisibility::Sealed
        );
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Frozen),
            ResultVisibility::Sealed
        );
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Open),
            ResultVisibility::Sealed
        );
    }

    #[test]
    fn result_visibility_disclosed_after_close() {
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Closed),
            ResultVisibility::Disclosed
        );
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Verified),
            ResultVisibility::Disclosed
        );
        assert_eq!(
            result_visibility_for(ElectionLifecycleStateV1::Finalized),
            ResultVisibility::Disclosed
        );
    }

    #[test]
    fn stable_identifiers_are_machine_readable() {
        assert_eq!(ParticipationVisibility::Live.as_str(), "LIVE");
        assert_eq!(ParticipationVisibility::Coarse.as_str(), "COARSE");
        assert_eq!(
            ParticipationVisibility::SealedUntilClose.as_str(),
            "SEALED_UNTIL_CLOSE"
        );
        assert_eq!(ResultVisibility::Sealed.as_str(), "SEALED");
        assert_eq!(ResultVisibility::Disclosed.as_str(), "DISCLOSED");
    }

    /// The JSON projection consumed by the frontend must match the stable
    /// `as_str` identifiers, not the serde-default variant names. A regression
    /// here silently breaks every frontend visibility comparison (the
    /// `Policy: .` and `Results: Sealed` presentation bugs).
    #[test]
    fn visibility_enums_serialize_as_stable_identifiers() {
        // `.ok()` (not `.unwrap()`) keeps this within the workspace clippy
        // policy that denies `unwrap_used`/`expect_used`; serialization of a
        // fieldless enum cannot fail, so `Some(_)` is always taken.
        for variant in [
            ParticipationVisibility::Live,
            ParticipationVisibility::Coarse,
            ParticipationVisibility::SealedUntilClose,
        ] {
            assert_eq!(
                serde_json::to_value(variant).ok(),
                Some(serde_json::Value::String(variant.as_str().to_owned())),
            );
        }
        for variant in [ResultVisibility::Sealed, ResultVisibility::Disclosed] {
            assert_eq!(
                serde_json::to_value(variant).ok(),
                Some(serde_json::Value::String(variant.as_str().to_owned())),
            );
        }
    }
}
