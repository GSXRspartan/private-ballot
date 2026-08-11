/**
 * Pure lifecycle helpers shared by the screens.
 *
 * These are framework-free pure functions so the gating logic can be unit-tested
 * under Node's built-in test runner without a React harness. The authoritative
 * sealed-results gate lives in gui-core (`GuiElectionSessionV1::tally`); this
 * module only mirrors the backend vocabulary so the Manage Election button state
 * stays consistent with it.
 */

import type {
  CoarseParticipationBucket,
  GuiParticipationSummaryV1,
  GuiTallySummaryV1,
  ParticipationVisibility,
  ResultVisibility,
} from "./api/types";

/** Backend lifecycle state identifiers, verbatim from `ElectionLifecycleStateV1`. */
export const LIFECYCLE_STATES = [
  "DRAFT",
  "FROZEN",
  "OPEN",
  "CLOSED",
  "VERIFIED",
  "FINALIZED",
] as const;

export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

/** Lifecycle states in which tally results are available after voting close. */
export const TALLY_AVAILABLE_LIFECYCLE_STATES: ReadonlyArray<LifecycleState> = [
  "CLOSED",
  "VERIFIED",
  "FINALIZED",
];

/** Returns true when tally results may be disclosed for the given lifecycle. */
export function canShowTally(state: string | null | undefined): boolean {
  if (state === null || state === undefined) return false;
  return (TALLY_AVAILABLE_LIFECYCLE_STATES as ReadonlyArray<string>).includes(state);
}

/** A final archive must describe a completed voting lifecycle. The Rust
 * archive writer remains authoritative; this only prevents misleading UI
 * wording and actions while voting is still open. */
export function canWriteFinalArchive(state: string | null | undefined): boolean {
  return canShowTally(state);
}

/** Returns true while results are sealed (DRAFT, FROZEN, OPEN, or unknown). */
export function resultsAreSealed(state: string | null | undefined): boolean {
  return !canShowTally(state);
}

// ---------------------------------------------------------------------------
// Participation formatting (Slice 5A5).
//
// The backend exposes participation in basis points (0..=10000) to avoid
// floating-point weirdness at the boundary. These pure helpers format that
// value for display and map the backend visibility enums to presentation
// text. They never compute participation from raw private data; the backend
// is authoritative.
// ---------------------------------------------------------------------------

/** Formats a basis-points value (0..=10000) as a percentage string with one
 *  decimal place (truncated, matching the integer backend), e.g. 6520 ->
 *  "65.2%". Whole percentages omit the decimal: 5000 -> "50%". Returns "0%"
 *  for 0/null/undefined. No floating-point arithmetic is used at the boundary;
 *  the backend exposes integer basis points. */
export function formatPercent(bps: number | null | undefined): string {
  if (bps === null || bps === undefined) return "0%";
  const clamped = Math.max(0, Math.min(10000, Math.trunc(bps)));
  const tenths = Math.floor(clamped / 10); // 0..1000
  const whole = Math.floor(tenths / 10); // 0..100
  const frac = tenths % 10; // 0..9
  if (frac === 0) return `${whole}%`;
  return `${whole}.${frac}%`;
}

/** Human-facing label for a coarse participation bucket. */
export function coarseBucketLabel(
  bucket: CoarseParticipationBucket | null | undefined,
): string {
  switch (bucket) {
    case "ZeroToTwentyFour":
      return "0–24%";
    case "TwentyFiveToFortyNine":
      return "25–49%";
    case "FiftyToSeventyFour":
      return "50–74%";
    case "SeventyFiveToNinetyNine":
      return "75–99%";
    case "OneHundred":
      return "100%";
    default:
      return "—";
  }
}

/** Human-facing label for the participation-visibility policy. */
export function participationVisibilityLabel(
  visibility: ParticipationVisibility,
): string {
  switch (visibility) {
    case "LIVE":
      return "Live";
    case "COARSE":
      return "Coarse";
    case "SEALED_UNTIL_CLOSE":
      return "Sealed until close";
  }
}

/** Human-facing label for the result-disclosure state. */
export function resultVisibilityLabel(visibility: ResultVisibility): string {
  return visibility === "DISCLOSED" ? "Disclosed" : "Sealed";
}

/** Returns true when participation numerics may be displayed (i.e. the
 *  backend returned them). This mirrors the backend DTO: when sealed, the
 *  numeric fields are null. The frontend must not invent values. */
export function participationIsDisclosed(
  summary: GuiParticipationSummaryV1 | null | undefined,
): boolean {
  if (!summary) return false;
  return summary.accepted_ballots !== null;
}

/** Builds a screen-reader-friendly textual equivalent for the participation
 *  card so a screen reader can learn the value without interpreting SVG
 *  geometry. */
export function participationAccessibleText(
  summary: GuiParticipationSummaryV1 | null | undefined,
): string {
  if (!summary) return "No participation data available.";
  if (summary.participation_visibility === "SEALED_UNTIL_CLOSE") {
    return "Participation is sealed until voting closes.";
  }
  if (summary.participation_visibility === "COARSE") {
    return `Participation band: ${coarseBucketLabel(summary.coarse_bucket)}.`;
  }
  const accepted = summary.accepted_ballots ?? 0;
  const pct = formatPercent(summary.participation_basis_points);
  return `Participation ${pct}, ${accepted} of ${summary.eligible_voters} eligible voters.`;
}

// ---------------------------------------------------------------------------
// Final-result percentage semantics (Slice 5A5, section G).
//
// For approval/multi-approval ballots, each option's approval percentage is
// expressed as a share of accepted ballots, NOT a share of "the vote" (which
// would imply a single-choice partition). Multiple options may each exceed
// 100%/sum because voters may approve multiple options. The denominator is
// the accepted-ballot count from the tally.
// ---------------------------------------------------------------------------

/** Computes one option's approval percentage in basis points of accepted
 *  ballots. Returns 0 when there are no accepted ballots. */
export function approvalBps(approvals: number, acceptedBallots: number): number {
  if (acceptedBallots <= 0) return 0;
  if (approvals >= acceptedBallots) return 10000;
  const bps = Math.trunc((approvals * 10000) / acceptedBallots);
  return Math.max(0, Math.min(10000, bps));
}

/** Builds the accurate label for one option's approval bar.
 *  "Approved by 61.2% of accepted ballots" rather than "61.2% of the vote",
 *  because multi-approval ballots do not partition a single vote. */
export function approvalLabel(
  _displayNoun: string,
  approvals: number,
  acceptedBallots: number,
): string {
  const pct = formatPercent(approvalBps(approvals, acceptedBallots));
  return `Approved by ${pct} of accepted ballots`;
}

/** Returns true when the tally represents a multi-approval ballot where
 *  option percentages may not sum to 100%. The current ballot kind is always
 *  `NON_BINDING_APPROVAL_PILOT`, which is an approval ballot; this helper
 *  centralizes the rule so pie charts are never used for it. */
export function isMultiApprovalBallot(_tally: GuiTallySummaryV1): boolean {
  // Every supported ballot kind in v1 is an approval ballot. A pie chart
  // would be misleading because approvals are not a partition of a single
  // vote. This function exists so a future single-choice ballot kind can
  // override it.
  return true;
}
