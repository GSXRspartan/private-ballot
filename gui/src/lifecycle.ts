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

/** A genuine final archive must be written only after the election reaches
 * FINALIZED. The Rust finalized writer remains authoritative; this mirrors
 * that gate so the UI ordering does not imply CLOSED/VERIFIED are final. */
export function canWriteFinalArchive(state: string | null | undefined): boolean {
  return state === "FINALIZED";
}

export interface AnchorDeploymentLockPrerequisites {
  canAct: boolean;
  busy: boolean;
  templateAddress: string | null | undefined;
  selectedWasmPath: string | null | undefined;
  wasmInspectionPresent: boolean;
}

export function anchorDeploymentLockBlockers(
  input: AnchorDeploymentLockPrerequisites,
): string[] {
  const blockers: string[] = [];
  if (!input.canAct) blockers.push("Load an organizer election in the desktop app");
  if (input.busy) blockers.push("Another anchor operation is running");
  if (!input.templateAddress?.trim()) blockers.push("Template address is missing");
  if (!input.selectedWasmPath?.trim()) blockers.push("Published template WASM has not been selected");
  if (input.selectedWasmPath?.trim() && !input.wasmInspectionPresent) {
    blockers.push("Selected WASM has not been inspected");
  }
  return blockers;
}

export interface AnchorPreparePrerequisites {
  canAct: boolean;
  busy: boolean;
  archiveResultPresent: boolean;
  trustedDeploymentPresent: boolean;
  signerMode: AnchorSignerMode;
  managedAnchorWalletSupported: boolean;
  walletdEndpoint: string | null | undefined;
  indexerEndpoint: string | null | undefined;
  accountReference: string | null | undefined;
  feeComponent: string | null | undefined;
  declaredSealPublicKey: string | null | undefined;
  dedicatedOrganizerWalletAttested: boolean;
  acceptedBallotFloor: number;
  maxEpochDelta: number;
  maxFee: number;
}

export type AnchorSignerMode = "managed-anchor-wallet" | "external-walletd";

export function anchorPrepareBlockers(
  input: AnchorPreparePrerequisites,
): string[] {
  const blockers: string[] = [];
  if (!input.canAct) blockers.push("Load an organizer election in the desktop app");
  if (!input.archiveResultPresent) blockers.push("Final archive has not been written and verified");
  if (!input.trustedDeploymentPresent) blockers.push("Ootle deployment is not locked");

  if (input.signerMode === "managed-anchor-wallet") {
    if (!input.managedAnchorWalletSupported) {
      blockers.push("Managed anchor wallet is not available in this build; use Advanced external walletd");
    }
  } else {
    if (!input.walletdEndpoint?.trim()) blockers.push("Walletd endpoint is missing");
    if (!input.indexerEndpoint?.trim()) blockers.push("Indexer endpoint is missing");
    if (!input.accountReference?.trim()) blockers.push("Fee account is missing");
    if (!input.feeComponent?.trim()) blockers.push("Fee component address is missing");
    if (!input.declaredSealPublicKey?.trim()) {
      blockers.push("Declared seal public key is missing");
    }
    if (!input.dedicatedOrganizerWalletAttested) {
      blockers.push("Dedicated organizer wallet acknowledgement required");
    }
  }

  if (!Number.isFinite(input.acceptedBallotFloor) || input.acceptedBallotFloor < 2) {
    blockers.push("Accepted ballot floor must be at least 2");
  }
  if (!Number.isFinite(input.maxEpochDelta) || input.maxEpochDelta < 1) {
    blockers.push("Max epoch delta must be at least 1");
  }
  if (!Number.isFinite(input.maxFee) || input.maxFee < 1) {
    blockers.push("Max fee must be at least 1");
  }
  if (input.busy) blockers.push("Another anchor operation is running");
  return blockers;
}

export interface AnchorPublishPrerequisites {
  canAct: boolean;
  busy: boolean;
  archiveResultPresent: boolean;
  anchorConfigPresent: boolean;
  walletdBearerTokenUnavailable?: boolean;
}

export function anchorPublishBlockers(
  input: AnchorPublishPrerequisites,
): string[] {
  const blockers: string[] = [];
  if (!input.canAct) blockers.push("Load an organizer election in the desktop app");
  if (!input.archiveResultPresent) blockers.push("Final archive has not been written and verified");
  if (!input.anchorConfigPresent) blockers.push("Anchor configuration has not been prepared");
  if (input.walletdBearerTokenUnavailable) {
    blockers.push("Walletd bearer token requested but unavailable");
  }
  if (input.busy) blockers.push("Another anchor operation is running");
  return blockers;
}

/** Returns true while results are sealed (DRAFT, FROZEN, OPEN, or unknown). */
export function resultsAreSealed(state: string | null | undefined): boolean {
  return !canShowTally(state);
}

/**
 * Plain-language voter-facing label for a lifecycle state. The raw machine
 * strings (DRAFT/FROZEN/OPEN/…) stay in lifecycle pills and technical
 * details; this is the human sentence for primary voter screens.
 */
export function lifecyclePlainText(state: string | null | undefined): string {
  switch (state) {
    case "DRAFT":
      return "Being prepared — not yet locked";
    case "FROZEN":
      return "Locked — voting has not opened yet";
    case "OPEN":
      return "Voting is open";
    case "CLOSED":
      return "Voting is closed";
    case "VERIFIED":
      return "Results verified";
    case "FINALIZED":
      return "Election finalized";
    default:
      return state ?? "Unknown";
  }
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

/**
 * Truthful label for sealed/hidden participation counts, derived from the
 * actual lifecycle. While voting is OPEN the count is intentionally hidden
 * ("Hidden while voting is open"); before voting opens the truthful statement
 * is that voting has not opened yet — never the OPEN wording, and never a
 * fabricated authoritative zero (the sealed DTO does not disclose one).
 */
export function sealedParticipationText(
  lifecycle: string | null | undefined,
): string {
  if (lifecycle === "OPEN") return "Hidden while voting is open";
  if (lifecycle === "FROZEN" || lifecycle === "DRAFT") {
    return "Voting has not opened yet";
  }
  return "Hidden";
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

/** Human-facing description of a tally's leading outcome (never an invented
 *  winner). `leading` is an externally-tagged serde enum: its unit variant is
 *  the BARE STRING "NoApprovals", while the data-bearing variants are
 *  single-key objects. The string form MUST be handled before any `in` check —
 *  `"x" in aString` throws a TypeError — which was the zero-ballot Compute-tally
 *  crash. This single shared helper keeps both the field text and the result
 *  bars in agreement and pins the behavior in one testable place. */
export function describeLeadingOutcome(tally: GuiTallySummaryV1): string {
  const leading = tally.leading;
  if (leading === "NoApprovals") return "No approvals recorded.";
  if ("SingleLeader" in leading) {
    const leader = leading.SingleLeader;
    return `Leading: ${leader.display_name || leader.candidate_id_hex} (${leader.approvals} approvals).`;
  }
  const tie = leading.Tie;
  return `Unresolved tie between ${tie.candidate_ids_hex.length} options (${tie.approvals} approvals each).`;
}

// ---------------------------------------------------------------------------
// Organizer lifecycle progression + next-step guidance (presentation only).
//
// These helpers mirror the REAL append-only lifecycle
// (DRAFT → FROZEN → OPEN → CLOSED → VERIFIED → FINALIZED). They never invent
// states and never mark a stage complete unless the backend lifecycle says it
// has actually been reached; irreversible states are presented as one-way.
// ---------------------------------------------------------------------------

export interface OrganizerLifecycleStep {
  key: string;
  label: string;
  state: "done" | "current" | "todo";
}

const ORGANIZER_STEP_ORDER = [
  "DRAFT",
  "FROZEN",
  "OPEN",
  "CLOSED",
  "VERIFIED",
  "FINALIZED",
] as const;

const ORGANIZER_STEP_LABELS = [
  "Created",
  "Frozen",
  "Open",
  "Closed",
  "Verified",
  "Finalized",
] as const;

/**
 * Maps the actual lifecycle state onto the organizer progression:
 *   Created → Frozen → Open → Closed → Verified → Finalized
 * Past stages are done, the current stage is emphasized, future stages stay
 * subdued. FINALIZED is terminal and shows as genuinely complete; an
 * unrecognized state falls back to the first stage without claiming progress.
 */
export function organizerLifecycleSteps(
  state: string | null | undefined,
): OrganizerLifecycleStep[] {
  const index = state
    ? (ORGANIZER_STEP_ORDER as readonly string[]).indexOf(state)
    : -1;
  const currentIndex = index >= 0 ? index : 0;
  const terminalComplete = state === "FINALIZED";
  return ORGANIZER_STEP_LABELS.map((label, i) => ({
    key: ORGANIZER_STEP_ORDER[i],
    label,
    state:
      i < currentIndex || (terminalComplete && i === currentIndex)
        ? "done"
        : i === currentIndex
          ? "current"
          : "todo",
  }));
}

export interface OrganizerNextStep {
  title: string;
  body: string;
}

/**
 * Plain-language "what should I do next" for the organizer, derived ONLY from
 * the actual lifecycle state plus whether a tally/archive has been produced
 * this session. It never fabricates lifecycle states and never implies an
 * irreversible transition has already happened.
 */
export function nextOrganizerStep(input: {
  lifecycle: string | null | undefined;
  tallyComputed: boolean;
  /**
   * True when a verified final archive exists for the current election
   * (transport-bound, hash-matched, and independently verified by the
   * archive verifier). Callers pass `archiveReadyForAnchor` here.
   */
  archiveVerified: boolean;
  /**
   * True when a Tari Ootle anchor has been submitted for this archive but its
   * receipt has not yet reached the terminal verified state. Pass false if
   * there is no submitted anchor at all.
   */
  anchorSubmittedButUnverified?: boolean;
  /**
   * True when a Tari Ootle anchor receipt for this archive has been
   * independently verified (terminal RECEIPT_VERIFIED state).
   */
  anchorVerified?: boolean;
}): OrganizerNextStep {
  switch (input.lifecycle) {
    case "FROZEN":
      return {
        title: "Get ready to open voting",
        body: "Start private intake, distribute the voter materials, then open voting.",
      };
    case "OPEN":
      return {
        title: "Voting is open",
        body: "Private intake can receive ballots while voting is open. Close voting when the voting period ends — closing is permanent.",
      };
    case "CLOSED":
      return input.tallyComputed
        ? {
            title: "Review the result",
            body: "Review the computed tally below, then mark verification complete.",
          }
        : {
            title: "Voting is closed",
            body: "No additional ballots can be accepted. Compute the tally when ready.",
          };
    case "VERIFIED":
      return {
        title: "Verification recorded",
        body: "Finalize the election when the verification is complete. Finalizing is permanent.",
      };
    case "FINALIZED":
      // The verified final archive is authoritative; a Tari Ootle anchor is
      // optional public integrity evidence. State priority (from most complete
      // to least) determines what to suggest next.
      if (input.archiveVerified && input.anchorVerified === true) {
        return {
          title: "Election complete",
          body: "The verified final archive is authoritative. The optional Tari Ootle anchor has been published and its receipt verified.",
        };
      }
      if (input.archiveVerified && input.anchorSubmittedButUnverified === true) {
        return {
          title: "Verify existing anchor",
          body: "An anchor transaction already exists for this archive. Verify its receipt on the Anchor screen.",
        };
      }
      if (input.archiveVerified) {
        return {
          title: "Election record verified",
          body: "The independently verified final archive is complete and authoritative. Optionally publish a public integrity anchor to Tari Ootle — anchoring is optional and non-binding.",
        };
      }
      return {
        title: "Verify final archive",
        body: "Open Archive and independently verify the final record. The final archive is the authoritative election record.",
      };
    case "DRAFT":
      return {
        title: "Election draft",
        body: "Finish setting up the election and freeze it on the Create Election screen.",
      };
    default:
      return {
        title: "No election loaded",
        body: "Load an election to see what to do next.",
      };
  }
}

// ---------------------------------------------------------------------------
// Guided organizer workspace (progressive disclosure, presentation only).
//
// The organizer screen is lifecycle-driven: the cards relevant to the CURRENT
// lifecycle phase stay prominent, completed steps collapse into compact
// summaries, and future phases do not occupy full-size cards. Every gate on
// every control is unchanged — this matrix only decides which EXISTING cards
// render prominently in guided mode. "Show all election controls" restores the
// complete surface for technical review without touching any gate.
// ---------------------------------------------------------------------------

/** Identifiers for the existing Manage Election control cards. */
export type OrganizerControlKey =
  | "open"
  | "close"
  | "intake"
  | "materials"
  | "office"
  | "participation"
  | "tally"
  | "verify"
  | "finalArchive"
  | "anchor";

/**
 * The control cards that are PROMINENT for each lifecycle phase in guided
 * mode. Cards not listed remain available through "Show all election
 * controls" (presentation only — their gates never change). Returns null for
 * null/unknown states so the full control surface shows as a safe fallback.
 */
export function organizerGuidedControls(
  lifecycle: string | null | undefined,
): readonly OrganizerControlKey[] | null {
  switch (lifecycle) {
    case "FROZEN":
      // Prepare voting: private intake, voter materials, then open voting.
      return ["intake", "materials", "open"];
    case "OPEN":
      // Voting is open: intake health, ballot intake, materials, the
      // (hidden) participation status, and the lifecycle-ending close action.
      return ["intake", "office", "materials", "participation", "close"];
    case "CLOSED":
      // Verify the result: disclosed participation, tally, verify.
      return ["participation", "tally", "verify"];
    case "VERIFIED":
      // Finish the election: verified result summary + finalize.
      return ["tally", "finalArchive"];
    case "FINALIZED":
      // Publish and verify the record: result, final archive, optional anchor.
      return ["tally", "finalArchive", "anchor"];
    default:
      return null;
  }
}

/**
 * Plain-language primary heading for the current lifecycle phase in guided
 * organizer mode. Returns null when there is no guided heading (no election
 * or an unrecognized state), so the screen falls back to its full layout.
 */
export function organizerPhaseHeading(
  lifecycle: string | null | undefined,
): string | null {
  switch (lifecycle) {
    case "FROZEN":
      return "Prepare voting";
    case "OPEN":
      return "Voting is open";
    case "CLOSED":
      return "Verify the result";
    case "VERIFIED":
      return "Finish the election";
    case "FINALIZED":
      return "Publish and verify the record";
    default:
      return null;
  }
}
