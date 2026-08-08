/**
 * Pure lifecycle helpers shared by the screens.
 *
 * These are framework-free pure functions so the gating logic can be unit-tested
 * under Node's built-in test runner without a React harness. The authoritative
 * sealed-results gate lives in gui-core (`GuiElectionSessionV1::tally`); this
 * module only mirrors the backend vocabulary so the Manage Election button state
 * stays consistent with it.
 */

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

/** Returns true while results are sealed (DRAFT, FROZEN, OPEN, or unknown). */
export function resultsAreSealed(state: string | null | undefined): boolean {
  return !canShowTally(state);
}
