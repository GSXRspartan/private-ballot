/**
 * Pure helpers describing the voter-facing terminal / read-only presentation
 * for a loaded election. These are framework-free so the gating logic can be
 * unit-tested under Node's built-in test runner without a React harness.
 *
 * The authoritative lifecycle gate lives in the Rust backend; these helpers
 * merely present the same truth to the voter (no vote actions after
 * CLOSED/FINALIZED) and never invent state.
 */

/** Voting-closed banner descriptor, or `null` when the election is not in a
 *  terminal read-only state for the voter (DRAFT/FROZEN/OPEN). VERIFIED is
 *  treated the same as CLOSED for voters — voting has closed. */
export interface VotingClosedBanner {
  /** Short heading, e.g. "Voting closed". */
  title: string;
  /** One or two sentences explaining what the voter can still do. */
  body: string;
  /** Whether verification of the final record is the appropriate next step. */
  offersFinalRecord: boolean;
}

/**
 * Returns the read-only banner descriptor for a voter-loaded election, or
 * `null` when the election is not closed/finalized. CLOSED and VERIFIED both
 * mean voting can no longer happen; FINALIZED additionally means the final
 * record is available for verification.
 */
export function votingClosedBanner(
  lifecycleState: string | null | undefined,
): VotingClosedBanner | null {
  if (lifecycleState === "FINALIZED") {
    return {
      title: "Voting closed",
      body:
        "This election is finalized. You can review the election and verify the final record, but no ballot can be created, changed, or submitted.",
      offersFinalRecord: true,
    };
  }
  if (lifecycleState === "CLOSED" || lifecycleState === "VERIFIED") {
    return {
      title: "Voting closed",
      body:
        "Responses can no longer be chosen or changed. Final verification may still be in progress.",
      offersFinalRecord: false,
    };
  }
  return null;
}

/** Convenience: true when the voter is in a terminal read-only presentation
 *  (CLOSED/VERIFIED/FINALIZED). */
export function isVoterReadOnlyLifecycle(
  lifecycleState: string | null | undefined,
): boolean {
  return votingClosedBanner(lifecycleState) !== null;
}

/**
 * Whether the "Create credential" action should be primary or de-emphasized
 * for the voter on this election. After an election is frozen (or later), a
 * newly created credential cannot make the voter eligible for this frozen
 * registry, so Create moves under a "for a future election" disclosure.
 * Before an election is loaded (or in a DRAFT/unknown state) creation is
 * primary again.
 */
export function createCredentialIsFutureElectionOnly(
  lifecycleState: string | null | undefined,
): boolean {
  return (
    lifecycleState === "FROZEN" ||
    lifecycleState === "OPEN" ||
    lifecycleState === "CLOSED" ||
    lifecycleState === "VERIFIED" ||
    lifecycleState === "FINALIZED"
  );
}
