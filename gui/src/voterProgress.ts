/**
 * Voter progression derivation for the Vote screen (presentation only).
 *
 * Maps the EXISTING voter workflow/session state onto the five conceptual
 * stages of the guided voting journey:
 *
 *   Election → Identity → Vote → Privacy → Submit
 *
 * No backend state is invented here: every input is already reported by the
 * existing workflow/credential/selection DTOs or by existing screen state
 * (review/selection stage entry). A stage is "done" only when the real
 * underlying step has completed; the first incomplete stage is "current" and
 * everything after it stays subdued ("todo"). The durable cast state
 * dominates the final stage so a completed vote still shows Submit as done
 * after navigation or an application restart.
 */

import type { GuiVoterCastLockStateV1 } from "./api/types";

export type ProgressStepState = "done" | "current" | "todo";

export interface ProgressStep {
  key: string;
  label: string;
  state: ProgressStepState;
}

/** Inputs mirroring the existing Vote screen state; nothing new is fetched. */
export interface VoterProgressInput {
  /** An election is loaded in this session. */
  electionLoaded: boolean;
  /** The voter confirmed the election review and continued (existing gate). */
  reviewPassed: boolean;
  /** A loaded credential is eligible and may continue (backend status). */
  identityReady: boolean;
  /** The voter continued into the ballot-response stage. */
  voteEntered: boolean;
  /** The backend reports a valid, loaded selection. */
  choiceMade: boolean;
  /** The prepared anonymous ballot is in the transient "Ready" state. */
  ballotReady: boolean;
  /** Durable, authoritative cast-lock state from the workflow DTO. */
  castState: GuiVoterCastLockStateV1;
}

/** The five voter-facing stage labels, in order. */
export const VOTER_STAGE_LABELS = [
  "Election",
  "Identity",
  "Vote",
  "Privacy",
  "Submit",
] as const;

/**
 * Derives the per-stage presentation state. Monotonic: a completed stage
 * stays behind the voter, the first incomplete stage is the current one, and
 * later stages remain subdued. Changing the choice after preparation
 * legitimately moves Privacy back to current (the proof must be recreated);
 * a durably locked ballot (CAST_PENDING/CAST) keeps Vote/Privacy done.
 */
export function voterStages(input: VoterProgressInput): ProgressStep[] {
  const castLocked = input.castState === "CAST_PENDING" || input.castState === "CAST";
  const done: readonly boolean[] = [
    input.electionLoaded && input.reviewPassed,
    input.reviewPassed && input.identityReady && input.voteEntered,
    input.voteEntered && (input.choiceMade || input.ballotReady || castLocked),
    input.ballotReady || castLocked,
    input.castState === "CAST",
  ];
  let currentAssigned = false;
  return VOTER_STAGE_LABELS.map((label, index) => {
    if (done[index]) return { key: label, label, state: "done" };
    if (!currentAssigned) {
      currentAssigned = true;
      return { key: label, label, state: "current" };
    }
    return { key: label, label, state: "todo" };
  });
}
