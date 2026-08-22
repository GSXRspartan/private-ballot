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

/**
 * Durable/session backend signals that prove how far the voter has actually
 * progressed, independent of the transient in-component stage gate booleans
 * (`credentialStage`, `selectionStage`) that reset to `false` on every mount.
 *
 * Used to RECONSTRUCT the guided stage after simple screen navigation or an
 * application restart, so the workflow never snaps back to the first stage
 * while real progress still exists. Every field mirrors an existing DTO value;
 * nothing new is fetched, no secret crosses the boundary, and no second
 * frontend persistence system is introduced.
 */
export interface VoterStageReconstructionInput {
  /** A voter governance credential is loaded (durable via the credential store,
   *  re-installed on restart). */
  credentialLoaded: boolean;
  /** The loaded credential is eligible and may continue (backend status). */
  identityReady: boolean;
  /** The backend reports a loaded ballot selection. Session state: intentionally
   *  NOT durable across a restart (no ballot/proof/nullifier exists yet). */
  selectionLoaded: boolean;
  /** A prepared anonymous ballot is in the transient Ready state (session). */
  ballotReady: boolean;
  /** The ballot is durably locked (CAST_PENDING or CAST). */
  castLocked: boolean;
}

/**
 * Whether the voter has observably passed the Election-review gate. True when
 * the in-component gate is set OR any later durable/session progress exists — a
 * loaded credential, an eligible identity, a selection, a prepared ballot, or a
 * locked ballot each prove the review was already passed. Monotonic: it only
 * ever recognises real progress, never fabricates it, so a crash can never
 * advance the voter past a stage they did not reach.
 */
export function reviewStageReached(
  uiEntered: boolean,
  signals: VoterStageReconstructionInput,
): boolean {
  return (
    uiEntered ||
    signals.credentialLoaded ||
    signals.identityReady ||
    signals.selectionLoaded ||
    signals.ballotReady ||
    signals.castLocked
  );
}

/**
 * Whether the voter has observably entered the Vote (ballot-response) stage.
 * True when the in-component gate is set OR a backend selection, a prepared
 * ballot, or a locked ballot exists. A pre-submission selection is session
 * state and is intentionally not durable across a restart; when it is absent
 * the voter returns to the Vote stage (with identity already recognised), never
 * to the beginning, and re-selects — no ballot, proof, or nullifier was ever
 * created, so nothing is lost beyond the unsubmitted choice.
 */
export function voteStageReached(
  uiEntered: boolean,
  signals: VoterStageReconstructionInput,
): boolean {
  return uiEntered || signals.selectionLoaded || signals.ballotReady || signals.castLocked;
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
