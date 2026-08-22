import type {
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStateV1,
} from "./api/types";

export type VoterReceiptState =
  | "OFFLINE_EXPORT"
  | "RECEIVED"
  | "ACCEPTED"
  | "REJECTED";

export type OrganizerAggregateState = "INCLUDED" | "ANCHORED";

export function selectionSummaryText(
  selection: GuiVoterSelectionStatusV1 | null,
): string {
  if (!selection?.selection_loaded) return "No selection";
  if (selection.abstaining) return "Abstaining";
  return `${selection.selected_count} selected`;
}

export function workflowTone(
  state: GuiVoterWorkflowStateV1 | null | undefined,
): "ok" | "warn" | "neutral" {
  if (state === "SelectionReady" || state === "PreparedBallotReady" || state === "BallotCast")
    return "ok";
  if (
    state === "CredentialNotEligible" ||
    state === "CastPending" ||
    state === "ElectionNotOpen"
  )
    return "warn";
  return "neutral";
}

/**
 * Plain-language voter status for an internal workflow state. The raw
 * backend enum identifiers (SelectionReady, SelectionIncomplete, …) are
 * protocol state and are never shown to ordinary voters; they remain
 * available in the backend DTO for auditors. These sentences describe the
 * voter's next step and never imply that a selection was submitted.
 *
 * `ElectionNotOpen` deliberately does NOT say "choose a response": while the
 * authoritative lifecycle is not OPEN nothing else in the workflow can
 * proceed. Use {@link electionNotOpenText} so the message states the actual
 * lifecycle truth (FROZEN = not opened yet, CLOSED+ = closed).
 */
export function workflowStateText(
  state: GuiVoterWorkflowStateV1 | null | undefined,
): string {
  switch (state) {
    case "SelectionReady":
      return "Your response is ready.";
    case "PreparingProof":
      return "Preparing your ballot…";
    case "PreparedBallotReady":
      return "Your ballot is prepared.";
    case "BallotCast":
      return "Your ballot was exported and cast on this device for this election.";
    case "CastPending":
      return "Finishing your ballot submission. Your choice is locked for this election.";
    case "ReviewRequired":
      return "Review the election to continue.";
    case "CredentialMissing":
      return "An eligible voter credential is required to continue.";
    case "CredentialNotEligible":
      return "This credential is not eligible for this election.";
    case "ElectionNotOpen":
      return "Voting is not open on this election.";
    case "SelectionIncomplete":
      return "Choose a response to continue.";
    default:
      return "Choose a response to continue.";
  }
}

/**
 * The exact lifecycle truth for a non-open election. `lifecycleState` comes
 * from the authoritative backend selection/workflow DTO (never from frontend
 * state), so FROZEN and CLOSED are reported distinctly and honestly.
 */
export function electionNotOpenText(lifecycleState: string | null | undefined): string {
  if (lifecycleState === "FROZEN") {
    return "Voting has not opened yet. This app will show responses as choosable only once the ballot office confirms voting is open.";
  }
  if (
    lifecycleState === "CLOSED" ||
    lifecycleState === "VERIFIED" ||
    lifecycleState === "FINALIZED"
  ) {
    return "Voting has closed. Responses can no longer be chosen or changed.";
  }
  return "Voting is not open on this election.";
}

export function selectionAtApprovalMax(
  selection: GuiVoterSelectionStatusV1 | null,
): boolean {
  return !!selection && !selection.abstaining && selection.selected_count >= selection.approval_max;
}

/**
 * Plain-language explanation of a private-submission receipt state. The
 * states are deliberately NOT collapsed into one generic "Success": each
 * says exactly what the implementation has established, no more.
 */
export function receiptStateText(state: string): string {
  switch (state) {
    case "OFFLINE_EXPORT":
      return "Offline export: no online submission was made.";
    case "RECEIVED":
      return "Received: the submission reached the transport system.";
    case "ACCEPTED":
      return "Accepted: the ballot passed election validation and was accepted.";
    case "REJECTED":
      return "Rejected: the ballot was not accepted by the election.";
    default:
      return "Unknown submission status.";
  }
}

/** Whether a receipt state means the ballot was definitively accepted. */
export function receiptStateIsAccepted(state: string): boolean {
  return state === "ACCEPTED";
}

/** Plain-language organizer/archive aggregate state. This is deliberately
 * separate from voter transport receipt states. */
export function aggregateStateText(state: OrganizerAggregateState): string {
  switch (state) {
    case "INCLUDED":
      return "Included: the accepted ballot is included in the finalized or published aggregate record, but valid terminal Ootle evidence has not been independently established.";
    case "ANCHORED":
      return "Anchored: the accepted ballot is included in a verified FINALIZED archive whose aggregate archive commitment has valid independently verified Ootle anchor evidence.";
  }
}

export function noVoterWorkflowSecretFieldNames(fieldNames: string[]): boolean {
  const forbidden = [
    "secret",
    "scalar",
    "seed",
    "mnemonic",
    "private",
    "credential_bytes",
    "wallet_seed",
    "registry_index",
    "member_index",
    "nullifier",
    "proof",
    "passphrase",
    "password",
    "duplicate_of_sequence",
    "intake_sequence",
  ];
  return fieldNames.every((field) => {
    const normalized = field.toLowerCase();
    return forbidden.every((marker) => !normalized.includes(marker));
  });
}
