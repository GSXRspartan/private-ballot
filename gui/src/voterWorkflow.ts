import type {
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStateV1,
} from "./api/types";

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
  if (state === "SelectionReady") return "ok";
  if (state === "CredentialNotEligible") return "warn";
  return "neutral";
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
    case "RECEIVED":
      return "Received: the submission reached the transport system.";
    case "ACCEPTED":
      return "Accepted: the ballot passed election validation and was accepted.";
    case "REJECTED":
      return "Rejected: the ballot was not accepted by the election.";
    case "INCLUDED":
      return "Included: the ballot was included in the finalized election record.";
    case "ANCHORED":
      return "Anchored: the finalized commitment has the required anchor evidence.";
    case "OFFLINE_EXPORT":
      return "Offline export: no online submission was made.";
    default:
      return `Submission status: ${state}.`;
  }
}

/** Whether a receipt state means the ballot was definitively accepted. */
export function receiptStateIsAccepted(state: string): boolean {
  return state === "ACCEPTED" || state === "INCLUDED" || state === "ANCHORED";
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
    "duplicate_of_sequence",
    "intake_sequence",
  ];
  return fieldNames.every((field) => {
    const normalized = field.toLowerCase();
    return forbidden.every((marker) => !normalized.includes(marker));
  });
}
