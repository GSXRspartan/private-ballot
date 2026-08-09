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
