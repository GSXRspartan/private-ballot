import type { GuiBallotIntakeResultV1 } from "./api/types";

const REJECTION_LABELS: Record<string, string> = {
  DUPLICATE_NULLIFIER: "Duplicate ballot for this election.",
  WRONG_MANIFEST_HASH: "Ballot package is for a different election.",
  LIFECYCLE_COMMITMENT_MISMATCH: "Ballot package is for a different election.",
  CANDIDATE_SET_COMMITMENT_MISMATCH: "Ballot package is for a different election.",
  ELECTION_NOT_OPEN: "Election is not open for ballot intake.",
  MALFORMED_PROOF: "Ballot proof is malformed.",
  INVALID_PROOF: "Ballot proof is invalid.",
  UNKNOWN_CANDIDATE_ID: "Ballot selection is not valid for this election.",
  UNSUPPORTED_PROOF_SUITE: "Ballot proof suite is unsupported.",
  NON_CANONICAL_CBOR: "Ballot package is not canonical CBOR.",
  TRAILING_DATA: "Ballot package has trailing bytes.",
};

export function intakeResultTitle(result: GuiBallotIntakeResultV1 | null): string {
  if (result === null) return "No ballot package imported.";
  return result.accepted ? "Ballot accepted" : "Ballot rejected";
}

export function intakeResultMessage(result: GuiBallotIntakeResultV1 | null): string {
  if (result === null) return "No recent intake result.";
  if (result.accepted) return "Ballot accepted.";
  return REJECTION_LABELS[result.code] ?? "Ballot package failed validation.";
}

export function intakeCanImport(shellAvailable: boolean, lifecycle: string | null): boolean {
  return shellAvailable && lifecycle === "OPEN";
}
