/**
 * Typed client over the Tauri command boundary.
 *
 * gui-core is the ONLY backend interface (ADR-0007): every call goes through
 * a typed Tauri command implemented by the Rust shell; there is no local
 * HTTP server, no CLI invocation, and no stdout parsing. When the frontend
 * runs outside the desktop shell (plain browser dev), calls reject with a
 * `GUI_SHELL_UNAVAILABLE` error and screens render their neutral states —
 * never mock data.
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  GuiAnchorConfigInspectionV1,
  GuiAnchorEvidenceInspectionV1,
  GuiAnchorSnapshotInspectionV1,
  GuiArchiveVerificationV1,
  GuiArchiveWriteResultV1,
  GuiBallotPresentationType,
  GuiBallotIntakeResultV1,
  GuiCommandError,
  GuiElectionCreationResultV1,
  GuiElectionDraftPreviewV1,
  GuiElectionExportResultV1,
  GuiElectionSummaryV1,
  GuiGovernanceDocumentDigestV1,
  GuiGovernanceDocumentStatusV1,
  GuiParticipationSummaryV1,
  GuiTallySummaryV1,
  GuiVoterCredentialStatusV1,
  GuiVoterElectionConfirmationV1,
  PresentationIdentifier,
  ShellInfoV1,
} from "./types";

export class BackendError extends Error {
  readonly payload: GuiCommandError;

  constructor(payload: GuiCommandError) {
    super(payload.message);
    this.name = "BackendError";
    this.payload = payload;
  }
}

export function isDesktopShell(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const SHELL_UNAVAILABLE: GuiCommandError = {
  code: "GUI_SHELL_UNAVAILABLE",
  category: "FILE_IO",
  context: null,
  message: "the desktop shell backend is not running",
};

function asBackendError(error: unknown): BackendError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "category" in error &&
    "message" in error
  ) {
    return new BackendError(error as GuiCommandError);
  }
  return new BackendError({
    code: "GUI_UNEXPECTED_ERROR",
    category: "INVALID_INPUT",
    context: null,
    message: "an unexpected frontend/backend boundary error occurred",
  });
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isDesktopShell()) {
    throw new BackendError(SHELL_UNAVAILABLE);
  }
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw asBackendError(error);
  }
}

export const api = {
  shellInfo: () => call<ShellInfoV1>("shell_info"),

  loadElection: (manifestPath: string, registryPath: string, optionSetPath: string) =>
    call<GuiElectionSummaryV1>("load_election", {
      manifestPath,
      registryPath,
      optionSetPath,
    }),

  unloadElection: () => call<void>("unload_election"),

  electionSummary: () => call<GuiElectionSummaryV1 | null>("election_summary"),

  openVoting: () => call<GuiElectionSummaryV1>("open_voting"),
  closeVoting: () => call<GuiElectionSummaryV1>("close_voting"),
  markVerified: () => call<GuiElectionSummaryV1>("mark_verified"),
  finalizeElection: () => call<GuiElectionSummaryV1>("finalize_election"),

  intakeBallotPackage: (packagePath: string) =>
    call<GuiBallotIntakeResultV1>("intake_ballot_package", { packagePath }),

  currentTally: () => call<GuiTallySummaryV1>("current_tally"),

  participationSummary: () =>
    call<GuiParticipationSummaryV1>("participation_summary"),

  writeArchive: (targetDir: string) =>
    call<GuiArchiveWriteResultV1>("write_archive", { targetDir }),

  verifyArchive: (directory: string) =>
    call<GuiArchiveVerificationV1>("verify_archive", { directory }),

  inspectAnchorConfig: (path: string) =>
    call<GuiAnchorConfigInspectionV1>("inspect_anchor_config", { path }),

  inspectAnchorSnapshot: (path: string) =>
    call<GuiAnchorSnapshotInspectionV1>("inspect_anchor_snapshot", { path }),

  inspectAnchorEvidence: (path: string) =>
    call<GuiAnchorEvidenceInspectionV1>("inspect_anchor_evidence", { path }),

  // Organizer election creation (Slice 5A6).
  startElectionDraft: () => call<void>("start_election_draft"),
  discardElectionDraft: () => call<void>("discard_election_draft"),
  setDraftBasics: (electionIdText: string, governanceSourceRevision: string) =>
    call<void>("set_draft_basics", { electionIdText, governanceSourceRevision }),
  setDraftRules: (approvalMin: number, approvalMax: number, allowAbstention: boolean) =>
    call<void>("set_draft_rules", { approvalMin, approvalMax, allowAbstention }),
  setDraftVoters: (publicKeyHexs: string[]) =>
    call<void>("set_draft_voters", { publicKeyHexs }),
  setDraftOptions: (
    options: { machine_id_text: string; display_name: string }[],
  ) => call<void>("set_draft_options", { options }),
  setDraftPresentation: (presentation: PresentationIdentifier) =>
    call<void>("set_draft_presentation", { presentation }),
  importRegistryToDraft: (registryPath: string) =>
    call<void>("import_registry_to_draft", { registryPath }),
  previewDraft: () => call<GuiElectionDraftPreviewV1>("preview_draft"),
  freezeElection: () => call<GuiElectionCreationResultV1>("freeze_election"),
  exportElectionArtifacts: (targetDir: string) =>
    call<GuiElectionExportResultV1>("export_election_artifacts", { targetDir }),

  // Slice 5A8: governance source pinning, document archival, voter confirmation.
  setDraftGovernanceSourceRevision: (governanceSourceRevision: string) =>
    call<void>("set_draft_governance_source_revision", { governanceSourceRevision }),
  setDraftGovernanceDocument: (path: string) =>
    call<GuiGovernanceDocumentDigestV1>("set_draft_governance_document", { path }),
  clearDraftGovernanceDocument: () => call<void>("clear_draft_governance_document"),
  useGovernanceDocumentDigestAsRevision: () =>
    call<void>("use_governance_document_digest_as_revision"),
  computeGovernanceDocumentDigest: (path: string) =>
    call<GuiGovernanceDocumentDigestV1>("compute_governance_document_digest", { path }),
  matchGovernanceDocument: (
    governanceSourceRevision: string,
    governanceDocumentPath: string | null,
  ) =>
    call<GuiGovernanceDocumentStatusV1>("match_governance_document", {
      governanceSourceRevision,
      governanceDocumentPath,
    }),
  voterConfirmation: (governanceDocumentPath: string | null) =>
    call<GuiVoterElectionConfirmationV1>("voter_confirmation", { governanceDocumentPath }),
  voterGovernanceCredentialStatus: () =>
    call<GuiVoterCredentialStatusV1>("voter_governance_credential_status"),
  generateVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("generate_voter_governance_credential"),
  resetVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("reset_voter_governance_credential"),
  writeArchiveWithGovernanceDocument: (
    targetDir: string,
    governanceDocumentPath: string | null,
  ) =>
    call<GuiArchiveWriteResultV1>("write_archive_with_governance_document", {
      targetDir,
      governanceDocumentPath,
    }),
};

/** The presentation type the frontend should send to the backend for a given
 *  UI ballot-type choice. */
export function presentationIdentifier(
  type: GuiBallotPresentationType,
): PresentationIdentifier {
  switch (type) {
    case "Candidate":
      return "candidate";
    case "GovernanceProposal":
      return "governance-proposal";
    case "BallotMeasure":
      return "ballot-measure";
  }
}
