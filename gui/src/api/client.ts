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
  GuiBallotIntakeResultV1,
  GuiCommandError,
  GuiElectionSummaryV1,
  GuiTallySummaryV1,
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
};
