/**
 * Pure organizer-creation helpers (Slice 5A6).
 *
 * Framework-free pure functions so the creation logic can be unit-tested under
 * Node's built-in test runner without a React harness. The authoritative
 * validation lives in gui-core; these helpers only prepare presentation and
 * detect obvious input problems before sending data to the backend.
 *
 * No secret material is ever handled here: only public governance keys (hex)
 * and display data.
 */

import type { GuiElectionDraftPreviewV1, GuiBallotPresentationType } from "./api/types";

/** Canonical byte length of one Ristretto255 compressed public key. */
export const GOVERNANCE_KEY_BYTES = 32;
export const GOVERNANCE_KEY_HEX_LEN = GOVERNANCE_KEY_BYTES * 2;

/** Result of parsing a pasted public-key list. */
export interface ParsedVoterList {
  keys: string[];
  errors: string[];
}

/**
 * Parses a newline-separated list of hex governance public keys. Trims each
 * line, ignores blank lines, and validates that each non-blank line is exactly
 * 64 lowercase/uppercase hex characters. Duplicates are surfaced as errors
 * (the backend rejects them too, but surfacing early improves UX). This is a
 * non-canonical convenience input format only.
 */
export function parseVoterHexList(text: string): ParsedVoterList {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    if (!/^[0-9a-fA-F]+$/.test(line)) {
      errors.push(`Not valid hexadecimal: ${truncate(line)}`);
      continue;
    }
    if (line.length !== GOVERNANCE_KEY_HEX_LEN) {
      errors.push(
        `Expected ${GOVERNANCE_KEY_HEX_LEN} hex characters (32 bytes), got ${line.length}: ${truncate(line)}`,
      );
      continue;
    }
    if (seen.has(line.toLowerCase())) {
      errors.push(`Duplicate public key: ${truncate(line)}`);
      continue;
    }
    seen.add(line.toLowerCase());
  }
  // Rebuild the forwarded list preserving order, deduplicated by lowercase.
  // The backend re-validates every key (hex, length, Ristretto point, dedup).
  const ordered: string[] = [];
  const orderedSeen = new Set<string>();
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (
      /^[0-9a-fA-F]+$/.test(line) &&
      line.length === GOVERNANCE_KEY_HEX_LEN &&
      !orderedSeen.has(lower)
    ) {
      ordered.push(line);
      orderedSeen.add(lower);
    }
  }
  return { keys: ordered, errors };
}

function truncate(text: string, max = 24): string {
  return text.length <= max ? text : `${text.slice(0, max)}\u{2026}`;
}

/** One ballot option being edited in the UI. */
export interface DraftOptionInput {
  machine_id_text: string;
  display_name: string;
}

/** Returns user-facing validation errors for an option list, or an empty array
 *  when the list is valid (or empty, which is permitted during editing). */
export function optionValidationErrors(options: DraftOptionInput[]): string[] {
  const errors: string[] = [];
  const seenIds = new Set<string>();
  const seenLabels = new Set<string>();
  for (const option of options) {
    if (option.machine_id_text.trim().length === 0) {
      errors.push("A ballot option has an empty machine ID.");
      continue;
    }
    if (option.display_name.trim().length === 0) {
      errors.push(`Option "${option.machine_id_text}" has an empty display label.`);
      continue;
    }
    if (seenIds.has(option.machine_id_text)) {
      errors.push(`Duplicate machine ID: ${option.machine_id_text}`);
      continue;
    }
    // Display labels are compared after the same trim normalization the backend
    // applies; canonical labels are not altered. The backend re-validates.
    const labelKey = option.display_name.trim();
    if (seenLabels.has(labelKey)) {
      errors.push(`Duplicate display label: ${option.display_name.trim()}`);
      continue;
    }
    seenIds.add(option.machine_id_text);
    seenLabels.add(labelKey);
  }
  return errors;
}

/** Returns true when the draft preview is complete and not yet frozen. */
export function freezeAvailable(preview: GuiElectionDraftPreviewV1 | null): boolean {
  if (!preview) return false;
  return preview.complete && !preview.frozen;
}

/** Returns true when the draft is frozen and export is available. */
export function exportAvailable(preview: GuiElectionDraftPreviewV1 | null): boolean {
  if (!preview) return false;
  return preview.frozen;
}

/** Human-facing label for a presentation type. */
export function presentationLabel(type: GuiBallotPresentationType): string {
  switch (type) {
    case "Candidate":
      return "Candidate election";
    case "GovernanceProposal":
      return "Governance proposal";
    case "BallotMeasure":
      return "Ballot measure";
  }
}

/** Noun for the whole option set under a presentation type. */
export function optionSetNoun(type: GuiBallotPresentationType): string {
  switch (type) {
    case "Candidate":
      return "Candidates";
    case "GovernanceProposal":
      return "Choices";
    case "BallotMeasure":
      return "Responses";
  }
}

/** Singular noun for one option. */
export function optionNoun(type: GuiBallotPresentationType): string {
  switch (type) {
    case "Candidate":
      return "candidate";
    case "GovernanceProposal":
      return "choice";
    case "BallotMeasure":
      return "response";
  }
}

/** Human-facing approval-rule sentence for the review screen. */
export function approvalRulePreview(
  min: number | null,
  max: number | null,
  abstention: boolean,
): string {
  if (min === null || max === null) return "Approval limits not set.";
  const range =
    min === 0 && abstention
      ? `up to ${max} option${max === 1 ? "" : "s"}`
      : min === max
        ? `exactly ${min} option${min === 1 ? "" : "s"}`
        : `between ${min} and ${max} options`;
  const abstentionClause = abstention
    ? " Abstaining (an empty selection) is permitted."
    : " Abstaining is not permitted.";
  return `Each ballot approves ${range}.${abstentionClause}`;
}

/** The quorum-rule statement for the review screen. The version-one manifest
 *  carries no quorum field, so this is always the conservative statement. */
export const NO_QUORUM_STATEMENT =
  "No quorum rule is represented in this election manifest.";

/**
 * Returns true when the configured approval rules would permit no castable
 * ballot (maximum approvals is zero while abstention is disabled). Mirrors the
 * backend organizer-facade safety rule; the backend re-validates authoritatively.
 */
export function isUncastableApprovalConfig(
  min: number | null,
  max: number | null,
  abstention: boolean,
): boolean {
  if (min === null || max === null) return false;
  return !abstention && max === 0;
}

/** State of the authoritative Rust-side election-draft setup. */
export type DraftInitializationState = "initializing" | "ready" | "failed";

/** Only a successfully started Rust draft may be edited by the wizard. */
export function draftIsReady(state: DraftInitializationState): boolean {
  return state === "ready";
}

/**
 * Starts a fresh authoritative election draft and reports its lifecycle to the
 * caller. This deliberately does not create or retain a TypeScript draft.
 */
export async function initializeElectionDraft(
  startElectionDraft: () => Promise<void>,
  setState: (state: DraftInitializationState) => void,
): Promise<void> {
  setState("initializing");
  try {
    await startElectionDraft();
    setState("ready");
  } catch (error) {
    setState("failed");
    throw error;
  }
}
