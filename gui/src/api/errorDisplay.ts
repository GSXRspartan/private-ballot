/**
 * Structured error presentation for `GuiCommandError`.
 *
 * gui-core's bounded error model already carries a stable machine `code`, a
 * coarse `category`, and a safe static `message`. This module maps that onto a
 * user-facing presentation, in this order:
 *
 *   1. What happened      — a concise title derived from the category, plus
 *                           the safe bounded backend message verbatim (never
 *                           a raw Rust backtrace or third-party text).
 *   2. What to do next    — a plain-language suggested next step.
 *   3. Technical details  — the stable machine code, coarse category, and
 *                           optional context label under a disclosure.
 *
 * No secret, path, or unbounded third-party text is ever rendered: the backend
 * guarantees it, and this layer only rewrites the category into a title and a
 * next step.
 */

import type { GuiCommandError } from "./types";

export interface ErrorDisplay {
  /** Concise, friendly title derived from the coarse category. */
  title: string;
  /** Safe, bounded message from the backend. */
  message: string;
  /** Plain-language suggested next step for the user. */
  nextStep: string;
  /** Stable machine code for the Technical details disclosure. */
  code: string;
  /** Coarse category code, also shown under Technical details. */
  category: string;
  /** Optional static context label (artifact/stage) from the backend. */
  context: string | null;
}

const CATEGORY_TITLES: Record<string, string> = {
  INVALID_INPUT: "Invalid election files",
  UNSUPPORTED_FORMAT: "Unsupported file format or version",
  BINDING_MISMATCH: "Election files do not match",
  PROOF_FAILURE: "Ballot proof verification failed",
  DUPLICATE_BALLOT: "Duplicate ballot",
  INVALID_LIFECYCLE_TRANSITION: "Action not available right now",
  ARCHIVE_INTEGRITY: "Archive integrity check failed",
  FILE_IO: "File could not be read",
  ANCHOR_ARTIFACT_INTEGRITY: "Anchor artifact failed validation",
  UNAVAILABLE: "Service not available",
};

const CATEGORY_NEXT_STEPS: Record<string, string> = {
  INVALID_INPUT:
    "Check the information or files you provided and try again.",
  UNSUPPORTED_FORMAT:
    "Make sure the file was produced by a compatible version of this application.",
  BINDING_MISMATCH:
    "Make sure all of the selected files belong to the same election, then try again.",
  PROOF_FAILURE:
    "Make sure you selected the correct ballot file for this election and try again.",
  DUPLICATE_BALLOT:
    "This ballot was already accepted for this election. No further action is needed.",
  INVALID_LIFECYCLE_TRANSITION:
    "The election is not in the right state for this action. Check the election status and try again.",
  ARCHIVE_INTEGRITY:
    "The saved election record did not pass verification. Do not rely on this archive; re-export it from the original election data if possible.",
  FILE_IO:
    "Check that the file or folder exists and that you have permission to access it, then try again.",
  ANCHOR_ARTIFACT_INTEGRITY:
    "Check that you selected the correct anchor artifact for this election and try again.",
  UNAVAILABLE:
    "This option is not available in the current configuration. Choose one of the available options instead.",
};

const FALLBACK_TITLE = "Something went wrong";
const FALLBACK_NEXT_STEP =
  "Dismiss this message and try the action again. If it keeps failing, note the technical details below.";

export function describeError(error: GuiCommandError): ErrorDisplay {
  // Browser preview without the desktop shell is an environment state, not
  // a file problem.
  if (error.code === "GUI_SHELL_UNAVAILABLE") {
    return {
      title: "Desktop shell not running",
      message: error.message,
      nextStep:
        "Election operations are available in the desktop application, not in the browser preview.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  return {
    title: CATEGORY_TITLES[error.category] ?? FALLBACK_TITLE,
    message: error.message,
    nextStep: CATEGORY_NEXT_STEPS[error.category] ?? FALLBACK_NEXT_STEP,
    code: error.code,
    category: error.category,
    context: error.context,
  };
}
