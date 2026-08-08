/**
 * Structured error presentation for `GuiCommandError`.
 *
 * gui-core's bounded error model already carries a stable machine `code`, a
 * coarse `category`, and a safe static `message`. This module maps that onto a
 * user-facing presentation: a concise title derived from the category, the safe
 * message verbatim (never a raw Rust backtrace or third-party text), and the
 * stable machine code reserved for an "Advanced details" disclosure.
 *
 * No secret, path, or unbounded third-party text is ever rendered: the backend
 * guarantees it, and this layer only rewrites the category into a title.
 */

import type { GuiCommandError } from "./types";

export interface ErrorDisplay {
  /** Concise, friendly title derived from the coarse category. */
  title: string;
  /** Safe, bounded message from the backend. */
  message: string;
  /** Stable machine code for the Advanced details disclosure. */
  code: string;
  /** Coarse category code, also shown under Advanced details. */
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
  INVALID_LIFECYCLE_TRANSITION: "Action not permitted in this state",
  ARCHIVE_INTEGRITY: "Archive integrity check failed",
  FILE_IO: "File could not be read",
  ANCHOR_ARTIFACT_INTEGRITY: "Anchor artifact failed validation",
};

const FALLBACK_TITLE = "Something went wrong";

export function describeError(error: GuiCommandError): ErrorDisplay {
  return {
    title: CATEGORY_TITLES[error.category] ?? FALLBACK_TITLE,
    message: error.message,
    code: error.code,
    category: error.category,
    context: error.context,
  };
}
