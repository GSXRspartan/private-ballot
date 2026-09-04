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
  // A refused non-empty export/archive destination is a protective
  // no-overwrite refusal, not a read failure: give it an accurate title and
  // next step instead of the generic FILE_IO presentation.
  if (error.code === "GUI_EXPORT_TARGET_NOT_EMPTY") {
    return {
      title: "Export folder is not empty",
      message:
        "Election packages can only be exported to a new or empty folder. This prevents files from different election records from being mixed or overwritten.",
      nextStep:
        "Choose or create a new empty folder, then try again.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_ARCHIVE_TARGET_NOT_EMPTY") {
    return {
      title: "Folder is not empty",
      message:
        "Final archives can only be written to a new or empty folder. This prevents files from different election records from being mixed or overwritten.",
      nextStep:
        "Choose or create a new empty folder, then try again.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_ARCHIVE_NOT_FINALIZED") {
    return {
      title: "Election is not finalized",
      message: error.message,
      nextStep: "Finalize the verified election before writing the final archive.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_ALREADY_LOADED") {
    return {
      title: "Credential already unlocked",
      message:
        "A different voter credential is already unlocked. Clear it from memory before switching credentials.",
      nextStep:
        "Use Clear from memory, then unlock or import the other credential.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_UNLOCK_FAILED") {
    return {
      title: "Credential could not be unlocked",
      message:
        "Could not unlock this credential. The passphrase may be incorrect or the file may be damaged.",
      nextStep: "Check the passphrase and selected credential file, then try again.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_OUTPUT_COLLISION") {
    return {
      title: "Credential file already exists",
      message:
        "The credential output file already exists. Existing credential files are not overwritten.",
      nextStep: "Choose a new backup filename or remove the old file yourself, then try again.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_UNSAFE_PATH") {
    return {
      title: "Credential path is not allowed",
      message:
        "Portable credential import and backup require a regular absolute file path.",
      nextStep: "Use the native file dialog to choose a normal .tcbcred file path.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_APP_DATA_UNAVAILABLE") {
    return {
      title: "Credential store unavailable",
      message: "The application data directory is unavailable.",
      nextStep: "Check that the desktop app can access its application data folder, then try again.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID") {
    return {
      title: "Deployment lock needs attention",
      message: error.message,
      nextStep:
        "Reload the deployment state. If this persists, use the deployment reset control; it only clears the saved deployment lock record.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_TRUSTED_OOTLE_DEPLOYMENT_LOCKED") {
    return {
      title: "Deployment is already locked",
      message: error.message,
      nextStep:
        "Reload the deployment state. To replace it, use Unlock / replace first.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_CONTAINER_FRAMING") {
    return {
      title: "Credential file is not supported",
      message:
        "The voter credential file is not a supported V1 credential container.",
      nextStep: "Choose a .tcbcred file created by this version of Private Ballot.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_CREDENTIAL_CONTAINER_VERSION") {
    return {
      title: "Credential file version is not supported",
      message: "The voter credential file version is not supported.",
      nextStep: "Use a credential backup created by a compatible version of the app.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED") {
    return {
      title: "This location can't be used for ballot export",
      message:
        "This location does not support the safe ballot finalization required by Private Ballot.",
      nextStep:
        "Choose another location, such as a local folder on your computer's main drive where you have permission to save files.",
      code: error.code,
      category: error.category,
      context: error.context,
    };
  }
  if (error.code === "GUI_BALLOT_EXPORT_PROBE_FAILED") {
    return {
      title: "Ballot export location could not be verified",
      message:
        "Private Ballot could not verify the chosen location supports safe ballot finalization.",
      nextStep:
        "Choose another location, such as a local folder on your computer's main drive, then try again.",
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
