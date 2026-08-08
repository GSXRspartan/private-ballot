/**
 * Pure governance-source presentation helpers (Slice 5A8).
 *
 * Framework-free pure functions for the organizer and voter UI. The
 * authoritative validation lives in gui-core; these helpers only format
 * presentation labels and detect obvious problems for display. No secret
 * material is handled here. No network access.
 */

import type {
  GuiGovernanceMatchStatus,
  GuiGovernanceSourcePinV1,
} from "./api/types";

/** Prefix for the recommended content-digest pin form. */
export const GOVERNANCE_PIN_PREFIX_BLAKE3 = "blake3:";
/** Prefix for the advanced Git commit SHA pin form. */
export const GOVERNANCE_PIN_PREFIX_GIT = "git:";

/** Whether a bound pin is the recommended content-digest form. */
export function isContentDigestPin(pin: GuiGovernanceSourcePinV1 | null): boolean {
  return !!pin && pin.kind === "BLAKE3_DIGEST" && pin.format_valid;
}

/** Whether a bound pin is the advanced Git commit SHA form. */
export function isGitCommitPin(pin: GuiGovernanceSourcePinV1 | null): boolean {
  return !!pin && pin.kind === "GIT_COMMIT" && pin.format_valid;
}

/** Concise user-facing label for the pin kind. */
export function pinKindLabel(pin: GuiGovernanceSourcePinV1 | null): string {
  if (!pin) return "No governance source";
  switch (pin.kind) {
    case "BLAKE3_DIGEST":
      return "Content digest";
    case "GIT_COMMIT":
      return "Git commit SHA";
    default:
      return "Unrecognized reference";
  }
}

/** Concise status tone for the pin format validity. */
export function pinFormatTone(pin: GuiGovernanceSourcePinV1 | null): "ok" | "warn" | "neutral" {
  if (!pin) return "neutral";
  return pin.format_valid ? "ok" : "warn";
}

/** User-facing status tone for the document match status. Returns "ok" only
 *  when the digest has actually been cryptographically matched. Never returns
 *  "ok" for operator-attested correspondence. */
export function documentMatchTone(status: GuiGovernanceMatchStatus | null | undefined): "ok" | "warn" | "neutral" | "error" {
  if (!status) return "neutral";
  switch (status) {
    case "MATCHED":
      return "ok";
    case "MISMATCH":
      return "error";
    case "OPERATOR_ATTESTED":
    case "UNVERIFIED_REFERENCE":
      return "warn";
    default:
      return "neutral";
  }
}

/** Concise label for the document match status (Bound / Matched /
 *  Operator-attested / Not available). Calm and professional. */
export function documentMatchShortLabel(status: GuiGovernanceMatchStatus | null | undefined): string {
  if (!status) return "Not available";
  switch (status) {
    case "MATCHED":
      return "Matched";
    case "MISMATCH":
      return "Mismatch";
    case "OPERATOR_ATTESTED":
      return "Operator-attested";
    case "UNVERIFIED_REFERENCE":
      return "Not available";
    default:
      return "Not applicable";
  }
}

/** Whether the governance document status indicates a cryptographic match. */
export function isCryptographicallyMatched(
  status: GuiGovernanceMatchStatus | null | undefined,
): boolean {
  return status === "MATCHED";
}

/** Formats a byte count for human display (binary units, one decimal). */
export function formatByteSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || bytes < 0) return "—";
  if (bytes === 0) return "0 bytes";
  const units = ["bytes", "KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${value} ${units[unit]}`;
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** The recommended-mode call to action shown to organizers. */
export const RECOMMENDED_PIN_LABEL = "Recommended: pin by content digest";
/** The advanced-mode call to action shown to organizers. */
export const ADVANCED_PIN_LABEL = "Advanced: use an immutable Git commit reference";

/** Whether the voter confirmation "Continue" action is available. The
 *  confirmation boundary requires the bound fields to be present; the action
 *  never starts credential handling or proof generation. */
export function confirmationContinueAvailable(
  confirmation: { bound: { manifest_hash_hex: string } } | null,
): boolean {
  return !!confirmation && confirmation.bound.manifest_hash_hex.length > 0;
}

/** Label for the cryptographically bound section. */
export const BOUND_SECTION_LABEL = "Cryptographically bound";
/** Label for the non-canonical presentation section. */
export const PRESENTATION_SECTION_LABEL = "Presentation";
/** Label for the informational notice under the presentation label. */
export const INFORMATIONAL_LABEL = "Informational";
/** Label for the advanced details disclosure. */
export const ADVANCED_DETAILS_LABEL = "Advanced details";

/** Whether the next voter stage is still a deferred placeholder. Always true
 *  in this slice; credential/proof handling remains deferred. */
export function nextStageIsPlaceholder(placeholder: string | null | undefined): boolean {
  return !!placeholder && placeholder.includes("next reviewed slice");
}
