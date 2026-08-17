/**
 * Input-bound archive verification state.
 *
 * A verification result is only meaningful for the exact inputs it was computed
 * from. The UI must never present cryptographic success for a directory (or
 * evidence path) other than the one the authoritative Rust verifier actually
 * checked. These pure helpers bind each result to its inputs and gate rendering
 * and async installation on input equality, so:
 *
 *   - a result is renderable only while its bound inputs still match the
 *     current inputs;
 *   - an async response that resolves after the user changed the inputs is
 *     recognized as stale and discarded, never installed for the new inputs.
 *
 * The backend verification itself is never cancelled or weakened; Rust remains
 * authoritative. These helpers only decide what the UI may display.
 */

import type {
  GuiArchiveVerificationV1,
  GuiTransportAnchorVerificationV1,
} from "../api/types";

/** An archive verification result bound to the directory that produced it. */
export interface ArchiveVerificationBindingV1 {
  result: GuiArchiveVerificationV1;
  verifiedDirectory: string;
}

/** A transport-anchor verification result bound to BOTH inputs that produced
 *  it. */
export interface TransportAnchorBindingV1 {
  result: GuiTransportAnchorVerificationV1;
  checkedArchiveDirectory: string;
  checkedEvidencePath: string;
}

/** Returns the archive result only while its bound directory still equals the
 *  current archive directory; otherwise `null` (not renderable). */
export function boundArchiveResult(
  binding: ArchiveVerificationBindingV1 | null,
  currentDirectory: string,
): GuiArchiveVerificationV1 | null {
  if (!binding) return null;
  return binding.verifiedDirectory === currentDirectory ? binding.result : null;
}

/** Returns the transport-anchor result only while BOTH bound inputs still equal
 *  the current inputs; otherwise `null` (not renderable). */
export function boundTransportAnchorResult(
  binding: TransportAnchorBindingV1 | null,
  currentDirectory: string,
  currentEvidencePath: string,
): GuiTransportAnchorVerificationV1 | null {
  if (!binding) return null;
  return binding.checkedArchiveDirectory === currentDirectory &&
    binding.checkedEvidencePath === currentEvidencePath
    ? binding.result
    : null;
}

/** True when an in-flight archive verification for `submittedDirectory` is
 *  stale because the current directory changed while it was running. Its result
 *  must be discarded rather than installed for the new directory. */
export function archiveResultIsStale(
  submittedDirectory: string,
  currentDirectory: string,
): boolean {
  return submittedDirectory !== currentDirectory;
}

/** True when an in-flight transport-anchor verification is stale because either
 *  bound input changed while it was running. */
export function transportAnchorResultIsStale(
  submitted: { archiveDirectory: string; evidencePath: string },
  current: { archiveDirectory: string; evidencePath: string },
): boolean {
  return (
    submitted.archiveDirectory !== current.archiveDirectory ||
    submitted.evidencePath !== current.evidencePath
  );
}
