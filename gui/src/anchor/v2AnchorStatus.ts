/**
 * Pure helpers projecting a persisted V2 anchor lifecycle
 * (`GuiV2LiveAnchorHydratedStateV1`) into voter/organizer-safe status
 * descriptors for the Archive and Anchor read-only status surfaces.
 *
 * These helpers never contact walletd or the indexer — the underlying
 * `inspect_v2_live_anchor_state` Rust command is strictly read-only, and its
 * result is what feeds these projections. They are framework-free so they can
 * be unit-tested under Node's built-in test runner.
 */

import type { GuiV2LiveAnchorHydratedStateV1 } from "../api/types";

export type V2AnchorSummaryKind =
  | "verified"
  | "submitted-unverified"
  | "recoverable"
  | "failed"
  | "no-anchor";

/**
 * One-glance V2 anchor summary derived from the hydrated lifecycle. `kind`
 * decides which read-only surface to render on Archive / Anchor:
 *
 *   - "verified": the receipt has been verified and immutable evidence is on
 *     disk — the terminal, fully OK state. Displayed as "Anchored · Verified".
 *   - "submitted-unverified": a transaction exists but the receipt is not
 *     verified yet. Never offers a fresh publish path here; recovery must run
 *     through Manage Election.
 *   - "recoverable": specifically a lifecycle in POLLING_RECEIPT or a
 *     verifier-topic-mismatch FAILED, which can be advanced by re-polling.
 *   - "failed": terminal failure without a recoverable transaction.
 *   - "no-anchor": no lifecycle or evidence sidecar exists — anchoring is
 *     optional; the archive is authoritative on its own.
 */
export interface V2AnchorSummary {
  kind: V2AnchorSummaryKind;
  transactionId: string | null;
  network: string | null;
  evidencePath: string;
  lifecyclePath: string;
  failurePath: string;
  templateAddress: string | null;
  templateModule: string | null;
  templateFunction: string | null;
  templateTopic: string | null;
  templateArtifactDigestHex: string | null;
  payloadHex: string | null;
  expectedDigestHex: string | null;
  phase: string | null;
  failureReason: string | null;
  recoverable: boolean;
  receiptVerified: boolean;
  evidencePresent: boolean;
  lifecyclePresent: boolean;
  failurePresent: boolean;
}

/**
 * Projects the raw hydrated V2 anchor state into a summary. Returns `null`
 * only when the input is missing entirely; a hydrated state with neither a
 * lifecycle nor evidence maps to `kind: "no-anchor"`.
 */
export function summarizeV2AnchorState(
  state: GuiV2LiveAnchorHydratedStateV1 | null,
): V2AnchorSummary | null {
  if (!state) return null;
  const base = {
    transactionId: state.transaction_id,
    network: state.network,
    evidencePath: state.evidence_path,
    lifecyclePath: state.lifecycle_path,
    failurePath: state.failure_path,
    templateAddress: state.template_address,
    templateModule: state.template_module,
    templateFunction: state.template_function,
    templateTopic: state.template_topic,
    templateArtifactDigestHex: state.template_artifact_digest_hex,
    payloadHex: state.payload_hex,
    expectedDigestHex: state.expected_digest_hex,
    phase: state.phase,
    failureReason: state.failure_reason,
    recoverable: state.recoverable,
    receiptVerified: state.receipt_verified,
    evidencePresent: state.evidence_present,
    lifecyclePresent: state.lifecycle_present,
    failurePresent: state.failure_present,
  } as const;
  if (state.receipt_verified && state.evidence_present) {
    return { ...base, kind: "verified" };
  }
  if (!state.lifecycle_present && !state.evidence_present) {
    return { ...base, kind: "no-anchor" };
  }
  if (state.recoverable) {
    return { ...base, kind: "recoverable" };
  }
  if (state.phase === "FAILED") {
    return { ...base, kind: "failed" };
  }
  if (state.transaction_id) {
    return { ...base, kind: "submitted-unverified" };
  }
  // Lifecycle exists but no transaction yet (BUILT/PREPARED/etc). Treat this
  // as submitted-unverified for display purposes: a fresh publish is still
  // blocked, and Manage Election is the correct place to advance it.
  return { ...base, kind: "submitted-unverified" };
}

/** One-line badge label for the V2 anchor status pill. */
export function v2AnchorBadgeLabel(kind: V2AnchorSummaryKind): string {
  switch (kind) {
    case "verified":
      return "Anchored · Verified";
    case "submitted-unverified":
      return "Anchor submitted · verification pending";
    case "recoverable":
      return "Anchor submitted · recovery available";
    case "failed":
      return "Anchor failed";
    case "no-anchor":
      return "No Ootle anchor published";
  }
}

/** Pill tone matching the summary kind. */
export function v2AnchorBadgeTone(
  kind: V2AnchorSummaryKind,
): "ok" | "warn" | "error" | "neutral" {
  switch (kind) {
    case "verified":
      return "ok";
    case "submitted-unverified":
    case "recoverable":
      return "warn";
    case "failed":
      return "error";
    case "no-anchor":
      return "neutral";
  }
}
