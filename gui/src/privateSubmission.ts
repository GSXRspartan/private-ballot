import type {
  GuiPrivateReleaseResultV1,
  GuiPrivateSubmissionResultV1,
  GuiVoterCastLockStateV1,
} from "./api/types";

/**
 * Bounded automatic-retry backoff schedule (milliseconds) for a private
 * submission whose ONLY failure so far is transient transport/onion
 * reachability. One entry per automatic retry, so the schedule length is also
 * the maximum number of automatic retries. Kept short and small on purpose: a
 * transient onion route usually becomes reachable within a few seconds, and an
 * ordinary voter must never be forced to hammer Retry by hand. There is no
 * indefinite loop — after these are exhausted the truthful CAST_PENDING UI and
 * the manual Retry button stand.
 *
 * Each automatic retry re-sends the EXACT same staged encrypted submission
 * through the existing exact-retry path (same digest, same nullifier, same
 * proof, same payload); it never creates a new ballot and an authenticated
 * organizer receipt remains mandatory for CAST.
 */
export const PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS: readonly number[] = [
  2000, 5000, 8000,
];

/** The bounded, PRIVACY-SAFE diagnostic stage that means the ballot could not be
 *  delivered because no authenticated organizer receipt was obtained — i.e. a
 *  transient transport/onion-reachability failure. This is the ONLY stage an
 *  automatic retry is allowed to react to. Every other stage means the payload
 *  reached the organizer (authenticated rejection, receipt/descriptor/package
 *  mismatch, invalid receipt) or a local finalization issue, and must be
 *  surfaced immediately, never auto-retried. */
export const TRANSIENT_TRANSPORT_STAGE = "PRIVATE_TRANSPORT_UNAVAILABLE";

/**
 * Whether a private-release result is a TRANSIENT transport/reachability failure
 * that is safe to auto-retry with the exact same staged submission.
 *
 * True ONLY when the durable state is `CAST_PENDING` and the diagnostic stage is
 * exactly {@link TRANSIENT_TRANSPORT_STAGE}. A `CAST` success, any receipt-level
 * stage (authenticated rejection, signature/descriptor/package mismatch, parse
 * failure), or a local persist/promotion failure all return `false` so they are
 * surfaced immediately and never retried. A non-release result (e.g. the offline
 * export DTO) also returns `false`.
 */
export function isTransientPrivateReleaseResult(
  result: GuiPrivateReleaseResultV1 | GuiPrivateSubmissionResultV1 | null,
): boolean {
  if (result === null || !("diagnostic_stage" in result)) return false;
  return (
    result.cast_lock_state === "CAST_PENDING" &&
    result.diagnostic_stage === TRANSIENT_TRANSPORT_STAGE
  );
}

/**
 * Voter-facing status of the private (controlled managed-Tor) submission,
 * derived from AUTHORITATIVE durable state — never from a transient React
 * variable alone. The durable `castState` (`NOT_CAST` / `CAST_PENDING` / `CAST`)
 * is the source of truth, so the correct result survives a page navigation or a
 * full application restart: a completed vote still reads SUCCESS, and an
 * unconfirmed submission still reads PENDING with a retry path, without relying
 * on any in-memory result object.
 *
 * The distinct phases exist so success, failure, and "still pending" are never
 * collapsed into one ambiguous state. Only an authenticated organizer receipt
 * that promoted the durable state to CAST is ever reported as success; an
 * HTTP-level result is never sufficient (that check lives entirely in the Rust
 * release boundary, not here).
 */
export type PrivateSubmissionPhase =
  | "NOT_CONFIGURED"
  | "READY_TO_START"
  | "READY"
  | "SUBMITTING"
  | "SUCCESS"
  | "PENDING"
  | "REJECTED";

export interface PrivateSubmissionStatus {
  phase: PrivateSubmissionPhase;
  tone: "ok" | "warn" | "info" | "error";
  title: string;
  detail: string;
}

/**
 * Whether the controlled managed-Tor "Private submission (controlled test)" card
 * should render.
 *
 * It renders ONLY when the controlled-test feature is actually present in this
 * build (`featurePresent`) AND there is something to do: a ballot is Ready to
 * submit, or the durable cast state is CAST_PENDING/CAST (so the recovery/status
 * route survives a restart even when the transient prepared-ballot state is
 * gone). A production build without the `managed-tor-test` feature never has the
 * feature present, so this card is always absent there and the truthful offline/
 * unavailable production guidance stands alone.
 */
export function managedTorTestCardVisible(input: {
  /** True only when the controlled-test feature is compiled into this build. */
  featurePresent: boolean;
  /** Whether the prepared ballot is currently in the transient "Ready" state. */
  preparedReady: boolean;
  /** Durable, authoritative cast-lock state from the backend workflow DTO. */
  castState: GuiVoterCastLockStateV1;
}): boolean {
  if (!input.featurePresent) return false;
  const castLocked = input.castState === "CAST_PENDING" || input.castState === "CAST";
  return input.preparedReady || castLocked;
}

/**
 * Maps a backend controlled-test diagnostic stage code to a short, voter-safe
 * sentence for the Advanced/diagnostics panel. The codes are a bounded,
 * privacy-safe vocabulary (they never carry secret or network-identity
 * material); an unknown code is shown verbatim so a new backend stage is never
 * silently hidden. Returns `null` when there is no stage to describe.
 */
export function privateSubmissionStageLabel(stage: string | null | undefined): string | null {
  if (!stage) return null;
  switch (stage) {
    case "PRIVATE_TRANSPORT_UNAVAILABLE":
      return "The private connection could not deliver the ballot (no authenticated organizer receipt was received). Check that the organizer intake is running and reachable, then retry.";
    case "RECEIPT_PARSE_FAILED":
      return "A reply was received but it was not a well-formed organizer receipt.";
    case "RECEIPT_SIGNATURE_INVALID":
      return "The organizer receipt did not verify against the trusted transport descriptor.";
    case "RECEIPT_DESCRIPTOR_MISMATCH":
      return "The organizer receipt was bound to a different transport descriptor.";
    case "RECEIPT_PACKAGE_MISMATCH":
      return "The organizer receipt acknowledged a different ballot package.";
    case "RECEIPT_REJECTED_BY_ORGANIZER":
      return "The organizer authenticated the delivery but rejected the ballot. Your ballot stays locked; no new ballot is created.";
    case "RECEIPT_PERSIST_FAILED":
      return "The ballot was delivered and authenticated, but the local receipt record could not be saved. Retry to finish.";
    case "CAST_PROMOTION_FAILED":
      return "The ballot was delivered and authenticated, but the local cast record could not be finalized. Retry to finish.";
    default:
      return `Safe stage: ${stage}`;
  }
}

export interface PrivateSubmissionInput {
  /** Durable, authoritative cast-lock state from the backend workflow DTO. */
  castState: GuiVoterCastLockStateV1;
  /** Whether the controlled-test transport has been configured this session. */
  configured: boolean;
  /** Whether the managed Tor child is running with a ready SOCKS listener. */
  torRunning: boolean;
  /** Whether a submit/retry request is currently in flight. */
  busy: boolean;
  /** The most recent receipt state from a private-submission result this
   *  session, if any (e.g. "REJECTED"). Transient; used only to refine the
   *  CAST_PENDING presentation, never to claim success. */
  lastReceiptState: string | null;
}

/**
 * Derives the private-submission status block. The durable cast state dominates:
 * CAST is always SUCCESS and CAST_PENDING is always locked/pending (or a
 * short-lived SUBMITTING while a request is in flight), regardless of the
 * transient transport connection state.
 */
export function privateSubmissionStatus(
  input: PrivateSubmissionInput,
): PrivateSubmissionStatus {
  const { castState, configured, torRunning, busy, lastReceiptState } = input;

  if (castState === "CAST") {
    return {
      phase: "SUCCESS",
      tone: "ok",
      title: "Vote submitted successfully",
      detail:
        "Authenticated organizer receipt verified. Your vote is locked for this election.",
    };
  }

  if (castState === "CAST_PENDING") {
    if (busy) {
      return {
        phase: "SUBMITTING",
        tone: "info",
        title: "Submitting ballot privately…",
        detail: "Waiting for the authenticated organizer receipt.",
      };
    }
    if (lastReceiptState === "REJECTED") {
      return {
        phase: "REJECTED",
        tone: "error",
        title: "Submission was rejected by the organizer.",
        detail:
          "Your ballot remains locked for this election. No new ballot will be created.",
      };
    }
    return {
      phase: "PENDING",
      tone: "warn",
      title: "Submission could not be confirmed.",
      detail:
        "Your ballot remains safely locked and the same encrypted submission can be retried. No new ballot will be created.",
    };
  }

  // NOT_CAST: no durable submission exists yet.
  if (busy) {
    return {
      phase: "SUBMITTING",
      tone: "info",
      title: "Submitting ballot privately…",
      detail: "Waiting for the authenticated organizer receipt.",
    };
  }
  if (!configured) {
    return {
      phase: "NOT_CONFIGURED",
      tone: "info",
      title: "Private connection is not ready.",
      detail: "Configure and start the private connection to submit.",
    };
  }
  if (!torRunning) {
    return {
      phase: "READY_TO_START",
      tone: "info",
      title: "Private connection is configured.",
      detail: "Start the private connection, then submit privately.",
    };
  }
  return {
    phase: "READY",
    tone: "ok",
    title: "Private connection ready.",
    detail: "You can submit your ballot privately.",
  };
}
