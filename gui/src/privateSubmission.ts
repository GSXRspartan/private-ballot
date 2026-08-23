import type {
  GuiCommandError,
  GuiPrivateReleaseResultV1,
  GuiPrivateSubmissionResultV1,
  GuiVoterCastLockStateV1,
} from "./api/types";

/**
 * Bounded automatic-retry backoff schedule (milliseconds) for a private
 * submission whose ONLY failure so far is transient transport/onion
 * reachability. One entry per automatic retry, so the schedule length is also
 * the maximum number of automatic retries (here: 5 retries after the first
 * attempt = 6 attempts total). There is no indefinite loop — after these are
 * exhausted the truthful CAST_PENDING UI and the manual Retry button stand.
 *
 * The schedule has two bands, chosen from the real restart evidence:
 *   - quick (2s, 5s, 8s): a brief transient onion hiccup usually clears here.
 *   - restart-aware (15s, 30s): after the ballot office RESTARTS its Tor, the
 *     hidden-service descriptor must be re-published and propagated before an
 *     independent voter circuit can reach the onion — observed to take up to
 *     ~1 minute. The two slower attempts cover that window without hammering
 *     the onion or spinning an unbounded background task. (~60s of delays plus
 *     bounded per-attempt connection time; the app has no reliable end-to-end
 *     onion-reachability signal, so it tolerates the latency rather than
 *     probing for a green light it cannot trust.)
 *
 * Each automatic retry re-sends the EXACT same staged encrypted submission
 * through the existing exact-retry path (same digest, same nullifier, same
 * proof, same payload); it never creates a new ballot and an authenticated
 * organizer receipt remains mandatory for CAST.
 */
export const PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS: readonly number[] = [
  2000, 5000, 8000, 15000, 30000,
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
 * Backend error codes that mean the private DELIVERY could not be confirmed
 * because the ballot office (organizer onion) was temporarily unreachable — a
 * transient transport failure, NOT a cryptographic/protocol rejection.
 *
 * DEFENSE-IN-DEPTH ONLY. The normal post-release remote-unavailable path never
 * throws: the backend stages the exact envelope and persists CAST_PENDING
 * BEFORE the network send, so a delivery outage arrives as a RETURNED
 * CAST_PENDING result (diagnostic PRIVATE_TRANSPORT_UNAVAILABLE), which the
 * primary classifier {@link isTransientPrivateReleaseResult} handles. This set
 * only catches a THROWN transport error, and even then the caller acts on it
 * ONLY when the AUTHORITATIVE durable state is already `CAST_PENDING` — so an
 * error code alone can never fabricate a locked state, and the exact staged
 * submission (never a new ballot) is what gets retransmitted.
 *
 * PRE-staging failures are deliberately NOT here: a descriptor-authenticity /
 * election-binding / envelope-seal failure now surfaces with a distinct,
 * honest, TERMINAL code (`GUI_RELEASE_DESCRIPTOR_*` / `GUI_RELEASE_ENVELOPE_*` /
 * `GUI_RELEASE_BALLOT_OVERSIZED`) that fails closed as NOT_CAST and must never
 * be auto-retried. Local-Tor-down (`GUI_TOR_NOT_RUNNING`) is also excluded: it
 * needs an explicit Reconnect, not a blind retry.
 */
export const RECOVERABLE_TRANSPORT_ERROR_CODES: ReadonlySet<string> = new Set([
  "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
  "GUI_TOR_CARRIER_UNAVAILABLE",
]);

/**
 * Whether a THROWN backend error is a recoverable (transient) transport-delivery
 * failure. Defense-in-depth: a recoverable transport error is only ever acted on
 * by the caller when the durable cast state is already `CAST_PENDING`; it must
 * NOT be presented as a terminal red error there, and it stays in the exact
 * retry flow. Any other code (pre-staging descriptor/seal terminal codes,
 * authenticated rejection, invalid receipt, descriptor/package mismatch, or any
 * non-transport error) is terminal and never retried.
 */
export function isRecoverableTransportError(error: GuiCommandError | null): boolean {
  return error !== null && RECOVERABLE_TRANSPORT_ERROR_CODES.has(error.code);
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

export interface BallotOfficeConnectionVisibilityInput {
  /** True when an election is loaded (imported voter session). */
  electionLoaded: boolean;
  /** True only when the controlled-test transport feature is compiled in. */
  featurePresent: boolean;
}

/**
 * Whether the "Ballot office connection" card should render on the Vote
 * screen.
 *
 * This is deliberately INDEPENDENT of ballot-submission progress: it depends
 * only on an election being loaded and the transport feature being present.
 * The two-computer physical test exposed a circular dead end when this setup
 * was buried inside the submission card's `preparedReady || castLocked` gate:
 * a FROZEN voter needed an authenticated OPEN status, which requires the
 * transport-bundle-pinned authority, which could not be configured until the
 * ballot was prepared — which itself required OPEN.
 *
 * Configuring or connecting here is lifecycle/transport setup only: it never
 * advances the election lifecycle and never touches selection, proof, ballot,
 * or cast state (those gates live entirely in the Rust backend). Submission
 * controls remain separately gated by {@link managedTorTestCardVisible}.
 */
export function ballotOfficeConnectionVisible(
  input: BallotOfficeConnectionVisibilityInput,
): boolean {
  return input.electionLoaded && input.featurePresent;
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
      title: "Your ballot was accepted ✓",
      detail:
        "The ballot office returned an authenticated receipt for this exact ballot. Your vote is locked for this election.",
    };
  }

  if (castState === "CAST_PENDING") {
    if (busy) {
      return {
        phase: "SUBMITTING",
        tone: "info",
        title: "Sending your encrypted ballot privately…",
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
      title: "Delivery wasn't confirmed",
      detail:
        "Your ballot is safely locked. The ballot office is not reachable yet — this can happen briefly after it restarts its private connection. You can retry this exact encrypted submission; no new ballot will be created.",
    };
  }

  // NOT_CAST: no durable submission exists yet.
  if (busy) {
    return {
      phase: "SUBMITTING",
      tone: "info",
      title: "Sending your encrypted ballot privately…",
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
    title: "Local private connection ready ✓",
    detail:
      "Your local private connection is working. You can submit your ballot privately. If the ballot office recently restarted, its private address may take a short time to become reachable.",
  };
}
