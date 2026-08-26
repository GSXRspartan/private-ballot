/**
 * Backend-authoritative decision helpers for the voter's AUTOMATIC lifecycle
 * poll (the tick side of `lifecycleAutoRefresh.ts`).
 *
 * The authenticated backend path (`fetch_election_status_private`) remains the
 * ONLY authority: it verifies the signed statement against the pinned
 * ballot-office anchor and THIS election's identity, applies it monotonically
 * (fail-closed), persists it, and reports what it did via
 * `AppliedElectionStatusResultV1`. These helpers add NO second protocol and NO
 * frontend-trusted lifecycle state; they only interpret that authoritative
 * answer so a poll that did NOT advance authenticated knowledge can skip every
 * broad presentation refresh (election summary re-read, workflow
 * reconstruction) and stay invisible on screen.
 */

import type { AppliedElectionStatusResultV1 } from "./api/types";

/** Whether one applied-status result differs from what the status card last
 * painted. A no-op poll re-answers with identical content; painting it again
 * would be a needless render churn, so the caller keeps the previous object. */
export function appliedStatusDiffersFromPainted(
  prev: AppliedElectionStatusResultV1 | null,
  next: AppliedElectionStatusResultV1,
): boolean {
  return (
    prev === null ||
    prev.effective_state !== next.effective_state ||
    prev.advanced !== next.advanced ||
    prev.generation !== next.generation
  );
}

/**
 * Whether one authenticated application actually moved this election's
 * lifecycle forward relative to what the screen currently mirrors.
 *
 * `applied.advanced` is the backend's own idempotence verdict (false for an
 * exact re-application). The `paintedLifecycleState` comparison is defense in
 * depth: if the backend session ever sits at a state the screen has not yet
 * mirrored (e.g. an apply succeeded but a previous refresh was lost), the next
 * poll still triggers exactly one healing refresh even though `advanced` was
 * false. Both inputs come from the backend; nothing here decides lifecycle
 * truth on its own.
 */
export function authenticatedLifecycleAdvanced(
  applied: AppliedElectionStatusResultV1,
  paintedLifecycleState: string,
): boolean {
  return applied.advanced || applied.effective_state !== paintedLifecycleState;
}
