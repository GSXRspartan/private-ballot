/**
 * Framework-free engine for the voter's AUTOMATIC authenticated lifecycle
 * refresh over an ALREADY-RUNNING private connection.
 *
 * Scope and contract (deliberately narrow):
 *
 * - This module only decides WHEN an automatic status check runs (cadence,
 *   jitter, overlap prevention, start/stop/dispose lifecycle). It never talks
 *   to the backend itself: the caller supplies the `tick` implementation,
 *   which MUST be the existing authenticated private-status path
 *   (`fetch_election_status_private` -> Rust verify/monotonic-apply/persist).
 *   All protocol verification stays backend-authoritative; nothing here
 *   parses statements or judges lifecycle transitions.
 * - The engine never starts Tor. Readiness is an input decision made by the
 *   caller (the Vote screen polls only while the managed private connection
 *   is configured AND already running for the loaded election); there is no
 *   clearnet fallback and no reconnect logic anywhere in this file.
 * - A tick that throws is swallowed by the loop (a transient transport hiccup
 *   must neither erase the last authenticated state nor kill polling); the
 *   loop simply tries again at the next scheduled tick.
 * - At most ONE automatic tick is ever in flight: a timer fire while a tick
 *   is still running is counted and SKIPPED, not queued.
 * - `start` is idempotent and `stop`/`dispose` cancel pending timers, so
 *   React StrictMode double-mounts and route remounts can never accumulate
 *   duplicate pollers. A controller disposed by an unmounted tree refuses
 *   all further starts; callers create a fresh instance instead.
 */

/** Conservative base cadence between automatic authenticated status checks.
 * A large voter cohort polling a single ballot office must stay polite;
 * lifecycle changes are rare human actions (open/close/verify/finalize), so
 * tens of seconds of latency is imperceptible next to the manual control. */
export const LIFECYCLE_AUTO_REFRESH_INTERVAL_MS = 20_000;

/** Small deterministic jitter added on top of the base cadence so many voters
 * that connected around the same moment do not re-synchronize into request
 * storms. Deterministic (no randomness) so tests can assert exact schedules. */
export const LIFECYCLE_AUTO_REFRESH_JITTER_MS = 4_000;

const JITTER_STEPS = 4;

export type LifecycleAutoRefreshScheduler = (
  handler: () => void,
  timeoutMs: number,
) => unknown;

export type LifecycleAutoRefreshCanceler = (handle: unknown) => void;

export interface LifecycleAutoRefreshOptions {
  /** One authenticated status check. Must reject/resolve without side effects
   * the engine depends on; failures are contained by the loop. */
  tick: () => Promise<void>;
  intervalMs?: number;
  jitterMs?: number;
  scheduleTimeout?: LifecycleAutoRefreshScheduler;
  cancelTimeout?: LifecycleAutoRefreshCanceler;
}

/** FINALIZED is the terminal lifecycle state: once reached, no newer signed
 * statement can advance the election further, so automatic polling is useless
 * and stops. */
export function isTerminalLifecycleState(
  state: string | null | undefined,
): boolean {
  return state === "FINALIZED";
}

/** Deterministic delay before tick number `tickIndex` (0-based): the base
 * interval plus a jitter step that advances one quarter of `jitterMs` per
 * completed tick and wraps every four ticks. */
export function automaticLifecycleRefreshDelayMs(
  tickIndex: number,
  intervalMs: number = LIFECYCLE_AUTO_REFRESH_INTERVAL_MS,
  jitterMs: number = LIFECYCLE_AUTO_REFRESH_JITTER_MS,
): number {
  const step = Math.max(0, Math.round(jitterMs / JITTER_STEPS));
  return intervalMs + (Math.max(0, tickIndex) % JITTER_STEPS) * step;
}

export class LifecycleAutoRefreshController {
  private readonly tickFn: () => Promise<void>;
  private readonly intervalMs: number;
  private readonly jitterMs: number;
  private readonly scheduleTimeout: LifecycleAutoRefreshScheduler;
  private readonly cancelTimeout: LifecycleAutoRefreshCanceler;

  private active = false;
  private disposed = false;
  private tickInFlight = false;
  /** Incremented on every start/stop so settle handlers from a previous
   * run can never schedule timers into a newer run. */
  private runId = 0;
  private timerHandle: unknown = null;
  private completedTicks = 0;
  private startedRuns = 0;
  private skippedBusyFires = 0;

  constructor(options: LifecycleAutoRefreshOptions) {
    this.tickFn = options.tick;
    this.intervalMs = options.intervalMs ?? LIFECYCLE_AUTO_REFRESH_INTERVAL_MS;
    this.jitterMs = options.jitterMs ?? LIFECYCLE_AUTO_REFRESH_JITTER_MS;
    this.scheduleTimeout =
      options.scheduleTimeout ??
      ((handler, timeoutMs) => globalThis.setTimeout(handler, timeoutMs));
    this.cancelTimeout =
      options.cancelTimeout ?? ((handle) => globalThis.clearTimeout(handle as number));
  }

  /** True while the controller is started (polling loop armed). */
  get running(): boolean {
    return this.active;
  }

  /** True while exactly one tick is executing. */
  get busy(): boolean {
    return this.tickInFlight;
  }

  /** Disposed controllers are permanently inert (their owning tree unmounted);
   * callers must construct a fresh instance to poll again. */
  isDisposed(): boolean {
    return this.disposed;
  }

  /** Observability counters for behavior tests. */
  get stats(): { ranTicks: number; skippedBusyFires: number; startedRuns: number } {
    return {
      ranTicks: this.completedTicks,
      skippedBusyFires: this.skippedBusyFires,
      startedRuns: this.startedRuns,
    };
  }

  /** Arms the polling loop. Idempotent: calling start while already running
   * never creates a second timer chain (StrictMode safety). `immediate`
   * performs the first check right away — used when the caller observes that
   * the private connection just became ready. */
  start(immediate = false): void {
    if (this.disposed || this.active) return;
    this.active = true;
    const run = ++this.runId;
    this.startedRuns += 1;
    this.schedule(run, immediate ? 0 : this.delayFor(this.completedTicks));
  }

  /** Disarms the loop and cancels any pending timer. An already-executing
   * tick cannot be aborted (it is a backend command), but its settle handler
   * is invalidated via the run id, so it schedules nothing further. */
  stop(): void {
    if (!this.active && this.timerHandle === null) {
      // Still bump the run id: a stop after a stop must also invalidate any
      // in-flight tick from a previous run.
      this.runId += 1;
      return;
    }
    this.active = false;
    this.runId += 1;
    this.cancelTimer();
  }

  /** Permanent stop for unmount/app shutdown. Refuses every future start. */
  dispose(): void {
    this.stop();
    this.disposed = true;
  }

  private delayFor(tickIndex: number): number {
    return automaticLifecycleRefreshDelayMs(
      tickIndex,
      this.intervalMs,
      this.jitterMs,
    );
  }

  private cancelTimer(): void {
    if (this.timerHandle !== null) {
      this.cancelTimeout(this.timerHandle);
      this.timerHandle = null;
    }
  }

  private schedule(run: number, delayMs: number): void {
    this.cancelTimer();
    this.timerHandle = this.scheduleTimeout(() => this.fire(run), delayMs);
  }

  private fire(run: number): void {
    this.timerHandle = null;
    if (!this.active || run !== this.runId || this.disposed) return;
    // Never allow overlapping status requests: a fire landing while a tick
    // is still running is counted and SKIPPED, not queued.
    if (this.tickInFlight) {
      this.skippedBusyFires += 1;
      this.schedule(run, this.delayFor(this.completedTicks));
      return;
    }
    // Fixed-cadence heartbeat: the next slot is armed IMMEDIATELY so a slow
    // backend response cannot stretch or stall the cadence; any fire landing
    // while this request is still running hits the skip branch above.
    this.schedule(run, this.delayFor(this.completedTicks));
    this.tickInFlight = true;
    void Promise.resolve()
      .then(() => this.tickFn())
      .catch(() => {
        // Transient failure: contained here so the loop survives and the
        // caller's last authenticated state is untouched.
      })
      .then(() => {
        this.tickInFlight = false;
        if (run !== this.runId || this.disposed) return;
        this.completedTicks += 1;
      });
  }
}
