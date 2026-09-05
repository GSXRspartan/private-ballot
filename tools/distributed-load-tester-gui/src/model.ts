export const LARGE_RUN_WARNING_THRESHOLD = 100;
export const DEFAULT_TOR_SOCKS = "127.0.0.1:9050";

// Managed Tor is the normal workflow: the GUI owns Tor's lifecycle for the
// run, and the operator only picks the Tor executable. Manual SOCKS is the
// advanced fallback for hosts already running a local Tor listener — used
// for developer debugging and the earlier CLI/PowerShell physical topology.
export type TorMode = "managed" | "manual-socks";

// Backend-facing Tor readiness pill state. Reused for both Test Tor and the
// runtime Tor status surface so the run flow always presents the same
// vocabulary the operator saw during setup.
export type TorStatus =
  | "NOT_SELECTED"
  | "SELECTED"
  | "VALIDATING"
  | "READY"
  | "INVALID"
  | "TESTING"
  | "TESTED_READY"
  | "TEST_FAILED";

// A successful release means the ballot was delivered and its transport receipt
// verified locally. It does NOT mean the organizer application has accepted the
// ballot or counted it in the final tally, which must be confirmed separately.
export const VOTES_DELIVERED_LABEL = "Votes delivered (receipt verified)";

export type RunState =
  | "IDLE"
  | "VALIDATED"
  | "RUNNING"
  | "STOPPING"
  | "COMPLETE"
  | "STOPPED"
  | "FAILED";

export interface LoadProgress {
  total_voters?: number;
  totalVoters?: number;
  completed_voters?: number;
  completedVoters?: number;
  accepted: number;
  rejected: number;
  failed: number;
  remaining: number;
  current_credential_file?: string | null;
  currentCredentialFile?: string | null;
  elapsed_ms?: number;
  elapsedMs?: number;
  average_ms_per_completed_voter?: number;
  averageMsPerCompletedVoter?: number;
  estimated_remaining_ms?: number | null;
  estimatedRemainingMs?: number | null;
  terminal_state?: "COMPLETE" | "STOPPED" | "FAILED" | null;
  terminalState?: "COMPLETE" | "STOPPED" | "FAILED" | null;
}

export function shouldWarnLargeRun(voterCount: number): boolean {
  return voterCount >= LARGE_RUN_WARNING_THRESHOLD;
}

export function canStartLoadTest(runState: RunState, validated: boolean): boolean {
  return validated && (runState === "VALIDATED" || runState === "COMPLETE" || runState === "STOPPED" || runState === "FAILED");
}

// A stop request is cooperative: the in-flight voter is allowed to finish before
// the run terminates. Until the backend emits its terminal STOPPED (or COMPLETE)
// event, the UI shows a transient STOPPING state. A stop request only advances a
// RUNNING run; every other state is returned unchanged so repeated clicks (or a
// late click after the run already ended) cannot create a race.
export function nextStateAfterStopRequest(runState: RunState): RunState {
  return runState === "RUNNING" ? "STOPPING" : runState;
}

export function isStopping(runState: RunState): boolean {
  return runState === "STOPPING";
}

// A rejected Start (or Stop) request can leave the UI mid-run. Recover to the
// terminal, recoverable FAILED state — which re-enables Start — but only from an
// in-flight state. Every other state is returned unchanged so a late rejection
// cannot clobber an already-terminal outcome (COMPLETE/STOPPED) reported by the
// backend's progress event.
export function stateAfterFailedAction(runState: RunState): RunState {
  return runState === "RUNNING" || runState === "STOPPING" ? "FAILED" : runState;
}

// The Stop control is actionable only while a run is actively RUNNING; once a
// stop has been requested (STOPPING) it stays disabled until the terminal event.
export function canStopRun(runState: RunState): boolean {
  return runState === "RUNNING";
}

export function passphraseMismatch(passphrase: string, confirmation: string): boolean {
  return passphrase.length > 0 && confirmation.length > 0 && passphrase !== confirmation;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) {
    return "n/a";
  }
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  const seconds = Math.round(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const rem = seconds % 60;
  return minutes > 0 ? `${minutes}m ${rem}s` : `${seconds}s`;
}

export function progressTotal(progress: LoadProgress | null): number {
  return progress?.total_voters ?? progress?.totalVoters ?? 0;
}

export function progressCompleted(progress: LoadProgress | null): number {
  return progress?.completed_voters ?? progress?.completedVoters ?? 0;
}

export function progressElapsed(progress: LoadProgress | null): number {
  return progress?.elapsed_ms ?? progress?.elapsedMs ?? 0;
}

export function secretFreeProgressText(progress: LoadProgress): string {
  const current = progress.current_credential_file ?? progress.currentCredentialFile ?? "between voters";
  return `${progressCompleted(progress)} of ${progressTotal(progress)} completed; current ${current}`;
}

// Managed Tor cannot Start Load Test until the executable has passed the
// backend validator (READY or TESTED_READY). Manual SOCKS mode has no
// separate Tor validation surface; the endpoint is validated together with
// the other inputs, so any non-empty status is acceptable.
export function isTorReadyForRun(mode: TorMode, status: TorStatus): boolean {
  if (mode === "managed") {
    return status === "READY" || status === "TESTED_READY";
  }
  return true;
}

// The short pill label the header displays. Kept in one place so a wording
// change never drifts between the setup surface and the running surface.
export function torStatusLabel(status: TorStatus): string {
  switch (status) {
    case "NOT_SELECTED": return "Not selected";
    case "SELECTED": return "Selected";
    case "VALIDATING": return "Validating";
    case "READY": return "Ready ✓";
    case "INVALID": return "Invalid";
    case "TESTING": return "Testing Tor";
    case "TESTED_READY": return "Tor ready ✓";
    case "TEST_FAILED": return "Tor error";
  }
}
