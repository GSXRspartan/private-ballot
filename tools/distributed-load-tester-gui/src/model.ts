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
  terminal_state?: "RUNNING" | "COMPLETE" | "STOPPED" | "FAILED" | null;
  terminalState?: "RUNNING" | "COMPLETE" | "STOPPED" | "FAILED" | null;
}

export function shouldWarnLargeRun(voterCount: number): boolean {
  return voterCount >= LARGE_RUN_WARNING_THRESHOLD;
}

// The run-affecting fields the operator fills in on the Run tab. `count` and
// `startIndex` are the exact-selection levers: the number the operator enters
// here is the number of local voters the backend must submit, and it MUST
// reach the load driver unchanged. Kept as its own shape (rather than inlined
// in App.tsx) so the value flow can be unit-tested across the frontend/backend
// boundary without a DOM.
export interface RunConfigInput {
  manifestPath: string;
  registryPath: string;
  candidatePath: string;
  voterPublicBundlePath: string;
  credentialsDir: string;
  passphrase: string;
  torMode: TorMode;
  torExe: string;
  torSocks: string;
  resultsPath: string;
  choice: string;
  count: number;
  startIndex: number;
}

// The exact camelCase payload the `validate_load_test` / `start_load_test`
// Tauri commands deserialize. `count` and `startIndex` are passed through
// verbatim from `RunConfigInput`; nothing between the operator's entry and this
// payload is allowed to recompute the requested voter count from a selected /
// remaining / detected credential total.
export interface LoadTestRequestPayload {
  manifestPath: string;
  registryPath: string;
  candidatePath: string;
  voterPublicBundlePath: string;
  credentialsDir: string;
  passphrase: string;
  torMode: TorMode;
  torExe: string | null;
  torSocks: string | null;
  resultsPath: string;
  choice: string;
  count: number;
  startIndex: number;
  runId: string;
}

// Builds the Tauri command payload from the operator's run form. Shared by both
// Validate Inputs and Start Load Test so the two calls can never disagree about
// the requested count: the same `count` / `startIndex` the operator entered are
// transmitted verbatim. Only Tor-mode-dependent transport fields are nulled and
// a fresh per-run id is stamped; the selection levers are copied unchanged.
export function buildLoadTestRequest(
  form: RunConfigInput,
  runId: string,
): LoadTestRequestPayload {
  return {
    manifestPath: form.manifestPath,
    registryPath: form.registryPath,
    candidatePath: form.candidatePath,
    voterPublicBundlePath: form.voterPublicBundlePath,
    credentialsDir: form.credentialsDir,
    passphrase: form.passphrase,
    torMode: form.torMode,
    torExe: form.torMode === "managed" ? form.torExe : null,
    torSocks: form.torMode === "manual-socks" ? form.torSocks : null,
    resultsPath: form.resultsPath,
    choice: form.choice,
    count: form.count,
    startIndex: form.startIndex,
    runId,
  };
}

// Frontend-only validation-staleness key. Never sent to the backend and never
// persisted; it only ever compares the current run form to the form that
// passed validation. `count` and `startIndex` are part of the key, so any edit
// to the requested count (or the first-local index, or any other run-affecting
// field) makes the prior validation stale and disables Start until the operator
// re-validates. The per-run id is deliberately NOT part of the run form and so
// never enters this key.
export function runConfigKey(form: RunConfigInput): string {
  return JSON.stringify(form);
}

export function canStartLoadTest(
  runState: RunState,
  validated: boolean,
  resultsPath: string,
): boolean {
  // Durable per-host results evidence is mandatory: Run Test stays disabled
  // until a results JSON destination has been selected, even when every other
  // input has been validated.
  return (
    validated &&
    resultsPath.trim().length > 0 &&
    (runState === "VALIDATED" || runState === "COMPLETE" || runState === "STOPPED" || runState === "FAILED")
  );
}

// Validation staleness is derived by comparing the form snapshot that was
// validated against the CURRENT form. Any field change — including the results
// path — produces a different key, so stale validation can never enable Start.
export function isValidationCurrent(
  validatedKey: string | null,
  currentKey: string,
): boolean {
  return validatedKey !== null && validatedKey === currentKey;
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
