import { open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useMemo, useState } from "react";

import { BackendError, call } from "./api";
import {
  DEFAULT_TOR_SOCKS,
  LoadProgress,
  RunState,
  TorMode,
  TorStatus,
  VOTES_DELIVERED_LABEL,
  buildLoadTestRequest,
  canStartLoadTest,
  canStopRun,
  formatDuration,
  isStopping,
  isTorReadyForRun,
  isValidationCurrent,
  nextStateAfterStopRequest,
  passphraseMismatch,
  runConfigKey,
  progressCompleted,
  progressElapsed,
  progressTotal,
  secretFreeProgressText,
  shouldWarnLargeRun,
  stateAfterFailedAction,
  torStatusLabel,
} from "./model";

type Tab = "cohort" | "partition" | "run" | "results";

interface ShellInfo {
  maxRegistryMembers: number;
  largeRunWarningThreshold: number;
  defaultTorSocks: string;
  concurrency: number;
}

interface CohortForm {
  voterCount: number;
  outputDir: string;
  passphrase: string;
  confirmPassphrase: string;
}

interface PartitionForm {
  credentialsDir: string;
  startIndex: number;
  voterCount: number;
  outputDir: string;
}

interface RunForm {
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

interface SummaryLine {
  label: string;
  value: string | number;
}

interface ChecklistItem {
  label: string;
  checked: boolean;
  detail?: string;
}

interface TorExecutableStatus {
  accepted: boolean;
  executableBasename?: string | null;
  version?: string | null;
}

interface TestTorResult {
  torReady: boolean;
  version?: string | null;
  socksAddr: string;
  startedUtc: string;
  stoppedUtc: string;
  executableBasename?: string | null;
  stoppedByRunner: boolean;
}

interface TorStatusEvent {
  stage: "STARTING_TOR" | "TOR_READY" | "STOPPING_TOR";
  socksAddr?: string | null;
}

const tabs: Array<{ id: Tab; label: string; shortLabel: string }> = [
  { id: "cohort", label: "CREATE TEST VOTERS", shortLabel: "VOTERS" },
  { id: "partition", label: "SPLIT VOTERS", shortLabel: "SPLIT" },
  { id: "run", label: "RUN TEST", shortLabel: "RUN" },
  { id: "results", label: "RESULTS", shortLabel: "RESULTS" },
];

const initialCohort: CohortForm = {
  voterCount: 10,
  outputDir: "",
  passphrase: "",
  confirmPassphrase: "",
};

const initialPartition: PartitionForm = {
  credentialsDir: "",
  startIndex: 1,
  voterCount: 10,
  outputDir: "",
};

const initialRun: RunForm = {
  manifestPath: "",
  registryPath: "",
  candidatePath: "",
  voterPublicBundlePath: "",
  credentialsDir: "",
  passphrase: "",
  torMode: "managed",
  torExe: "",
  torSocks: DEFAULT_TOR_SOCKS,
  resultsPath: "",
  choice: "round-robin",
  count: 1,
  startIndex: 1,
};

export default function App() {
  const [tab, setTab] = useState<Tab>("cohort");
  const [shellInfo, setShellInfo] = useState<ShellInfo | null>(null);
  const [cohort, setCohort] = useState<CohortForm>(initialCohort);
  const [partition, setPartition] = useState<PartitionForm>(initialPartition);
  const [run, setRun] = useState<RunForm>(initialRun);
  const [partitionDetected, setPartitionDetected] = useState(0);
  const [runState, setRunState] = useState<RunState>("IDLE");
  const [validatedKey, setValidatedKey] = useState<string | null>(null);
  const [progress, setProgress] = useState<LoadProgress | null>(null);
  const [resultsPath, setResultsPath] = useState("");
  const [summary, setSummary] = useState<SummaryLine[]>([]);
  const [error, setError] = useState("");
  const [loadWarning, setLoadWarning] = useState("");
  const [busy, setBusy] = useState(false);
  const [torStatus, setTorStatus] = useState<TorStatus>("NOT_SELECTED");
  const [torDetail, setTorDetail] = useState<string>("");
  const [torRuntime, setTorRuntime] = useState<TorStatusEvent | null>(null);
  const partitionLastVoter = partition.startIndex + partition.voterCount - 1;

  useEffect(() => {
    call<ShellInfo>("shell_info")
      .then((info) => {
        setShellInfo(info);
        setRun((current) => ({ ...current, torSocks: info.defaultTorSocks }));
      })
      .catch((err: BackendError) => setError(err.message));
  }, []);

  useEffect(() => {
    let unlisten: VoidFunction | null = null;
    void listen<LoadProgress>("load-progress", (event) => {
      setProgress(event.payload);
      const terminal = event.payload.terminal_state ?? event.payload.terminalState;
      if (terminal === "COMPLETE" || terminal === "STOPPED" || terminal === "FAILED") {
        setRunState(terminal);
      }
    }).then((dispose) => {
      unlisten = dispose;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    let unlisten: VoidFunction | null = null;
    void listen<TorStatusEvent>("load-status", (event) => {
      setTorRuntime(event.payload);
    }).then((dispose) => {
      unlisten = dispose;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    let unlisten: VoidFunction | null = null;
    void listen<string>("load-warning", (event) => {
      setLoadWarning(event.payload);
    }).then((dispose) => {
      unlisten = dispose;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const largeRun = useMemo(
    () => shouldWarnLargeRun(cohort.voterCount) || shouldWarnLargeRun(run.count),
    [cohort.voterCount, run.count],
  );

  async function chooseDirectory(onPick: (path: string) => void) {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked === "string") {
      onPick(picked);
    }
  }

  async function chooseFile(onPick: (path: string) => void) {
    const picked = await open({ directory: false, multiple: false });
    if (typeof picked === "string") {
      onPick(picked);
    }
  }

  async function chooseSavePath(onPick: (path: string) => void) {
    const picked = await save({ defaultPath: "distributed-load-results.json" });
    if (typeof picked === "string") {
      onPick(picked);
    }
  }

  async function runAction(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : "operation failed");
      setRunState((current) => stateAfterFailedAction(current));
    } finally {
      setBusy(false);
    }
  }

  function setResultSummary(lines: SummaryLine[], path = "") {
    setSummary(lines);
    if (path) {
      setResultsPath(path);
    }
    setTab("results");
  }

  function updateRun(next: Partial<RunForm>) {
    setRun((current) => ({ ...current, ...next }));
  }

  function updateTorMode(mode: TorMode) {
    setTorStatus(mode === "managed" && run.torExe ? "SELECTED" : "NOT_SELECTED");
    setTorDetail("");
    setRun((current) => ({ ...current, torMode: mode }));
  }

  const generateCohort = () =>
    runAction(async () => {
      const result = await call<Record<string, string | number>>("generate_cohort", {
        request: {
          voterCount: cohort.voterCount,
          outputDir: cohort.outputDir,
          passphrase: cohort.passphrase,
          confirmPassphrase: cohort.confirmPassphrase,
        },
      });
      setCohort((current) => ({ ...current, passphrase: "", confirmPassphrase: "" }));
      setResultSummary([
        { label: "Credentials generated", value: result.credentialsGenerated as number },
        { label: "Registry members", value: result.registryMembers as number },
        { label: "Organizer registry", value: result.organizerRegistry as string },
        { label: "Voter credentials", value: result.votersDir as string },
        { label: "Elapsed", value: formatDuration(result.elapsedMs as number) },
      ]);
    });

  const detectCredentials = () =>
    runAction(async () => {
      const result = await call<{ credentialsDetected: number }>("detect_partition_credentials", {
        credentialsDir: partition.credentialsDir,
      });
      setPartitionDetected(result.credentialsDetected);
    });

  const createPartition = () =>
    runAction(async () => {
      const result = await call<Record<string, string | number>>("create_partition", {
        request: {
          credentialsDir: partition.credentialsDir,
          startIndex: partition.startIndex,
          voterCount: partition.voterCount,
          outputDir: partition.outputDir,
        },
      });
      setResultSummary([
        { label: "Credentials detected", value: result.credentialsDetected as number },
        { label: "Credentials copied", value: result.credentialsCopied as number },
        { label: "First voter", value: result.firstVoter as number },
        { label: "Last voter", value: result.lastVoter as number },
        { label: "Destination", value: result.destination as string },
      ]);
    });

  async function selectTorExecutable() {
    const picked = await open({ directory: false, multiple: false });
    if (typeof picked !== "string") {
      return;
    }
    setRun((current) => ({ ...current, torExe: picked }));
    setTorStatus("VALIDATING");
    setTorDetail("");
    try {
      const status = await call<TorExecutableStatus>("validate_tor_executable", { request: { torExe: picked } });
      if (status.accepted) {
        setTorStatus("READY");
        setTorDetail(status.executableBasename ? `Selected ${status.executableBasename}.` : "Selected.");
      } else {
        setTorStatus("INVALID");
        setTorDetail("Executable was not accepted.");
      }
    } catch (err) {
      setTorStatus("INVALID");
      setTorDetail(err instanceof Error ? err.message : "Executable validation failed.");
    }
  }

  const testTor = () =>
    runAction(async () => {
      if (!run.torExe) {
        return;
      }
      setTorStatus("TESTING");
      setTorDetail("");
      try {
        const result = await call<TestTorResult>("test_tor", { request: { torExe: run.torExe } });
        setTorStatus("TESTED_READY");
        const version = result.version ? ` (${result.version})` : "";
        setTorDetail(`Bootstrap succeeded on ${result.socksAddr}${version}. Tor was stopped and reaped after the test.`);
      } catch (err) {
        setTorStatus("TEST_FAILED");
        setTorDetail(err instanceof Error ? err.message : "Test Tor failed.");
        throw err;
      }
    });

  const validateRun = () =>
    runAction(async () => {
      const result = await call<Record<string, string | number>>("validate_load_test", {
        request: runRequest(),
      });
      // Validation is pinned to the exact form snapshot that passed; any later
      // edit (including the results path) invalidates it via key comparison.
      setValidatedKey(runFormKey(run));
      setRunState("VALIDATED");
      setResultSummary([
        { label: "Test voter credentials detected", value: (result.credentialCount ?? result.credential_count) as number },
        { label: "Voters this computer will submit", value: (result.requestedVoterCount ?? result.requested_voter_count) as number },
        { label: "Credentials selected for this run", value: (result.selectedVoterCount ?? result.selected_voter_count) as number },
        { label: "First local credential", value: (result.startIndex ?? result.start_index) as number },
        { label: "Tor mode", value: run.torMode === "managed" ? "Managed" : "Advanced — existing local SOCKS" },
        { label: "Candidate rotation", value: result.choice === "round-robin" ? "Rotate evenly through candidates" : (result.choice as string) },
      ]);
      setTab("run");
    });

  const startRun = () =>
    runAction(async () => {
      setRunState("RUNNING");
      setProgress(null);
      setLoadWarning("");
      setTorRuntime({ stage: "STARTING_TOR" });
      const report = await call<Record<string, string | number>>("start_load_test", {
        request: runRequest(),
      });
      setRun((current) => ({ ...current, passphrase: "" }));
      const terminal = String(report.terminal_state ?? report.terminalState ?? "COMPLETE") as RunState;
      setRunState(terminal);
      setResultSummary(
        [
          { label: "State", value: terminal },
          { label: "Votes attempted", value: report.completed_voters ?? report.completedVoters ?? 0 },
          { label: VOTES_DELIVERED_LABEL, value: report.successful_submissions ?? report.successfulSubmissions ?? 0 },
          { label: "Receipts rejected", value: report.receipt_verification_failures ?? report.receiptVerificationFailures ?? 0 },
          { label: "Submission failures", value: report.failed_submissions ?? report.failedSubmissions ?? 0 },
          { label: "Voters remaining", value: report.remaining_voters ?? report.remainingVoters ?? 0 },
          { label: "Elapsed", value: formatDuration(Number(report.elapsed_ms ?? report.elapsedMs ?? 0)) },
        ],
        run.resultsPath,
      );
    });

  const stopAfterCurrent = () =>
    runAction(async () => {
      setRunState((current) => nextStateAfterStopRequest(current));
      await call<void>("stop_after_current_voter");
    });

  // Both Validate Inputs and Start Load Test build their payload here, so the
  // requested count/start index the operator entered are transmitted verbatim
  // and identically by both calls — the count can never be recomputed or
  // reinterpreted between validate and start.
  function runRequest() {
    return buildLoadTestRequest(run, `gui-${Date.now()}`);
  }

  // Frontend-only snapshot key for validation staleness. Never sent to the
  // backend and never persisted; it only ever compares form state to the form
  // state that passed validation.
  function runFormKey(form: RunForm): string {
    return runConfigKey(form);
  }

  const validated = isValidationCurrent(validatedKey, runFormKey(run));
  const torReady = isTorReadyForRun(run.torMode, torStatus);

  const readiness: ChecklistItem[] = [
    readinessItem("Election setup file loaded", run.manifestPath, validated, "election-manifest.cbor"),
    readinessItem("Eligible voter list loaded", run.registryPath, validated, "voter-registry.cbor"),
    readinessItem("Candidate list loaded", run.candidatePath, validated, "candidate-set.cbor"),
    readinessItem("Election public keys loaded", run.voterPublicBundlePath, validated, "voter-public-bundle.cbor"),
    readinessItem("Test voter credentials detected", run.credentialsDir, validated),
    {
      label: "Credential password provided or validated as appropriate",
      checked: validated || run.passphrase.length > 0,
      detail: validated ? "Checked by validation." : run.passphrase.length > 0 ? "Password provided." : "Password is required before validation.",
    },
    {
      label: run.torMode === "managed" ? "Tor executable ready" : "Tor SOCKS endpoint valid",
      checked: torReady && (validated || run.torMode === "manual-socks"),
      detail: torDetail || (torReady ? "Selected." : "Required before Run Test."),
    },
    {
      label: "Results output selected",
      checked: run.resultsPath.length > 0,
      detail: run.resultsPath ? "Selected." : "Choose where to save the JSON report.",
    },
  ];

  const canStart = canStartLoadTest(runState, validated, run.resultsPath) && torReady;

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <div className="eyebrow">LOAD TEST TOOL</div>
          <h1>Private Ballot Load Tester</h1>
          <p>For test elections only. This is not the normal voter application.</p>
        </div>
        <div className="statusBox">
          <strong>Sequential safety mode</strong>
          <span>Concurrency: {shellInfo?.concurrency ?? 1}</span>
          <span>Tor: {run.torMode === "managed" ? "Managed" : "Advanced SOCKS"}</span>
          <span>Status: {torStatusLabel(torStatus)}</span>
        </div>
      </header>

      <section className="workflow">
        <ol>
          <li>Create simulated voters</li>
          <li>Split them between test computers</li>
          <li>Load the election files, pick a Tor executable, and submit votes</li>
          <li>Review the results</li>
        </ol>
      </section>

      <details className="helpBox">
        <summary>HOW TO USE THIS TOOL</summary>
        <div className="helpContent">
          <h2>Quick Start</h2>
          <ol>
            <li><strong>Create Test Voters</strong> Choose how many simulated voters you want, select a folder, create a credential password, then click Create Test Voters.</li>
            <li><strong>Split Voters Between Computers</strong> Select the folder containing the test voters. Choose which voter numbers belong on this computer and copy them into a separate folder. Example: Computer B could receive voters 1 through 5. A VPS could receive voters 6 through 10.</li>
            <li><strong>Run the Test</strong> On each test computer, select the election setup file, eligible voter list, candidate list, election public keys, that computer's test voter folder, credential password, results output location, and a Tor executable. The tester starts one local managed Tor process for that computer and submits votes sequentially using the real ballot submission path.</li>
            <li><strong>Review Results</strong> The Results page reports what this local tester attempted and completed. The organizer application is checked separately to confirm accepted ballots and the final tally.</li>
          </ol>
          <p className="warningText">Test voter credentials are private. Only copy each computer's assigned voter group to that computer. These simulated voters do not represent separate people, devices, or independent Tor users.</p>
        </div>
      </details>

      {largeRun && (
        <section className="notice warn">
          Every simulated voter has a unique credential and generates a real Triptych proof. Large registry tiers can require significant CPU time, and Tor submission adds wall-clock time. Protocol registry limit: {shellInfo?.maxRegistryMembers ?? 4096} members.
        </section>
      )}
      {error && <section className="notice error">{error}</section>}

      <nav className="tabs" aria-label="Load tester workflow">
        {tabs.map((item) => (
          <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}>
            <span className="tabFull">{item.label}</span>
            <span className="tabShort">{item.shortLabel}</span>
          </button>
        ))}
      </nav>

      {tab === "cohort" && (
        <section className="panel">
          <h2>Create Test Voters</h2>
          <p>Start here. This creates the simulated voter credentials used by the test.</p>
          <p>Creates unique simulated voter credentials using the real ballot credential format.</p>
          <div className="grid">
            <NumberField label="How many simulated voters?" value={cohort.voterCount} onChange={(v) => setCohort({ ...cohort, voterCount: v })} />
            <PathField label="Save test voters here" value={cohort.outputDir} onPick={() => chooseDirectory((v) => setCohort({ ...cohort, outputDir: v }))} />
            <PasswordField label="Credential password" value={cohort.passphrase} onChange={(v) => setCohort({ ...cohort, passphrase: v })} />
            <PasswordField label="Confirm password" value={cohort.confirmPassphrase} onChange={(v) => setCohort({ ...cohort, confirmPassphrase: v })} />
          </div>
          {passphraseMismatch(cohort.passphrase, cohort.confirmPassphrase) && <p className="fieldError">Password confirmation does not match.</p>}
          <button className="primary" disabled={busy || passphraseMismatch(cohort.passphrase, cohort.confirmPassphrase)} onClick={generateCohort}>
            Create {cohort.voterCount} Test Voters
          </button>
        </section>
      )}

      {tab === "partition" && (
        <section className="panel">
          <h2>Split Test Voters</h2>
          <p>Use this after creating voters to divide them between test computers.</p>
          <div className="grid">
            <PathField label="Folder containing all test voters" value={partition.credentialsDir} onPick={() => chooseDirectory((v) => setPartition({ ...partition, credentialsDir: v }))} />
            <NumberField label="First voter to copy" value={partition.startIndex} onChange={(v) => setPartition({ ...partition, startIndex: v })} />
            <NumberField label="How many voters?" value={partition.voterCount} onChange={(v) => setPartition({ ...partition, voterCount: v })} />
            <PathField label="Copy selected voters to" value={partition.outputDir} onPick={() => chooseDirectory((v) => setPartition({ ...partition, outputDir: v }))} />
          </div>
          <div className="previewBox">
            <strong>Voters {partition.startIndex} through {partitionLastVoter}</strong>
            <span>{partition.voterCount} voters total</span>
          </div>
          <div className="buttonRow">
            <button onClick={detectCredentials} disabled={busy}>Check Voters</button>
            <button className="primary" onClick={createPartition} disabled={busy}>Create Voter Group</button>
            <span>{partitionDetected} credentials detected</span>
          </div>
        </section>
      )}

      {tab === "run" && (
        <section className="panel">
          <h2>Run Test</h2>
          <p>Use this on each test computer after its voter group and public election files have been copied over.</p>
          <section className="notice">
            Votes are submitted one at a time. All simulated voters on this computer share this Tor instance. This test does not simulate independent Tor users.
          </section>
          <section className="notice">
            "First local credential" counts within THIS computer's credential folder: 1 is the first credential file it contains. A folder copied from global voters 251–500 runs as local voters 1–250. The organizer still sees the correct global voters.
          </section>
          <div className="grid">
            <PathField label="Election setup file" help="Expected filename: election-manifest.cbor" value={run.manifestPath} onPick={() => chooseFile((v) => updateRun({ manifestPath: v }))} />
            <PathField label="Eligible voter list" help="Expected filename: voter-registry.cbor" value={run.registryPath} onPick={() => chooseFile((v) => updateRun({ registryPath: v }))} />
            <PathField label="Candidate list" help="Expected filename: candidate-set.cbor" value={run.candidatePath} onPick={() => chooseFile((v) => updateRun({ candidatePath: v }))} />
            <PathField label="Election public keys" help="Expected filename: voter-public-bundle.cbor" value={run.voterPublicBundlePath} onPick={() => chooseFile((v) => updateRun({ voterPublicBundlePath: v }))} />
            <PathField label="This computer's test voter folder" help="Contains this computer's assigned credential files." value={run.credentialsDir} onPick={() => chooseDirectory((v) => updateRun({ credentialsDir: v }))} />
            <PathField label="Save test results as" help="Writes the same Results JSON file used by the backend." value={run.resultsPath} onPick={() => chooseSavePath((v) => updateRun({ resultsPath: v }))} />
            <PasswordField label="Credential password" value={run.passphrase} onChange={(v) => updateRun({ passphrase: v })} />
            <ReadOnlyField label="Choice strategy" value="Rotate evenly through candidates" help="Backend value: round-robin" />
            <NumberField label="How many voters should this computer submit?" value={run.count} onChange={(v) => updateRun({ count: v })} />
            <NumberField label="First local credential to submit (1 = first file in this folder)" value={run.startIndex} onChange={(v) => updateRun({ startIndex: v })} />
          </div>

          <section className="torPanel">
            <h2>Tor</h2>
            <p>
              This computer needs a local Tor process to submit votes. Pick the Tor executable and the load tester will start
              and stop Tor automatically each time Run Test runs. Advanced operators can point at a Tor SOCKS listener that
              is already running.
            </p>
            <div className="torModeRow" role="radiogroup" aria-label="Tor mode">
              <label className={`torModeChoice ${run.torMode === "managed" ? "active" : ""}`}>
                <input type="radio" name="torMode" value="managed" checked={run.torMode === "managed"} onChange={() => updateTorMode("managed")} />
                <span><strong>Managed Tor executable</strong><small>Normal — Run Test starts and stops Tor for you.</small></span>
              </label>
              <label className={`torModeChoice ${run.torMode === "manual-socks" ? "active" : ""}`}>
                <input type="radio" name="torMode" value="manual-socks" checked={run.torMode === "manual-socks"} onChange={() => updateTorMode("manual-socks")} />
                <span><strong>Advanced — use existing SOCKS</strong><small>Developer/debug only.</small></span>
              </label>
            </div>

            {run.torMode === "managed" && (
              <div className="grid">
                <PathField label="Tor executable" help="Absolute path (no symlinks or reparse points). Tor is never downloaded, installed, or found on your PATH." value={run.torExe} onPick={selectTorExecutable} />
              </div>
            )}
            {run.torMode === "manual-socks" && (
              <div className="grid">
                <TextField label="Tor SOCKS endpoint" value={run.torSocks} onChange={(v) => updateRun({ torSocks: v })} />
              </div>
            )}

            <div className="torStatusRow">
              <span className={`torPill status-${torStatus}`}>{torStatusLabel(torStatus)}</span>
              {torDetail && <small className="torDetail">{torDetail}</small>}
              {run.torMode === "managed" && (
                <button className="small" onClick={testTor} disabled={busy || !run.torExe || runState === "RUNNING" || isStopping(runState)}>
                  Test Tor
                </button>
              )}
            </div>
          </section>

          <ReadinessChecklist items={readiness} />

          <div className="buttonRow">
            <button onClick={validateRun} disabled={busy || runState === "RUNNING" || isStopping(runState) || run.passphrase.length === 0}>Validate Inputs</button>
            <button className="primary" onClick={startRun} disabled={busy || !canStart}>Start Load Test</button>
            <button onClick={stopAfterCurrent} disabled={!canStopRun(runState)}>Stop After Current Voter</button>
          </div>
          {isStopping(runState) && (
            <section className="notice warn">
              Stopping after current voter… The voter currently generating or submitting is allowed to finish safely. The run ends when the backend confirms it stopped.
            </section>
          )}
          {loadWarning && <section className="notice warn">{loadWarning}</section>}
          {torRuntime && runState === "RUNNING" && (
            <section className="notice">
              {torRuntime.stage === "STARTING_TOR" && "Starting Tor…"}
              {torRuntime.stage === "TOR_READY" && `Tor ready ✓ on ${torRuntime.socksAddr ?? "loopback SOCKS"}.`}
              {torRuntime.stage === "STOPPING_TOR" && "Stopping Tor…"}
            </section>
          )}
          {progress && <ProgressView progress={progress} />}
        </section>
      )}

      {tab === "results" && (
        <section className="panel">
          <h2>Results</h2>
          <p>Shows the progress and outcome of tests run on this computer.</p>
          {summary.length === 0 ? (
            <p>No test results yet.</p>
          ) : (
            <dl className="summary">
              {summary.map((line) => (
                <div key={line.label}>
                  <dt>{line.label}</dt>
                  <dd>{line.value}</dd>
                </div>
              ))}
            </dl>
          )}
          {resultsPath && <p className="resultPath">Results JSON: {resultsPath}</p>}
        </section>
      )}
    </main>
  );
}

function readinessItem(label: string, value: string, validated: boolean, expectedFilename?: string): ChecklistItem {
  if (validated) {
    return { label, checked: true, detail: "Checked by validation." };
  }
  if (value) {
    return { label, checked: false, detail: expectedFilename ? `Selected; expected filename: ${expectedFilename}` : "Selected; will be checked by validation." };
  }
  return { label, checked: false, detail: expectedFilename ? `Expected filename: ${expectedFilename}` : "Required before validation." };
}

function TextField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} onChange={(event) => onChange(event.currentTarget.value)} />
    </label>
  );
}

function PasswordField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input type="password" value={value} onChange={(event) => onChange(event.currentTarget.value)} autoComplete="off" />
    </label>
  );
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type="number"
        min={1}
        value={value}
        // A focused <input type="number"> silently steps its value when the
        // wheel scrolls over it or Up/Down is pressed. On a long form these are
        // both easy to trigger by accident while scrolling to the next control
        // — an incidental scroll can turn an entered 100 into 89 with no visible
        // edit. These are run-affecting counts (requested voter count, first
        // local credential), so both accidental stepping vectors are neutralised:
        // the wheel drops focus instead of changing the value, and vertical
        // arrows are ignored. Typing (the intended entry path) is unaffected.
        onWheel={(event) => event.currentTarget.blur()}
        onKeyDown={(event) => {
          if (event.key === "ArrowUp" || event.key === "ArrowDown") {
            event.preventDefault();
          }
        }}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </label>
  );
}

function ReadOnlyField({ label, value, help }: { label: string; value: string; help?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input value={value} readOnly />
      {help && <small>{help}</small>}
    </label>
  );
}

function PathField({ label, value, onPick, help }: { label: string; value: string; onPick: () => void; help?: string }) {
  return (
    <label className="field pathField">
      <span>{label}</span>
      <div>
        <input value={value} readOnly />
        <button type="button" onClick={onPick}>Browse</button>
      </div>
      {help && <small>{help}</small>}
    </label>
  );
}

function ReadinessChecklist({ items }: { items: ChecklistItem[] }) {
  return (
    <section className="checklist" aria-label="Readiness checklist">
      <h2>Readiness Checklist</h2>
      <div>
        {items.map((item) => (
          <div className={item.checked ? "checkItem ready" : "checkItem"} key={item.label}>
            <span aria-hidden="true">{item.checked ? "Ready" : "Check"}</span>
            <div>
              <strong>{item.label}</strong>
              {item.detail && <small>{item.detail}</small>}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function ProgressView({ progress }: { progress: LoadProgress }) {
  const total = progressTotal(progress);
  const completed = progressCompleted(progress);
  const percent = total > 0 ? Math.round((completed / total) * 100) : 0;
  return (
    <section className="progressBox">
      <div className="progressHeader">
        <strong>{secretFreeProgressText(progress)}</strong>
        <span>{percent}%</span>
      </div>
      <div className="bar"><span style={{ width: `${percent}%` }} /></div>
      <div className="metrics">
        <span>Delivered {progress.accepted}</span>
        <span>Rejected {progress.rejected}</span>
        <span>Failed {progress.failed}</span>
        <span>Remaining {progress.remaining}</span>
        <span>Elapsed {formatDuration(progressElapsed(progress))}</span>
      </div>
    </section>
  );
}
