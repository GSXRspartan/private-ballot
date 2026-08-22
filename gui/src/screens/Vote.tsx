import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import {
  pickBallotPackagePath,
  pickDirectory,
  pickElectionArtifact,
  pickGovernanceDocument,
  pickTorExecutable,
  pickVoterTransportBundle,
} from "../api/dialog";
import {
  recallManagedTorConfig,
  rememberManagedTorConfig,
} from "../api/managedTorConfigMemory";
import {
  PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS,
  isRecoverableTransportError,
  isTransientPrivateReleaseResult,
  managedTorTestCardVisible,
  privateSubmissionStageLabel,
  privateSubmissionStatus,
} from "../privateSubmission";
import type {
  GuiCommandError,
  GuiGovernanceDocumentDigestV1,
  GuiPrivateReleaseResultV1,
  GuiPrivateRouteV1,
  GuiPrivateSubmissionResultV1,
  GuiPrivateTransportAvailabilityV1,
  GuiSavedVoterCredentialsV1,
  GuiVoterCastLockStateV1,
  GuiVoterCredentialStatusV1,
  GuiVoterElectionConfirmationV1,
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStatusV1,
  ManagedTorTestStatusV1,
  VoterTorStatusV1,
} from "../api/types";
import { selectionInstructionText } from "../ballot/ballotTypes";
import { lifecyclePlainText } from "../lifecycle";
import {
  BOUND_SECTION_LABEL,
  confirmationContinueAvailable,
  documentMatchShortLabel,
  documentMatchTone,
  formatByteSize,
  isCryptographicallyMatched,
} from "../governance";
import {
  canProceedAfterCredential,
  credentialEligibilityTone,
  publicKeyDisplay,
} from "../voterCredential";
import {
  receiptStateIsAccepted,
  receiptStateText,
  selectionAtApprovalMax,
  selectionSummaryText,
  workflowStateText,
  workflowTone,
} from "../voterWorkflow";
import { BallotSaveDialogError, requestAndExportPreparedBallot } from "../voterExport";
import { useAppState } from "../state/AppState";
import { RequestGenerationGate } from "../requestGeneration";
import { reviewStageReached, voteStageReached, voterStages } from "../voterProgress";
import {
  BackendErrorNotice,
  Card,
  ConfirmDialog,
  CopyButton,
  DetailsSection,
  Field,
  HashValue,
  LifecyclePill,
  Notice,
  Pill,
} from "../components/ui";
import { ProgressSteps } from "../components/ProgressSteps";
import { VoterCredentialCard } from "../components/VoterCredentialCard";

/**
 * Vote (voter) — the voter journey in plain terms:
 *
 *   Load election → review the election → confirm the governance source →
 *   confirm eligibility → choose a vote → create an anonymous eligibility
 *   proof → submit privately or save a ballot file → review submission
 *   status.
 *
 * All proof construction, ballot packaging, and verification happen in the
 * Rust backend; this screen never implements protocol logic, never holds
 * secret material, and never submits ballot bytes itself.
 */

/**
 * Sleeps up to `ms`, polling a cancel flag so a stop/cancel takes effect
 * promptly (within one poll interval) instead of after the full delay. Resolves
 * `true` if the delay elapsed, `false` if it was cancelled. Never a tight loop.
 */
function abortableSleep(ms: number, cancelRef: { current: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    const start = Date.now();
    const step = 150;
    const tick = () => {
      if (cancelRef.current) return resolve(false);
      if (Date.now() - start >= ms) return resolve(true);
      setTimeout(tick, step);
    };
    setTimeout(tick, Math.min(step, ms));
  });
}

/**
 * Compact completed-stage summary for the guided voter workflow
 * (progressive disclosure, presentation only). A finished stage collapses to
 * a checkmarked summary with a deliberate review control that re-expands the
 * full stage content in place; collapsing never touches the underlying
 * workflow/backend state.
 */
function GuidedStageSummary({
  title,
  lines,
  reviewLabel,
  onReview,
}: {
  title: string;
  lines: string[];
  reviewLabel: string;
  onReview: () => void;
}) {
  return (
    <section className="card guided-summary" aria-label={title}>
      <h3 className="card-title">✓ {title}</h3>
      {lines
        .filter((line) => line !== "")
        .map((line) => (
          <p className="card-body" key={line}>
            {line}
          </p>
        ))}
      <div className="action-row">
        <button
          type="button"
          className="btn btn-secondary"
          aria-expanded={false}
          onClick={onReview}
        >
          {reviewLabel}
        </button>
      </div>
    </section>
  );
}

export function Vote() {
  const { election, shellAvailable, loadElection } = useAppState();
  const [loadManifestPath, setLoadManifestPath] = useState("");
  const [loadRegistryPath, setLoadRegistryPath] = useState("");
  const [loadOptionSetPath, setLoadOptionSetPath] = useState("");
  const [confirmation, setConfirmation] = useState<GuiVoterElectionConfirmationV1 | null>(null);
  const [govDocDigest, setGovDocDigest] = useState<GuiGovernanceDocumentDigestV1 | null>(null);
  const [credential, setCredential] = useState<GuiVoterCredentialStatusV1 | null>(null);
  const [savedCredentials, setSavedCredentials] =
    useState<GuiSavedVoterCredentialsV1 | null>(null);
  const [selection, setSelection] = useState<GuiVoterSelectionStatusV1 | null>(null);
  const [workflow, setWorkflow] = useState<GuiVoterWorkflowStatusV1 | null>(null);
  const [selectedOptionIds, setSelectedOptionIds] = useState<string[]>([]);
  const [abstaining, setAbstaining] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [credentialStage, setCredentialStage] = useState(false);
  const [selectionStage, setSelectionStage] = useState(false);
  const [error, setError] = useState<GuiCommandError | null>(null);
  const [credentialError, setCredentialError] = useState<GuiCommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmCast, setConfirmCast] = useState(false);
  // Guided progressive disclosure (presentation only). Default = guided mode:
  // the current stage is expanded, completed stages collapse to compact
  // summaries, and future stages stay out of the main workflow. `showAllSteps`
  // restores the complete control surface for technical review/testing without
  // touching any workflow state; `reviewStage` re-expands one completed stage
  // on deliberate voter request.
  const [showAllSteps, setShowAllSteps] = useState(false);
  const [reviewStage, setReviewStage] = useState<string | null>(null);
  // Voter override for the collapsed offline-delivery disclosure; null = the
  // default (open only when no private online route is available).
  const [offlineOpenOverride, setOfflineOpenOverride] = useState<boolean | null>(null);
  const [transport, setTransport] = useState<GuiPrivateTransportAvailabilityV1 | null>(null);
  const [privateRoute, setPrivateRoute] = useState<GuiPrivateRouteV1>("ManagedTor");
  const [privateResult, setPrivateResult] = useState<GuiPrivateReleaseResultV1 | GuiPrivateSubmissionResultV1 | null>(null);
  const [managedTorStatus, setManagedTorStatus] = useState<ManagedTorTestStatusV1 | null>(null);
  // Read-only voter Tor availability (auto-detected from the reviewed allowlist
  // or a remembered/selected path). Drives the "Tor installed: Found" line and
  // the one-click Connect flow; never starts Tor by itself.
  const [voterTorStatus, setVoterTorStatus] = useState<VoterTorStatusV1 | null>(null);
  // Bounded automatic-retry state for a private submission whose only failure is
  // transient transport/onion reachability. `autoRetryAttempt` is the 1-based
  // automatic-retry number currently in progress (0 = none). The cancel ref is
  // flipped by Stop retrying / stopping Tor / leaving the screen so no retry
  // continues in the background.
  const [autoRetryAttempt, setAutoRetryAttempt] = useState(0);
  const autoRetryCancelRef = useRef(false);
  // True only while a private submit/retry orchestration is in flight, so the
  // "Sending your encrypted ballot privately…" status paints only during an
  // actual submission and never during an unrelated busy operation (proof
  // creation, offline export, connect). Button disabling still uses `busy`.
  const [submitting, setSubmitting] = useState(false);
  // Local, voter-safe error for the private-submission controls only, shown next
  // to those controls instead of only at the top of the screen (Issue 5). It
  // never carries transport internals beyond the backend's coarsened codes.
  const [privateError, setPrivateError] = useState<GuiCommandError | null>(null);
  // The three NON-SECRET controlled-test paths, pre-filled from local memory so a
  // tester does not retype them after navigation/restart. Pre-filling never
  // starts Tor or transmits anything; Rust re-validates every path before use.
  // tor.exe is a GLOBAL convenience path; the bundle and data directory are
  // ELECTION-SPECIFIC and are (re)hydrated per election below, so a different
  // election never silently inherits the previous election's transport bundle.
  const [torExePath, setTorExePath] = useState(() => recallManagedTorConfig().torExePath);
  const [torDataDir, setTorDataDir] = useState("");
  const [voterBundlePath, setVoterBundlePath] = useState("");
  // Pre-release recovery: when a ballot-office connection is already configured
  // but the private connection is stopped (e.g. it was configured with a bundle
  // bound to the WRONG election), the voter can deliberately re-open the
  // connection-file selector to replace it — without restarting the app,
  // reloading the election, or touching the prepared ballot. Presentation-only:
  // it just reveals the existing configure/verify flow, which still fails closed
  // on an election mismatch. Never offered once the ballot is durably locked.
  const [reconfiguring, setReconfiguring] = useState(false);
  const selectionDraftIdsRef = useRef<string[]>([]);
  const selectionRequestGenerationRef = useRef(0);
  const confirmationRequestGenerationRef = useRef(new RequestGenerationGate());

  useEffect(() => {
    setConfirmation(null);
    setGovDocDigest(null);
    setSelection(null);
    setWorkflow(null);
    setSelectedOptionIds([]);
    setAbstaining(false);
    selectionDraftIdsRef.current = [];
    selectionRequestGenerationRef.current += 1;
    confirmationRequestGenerationRef.current.invalidate();
    setConfirmed(false);
    setCredentialStage(false);
    setSelectionStage(false);
    setReviewStage(null);
    setOfflineOpenOverride(null);
    setTransport(null);
    setPrivateRoute("ManagedTor");
    setPrivateResult(null);
    setPrivateError(null);
    setReconfiguring(false);
    // Leaving/switching elections cancels any in-progress automatic retry so it
    // never continues against a stale election.
    autoRetryCancelRef.current = true;
    setAutoRetryAttempt(0);
  }, [election]);

  // On unmount (voter leaves the screen), cancel any in-progress automatic retry
  // so no submission continues in the background.
  useEffect(() => {
    return () => {
      autoRetryCancelRef.current = true;
    };
  }, []);

  // Re-hydrate the remembered controlled-test paths whenever the election
  // identity changes. The GLOBAL tor.exe is restored; the ELECTION-SPECIFIC
  // bundle and data directory are restored only when they were remembered for
  // THIS election (manifest hash), and are otherwise cleared so a prior
  // election's transport bundle is never silently reused (F2). Runs on mount and
  // on every election switch, not on same-election field edits.
  const electionManifestHashHex = election?.manifest_hash_hex ?? "";
  useEffect(() => {
    const remembered = recallManagedTorConfig(electionManifestHashHex);
    setTorExePath(remembered.torExePath);
    setTorDataDir(remembered.torDataDir);
    setVoterBundlePath(remembered.voterBundlePath);
  }, [electionManifestHashHex]);

  function commandErrorFromUnknown(err: unknown): GuiCommandError {
    if (err instanceof BackendError) return err.payload;
    return {
      code: "GUI_UNEXPECTED_ERROR",
      category: "INVALID_INPUT",
      context: null,
      message: "an unexpected frontend/backend boundary error occurred",
    };
  }

  function captureError(err: unknown) {
    setError(commandErrorFromUnknown(err));
  }

  function captureCredentialError(err: unknown) {
    setCredentialError(commandErrorFromUnknown(err));
  }

  // Voter-facing Load Election. Reuses the same safe backend loading path
  // as the organizer screens; no parallel protocol implementation.
  async function onPickLoadArtifact(which: "manifest" | "registry" | "optionSet") {
    const titles = {
      manifest: "Choose election definition file",
      registry: "Choose eligible voter list file",
      optionSet: "Choose ballot options file",
    } as const;
    const picked = await pickElectionArtifact(titles[which]);
    if (picked === null) return;
    if (which === "manifest") setLoadManifestPath(picked);
    else if (which === "registry") setLoadRegistryPath(picked);
    else setLoadOptionSetPath(picked);
  }

  async function onVoterLoadElection() {
    setBusy(true);
    setError(null);
    try {
      await loadElection(loadManifestPath, loadRegistryPath, loadOptionSetPath);
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function loadConfirmation(path: string | null) {
    if (!election || !shellAvailable) return;
    const requestGeneration = confirmationRequestGenerationRef.current.begin();
    setBusy(true);
    setError(null);
    try {
      const c = await api.voterConfirmation(path);
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) setConfirmation(c);
    } catch (err) {
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) {
        captureError(err);
        setConfirmation(null);
      }
    } finally {
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) setBusy(false);
    }
  }

  useEffect(() => {
    if (election && shellAvailable) void loadConfirmation(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election, shellAvailable]);

  useEffect(() => {
    if (shellAvailable) void refreshCredentialStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election, shellAvailable]);

  // On entering the Vote screen (navigation back OR an application restart),
  // read the AUTHORITATIVE workflow status once so the guided stage can be
  // RECONSTRUCTED from real backend/durable state (loaded selection, prepared
  // ballot, durable cast-lock) instead of snapping back to the first stage
  // because the in-component gate booleans reset on mount. This is read-only:
  // it never starts Tor, prepares a ballot, releases a submission, or creates
  // any durable record; `review_confirmed` is passed false so no gate is
  // asserted the voter has not re-confirmed this session.
  useEffect(() => {
    if (election && shellAvailable) void refreshWorkflow(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election, shellAvailable]);

  // Populate the controlled managed-Tor status on load so the recovery/status
  // card reflects reality after a restart (feature presence + durable state),
  // without waiting for the voter to act. Read-only: it never starts Tor,
  // creates a PENDING record, or transmits anything.
  useEffect(() => {
    if (election && shellAvailable) void refreshManagedTorStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election, shellAvailable]);

  // Probe voter Tor availability (read-only) so the one-click Connect flow can
  // show "Tor installed: Found" without the voter typing a path. Re-runs when
  // the remembered/selected tor.exe changes.
  useEffect(() => {
    if (election && shellAvailable) void refreshVoterTorStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election, shellAvailable, torExePath]);

  // Truthful ready-state: while the managed-Tor connection is configured and the
  // ballot is not yet durably CAST, re-read the AUTHORITATIVE status on a bounded
  // interval. The backend status checks the owned Tor child's liveness (try_wait)
  // and a fresh SOCKS probe, so if the child has exited, tor_running flips to
  // false and the banner stops claiming "Private connection ready" and reveals
  // Reconnect instead — the UI can never simultaneously show "ready" and a dead
  // child. Not a tight loop; the Rust status runs off the main thread.
  useEffect(() => {
    if (!shellAvailable) return;
    if (!managedTorStatus?.configured) return;
    if (workflow?.cast_lock_state === "CAST") return;
    const intervalId = setInterval(() => {
      void refreshManagedTorStatus();
    }, 5000);
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shellAvailable, managedTorStatus?.configured, workflow?.cast_lock_state]);

  async function onSelectGovernanceDocument() {
    const path = await pickGovernanceDocument("Select local governance document to inspect");
    if (!path) return;
    setBusy(true);
    setError(null);
    const requestGeneration = confirmationRequestGenerationRef.current.begin();
    try {
      const digest = await api.computeGovernanceDocumentDigest(path);
      if (!confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) return;
      setGovDocDigest(digest);
      const c = await api.voterConfirmation(path);
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) setConfirmation(c);
    } catch (err) {
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) captureError(err);
    } finally {
      if (confirmationRequestGenerationRef.current.isCurrent(requestGeneration)) setBusy(false);
    }
  }

  async function onClearGovernanceDocument() {
    setGovDocDigest(null);
    await loadConfirmation(null);
  }

  async function onEnterCredentialStage() {
    if (!election || !shellAvailable) return;
    setCredentialStage(true);
    setBusy(true);
    setError(null);
    try {
      await refreshCredentialStatus();
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function refreshSavedCredentials() {
    if (!shellAvailable) return null;
    const saved = await api.listSavedVoterCredentials();
    setSavedCredentials(saved);
    return saved;
  }

  async function refreshCredentialStatus() {
    if (!shellAvailable) return null;
    const [status, saved] = await Promise.all([
      api.voterGovernanceCredentialStatus(),
      api.listSavedVoterCredentials(),
    ]);
    setCredential(status);
    setSavedCredentials(saved);
    return status;
  }

  async function applyCredentialStatus(status: GuiVoterCredentialStatusV1) {
    setCredential(status);
    await refreshSavedCredentials();
    if (selectionStage) await refreshWorkflow(true);
  }

  async function onCreateCredential(passphrase: string) {
    const status = await api.createDurableVoterCredential(passphrase);
    await applyCredentialStatus(status);
  }

  async function onUnlockCredential(publicKeyHex: string, passphrase: string) {
    const status = await api.unlockSavedVoterCredential(publicKeyHex, passphrase);
    await applyCredentialStatus(status);
  }

  async function onImportCredential(
    path: string,
    passphrase: string,
    persistLocally: boolean,
  ) {
    const status = await api.importVoterCredential(path, passphrase, persistLocally);
    await applyCredentialStatus(status);
  }

  async function onBackupCredential(path: string, passphrase: string) {
    await api.backupVoterCredential(path, passphrase);
  }

  async function onClearCredentialFromMemory() {
    if (!shellAvailable) {
      setCredential(null);
      setWorkflow(null);
      return;
    }
    const status = await api.clearVoterCredentialFromMemory();
    await applyCredentialStatus(status);
  }

  async function onDeleteSavedCredential(publicKeyHex: string) {
    await api.deleteSavedVoterCredential(publicKeyHex);
    await refreshCredentialStatus();
    if (selectionStage) await refreshWorkflow(true);
  }

  async function refreshWorkflow(reviewConfirmed = confirmed) {
    if (!election || !shellAvailable) return;
    const status = await api.voterWorkflowStatus(reviewConfirmed);
    setWorkflow(status);
    setCredential(status.credential);
    setSelection(status.selection);
    setSelectedOptionIds(status.selection.selected_option_ids_hex);
    setAbstaining(status.selection.abstaining);
    selectionDraftIdsRef.current = status.selection.selected_option_ids_hex;
  }

  async function refreshSelection() {
    if (!election || !shellAvailable) return;
    const status = await api.voterBallotSelectionStatus();
    setSelection(status);
    setSelectedOptionIds(status.selected_option_ids_hex);
    setAbstaining(status.abstaining);
    selectionDraftIdsRef.current = status.selected_option_ids_hex;
  }

  async function onEnterSelectionStage() {
    setSelectionStage(true);
    setBusy(true);
    setError(null);
    try {
      await refreshSelection();
      await refreshWorkflow(true);
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function setBackendSelection(nextIds: string[], nextAbstaining: boolean) {
    const requestGeneration = selectionRequestGenerationRef.current + 1;
    selectionRequestGenerationRef.current = requestGeneration;
    setBusy(true);
    setError(null);
    try {
      const status =
        nextIds.length === 0 && !nextAbstaining
          ? await api.clearVoterBallotSelection()
          : await api.setVoterBallotSelection(nextIds, nextAbstaining);
      if (requestGeneration !== selectionRequestGenerationRef.current) return;
      setSelection(status);
      setSelectedOptionIds(status.selected_option_ids_hex);
      setAbstaining(status.abstaining);
      selectionDraftIdsRef.current = status.selected_option_ids_hex;
      await refreshWorkflow(true);
    } catch (err) {
      if (requestGeneration === selectionRequestGenerationRef.current) captureError(err);
    } finally {
      if (requestGeneration === selectionRequestGenerationRef.current) setBusy(false);
    }
  }

  async function onToggleOption(optionId: string, checked: boolean) {
    const set = new Set(selectionDraftIdsRef.current);
    if (checked) set.add(optionId);
    else set.delete(optionId);
    const nextIds = [...set];
    selectionDraftIdsRef.current = nextIds;
    setSelectedOptionIds(nextIds);
    setAbstaining(false);
    await setBackendSelection(nextIds, false);
  }

  async function onToggleAbstain(checked: boolean) {
    selectionDraftIdsRef.current = [];
    setSelectedOptionIds([]);
    setAbstaining(checked);
    await setBackendSelection([], checked);
  }

  async function onGenerateProof() {
    if (!shellAvailable) return;
    setBusy(true);
    setError(null);
    try {
      const prepared = await api.prepareVoterBallot();
      await refreshWorkflow(true);
      setTransport(await api.privateTransportAvailability());
      await refreshManagedTorStatus();
      if (prepared.state !== "Ready") {
        setError({
          code: "GUI_PROOF_VERIFICATION_FAILED",
          category: "PROOF_FAILURE",
          context: "prepare-ballot",
          message: "the ballot package was not prepared",
        });
      }
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function onExportBallot() {
    setBusy(true);
    setError(null);
    try {
      const saved = await requestAndExportPreparedBallot(
        pickBallotPackagePath,
        (path) => api.exportPreparedVoterBallot(path),
      );
      if (!saved) return;
      await refreshWorkflow(true);
    } catch (err) {
      if (err instanceof BallotSaveDialogError) {
        setError({
          code: "GUI_BALLOT_SAVE_DIALOG_UNAVAILABLE",
          category: "FILE_IO",
          context: "export-ballot",
          message:
            "The native Save dialog could not open. Check that the desktop app can show save dialogs, then try again.",
        });
      } else {
        captureError(err);
      }
    } finally {
      setBusy(false);
    }
  }

  async function onChangeChoice() {
    setBusy(true);
    setError(null);
    try {
      await api.changeMyBallotChoice();
      await refreshWorkflow(true);
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function onSubmitPrivately() {
    if (privateRoute === "OfflineExport") {
      await onExportBallot();
      return;
    }
    await runBoundedPrivateSubmission(() =>
      api.submitPreparedVoterBallotPrivately(privateRoute),
    );
  }

  // Runs a private submission with a SMALL, BOUNDED automatic retry that reacts
  // ONLY to a transient transport/onion-reachability failure. The very first
  // attempt is `initialAttempt` (a fresh submit, or a manual retry); every
  // automatic retry after that re-sends the EXACT same staged encrypted
  // submission through `retry_private_submission` — the existing exact-retry
  // path. It never prepares, re-seals, or re-submits a new ballot, so no new
  // proof/nullifier/digest is ever created, and an authenticated organizer
  // receipt stays mandatory for CAST. Any non-transient outcome (authenticated
  // rejection, receipt/descriptor/package mismatch, invalid receipt, local
  // finalization failure, or a thrown error) is surfaced immediately and never
  // retried. The loop is bounded by the backoff schedule and is cancelled the
  // moment the voter stops retrying, stops Tor, or leaves the screen.
  // Reads the AUTHORITATIVE durable cast-lock state without throwing, so the
  // retry loop can decide (from real backend state, never a guess) whether a
  // failed attempt left the ballot durably locked (CAST_PENDING) and therefore
  // safe to keep exact-retrying.
  async function durableCastStateOrNull(): Promise<GuiVoterCastLockStateV1 | null> {
    if (!election || !shellAvailable) return null;
    try {
      const status = await api.voterWorkflowStatus(confirmed);
      return status.cast_lock_state;
    } catch {
      return null;
    }
  }

  async function runBoundedPrivateSubmission(
    initialAttempt: () => Promise<GuiPrivateReleaseResultV1 | GuiPrivateSubmissionResultV1>,
  ) {
    setBusy(true);
    setSubmitting(true);
    setError(null);
    setPrivateError(null);
    setPrivateResult(null);
    setAutoRetryAttempt(0);
    autoRetryCancelRef.current = false;
    try {
      let attempt = 0;
      // Each attempt: the first is the fresh submit, subsequent ones re-send the
      // EXACT same staged encrypted submission (exact-retry). The loop is driven
      // by whether the outcome is a RECOVERABLE transient transport failure —
      // whether the backend RETURNED a CAST_PENDING transient result, OR THREW a
      // transport-unavailable error while the ballot is durably CAST_PENDING. A
      // thrown transport error no longer breaks the bounded backoff into a
      // generic terminal error, so a transient ballot-office outage reliably
      // enters (and stays in) the recoverable retry/backoff state. Terminal
      // errors (non-transport codes, or a transport error while the ballot is
      // NOT durably locked) are surfaced immediately and never retried.
      let nextAttempt = initialAttempt;
      for (;;) {
        let recoverableTransient = false;
        try {
          const result = await nextAttempt();
          setPrivateResult(result);
          recoverableTransient = isTransientPrivateReleaseResult(result);
        } catch (err) {
          const commandError = commandErrorFromUnknown(err);
          const castStateNow = await durableCastStateOrNull();
          if (castStateNow === "CAST_PENDING" && isRecoverableTransportError(commandError)) {
            // The ballot is durably locked and the only failure so far is a
            // transient delivery outage: stay in the recovery flow (no generic
            // terminal error) and keep retrying the exact staged submission.
            recoverableTransient = true;
          } else {
            // Terminal (or nothing was staged): surface next to the controls;
            // the durable cast state remains the authority for locked/pending.
            setPrivateError(commandError);
            break;
          }
        }
        if (
          !recoverableTransient ||
          autoRetryCancelRef.current ||
          attempt >= PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length
        ) {
          break;
        }
        const delayMs = PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS[attempt];
        attempt += 1;
        setAutoRetryAttempt(attempt);
        const elapsed = await abortableSleep(delayMs, autoRetryCancelRef);
        if (!elapsed || autoRetryCancelRef.current) break;
        // EXACT same staged encrypted submission (exact-retry path).
        nextAttempt = () => api.retryPrivateSubmission();
      }
      setTransport(await api.privateTransportAvailability());
      await refreshWorkflow(true);
      // Re-read the AUTHORITATIVE managed-Tor status so a failure caused by the
      // Tor child having exited flips the connection banner out of "ready" (and
      // reveals Reconnect) instead of leaving a stale "Private connection ready"
      // contradicting "the managed Tor process has exited".
      setManagedTorStatus(await api.managedTorTestStatus());
    } catch (err) {
      // Reached only if a post-loop refresh throws; keep it next to the controls.
      setPrivateError(commandErrorFromUnknown(err));
      await refreshWorkflow(true).catch(() => {});
      await refreshManagedTorStatus().catch(() => {});
    } finally {
      setAutoRetryAttempt(0);
      setSubmitting(false);
      setBusy(false);
    }
  }

  // Cancels any in-progress automatic retry without stopping Tor. The current
  // in-flight backend call (if any) completes, but no further retry is scheduled.
  function onStopAutoRetry() {
    autoRetryCancelRef.current = true;
    setAutoRetryAttempt(0);
  }

  async function refreshManagedTorStatus() {
    if (!shellAvailable) return;
    try {
      setManagedTorStatus(await api.managedTorTestStatus());
    } catch {
      // The command may fail closed when the feature is absent; ignore.
    }
  }

  async function onConfigureManagedTor() {
    setBusy(true);
    setError(null);
    setPrivateError(null);
    try {
      // An empty data directory means "auto" — the backend derives an app-owned,
      // election-scoped directory the voter never has to choose.
      const status = await api.configureManagedTorTest(torExePath, torDataDir, voterBundlePath);
      // Remember only the NON-SECRET paths for the next run/navigation.
      rememberManagedTorConfig({
        torExePath,
        torDataDir,
        voterBundlePath,
        electionManifestHashHex,
      });
      setManagedTorStatus(status);
      setReconfiguring(false);
    } catch (err) {
      setPrivateError(commandErrorFromUnknown(err));
    } finally {
      setBusy(false);
    }
  }

  // Read-only voter Tor availability probe. Never starts Tor.
  async function refreshVoterTorStatus() {
    if (!shellAvailable) return;
    try {
      setVoterTorStatus(await api.voterTorStatus(torExePath.length > 0 ? torExePath : undefined));
    } catch {
      // Best-effort; leave the last known status visible on failure.
    }
  }

  // One-click voter connect: configure (auto tor.exe + auto app-owned data dir +
  // the verified organizer bundle) then start the managed Tor connection. The
  // Rust shell re-validates every path and re-verifies the bundle against the
  // loaded election before anything starts; no clearnet fallback exists.
  async function onConnectPrivately() {
    setBusy(true);
    setError(null);
    setPrivateError(null);
    try {
      // "" data dir → backend auto-derives the app-owned election-scoped dir.
      await api.configureManagedTorTest(torExePath, "", voterBundlePath);
      rememberManagedTorConfig({
        torExePath,
        torDataDir: "",
        voterBundlePath,
        electionManifestHashHex,
      });
      const status = await api.startManagedTor();
      setManagedTorStatus(status);
      // A successful (re)connect replaces any prior configuration; leave the
      // reconfigure flow.
      setReconfiguring(false);
    } catch (err) {
      setPrivateError(commandErrorFromUnknown(err));
    } finally {
      setBusy(false);
    }
  }

  async function onBrowseTorExe() {
    const picked = await pickTorExecutable();
    if (picked === null) return;
    setTorExePath(picked);
    // Remember the tor.exe globally (non-secret convenience) and re-probe so the
    // "Tor installed" line updates immediately.
    const current = recallManagedTorConfig(electionManifestHashHex);
    rememberManagedTorConfig({ ...current, torExePath: picked });
    try {
      setVoterTorStatus(await api.voterTorStatus(picked));
    } catch {
      // Best-effort probe.
    }
  }

  async function onBrowseVoterBundle() {
    const picked = await pickVoterTransportBundle();
    if (picked !== null) setVoterBundlePath(picked);
  }

  async function onBrowseTorDataDir() {
    const picked = await pickDirectory("Choose voter Tor data directory");
    if (picked !== null) setTorDataDir(picked);
  }

  async function onStartManagedTor() {
    setBusy(true);
    setError(null);
    setPrivateError(null);
    try {
      const status = await api.startManagedTor();
      setManagedTorStatus(status);
    } catch (err) {
      setPrivateError(commandErrorFromUnknown(err));
    } finally {
      setBusy(false);
    }
  }

  async function onStopManagedTor() {
    // Stopping the connection also cancels any in-progress automatic retry so no
    // submission continues in the background after the voter stops.
    autoRetryCancelRef.current = true;
    setBusy(true);
    setError(null);
    setPrivateError(null);
    try {
      const status = await api.stopManagedTor();
      setManagedTorStatus(status);
    } catch (err) {
      setPrivateError(commandErrorFromUnknown(err));
    } finally {
      setBusy(false);
    }
  }

  // Manual retry fallback: same bounded exact-retry runner, seeded with an
  // immediate exact-retry attempt. Remains available after automatic retries
  // are exhausted.
  async function onRetryPrivateSubmission() {
    await runBoundedPrivateSubmission(() => api.retryPrivateSubmission());
  }

  const docStatus = confirmation?.governance_document_status ?? null;
  const matchTone = documentMatchTone(docStatus?.status);
  const eligibilityTone = credentialEligibilityTone(credential?.eligibility ?? "NotChecked");
  const selectionLiveText = selectionSummaryText(selection);
  const selectionAtMax = selectionAtApprovalMax(selection);
  // Durable local cast state. Once CAST, the choice is locked on this device and
  // no reconsideration/preparation is offered (the election-scoped nullifier is
  // the authoritative cross-machine one-vote rule). CAST_PENDING is a locked
  // recovery state.
  const castState = workflow?.cast_lock_state ?? "NOT_CAST";
  const ballotCast = castState === "CAST";
  const castPending = castState === "CAST_PENDING";
  const castLocked = ballotCast || castPending;
  // Whether THIS ballot reached CAST through an authenticated online (Tor)
  // submission in this session, rather than an offline file export. The durable
  // cast-lock state carries only NOT_CAST/CAST_PENDING/CAST and cannot itself
  // distinguish the two, so we use the in-session accepted private result. When
  // it is present the "Ballot cast" card must NOT tell the voter to deliver an
  // exported file — the organizer already returned an authenticated receipt.
  const castViaAuthenticatedOnline =
    ballotCast &&
    privateResult !== null &&
    "receipt_state" in privateResult &&
    receiptStateIsAccepted(privateResult.receipt_state);
  // Whether the controlled managed-Tor test feature is present in this build.
  // The status command returns a value (even "not configured") when compiled,
  // and the frontend leaves managedTorStatus null when the command is absent.
  const managedTorFeaturePresent = managedTorStatus !== null;
  // Authoritative private-submission status, derived from DURABLE cast state so
  // it survives navigation/restart (Issues 4 and 17) — a transient result object
  // is never required to show SUCCESS or PENDING.
  const privateStatus = privateSubmissionStatus({
    castState,
    configured: managedTorStatus?.configured ?? false,
    torRunning: managedTorStatus?.tor_running ?? false,
    busy: submitting,
    lastReceiptState:
      privateResult && "receipt_state" in privateResult ? privateResult.receipt_state : null,
  });
  // Bounded, privacy-safe stage from the most recent private-release attempt,
  // for the Advanced/diagnostics panel only. Present only on an uncertain
  // (CAST_PENDING) attempt this session; the durable status block above is the
  // authoritative success/pending indicator.
  const privateStageLabel =
    privateResult && "diagnostic_stage" in privateResult
      ? privateSubmissionStageLabel(privateResult.diagnostic_stage)
      : null;

  // ---------------------------------------------------------------------
  // Guided progressive disclosure (presentation only). Derived from the SAME
  // existing workflow/session inputs as the progress indicator below — no new
  // state is fetched and no gate changes. Guided mode (default): the current
  // stage is expanded, completed stages collapse to compact summaries, future
  // stages stay hidden. Show all steps restores the full control surface.
  // ---------------------------------------------------------------------
  // Reconstruct how far the voter has ACTUALLY progressed from durable/session
  // backend state, so navigation or a restart never snaps the guided workflow
  // back to the beginning while real progress exists (the in-component gate
  // booleans `credentialStage`/`selectionStage` reset to false on every mount).
  const stageReconstruction = {
    credentialLoaded: !!credential?.credential_loaded,
    identityReady: canProceedAfterCredential(credential),
    selectionLoaded: !!selection?.selection_loaded,
    ballotReady: workflow?.prepared_ballot.state === "Ready",
    castLocked,
  };
  const reviewReached = reviewStageReached(credentialStage, stageReconstruction);
  const voteReached = voteStageReached(selectionStage, stageReconstruction);
  const guidedStages = voterStages({
    electionLoaded: election !== null,
    reviewPassed: reviewReached,
    identityReady: canProceedAfterCredential(credential),
    voteEntered: voteReached,
    choiceMade: !!selection?.selection_loaded && selection.valid,
    ballotReady: workflow?.prepared_ballot.state === "Ready",
    castState,
  });
  const currentStageKey =
    guidedStages.find((stage) => stage.state === "current")?.key ?? null;
  const guidedStageDone = (key: string) =>
    guidedStages.some((stage) => stage.key === key && stage.state === "done");
  // A stage renders in full when it is current, when the voter deliberately
  // re-expanded it for review, or in show-all mode.
  const stageExpanded = (key: string) =>
    showAllSteps || currentStageKey === key || reviewStage === key;
  // The private-submission card is the Submit stage; a durably locked ballot
  // (CAST_PENDING/CAST) keeps its recovery/receipt surface visible.
  const submitStageVisible =
    showAllSteps || currentStageKey === "Submit" || castLocked;
  // Plain-language choice text for the collapsed Vote-stage summary, derived
  // from the existing confirmed candidates + selection state (never stored
  // separately).
  const voteChoiceText = abstaining
    ? "Abstention"
    : confirmation
      ? confirmation.candidates
          .filter((option) => selectedOptionIds.includes(option.machine_id_hex))
          .map((option) => option.display_name)
          .join(", ")
      : "";
  // Whether a private online delivery route exists in this build/session; when
  // none does, the offline delivery disclosure starts open instead of buried.
  const onlineRouteAvailable =
    (transport?.managed_tor_available ?? false) ||
    (transport?.split_trust_relay_available ?? false) ||
    managedTorFeaturePresent;
  // "Hide details" control shown above a deliberately re-expanded completed
  // stage (guided mode only).
  const hideStageDetails = (key: string) =>
    !showAllSteps && reviewStage === key ? (
      <div className="action-row">
        <button
          type="button"
          className="btn btn-secondary"
          aria-expanded={true}
          onClick={() => setReviewStage(null)}
        >
          Hide details
        </button>
      </div>
    ) : null;

  return (
    <>
      <h1 className="screen-header">Vote</h1>
      <p className="screen-lede">
        Cast your ballot in a few steps: load the election, review what you are voting on,
        confirm you are eligible, choose your vote, then create an anonymous eligibility proof
        and submit privately or save a ballot file for the organizer.
      </p>

      <details className="voter-guide">
        <summary className="voter-guide-summary">How voting works</summary>
        <ol className="voter-guide-steps">
          <li>
            <strong>Load the election.</strong> You receive the election files from the
            organizer. The app checks that the files belong together and have not been
            altered.
          </li>
          <li>
            <strong>Review the election.</strong> Confirm what is being voted on, the
            governance source, and the available choices before continuing.
          </li>
          <li>
            <strong>Prove you are eligible privately.</strong> Your voter credential lets the
            app prove that you belong to the approved voter list without revealing which
            eligible voter you are.
          </li>
          <li>
            <strong>Choose your vote.</strong> Your ballot is tied to this specific election,
            so it cannot be reused for a different election.
          </li>
          <li>
            <strong>Submit your ballot.</strong> You can submit through the private online
            route or save the ballot file and transfer it separately.
          </li>
          <li>
            <strong>Check its status.</strong> The app shows whether your ballot was received,
            accepted by the organizer, or rejected. Inclusion and Ootle anchoring are checked
            later from the published archive and organizer evidence.
          </li>
        </ol>
        <DetailsSection summary="Technical details">
          <p className="card-body">
            Eligibility is proven with the Tari Triptych implementation using an
            election-bound proof. This voter workflow reports local preparation and transport
            receipt state only; finalized archive inclusion and aggregate Ootle evidence are
            verified from published organizer records.
          </p>
        </DetailsSection>
      </details>

      <div className="notice notice-info privacy-notice" role="note">
        <h2 className="privacy-notice-title">What privacy does this provide?</h2>
        <ul className="privacy-notice-list">
          <li>
            <strong>Eligibility stays anonymous.</strong> Your eligibility proof shows that an
            approved voter participated without revealing which eligible voter you are.
          </li>
          <li>
            <strong>Your vote choice is not permanently sealed.</strong> It may become visible
            as part of the final verifiable election record.
          </li>
          <li>
            <strong>Keep your voter credential private.</strong> Never send it to the
            organizer or another voter.
          </li>
        </ul>
      </div>

      <BackendErrorNotice error={error} onDismiss={() => setError(null)} />

      <VoterCredentialCard
        status={credential}
        savedCredentials={savedCredentials}
        shellAvailable={shellAvailable}
        busy={busy}
        context="vote"
        showFrozenElectionNotice={!!election}
        onCreate={onCreateCredential}
        onUnlock={onUnlockCredential}
        onImport={onImportCredential}
        onBackup={onBackupCredential}
        onClear={onClearCredentialFromMemory}
        onDeleteSaved={onDeleteSavedCredential}
        onError={captureCredentialError}
        operationError={credentialError}
        onOperationSuccess={() => setCredentialError(null)}
        onOperationErrorDismiss={() => setCredentialError(null)}
      />

      {/* Guided voter progression, derived entirely from the existing workflow
          /session state (no new backend state). Completed stages carry a
          checkmark, the current stage is emphasized, future stages subdued. */}
      {election && (
        <>
          {/* Single source of truth: the progress indicator reuses the SAME
              reconstructed guided stages as the workflow cards, so navigation
              or a restart never leaves the bar and the cards disagreeing. */}
          <ProgressSteps label="Voting progress" steps={guidedStages} />
          {/* Presentation-only escape hatch: reveals every stage (including
              future/technical ones) for review or testing. It never changes
              workflow state, never bypasses a gate, and never enables a
              disabled control. */}
          <div className="action-row">
            <button
              type="button"
              className="btn btn-secondary"
              aria-pressed={showAllSteps}
              onClick={() => setShowAllSteps((current) => !current)}
            >
              {showAllSteps ? "Show guided steps" : "Show all steps"}
            </button>
          </div>
        </>
      )}

      {!election && (
        <Card title="Load Election">
          <p className="card-body">
            To vote, load the election files shared by the election organizer: the election
            definition, the eligible voter list, and the ballot options. The app checks that
            the files are complete and unaltered before continuing.
          </p>
          <DetailsSection summary="Technical details">
            <p className="card-body">
              The election definition is the manifest file, the eligible voter list is the
              registry file, and the ballot options are the candidate/option set file.
            </p>
          </DetailsSection>
          <div className="form-row">
            <label htmlFor="vote-manifest">Election definition</label>
            <div className="file-row">
              <input
                id="vote-manifest"
                type="text"
                readOnly
                value={loadManifestPath ? loadManifestPath.split(/[\\/]/).pop() : ""}
                placeholder="no file selected"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable || busy}
                onClick={() => void onPickLoadArtifact("manifest")}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="form-row">
            <label htmlFor="vote-registry">Eligible voter list</label>
            <div className="file-row">
              <input
                id="vote-registry"
                type="text"
                readOnly
                value={loadRegistryPath ? loadRegistryPath.split(/[\\/]/).pop() : ""}
                placeholder="no file selected"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable || busy}
                onClick={() => void onPickLoadArtifact("registry")}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="form-row">
            <label htmlFor="vote-optionset">Ballot options</label>
            <div className="file-row">
              <input
                id="vote-optionset"
                type="text"
                readOnly
                value={loadOptionSetPath ? loadOptionSetPath.split(/[\\/]/).pop() : ""}
                placeholder="no file selected"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable || busy}
                onClick={() => void onPickLoadArtifact("optionSet")}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={
                !shellAvailable ||
                busy ||
                loadManifestPath === "" ||
                loadRegistryPath === "" ||
                loadOptionSetPath === ""
              }
              onClick={() => void onVoterLoadElection()}
            >
              Load Election
            </button>
          </div>
          {shellAvailable &&
            (loadManifestPath === "" ||
              loadRegistryPath === "" ||
              loadOptionSetPath === "") && (
              <p className="form-hint">Choose all required election files to continue.</p>
            )}
        </Card>
      )}

      {confirmation && (
        <>
          {/* Guided stage 1 — Election: full while current; once completed it
              collapses to a compact summary and can be deliberately re-expanded
              with Review details. Future stages stay hidden. */}
          {!showAllSteps && guidedStageDone("Election") && reviewStage !== "Election" ? (
            <GuidedStageSummary
              title="Election reviewed"
              lines={[
                confirmation.bound.election_id_text ?? confirmation.bound.election_id_hex,
                confirmation.bound.proposal_question ?? "",
              ]}
              reviewLabel="Review details"
              onReview={() => setReviewStage("Election")}
            />
          ) : stageExpanded("Election") ? (
          <>
          {hideStageDetails("Election")}
          <Card title={BOUND_SECTION_LABEL}>
            <Notice tone="info">
              These details come straight from the election definition and cannot be changed by
              anyone, including this app.
            </Notice>
            <div className="field-list">
              <Field label="Election">
                <span className="field-value">
                  {confirmation.bound.election_id_text ?? confirmation.bound.election_id_hex}
                </span>
              </Field>
              {confirmation.bound.proposal_question && (
                <Field label="Ballot question">
                  <span className="field-value">
                    {confirmation.bound.proposal_question}
                  </span>
                </Field>
              )}
              {election && (
                <Field label="Status">
                  <span className="field-value">
                    {lifecyclePlainText(election.lifecycle_state)}
                  </span>
                </Field>
              )}
              <Field label="How many to choose">
                <span className="field-value">
                  {selectionInstructionText(confirmation.bound)}
                </span>
              </Field>
              <Field label="Choices on the ballot">
                <ul className="option-list bound-labels" aria-label="Ballot choices, read-only">
                  {confirmation.bound.option_display_labels.map((label, i) => (
                    <li key={i} className="option-item">
                      <span className="option-marker" aria-hidden="true" />
                      <span>{label}</span>
                    </li>
                  ))}
                </ul>
              </Field>
            </div>
            <p className="form-hint">
              This list is read-only. You choose your response after confirming the election.
            </p>
            {confirmation.no_proposal_question_notice && (
              <p className="form-hint">{confirmation.no_proposal_question_notice}</p>
            )}
            <DetailsSection summary="Election details">
              <div className="field-list">
                <Field label="Election ID (canonical)">
                  <HashValue value={confirmation.bound.election_id_hex} />
                  <CopyButton value={confirmation.bound.election_id_hex} />
                </Field>
                <Field label="Ballot kind">
                  <span className="field-value">{confirmation.bound.ballot_kind}</span>
                </Field>
                <Field label="Manifest hash">
                  <HashValue value={confirmation.bound.manifest_hash_hex} />
                  <CopyButton value={confirmation.bound.manifest_hash_hex} />
                </Field>
                <Field label="Governance source revision">
                  <span className="field-value">
                    {confirmation.bound.governance_source_revision}
                  </span>
                </Field>
                {confirmation.bound.proposal_question && (
                  <Field label="Bound ballot question">
                    <span className="field-value">
                      {confirmation.bound.proposal_question}
                    </span>
                  </Field>
                )}
                <Field label="Proof-suite ID">
                  <span className="field-value">{confirmation.bound.proof_suite_id}</span>
                </Field>
                <Field label="Option machine IDs">
                  <ul className="option-list bound-labels">
                    {confirmation.advanced.option_machine_ids_hex.map((id, i) => (
                      <li key={i} className="option-item">
                        <span className="hash">{id}</span>
                      </li>
                    ))}
                  </ul>
                </Field>
                <Field label="Registry commitment">
                  <HashValue value={confirmation.advanced.registry_commitment_hex} />
                  <CopyButton value={confirmation.advanced.registry_commitment_hex} />
                </Field>
                <Field label="Candidate-set commitment">
                  <HashValue value={confirmation.advanced.candidate_set_commitment_hex} />
                  <CopyButton value={confirmation.advanced.candidate_set_commitment_hex} />
                </Field>
                <Field label="Eligible voters / anonymity-set size">
                  <span className="field-value">{confirmation.advanced.voter_count}</span>
                </Field>
              </div>
              <p className="form-hint">{confirmation.presentation_notice}</p>
            </DetailsSection>
          </Card>

          <Card title="Governance document">
            <p className="form-hint">
              This records the source material that defines what is being voted on, so voters
              and verifiers can confirm they are using the same proposal or election
              information. Optionally select your local copy of the document to check that it
              matches what the election definition records. Nothing is uploaded; the check
              happens on this computer.
            </p>
            {govDocDigest ? (
              <div className="field-list">
                <Field label="Filename">
                  <span className="field-value">{govDocDigest.display_filename}</span>
                </Field>
                <Field label="Byte size">
                  <span className="field-value">{formatByteSize(govDocDigest.bytes)}</span>
                </Field>
                <Field label="Document digest">
                  <HashValue value={govDocDigest.digest_hex} />
                  <CopyButton value={govDocDigest.digest_hex} />
                </Field>
              </div>
            ) : (
              <p className="field-value">No governance document selected.</p>
            )}
            <div className="action-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onSelectGovernanceDocument}
                disabled={busy}
              >
                {govDocDigest ? "Replace document" : "Select governance document"}
              </button>
              {govDocDigest && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={onClearGovernanceDocument}
                  disabled={busy}
                >
                  Clear
                </button>
              )}
            </div>
            {docStatus && (
              <div className="field-list">
                <Field label="Status">
                  <Pill tone={matchTone === "ok" ? "ok" : matchTone === "error" ? "error" : matchTone === "warn" ? "warn" : "neutral"}>
                    {documentMatchShortLabel(docStatus.status)}
                  </Pill>
                </Field>
                <Field label="Detail">
                  <span className="field-value">{docStatus.status_label}</span>
                </Field>
                {isCryptographicallyMatched(docStatus.status) && (
                  <Field label="Binding">
                    <span className="field-value">
                      Digest matches bound governance source
                    </span>
                  </Field>
                )}
              </div>
            )}
          </Card>

          <Card title="Review election">
            <label className="radio-option">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              I have reviewed the election details above and confirmed what I am voting on.
            </label>
            <div className="action-row">
              <button
                type="button"
                className="btn btn-primary"
                disabled={!confirmed || !confirmationContinueAvailable(confirmation) || busy}
                onClick={() => void onEnterCredentialStage()}
              >
                Continue
              </button>
            </div>
            <p className="form-hint">
              Continuing does not create a proof, cast a vote, or send anything anywhere.
            </p>
          </Card>
          </>
          ) : null}

          {credentialStage && (
            <>
              {/* Guided stage 2 — Identity: full while current; once completed
                  it collapses to a compact eligibility summary. */}
              {!showAllSteps && guidedStageDone("Identity") && reviewStage !== "Identity" ? (
                <GuidedStageSummary
                  title="Eligible to vote"
                  lines={["Credential verified locally"]}
                  reviewLabel="Review details"
                  onReview={() => setReviewStage("Identity")}
                />
              ) : stageExpanded("Identity") ? (
              <>
              {hideStageDetails("Identity")}
              <Card title="Confirm you are eligible to vote">
                <p className="card-body">
                  Your private voting credential stays under your control. The ballot office
                  receives only your public enrollment key. The app checks that key against the
                  election&rsquo;s eligible voter list.
                </p>
                {credential?.credential_loaded && (
                  <Notice tone="ok">Voting credential found ✓</Notice>
                )}
                <div className="field-list">
                  <Field label="Eligibility status">
                    <Pill tone={eligibilityTone}>
                      {credential?.eligibility_label ?? "No credential loaded"}
                    </Pill>
                  </Field>
                </div>
                {!credential?.credential_loaded && (
                  <p className="form-hint">
                    Create or unlock your voting credential above, then continue.
                  </p>
                )}
                {credential?.eligibility === "NotEligible" && (
                  <Notice tone="warn">
                    This voting key is not on the election&rsquo;s eligible voter list. Check that
                    the organizer enrolled your key before the election was finalized.
                  </Notice>
                )}
                {credential?.eligibility === "NotEligible" && (
                  <Notice tone="warn">
                    Creating or importing another credential cannot change this frozen registry.
                    Clear the current credential from memory before switching identities.
                  </Notice>
                )}
                <div className="action-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={!canProceedAfterCredential(credential) || busy}
                    onClick={() => void onEnterSelectionStage()}
                  >
                    Continue
                  </button>
                </div>
                <DetailsSection summary="Technical details">
                  <div className="field-list">
                    <Field label="Your public voting key">
                      {credential?.public_governance_key_hex ? (
                        <>
                          <span className="field-value">{publicKeyDisplay(credential)}</span>
                          <CopyButton value={credential.public_governance_key_hex} />
                        </>
                      ) : (
                        <span className="field-value">Not loaded</span>
                      )}
                    </Field>
                  </div>
                </DetailsSection>
              </Card>
              </>
              ) : null}

              {selectionStage && confirmation && (
                <>
                  {/* Guided stage 3 — Vote. The editable choice UI is shown
                      only while nothing is durably locked. After a restart in
                      CAST_PENDING the plaintext choice is intentionally not
                      restored from the encrypted pending submission, so a
                      "No selection" editable list would be misleading
                      (Issue 11); the locked card below is shown instead. */}
                  {!castLocked && (
                    !showAllSteps && guidedStageDone("Vote") && reviewStage !== "Vote" ? (
                      <GuidedStageSummary
                        title="Response selected"
                        lines={[
                          voteChoiceText === ""
                            ? "Your choice is saved."
                            : `Your choice: ${voteChoiceText}`,
                        ]}
                        reviewLabel="Change my choice"
                        onReview={() => setReviewStage("Vote")}
                      />
                    ) : stageExpanded("Vote") ? (
                    <>
                    {hideStageDetails("Vote")}
                  <Card title="Choose your response">
                    {/* The CURRENT CANONICAL ballot question, read straight from
                        the confirmed election binding (the SAME source as the
                        choices below), so the question and responses are never
                        separated by scrolling. It is never a second editable copy
                        and it clears/updates on election switch or unload because
                        `confirmation` is reset per election. */}
                    {confirmation.bound.proposal_question && (
                      <p className="selection-question">
                        {confirmation.bound.proposal_question}
                      </p>
                    )}
                    <p className="selection-instruction">
                      {selectionInstructionText(selection ?? confirmation.bound)}
                    </p>
                    <fieldset className="selection-fieldset" disabled={busy || abstaining}>
                      <legend>Ballot responses</legend>
                      <div className="selection-options">
                        {confirmation.candidates.map((option) => {
                          const checked = selectedOptionIds.includes(option.machine_id_hex);
                          const disabled = !checked && selectionAtMax;
                          return (
                            <label className="selection-option selection-option-choice" key={option.machine_id_hex}>
                              <input
                                type="checkbox"
                                checked={checked}
                                disabled={busy || abstaining || disabled}
                                onChange={(e) =>
                                  void onToggleOption(option.machine_id_hex, e.target.checked)
                                }
                              />
                              <span className="selection-option-label">
                                {option.display_name}
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    </fieldset>
                    {selection?.abstention_allowed && (
                      <label className="selection-option selection-abstain">
                        <input
                          type="checkbox"
                          checked={abstaining}
                          disabled={busy}
                          onChange={(e) => void onToggleAbstain(e.target.checked)}
                        />
                        Abstain (choose nothing)
                      </label>
                    )}
                    <div className="selection-status" aria-live="polite">
                      <Pill tone={workflowTone(workflow?.workflow_state)}>
                        {workflowStateText(workflow?.workflow_state)}
                      </Pill>
                      <span>{selectionLiveText}</span>
                    </div>
                    <p className="form-hint">
                      Choosing a response does not submit a vote. You can change your choice
                      until you submit or save your anonymous ballot.
                    </p>
                    {selection && !selection.valid && (
                      <Notice tone="warn">{selection.message}</Notice>
                    )}
                    <div className="action-row">
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={busy || !selection?.selection_loaded}
                        onClick={() => void setBackendSelection([], false)}
                      >
                        Clear selection
                      </button>
                    </div>
                    <DetailsSection summary="Technical details">
                      <div className="field-list">
                        <Field label="Option machine IDs">
                          <ul className="option-list bound-labels">
                            {confirmation.candidates.map((option) => (
                              <li key={option.machine_id_hex} className="option-item">
                                <span>{option.display_name}</span>
                                <span className="hash form-hint">
                                  {option.machine_id_text ?? option.machine_id_hex}
                                </span>
                              </li>
                            ))}
                          </ul>
                        </Field>
                        {selection && (
                          <>
                            <Field label="Approval limits">
                              <span className="field-value">
                                {selection.approval_min}–{selection.approval_max}
                              </span>
                            </Field>
                            <Field label="Lifecycle">
                              <span className="field-value">{selection.lifecycle_state}</span>
                            </Field>
                          </>
                        )}
                      </div>
                    </DetailsSection>
                  </Card>
                    </>
                    ) : null
                  )}

                  {castLocked ? (
                    <Card title={ballotCast ? "Ballot cast" : "Finishing your ballot submission"}>
                      {ballotCast ? (
                        <>
                          {castViaAuthenticatedOnline ? (
                            <>
                              <Notice tone="ok">
                                <strong>Your ballot was accepted ✓</strong>
                                <br />
                                The ballot office returned an authenticated receipt for this exact
                                ballot. Your vote is locked for this election and your choice can
                                no longer be changed here.
                              </Notice>
                              <p className="card-body">
                                Final inclusion can be independently checked from the published
                                election archive after voting closes.
                              </p>
                              <DetailsSection summary="Receipt details">
                                <p className="card-body">
                                  An authenticated receipt confirms the organizer received your
                                  encrypted ballot. Acceptance, counting, final-record inclusion,
                                  and Ootle anchoring are confirmed separately from the published
                                  record.
                                </p>
                                {privateResult && "receipt_state" in privateResult && (
                                  <div className="field-list">
                                    <Field label="Receipt">
                                      <span className="field-value">
                                        {receiptStateText(privateResult.receipt_state)}
                                      </span>
                                    </Field>
                                    {"package_digest_hex" in privateResult && (
                                      <Field label="Ballot package digest">
                                        <HashValue value={privateResult.package_digest_hex} />
                                      </Field>
                                    )}
                                  </div>
                                )}
                              </DetailsSection>
                            </>
                          ) : (
                            <>
                              <Notice tone="ok">
                                Your ballot for this election was exported and cast on this device.
                                Your choice can no longer be changed here.
                              </Notice>
                              <p className="card-body">
                                Exporting released your ballot file for delivery. It does not mean the
                                organizer has received, accepted, counted, included, or anchored it —
                                those are confirmed separately from the published record.
                              </p>
                              <p className="card-body">
                                Deliver the exported ballot file through the election's approved intake
                                method.
                              </p>
                            </>
                          )}
                          <DetailsSection summary="Why can't I change it?">
                            <p className="card-body">
                              This installation locks your credential for this election once a
                              ballot is exported, so you are not misled into thinking a released
                              ballot can be replaced. Even on another computer, the election
                              independently rejects a second ballot from the same credential using
                              its election-scoped duplicate check — that cryptographic rule, not
                              this local lock, is what guarantees one vote.
                            </p>
                          </DetailsSection>
                        </>
                      ) : (
                        <>
                          <Notice tone="warn">
                            Your ballot for this election is being finalized, and your choice is
                            locked. Return to this screen to finish it. If it cannot be completed
                            safely, your credential stays locked for this election so the one-vote
                            rule is never weakened. Your vote was not erased and you do not need to
                            choose again.
                          </Notice>
                          <p className="card-body">
                            Your previously prepared ballot is locked. The plaintext choice is not
                            restored from the encrypted pending submission; you can retry the same
                            encrypted submission below without creating a new ballot.
                          </p>
                          <div className="field-list">
                            <Field label="Status">
                              <Pill tone={workflowTone(workflow?.workflow_state)}>
                                {workflowStateText(workflow?.workflow_state)}
                              </Pill>
                            </Field>
                          </div>
                        </>
                      )}
                    </Card>
                  ) : (
                  <>
                  {/* Guided stage 4 — Privacy: full while current; once the
                      anonymous ballot is prepared, the proof-generation card
                      collapses and the prepared-ballot review below is the
                      completed-stage summary. */}
                  {(showAllSteps || currentStageKey === "Privacy") && (
                  <Card title="Protect your vote">
                    <p className="card-body">
                      Create the anonymous eligibility proof for your ballot:
                    </p>
                    <ul className="privacy-notice-list">
                      <li>✓ Your eligibility is proven anonymously.</li>
                      <li>✓ Your identity is not included with your choice.</li>
                      <li>
                        ✓ The same credential cannot produce two accepted ballots in this
                        election.
                      </li>
                    </ul>
                    <Notice tone="info">
                      This proves that your credential belongs to the eligible voter set without
                      revealing which eligible voter you are. Your ballot choice is not
                      permanently sealed and may appear in the final verifiable election record.
                    </Notice>
                    <p className="form-hint">
                      Your choice and the prepared proof are held only in this session until you
                      submit or save your ballot. If the app closes first, you will re-select and
                      re-create the proof — no ballot is cast and nothing is sent until you submit.
                    </p>
                    <div className="field-list">
                      <Field label="Status">
                        <Pill tone={workflowTone(workflow?.workflow_state)}>
                          {workflowStateText(workflow?.workflow_state)}
                        </Pill>
                      </Field>
                      <Field label="Preparation">
                        <span className="field-value">
                          {workflow?.prepared_ballot.message ?? "No ballot has been prepared."}
                        </span>
                      </Field>
                    </div>
                    {busy && workflow?.prepared_ballot.state !== "Ready" && (
                      <Notice tone="info">
                        Creating your anonymous eligibility proof… This can take a moment.
                      </Notice>
                    )}
                    <div className="action-row">
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={
                          busy ||
                          !workflow?.can_prepare_ballot ||
                          workflow?.prepared_ballot.state === "Ready"
                        }
                        onClick={() => void onGenerateProof()}
                      >
                        Create anonymous eligibility proof
                      </button>
                    </div>
                    <DetailsSection summary="How does anonymous eligibility work?">
                      <p className="card-body">
                        Eligibility is proven with the Tari Triptych implementation. The proof is
                        bound to this election and carries a unique election-scoped linking tag,
                        so a second ballot from the same voter is detected and rejected — without
                        revealing which eligible voter cast it. The proof is constructed and
                        verified in the Rust backend; this screen never sees secret material.
                      </p>
                    </DetailsSection>
                  </Card>
                  )}
                  {/* Completed Privacy-stage summary / Submit-stage lead-in:
                      the prepared anonymous ballot review with delivery
                      options. */}
                  {workflow?.prepared_ballot.summary && (
                  <Card title="Your anonymous ballot is ready">
                        <div className="field-list">
                          <Field label="Election">
                            <span className="field-value">
                              {confirmation.bound.election_id_text ??
                                confirmation.bound.election_id_hex}
                            </span>
                          </Field>
                          <Field label="Your choice">
                            <span className="field-value">
                              {workflow.prepared_ballot.summary.selected_display_labels.join(", ") || "Abstention"}
                            </span>
                          </Field>
                          <Field label="Status">
                            <Pill tone="ok">Ballot prepared</Pill>
                          </Field>
                          <Field label="Local verification">
                            <Pill tone="ok">Verified</Pill>
                          </Field>
                        </div>
                        <DetailsSection summary="Technical details">
                          <div className="field-list">
                            <Field label="Package digest">
                              <HashValue value={workflow.prepared_ballot.summary.package_digest_hex} />
                            </Field>
                            <Field label="Proof suite">
                              <span className="field-value">
                                {workflow.prepared_ballot.summary.proof_suite_id}
                              </span>
                            </Field>
                            <Field label="Package size">
                              <span className="field-value">
                                {formatByteSize(workflow.prepared_ballot.summary.canonical_package_bytes)}
                              </span>
                            </Field>
                          </div>
                        </DetailsSection>
                        <div className="action-row">
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={busy}
                            onClick={() => void onChangeChoice()}
                          >
                            Change my choice
                          </button>
                        </div>
                        <p className="form-hint">
                          Continue to private delivery below to submit now. You can still change
                          your choice until you submit or save your anonymous ballot.
                        </p>

                        {/* Offline delivery stays available but collapsed by
                            default while a private online route exists; when no
                            online route is available it starts open. The voter
                            can always open it deliberately. */}
                        <details
                          className="details-section"
                          open={offlineOpenOverride ?? !onlineRouteAvailable}
                          onToggle={(e) =>
                            setOfflineOpenOverride((e.target as HTMLDetailsElement).open)
                          }
                        >
                          <summary className="details-summary">Other delivery options</summary>
                          <div className="details-body">
                        <p className="card-body">
                          Offline submission: save an encrypted ballot file and deliver it through
                          the election&rsquo;s approved manual method. Nothing is sent over the
                          network when you save.
                        </p>
                        <Notice tone="warn">
                          Once you save or send this ballot for submission, your vote is locked on
                          this device. After this ballot is exported for submission, your vote for this election
                          cannot be changed on this device. You can still change your choice until
                          you save.
                        </Notice>
                        <div className="action-row">
                          <button
                            type="button"
                            className="btn btn-primary"
                            disabled={busy || !workflow.prepared_ballot.ready_to_export}
                            onClick={() => setConfirmCast(true)}
                          >
                            Save encrypted ballot file
                          </button>
                        </div>
                          </div>
                        </details>
                        {transport &&
                          (transport.managed_tor_available ||
                          transport.split_trust_relay_available ? (
                            <>
                              <h3 className="submission-route-heading">
                                Private online submission · Tor
                              </h3>
                              <p className="form-hint">
                                Send the encrypted ballot directly to the organizer over a private
                                online route. Submission is confirmed only after an authenticated
                                organizer receipt is verified. The verified ballot package stays in
                                the Rust backend; this screen never sends ballot bytes itself.
                              </p>
                              <div className="selection-options" role="radiogroup" aria-label="Private submission route">
                                <label className="selection-option">
                                  <input
                                    type="radio"
                                    name="private-route"
                                    checked={privateRoute === "ManagedTor"}
                                    disabled={busy || !transport.managed_tor_available}
                                    onChange={() => setPrivateRoute("ManagedTor")}
                                  />
                                  <span className="selection-option-label">Private online submission</span>
                                  <span className="selection-option-desc">Uses Tor to help separate your network identity from your ballot submission.</span>
                                </label>
                                <label className="selection-option">
                                  <input
                                    type="radio"
                                    name="private-route"
                                    checked={privateRoute === "SplitTrustRelay"}
                                    disabled={busy || !transport.split_trust_relay_available}
                                    onChange={() => setPrivateRoute("SplitTrustRelay")}
                                  />
                                  <span className="selection-option-label">Split-trust relay</span>
                                  <span className="selection-option-desc">An alternative private route that splits trust between independent relays.</span>
                                </label>
                              </div>
                              <div className="action-row">
                                <button
                                  type="button"
                                  className="btn btn-primary"
                                  disabled={
                                    busy ||
                                    (privateRoute === "ManagedTor" && !transport.managed_tor_available) ||
                                    (privateRoute === "SplitTrustRelay" && !transport.split_trust_relay_available)
                                  }
                                  onClick={() => void onSubmitPrivately()}
                                >
                                  Submit vote privately
                                </button>
                              </div>
                            </>
                          ) : managedTorFeaturePresent ? (
                            // The controlled managed-Tor test transport IS available
                            // in this build, so the generic production "unavailable"
                            // message would contradict the active card below (Issue 9).
                            <Notice tone="info">
                              Submit through the private connection in the controlled-test card
                              below, or save the ballot file above and deliver it through the
                              election's approved intake method.
                            </Notice>
                          ) : (
                            <>
                              <Notice tone="info">
                                Online private submission is not available in this build. Save the
                                ballot file above and deliver it through the election's approved
                                intake method.
                              </Notice>
                              <DetailsSection summary="Transport details">
                                <p className="card-body">{transport.message}</p>
                              </DetailsSection>
                            </>
                          ))}
                        {privateResult && (
                          <Notice tone={receiptStateIsAccepted(privateResult.receipt_state) ? "ok" : "info"}>
                            {receiptStateText(privateResult.receipt_state)}
                            {"reduced_anonymity" in privateResult && privateResult.reduced_anonymity && " Reduced anonymity / small population."}
                            {"cast_lock_state" in privateResult && privateResult.cast_lock_state === "CAST" && " Ballot accepted; receipt authenticated."}
                            {"cast_lock_state" in privateResult && privateResult.cast_lock_state === "CAST_PENDING" && " Submission uncertain; ballot remains locked. Retry when ready."}
                            {"released" in privateResult && privateResult.released && " Delivery authenticated (this is not final archive or Ootle anchor)."}
                          </Notice>
                        )}
                      </Card>
                  )}
                  </>
                  )}

                  {/* managed-tor-test: private submission controls. Rendered ONLY
                      when the controlled-test feature is actually present in this
                      build (a production build without `managed-tor-test` never
                      shows this card — the backend refuses those commands and the
                      status command is absent, so managedTorFeaturePresent stays
                      false). When present, it is shown whenever a ballot is Ready
                      to submit OR the durable cast state is CAST_PENDING/CAST, so
                      the recovery/status route survives a restart even though the
                      transient prepared-ballot state is gone (Issue 2). */}
                  {managedTorTestCardVisible({
                    featurePresent: managedTorFeaturePresent,
                    preparedReady: workflow?.prepared_ballot.state === "Ready",
                    castState,
                  }) && submitStageVisible && (
                    <Card title="Submit your ballot privately">
                      {/* Unmistakable, authoritative status derived from the
                          DURABLE cast state (Issues 4/17), so SUCCESS and PENDING
                          survive navigation/restart without any transient result. */}
                      <Notice tone={privateStatus.tone}>
                        <strong>{privateStatus.title}</strong>
                        <br />
                        {privateStatus.detail}
                      </Notice>

                      {/* Bounded automatic retry of the EXACT same encrypted
                          submission while the onion route is transiently
                          unreachable. No new ballot is created. */}
                      {autoRetryAttempt > 0 && (
                        <div className="config-stack">
                          <p className="form-hint" role="status" aria-live="polite">
                            The ballot office isn&rsquo;t reachable yet — this can happen briefly
                            after it restarts its private connection. Retrying the same ballot…
                            (Retry {autoRetryAttempt} of{" "}
                            {PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length})
                            <br />
                            Your vote is locked. The app waits a little longer between later
                            retries and re-sends the same encrypted ballot — it never creates
                            another vote. You can Stop retrying and retry manually anytime.
                          </p>
                          <div className="action-row">
                            <button
                              type="button"
                              className="btn btn-secondary"
                              onClick={() => onStopAutoRetry()}
                            >
                              Stop retrying
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Private-submission errors are shown HERE, next to the
                          controls, not only at the top of the screen (Issue 5). */}
                      <BackendErrorNotice
                        error={privateError}
                        onDismiss={() => setPrivateError(null)}
                      />

                      {((!managedTorStatus?.configured && !ballotCast) ||
                        (reconfiguring && !castLocked)) &&
                        !managedTorStatus?.tor_running && (
                        <div className="config-stack">
                          {reconfiguring && managedTorStatus?.configured && (
                            <Notice tone="warn">
                              Choose the correct ballot-office connection file for this election.
                              Replacing it does not change your prepared ballot, your response, or
                              your anonymous proof — it only updates which ballot office you connect
                              to. A file from another election is still rejected.
                            </Notice>
                          )}
                          <p className="form-hint">
                            Connecting privately runs Tor for you — there is no port, torrc, or
                            Tor data directory to set up. You only need the ballot-office
                            connection file for this election. Nothing is sent until you submit.
                          </p>
                          <div className="field-list">
                            <Field label="Tor installed">
                              {voterTorStatus === null
                                ? "Checking…"
                                : voterTorStatus.tor_found
                                  ? "Found ✓"
                                  : "Not found"}
                            </Field>
                            <Field label="Ballot office">
                              {!voterBundlePath
                                ? "Connection file required"
                                : reconfiguring
                                  ? "Selected — will be re-checked on connect"
                                  : "Verified for this election ✓"}
                            </Field>
                          </div>

                          {voterTorStatus !== null && !voterTorStatus.tor_found && (
                            <>
                              <Notice tone="info">
                                Tor was not found automatically. Select a Tor executable once; the
                                app remembers it and never downloads or installs Tor.
                              </Notice>
                              <div className="action-row">
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy || !shellAvailable}
                                  onClick={() => void onBrowseTorExe()}
                                >
                                  Select Tor executable
                                </button>
                              </div>
                            </>
                          )}

                          {(!voterBundlePath || reconfiguring) && (
                            <>
                              {!voterBundlePath && (
                                <Notice tone="info">
                                  Ballot-office connection file required. Ask the ballot office for
                                  the voter transport bundle file, then select it here.
                                </Notice>
                              )}
                              <div className="action-row">
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy || !shellAvailable}
                                  onClick={() => void onBrowseVoterBundle()}
                                >
                                  {reconfiguring && voterBundlePath
                                    ? "Choose a different ballot-office connection file"
                                    : "Select ballot-office connection file"}
                                </button>
                              </div>
                            </>
                          )}

                          <div className="action-row">
                            <button
                              type="button"
                              className="btn btn-primary"
                              disabled={
                                busy ||
                                !voterBundlePath ||
                                !(voterTorStatus?.tor_found ?? false)
                              }
                              onClick={() => void onConnectPrivately()}
                            >
                              Connect privately
                            </button>
                            {reconfiguring && managedTorStatus?.configured && (
                              <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={busy}
                                onClick={() => setReconfiguring(false)}
                              >
                                Cancel
                              </button>
                            )}
                          </div>

                          <DetailsSection summary="Advanced">
                            <p className="form-hint">
                              Override the auto-detected Tor executable or supply a manual Tor data
                              directory. Normal use needs neither — leave them blank for the
                              app-owned, election-scoped defaults.
                            </p>
                            <div className="form-row form-row--full">
                              <label htmlFor="tor-exe-path">Tor executable (optional override)</label>
                              <div className="file-row">
                                <input
                                  id="tor-exe-path"
                                  type="text"
                                  value={torExePath}
                                  onChange={(e) => setTorExePath(e.target.value)}
                                  placeholder="auto-detected"
                                />
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy || !shellAvailable}
                                  onClick={() => void onBrowseTorExe()}
                                >
                                  Browse
                                </button>
                              </div>
                            </div>
                            <div className="form-row form-row--full">
                              <label htmlFor="voter-bundle-path">Voter transport bundle</label>
                              <div className="file-row">
                                <input
                                  id="voter-bundle-path"
                                  type="text"
                                  value={voterBundlePath}
                                  onChange={(e) => setVoterBundlePath(e.target.value)}
                                  placeholder="C:\test-root\voter-public-bundle.cbor"
                                />
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy || !shellAvailable}
                                  onClick={() => void onBrowseVoterBundle()}
                                >
                                  Browse
                                </button>
                              </div>
                            </div>
                            <div className="form-row form-row--full">
                              <label htmlFor="tor-data-dir">Voter Tor data directory (optional)</label>
                              <div className="file-row">
                                <input
                                  id="tor-data-dir"
                                  type="text"
                                  value={torDataDir}
                                  onChange={(e) => setTorDataDir(e.target.value)}
                                  placeholder="auto (app-owned, election-scoped)"
                                />
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy || !shellAvailable}
                                  onClick={() => void onBrowseTorDataDir()}
                                >
                                  Browse
                                </button>
                              </div>
                            </div>
                            <div className="action-row">
                              <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={busy || !voterBundlePath}
                                onClick={() => void onConfigureManagedTor()}
                              >
                                Configure only (do not start)
                              </button>
                            </div>
                          </DetailsSection>
                        </div>
                      )}

                      {managedTorStatus?.configured &&
                        !managedTorStatus.tor_running &&
                        !ballotCast &&
                        !reconfiguring && (
                        <div className="action-row">
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={busy}
                            onClick={() => void onStartManagedTor()}
                          >
                            Start private connection
                          </button>
                          {/* Pre-release recovery: replace a configured
                              ballot-office connection (e.g. one bound to the
                              wrong election) without restarting the app,
                              reloading the election, or disturbing the prepared
                              ballot. Only before the ballot is durably locked —
                              a CAST_PENDING staged envelope is bound to its
                              original release descriptor and is retried exactly,
                              never re-pointed. */}
                          {!castLocked && (
                            <button
                              type="button"
                              className="btn btn-secondary"
                              disabled={busy}
                              onClick={() => {
                                setPrivateError(null);
                                setReconfiguring(true);
                              }}
                            >
                              Change ballot-office connection
                            </button>
                          )}
                        </div>
                      )}

                      {/* Fresh Submit is offered ONLY when nothing is durably
                          locked (Issues 3/18). CAST_PENDING shows Retry instead,
                          and CAST shows neither. */}
                      {managedTorStatus?.tor_running && !castLocked && (
                        <div className="action-row">
                          <button
                            type="button"
                            className="btn btn-primary"
                            disabled={busy || !workflow?.prepared_ballot.ready_to_export}
                            onClick={() => void onSubmitPrivately()}
                          >
                            Submit vote privately
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={busy}
                            onClick={() => void onStopManagedTor()}
                          >
                            Stop private connection
                          </button>
                        </div>
                      )}

                      {/* CAST_PENDING recovery: retries the EXACT staged envelope
                          only; it never prepares or sends a new ballot. No fresh
                          Submit is shown here (Issue 3). */}
                      {castPending && (
                        <div className="config-stack">
                          {managedTorStatus?.configured && !managedTorStatus.tor_running && (
                            <Notice tone="info">
                              Private connection stopped. Reconnect privately, then retry the
                              exact same encrypted ballot — a new vote will not be created.
                            </Notice>
                          )}
                          <div className="action-row">
                            <button
                              type="button"
                              className="btn btn-primary"
                              disabled={busy}
                              onClick={() => void onRetryPrivateSubmission()}
                            >
                              Retry private submission
                            </button>
                            {managedTorStatus?.tor_running ? (
                              <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={busy}
                                onClick={() => void onStopManagedTor()}
                              >
                                Stop private connection
                              </button>
                            ) : (
                              managedTorStatus?.configured && (
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  disabled={busy}
                                  onClick={() => void onStartManagedTor()}
                                >
                                  Reconnect privately
                                </button>
                              )
                            )}
                          </div>
                        </div>
                      )}

                      <DetailsSection summary="Advanced connection details">
                        {privateStageLabel && (
                          <Notice tone="info">
                            <strong>Last attempt diagnostic</strong>
                            <br />
                            {privateStageLabel}
                          </Notice>
                        )}
                        <p className="form-hint">
                          Connection process:{" "}
                          {managedTorStatus?.tor_running
                            ? managedTorStatus.socks_ready
                              ? "running (local private endpoint ready)"
                              : "running"
                            : "not running"}
                        </p>
                        {voterTorStatus?.resolved_tor_path && (
                          <p className="form-hint">
                            Tor executable: <code>{voterTorStatus.resolved_tor_path}</code>
                          </p>
                        )}
                        <p className="form-hint">
                          Tor data directory:{" "}
                          {torDataDir ? <code>{torDataDir}</code> : "automatic (app-owned, election-scoped)"}
                        </p>
                        {managedTorStatus?.socks_addr && (
                          <p className="form-hint">
                            Local SOCKS endpoint: <code>{managedTorStatus.socks_addr}</code>
                          </p>
                        )}
                        {managedTorStatus?.onion_hostname && (
                          <p className="form-hint">
                            Organizer onion (public route):{" "}
                            <code>{managedTorStatus.onion_hostname}</code>
                          </p>
                        )}
                        {managedTorStatus?.descriptor_fingerprint && (
                          <p className="form-hint">
                            Descriptor fingerprint:{" "}
                            <code>{managedTorStatus.descriptor_fingerprint}</code>
                          </p>
                        )}
                        <p className="card-body">
                          Tor mitigates submission network metadata. The cryptographic ballot
                          protocol provides anonymous eligibility and linkability properties. These
                          are distinct concepts; Tor alone does not provide voting anonymity. A
                          &ldquo;ready&rdquo; private connection means the managed Tor process is
                          running with a working local SOCKS listener; it does not by itself mean the
                          organizer is reachable or that a ballot was delivered.
                        </p>
                      </DetailsSection>
                    </Card>
                  )}
                </>
              )}
            </>
          )}
        </>
      )}

      {election && !confirmation && (
        <Card title="Loaded election (read-only)">
          <div className="field-list">
            <Field label="Election">
              {election.election_id_text ?? election.election_id_hex}
            </Field>
            <Field label="Lifecycle">
              <LifecyclePill state={election.lifecycle_state} />
            </Field>
          </div>
        </Card>
      )}

      {confirmCast && (
        <ConfirmDialog
          title="Save this ballot file?"
          body={
            <>
              <p>
                After this ballot is exported for submission, your vote for this election cannot
                be changed on this device.
              </p>
              <p>
                Saving writes an encrypted ballot file to this device for offline delivery.
                Nothing is sent over the network, and it does not mean the organizer has received,
                accepted, or counted it.
              </p>
            </>
          }
          confirmLabel="Save encrypted ballot file"
          confirmTone="danger"
          busy={busy}
          onConfirm={() => {
            setConfirmCast(false);
            void onExportBallot();
          }}
          onCancel={() => setConfirmCast(false)}
        />
      )}
    </>
  );
}
