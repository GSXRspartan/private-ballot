import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import {
  pickBallotPackageFile,
  pickDirectory,
  pickElectionArtifact,
  pickElectionStatusExportPath,
  pickGovernanceDocument,
  pickTorExecutable,
} from "../api/dialog";
import {
  recallManagedTorConfig,
  rememberManagedTorConfig,
} from "../api/managedTorConfigMemory";
import type {
  GuiArchiveWriteResultV1,
  GuiCommandError,
  GuiLiveAnchorConfigResultV1,
  GuiLiveAnchorStepResultV1,
  GuiTallySummaryV1,
  OrganizerIntakeStatusV1,
} from "../api/types";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { intakeCanImport, intakeResultMessage, intakeResultTitle } from "../intake";
import {
  canShowTally,
  canWriteFinalArchive,
  coarseBucketLabel,
  describeLeadingOutcome,
  formatPercent,
  nextOrganizerStep,
  organizerGuidedControls,
  organizerLifecycleSteps,
  organizerPhaseHeading,
  participationAccessibleText,
  participationIsDisclosed,
  participationVisibilityLabel,
  sealedParticipationText,
} from "../lifecycle";
import type { OrganizerControlKey } from "../lifecycle";
import { useAppState } from "../state/AppState";
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
import { LockIcon } from "../components/icons";
import { ProgressSteps } from "../components/ProgressSteps";
import { ParticipationTrack } from "../components/ParticipationTrack";
import { ResultBars } from "../components/ResultBars";

function basename(path: string): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

/**
 * Manage Election (organizer): Load Election via native file pickers, then walk
 * the append-only lifecycle. Loading validates canonical encodings, recomputes
 * both commitments and the manifest hash, enforces the production proof-suite
 * policy, and freezes the lifecycle — all through gui-core. This screen contains
 * no protocol logic and never edits the frozen canonical artifacts.
 */
export function ManageElection() {
  const {
    election,
    electionAuthority,
    participation,
    refreshParticipation,
    backendError,
    shellAvailable,
    loadElection,
    loadElectionFolder,
    unloadElection,
    runLifecycle,
    recordAction,
    dismissError,
    selectedArtifactPaths,
  } = useAppState();

  const [folderBusy, setFolderBusy] = useState(false);
  const [manifestPath, setManifestPath] = useState("");
  const [registryPath, setRegistryPath] = useState("");
  const [optionSetPath, setOptionSetPath] = useState("");
  const [packagePath, setPackagePath] = useState("");
  const [archiveDir, setArchiveDir] = useState("");
  const [archiveGovernanceDocPath, setArchiveGovernanceDocPath] = useState<string | null>(null);
  const [lastIntake, setLastIntake] = useState<Awaited<ReturnType<typeof api.intakeBallotPackage>> | null>(null);
  const [tally, setTally] = useState<GuiTallySummaryV1 | null>(null);
  const [syncSummary, setSyncSummary] =
    useState<Awaited<ReturnType<typeof api.syncPrivateIntake>> | null>(null);
  const [inboxPath, setInboxPath] = useState<string | null>(null);
  const [syncBusy, setSyncBusy] = useState(false);
  // Organizer near-one-click private intake. torExePath is a GLOBAL convenience
  // path the backend re-validates and may fall back from to its allowlist; the
  // frontend never chooses ports, torrc, onion, or the inbox path.
  const [organizerStatus, setOrganizerStatus] = useState<OrganizerIntakeStatusV1 | null>(null);
  const [organizerBusy, setOrganizerBusy] = useState(false);
  const [intakeTorExePath, setIntakeTorExePath] = useState(
    () => recallManagedTorConfig().torExePath,
  );
  const [bundleExportPath, setBundleExportPath] = useState<string | null>(null);
  // Bounded automatic inbox sync: a single in-flight guard and the last observed
  // intake-worker accepted count. Auto-sync calls the SAME authoritative
  // sync_private_intake path only when a NEW Tor delivery is observed, so it
  // never churns workspace revisions while idle and never becomes a busy loop.
  const autoSyncBusyRef = useRef(false);
  const prevAcceptedRef = useRef<number | null>(null);
  const [archiveResult, setArchiveResult] = useState<GuiArchiveWriteResultV1 | null>(null);
  const [localError, setLocalError] = useState<GuiCommandError | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [confirmFinalize, setConfirmFinalize] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  // Organizer-side Ootle aggregate anchor publish state.
  const [anchorConfigResult, setAnchorConfigResult] =
    useState<GuiLiveAnchorConfigResultV1 | null>(null);
  const [anchorStepResult, setAnchorStepResult] =
    useState<GuiLiveAnchorStepResultV1 | null>(null);
  const [anchorBusy, setAnchorBusy] = useState(false);
  const [anchorNetwork, setAnchorNetwork] = useState("esmeralda");
  const [anchorWalletdEndpoint, setAnchorWalletdEndpoint] = useState(
    "http://127.0.0.1:12009",
  );
  const [anchorIndexerEndpoint, setAnchorIndexerEndpoint] = useState(
    "http://127.0.0.1:12500",
  );
  const [anchorAccountRef, setAnchorAccountRef] = useState("organizer-fee-account");
  const [anchorFeeComponent, setAnchorFeeComponent] = useState("");
  const [anchorSealSignerKind, setAnchorSealSignerKind] = useState("account");
  const [anchorSealSignerId, setAnchorSealSignerId] = useState("0");
  const [anchorSealPubKey, setAnchorSealPubKey] = useState("");
  const [anchorMaxFee, setAnchorMaxFee] = useState(1000);
  const [anchorFloor, setAnchorFloor] = useState(2);
  const [anchorDedicatedWallet, setAnchorDedicatedWallet] = useState(false);
  // The frontend only chooses whether to attach the token; the backend reads
  // the single fixed WALLETD_AUTH_TOKEN variable and never an arbitrary name.
  const [anchorUseAuth, setAnchorUseAuth] = useState(false);
  // Guided organizer workspace (progressive disclosure, presentation only).
  // Default = guided mode: the current lifecycle phase's controls are
  // prominent, completed phases collapse to compact summaries, and future
  // phases stay out of the main view. `showAllControls` restores the complete
  // control surface for technical review/debugging; it never changes a gate,
  // never enables a disabled control, and never creates an alternate command
  // path.
  const [showAllControls, setShowAllControls] = useState(false);

  const presentation = presentationFor(election);
  const lifecycle = election?.lifecycle_state ?? null;
  // ROLE GATING (presentation mirror of the Rust authority gate): organizer
  // controls render ONLY for a session the backend established as
  // organizer-owned (freeze or organizer-workspace resume). An election
  // imported from public artifacts is a VOTER context on this screen: it gets
  // a read-only view and an explicit explanation, never ballot-office controls.
  // This is defense-in-depth UX only — every organizer command is rejected by
  // the backend (`GUI_ORGANIZER_AUTHORITY_REQUIRED`) even if invoked directly.
  const isOrganizer = election !== null && electionAuthority === "organizer";
  const isImportedVoter = election !== null && electionAuthority === "imported_voter";
  const canAct = shellAvailable && election !== null;
  const canImportBallot = canAct && intakeCanImport(shellAvailable, lifecycle);
  const canLoad = shellAvailable && manifestPath !== "" && registryPath !== "" && optionSetPath !== "";
  const tallyAvailable = canShowTally(lifecycle);
  const finalArchiveAvailable = canWriteFinalArchive(lifecycle);
  const finalArchiveError =
    localError !== null &&
    (localError.code === "GUI_ARCHIVE_TARGET_NOT_EMPTY" ||
      localError.code === "GUI_ARCHIVE_NOT_FINALIZED" ||
      localError.context === "archive-directory");
  const participationSealed =
    participation !== null && participation.participation_visibility === "SEALED_UNTIL_CLOSE";
  const participationDisclosed = participationIsDisclosed(participation);
  // Plain-language organizer guidance derived ONLY from the real lifecycle
  // state plus this session's tally/archive results. Never invents states.
  const nextStep = nextOrganizerStep({
    lifecycle,
    tallyComputed: tally !== null,
    archiveWritten: archiveResult !== null,
  });

  // Guided progressive disclosure derived ONLY from the real lifecycle state.
  // `organizerGuidedControls` returns null for no/unknown lifecycle, which is
  // the safe fallback: the full control surface renders exactly as before.
  const guidedControls = showAllControls ? null : organizerGuidedControls(lifecycle);
  const guidedMode = guidedControls !== null;
  const showControl = (control: OrganizerControlKey): boolean =>
    guidedControls === null || guidedControls.includes(control);
  const phaseHeading = guidedMode ? organizerPhaseHeading(lifecycle) : null;
  const resultsVisible =
    !guidedMode ||
    showControl("tally") ||
    showControl("verify") ||
    showControl("finalArchive") ||
    showControl("anchor");
  // Compact completed-phase summaries, derived only from existing state (the
  // real lifecycle, the provisioned-transport flag, this session's tally and
  // archive results). A summary is listed only when its full card is not
  // currently prominent; Show all election controls remains the way to inspect
  // any completed step in full.
  const completedSummaries: string[] = [];
  if (guidedMode && lifecycle !== null) {
    if (lifecycle !== "FROZEN") {
      if (organizerStatus?.transport_provisioned && !showControl("intake")) {
        completedSummaries.push("Private intake configured");
      }
      if (organizerStatus?.transport_provisioned && !showControl("materials")) {
        completedSummaries.push("Voter materials available");
      }
      completedSummaries.push("Voting opened");
    }
    if (lifecycle === "CLOSED" || lifecycle === "VERIFIED" || lifecycle === "FINALIZED") {
      completedSummaries.push("Voting closed");
    }
    if (tally !== null && !showControl("tally")) {
      completedSummaries.push("Tally computed");
    }
    if (lifecycle === "VERIFIED" || lifecycle === "FINALIZED") {
      completedSummaries.push("Result verified");
    }
    if (lifecycle === "FINALIZED") {
      completedSummaries.push("Election finalized");
    }
    if (archiveResult !== null && !showControl("finalArchive")) {
      completedSummaries.push("Final archive written");
    }
  }

  const showError = (error: unknown) => {
    setLocalError(
      error instanceof BackendError
        ? error.payload
        : {
            code: "GUI_UNEXPECTED_ERROR",
            category: "INVALID_INPUT",
            context: null,
            message: "an unexpected frontend/backend boundary error occurred",
          },
    );
  };

  const clearLocalError = () => setLocalError(null);

  const onPickManifest = async () => {
    clearLocalError();
    const picked = await pickElectionArtifact("Choose election definition file");
    if (picked !== null) setManifestPath(picked);
  };
  const onPickRegistry = async () => {
    clearLocalError();
    const picked = await pickElectionArtifact("Choose eligible voter list file");
    if (picked !== null) setRegistryPath(picked);
  };
  const onPickOptionSet = async () => {
    clearLocalError();
    const picked = await pickElectionArtifact("Choose ballot options file");
    if (picked !== null) setOptionSetPath(picked);
  };

  const onLoad = async () => {
    clearLocalError();
    try {
      await loadElection(manifestPath, registryPath, optionSetPath);
      setTally(null);
      setArchiveResult(null);
      setLastIntake(null);
    } catch (error) {
      showError(error);
    }
  };

  const onOpenElectionFolder = async () => {
    clearLocalError();
    const folder = await pickDirectory("Select the election folder itself (do not open it)");
    if (folder === null) return;
    setFolderBusy(true);
    try {
      await loadElectionFolder(folder);
      setTally(null);
      setArchiveResult(null);
      setLastIntake(null);
    } catch (error) {
      showError(error);
    } finally {
      setFolderBusy(false);
    }
  };

  const onIntake = async () => {
    clearLocalError();
    try {
      const picked = await pickBallotPackageFile();
      if (picked === null) return;
      setPackagePath(picked);
      const result = await api.intakeBallotPackage(picked);
      setLastIntake(result);
      recordAction(result.accepted ? "Ballot accepted" : `Ballot rejected (${result.code})`);
      // Refresh participation so the dashboard reflects the new acceptance
      // state. While OPEN the backend still returns sealed numerics, so no
      // sealed value is disclosed by this refresh.
      await refreshParticipation();
    } catch (error) {
      showError(error);
    }
  };

  const onTally = async () => {
    clearLocalError();
    try {
      const result = await api.currentTally();
      setTally(result);
      recordAction("Computed tally");
    } catch (error) {
      showError(error);
    }
  };

  const onSyncPrivateIntake = async () => {
    clearLocalError();
    setSyncBusy(true);
    try {
      const summary = await api.syncPrivateIntake();
      setSyncSummary(summary);
      await refreshParticipation();
      recordAction(
        summary.newly_accepted > 0
          ? `Synced ${summary.newly_accepted} ballot(s) from private intake`
          : "Synced private intake (no new ballots)",
      );
    } catch (error) {
      showError(error);
    } finally {
      setSyncBusy(false);
    }
  };

  const onRevealInboxPath = async () => {
    clearLocalError();
    try {
      setInboxPath(await api.privateIntakeInboxPath());
    } catch (error) {
      showError(error);
    }
  };

  // Read-only organizer intake status. Never starts Tor or provisions anything.
  const refreshOrganizerStatus = async () => {
    if (!shellAvailable || !election) return;
    try {
      setOrganizerStatus(await api.organizerTorStatus(intakeTorExepathOrUndefined()));
    } catch {
      // Status is best-effort; a failure leaves the last known status visible.
    }
  };

  const intakeTorExepathOrUndefined = () =>
    intakeTorExePath.length > 0 ? intakeTorExePath : undefined;

  // Load intake status when an election is loaded so the operator sees the
  // Tor/transport state without acting. Read-only. Also reset the per-election
  // auto-sync observation baseline so the next tick performs a first-observation
  // reconciliation for the newly loaded/recovered election.
  useEffect(() => {
    prevAcceptedRef.current = null;
    // Only an organizer context may query ballot-office intake status; the
    // backend rejects it for imported voter sessions, so we never ask.
    if (election && shellAvailable && isOrganizer) void refreshOrganizerStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election?.manifest_hash_hex, shellAvailable, isOrganizer]);

  // Restart reconciliation: when an OPEN election is loaded/recovered, run ONE
  // authoritative reconciliation so a durable inbox package accepted before an
  // application restart is imported into the organizer workspace even if the Tor
  // intake worker is not (yet) running again. Best-effort and idempotent: the
  // backend writes a workspace revision only when a package is newly accepted, so
  // an empty/duplicate-only inbox changes nothing; a not-open lifecycle simply
  // has nothing to reconcile and is skipped.
  useEffect(() => {
    if (!shellAvailable || !election || lifecycle !== "OPEN" || !isOrganizer) return;
    let cancelled = false;
    void (async () => {
      try {
        const summary = await api.syncPrivateIntake();
        if (cancelled) return;
        if (summary.newly_accepted > 0) {
          setSyncSummary(summary);
          await refreshParticipation();
          recordAction(
            `Reconciled ${summary.newly_accepted} durable ballot(s) from private intake`,
          );
        }
      } catch {
        // Best-effort recovery pass; the manual Sync button remains the fallback.
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [election?.manifest_hash_hex, lifecycle, shellAvailable]);

  // One bounded auto-sync tick: re-read the read-only intake status; when the
  // intake worker reports MORE accepted ballots than the previous observation (a
  // new Tor delivery), ingest through the SAME authoritative sync_private_intake
  // path. Idempotent (duplicates never re-count); a single in-flight guard
  // prevents overlap. Failures are surfaced, not swallowed.
  const autoSyncTick = async () => {
    if (autoSyncBusyRef.current) return;
    autoSyncBusyRef.current = true;
    try {
      const status = await api.organizerTorStatus(intakeTorExepathOrUndefined());
      setOrganizerStatus(status);
      const prev = prevAcceptedRef.current;
      prevAcceptedRef.current = status.accepted_ballots;
      // Reconcile on the FIRST observation of a bound worker (prev === null), then
      // on every subsequent INCREASE. The first-observation reconciliation is the
      // restart/first-mount fix: the process-local intake worker counter restarts
      // at 0, so a durable inbox package already accepted before restart would
      // otherwise never trigger a delta and would sit unsynced until a manual
      // Sync. The authoritative sync is idempotent and writes a workspace revision
      // only when a package is newly accepted, so this never double-counts and
      // never churns revisions on an empty/duplicate-only inbox.
      const firstObservation = prev === null;
      if (firstObservation || status.accepted_ballots > prev) {
        const summary = await api.syncPrivateIntake();
        setSyncSummary(summary);
        await refreshParticipation();
        recordAction(
          summary.newly_accepted > 0
            ? `Auto-synced ${summary.newly_accepted} ballot(s) from private intake`
            : "Auto-synced private intake",
        );
      }
    } catch (error) {
      // Surface the failure next to the controls; stop the busy guard so the next
      // interval can retry once the operator has seen it.
      showError(error);
    } finally {
      autoSyncBusyRef.current = false;
    }
  };

  // Bounded automatic inbox sync runs ONLY while an election is loaded, voting is
  // OPEN, and a ready intake worker is bound to THIS election. A fixed interval
  // (never a tight loop) polls the read-only status; the authoritative writer
  // boundary is unchanged. The manual "Sync accepted ballots" button remains.
  const autoSyncActive =
    shellAvailable &&
    election !== null &&
    lifecycle === "OPEN" &&
    (organizerStatus?.intake_running ?? false) &&
    (organizerStatus?.election_bound ?? false);
  useEffect(() => {
    if (!autoSyncActive) return;
    const intervalId = setInterval(() => {
      void autoSyncTick();
    }, 4000);
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoSyncActive]);

  const onSelectIntakeTorExe = async () => {
    clearLocalError();
    const picked = await pickTorExecutable();
    if (picked === null) return;
    setIntakeTorExePath(picked);
    // Remember the tor.exe globally (non-secret convenience); election-specific
    // fields are left untouched.
    const current = recallManagedTorConfig();
    rememberManagedTorConfig({ ...current, torExePath: picked });
    try {
      setOrganizerStatus(await api.organizerTorStatus(picked));
    } catch (error) {
      showError(error);
    }
  };

  const onStartIntake = async () => {
    clearLocalError();
    setOrganizerBusy(true);
    try {
      const status = await api.startPrivateIntake(intakeTorExepathOrUndefined());
      setOrganizerStatus(status);
      recordAction("Started private ballot intake");
    } catch (error) {
      showError(error);
    } finally {
      setOrganizerBusy(false);
    }
  };

  const onStopIntake = async () => {
    clearLocalError();
    setOrganizerBusy(true);
    try {
      const status = await api.stopPrivateIntake();
      setOrganizerStatus(status);
      recordAction("Stopped private ballot intake");
    } catch (error) {
      showError(error);
    } finally {
      setOrganizerBusy(false);
    }
  };

  const onExportVoterBundle = async () => {
    clearLocalError();
    setBundleExportPath(null);
    const dir = await pickDirectory("Choose a folder for the voter transport bundle", "electionExport");
    if (dir === null) return;
    try {
      const result = await api.exportVoterTransportBundle(dir);
      setBundleExportPath(result.written_path);
      recordAction("Exported voter transport bundle");
    } catch (error) {
      showError(error);
    }
  };

  const [statusExport, setStatusExport] = useState<{
    written_path: string;
    lifecycle_state: string;
    generation: number;
  } | null>(null);

  // Exports one authenticated election-status statement: a signed statement of
  // the CURRENT authoritative lifecycle, bound to this exact frozen election,
  // signed by the same ballot-office root key as the transport descriptor.
  // Voters import it to learn FROZEN/OPEN/CLOSED/... without trusting any
  // unsigned claim. The generation is reserved durably before signing, so
  // restarts never reuse one and stale artifacts can never roll voters back.
  const onExportElectionStatus = async () => {
    clearLocalError();
    setStatusExport(null);
    const path = await pickElectionStatusExportPath();
    if (path === null) return;
    try {
      const result = await api.exportElectionStatusArtifact(path);
      setStatusExport(result);
      recordAction(
        `Exported signed election status (${result.lifecycle_state}, generation ${result.generation})`,
      );
    } catch (error) {
      showError(error);
    }
  };

  const onWriteArchive = async () => {
    clearLocalError();
    setArchiveResult(null);
    try {
      const result = await api.writeFinalizedArchive(
        archiveDir,
        archiveGovernanceDocPath,
      );
      setArchiveResult(result);
      recordAction(
        archiveGovernanceDocPath
          ? "Wrote finalized archive with governance document"
          : "Wrote finalized archive",
      );
    } catch (error) {
      showError(error);
    }
  };

  const anchorPaths = (archiveDirName: string) => ({
    configPath: `${archiveDirName}-anchor-config.cbor`,
    snapshotPath: `${archiveDirName}-anchor-snapshot.cbor`,
    evidencePath: `${archiveDirName}-anchor-evidence.cbor`,
  });

  const onPrepareAnchorConfig = async () => {
    if (!archiveResult) return;
    clearLocalError();
    setAnchorBusy(true);
    setAnchorConfigResult(null);
    setAnchorStepResult(null);
    const { configPath, snapshotPath, evidencePath } = anchorPaths(
      archiveResult.directory,
    );
    try {
      const result = await api.writeLiveAnchorConfig({
        archive_directory: archiveResult.directory,
        output_config_path: configPath,
        network: anchorNetwork,
        walletd_endpoint: anchorWalletdEndpoint,
        indexer_endpoint: anchorIndexerEndpoint,
        account_reference: anchorAccountRef,
        fee_component: anchorFeeComponent,
        seal_signer_kind: anchorSealSignerKind,
        seal_signer_id: anchorSealSignerId,
        declared_seal_public_key: anchorSealPubKey,
        dedicated_organizer_wallet_attested: anchorDedicatedWallet,
        max_fee: anchorMaxFee,
        required_accepted_ballot_floor: anchorFloor,
        reduced_anonymity_acknowledged: true,
        snapshot_path: snapshotPath,
        evidence_path: evidencePath,
        backoff_base_secs: 1,
        backoff_cap_secs: 10,
        receipt_query_attempts: 8,
        request_timeout_secs: 30,
        ttl_secs: null,
      });
      setAnchorConfigResult(result);
      recordAction("Prepared anchor configuration");
    } catch (error) {
      showError(error);
    } finally {
      setAnchorBusy(false);
    }
  };

  const onAnchorStep = async (decision: "approve" | "reject" | "none") => {
    if (!archiveResult || !anchorConfigResult) return;
    clearLocalError();
    setAnchorBusy(true);
    const { snapshotPath, evidencePath } = anchorPaths(archiveResult.directory);
    try {
      const result = await api.runLiveAnchorLifecycleStep({
        config_path: anchorConfigResult.config_path,
        archive_directory: archiveResult.directory,
        use_walletd_auth: anchorUseAuth,
        decision,
      });
      setAnchorStepResult(result);
      if (result.phase_is_terminal_success) {
        recordAction(`Anchor finalized: ${result.phase}`);
      } else if (result.phase_is_terminal) {
        recordAction(`Anchor terminal: ${result.phase}`);
      } else {
        recordAction(`Anchor step: ${result.phase}`);
      }
      // Keep snapshot/evidence paths in sync for the inspection screens.
      void snapshotPath;
      void evidencePath;
    } catch (error) {
      showError(error);
    } finally {
      setAnchorBusy(false);
    }
  };

  const onPickArchiveGovernanceDoc = async () => {
    const path = await pickGovernanceDocument("Select governance document to archive");
    setArchiveGovernanceDocPath(path);
  };

  const onPickArchiveDir = async () => {
    clearLocalError();
    const picked = await pickDirectory("Choose archive output directory", "archive");
    if (picked !== null) setArchiveDir(picked);
  };

  // Closing voting is irreversible. The dialog is a presentation safeguard
  // only; the backend lifecycle state machine remains the authoritative
  // validation and still rejects an invalid transition.
  const onConfirmClose = async () => {
    setConfirmClose(false);
    setLifecycleBusy(true);
    try {
      await runLifecycle("close");
    } finally {
      setLifecycleBusy(false);
    }
  };

  // Finalizing is likewise irreversible: the verified result and finalized
  // election record become permanent. Same presentation-only safeguard; the
  // backend lifecycle state machine remains authoritative.
  const onConfirmFinalize = async () => {
    setConfirmFinalize(false);
    setLifecycleBusy(true);
    try {
      await runLifecycle("finalize");
    } finally {
      setLifecycleBusy(false);
    }
  };

  // Shared load controls (folder picker, unload, advanced manual load). Rendered
  // inline in the full "Load Election" card when no election is loaded, and
  // tucked inside a "Load a different election" disclosure once one is loaded, so
  // a recovered/loaded session is not buried under the folder-selection tutorial.
  const loadElectionControls = (
    <>
      <div className="btn-row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!shellAvailable || folderBusy}
          onClick={() => void onOpenElectionFolder()}
        >
          Select Election Folder
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={!canAct}
          onClick={() => void unloadElection()}
        >
          Unload Election
        </button>
      </div>
      <p className="form-hint">
        The folder must contain election-manifest.cbor, voter-registry.cbor, and
        candidate-set.cbor. Identity is derived from the decoded bytes, not the filenames.
      </p>
      <DetailsSection summary="Advanced / manual load (choose three files)">
        <p className="card-body">
          The election definition is the manifest file, the eligible voter list is the
          registry file, and the ballot options are the candidate/option set file. Loading
          validates canonical encodings, recomputes both commitments and the manifest hash,
          enforces the production proof-suite policy, and freezes the lifecycle. The session
          starts in FROZEN. Filenames are shown for convenience only — identity is derived
          from the decoded bytes.
        </p>
        <div className="form-row">
          <label htmlFor="manifest-path">Election definition</label>
          <div className="file-row">
            <input
              id="manifest-path"
              type="text"
              readOnly
              value={manifestPath ? basename(manifestPath) : ""}
              placeholder="no file selected"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickManifest()}
            >
              Browse
            </button>
          </div>
        </div>
        <div className="form-row">
          <label htmlFor="registry-path">Eligible voter list</label>
          <div className="file-row">
            <input
              id="registry-path"
              type="text"
              readOnly
              value={registryPath ? basename(registryPath) : ""}
              placeholder="no file selected"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickRegistry()}
            >
              Browse
            </button>
          </div>
        </div>
        <div className="form-row">
          <label htmlFor="optionset-path">Ballot options</label>
          <div className="file-row">
            <input
              id="optionset-path"
              type="text"
              readOnly
              value={optionSetPath ? basename(optionSetPath) : ""}
              placeholder="no file selected"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickOptionSet()}
            >
              Browse
            </button>
          </div>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!canLoad}
            onClick={() => void onLoad()}
          >
            Load and Validate Election
          </button>
        </div>
        {shellAvailable && !election && !canLoad && (
          <p className="form-hint">Choose all three election files to load manually.</p>
        )}
      </DetailsSection>
    </>
  );

  return (
    <>
      <h1 className="screen-header">Manage Election</h1>
      {isImportedVoter ? (
        <p className="screen-lede">
          Voter view of this election: this computer imported its public election
          package, so it can inspect the election and vote — it is not the ballot office.
        </p>
      ) : (
        <p className="screen-lede">
          Organizer tools for one election: load the election files, open and close voting,
          accept submitted ballots, compute the tally, and write the verifiable election record.
        </p>
      )}

      <BackendErrorNotice error={backendError} onDismiss={dismissError} />
      <BackendErrorNotice error={finalArchiveError ? null : localError} onDismiss={clearLocalError} />
      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: commands are disabled because the desktop shell is not running.
        </Notice>
      )}

      {isImportedVoter && (
        <Notice tone="info">
          <strong>This election was imported from public election artifacts.</strong> This app
          instance is a voter for this election, not its ballot office. Organizing actions —
          opening or closing voting, running private intake, exporting voter materials, signing
          status statements, tallying, and writing archives — belong to the ballot-office
          computer and are neither shown here nor accepted by the backend. To vote in this
          election, use the Vote screen.
        </Notice>
      )}

      {election ? (
        // An election is already loaded (this session) or recovered from durable
        // state. Collapse the full folder-selection tutorial into a compact
        // status banner; the tutorial + manual load stay one click away under
        // "Load a different election" so they never dominate a resumed session.
        <Card title="Election">
          <Notice tone="ok">
            {selectedArtifactPaths ? "Election loaded ✓" : "Election recovered ✓"}
          </Notice>
          <div className="field-list">
            <Field label="Election">
              {election.election_id_text ?? election.election_id_hex}
            </Field>
            <Field label="Status">
              <LifecyclePill state={lifecycle} />
            </Field>
          </div>
          {/* The real append-only lifecycle, derived from the backend state.
              Past stages are done, the current stage is emphasized, and
              irreversible stages never appear reversible. */}
          <ProgressSteps
            label="Election lifecycle"
            steps={organizerLifecycleSteps(lifecycle)}
          />
          {!selectedArtifactPaths && (
            <p className="form-hint">
              Recovered from durable session state. Its lifecycle, ballot intake, and tally
              controls below operate on that recovered session; the original source files are
              not needed to continue. Load different files only to switch elections.
            </p>
          )}
          <DetailsSection summary="Load a different election">
            {loadElectionControls}
          </DetailsSection>
        </Card>
      ) : (
        <Card title="Load Election">
          <p className="card-body">
            The simplest way to load an election is to choose the folder that contains its three
            exported files. Loading checks that the files are complete, unaltered, and belong to
            the same election, then freezes the session for review before voting is opened.
          </p>
          <p className="card-body">
            Select the election folder itself — do not open it first. In the picker, click the
            folder once to highlight it, then confirm; opening it makes the dialog look empty
            because it only shows sub-folders. The folder must contain election-manifest.cbor,
            voter-registry.cbor, and candidate-set.cbor.
          </p>
          {loadElectionControls}
        </Card>
      )}

      {isOrganizer && election && (
        // Plain-language guidance derived from the real lifecycle state; it
        // never fabricates states or implies an irreversible step has happened.
        <Card title="Next step">
          <p className="card-body">
            <strong>{nextStep.title}</strong>
          </p>
          <p className="card-body">{nextStep.body}</p>
        </Card>
      )}

      {/* Presentation-only escape hatch: reveals the complete control surface
          (including future phases and technical controls) for review or
          debugging. It never changes workflow state, never bypasses a gate,
          and never enables a disabled control. Organizer context only: an
          imported voter election has no organizer controls to reveal. */}
      {isOrganizer && (
        <div className="action-row">
          <button
            type="button"
            className="btn btn-secondary"
            aria-pressed={showAllControls}
            onClick={() => setShowAllControls((current) => !current)}
          >
            {showAllControls ? "Show guided view" : "Show all election controls"}
          </button>
        </div>
      )}

      {/* Completed-phase summaries (guided mode only): compact, derived from
          existing state, each inspectable via Show all election controls. */}
      {isOrganizer && guidedMode && completedSummaries.length > 0 && (
        <Card title="Progress so far">
          <ul className="guide-facts">
            {completedSummaries.map((summary) => (
              <li key={summary}>✓ {summary}</li>
            ))}
          </ul>
          <p className="form-hint">
            Use Show all election controls to inspect any completed step in full.
          </p>
        </Card>
      )}

      {/* The current lifecycle phase leads the workspace. */}
      {isOrganizer && guidedMode && phaseHeading !== null && (
        <h2 className="screen-section">{phaseHeading}</h2>
      )}

      {shellAvailable && !election && (
        <Notice tone="info">Load an election to enable these controls.</Notice>
      )}

      {isOrganizer && (
      <div className="card-grid">
        {/* Guided mode shows only the current phase's cards prominently; the
            rest stay one toggle away under Show all election controls. Card
            order serves the current phase: intake and voter materials first,
            the lifecycle transition actions last. */}
        {showControl("intake") && (
        <Card title="Private ballot intake">
          <p className="card-body">
            Accept ballots submitted privately over Tor. Starting intake runs Tor and the
            private receiver for you — no terminal, torrc, or network settings. Ballots are
            accepted into this election through the same checks as an imported ballot: each is
            accepted only once, and an exact resend is never counted twice.
          </p>

          {/* Near-one-click status line: a plain Ready pill first, then the
              plain Tor/transport lines. The two accepted-ballot counters stay
              DISTINCT on purpose: the election total is authoritative and
              survives restarts; the per-session receiver count does not. */}
          <div className="field-list">
            <Field label="Status">
              {organizerStatus === null ? (
                <Pill tone="neutral">Checking…</Pill>
              ) : organizerStatus.failed ? (
                <Pill tone="error">Could not start</Pill>
              ) : organizerStatus.intake_running && organizerStatus.ready ? (
                <Pill tone="ok">Running ✓</Pill>
              ) : organizerStatus.intake_running ? (
                <Pill tone="warn">Starting…</Pill>
              ) : (
                <Pill tone="neutral">Not running</Pill>
              )}
            </Field>
            <Field label="Tor">
              {organizerStatus === null
                ? "Checking…"
                : organizerStatus.tor_found
                  ? "Found"
                  : "Not found"}
            </Field>
            <Field label="Election transport">
              {organizerStatus === null
                ? "Checking…"
                : organizerStatus.failed
                  ? "Provisioned (private address kept)"
                  : organizerStatus.intake_running && organizerStatus.ready
                    ? "Private receiver running (local)"
                    : organizerStatus.transport_provisioned
                      ? "Ready to start"
                      : "Not provisioned"}
            </Field>
            {/* AUTHORITATIVE election accepted count comes from the durable
                session/workspace (participation), NOT the Tor worker. A Tor
                worker restart resets its own counter to 0 but must never make an
                already-accepted, durably-recorded ballot appear to disappear. */}
            <Field label="Election accepted ballots">
              {participationDisclosed && participation?.accepted_ballots != null
                ? participation.accepted_ballots
                : participationSealed
                  ? sealedParticipationText(lifecycle)
                  : "—"}
            </Field>
            {organizerStatus?.intake_running && (
              <Field label="Received this intake session">
                {organizerStatus.accepted_ballots}
              </Field>
            )}
          </div>
          {organizerStatus?.intake_running && organizerStatus.ready && (
            <Notice tone="info">
              Private intake is running. This confirms the local Tor process and ballot receiver
              are ready. After starting or restarting Tor, the private address can take a short
              time (up to about a minute) to become reachable by voters — a voter&rsquo;s ballot
              stays safely locked and is delivered on a retry once the address is reachable.
            </Notice>
          )}
          {organizerStatus?.intake_running && (
            <p className="form-hint">
              “Received this intake session” is the running Tor receiver’s own count and resets
              to 0 whenever intake restarts. The authoritative election total above is kept in the
              durable workspace and survives restarts; accepted ballots are reconciled into it
              automatically.
            </p>
          )}

          {organizerStatus !== null && !organizerStatus.tor_found && (
            <>
              <Notice tone="info">
                Tor was not found automatically. Select a Tor executable once; the app remembers
                it and never downloads or installs Tor.
              </Notice>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!canAct || organizerBusy}
                onClick={() => void onSelectIntakeTorExe()}
              >
                Select Tor executable
              </button>
            </>
          )}

          {organizerStatus?.failed && (
            <Notice tone="error">
              Private intake could not start. This election&rsquo;s private address and receiver
              are safe and unchanged — restart private intake to try again. If it keeps failing
              right after a restart, a previous run&rsquo;s background Tor may still be exiting;
              wait a few seconds and restart once more.
              {organizerStatus.failure_reason && (
                <>
                  {" "}
                  <span className="form-hint">
                    (diagnostic: {organizerStatus.failure_reason})
                  </span>
                </>
              )}
            </Notice>
          )}

          {organizerStatus?.intake_running &&
            !organizerStatus.failed &&
            !organizerStatus.election_bound && (
              <Notice tone="warn">
                Private intake is running for a different election. Stop it before starting intake
                for this election.
              </Notice>
            )}

          <div className="btn-row">
            {organizerStatus?.failed ? (
              // A failed intake is recoverable with a single click: the backend
              // reaps the dead controller and starts fresh (a new run directory,
              // the SAME onion identity). Never leaves the operator with only a
              // "Stop" against a service that is already down.
              <button
                type="button"
                className="btn btn-primary"
                disabled={
                  !canAct ||
                  organizerBusy ||
                  (organizerStatus !== null && !organizerStatus.tor_found)
                }
                onClick={() => void onStartIntake()}
              >
                {organizerBusy ? "Restarting…" : "Restart private intake"}
              </button>
            ) : organizerStatus?.intake_running ? (
              <button
                type="button"
                className="btn btn-danger"
                disabled={!canAct || organizerBusy}
                onClick={() => void onStopIntake()}
              >
                {organizerBusy ? "Stopping…" : "Stop private intake"}
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-primary"
                disabled={
                  !canAct ||
                  organizerBusy ||
                  (organizerStatus !== null && !organizerStatus.tor_found)
                }
                onClick={() => void onStartIntake()}
              >
                {organizerBusy ? "Starting…" : "Start private intake"}
              </button>
            )}
          </div>
          <p className="form-hint">
            Starting intake does not open voting. Open voting separately when you are ready to
            accept ballots.
          </p>

          {/* Auto-sync (bounded) runs while intake is ready and voting is OPEN,
              using the SAME authoritative path as the manual Sync below. */}
          {autoSyncActive && (
            <p className="form-hint">
              Accepted ballots sync into this election automatically while intake is running.
              You can also sync now.
            </p>
          )}

          {/* Manual sync stays available but is recovery-oriented: normal
              operation auto-reconciles, so this is not part of the main flow.
              It also remains available while CLOSED so ballots the collector
              already accepted (and receipted) before close can finish their
              durable hand-off into this workspace — never a new-acceptance
              path. */}
          <h3 className="card-section-heading">Recovery / manual actions</h3>
          <p className="form-hint">
            Accepted ballots reconcile automatically during normal operation. Use this only to
            reconcile manually after a restart or a problem. After voting closes, sync once more
            to finish any ballots that were already accepted before the close.
          </p>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={
                !canAct ||
                syncBusy ||
                !(lifecycle === "OPEN" || lifecycle === "CLOSED")
              }
              onClick={() => void onSyncPrivateIntake()}
            >
              {syncBusy ? "Syncing…" : "Sync accepted ballots"}
            </button>
          </div>
          {syncSummary && (
            <div className="field-list">
              <Field label="Newly accepted">{syncSummary.newly_accepted}</Field>
              <Field label="Already counted">{syncSummary.duplicates}</Field>
              {syncSummary.rejected > 0 && (
                <Field label="Rejected">{syncSummary.rejected}</Field>
              )}
            </div>
          )}
          {lifecycle !== "OPEN" && lifecycle !== null && (
            <p className="card-body">
              Private intake sync is available only while voting is open.
            </p>
          )}

          <DetailsSection summary="Advanced Tor diagnostics">
            <div className="field-list">
              {organizerStatus?.published_lifecycle && (
                <Field label="Served election status">
                  {organizerStatus.published_lifecycle}
                  {organizerStatus.status_generation !== null &&
                    ` (generation ${organizerStatus.status_generation})`}
                </Field>
              )}
              {organizerStatus?.authoritative_lifecycle &&
                organizerStatus.authoritative_lifecycle !==
                  organizerStatus.published_lifecycle && (
                  <Field label="Authoritative lifecycle (reconciling)">
                    {organizerStatus.authoritative_lifecycle}
                  </Field>
                )}
              {organizerStatus?.onion_hostname && (
                <Field label="Verified onion">
                  <span className="hash">{organizerStatus.onion_hostname}</span>
                </Field>
              )}
              {organizerStatus?.descriptor_fingerprint && (
                <Field label="Descriptor fingerprint">
                  <HashValue value={organizerStatus.descriptor_fingerprint} />
                </Field>
              )}
              {organizerStatus?.collector_addr && (
                <Field label="Loopback collector">
                  <span className="hash">{organizerStatus.collector_addr}</span>
                </Field>
              )}
              {organizerStatus?.tor_data_dir && (
                <Field label="Tor data directory">
                  <span className="hash">{organizerStatus.tor_data_dir}</span>
                </Field>
              )}
            </div>
            <p className="card-body">
              These details are managed for you and are shown only for troubleshooting. No
              private key material is ever displayed or exported.
            </p>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!canAct}
              onClick={() => void onRevealInboxPath()}
            >
              Show intake inbox folder
            </button>
            {inboxPath && (
              <div className="form-row">
                <label htmlFor="inbox-path">Intake inbox folder</label>
                <input id="inbox-path" type="text" readOnly value={inboxPath} />
              </div>
            )}
          </DetailsSection>
        </Card>
        )}

        {showControl("materials") && (
        <Card title="Voter materials">
          <p className="card-body">
            Voters need two things from the ballot office before they can vote:
          </p>
          <ul className="guide-facts">
            <li>
              <strong>The frozen election package</strong> — the election definition, eligible
              voter list, and ballot options, exported when the election was created and frozen
              (Create Election screen).
            </li>
            <li>
              <strong>The voter transport bundle</strong> — lets each voter&rsquo;s app verify
              and reach this ballot office over the private route.
            </li>
          </ul>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={
                !canAct ||
                organizerBusy ||
                !(organizerStatus?.transport_provisioned ?? false)
              }
              onClick={() => void onExportVoterBundle()}
            >
              Export voter transport bundle
            </button>
          </div>
          {!(organizerStatus?.transport_provisioned ?? false) && (
            <p className="form-hint">
              The bundle can be exported once this election&rsquo;s private transport is
              provisioned — start private intake once, then export.
            </p>
          )}
          {bundleExportPath && (
            <Notice tone="ok">
              Voter transport bundle exported
              <br />
              <span className="hash">{bundleExportPath}</span>
            </Notice>
          )}

          <h3 className="card-section-heading">Signed election status</h3>
          <p className="card-body">
            The frozen election package never changes, but voting itself opens and closes. To
            tell voters the current state truthfully — on another computer, even offline — export
            a signed status statement after each lifecycle change (open voting, close voting) and
            give each voter a copy. It is bound to this exact election and signed by this ballot
            office; voters reject anything else.
          </p>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!canAct || organizerBusy || lifecycle === null}
              onClick={() => void onExportElectionStatus()}
            >
              {organizerBusy ? "Working…" : "Export signed election status"}
            </button>
          </div>
          {statusExport && (
            <Notice tone="ok">
              Signed election status exported ({statusExport.lifecycle_state}, generation{" "}
              {statusExport.generation})
              <br />
              <span className="hash">{statusExport.written_path}</span>
            </Notice>
          )}
        </Card>
        )}

        {showControl("office") && (
        <Card title="Ballot office">
          <p className="card-body">
            Import submitted ballot files here. Each ballot is checked before it is accepted
            into the election; a ballot that fails a check is rejected, and a ballot that was
            already accepted is never counted twice.
          </p>
          <DetailsSection summary="Technical details">
            <p className="card-body">
              The file is only a carrier for exact package bytes; canonical parsing, proof
              verification, lifecycle checks, and duplicate (nullifier) detection happen in the
              Rust backend through the authoritative intake path.
            </p>
          </DetailsSection>
          <div className="form-row">
            <label htmlFor="package-path">Last selected package</label>
            <input
              id="package-path"
              type="text"
              readOnly
              value={packagePath}
              placeholder="no ballot package selected"
            />
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canImportBallot}
            onClick={() => void onIntake()}
          >
            Import ballot package
          </button>
          <div className="field-list">
            <Field label="Last intake">{intakeResultTitle(lastIntake)}</Field>
            {lastIntake && <Field label="Result">{intakeResultMessage(lastIntake)}</Field>}
          </div>
          {lifecycle !== "OPEN" && lifecycle !== null && (
            <p className="card-body">Ballot intake is available only while voting is open.</p>
          )}
        </Card>
        )}

        {showControl("participation") && (
        <Card title="Participation">
          {participation ? (
            <>
              <div
                className="metric-head"
                role="img"
                aria-label={participationAccessibleText(participation)}
              >
                {participationSealed ? (
                  <span className="metric-value metric-sealed">
                    <LockIcon label="Hidden" />
                    {sealedParticipationText(lifecycle)}
                  </span>
                ) : participation.participation_visibility === "COARSE" ? (
                  <span className="metric-value">
                    {coarseBucketLabel(participation.coarse_bucket)}
                  </span>
                ) : participation.participation_basis_points !== null ? (
                  <span className="metric-value">
                    {formatPercent(participation.participation_basis_points)}
                  </span>
                ) : (
                  <span className="metric-value metric-sealed">
                    <LockIcon label="Hidden" />
                    Hidden
                  </span>
                )}
                {participationDisclosed && participation.accepted_ballots !== null && (
                  <span className="metric-sub">
                    {participation.accepted_ballots} of {participation.eligible_voters} eligible voters
                  </span>
                )}
              </div>
              <ParticipationTrack
                summary={participation}
                sealedLabel={sealedParticipationText(lifecycle)}
              />
              {participationSealed && lifecycle === "OPEN" && (
                <p className="card-body">
                  Participation is hidden while voting is open — this is intentional, not missing
                  data. Participation is disclosed after voting closes.
                </p>
              )}
              {participation.small_electorate && !participationSealed && lifecycle === "OPEN" && (
                <p className="card-body">
                  Small electorate: live detail is hidden while voting is open.
                </p>
              )}
              {participation.small_electorate && !participationSealed && lifecycle !== "OPEN" && lifecycle !== null && (
                <p className="card-body">
                  Small electorate: live detail was hidden while voting was open.
                </p>
              )}
              <p className="card-body">
                Policy: {participationVisibilityLabel(participation.participation_visibility)}.
              </p>
            </>
          ) : (
            <p className="card-body">No participation data available in this session.</p>
          )}
        </Card>
        )}

        {/* The lifecycle transition actions are the logical final actions of
            their phases: Open voting ends the FROZEN preparation phase, Close
            voting ends the OPEN phase. */}
        {showControl("open") && (
        <Card title="Open Voting">
          <p className="card-body">
            Opening voting means the election starts accepting ballots from eligible voters.
            The election definition stays locked. Voting stays open until you close it.
          </p>
          <p className="card-body">
            <strong>Opening voting cannot be undone.</strong> Start private intake and share the
            voter materials first, then open voting when you are ready to accept ballots.
          </p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "FROZEN"}
            onClick={() => void runLifecycle("open")}
          >
            Open voting
          </button>
        </Card>
        )}

        {showControl("close") && (
        <Card title="Close Voting">
          <p className="card-body">
            Closing voting is permanent: no additional ballots can be accepted after this
            election is closed. This cannot be undone.
          </p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!canAct || lifecycle !== "OPEN" || lifecycleBusy}
            onClick={() => setConfirmClose(true)}
          >
            Close voting
          </button>
        </Card>
        )}
      </div>
      )}

      {/* Results workflow, in order: the gates on each button remain the
          authoritative lifecycle gates; the heading only makes the existing
          progression obvious. In guided mode the whole section appears only
          when a results-phase control is relevant to the current lifecycle. */}
      {isOrganizer && resultsVisible && (
        <>
          <h2 className="screen-section">Results</h2>
          <p className="form-hint">
            After voting closes: compute the tally, review the result, mark verification complete,
            finalize the election, then write the final archive and verify it independently on the
            Archive screen.
          </p>
        </>
      )}

      {isOrganizer && (
      <div className="card-grid">
        {showControl("tally") && (
        <Card title="Tally">
          <p className="card-body">
            Deterministic approval tally over accepted ballots. A tie is reported as a tie.
          </p>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!canAct || !tallyAvailable}
            onClick={() => void onTally()}
          >
            Compute tally
          </button>
          {!tallyAvailable && lifecycle !== null && (
            <p className="card-body">The tally becomes available after voting closes.</p>
          )}
          {tally && tallyAvailable && (
            <div className="field-list">
              <Field label="Accepted ballots">{tally.accepted_ballots}</Field>
              <Field label="Abstentions">{tally.abstentions}</Field>
              <Field label="Outcome">{describeLeadingOutcome(tally)}</Field>
            </div>
          )}
          {tally && tallyAvailable && (
            <ResultBars tally={tally} election={election} />
          )}
          {!tallyAvailable && (
            <div
              className="result-bars-sealed"
              role="img"
              aria-label="The tally becomes available after voting closes."
            >
              <div className="result-bars-sealed-label">
                <LockIcon label="Sealed" />
                Tally locked
              </div>
              <p className="card-body">The tally becomes available after voting closes.</p>
            </div>
          )}
        </Card>
        )}

        {showControl("verify") && (
        <Card title="Verify">
          <p className="card-body">
            Records completion of public verification. Full offline replay verification of an
            archive is on the Archive screen.
          </p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "CLOSED"}
            onClick={() => void runLifecycle("verify")}
          >
            Mark verified
          </button>
        </Card>
        )}

        {showControl("finalArchive") && (
        <Card title="Final archive">
          <p className="card-body">
            Writes the complete election record to a folder: the election definition, eligible
            voter list, ballot options, and accepted ballots. Anyone can later verify this
            record independently on the Archive screen. Optionally include the governance
            supporting document so its bytes travel with the record.
          </p>
          {!finalArchiveAvailable && (
            <Notice tone="info">
              Mark verified and finalize the election before writing the final archive.
            </Notice>
          )}
          <DetailsSection summary="Technical details">
            <p className="card-body">
              Writes the canonical offline archive (manifest, registry, option set, submissions,
              archive manifest) with atomic file writes. The optional governance supporting
              document (ADR-0008) is archived at the project-controlled
              <span className="hash"> governance/source.bin</span> path and covered by the
              archive hash. It is supporting evidence, not a fourth canonical election artifact.
            </p>
          </DetailsSection>
          <div className="form-row">
            <label htmlFor="archive-dir">Target directory (new or empty)</label>
            <div className="file-row">
              <input
                id="archive-dir"
                type="text"
                value={archiveDir}
                onChange={(e) => {
                  setArchiveDir(e.target.value);
                  setArchiveResult(null);
                  if (finalArchiveError) clearLocalError();
                }}
                placeholder="archive output directory"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!canAct}
                onClick={() => void onPickArchiveDir()}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="form-row">
            <label htmlFor="archive-gov-doc">Governance document (optional)</label>
            <input
              id="archive-gov-doc"
              type="text"
              readOnly
              value={archiveGovernanceDocPath ?? ""}
              placeholder="no governance document selected"
            />
            <div className="btn-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onPickArchiveGovernanceDoc}
                disabled={!canAct}
              >
                Select governance document
              </button>
              {archiveGovernanceDocPath && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setArchiveGovernanceDocPath(null)}
                >
                  Clear
                </button>
              )}
            </div>
          </div>
          {/* VERIFIED phase: the finalize action is the prominent next step,
              so its permanence warning sits directly beside it (the explicit
              confirmation dialog remains the safeguard). */}
          {lifecycle === "VERIFIED" && (
            <Notice tone="warn">
              Finalizing is permanent: the verified result and finalized election record
              cannot be changed afterward.
            </Notice>
          )}
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-danger"
              disabled={!canAct || lifecycle !== "VERIFIED" || lifecycleBusy}
              onClick={() => setConfirmFinalize(true)}
            >
              Finalize election
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canAct || !archiveDir || !finalArchiveAvailable}
              onClick={() => void onWriteArchive()}
            >
              Write final archive
            </button>
          </div>
          <BackendErrorNotice error={finalArchiveError ? localError : null} onDismiss={clearLocalError} />
          {archiveResult && (
            <>
              <Notice tone="ok">
                Final archive written
                <br />
                <span className="hash">{archiveResult.directory}</span>
              </Notice>
              <div className="field-list">
                <Field label="Archive hash">
                  <HashValue value={archiveResult.archive_hash_hex} />
                  <CopyButton value={archiveResult.archive_hash_hex} />
                </Field>
                <Field label="Files written">{archiveResult.files.length}</Field>
              </div>
            </>
          )}
        </Card>
        )}

        {showControl("anchor") && (
        <Card title="Anchor">
          <Notice tone="info">
            Optional public integrity anchor: anchor the aggregate finalized archive commitment
            on Tari Ootle. Individual votes are not written to Ootle. Anchoring is optional and
            non-binding — the independently verified offline archive remains authoritative.
          </Notice>
          {!archiveResult && (
            <p className="form-hint">Write and verify the final archive first.</p>
          )}
          {archiveResult && (
            <>
              <div className="field-list">
                <Field label="Archive directory">
                  <HashValue value={archiveResult.directory} />
                </Field>
                <Field label="Archive hash">
                  <HashValue value={archiveResult.archive_hash_hex} />
                </Field>
              </div>

              {!anchorConfigResult && (
                <>
                  <div className="card-grid">
                    <div className="form-row">
                      <label htmlFor="anchor-network">Network</label>
                      <select
                        id="anchor-network"
                        value={anchorNetwork}
                        onChange={(e) => setAnchorNetwork(e.target.value)}
                      >
                        <option value="esmeralda">esmeralda (testnet)</option>
                        <option value="igor">igor (testnet)</option>
                        <option value="localnet">localnet</option>
                      </select>
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-walletd">Walletd endpoint</label>
                      <input
                        id="anchor-walletd"
                        type="text"
                        value={anchorWalletdEndpoint}
                        onChange={(e) => setAnchorWalletdEndpoint(e.target.value)}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-indexer">Indexer endpoint</label>
                      <input
                        id="anchor-indexer"
                        type="text"
                        value={anchorIndexerEndpoint}
                        onChange={(e) => setAnchorIndexerEndpoint(e.target.value)}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-account">Fee account</label>
                      <input
                        id="anchor-account"
                        type="text"
                        value={anchorAccountRef}
                        onChange={(e) => setAnchorAccountRef(e.target.value)}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-fee-comp">Fee component address</label>
                      <input
                        id="anchor-fee-comp"
                        type="text"
                        value={anchorFeeComponent}
                        placeholder="component_..."
                        onChange={(e) => setAnchorFeeComponent(e.target.value)}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-seal-kind">Seal signer</label>
                      <select
                        id="anchor-seal-kind"
                        value={anchorSealSignerKind}
                        onChange={(e) => setAnchorSealSignerKind(e.target.value)}
                      >
                        <option value="account">account key</option>
                        <option value="transaction">transaction key</option>
                        <option value="imported">imported key</option>
                      </select>
                      <input
                        id="anchor-seal-id"
                        type="number"
                        min="0"
                        value={anchorSealSignerId}
                        onChange={(e) => setAnchorSealSignerId(e.target.value)}
                        style={{ width: "5rem" }}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-seal-pubkey">Declared seal public key</label>
                      <input
                        id="anchor-seal-pubkey"
                        type="text"
                        value={anchorSealPubKey}
                        onChange={(e) => setAnchorSealPubKey(e.target.value)}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-maxfee">Max fee</label>
                      <input
                        id="anchor-maxfee"
                        type="number"
                        min="1"
                        value={anchorMaxFee}
                        onChange={(e) => setAnchorMaxFee(Number(e.target.value))}
                      />
                    </div>
                    <div className="form-row">
                      <label htmlFor="anchor-floor">Accepted ballot floor (min 2)</label>
                      <input
                        id="anchor-floor"
                        type="number"
                        min="2"
                        value={anchorFloor}
                        onChange={(e) => setAnchorFloor(Number(e.target.value))}
                      />
                    </div>
                    <div className="form-row">
                      <label>
                        <input
                          type="checkbox"
                          checked={anchorUseAuth}
                          onChange={(e) => setAnchorUseAuth(e.target.checked)}
                        />{" "}
                        Attach walletd bearer token from the WALLETD_AUTH_TOKEN
                        environment variable
                      </label>
                    </div>
                    <div className="form-row">
                      <label>
                        <input
                          type="checkbox"
                          checked={anchorDedicatedWallet}
                          onChange={(e) => setAnchorDedicatedWallet(e.target.checked)}
                        />{" "}
                        Dedicated organizer-only wallet (attested)
                      </label>
                    </div>
                  </div>

                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={
                        !canAct ||
                        anchorBusy ||
                        !anchorDedicatedWallet ||
                        !anchorSealPubKey ||
                        !anchorFeeComponent ||
                        anchorFloor < 2
                      }
                      onClick={() => void onPrepareAnchorConfig()}
                    >
                      Prepare anchor configuration
                    </button>
                  </div>
                  {anchorFloor < 2 && (
                    <Notice tone="error">
                      A minimum floor of 2 is required so a one-voter aggregate anchor cannot be
                      casually published.
                    </Notice>
                  )}
                </>
              )}

              {anchorConfigResult && (
                <>
                  <div className="field-list">
                    <Field label="Anchor digest">
                      <HashValue value={anchorConfigResult.anchor_digest_hex} />
                      <CopyButton value={anchorConfigResult.anchor_digest_hex} />
                    </Field>
                    <Field label="Manifest hash">
                      <HashValue value={anchorConfigResult.manifest_hash_hex} />
                    </Field>
                    <Field label="Archive hash">
                      <HashValue value={anchorConfigResult.archive_hash_hex} />
                    </Field>
                    <Field label="Accepted ballots">
                      {anchorConfigResult.accepted_ballot_count}
                    </Field>
                    <Field label="Floor enforced">
                      {anchorConfigResult.required_accepted_ballot_floor}
                    </Field>
                  </div>

                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={!canAct || anchorBusy}
                      onClick={() => void onAnchorStep("approve")}
                    >
                      {anchorBusy ? "Working…" : "Publish aggregate anchor"}
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      disabled={!canAct || anchorBusy}
                      onClick={() => void onAnchorStep("reject")}
                    >
                      Reject
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={!canAct || anchorBusy}
                      onClick={() => void onAnchorStep("none")}
                    >
                      Check status
                    </button>
                  </div>
                </>
              )}

              {anchorStepResult && (
                <div className="field-list">
                  <Field label="Anchor status">
                    {anchorStepResult.phase_is_terminal_success ? (
                      <Pill tone="ok">{anchorStepResult.phase}</Pill>
                    ) : anchorStepResult.phase_is_terminal ? (
                      <Pill tone="error">{anchorStepResult.phase}</Pill>
                    ) : (
                      <Pill tone="info">{anchorStepResult.phase}</Pill>
                    )}
                  </Field>
                  <Field label="Machine code">{anchorStepResult.machine_code}</Field>
                  {anchorStepResult.transaction_id && (
                    <Field label="Transaction">
                      <HashValue value={anchorStepResult.transaction_id} />
                    </Field>
                  )}
                  {anchorStepResult.evidence_written && (
                    <Field label="Evidence">
                      <HashValue value={anchorStepResult.evidence_path} />
                    </Field>
                  )}
                  {anchorStepResult.diagnostic && (
                    <Field label="Diagnostic">{anchorStepResult.diagnostic}</Field>
                  )}
                  {anchorStepResult.next_backoff_secs !== null && (
                    <Field label="Next poll backoff">
                      {anchorStepResult.next_backoff_secs}s
                    </Field>
                  )}
                </div>
              )}
              <BackendErrorNotice
                error={localError}
                onDismiss={() => setLocalError(null)}
              />
            </>
          )}
        </Card>
        )}
      </div>
      )}

      {/* Reference details for the loaded election. The entire technical
          section is collapsed by default so normal ballot-office operation
          never requires scrolling through cryptographic internals; nothing is
          removed — every manifest/proof-suite/commitment/identifier field is
          preserved inside the disclosure. Read-only public data: it stays
          available in every role, including imported voter context. */}
      {election && (
        <DetailsSection summary="Election technical details">
          <>
          <h2 className="screen-section">Election details</h2>
          <Card title="Election overview">
            <div className="field-list">
              <Field label="Election">
                {election.election_id_text ?? election.election_id_hex}
              </Field>
              <Field label="Lifecycle">
                <LifecyclePill state={lifecycle} />
              </Field>
              <Field label="Manifest schema">
                ElectionManifestV{election.manifest_schema_version}
              </Field>
              {election.proposal_question && (
                <Field label="Ballot question">{election.proposal_question}</Field>
              )}
              <Field label="Proof suite">{election.proof_suite_id}</Field>
              <Field label="Ballot kind">{election.ballot_kind}</Field>
              <Field label="Confidentiality">{election.ballot_confidentiality}</Field>
            </div>
            <p className="form-hint">
              Manifest hash and other canonical identifiers are under Advanced details below.
            </p>
          </Card>

          <div className="card-grid">
            <Card title="Eligibility">
              <div className="field-list">
                <Field label="Eligible voters">{election.voter_count}</Field>
                <Field label="Registry commitment">
                  <HashValue value={election.registry_commitment_hex} />
                  <CopyButton value={election.registry_commitment_hex} />
                </Field>
              </div>
            </Card>

            <Card title="Voting rules">
              <div className="field-list">
                <Field label="Approval rule">{approvalRuleText(election)}</Field>
                <Field label="Abstention">
                  {election.abstention_allowed ? "permitted" : "not permitted"}
                </Field>
              <Field label="Governance source">
                {election.governance_source_revision}
              </Field>
              {election.proposal_question && (
                <Field label="Ballot question">{election.proposal_question}</Field>
              )}
              <Field label="Quorum">No quorum rule is represented in this election manifest.</Field>
              </div>
              <p className="card-body">
                The version-one manifest carries no quorum, minimum-participation, or passing
                threshold field. No governance rule is inferred from community conventions.
              </p>
            </Card>
          </div>

          <Card title={presentation.optionSetNoun}>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Display label</th>
                  <th scope="col">Machine ID</th>
                </tr>
              </thead>
              <tbody>
                {election.candidates.map((option) => (
                  <tr key={option.machine_id_hex}>
                    <td>{option.display_name}</td>
                    <td>
                      <span className="hash">
                        {option.machine_id_text ?? option.machine_id_hex}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Advanced details">
            <div className="field-list">
              <Field label="Manifest hash">
                <HashValue value={election.manifest_hash_hex} />
                <CopyButton value={election.manifest_hash_hex} />
              </Field>
              <Field label="Manifest schema">
                ElectionManifestV{election.manifest_schema_version}
              </Field>
              <Field label="Registry commitment">
                <HashValue value={election.registry_commitment_hex} />
                <CopyButton value={election.registry_commitment_hex} />
              </Field>
              <Field label="Option-set commitment">
                <HashValue value={election.candidate_set_commitment_hex} />
                <CopyButton value={election.candidate_set_commitment_hex} />
              </Field>
              <Field label="Proof-suite identifier">{election.proof_suite_id}</Field>
              <Field label="Election ID (canonical)">
                <HashValue value={election.election_id_hex} />
                <CopyButton value={election.election_id_hex} />
              </Field>
            </div>
            <DetailsSection summary="Canonical option IDs">
              <ul className="option-list">
                {election.candidates.map((option) => (
                  <li key={option.machine_id_hex} className="option-item">
                    <span className="option-marker" aria-hidden="true" />
                    <span>{option.display_name}</span>
                    <span className="hash form-hint">
                      {option.machine_id_text ?? option.machine_id_hex}
                    </span>
                  </li>
                ))}
              </ul>
            </DetailsSection>
          </Card>

          {selectedArtifactPaths && (
            <Card title="Loaded artifacts (session only)">
              <div className="field-list">
                <Field label="Manifest">{basename(selectedArtifactPaths.manifest)}</Field>
                <Field label="Registry">{basename(selectedArtifactPaths.registry)}</Field>
                <Field label="Option set">{basename(selectedArtifactPaths.optionSet)}</Field>
              </div>
              <p className="form-hint">
                Paths are held in session memory only and are not persisted. Unloading clears them.
              </p>
            </Card>
          )}
          </>
        </DetailsSection>
      )}

      {confirmClose && (
        <ConfirmDialog
          title="Close voting?"
          body={
            <>
              <p>
                No additional ballots can be accepted after this election is closed.
              </p>
              <p>
                <strong>This cannot be undone.</strong>
              </p>
            </>
          }
          confirmLabel="Close voting permanently"
          confirmTone="danger"
          busy={lifecycleBusy}
          onConfirm={() => void onConfirmClose()}
          onCancel={() => setConfirmClose(false)}
        />
      )}

      {confirmFinalize && (
        <ConfirmDialog
          title="Finalize this election?"
          body={
            <>
              <p>
                The verified result and finalized election record become permanent.
              </p>
              <p>
                <strong>This cannot be undone.</strong>
              </p>
            </>
          }
          confirmLabel="Finalize election"
          confirmTone="danger"
          busy={lifecycleBusy}
          onConfirm={() => void onConfirmFinalize()}
          onCancel={() => setConfirmFinalize(false)}
        />
      )}
    </>
  );
}
