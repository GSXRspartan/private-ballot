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
import {
  recallOrganizerRemoteTorConfig,
  rememberOrganizerRemoteTorConfig,
} from "../api/organizerRemoteTorMemory";
import type {
  GuiArchiveWriteResultV1,
  GuiCommandError,
  GuiTallySummaryV1,
  GuiTrustedOotleDeploymentStatusV2,
  GuiWalletdAnchorAccountV1,
  OrganizerIntakeStatusV1,
  ProductionTransportAuthorityReadinessV1,
  WalletdConnectionDiagnosticsV1,
  WalletdCredentialStatusV1,
  WalletdReadinessV1,
} from "../api/types";
import {
  anchorFormStorageKey,
  applyConnectedWallet,
  clearAnchorFormState,
  defaultAnchorFormState,
  loadAnchorFormState,
  saveAnchorFormState,
  walletAccountsErrorMessage,
  walletActionStatusForKind,
  type AnchorFormState,
  type KeyValueStore,
} from "../anchor/anchorForm";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { intakeCanImport, intakeResultMessage, intakeResultTitle } from "../intake";
import { boundArchiveResult } from "../archive/archiveBinding";
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
import type { AnchorSignerMode, OrganizerControlKey } from "../lifecycle";
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

const DEFAULT_ANCHOR_SIGNER_MODE: AnchorSignerMode = "external-walletd";
// The normal organizer publishing surface is V2 (public aggregate summary). The
// legacy V1 aggregate-digest publishing UX has been retired from the normal
// flow; V1 verification of historical anchors remains supported via the Anchor
// inspection screen and the CLI. This constant keeps the persisted form state
// well-typed without exposing a UI selector.
const ANCHOR_VERSION: "v2" = "v2";

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
    archiveView,
    updateArchiveView,
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
  // Advanced external-remote Tor hosting: an EXTERNALLY managed Tor instance
  // (trusted LAN/VPN/tunnel) already hosts the organizer onion service, so
  // Private Ballot never spawns/owns a Tor process in that mode. These are
  // GLOBAL non-secret preferences; the Rust shell re-validates every field
  // (fail closed) before anything connects. Default/absent → managed-local.
  const [organizerTorMode, setOrganizerTorMode] = useState<"managed-local" | "external-remote">(
    () =>
      recallOrganizerRemoteTorConfig().torMode === "external-remote"
        ? "external-remote"
        : "managed-local",
  );
  const [remoteSocksHost, setRemoteSocksHost] = useState(
    () => recallOrganizerRemoteTorConfig().socksHost,
  );
  const [remoteSocksPort, setRemoteSocksPort] = useState(
    () => recallOrganizerRemoteTorConfig().socksPort || "9050",
  );
  const [remoteOnionHostname, setRemoteOnionHostname] = useState(
    () => recallOrganizerRemoteTorConfig().onionHostname,
  );
  const [remoteCollectorPort, setRemoteCollectorPort] = useState(
    () => recallOrganizerRemoteTorConfig().collectorPort || "18081",
  );
  const [remoteTestStatus, setRemoteTestStatus] = useState<OrganizerIntakeStatusV1 | null>(null);
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
  const [confirmUnlockDeploymentV2, setConfirmUnlockDeploymentV2] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const [deploymentBusy, setDeploymentBusy] = useState(false);
  const [trustedDeploymentV2Status, setTrustedDeploymentV2Status] =
    useState<GuiTrustedOotleDeploymentStatusV2 | null>(null);
  const [trustedDeploymentV2StatusError, setTrustedDeploymentV2StatusError] =
    useState<GuiCommandError | null>(null);
  // Build-static anchor-deployment capability. When transport-binding provenance
  // is unavailable, this build cannot produce an anchor-eligible archive at all,
  // so the finalized-archive/anchor workflow is presented as unavailable rather
  // than offering an action that would fail closed. `null` = not yet loaded.
  const [transportBindingProvenanceAvailable, setTransportBindingProvenanceAvailable] =
    useState<boolean | null>(null);
  const [anchorSignerMode, setAnchorSignerMode] =
    useState<AnchorSignerMode>(DEFAULT_ANCHOR_SIGNER_MODE);
  const [anchorNetwork, setAnchorNetwork] = useState("esmeralda");
  const [anchorWalletdEndpoint, setAnchorWalletdEndpoint] = useState(
    "http://127.0.0.1:5100",
  );
  const [anchorIndexerEndpoint, setAnchorIndexerEndpoint] = useState(
    "https://ootle-indexer-a.tari.com/",
  );
  // Per-network published V2 event-template deployment. The operator supplies
  // only the address and (optionally) an artifact digest override; the backend
  // enforces the pinned reviewed WASM digest.
  const [anchorV2TemplateAddress, setAnchorV2TemplateAddress] = useState("");
  const [anchorV2ArtifactDigest, setAnchorV2ArtifactDigest] = useState("");
  const [anchorMaxEpochDelta, setAnchorMaxEpochDelta] = useState(12);
  const [anchorAccountRef, setAnchorAccountRef] = useState("organizer-fee-account");
  const [anchorFeeComponent, setAnchorFeeComponent] = useState("");
  const [anchorSealSignerKind, setAnchorSealSignerKind] = useState("account");
  const [anchorSealSignerId, setAnchorSealSignerId] = useState("0");
  const [anchorSealPubKey, setAnchorSealPubKey] = useState("");
  const [anchorMaxFee, setAnchorMaxFee] = useState(1000);
  const [anchorFloor, setAnchorFloor] = useState(2);
  const [anchorDedicatedWallet, setAnchorDedicatedWallet] = useState(false);
  const anchorVersion = ANCHOR_VERSION;
  const [anchorV2Result, setAnchorV2Result] =
    useState<import("../api/types").GuiLiveAnchorV2ResultV1 | null>(null);
  const [anchorV2Preparation, setAnchorV2Preparation] =
    useState<import("../api/types").GuiV2AnchorPublishPreparationV1 | null>(null);
  const [anchorV2StepResult, setAnchorV2StepResult] =
    useState<import("../api/types").GuiV2LiveAnchorStepResultV1 | null>(null);
  const [anchorV2PublishConfirmed, setAnchorV2PublishConfirmed] = useState(false);
  const [anchorV2Busy, setAnchorV2Busy] = useState(false);
  // Hydrated view of the persisted V2 lifecycle for `selectedFinalArchive`.
  // Populated by a read-only inspect on load; drives the "Existing V2 anchor
  // found" recovery panel and suppresses fresh Build/Prepare/Submit controls
  // whenever an on-chain transaction has already been submitted.
  const [anchorV2Hydrated, setAnchorV2Hydrated] =
    useState<import("../api/types").GuiV2LiveAnchorHydratedStateV1 | null>(null);
  const [anchorV2HydratedBusy, setAnchorV2HydratedBusy] = useState(false);
  const [anchorV2RecoveryBusy, setAnchorV2RecoveryBusy] = useState(false);
  // Connected-wallet account auto-fill (Task C).
  const [walletAccounts, setWalletAccounts] = useState<GuiWalletdAnchorAccountV1[] | null>(null);
  const [walletAccountsBusy, setWalletAccountsBusy] = useState(false);
  // Visible, secret-free status line for the "Use connected wallet" action, so a
  // click always shows a state transition (never a silent no-op). Cleared when a
  // new action starts. Never contains a token or API key.
  const [walletActionStatus, setWalletActionStatus] = useState<string | null>(null);
  // Read-only, secret-free connection diagnostic (no token/API key). Populated
  // on demand by the "Diagnose connection" control so an operator whose wallet
  // will not go Ready can see exactly where the flow stops: reachability,
  // credential presence, whether accounts.list was attempted, and the result.
  const [walletDiag, setWalletDiag] =
    useState<WalletdConnectionDiagnosticsV1 | null>(null);
  const [walletDiagBusy, setWalletDiagBusy] = useState(false);
  const onDiagnoseWalletConnection = async () => {
    setWalletDiagBusy(true);
    try {
      setWalletDiag(await api.walletdConnectionDiagnostics());
    } catch (error) {
      showError(error);
    } finally {
      setWalletDiagBusy(false);
    }
  };
  const [walletAccountPickerOpen, setWalletAccountPickerOpen] = useState(false);
  const anchorLoadedKeyRef = useRef<string | null>(null);
  // The frontend only signals whether to attach the walletd credential. The
  // shell resolves it from OS-backed secure storage (populated once via
  // Connect Tari Wallet) with WALLETD_AUTH_TOKEN as a dev-only fallback.
  const [anchorUseAuth, setAnchorUseAuth] = useState(false);
  const [walletdCredential, setWalletdCredential] =
    useState<WalletdCredentialStatusV1 | null>(null);
  const [walletdConnectOpen, setWalletdConnectOpen] = useState(false);
  const [walletdKeyInput, setWalletdKeyInput] = useState("");
  const [walletdBusy, setWalletdBusy] = useState(false);
  const [walletdError, setWalletdError] = useState<string | null>(null);
  const [walletdReadiness, setWalletdReadiness] =
    useState<WalletdReadinessV1 | null>(null);
  const [walletdReadinessBusy, setWalletdReadinessBusy] = useState(false);
  const refreshWalletdReadiness = async () => {
    setWalletdReadinessBusy(true);
    try {
      const readiness = await api.walletdReadiness();
      // The wallet card derives from the latest successful readiness result.
      setWalletdReadiness(readiness);
      // A fresh reachable probe supersedes any stale wallet-unreachable banner
      // left by an earlier failed account-list attempt.
      if (readiness.kind === "ready") clearStaleWalletError();
    } catch {
      // Bounded — probe failures are non-fatal; the last known state
      // remains visible.
    } finally {
      setWalletdReadinessBusy(false);
    }
  };
  // Production transport authority PUBLIC root (operator setup/review). Only
  // public material is ever handled here: the form collects a public-key hex,
  // and the readiness view shows a key id, network, and public-key fingerprint.
  // No private key is ever requested, entered, displayed, or persisted here.
  const [prodAuthority, setProdAuthority] =
    useState<ProductionTransportAuthorityReadinessV1 | null>(null);
  const [prodAuthorityBusy, setProdAuthorityBusy] = useState(false);
  const [prodAuthorityError, setProdAuthorityError] = useState<string | null>(null);
  const [prodAuthorityFormOpen, setProdAuthorityFormOpen] = useState(false);
  const [prodAuthorityNetwork, setProdAuthorityNetwork] = useState("");
  const [prodAuthorityKeyId, setProdAuthorityKeyId] = useState("");
  const [prodAuthorityPublicKeyHex, setProdAuthorityPublicKeyHex] = useState("");
  const [prodAuthorityLabel, setProdAuthorityLabel] = useState("");
  const refreshProductionAuthority = async () => {
    setProdAuthorityBusy(true);
    try {
      setProdAuthority(await api.productionTransportAuthorityStatus());
    } catch {
      // Bounded: a status probe failure leaves the last known state visible.
    } finally {
      setProdAuthorityBusy(false);
    }
  };
  const submitProductionAuthority = async () => {
    setProdAuthorityBusy(true);
    setProdAuthorityError(null);
    try {
      const readiness = await api.configureProductionTransportAuthorityRoot({
        network: prodAuthorityNetwork,
        root_key_id: prodAuthorityKeyId,
        root_public_key_hex: prodAuthorityPublicKeyHex,
        label: prodAuthorityLabel.trim().length > 0 ? prodAuthorityLabel.trim() : null,
      });
      setProdAuthority(readiness);
      setProdAuthorityFormOpen(false);
      setProdAuthorityPublicKeyHex("");
    } catch (error) {
      // Field-specific machine code surfaces so the operator sees WHICH field
      // is bad (key id, public key encoding, reserved id, network, ...).
      setProdAuthorityError(
        error instanceof BackendError ? error.payload.code : "GUI_PRODUCTION_TRANSPORT_AUTHORITY_CONFIG_SCHEMA_INVALID",
      );
    } finally {
      setProdAuthorityBusy(false);
    }
  };
  const forgetProductionAuthority = async () => {
    setProdAuthorityBusy(true);
    setProdAuthorityError(null);
    try {
      setProdAuthority(await api.forgetProductionTransportAuthorityRoot(true));
    } catch (error) {
      setProdAuthorityError(error instanceof BackendError ? error.payload.code : "GUI_IO_FAILURE");
    } finally {
      setProdAuthorityBusy(false);
    }
  };

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
  const verifiedArchiveResult = boundArchiveResult(
    archiveView.verification,
    archiveView.directory,
  );
  const verifiedFinalArchive =
    verifiedArchiveResult?.verified &&
    verifiedArchiveResult.finalized &&
    verifiedArchiveResult.transport_binding_present &&
    verifiedArchiveResult.transport_binding_verified &&
    verifiedArchiveResult.archive_hash_hex !== null &&
    verifiedArchiveResult.election_manifest_hash_hex === election?.manifest_hash_hex
      ? {
          directory: archiveView.directory,
          archive_hash_hex: verifiedArchiveResult.archive_hash_hex,
          file_count: verifiedArchiveResult.file_count,
          source: "verified" as const,
        }
      : null;
  const writtenArchiveVerified =
    archiveResult !== null && verifiedFinalArchive?.directory === archiveResult.directory;
  const selectedFinalArchive =
    archiveResult !== null && writtenArchiveVerified
      ? {
          directory: archiveResult.directory,
          archive_hash_hex: archiveResult.archive_hash_hex,
          file_count: archiveResult.files.length,
          source: "written" as const,
        }
      : verifiedFinalArchive;
  const archiveReadyForAnchor = selectedFinalArchive !== null;
  const finalArchiveError =
    localError !== null &&
    (localError.code === "GUI_ARCHIVE_TARGET_NOT_EMPTY" ||
      localError.code === "GUI_ARCHIVE_NOT_FINALIZED" ||
      localError.context === "archive-directory");
  const participationSealed =
    participation !== null && participation.participation_visibility === "SEALED_UNTIL_CLOSE";
  const participationDisclosed = participationIsDisclosed(participation);
  // Persisted terminal anchor state (RECEIPT_VERIFIED) takes priority over
  // any fresh in-session step result. Reading it here also feeds Next Step so
  // the completed-anchor case is never overridden by stale prep state.
  const anchorReceiptVerifiedTerminal =
    anchorV2StepResult?.receipt_verified === true ||
    anchorV2Hydrated?.receipt_verified === true;
  // Anchor submitted (transaction id known) but not yet terminal-verified.
  const anchorSubmittedButUnverifiedTerminal =
    !anchorReceiptVerifiedTerminal &&
    (anchorV2Hydrated?.transaction_id ?? null) !== null;
  // Plain-language organizer guidance derived ONLY from the real lifecycle
  // state plus this session's tally/archive/anchor results. Never invents
  // states. Terminal persisted anchor state wins over fresh preparation state.
  const nextStep = nextOrganizerStep({
    lifecycle,
    tallyComputed: tally !== null,
    archiveVerified: archiveReadyForAnchor,
    anchorSubmittedButUnverified: anchorSubmittedButUnverifiedTerminal,
    anchorVerified: anchorReceiptVerifiedTerminal,
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
  // Only surface items that ADD information beyond the lifecycle ProgressSteps
  // row (Created / Frozen / Open / Closed / Verified / Finalized). Repeating
  // "Voting opened", "Voting closed", "Result verified", "Election finalized"
  // in a second card duplicates what the lifecycle row already shows.
  const completedSummaries: string[] = [];
  if (guidedMode && lifecycle !== null) {
    if (lifecycle !== "FROZEN") {
      if (organizerStatus?.transport_provisioned && !showControl("intake")) {
        completedSummaries.push("Private intake configured");
      }
      if (organizerStatus?.transport_provisioned && !showControl("materials")) {
        completedSummaries.push("Voter materials available");
      }
    }
    if (tally !== null && !showControl("tally")) {
      completedSummaries.push("Tally computed");
    }
    if (archiveReadyForAnchor && !showControl("finalArchive")) {
      completedSummaries.push("Final archive written and verified");
    }
  }

  const trustedDeploymentV2 = trustedDeploymentV2Status?.deployment ?? null;
  const trustedDeploymentV2Fixed = trustedDeploymentV2Status?.fixed ?? null;
  // Anchor readiness checklist. Anchoring is locked until the election is
  // finalized and the archive is verified; the checklist makes each outstanding
  // prerequisite explicit so the operator is never left guessing why the
  // Prepare/Publish controls are disabled. Derived only from real state.
  const anchorDeploymentLocked = trustedDeploymentV2 !== null;
  const anchorPreparedForVersion = anchorV2Preparation !== null;
  const anchorPublishApproved = anchorV2StepResult?.receipt_verified === true;
  const anchorPrereqChecklist: { label: string; done: boolean }[] = [
    { label: "Election finalized", done: lifecycle === "FINALIZED" },
    { label: "Archive written", done: archiveResult !== null || verifiedFinalArchive !== null },
    { label: "Archive verified", done: archiveReadyForAnchor },
    { label: "Wallet connected", done: walletdReadiness?.kind === "ready" },
    { label: "Dedicated organizer wallet", done: anchorDedicatedWallet },
    { label: "Deployment locked", done: anchorDeploymentLocked },
    { label: "Anchor prepared", done: anchorPreparedForVersion },
    { label: "Publish approved", done: anchorPublishApproved },
  ];
  // The verified, finalized archive is the hard gate for anchoring: while it is
  // missing the operator must be sent back to the Archive step, not left to poke
  // at disabled controls.
  const anchorLockedUntilVerifiedArchive = !archiveReadyForAnchor;

  // Anchor Card status pill: terminal persisted state (receipt verified)
  // always wins over fresh in-session preparation/readiness state. Otherwise
  // it advertises what phase the V2 anchor is in without exposing internal
  // machine phases to a normal operator.
  const anchorStatusTone: "ok" | "warn" | "info" | "error" = anchorReceiptVerifiedTerminal
    ? "ok"
    : anchorSubmittedButUnverifiedTerminal
      ? "info"
      : anchorV2StepResult?.rejection_reason
        ? "error"
        : anchorV2Preparation
          ? "info"
          : archiveReadyForAnchor && anchorDeploymentLocked
            ? "ok"
            : "warn";
  const anchorStatusText = anchorReceiptVerifiedTerminal
    ? "Anchored · Verified"
    : anchorSubmittedButUnverifiedTerminal
      ? "Anchor submitted · verify receipt"
      : anchorV2StepResult?.rejection_reason
        ? "Wallet rejected request"
        : anchorV2Preparation
          ? "Awaiting wallet approval"
          : archiveReadyForAnchor && anchorDeploymentLocked
            ? "Ready to publish"
            : "Waiting for final archive";

  const commandErrorFromUnknown = (error: unknown): GuiCommandError =>
    error instanceof BackendError
      ? error.payload
      : {
          code: "GUI_UNEXPECTED_ERROR",
          category: "INVALID_INPUT",
          context: null,
          message: "an unexpected frontend/backend boundary error occurred",
        };

  const showError = (error: unknown) => {
    setLocalError(commandErrorFromUnknown(error));
  };

  const clearLocalError = () => setLocalError(null);

  // Clears ONLY a stale wallet/account error banner, leaving any unrelated
  // error intact. A previous "Use connected wallet" attempt that hit a
  // down walletd leaves a GUI_WALLETD_* banner; once readiness/account-listing
  // succeeds (or field validation passes) that banner must not survive, or the
  // operator sees a contradictory "walletd not reachable" beside a Ready wallet.
  const clearStaleWalletError = () =>
    setLocalError((prev) =>
      prev && (prev.context === "walletd" || prev.code.startsWith("GUI_WALLETD"))
        ? null
        : prev,
    );

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


  // HYDRATION: read the persisted V2 lifecycle sidecar for the currently
  // verified final archive so an already-submitted-but-unverified transaction is
  // recovered instead of falling back to the fresh Build/Prepare/Submit flow.
  // Read-only; never contacts walletd or the indexer. Runs for organizer
  // sessions only (the backend rejects it otherwise).
  useEffect(() => {
    if (!shellAvailable || !isOrganizer || !selectedFinalArchive) {
      setAnchorV2Hydrated(null);
      return;
    }
    let cancelled = false;
    setAnchorV2HydratedBusy(true);
    void (async () => {
      try {
        const hydrated = await api.inspectV2LiveAnchorState(selectedFinalArchive.directory);
        if (!cancelled) setAnchorV2Hydrated(hydrated);
      } catch {
        // Best-effort hydration. A read failure leaves the fresh flow visible;
        // the backend still fails closed on any doomed publish action.
        if (!cancelled) setAnchorV2Hydrated(null);
      } finally {
        if (!cancelled) setAnchorV2HydratedBusy(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [shellAvailable, isOrganizer, selectedFinalArchive?.directory, selectedFinalArchive?.archive_hash_hex]);

  const onRecoverExistingV2Anchor = async () => {
    if (!selectedFinalArchive || !anchorV2Hydrated?.transaction_id) return;
    clearLocalError();
    setAnchorV2RecoveryBusy(true);
    try {
      const result = await api.recoverV2LiveAnchor(
        selectedFinalArchive.directory,
        anchorIndexerEndpoint,
      );
      setAnchorV2StepResult(result);
      // Re-hydrate so blocks_fresh_publish / receipt_verified / phase reflect
      // the post-recovery persisted state.
      try {
        const hydrated = await api.inspectV2LiveAnchorState(selectedFinalArchive.directory);
        setAnchorV2Hydrated(hydrated);
      } catch {
        // Best-effort refresh; the step result already reflects the outcome.
      }
      recordAction(
        result.receipt_verified
          ? "Recovered existing V2 anchor (receipt verified)"
          : `Recovered existing V2 anchor: ${result.phase}`,
      );
    } catch (error) {
      showError(error);
    } finally {
      setAnchorV2RecoveryBusy(false);
    }
  };

  // Load the walletd credential status + one readiness probe once the shell
  // is available. The raw key never crosses this boundary — only presence
  // metadata and a bounded readiness kind. When a credential is present,
  // default to attaching it on publish so the organizer does not have to
  // toggle a checkbox on every launch.
  useEffect(() => {
    if (!shellAvailable) return;
    let cancelled = false;
    void (async () => {
      try {
        const status = await api.walletdCredentialStatus();
        if (cancelled) return;
        setWalletdCredential(status);
        if (status.stored || status.env_fallback_present) {
          setAnchorUseAuth(true);
        }
      } catch {
        // Best-effort; the Connect Tari Wallet control remains available.
      }
      if (cancelled) return;
      try {
        const readiness = await api.walletdReadiness();
        if (!cancelled) setWalletdReadiness(readiness);
      } catch {
        // Bounded probe; a failed probe leaves readiness null.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [shellAvailable]);

  useEffect(() => {
    if (!shellAvailable || !election || !isOrganizer || !tallyAvailable) {
      if (!tallyAvailable) setTally(null);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const result = await api.currentTally();
        if (!cancelled) setTally(result);
      } catch {
        // Authoritative refresh is best-effort on navigation; the Compute
        // tally button remains available and surfaces any real error.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [election?.manifest_hash_hex, lifecycle, shellAvailable, isOrganizer, tallyAvailable]);

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

  const refreshTrustedDeployment = async () => {
    if (!shellAvailable || !election || !isOrganizer) return;
    try {
      const v2Status = await api.trustedOotleDeploymentV2Status();
      setTrustedDeploymentV2Status(v2Status);
      setTrustedDeploymentV2StatusError(null);
    } catch (error) {
      setTrustedDeploymentV2Status(null);
      setTrustedDeploymentV2StatusError(commandErrorFromUnknown(error));
      showError(error);
    }
  };

  const intakeTorExepathOrUndefined = () =>
    intakeTorExePath.length > 0 ? intakeTorExePath : undefined;

  // Load the build's anchor-deployment capability once. It is compile-time
  // constant, so a single read is sufficient and never needs re-querying.
  useEffect(() => {
    if (!shellAvailable) return;
    let cancelled = false;
    void (async () => {
      try {
        const caps = await api.anchorDeploymentCapabilities();
        if (!cancelled) {
          setTransportBindingProvenanceAvailable(
            caps.transport_binding_provenance_available,
          );
        }
      } catch {
        // Best-effort; leave unknown (null) so the UI neither over-promises nor
        // falsely blocks. The backend still fails closed on any doomed action.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [shellAvailable]);

  // Load intake status when an election is loaded so the operator sees the
  // Tor/transport state without acting. Read-only. Also reset the per-election
  // auto-sync observation baseline so the next tick performs a first-observation
  // reconciliation for the newly loaded/recovered election.
  useEffect(() => {
    prevAcceptedRef.current = null;
    setTrustedDeploymentV2Status(null);
    setTrustedDeploymentV2StatusError(null);
    // Only an organizer context may query ballot-office intake status; the
    // backend rejects it for imported voter sessions, so we never ask.
    if (election && shellAvailable && isOrganizer) void refreshOrganizerStatus();
    if (election && shellAvailable && isOrganizer) void refreshTrustedDeployment();
    if (election && shellAvailable && isOrganizer) void refreshProductionAuthority();
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

  // The advanced external-remote argument for the intake start call, or
  // undefined for the default managed-local mode. Malformed numbers are sent
  // as 0 so the Rust shell rejects the whole request (fail closed).
  function remoteIntakeArg():
    | { socksHost: string; socksPort: number; onionHostname: string; collectorPort: number }
    | undefined {
    if (organizerTorMode !== "external-remote") return undefined;
    const port = /^\d{1,5}$/.test(remoteSocksPort.trim())
      ? Number(remoteSocksPort.trim())
      : 0;
    const collector = /^\d{1,5}$/.test(remoteCollectorPort.trim())
      ? Number(remoteCollectorPort.trim())
      : 0;
    return {
      socksHost: remoteSocksHost.trim(),
      socksPort: port,
      onionHostname: remoteOnionHostname.trim(),
      collectorPort: collector,
    };
  }

  // Persist the NON-SECRET external-remote configuration (mode + endpoint +
  // onion hostname + collector port). Sanitized on both write and read.
  function persistOrganizerRemoteTorConfig() {
    rememberOrganizerRemoteTorConfig({
      torMode: organizerTorMode,
      socksHost: remoteSocksHost.trim(),
      socksPort: remoteSocksPort.trim(),
      onionHostname: remoteOnionHostname.trim(),
      collectorPort: remoteCollectorPort.trim(),
    });
  }

  // Advanced external-remote explicit connection test. Runs ONLY the backend's
  // non-mutating, zero-application-byte SOCKS5 CONNECT probe to the organizer
  // onion through the external proxy — no collector start, no ballot bytes,
  // and the external Tor daemon is never touched.
  const onTestRemoteOrganizer = async () => {
    clearLocalError();
    setOrganizerBusy(true);
    try {
      const arg = remoteIntakeArg();
      if (!arg) return;
      const status = await api.testRemoteOrganizerTor(arg);
      setRemoteTestStatus(status);
      persistOrganizerRemoteTorConfig();
    } catch (error) {
      showError(error);
    } finally {
      setOrganizerBusy(false);
    }
  };

  const onStartIntake = async () => {
    clearLocalError();
    setOrganizerBusy(true);
    try {
      const status = await api.startPrivateIntake(
        intakeTorExepathOrUndefined(),
        remoteIntakeArg(),
      );
      setOrganizerStatus(status);
      persistOrganizerRemoteTorConfig();
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
      // This GUI's finalized archive is the anchor-eligible published record, so
      // it always requires a transport binding. The backend fails closed BEFORE
      // writing (GUI_TRANSPORT_ARCHIVE_BINDING_REQUIRED) when none is available,
      // so a valid-but-unbound archive is never produced and then mislabelled an
      // integrity failure.
      const result = await api.writeFinalizedArchive(
        archiveDir,
        archiveGovernanceDocPath,
        true,
      );
      setArchiveResult(result);
      const verification = await api.verifyArchive(result.directory);
      updateArchiveView({
        directory: result.directory,
        verification: { result: verification, verifiedDirectory: result.directory },
        transportAnchor: null,
      });
      if (
        !verification.verified ||
        !verification.finalized ||
        !verification.transport_binding_present ||
        !verification.transport_binding_verified
      ) {
        setLocalError({
          code: "GUI_FINAL_ARCHIVE_VERIFY_FAILED",
          category: "ARCHIVE_INTEGRITY",
          context: "archive-directory",
          message:
            "the finalized archive was written, but independent verification did not prove a finalized transport-bound archive",
        });
        return;
      }
      recordAction(
        archiveGovernanceDocPath
          ? "Wrote and verified finalized archive with governance document"
          : "Wrote and verified finalized archive",
      );
    } catch (error) {
      showError(error);
    }
  };

  // ---- Anchor form persistence (Task D) ---------------------------------

  const anchorStore = (): KeyValueStore | null => {
    try {
      return typeof window !== "undefined" && window.localStorage
        ? window.localStorage
        : null;
    } catch {
      return null;
    }
  };

  const anchorFormKey = anchorFormStorageKey(
    selectedFinalArchive?.archive_hash_hex,
    trustedDeploymentV2?.template_address,
  );

  const currentAnchorForm = (): AnchorFormState => ({
    signerMode: anchorSignerMode,
    anchorVersion,
    network: anchorNetwork,
    walletdEndpoint: anchorWalletdEndpoint,
    indexerEndpoint: anchorIndexerEndpoint,
    accountReference: anchorAccountRef,
    feeComponent: anchorFeeComponent,
    sealSignerKind: anchorSealSignerKind,
    sealSignerId: anchorSealSignerId,
    declaredSealPublicKey: anchorSealPubKey,
    maxFee: anchorMaxFee,
    maxEpochDelta: anchorMaxEpochDelta,
    acceptedBallotFloor: anchorFloor,
    dedicatedWallet: anchorDedicatedWallet,
  });

  const applyAnchorForm = (state: AnchorFormState) => {
    setAnchorSignerMode(state.signerMode);
    // Persisted anchorVersion is intentionally ignored: V2 is the only supported
    // publishing surface. The field is kept in the persisted schema so an
    // older saved form still loads without a validation failure.
    setAnchorNetwork(state.network);
    setAnchorWalletdEndpoint(state.walletdEndpoint);
    setAnchorIndexerEndpoint(state.indexerEndpoint);
    setAnchorAccountRef(state.accountReference);
    setAnchorFeeComponent(state.feeComponent);
    setAnchorSealSignerKind(state.sealSignerKind);
    setAnchorSealSignerId(state.sealSignerId);
    setAnchorSealPubKey(state.declaredSealPublicKey);
    setAnchorMaxFee(state.maxFee);
    setAnchorMaxEpochDelta(state.maxEpochDelta);
    setAnchorFloor(state.acceptedBallotFloor);
    setAnchorDedicatedWallet(state.dedicatedWallet);
  };

  // Restore the persisted form whenever the (archive hash, template address)
  // key changes — this is what survives tab/screen switches and unmount.
  useEffect(() => {
    applyAnchorForm(loadAnchorFormState(anchorStore(), anchorFormKey));
    anchorLoadedKeyRef.current = anchorFormKey;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchorFormKey]);

  // Persist on any field change, but only after this key has been loaded, so
  // the initial default state never clobbers stored values.
  useEffect(() => {
    if (anchorLoadedKeyRef.current !== anchorFormKey) return;
    saveAnchorFormState(anchorStore(), anchorFormKey, currentAnchorForm());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    anchorFormKey,
    anchorSignerMode,
    anchorVersion,
    anchorNetwork,
    anchorWalletdEndpoint,
    anchorIndexerEndpoint,
    anchorAccountRef,
    anchorFeeComponent,
    anchorSealSignerKind,
    anchorSealSignerId,
    anchorSealPubKey,
    anchorMaxFee,
    anchorMaxEpochDelta,
    anchorFloor,
    anchorDedicatedWallet,
  ]);

  const onUseConnectedWallet = async () => {
    clearLocalError();
    // A click ALWAYS produces a visible state transition: the status line and the
    // busy button change before the backend is even contacted, so the action can
    // never look like a silent no-op.
    setWalletActionStatus("Checking saved wallet credential…");
    setWalletAccountsBusy(true);
    try {
      setWalletActionStatus("Listing wallet accounts…");
      const result = await api.listWalletdAnchorAccounts();
      // The account-list result carries the same bounded readiness fields as a
      // readiness probe. Derive the wallet card status directly from this
      // latest successful call so the card can never disagree with the auto-fill
      // outcome (no second probe that could race or transiently fail).
      setWalletdReadiness({
        kind: result.kind,
        endpoint: result.endpoint,
        network: result.network,
        summary: result.summary,
      });
      // Terminal, secret-free status naming the exact outcome.
      setWalletActionStatus(walletActionStatusForKind(result.kind));
      if (result.kind !== "ready") {
        setWalletAccounts(null);
        // A reachable walletd whose account list failed (permission gap, call
        // failure) must never be reported as "not reachable" — the message
        // names the specific cause the operator can act on.
        const unreachable = result.kind === "unreachable";
        setLocalError({
          code: unreachable
            ? "GUI_WALLETD_ACCOUNTS_UNAVAILABLE"
            : "GUI_WALLETD_ACCOUNTS_NOT_READY",
          category: "UNAVAILABLE",
          context: "walletd",
          message: walletAccountsErrorMessage(result.kind),
        });
        return;
      }
      // A successful listing supersedes any stale wallet-unreachable banner left
      // by an earlier failed attempt.
      clearStaleWalletError();
      setWalletAccounts(result.accounts);
      if (result.accounts.length === 0) {
        setWalletActionStatus("Connected wallet has no accounts");
        setLocalError({
          code: "GUI_WALLETD_NO_ACCOUNTS",
          category: "UNAVAILABLE",
          context: "walletd",
          message: "the connected wallet has no accounts to select",
        });
      } else if (result.accounts.length === 1) {
        applyWalletAccount(result.accounts[0]);
      } else {
        setWalletActionStatus("Select the fee/seal account");
        setWalletAccountPickerOpen(true);
      }
    } catch (error) {
      setWalletActionStatus("Wallet account listing failed");
      showError(error);
    } finally {
      setWalletAccountsBusy(false);
    }
  };

  const applyWalletAccount = (account: GuiWalletdAnchorAccountV1) => {
    // The wallet layer is shared across versions: the account's fee component and
    // signer fill identically. Only the network *hint* is version-aware — it must
    // come from the lock that matches the selected anchor version, never the V1
    // lock while V2 is selected. A missing relevant lock keeps the safe fallback
    // (the form's current network is preserved by applyConnectedWallet).
    const relevantLock = trustedDeploymentV2;
    const filled = applyConnectedWallet(
      currentAnchorForm(),
      account,
      relevantLock
        ? { network: relevantLock.network, template_address: relevantLock.template_address }
        : null,
    );
    applyAnchorForm(filled);
    setWalletAccountPickerOpen(false);
    recordAction("Filled anchor fields from connected wallet");
  };

  const onResetAnchorForm = () => {
    clearAnchorFormState(anchorStore(), anchorFormKey);
    applyAnchorForm(defaultAnchorFormState());
    setAnchorV2Result(null);
    setAnchorV2Preparation(null);
    setWalletAccounts(null);
    setWalletAccountPickerOpen(false);
    recordAction("Reset anchor form");
  };

  // V2 deployment is independently locked. It never reads a V1 address or digest.
  const V2_TEMPLATE_MODULE = "tari_private_ballot_anchor_v2";
  const V2_TEMPLATE_FUNCTION = "publish_anchor_v2";
  const V2_EVENT_TOPIC =
    "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";

  const onBuildV2Payload = async () => {
    if (!selectedFinalArchive || !trustedDeploymentV2) return;
    clearLocalError();
    setAnchorV2Busy(true);
    setAnchorV2Result(null);
    setAnchorV2Preparation(null);
    setAnchorV2StepResult(null);
    setAnchorV2PublishConfirmed(false);
    try {
      const result = await api.buildV2PublicAnchorPayload({
        archive_directory: selectedFinalArchive.directory,
        network: trustedDeploymentV2.network,
        template_address: trustedDeploymentV2.template_address,
        template_module: V2_TEMPLATE_MODULE,
        template_function: V2_TEMPLATE_FUNCTION,
        template_event_topic: V2_EVENT_TOPIC,
        template_artifact_digest_hex:
          trustedDeploymentV2.template_artifact_digest_hex,
      });
      setAnchorV2Result(result);
      recordAction("Built V2 public anchor summary");
    } catch (error) {
      showError(error);
    } finally {
      setAnchorV2Busy(false);
    }
  };

  const onPrepareV2AnchorPublish = async () => {
    if (!selectedFinalArchive || !anchorV2Result) return;
    clearLocalError();
    setAnchorV2Busy(true);
    setAnchorV2Preparation(null);
    try {
      const preparation = await api.prepareV2AnchorPublish(
        selectedFinalArchive.directory,
        anchorV2Result.payload_hex,
        anchorV2Result.v2_anchor_digest_hex,
      );
      setAnchorV2Preparation(preparation);
      setAnchorV2StepResult(null);
      setAnchorV2PublishConfirmed(false);
      recordAction("Prepared V2 public-summary template call");
    } catch (error) {
      showError(error);
    } finally {
      setAnchorV2Busy(false);
    }
  };

  const onRunV2AnchorLifecycle = async (decision: "none" | "approve") => {
    if (!selectedFinalArchive || !anchorV2Result || !anchorV2Preparation) return;
    clearLocalError();
    setAnchorV2Busy(true);
    try {
      const result = await api.runV2LiveAnchorLifecycleStep({
        archive_directory: selectedFinalArchive.directory,
        payload_hex: anchorV2Result.payload_hex,
        expected_digest_hex: anchorV2Result.v2_anchor_digest_hex,
        fee_component: anchorFeeComponent,
        seal_signer_kind: anchorSealSignerKind,
        seal_signer_id: anchorSealSignerId,
        max_fee: anchorMaxFee,
        max_epoch_delta: anchorMaxEpochDelta,
        walletd_endpoint: anchorWalletdEndpoint,
        indexer_endpoint: anchorIndexerEndpoint,
        use_walletd_auth: anchorUseAuth,
        decision,
      });
      setAnchorV2StepResult(result);
      recordAction(`V2 anchor lifecycle: ${result.phase}`);
    } catch (error) {
      showError(error);
    } finally {
      setAnchorV2Busy(false);
    }
  };

  const onLockTrustedDeploymentV2 = async () => {
    clearLocalError();
    setDeploymentBusy(true);
    setAnchorV2Result(null);
    try {
      // Default to the pinned reviewed BLAKE3 from the backend fixed status,
      // so a normal organizer never has to compute or paste the artifact
      // digest. The Advanced override lets a reviewer submit a different
      // value, which the Rust lock will still reject unless it matches the
      // pinned constant.
      const manualDigest = anchorV2ArtifactDigest.trim();
      const digest =
        manualDigest.length === 64
          ? manualDigest
          : trustedDeploymentV2Fixed?.expected_artifact_digest_hex ?? "";
      const status = await api.lockTrustedOotleDeploymentV2({
        network: anchorNetwork,
        template_address: anchorV2TemplateAddress.trim(),
        template_artifact_digest_hex: digest,
      });
      setTrustedDeploymentV2Status(status);
      setTrustedDeploymentV2StatusError(null);
      recordAction(`Locked V2 Ootle anchor deployment (${status.deployment?.network ?? anchorNetwork})`);
    } catch (error) {
      showError(error);
      await refreshTrustedDeployment();
    } finally {
      setDeploymentBusy(false);
    }
  };

  const onUnlockTrustedDeploymentV2 = async () => {
    clearLocalError();
    setDeploymentBusy(true);
    setAnchorV2Result(null);
    try {
      const status = await api.unlockTrustedOotleDeploymentV2();
      setTrustedDeploymentV2Status(status);
      setTrustedDeploymentV2StatusError(null);
      setConfirmUnlockDeploymentV2(false);
      recordAction("Unlocked V2 Ootle anchor deployment");
    } catch (error) {
      showError(error);
    } finally {
      setDeploymentBusy(false);
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

  // Tari Wallet connection panel — visible on the Anchor card whenever an
  // organizer session is loaded. The V2 fee/request lifecycle drives every
  // wallet interaction through this one panel: connect the wallet, see its
  // readiness, replace the API key, remove it, and diagnose a stalled probe.
  const walletPanelJsx = (
    <div className="anchor-wallet-panel">
      <div className="anchor-wallet-panel__header">
        <strong>Tari Wallet</strong>
        {(() => {
          const kind = walletdReadiness?.kind ?? null;
          if (kind === "ready")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--ok">
                Ready
                {walletdReadiness?.network ? ` — ${walletdReadiness.network}` : ""}
              </span>
            );
          if (kind === "auth_rejected")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                Reconnect Tari Wallet
              </span>
            );
          if (kind === "permission_denied")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                Reconnect with Accounts:Read
              </span>
            );
          if (kind === "call_failed")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                walletd reachable — request failed
              </span>
            );
          if (kind === "unreachable")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                Start Tari Wallet
              </span>
            );
          if (kind === "no_credential")
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                Connect Tari Wallet
              </span>
            );
          if (walletdCredential?.stored)
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--ok">
                Connected
              </span>
            );
          if (walletdCredential?.env_fallback_present)
            return (
              <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
                Using development env var
              </span>
            );
          return (
            <span className="anchor-wallet-panel__status anchor-wallet-panel__status--warn">
              Not connected
            </span>
          );
        })()}
        <button
          type="button"
          className="btn btn-link"
          disabled={walletdReadinessBusy}
          onClick={() => void refreshWalletdReadiness()}
          title="Refresh Tari Wallet readiness"
        >
          {walletdReadinessBusy ? "Checking…" : "Refresh"}
        </button>
      </div>
      {walletdReadiness?.kind === "ready" && walletdReadiness?.summary && (
        <p className="form-hint">Selected organizer account: {walletdReadiness.summary}</p>
      )}
      {walletdCredential?.stored && (
        <p className="form-hint">
          API key stored in {walletdCredential.store_label}. The key is never displayed,
          exported, or written to logs. Private Ballot retrieves it automatically on
          every launch.
        </p>
      )}
      {!walletdCredential?.stored && !walletdCredential?.env_fallback_present && (
        <>
          <p className="form-hint">
            Open your Tari Wallet, create an API key named &quot;Private Ballot&quot;
            with these permissions:
          </p>
          <ul className="form-hint anchor-wallet-panel__perms">
            <li><code>Transactions:Read</code> — read anchor transaction state</li>
            <li>
              <code>TransactionRequests:Create</code> — prepare and submit the anchor
              request
            </li>
            <li><code>TransactionRequests:Read</code> — poll the anchor request status</li>
            <li>
              <code>TransactionRequests:Approve</code> — approve the prepared anchor
              request
            </li>
            <li>
              <code>Accounts:Read</code> — list your wallet accounts for one-click auto-fill
            </li>
          </ul>
          <p className="form-hint">
            Do NOT grant <code>Admin</code>. Paste the key once — Private Ballot
            stores it in your OS credential store and reuses it automatically.
          </p>
        </>
      )}
      {walletdConnectOpen ? (
        <div className="anchor-wallet-panel__form">
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder="tw_…"
            value={walletdKeyInput}
            disabled={walletdBusy}
            onChange={(e) => {
              setWalletdKeyInput(e.target.value);
              setWalletdError(null);
            }}
          />
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={walletdBusy || walletdKeyInput.trim().length < 46}
              onClick={() => {
                setWalletdBusy(true);
                setWalletdError(null);
                const key = walletdKeyInput;
                void (walletdCredential?.stored
                  ? api.reconnectWalletd(key)
                  : api.connectWalletd(key))
                  .then(async (status) => {
                    setWalletdCredential(status);
                    setWalletdConnectOpen(false);
                    setWalletdKeyInput("");
                    if (status.stored) setAnchorUseAuth(true);
                    setWalletAccounts(null);
                    clearLocalError();
                    await refreshWalletdReadiness();
                  })
                  .catch((err) => {
                    setWalletdError(
                      err instanceof BackendError
                        ? err.payload.message
                        : "could not save credential",
                    );
                  })
                  .finally(() => setWalletdBusy(false));
              }}
            >
              Save
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={walletdBusy}
              onClick={() => {
                setWalletdConnectOpen(false);
                setWalletdKeyInput("");
                setWalletdError(null);
              }}
            >
              Cancel
            </button>
          </div>
          {walletdError && <Notice tone="error">{walletdError}</Notice>}
        </div>
      ) : (
        <div className="btn-row">
          {walletdCredential?.stored ? (
            <>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={walletdBusy}
                onClick={() => setWalletdConnectOpen(true)}
              >
                Reconnect Tari Wallet
              </button>
              <button
                type="button"
                className="btn btn-tertiary"
                disabled={walletdBusy}
                onClick={() => {
                  setWalletdBusy(true);
                  void api
                    .forgetWalletd()
                    .then(async (status) => {
                      setWalletdCredential(status);
                      if (!status.stored && !status.env_fallback_present) {
                        setAnchorUseAuth(false);
                      }
                      await refreshWalletdReadiness();
                    })
                    .catch(() => {
                      setWalletdError("could not remove stored credential");
                    })
                    .finally(() => setWalletdBusy(false));
                }}
              >
                Forget Tari Wallet
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              disabled={walletdBusy}
              onClick={() => setWalletdConnectOpen(true)}
            >
              Connect Tari Wallet
            </button>
          )}
        </div>
      )}
      <div className="anchor-wallet-panel__diag">
        <button
          type="button"
          className="btn btn-link"
          disabled={walletDiagBusy}
          onClick={() => void onDiagnoseWalletConnection()}
          title="Run a read-only walletd connection check (no secrets shown)"
        >
          {walletDiagBusy ? "Diagnosing…" : "Diagnose connection"}
        </button>
        {walletDiag && (
          <dl
            className="form-hint anchor-wallet-diag"
            data-testid="wallet-connection-diagnostics"
          >
            <div>
              <dt>Endpoint</dt>
              <dd className="hash">{walletDiag.endpoint_normalized}</dd>
            </div>
            <div>
              <dt>Saved credential</dt>
              <dd>{walletDiag.saved_credential ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>TCP loopback</dt>
              <dd>
                {walletDiag.tcp_loopback_attempted
                  ? walletDiag.tcp_loopback_reachable
                    ? "reachable"
                    : "unreachable"
                  : "not attempted"}
              </dd>
            </div>
            <div>
              <dt>wallet.get_info</dt>
              <dd>
                {walletDiag.unauthenticated_wallet_get_info_attempted
                  ? walletDiag.unauthenticated_wallet_get_info_result.status === "success"
                    ? "success"
                    : `failed: ${walletDiag.unauthenticated_wallet_get_info_result.category ?? "unknown"}`
                  : "not attempted"}
              </dd>
            </div>
            <div>
              <dt>accounts.list</dt>
              <dd>
                {walletDiag.accounts_list_attempted
                  ? walletDiag.accounts_list_result.status === "success"
                    ? "success"
                    : `failed: ${walletDiag.accounts_list_result.category ?? "unknown"}`
                  : "not attempted"}
              </dd>
            </div>
            <div>
              <dt>Result</dt>
              <dd>{walletDiag.final_result_kind}</dd>
            </div>
            {walletDiag.network && (
              <div>
                <dt>Network</dt>
                <dd>{walletDiag.network}</dd>
              </div>
            )}
            {walletDiag.account_count !== null && (
              <div>
                <dt>Accounts</dt>
                <dd>{walletDiag.account_count}</dd>
              </div>
            )}
            {walletDiag.selected_account_name && (
              <div>
                <dt>Selected account</dt>
                <dd>{walletDiag.selected_account_name}</dd>
              </div>
            )}
          </dl>
        )}
      </div>
    </div>
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
          {organizerTorMode === "managed-local" ? (
            <p className="card-body">
              Accept ballots submitted privately over Tor. Starting intake runs Tor and the
              private receiver for you — no terminal, torrc, or network settings. Ballots are
              accepted into this election through the same checks as an imported ballot: each is
              accepted only once, and an exact resend is never counted twice.
            </p>
          ) : (
            <p className="card-body">
              Accept ballots submitted privately over Tor through your EXTERNALLY managed Tor
              instance. Private Ballot does not start, stop, or verify that Tor daemon; it only
              checks that the organizer onion is reachable through it and runs the local ballot
              receiver the remote hidden service forwards to. Ballot acceptance checks are
              identical to managed-local mode.
            </p>
          )}

          {/* Advanced Tor hosting mode. Hidden from the guided view entirely:
              normal operators always stay on the recommended managed-local
              mode; the remote option is only visible under Show all election
              controls and always requires explicit configuration. */}
          {showAllControls && (
            <>
              <fieldset className="tor-mode-fieldset">
                <legend>Organizer Tor hosting</legend>
                <label className="radio-row">
                  <input
                    type="radio"
                    name="organizer-tor-mode"
                    checked={organizerTorMode === "managed-local"}
                    disabled={organizerBusy || organizerStatus?.intake_running === true}
                    onChange={() => setOrganizerTorMode("managed-local")}
                  />
                  <span>
                    <strong>Managed Local Tor</strong> — Recommended. Private Ballot starts and
                    manages Tor locally.
                  </span>
                </label>
                <label className="radio-row">
                  <input
                    type="radio"
                    name="organizer-tor-mode"
                    checked={organizerTorMode === "external-remote"}
                    disabled={organizerBusy || organizerStatus?.intake_running === true}
                    onChange={() => setOrganizerTorMode("external-remote")}
                  />
                  <span>
                    <strong>Remote Organizer Tor</strong> — Advanced. Use an externally managed
                    Tor instance and onion service.
                  </span>
                </label>
              </fieldset>

              {organizerTorMode === "external-remote" && (
                <div className="config-stack">
                  <Notice tone="warn">
                    Remote Organizer Tor is intended for infrastructure you control over a
                    trusted LAN, VPN, or protected tunnel. Private Ballot does not manage or
                    verify the remote Tor daemon, and the link between this app and the SOCKS
                    proxy is not itself encrypted. The ballot receiver binds to this machine's
                    loopback only and is never exposed on the network, so a Tor daemon running
                    on a different machine must reach it through a tunnel that terminates on
                    this machine's loopback collector port — its HiddenServicePort cannot target
                    this machine's LAN address directly. Onion traffic still goes only through
                    Tor; there is no clearnet fallback.
                  </Notice>
                  <div className="form-row form-row--full">
                    <label htmlFor="remote-organizer-socks-host">SOCKS host</label>
                    <input
                      id="remote-organizer-socks-host"
                      type="text"
                      value={remoteSocksHost}
                      onChange={(e) => {
                        setRemoteSocksHost(e.target.value);
                        // Editing any field invalidates a prior connection-test
                        // result so a stale "Ready ✓" is never shown against
                        // changed inputs (the backend re-probes on Start anyway).
                        setRemoteTestStatus(null);
                      }}
                      placeholder="127.0.0.1  or  tor.internal.example"
                    />
                  </div>
                  <div className="form-row">
                    <label htmlFor="remote-organizer-socks-port">SOCKS port</label>
                    <input
                      id="remote-organizer-socks-port"
                      type="text"
                      inputMode="numeric"
                      value={remoteSocksPort}
                      onChange={(e) => {
                        setRemoteSocksPort(e.target.value);
                        setRemoteTestStatus(null);
                      }}
                      placeholder="9050"
                    />
                  </div>
                  <div className="form-row">
                    <label htmlFor="remote-organizer-collector-port">
                      Local collector port (remote HiddenServicePort target)
                    </label>
                    <input
                      id="remote-organizer-collector-port"
                      type="text"
                      inputMode="numeric"
                      value={remoteCollectorPort}
                      onChange={(e) => {
                        setRemoteCollectorPort(e.target.value);
                        setRemoteTestStatus(null);
                      }}
                      placeholder="18081"
                    />
                  </div>
                  <div className="form-row form-row--full">
                    <label htmlFor="remote-organizer-onion">Organizer onion hostname</label>
                    <input
                      id="remote-organizer-onion"
                      type="text"
                      value={remoteOnionHostname}
                      onChange={(e) => {
                        setRemoteOnionHostname(e.target.value);
                        setRemoteTestStatus(null);
                      }}
                      placeholder="your-organizer-onion-hostname.onion"
                    />
                  </div>
                  <div className="field-list">
                    <Field label="Connection test">
                      {remoteTestStatus === null
                        ? "Not checked"
                        : remoteTestStatus.ready
                          ? "Ready ✓"
                          : "Failed / not reachable"}
                    </Field>
                  </div>
                  <div className="action-row">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={
                        organizerBusy ||
                        organizerStatus?.intake_running === true ||
                        !remoteSocksHost.trim() ||
                        !remoteOnionHostname.trim()
                      }
                      onClick={() => void onTestRemoteOrganizer()}
                    >
                      Test connection
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

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
              {organizerTorMode === "external-remote"
                ? "External (not managed here)"
                : organizerStatus === null
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
                  (organizerTorMode === "managed-local" &&
                    organizerStatus !== null &&
                    !organizerStatus.tor_found)
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
                  (organizerTorMode === "managed-local"
                    ? organizerStatus !== null && !organizerStatus.tor_found
                    : !remoteSocksHost.trim() || !remoteOnionHostname.trim())
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
          {/* Terminal verified state wins: when a verified final archive
              already exists for this election, its summary leads the card and
              new-archive creation moves under a disclosure. The warning
              about the current runtime being unable to CREATE a new
              transport-bound archive only makes sense while we are still
              trying to create one; it must not visually imply the existing
              verified archive is defective. */}
          {verifiedFinalArchive && (
            <>
              <Notice tone="ok">
                <strong>Final archive verified</strong>
              </Notice>
              <div className="field-list" data-testid="final-archive-verified-summary">
                <Field label="Folder">
                  <span className="hash">{verifiedFinalArchive.directory}</span>
                  <CopyButton value={verifiedFinalArchive.directory} />
                </Field>
                <Field label="Archive hash">
                  <HashValue value={verifiedFinalArchive.archive_hash_hex} />
                  <CopyButton value={verifiedFinalArchive.archive_hash_hex} />
                </Field>
                <Field label="Files verified">{verifiedFinalArchive.file_count}</Field>
                {participationDisclosed && participation?.accepted_ballots != null && (
                  <Field label="Accepted ballots">{participation.accepted_ballots}</Field>
                )}
              </div>
              <p className="form-hint">
                The independently verified final archive is the authoritative election record.
                Anyone can re-verify it on the Archive screen.
              </p>
            </>
          )}
          {!verifiedFinalArchive && (
            <p className="card-body">
              Writes the complete election record to a folder: the election definition, eligible
              voter list, ballot options, and accepted ballots. Anyone can later verify this
              record independently on the Archive screen. Optionally include the governance
              supporting document so its bytes travel with the record.
            </p>
          )}
          {!finalArchiveAvailable && !verifiedFinalArchive && (
            <Notice tone="info">
              Mark verified and finalize the election before writing the final archive.
            </Notice>
          )}
          {transportBindingProvenanceAvailable === false && !verifiedFinalArchive && (
            <Notice tone="warn">
              This build cannot produce a transport-bound (anchor-eligible) archive:
              it has no configured private-transport provenance. Writing the final
              archive will be refused here (the election record stays valid and can
              still be verified offline), and live anchoring is unavailable. Use an
              organizer build with active private intake to produce an anchor-eligible
              archive.
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
          {!verifiedFinalArchive && (
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
          )}
          {!verifiedFinalArchive && (
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
          )}
          {/* VERIFIED phase: the finalize action is the prominent next step,
              so its permanence warning sits directly beside it (the explicit
              confirmation dialog remains the safeguard). */}
          {lifecycle === "VERIFIED" && (
            <Notice tone="warn">
              Finalizing is permanent: the verified result and finalized election record
              cannot be changed afterward.
            </Notice>
          )}
          {!verifiedFinalArchive && (
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
          )}
          <BackendErrorNotice error={finalArchiveError ? localError : null} onDismiss={clearLocalError} />
          {archiveResult && !verifiedFinalArchive && (
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
          {archiveResult && !writtenArchiveVerified && !verifiedFinalArchive && (
            <Notice tone="warn">
              The archive was written, but live anchor preparation is waiting for independent
              verification of the finalized transport binding.
            </Notice>
          )}
          {verifiedFinalArchive && (
            <DetailsSection summary="Create another final archive">
              <p className="form-hint">
                A verified final archive already exists for this election. Creating another
                archive does not modify or replace the existing one — it would write a separate
                record into a different folder.
              </p>
              {transportBindingProvenanceAvailable === false && (
                <Notice tone="warn">
                  This build cannot produce a transport-bound (anchor-eligible) archive:
                  it has no configured private-transport provenance. Writing another final
                  archive would be refused here. Use an organizer build with active private
                  intake to produce an anchor-eligible archive.
                </Notice>
              )}
              <div className="form-row">
                <label htmlFor="archive-dir-alt">Target directory (new or empty)</label>
                <div className="file-row">
                  <input
                    id="archive-dir-alt"
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
                <label htmlFor="archive-gov-doc-alt">Governance document (optional)</label>
                <input
                  id="archive-gov-doc-alt"
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
              <div className="btn-row">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!canAct || !archiveDir || !finalArchiveAvailable}
                  onClick={() => void onWriteArchive()}
                >
                  Write another final archive
                </button>
              </div>
              {archiveResult && (
                <>
                  <Notice tone="ok">
                    Additional archive written
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
            </DetailsSection>
          )}
        </Card>
        )}

        <Card title="Tari Anchor">
          <Notice tone="info">
            Optional public integrity anchor: anchor the aggregate finalized archive commitment
            on Tari Ootle. Individual votes are not written to Ootle. Anchoring is optional and
            non-binding — the independently verified offline archive remains authoritative.
          </Notice>

          {anchorLockedUntilVerifiedArchive && (
            <Notice tone="warn">
              <p className="anchor-prereq-title">
                <strong>Verify ballot results before anchoring</strong>
              </p>
              <p>
                Anchoring is locked until the election is finalized and the archive has been
                verified. The Ootle anchor is built from the verified archive hash and final
                tally. Open the Archive menu, verify the results, then return here to prepare the
                anchor.
              </p>
              <ul className="anchor-prereq-checklist">
                {anchorPrereqChecklist.map((item) => (
                  <li
                    key={item.label}
                    className={item.done ? "prereq-done" : "prereq-todo"}
                  >
                    <span aria-hidden="true" className="prereq-mark">
                      {item.done ? "✓" : "○"}
                    </span>
                    <span>{item.label}</span>
                    {!item.done && <span className="prereq-status"> — required</span>}
                  </li>
                ))}
              </ul>
            </Notice>
          )}

          <div className="field-list anchor-deployment-fields">
            <Field label="Status">
              <Pill tone={anchorStatusTone}>{anchorStatusText}</Pill>
            </Field>
            <Field label="Wallet">
              <Pill
                tone={
                  walletdReadiness?.kind === "ready"
                    ? "ok"
                    : walletdReadiness?.kind === "unreachable" || walletdReadiness === null
                      ? "warn"
                      : "info"
                }
              >
                {walletdReadiness?.summary ?? "Checking wallet"}
                {walletdReadiness?.network ? ` — ${walletdReadiness.network}` : ""}
              </Pill>
            </Field>
          </div>

          {/* Terminal verified anchor: fresh wallet/setup controls are not
              needed and previously produced contradictory UX (Start Tari
              Wallet / Ready to publish beside a verified anchor). Keep the
              wallet panel available under Advanced for diagnostics. */}
          {anchorReceiptVerifiedTerminal ? (
            <DetailsSection summary="Advanced: wallet connection">
              {walletPanelJsx}
            </DetailsSection>
          ) : (
            walletPanelJsx
          )}

          {/* Anchor setup assistant: one-click fill from the connected wallet.
              The V2 fee/request lifecycle uses the auto-filled wallet fields —
              organizers do not hand-type endpoint/fee/seal fields any more.
              Hidden after the anchor is terminal-verified; it is a preparation
              control and has no purpose once the anchor is complete. */}
          {!anchorReceiptVerifiedTerminal && (
          <div className="anchor-setup-assistant">
              <div className="btn-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={
                    !canAct ||
                    !trustedDeploymentV2 ||
                    walletAccountsBusy
                  }
                  onClick={() => void onUseConnectedWallet()}
                >
                  {walletAccountsBusy ? "Reading wallet…" : "Use connected wallet"}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={onResetAnchorForm}
                >
                  Reset anchor form
                </button>
              </div>
              {walletActionStatus && (
                <p
                  className="form-hint anchor-wallet-action-status"
                  role="status"
                  aria-live="polite"
                  data-testid="wallet-action-status"
                >
                  {walletActionStatus}
                </p>
              )}
              <label
                className="anchor-checkbox-row"
                data-testid="dedicated-organizer-wallet-attestation"
              >
                <input
                  type="checkbox"
                  checked={anchorDedicatedWallet}
                  onChange={(e) => setAnchorDedicatedWallet(e.target.checked)}
                />
                <span>
                  Dedicated organizer wallet
                  <small>
                    Confirm this Tari wallet/account is dedicated to
                    organizer-side election anchoring and is not being used as a
                    voter wallet.
                  </small>
                </span>
              </label>
              {!trustedDeploymentV2 && (
                <p className="form-hint">
                  Lock the Ootle anchor deployment (Advanced) before auto-fill.
                </p>
              )}

              {walletAccountPickerOpen && walletAccounts && walletAccounts.length > 1 && (
                <div className="anchor-account-picker">
                  <p className="form-hint">Select the organizer fee/seal account:</p>
                  {walletAccounts.map((account) => (
                    <button
                      type="button"
                      key={account.component_address}
                      className="btn btn-secondary anchor-account-option"
                      onClick={() => applyWalletAccount(account)}
                    >
                      <span className="anchor-account-name">
                        {account.name ?? "(unnamed account)"}
                        {account.is_default ? " • default" : ""}
                        {account.is_confirmed_on_chain ? "" : " • unconfirmed"}
                      </span>
                      <span className="hash anchor-account-address">
                        {account.component_address}
                      </span>
                      <span className="form-hint">
                        key index {account.key_index ?? "—"}
                      </span>
                    </button>
                  ))}
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setWalletAccountPickerOpen(false)}
                  >
                    Cancel
                  </button>
                </div>
              )}

            </div>
          )}

          {/* V2 public-summary anchor is the only supported normal publishing
              surface. Individual votes are never published — Ootle carries only
              the readable aggregate election summary. */}
          <div className="anchor-version-selector">
            <div className="anchor-v2-review">
                <Notice tone="info">
                  This anchor publishes the readable public aggregate election summary.
                  Individual votes are NEVER published. Detached evidence is written beside the
                  archive for independent re-verification.
                </Notice>
                <div className="field-list anchor-deployment-fields">
                  <Field label="Deployment lock">
                    {trustedDeploymentV2 ? (
                      <Pill tone="ok">LOCKED</Pill>
                    ) : trustedDeploymentV2StatusError ? (
                      <Pill tone="error">OUTDATED / RESET REQUIRED</Pill>
                    ) : (
                      <Pill tone="warn">UNLOCKED</Pill>
                    )}
                  </Field>
                </div>
                <DetailsSection summary="Advanced: anchor template binding">
                  <div className="field-list anchor-deployment-fields">
                    <Field label="Template module"><HashValue value={trustedDeploymentV2Fixed?.template_module} /></Field>
                    <Field label="Template function"><HashValue value={trustedDeploymentV2Fixed?.template_function} /></Field>
                    <Field label="Event topic"><HashValue value={trustedDeploymentV2Fixed?.template_event_topic} /></Field>
                  </div>
                </DetailsSection>
                {trustedDeploymentV2 ? (
                  <>
                    <div className="field-list anchor-deployment-fields">
                      <Field label="Network">{trustedDeploymentV2.network}</Field>
                      <Field label="Template address"><HashValue value={trustedDeploymentV2.template_address} /></Field>
                      <Field label="Artifact digest"><HashValue value={trustedDeploymentV2.template_artifact_digest_hex} /></Field>
                    </div>
                    {/* Anchor deployment replacement is destructive and
                        rarely needed. It stays under Advanced so a normal
                        operator does not encounter a prominent red button
                        beside a completed anchor. The destructive styling and
                        explicit confirmation dialog are preserved. */}
                    <DetailsSection summary="Advanced: replace anchor deployment">
                      {anchorReceiptVerifiedTerminal && (
                        <p className="form-hint">
                          This deployment produced the verified anchor for this archive.
                          Replacing it does not alter the historical transaction, receipt,
                          or evidence — those remain intact.
                        </p>
                      )}
                      <div className="btn-row">
                        <button type="button" className="btn btn-danger" disabled={!canAct || deploymentBusy || anchorV2Busy} onClick={() => setConfirmUnlockDeploymentV2(true)}>
                          Unlock / replace anchor deployment
                        </button>
                      </div>
                    </DetailsSection>
                  </>
                ) : trustedDeploymentV2StatusError ? (
                  <div className="anchor-config-grid">
                    <Notice tone="error">
                      The saved anchor deployment record could not be loaded
                      ({trustedDeploymentV2StatusError.code}). Reset clears only the anchor
                      deployment lock record; election, archive, tally, and voter data are not
                      touched.
                    </Notice>
                    <div className="btn-row">
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={!canAct || deploymentBusy}
                        onClick={() => void refreshTrustedDeployment()}
                      >
                        Reload deployment
                      </button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={!canAct || deploymentBusy || anchorV2Busy}
                        onClick={() => setConfirmUnlockDeploymentV2(true)}
                      >
                        Reset anchor deployment state
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="anchor-config-grid">
                    <div className="form-row anchor-form-row">
                      <label htmlFor="anchor-v2-template-address">Anchor template address</label>
                      <input id="anchor-v2-template-address" type="text" value={anchorV2TemplateAddress} placeholder="template_..." onChange={(e) => setAnchorV2TemplateAddress(e.target.value)} />
                    </div>
                    {/* The BLAKE3 artifact digest is pinned in the backend
                        (Rust constant `TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX`)
                        and only the reviewed WASM matches it, so the normal
                        organizer never has to compute or paste it. The lock
                        RPC still checks the submitted value equals the pinned
                        constant — pre-fill does not weaken binding. */}
                    <div className="field-list anchor-deployment-fields">
                      <Field label="Reviewed anchor artifact">
                        {trustedDeploymentV2Fixed?.expected_artifact_display_name ?? "—"}
                      </Field>
                      <Field label="Expected BLAKE3 (auto)">
                        <HashValue value={trustedDeploymentV2Fixed?.expected_artifact_digest_hex} />
                      </Field>
                    </div>
                    <details className="anchor-v2-summary-details">
                      <summary>Advanced: override artifact BLAKE3</summary>
                      <div className="form-row anchor-form-row">
                        <label htmlFor="anchor-v2-artifact-digest">BLAKE3 artifact digest</label>
                        <input id="anchor-v2-artifact-digest" type="text" value={anchorV2ArtifactDigest} placeholder="Leave blank to use the reviewed value" onChange={(e) => setAnchorV2ArtifactDigest(e.target.value)} />
                        <p className="form-hint">
                          Only for reviewers who want to submit a different digest for testing;
                          the backend will still reject anything that does not match the pinned
                          reviewed value above.
                        </p>
                      </div>
                    </details>
                    <div className="btn-row">
                      <button type="button" className="btn btn-primary" disabled={!canAct || deploymentBusy || trustedDeploymentV2StatusError !== null || anchorV2TemplateAddress.trim().length === 0 || !trustedDeploymentV2Fixed} onClick={() => void onLockTrustedDeploymentV2()}>
                        {deploymentBusy ? "Locking..." : "Lock anchor deployment"}
                      </button>
                    </div>
                  </div>
                )}
                {anchorV2Hydrated && (anchorV2Hydrated.blocks_fresh_publish || anchorV2Hydrated.transaction_id !== null) && (
                  <div
                    className="anchor-v2-recovery"
                    data-testid="anchor-v2-existing-recovery-panel"
                  >
                    <Notice tone={anchorV2Hydrated.receipt_verified ? "ok" : "warn"}>
                      <strong>
                        {anchorV2Hydrated.receipt_verified
                          ? "Anchored · Verified"
                          : "Existing anchor found for this archive"}
                      </strong>
                    </Notice>
                    {/* Normal summary: the human-useful fields (transaction,
                        network, receipt verification, evidence path). Wallet
                        request id and internal lifecycle phase are moved under
                        Advanced below. */}
                    <div className="field-list">
                      <Field label="Transaction">
                        {anchorV2Hydrated.transaction_id ? (
                          <>
                            <HashValue value={anchorV2Hydrated.transaction_id} />
                            <CopyButton value={anchorV2Hydrated.transaction_id} />
                          </>
                        ) : (
                          "—"
                        )}
                      </Field>
                      <Field label="Blockchain transaction">
                        {anchorV2Hydrated.transaction_id ? "Already submitted" : "Not yet submitted"}
                      </Field>
                      <Field label="Receipt verification">
                        {anchorV2Hydrated.receipt_verified
                          ? "Verified"
                          : anchorV2Hydrated.recoverable
                          ? "Needs recovery"
                          : anchorV2Hydrated.phase ?? "Unknown"}
                      </Field>
                      {anchorV2Hydrated.failure_reason && !anchorV2Hydrated.receipt_verified && (
                        <Field label="Failure">
                          {anchorV2Hydrated.failure_reason.includes("ANCHOR_RECEIPT_WRONG_EVENT_TOPIC")
                            ? "Previous receipt topic mismatch"
                            : anchorV2Hydrated.failure_reason}
                        </Field>
                      )}
                    </div>
                    {anchorV2Hydrated.receipt_verified ? (
                      <>
                        <Notice tone="ok">
                          Anchor published. Transaction accepted. Receipt verified. Canonical
                          public summary verified. Anchor digest verified. Evidence written.
                        </Notice>
                        <div className="field-list">
                          <Field label="Canonical public summary">Verified</Field>
                          <Field label="Anchor digest">Verified</Field>
                          {trustedDeploymentV2 && (
                            <Field label="Network">{trustedDeploymentV2.network}</Field>
                          )}
                          <Field label="Evidence file">
                            <span className="hash">{anchorV2Hydrated.evidence_path}</span>
                            <CopyButton value={anchorV2Hydrated.evidence_path} />
                          </Field>
                        </div>
                        <DetailsSection summary="Advanced: technical anchor fields">
                          <div className="field-list">
                            {anchorV2Hydrated.walletd_request_id !== null && (
                              <Field label="Wallet request ID">
                                {anchorV2Hydrated.walletd_request_id}
                              </Field>
                            )}
                            {anchorV2Hydrated.phase && (
                              <Field label="Lifecycle phase">{anchorV2Hydrated.phase}</Field>
                            )}
                            {trustedDeploymentV2Fixed?.template_module && (
                              <Field label="Template module">
                                <HashValue value={trustedDeploymentV2Fixed.template_module} />
                              </Field>
                            )}
                            {trustedDeploymentV2Fixed?.template_function && (
                              <Field label="Template function">
                                <HashValue value={trustedDeploymentV2Fixed.template_function} />
                              </Field>
                            )}
                            {trustedDeploymentV2Fixed?.template_event_topic && (
                              <Field label="Template event topic">
                                <HashValue value={trustedDeploymentV2Fixed.template_event_topic} />
                              </Field>
                            )}
                            {trustedDeploymentV2?.template_address && (
                              <Field label="Template address">
                                <HashValue value={trustedDeploymentV2.template_address} />
                              </Field>
                            )}
                            {trustedDeploymentV2?.template_artifact_digest_hex && (
                              <Field label="Artifact digest">
                                <HashValue value={trustedDeploymentV2.template_artifact_digest_hex} />
                              </Field>
                            )}
                          </div>
                        </DetailsSection>
                      </>
                    ) : (
                      <div className="field-list">
                        {anchorV2Hydrated.walletd_request_id !== null && (
                          <Field label="Wallet request ID">
                            {anchorV2Hydrated.walletd_request_id}
                          </Field>
                        )}
                        {anchorV2Hydrated.phase && (
                          <Field label="Lifecycle phase">{anchorV2Hydrated.phase}</Field>
                        )}
                      </div>
                    )}
                    {anchorV2Hydrated.receipt_verified ? null : anchorV2Hydrated.recoverable ? (
                      <>
                        <p className="form-hint">
                          An accepted transaction already exists. Recovery re-fetches the
                          on-chain receipt and re-verifies it against the locked anchor deployment
                          using the preserved public summary. It never creates a new wallet
                          request and never submits another transaction.
                        </p>
                        <div className="btn-row">
                          <button
                            type="button"
                            className="btn btn-primary"
                            disabled={
                              !canAct ||
                              !trustedDeploymentV2 ||
                              anchorV2RecoveryBusy ||
                              anchorIndexerEndpoint.trim().length === 0
                            }
                            onClick={() => void onRecoverExistingV2Anchor()}
                          >
                            {anchorV2RecoveryBusy
                              ? "Recovering…"
                              : anchorV2Hydrated.phase === "POLLING_RECEIPT"
                              ? "Recheck existing receipt"
                              : "Recover existing anchor"}
                          </button>
                        </div>
                        {anchorV2StepResult?.failure_reason && !anchorV2StepResult.rejection_reason && (
                          <Notice tone="error">{anchorV2StepResult.failure_reason}</Notice>
                        )}
                      </>
                    ) : (
                      <Notice tone="warn">
                        This existing anchor must be resolved before a replacement transaction
                        can be considered. Continue the walletd lifecycle from its current phase.
                      </Notice>
                    )}
                  </div>
                )}
                {!(anchorV2Hydrated?.blocks_fresh_publish) && (
                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={!canAct || !archiveReadyForAnchor || !trustedDeploymentV2 || anchorV2Busy}
                      onClick={() => void onBuildV2Payload()}
                    >
                      {anchorV2Busy ? "Building…" : "Build public summary"}
                    </button>
                  </div>
                )}
                {anchorV2HydratedBusy && !anchorV2Hydrated && (
                  <p className="form-hint">Loading existing anchor state…</p>
                )}
                {!(anchorV2Hydrated?.blocks_fresh_publish) && anchorV2Result && (
                  <div className="anchor-v2-result">
                    <div className="field-list">
                      <Field label="Public question">
                        {anchorV2Result.ballot_question || "(none)"}
                      </Field>
                      <Field label="Eligible voter count">
                        {anchorV2Result.eligible_voter_count}
                      </Field>
                      <Field label="Accepted ballots">
                        {anchorV2Result.accepted_ballot_count}
                      </Field>
                      <Field label="Rejected ballots">
                        {anchorV2Result.rejected_ballot_count}
                      </Field>
                      <Field label="Manifest hash">
                        <HashValue value={anchorV2Result.manifest_hash_hex} />
                      </Field>
                      <Field label="Archive hash">
                        <HashValue value={anchorV2Result.archive_hash_hex} />
                      </Field>
                      <Field label="Voter-registry commitment">
                        <HashValue value={anchorV2Result.registry_commitment_hex} />
                      </Field>
                      <Field label="Ballot-option commitment">
                        <HashValue value={anchorV2Result.option_set_commitment_hex} />
                      </Field>
                      <Field label="Anchor digest">
                        <HashValue value={anchorV2Result.v2_anchor_digest_hex} />
                        <CopyButton value={anchorV2Result.v2_anchor_digest_hex} />
                      </Field>
                      <Field label="Network">{anchorV2Result.network}</Field>
                    </div>
                    <div className="anchor-v2-tally">
                      <strong>Final tally</strong>
                      <ul>
                        {anchorV2Result.tally.map((row) => (
                          <li key={row.machine_id_hex}>
                            {row.display_label}: {row.count}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <Notice tone="warn">
                      This anchor publishes the readable public aggregate election summary.
                      Individual votes are NEVER published. Detached evidence is written beside
                      the archive for independent re-verification.
                    </Notice>
                    <div className="btn-row">
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={!canAct || anchorV2Busy || !trustedDeploymentV2}
                        onClick={() => void onPrepareV2AnchorPublish()}
                      >
                        {anchorV2Busy ? "Preparing..." : "Prepare anchor template call"}
                      </button>
                    </div>
                    {anchorV2Preparation && (
                      <>
                        <div className="field-list anchor-deployment-fields">
                          <Field label="Prepared function">{anchorV2Preparation.template_function}</Field>
                          <Field label="Prepared arguments">{anchorV2Preparation.arguments.length}</Field>
                          <Field label="Prepared digest"><HashValue value={anchorV2Preparation.anchor_digest_hex} /></Field>
                          <Field label="Public summary included">yes ({anchorV2Preparation.public_summary_json.length} bytes)</Field>
                          <Field label="Public question">{anchorV2Result.ballot_question || "(none)"}</Field>
                          <Field label="Ballot options">{anchorV2Result.tally.length}</Field>
                          <Field label="Final tally">
                            {anchorV2Result.tally
                              .map((row) => `${row.display_label}: ${row.count}`)
                              .join(" · ")}
                          </Field>
                          <Field label="Wallet approval">
                            {anchorV2StepResult?.waiting_for_wallet_approval ? "Waiting for explicit approval" : anchorV2StepResult?.phase ?? "Not requested"}
                          </Field>
                          <Field label="Wallet request ID">
                            {anchorV2StepResult?.walletd_request_id ?? "Not created"}
                          </Field>
                          <Field label="Request status">
                            {anchorV2StepResult?.wallet_request_status ?? "Not requested"}
                          </Field>
                          <Field label="Estimated fee">
                            {anchorV2StepResult?.estimated_required_fee ?? "Not estimated"}
                          </Field>
                          <Field label="Selected max fee">
                            {anchorV2StepResult?.selected_max_fee ?? "Not selected"}
                          </Field>
                          <Field label="Retry required">
                            {anchorV2StepResult?.retry_required ? "Yes" : "No"}
                          </Field>
                          <Field label="Receipt verification">
                            {anchorV2StepResult?.receipt_verified ? "Verified" : anchorV2StepResult?.phase === "POLLING_RECEIPT" ? "Polling" : "Not verified"}
                          </Field>
                        </div>
                        <details className="anchor-v2-summary-details">
                          <summary>Public summary — readable preview</summary>
                          {(() => {
                            let pretty: string;
                            try {
                              pretty = JSON.stringify(
                                JSON.parse(anchorV2Preparation.public_summary_json),
                                null,
                                2,
                              );
                            } catch {
                              // The canonical payload should always be valid JSON,
                              // but fall back to the raw string so the operator
                              // can still inspect what will publish.
                              pretty = anchorV2Preparation.public_summary_json;
                            }
                            return (
                              <>
                                <p className="form-hint">
                                  Formatted for reading only. The exact on-chain payload
                                  is the canonical one-line JSON below.
                                </p>
                                <pre className="anchor-v2-summary-pre anchor-v2-summary-pre--pretty">
                                  {pretty}
                                </pre>
                              </>
                            );
                          })()}
                          <div className="anchor-v2-summary-canonical">
                            <div className="anchor-v2-summary-canonical__header">
                              <strong>Exact canonical on-chain payload</strong>
                              <CopyButton value={anchorV2Preparation.public_summary_json} />
                            </div>
                            <pre className="anchor-v2-summary-pre anchor-v2-summary-pre--canonical">
                              {anchorV2Preparation.public_summary_json}
                            </pre>
                          </div>
                        </details>
                        <div className="btn-row">
                          {!anchorV2StepResult && (
                            <label className="anchor-v2-confirm-row">
                              <input type="checkbox" checked={anchorV2PublishConfirmed} onChange={(event) => setAnchorV2PublishConfirmed(event.target.checked)} />
                              <span>I confirm preparation of the anchor wallet request.</span>
                            </label>
                          )}
                          {anchorV2StepResult?.phase === "WAITING_FOR_WALLET_APPROVAL" ? (
                            <button type="button" className="btn btn-primary" disabled={anchorV2Busy} onClick={() => void onRunV2AnchorLifecycle("approve")}>
                              {anchorV2Busy ? "Approving…" : "Approve wallet request"}
                            </button>
                          ) : (
                            <button type="button" className="btn btn-primary" disabled={anchorV2Busy || walletdReadiness?.kind !== "ready" || anchorV2StepResult?.receipt_verified === true || (!anchorV2StepResult && !anchorV2PublishConfirmed)} onClick={() => void onRunV2AnchorLifecycle("none")}>
                              {anchorV2Busy ? "Working…" : anchorV2StepResult?.phase === "APPROVED" ? "Submit anchor request" : anchorV2StepResult?.phase === "POLLING_RECEIPT" ? "Check receipt" : anchorV2StepResult?.retry_required ? "Prepare new wallet request" : "Prepare wallet request"}
                            </button>
                          )}
                        </div>
                        {anchorV2StepResult?.rejection_reason && (
                          <Notice tone="error">{anchorV2StepResult.rejection_reason}</Notice>
                        )}
                        {anchorV2StepResult?.failure_reason && !anchorV2StepResult.rejection_reason && (
                          <Notice tone="error">{anchorV2StepResult.failure_reason}</Notice>
                        )}
                        {anchorV2StepResult?.receipt_verified && (
                          <Notice tone="ok">
                            <strong>Anchor published.</strong> Transaction accepted. Receipt
                            verified. Canonical public summary verified. Anchor digest
                            verified. Detached evidence written beside the archive.
                          </Notice>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
          </div>

          <DetailsSection summary="Advanced: technical release verification">
          <div className="production-authority-panel">
            <h4 className="screen-section">Production transport authority</h4>
            <p className="form-hint">
              This stores only the <strong>public</strong> verification root a release
              ceremony publishes. The private signing authority is never entered or
              stored in the app. Fake/test roots are rejected in release builds.
            </p>
            {prodAuthority === null ? (
              <p className="form-hint" data-testid="production-authority-loading">
                Checking production authority…
              </p>
            ) : prodAuthority.kind === "ready" ? (
              <div className="field-list" data-testid="production-authority-configured">
                <Field label="Status">
                  <Pill tone="ok">CONFIGURED</Pill>
                </Field>
                <Field label="Root key id">
                  <HashValue value={prodAuthority.root_key_id ?? undefined} />
                </Field>
                <Field label="Public key fingerprint">
                  <HashValue value={prodAuthority.public_key_fingerprint_hex ?? undefined} />
                </Field>
                <Field label="Network">{prodAuthority.network ?? "—"}</Field>
                {prodAuthority.label && <Field label="Label">{prodAuthority.label}</Field>}
                <Notice tone="info">
                  The private signing authority is NOT stored in this app; it stays with
                  the release custody process.
                </Notice>
                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-tertiary"
                    disabled={prodAuthorityBusy}
                    onClick={() => void forgetProductionAuthority()}
                  >
                    Forget production root
                  </button>
                </div>
              </div>
            ) : (
              <div data-testid="production-authority-unprovisioned">
                <Notice tone="warn">
                  {prodAuthority.kind === "malformed"
                    ? `Configured production authority root is invalid (${prodAuthority.code}). Fix or forget it.`
                    : "Production authority not provisioned. Production transport verification fails closed until an operator public root is loaded."}
                </Notice>
                {!prodAuthorityFormOpen ? (
                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={prodAuthorityBusy}
                      onClick={() => {
                        setProdAuthorityError(null);
                        // Default to the locked deployment network when known.
                        setProdAuthorityNetwork(anchorNetwork ?? "");
                        setProdAuthorityFormOpen(true);
                      }}
                    >
                      Load production public root
                    </button>
                  </div>
                ) : (
                  <div className="production-authority-form">
                    <div className="form-row anchor-form-row">
                      <label htmlFor="prod-authority-network">Network</label>
                      <input
                        id="prod-authority-network"
                        type="text"
                        value={prodAuthorityNetwork}
                        onChange={(e) => setProdAuthorityNetwork(e.target.value)}
                      />
                    </div>
                    <div className="form-row anchor-form-row">
                      <label htmlFor="prod-authority-key-id">Root key id</label>
                      <input
                        id="prod-authority-key-id"
                        type="text"
                        value={prodAuthorityKeyId}
                        onChange={(e) => setProdAuthorityKeyId(e.target.value)}
                      />
                    </div>
                    <div className="form-row anchor-form-row anchor-form-row--full">
                      <label htmlFor="prod-authority-public-key">
                        Root public key (64 hex chars — PUBLIC key only)
                      </label>
                      <input
                        id="prod-authority-public-key"
                        type="text"
                        value={prodAuthorityPublicKeyHex}
                        placeholder="ed25519 public key hex"
                        onChange={(e) => setProdAuthorityPublicKeyHex(e.target.value)}
                      />
                    </div>
                    <div className="form-row anchor-form-row">
                      <label htmlFor="prod-authority-label">Label (optional)</label>
                      <input
                        id="prod-authority-label"
                        type="text"
                        value={prodAuthorityLabel}
                        onChange={(e) => setProdAuthorityLabel(e.target.value)}
                      />
                    </div>
                    {prodAuthorityError && (
                      <Notice tone="error">
                        Could not configure production root: {prodAuthorityError}
                      </Notice>
                    )}
                    <div className="btn-row">
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={prodAuthorityBusy}
                        onClick={() => void submitProductionAuthority()}
                      >
                        Save production public root
                      </button>
                      <button
                        type="button"
                        className="btn btn-tertiary"
                        disabled={prodAuthorityBusy}
                        onClick={() => setProdAuthorityFormOpen(false)}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
          </DetailsSection>
        </Card>
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

      {confirmUnlockDeploymentV2 && (
        <ConfirmDialog
          title="Unlock Ootle anchor deployment?"
          body={<p>Future public-summary preparations will require a newly locked anchor template address and artifact digest.</p>}
          confirmLabel="Unlock anchor deployment"
          confirmTone="danger"
          busy={deploymentBusy}
          onConfirm={() => void onUnlockTrustedDeploymentV2()}
          onCancel={() => setConfirmUnlockDeploymentV2(false)}
        />
      )}
    </>
  );
}
