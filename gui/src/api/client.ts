/**
 * Typed client over the Tauri command boundary.
 *
 * gui-core is the ONLY backend interface (ADR-0007): every call goes through
 * a typed Tauri command implemented by the Rust shell; there is no local
 * HTTP server, no CLI invocation, and no stdout parsing. When the frontend
 * runs outside the desktop shell (plain browser dev), calls reject with a
 * `GUI_SHELL_UNAVAILABLE` error and screens render their neutral states —
 * never mock data.
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  ActiveElectionAuthorityV1,
  ActiveWorkspaceIdsV1,
  GuiAnchorConfigInspectionV1,
  GuiAnchorEvidenceInspectionV1,
  GuiV2AnchorEvidenceFileV1,
  GuiAnchorSnapshotInspectionV1,
  GuiAnchorDeploymentCapabilitiesV1,
  GuiArchiveVerificationV1,
  GuiArchiveWriteResultV1,
  GuiBallotPresentationType,
  GuiBallotIntakeResultV1,
  GuiLiveAnchorConfigRequestV1,
  GuiLiveAnchorConfigResultV1,
  GuiLiveAnchorPreflightResultV1,
  GuiLiveAnchorV2RequestV1,
  GuiLiveAnchorV2ResultV1,
  GuiV2AnchorPublishPreparationV1,
  GuiV2LiveAnchorStepRequestV1,
  GuiV2LiveAnchorStepResultV1,
  GuiLiveAnchorStepRequestV1,
  GuiLiveAnchorStepResultV1,
  ProductionTransportAuthorityConfigureRequestV1,
  ProductionTransportAuthorityReadinessV1,
  GuiPrivateIntakeSyncSummaryV1,
  GuiCommandError,
  GuiElectionCreationResultV1,
  GuiElectionDraftPreviewV1,
  GuiElectionExportResultV1,
  GuiElectionStatusExportResultV1,
  GuiElectionStatusImportResultV1,
  GuiElectionSummaryV1,
  GuiElectionWorkspaceResumeResultV1,
  GuiElectionWorkspaceSummaryV1,
  GuiGovernanceDocumentDigestV1,
  GuiGovernanceDocumentStatusV1,
  GuiParticipationSummaryV1,
  GuiPrivateReleaseResultV1,
  GuiPrivateRouteV1,
  GuiPrivateSubmissionResultV1,
  GuiPrivateTransportAvailabilityV1,
  GuiPreparedBallotExportV1,
  GuiPreparedBallotStatusV1,
  GuiSavedVoterCredentialDeleteResultV1,
  GuiSavedVoterCredentialsV1,
  GuiTallySummaryV1,
  GuiTransportAnchorVerificationV1,
  GuiTrustedOotleDeploymentLockRequestV1,
  GuiTrustedOotleDeploymentStatusV1,
  GuiTrustedOotleDeploymentLockRequestV2,
  GuiTrustedOotleDeploymentStatusV2,
  GuiTrustedOotleTemplateWasmInspectionV1,
  GuiVoterCredentialBackupResultV1,
  GuiVoterCredentialStatusV1,
  GuiVoterElectionConfirmationV1,
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStatusV1,
  ManagedTorStatusV1,
  OrganizerIntakeStatusV1,
  PresentationIdentifier,
  ShellInfoV1,
  VoterBundleExportResultV1,
  VoterTorStatusV1,
  WalletdCredentialStatusV1,
  WalletdReadinessV1,
  GuiWalletdAnchorAccountsV1,
  WalletdConnectionDiagnosticsV1,
} from "./types";

export class BackendError extends Error {
  readonly payload: GuiCommandError;

  constructor(payload: GuiCommandError) {
    super(payload.message);
    this.name = "BackendError";
    this.payload = payload;
  }
}

export function isDesktopShell(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const SHELL_UNAVAILABLE: GuiCommandError = {
  code: "GUI_SHELL_UNAVAILABLE",
  category: "FILE_IO",
  context: null,
  message: "the desktop shell backend is not running",
};

function asBackendError(error: unknown): BackendError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "category" in error &&
    "message" in error
  ) {
    return new BackendError(error as GuiCommandError);
  }
  return new BackendError({
    code: "GUI_UNEXPECTED_ERROR",
    category: "INVALID_INPUT",
    context: null,
    message: "an unexpected frontend/backend boundary error occurred",
  });
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isDesktopShell()) {
    throw new BackendError(SHELL_UNAVAILABLE);
  }
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw asBackendError(error);
  }
}

export const api = {
  shellInfo: () => call<ShellInfoV1>("shell_info"),

  loadElection: (manifestPath: string, registryPath: string, optionSetPath: string) =>
    call<GuiElectionSummaryV1>("load_election", {
      manifestPath,
      registryPath,
      optionSetPath,
    }),
  loadElectionFolder: (folderPath: string) =>
    call<GuiElectionSummaryV1>("load_election_folder", {
      folderPath,
    }),

  unloadElection: () => call<void>("unload_election"),

  electionSummary: () => call<GuiElectionSummaryV1 | null>("election_summary"),

  /** Backend-authoritative role of the active session (`null` when none). The
   *  UI uses this to hide organizer controls; the backend remains the
   *  enforcement point for every organizer command. */
  activeElectionAuthority: () =>
    call<ActiveElectionAuthorityV1 | null>("active_election_authority"),

  listElectionWorkspaces: () =>
    call<GuiElectionWorkspaceSummaryV1[]>("list_election_workspaces"),
  activeWorkspaceIds: () =>
    call<ActiveWorkspaceIdsV1>("active_workspace_ids"),
  resumeElectionWorkspace: (workspaceId: string) =>
    call<GuiElectionWorkspaceResumeResultV1>("resume_election_workspace", {
      workspaceId,
    }),
  deleteElectionWorkspace: (workspaceId: string) =>
    call<GuiElectionWorkspaceSummaryV1[]>("delete_election_workspace", {
      workspaceId,
    }),

  openVoting: () => call<GuiElectionSummaryV1>("open_voting"),
  closeVoting: () => call<GuiElectionSummaryV1>("close_voting"),
  markVerified: () => call<GuiElectionSummaryV1>("mark_verified"),
  finalizeElection: () => call<GuiElectionSummaryV1>("finalize_election"),

  intakeBallotPackage: (packagePath: string) =>
    call<GuiBallotIntakeResultV1>("intake_ballot_package", { packagePath }),

  privateIntakeInboxPath: () =>
    call<string>("private_intake_inbox_path"),

  syncPrivateIntake: () =>
    call<GuiPrivateIntakeSyncSummaryV1>("sync_private_intake"),

  currentTally: () => call<GuiTallySummaryV1>("current_tally"),

  participationSummary: () =>
    call<GuiParticipationSummaryV1>("participation_summary"),

  writeArchive: (targetDir: string) =>
    call<GuiArchiveWriteResultV1>("write_archive", { targetDir }),

  writeFinalizedArchive: (
    targetDir: string,
    governanceDocumentPath: string | null,
    requireTransportBinding: boolean,
  ) =>
    call<GuiArchiveWriteResultV1>("write_finalized_archive", {
      targetDir,
      governanceDocumentPath,
      requireTransportBinding,
    }),

  anchorDeploymentCapabilities: () =>
    call<GuiAnchorDeploymentCapabilitiesV1>("anchor_deployment_capabilities"),

  verifyArchive: (directory: string) =>
    call<GuiArchiveVerificationV1>("verify_archive", { directory }),
  verifyTransportArchiveAnchor: (archiveDirectory: string, anchorEvidencePath: string) =>
    call<GuiTransportAnchorVerificationV1>("verify_transport_archive_anchor", {
      archiveDirectory,
      anchorEvidencePath,
    }),

  inspectAnchorConfig: (path: string) =>
    call<GuiAnchorConfigInspectionV1>("inspect_anchor_config", { path }),

  inspectAnchorSnapshot: (path: string) =>
    call<GuiAnchorSnapshotInspectionV1>("inspect_anchor_snapshot", { path }),

  inspectAnchorEvidence: (path: string) =>
    call<GuiAnchorEvidenceInspectionV1>("inspect_anchor_evidence", { path }),

  /** Read + schema-validate a V2 public-anchor evidence JSON file. Read-only;
   *  no network. Returns the parsed public binding data verbatim; callers
   *  must still run `verifyV2PublicAnchorEvidence` before displaying any
   *  "verified" claim. */
  readV2PublicAnchorEvidenceFile: (path: string) =>
    call<GuiV2AnchorEvidenceFileV1>("read_v2_public_anchor_evidence_file", { path }),

  trustedOotleDeploymentStatus: () =>
    call<GuiTrustedOotleDeploymentStatusV1>("trusted_ootle_deployment_status"),

  inspectTemplateWasm: (path: string) =>
    call<GuiTrustedOotleTemplateWasmInspectionV1>("inspect_template_wasm", { path }),

  lockTrustedOotleDeployment: (request: GuiTrustedOotleDeploymentLockRequestV1) =>
    call<GuiTrustedOotleDeploymentStatusV1>("lock_trusted_ootle_deployment", {
      request,
    }),

  unlockTrustedOotleDeployment: () =>
    call<GuiTrustedOotleDeploymentStatusV1>("unlock_trusted_ootle_deployment", {
      confirm: true,
    }),

  trustedOotleDeploymentV2Status: () =>
    call<GuiTrustedOotleDeploymentStatusV2>("trusted_ootle_deployment_v2_status"),

  lockTrustedOotleDeploymentV2: (request: GuiTrustedOotleDeploymentLockRequestV2) =>
    call<GuiTrustedOotleDeploymentStatusV2>("lock_trusted_ootle_deployment_v2", { request }),

  unlockTrustedOotleDeploymentV2: () =>
    call<GuiTrustedOotleDeploymentStatusV2>("unlock_trusted_ootle_deployment_v2", {
      confirm: true,
    }),

  writeLiveAnchorConfig: (request: GuiLiveAnchorConfigRequestV1) =>
    call<GuiLiveAnchorConfigResultV1>("write_live_anchor_config_from_verified_archive", {
      request,
    }),

  validateLiveAnchorOperatorConfig: (request: GuiLiveAnchorConfigRequestV1) =>
    call<GuiLiveAnchorPreflightResultV1>("validate_live_anchor_operator_config", {
      request,
    }),

  buildV2PublicAnchorPayload: (request: GuiLiveAnchorV2RequestV1) =>
    call<GuiLiveAnchorV2ResultV1>("build_v2_public_anchor_payload", { request }),

  verifyV2PublicAnchorEvidence: (
    archiveDirectory: string,
    payloadHex: string,
    expectedDigestHex: string,
  ) =>
    call<GuiLiveAnchorV2ResultV1>("verify_v2_public_anchor_evidence", {
      archiveDirectory,
      payloadHex,
      expectedDigestHex,
    }),

  prepareV2AnchorPublish: (
    archiveDirectory: string,
    payloadHex: string,
    expectedDigestHex: string,
  ) =>
    call<GuiV2AnchorPublishPreparationV1>("prepare_v2_anchor_publish", {
      request: {
        archive_directory: archiveDirectory,
        payload_hex: payloadHex,
        expected_digest_hex: expectedDigestHex,
      },
    }),

  runV2LiveAnchorLifecycleStep: (request: GuiV2LiveAnchorStepRequestV1) =>
    call<GuiV2LiveAnchorStepResultV1>("run_v2_live_anchor_lifecycle_step", { request }),

  /** Read-only hydration of the persisted V2 anchor lifecycle for the given
   *  finalized archive directory. Never contacts walletd or the indexer. */
  inspectV2LiveAnchorState: (archiveDirectory: string) =>
    call<import("./types").GuiV2LiveAnchorHydratedStateV1>(
      "inspect_v2_live_anchor_state",
      { archiveDirectory },
    ),

  /** Advance a persisted V2 lifecycle that already carries a submitted
   *  transaction by re-polling the indexer only. NEVER contacts walletd, so no
   *  new wallet request can be created and no duplicate transaction can be
   *  produced. */
  recoverV2LiveAnchor: (archiveDirectory: string, indexerEndpoint: string) =>
    call<GuiV2LiveAnchorStepResultV1>("recover_v2_live_anchor", {
      archiveDirectory,
      indexerEndpoint,
    }),

  runLiveAnchorLifecycleStep: (request: GuiLiveAnchorStepRequestV1) =>
    call<GuiLiveAnchorStepResultV1>("run_live_anchor_lifecycle_step", { request }),

  // Production transport authority PUBLIC root (operator setup/review). Only
  // public material crosses this boundary: the request carries a public-key
  // hex, and the readiness result exposes only a key id, network, and a public
  // key fingerprint — never a private key.
  productionTransportAuthorityStatus: () =>
    call<ProductionTransportAuthorityReadinessV1>("production_transport_authority_status"),
  configureProductionTransportAuthorityRoot: (
    request: ProductionTransportAuthorityConfigureRequestV1,
  ) =>
    call<ProductionTransportAuthorityReadinessV1>(
      "configure_production_transport_authority_root",
      { request },
    ),
  forgetProductionTransportAuthorityRoot: (confirm: boolean) =>
    call<ProductionTransportAuthorityReadinessV1>(
      "forget_production_transport_authority_root",
      { confirm },
    ),

  // Walletd credential (Connect Tari Wallet / Reconnect / Forget). The raw
  // key is a write-only argument on connect/reconnect; it never comes back.
  walletdCredentialStatus: () =>
    call<WalletdCredentialStatusV1>("walletd_credential_status"),
  connectWalletd: (key: string) =>
    call<WalletdCredentialStatusV1>("connect_walletd", { key }),
  reconnectWalletd: (key: string) =>
    call<WalletdCredentialStatusV1>("reconnect_walletd", { key }),
  forgetWalletd: () => call<WalletdCredentialStatusV1>("forget_walletd"),
  walletdReadiness: () => call<WalletdReadinessV1>("walletd_readiness"),

  listWalletdAnchorAccounts: () =>
    call<GuiWalletdAnchorAccountsV1>("list_walletd_anchor_accounts"),

  // Read-only, secret-free connection diagnostic mirroring the auto-fill probe.
  walletdConnectionDiagnostics: () =>
    call<WalletdConnectionDiagnosticsV1>("walletd_connection_diagnostics"),

  // Organizer election creation (Slice 5A6).
  getOrCreateElectionDraft: () =>
    call<GuiElectionDraftPreviewV1>("get_or_create_election_draft"),
  startElectionDraft: () => call<void>("start_election_draft"),
  discardElectionDraft: () => call<void>("discard_election_draft"),
  setDraftBasics: (
    electionIdText: string,
    proposalQuestion: string,
    governanceSourceRevision: string,
  ) =>
    call<void>("set_draft_basics", {
      electionIdText,
      proposalQuestion,
      governanceSourceRevision,
    }),
  setDraftRules: (approvalMin: number, approvalMax: number, allowAbstention: boolean) =>
    call<void>("set_draft_rules", { approvalMin, approvalMax, allowAbstention }),
  setDraftVoters: (publicKeyHexs: string[]) =>
    call<void>("set_draft_voters", { publicKeyHexs }),
  setDraftOptions: (
    options: { machine_id_text: string; display_name: string }[],
  ) => call<void>("set_draft_options", { options }),
  setDraftPresentation: (presentation: PresentationIdentifier) =>
    call<void>("set_draft_presentation", { presentation }),
  importRegistryToDraft: (registryPath: string) =>
    call<void>("import_registry_to_draft", { registryPath }),
  previewDraft: () => call<GuiElectionDraftPreviewV1>("preview_draft"),
  freezeElection: () => call<GuiElectionCreationResultV1>("freeze_election"),
  exportElectionArtifacts: (targetDir: string) =>
    call<GuiElectionExportResultV1>("export_election_artifacts", { targetDir }),

  // Slice 5A8: governance source pinning, document archival, voter confirmation.
  setDraftGovernanceSourceRevision: (governanceSourceRevision: string) =>
    call<void>("set_draft_governance_source_revision", { governanceSourceRevision }),
  setDraftGovernanceDocument: (path: string) =>
    call<GuiGovernanceDocumentDigestV1>("set_draft_governance_document", { path }),
  clearDraftGovernanceDocument: () => call<void>("clear_draft_governance_document"),
  useGovernanceDocumentDigestAsRevision: () =>
    call<void>("use_governance_document_digest_as_revision"),
  computeGovernanceDocumentDigest: (path: string) =>
    call<GuiGovernanceDocumentDigestV1>("compute_governance_document_digest", { path }),
  matchGovernanceDocument: (
    governanceSourceRevision: string,
    governanceDocumentPath: string | null,
  ) =>
    call<GuiGovernanceDocumentStatusV1>("match_governance_document", {
      governanceSourceRevision,
      governanceDocumentPath,
    }),
  voterConfirmation: (governanceDocumentPath: string | null) =>
    call<GuiVoterElectionConfirmationV1>("voter_confirmation", { governanceDocumentPath }),
  voterGovernanceCredentialStatus: () =>
    call<GuiVoterCredentialStatusV1>("voter_governance_credential_status"),
  listSavedVoterCredentials: () =>
    call<GuiSavedVoterCredentialsV1>("list_saved_voter_credentials"),
  createDurableVoterCredential: (passphrase: string) =>
    call<GuiVoterCredentialStatusV1>("create_durable_voter_credential", { passphrase }),
  unlockSavedVoterCredential: (publicKeyHex: string, passphrase: string) =>
    call<GuiVoterCredentialStatusV1>("unlock_saved_voter_credential", {
      publicKeyHex,
      passphrase,
    }),
  importVoterCredential: (
    path: string,
    passphrase: string,
    persistLocally: boolean,
  ) =>
    call<GuiVoterCredentialStatusV1>("import_voter_credential", {
      path,
      passphrase,
      persistLocally,
    }),
  backupVoterCredential: (path: string, passphrase: string) =>
    call<GuiVoterCredentialBackupResultV1>("backup_voter_credential", {
      path,
      passphrase,
    }),
  clearVoterCredentialFromMemory: () =>
    call<GuiVoterCredentialStatusV1>("clear_voter_credential_from_memory"),
  deleteSavedVoterCredential: (publicKeyHex: string) =>
    call<GuiSavedVoterCredentialDeleteResultV1>("delete_saved_voter_credential", {
      publicKeyHex,
    }),
  generateVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("generate_voter_governance_credential"),
  generatePendingVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("generate_pending_voter_governance_credential"),
  resetVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("reset_voter_governance_credential"),
  resetPendingVoterGovernanceCredential: () =>
    call<GuiVoterCredentialStatusV1>("reset_pending_voter_governance_credential"),
  voterWorkflowStatus: (reviewConfirmed: boolean) =>
    call<GuiVoterWorkflowStatusV1>("voter_workflow_status", { reviewConfirmed }),
  voterBallotSelectionStatus: () =>
    call<GuiVoterSelectionStatusV1>("voter_ballot_selection_status"),
  setVoterBallotSelection: (selectedOptionIdsHex: string[], abstain: boolean) =>
    call<GuiVoterSelectionStatusV1>("set_voter_ballot_selection", {
      selectedOptionIdsHex,
      abstain,
    }),
  clearVoterBallotSelection: () =>
    call<GuiVoterSelectionStatusV1>("clear_voter_ballot_selection"),
  changeMyBallotChoice: () =>
    call<GuiPreparedBallotStatusV1>("change_my_ballot_choice"),
  prepareVoterBallot: () => call<GuiPreparedBallotStatusV1>("prepare_voter_ballot"),
  exportPreparedVoterBallot: (packagePath: string) =>
    call<GuiPreparedBallotExportV1>("export_prepared_voter_ballot", { packagePath }),
  privateTransportAvailability: () =>
    call<GuiPrivateTransportAvailabilityV1>("private_transport_availability"),
  submitPreparedVoterBallotPrivately: (route: GuiPrivateRouteV1) =>
    call<GuiPrivateReleaseResultV1 | GuiPrivateSubmissionResultV1>(
      "submit_prepared_voter_ballot_privately",
      { route },
    ),
  resetVoterWorkflow: () => call<GuiVoterWorkflowStatusV1>("reset_voter_workflow"),
  // managed-tor commands (no-ops/fail-closed when the feature is absent).
  configureManagedTor: (
    torExePath: string,
    voterTorDataDir: string,
    voterPublicBundlePath: string,
    // Advanced remote-SOCKS options. Omitted/undefined ⇒ default managed-local.
    remote?: { host: string; port: number },
  ) =>
    call<ManagedTorStatusV1>("configure_managed_tor", {
      input: {
        tor_exe_path: torExePath,
        voter_tor_data_dir: voterTorDataDir,
        voter_public_bundle_path: voterPublicBundlePath,
        tor_mode: remote ? "remote-socks" : "managed-local",
        remote_socks_host: remote ? remote.host : null,
        remote_socks_port: remote ? remote.port : null,
      },
    }),
  startManagedTor: () => call<ManagedTorStatusV1>("start_managed_tor"),
  stopManagedTor: () => call<ManagedTorStatusV1>("stop_managed_tor"),
  managedTorStatus: () => call<ManagedTorStatusV1>("managed_tor_status"),
  // Advanced remote-SOCKS explicit connectivity/readiness test (no ballot bytes).
  testRemoteTorConnection: () =>
    call<ManagedTorStatusV1>("test_remote_tor_connection"),
  // Read-only voter Tor availability (allowlist or remembered/selected path).
  voterTorStatus: (torExePath?: string) =>
    call<VoterTorStatusV1>("voter_tor_status", {
      torExePath: torExePath && torExePath.length > 0 ? torExePath : null,
    }),
  retryPrivateSubmission: () =>
    call<GuiPrivateReleaseResultV1>("retry_private_submission"),
  // Organizer near-one-click private intake (managed-tor). torExePath is an
  // optional remembered/selected convenience path; the backend re-validates it
  // and falls back to the reviewed allowlist. All of the crowded operator
  // details (torrc, ports, onion, fingerprint, inbox path) stay backend-owned.
  organizerTorStatus: (torExePath?: string) =>
    call<OrganizerIntakeStatusV1>("organizer_tor_status", {
      torExePath: torExePath && torExePath.length > 0 ? torExePath : null,
    }),
  startPrivateIntake: (torExePath?: string) =>
    call<OrganizerIntakeStatusV1>("start_private_intake", {
      torExePath: torExePath && torExePath.length > 0 ? torExePath : null,
    }),
  stopPrivateIntake: () =>
    call<OrganizerIntakeStatusV1>("stop_private_intake"),
  exportVoterTransportBundle: (destinationDir: string) =>
    call<VoterBundleExportResultV1>("export_voter_transport_bundle", {
      destinationDir,
    }),
  exportElectionStatusArtifact: (destinationPath: string) =>
    call<GuiElectionStatusExportResultV1>("export_election_status_artifact", {
      destinationPath,
    }),
  importElectionStatusArtifact: (statusPath: string) =>
    call<GuiElectionStatusImportResultV1>("import_election_status_artifact", {
      statusPath,
    }),
  fetchElectionStatusPrivate: () =>
    call<GuiElectionStatusImportResultV1>("fetch_election_status_private"),
  writeArchiveWithGovernanceDocument: (
    targetDir: string,
    governanceDocumentPath: string | null,
  ) =>
    call<GuiArchiveWriteResultV1>("write_archive_with_governance_document", {
      targetDir,
      governanceDocumentPath,
    }),
};

/** The presentation type the frontend should send to the backend for a given
 *  UI ballot-type choice. */
export function presentationIdentifier(
  type: GuiBallotPresentationType,
): PresentationIdentifier {
  switch (type) {
    case "Candidate":
      return "candidate";
    case "GovernanceProposal":
      return "governance-proposal";
    case "BallotMeasure":
      return "ballot-measure";
  }
}
