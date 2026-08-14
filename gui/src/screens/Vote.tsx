import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import {
  pickBallotPackagePath,
  pickElectionArtifact,
  pickGovernanceDocument,
} from "../api/dialog";
import type {
  GuiCommandError,
  GuiGovernanceDocumentDigestV1,
  GuiPrivateRouteV1,
  GuiPrivateSubmissionResultV1,
  GuiPrivateTransportAvailabilityV1,
  GuiSavedVoterCredentialsV1,
  GuiVoterCredentialStatusV1,
  GuiVoterElectionConfirmationV1,
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStatusV1,
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
import {
  BackendErrorNotice,
  Card,
  CopyButton,
  DetailsSection,
  Field,
  HashValue,
  LifecyclePill,
  Notice,
  Pill,
} from "../components/ui";
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
  const [exported, setExported] = useState(false);
  const [transport, setTransport] = useState<GuiPrivateTransportAvailabilityV1 | null>(null);
  const [privateRoute, setPrivateRoute] = useState<GuiPrivateRouteV1>("ManagedTor");
  const [privateResult, setPrivateResult] = useState<GuiPrivateSubmissionResultV1 | null>(null);
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
    setExported(false);
    setTransport(null);
    setPrivateRoute("ManagedTor");
    setPrivateResult(null);
  }, [election]);

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
    setExported(false);
    try {
      const prepared = await api.prepareVoterBallot();
      await refreshWorkflow(true);
      setTransport(await api.privateTransportAvailability());
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
      setExported(true);
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

  async function onSubmitPrivately() {
    if (privateRoute === "OfflineExport") {
      await onExportBallot();
      return;
    }
    setBusy(true);
    setError(null);
    setPrivateResult(null);
    try {
      setPrivateResult(await api.submitPreparedVoterBallotPrivately(privateRoute));
      setTransport(await api.privateTransportAvailability());
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  const docStatus = confirmation?.governance_document_status ?? null;
  const matchTone = documentMatchTone(docStatus?.status);
  const eligibilityTone = credentialEligibilityTone(credential?.eligibility ?? "NotChecked");
  const selectionLiveText = selectionSummaryText(selection);
  const selectionAtMax = selectionAtApprovalMax(selection);

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
              <Field label="How many to choose">
                <span className="field-value">
                  {selectionInstructionText(confirmation.bound)}
                </span>
              </Field>
            </div>
            <p className="form-hint">
              This list is read-only. You choose your response after confirming the election.
            </p>
            {confirmation.no_proposal_question_notice && (
              <p className="form-hint">{confirmation.no_proposal_question_notice}</p>
            )}
            <DetailsSection summary="Technical details">
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

          {credentialStage && (
            <>
              <Card title="Eligibility">
                <p className="form-hint">
                  The election defines who is eligible to vote. The app checks your public voting
                  key against the election&rsquo;s eligible voter list.
                </p>
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
                  <Field label="Eligibility status">
                    <Pill tone={eligibilityTone}>
                      {credential?.eligibility_label ?? "No credential loaded"}
                    </Pill>
                  </Field>
                </div>
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
              </Card>

              {selectionStage && confirmation && (
                <>
                  <Card title="Choose your response">
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
                      Choosing a response does not submit a vote. You can change your response at
                      any time before creating the proof.
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

                  <Card title="Anonymous eligibility proof">
                    <Notice tone="info">
                      This proves that your credential belongs to the eligible voter set without
                      revealing which eligible voter you are. Your ballot choice is not
                      permanently sealed and may appear in the final verifiable election record.
                    </Notice>
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
                    {busy && (
                      <Notice tone="info">
                        Creating anonymous eligibility proof… This can take a moment.
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
                    <DetailsSection summary="Technical details">
                      <p className="card-body">
                        Eligibility is proven with the Tari Triptych implementation. The proof is
                        bound to this election and carries a unique election-scoped linking tag,
                        so a second ballot from the same voter is detected and rejected — without
                        revealing which eligible voter cast it. The proof is constructed and
                        verified in the Rust backend; this screen never sees secret material.
                      </p>
                    </DetailsSection>
                    {workflow?.prepared_ballot.summary && (
                      <Card title="Ballot prepared">
                        <div className="field-list">
                          <Field label="Status">
                            <Pill tone="ok">Ballot prepared</Pill>
                          </Field>
                          <Field label="Local verification">
                            <Pill tone="ok">Verified</Pill>
                          </Field>
                          <Field label="Your response">
                            <span className="field-value">
                              {workflow.prepared_ballot.summary.selected_display_labels.join(", ") || "Abstention"}
                            </span>
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
                            className="btn btn-primary"
                            disabled={busy || !workflow.prepared_ballot.ready_to_export}
                            onClick={() => void onExportBallot()}
                          >
                            Save ballot file
                          </button>
                        </div>
                        {exported && (
                          <Notice tone="ok">
                            Ballot file saved. Deliver this file through the election's approved
                            intake method.
                          </Notice>
                        )}
                        {transport &&
                          (transport.managed_tor_available ||
                          transport.split_trust_relay_available ? (
                            <>
                              <p className="form-hint">
                                Alternatively, submit the prepared ballot through a private online
                                route. The verified ballot package stays in the Rust backend; this
                                screen never sends ballot bytes itself.
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
                                  Submit privately
                                </button>
                              </div>
                            </>
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
                            {privateResult.reduced_anonymity && " Reduced anonymity / small population."}
                          </Notice>
                        )}
                      </Card>
                    )}
                  </Card>
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
    </>
  );
}
