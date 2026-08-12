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
  GuiVoterCredentialStatusV1,
  GuiVoterElectionConfirmationV1,
  GuiVoterSelectionStatusV1,
  GuiVoterWorkflowStatusV1,
} from "../api/types";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import {
  ADVANCED_DETAILS_LABEL,
  BOUND_SECTION_LABEL,
  INFORMATIONAL_LABEL,
  PRESENTATION_SECTION_LABEL,
  confirmationContinueAvailable,
  documentMatchShortLabel,
  documentMatchTone,
  formatByteSize,
  isCryptographicallyMatched,
} from "../governance";
import {
  canProceedAfterCredential,
  credentialEligibilityTone,
  credentialStatusText,
  publicKeyDisplay,
  WALLET_SEED_WARNING,
} from "../voterCredential";
import {
  receiptStateIsAccepted,
  receiptStateText,
  selectionAtApprovalMax,
  selectionSummaryText,
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
  const [selection, setSelection] = useState<GuiVoterSelectionStatusV1 | null>(null);
  const [workflow, setWorkflow] = useState<GuiVoterWorkflowStatusV1 | null>(null);
  const [selectedOptionIds, setSelectedOptionIds] = useState<string[]>([]);
  const [abstaining, setAbstaining] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [credentialStage, setCredentialStage] = useState(false);
  const [selectionStage, setSelectionStage] = useState(false);
  const [error, setError] = useState<GuiCommandError | null>(null);
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
    setCredential(null);
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

  function captureError(err: unknown) {
    if (err instanceof BackendError) setError(err.payload);
    else
      setError({
        code: "GUI_UNEXPECTED_ERROR",
        category: "INVALID_INPUT",
        context: null,
        message: "an unexpected frontend/backend boundary error occurred",
      });
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
      setCredential(await api.voterGovernanceCredentialStatus());
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function onResetCredential() {
    if (!shellAvailable) {
      setCredential(null);
      setWorkflow(null);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const status = await api.resetVoterGovernanceCredential();
      setCredential(status);
      if (selectionStage) await refreshWorkflow(true);
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
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
  const presentation = presentationFor(election);
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
            accepted, included in the final election record, and, where applicable, anchored.
          </li>
        </ol>
        <DetailsSection summary="Technical details">
          <p className="card-body">
            Eligibility is proven with the Tari Triptych implementation using an
            election-bound proof. After submission, receipt states (received, accepted,
            included, and, where applicable, anchored) describe how far your ballot has
            progressed.
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
              <Field label="Election ID">
                <span className="field-value">
                  {confirmation.bound.election_id_text ?? confirmation.bound.election_id_hex}
                </span>
              </Field>
              <Field label="Canonical ballot kind">
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
              <Field label="Option display labels">
                <ul className="option-list bound-labels" aria-label="Bound option labels">
                  {confirmation.bound.option_display_labels.map((label, i) => (
                    <li key={i} className="option-item">
                      <span className="option-marker" aria-hidden="true" />
                      <span>{label}</span>
                    </li>
                  ))}
                </ul>
              </Field>
              <Field label="Approval rules">
                <span className="field-value">
                  between {confirmation.bound.approval_min} and {confirmation.bound.approval_max}{" "}
                  options; abstention{" "}
                  {confirmation.bound.abstention_allowed ? "permitted" : "not permitted"}
                </span>
              </Field>
              <Field label="Proof-suite ID">
                <span className="field-value">{confirmation.bound.proof_suite_id}</span>
              </Field>
            </div>
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

          <Card title={PRESENTATION_SECTION_LABEL}>
            <div className="field-list">
              <Field label="Presentation">
                <span className="field-value">Ballot options (neutral)</span>
              </Field>
            </div>
            <Notice tone="info">
              <strong>{INFORMATIONAL_LABEL}.</strong> {confirmation.presentation_notice}
            </Notice>
            <p className="form-hint">{confirmation.no_proposal_question_notice}</p>
          </Card>

          <Card title={ADVANCED_DETAILS_LABEL}>
            <DetailsSection summary="Show advanced commitments">
              <div className="field-list">
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
                <Field label="Voter count / anonymity-set size">
                  <span className="field-value">{confirmation.advanced.voter_count}</span>
                </Field>
              </div>
            </DetailsSection>
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
              <Card title="Your voter credential">
                <p className="form-hint">
                  The local-pilot credential was generated before this election was frozen. It lets the
                  app prove you are on the eligible voter list — without revealing which eligible
                  voter you are. It exists only for this session and is never stored.
                </p>
                <Notice tone="warn">{WALLET_SEED_WARNING}</Notice>
                <div className="field-list">
                  <Field label="Credential">
                    <span className="field-value">{credentialStatusText(credential)}</span>
                  </Field>
                  <Field label="Storage">
                    <span className="field-value">
                      {credential?.session_notice ??
                        "Governance credentials are session-only in this build."}
                    </span>
                  </Field>
                  <Field label="Import / export">
                    <span className="field-value">
                      Deferred until a reviewed private credential format exists.
                    </span>
                  </Field>
                </div>
                <div className="action-row">
                  {credential?.credential_loaded && (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={onResetCredential}
                      disabled={busy}
                    >
                      Clear credential
                    </button>
                  )}
                </div>
                <p className="form-hint">
                  {credential
                    ? credential.enrollment_notice
                    : "Checking for the Rust-owned local pilot credential."}
                </p>
                {!credential?.credential_loaded && (
                  <Notice tone="warn">
                    This election is already frozen. Generating a new credential now cannot add
                    it to the immutable voter registry. The enrolled local credential is required;
                    credential import is deferred until a reviewed private format exists.
                  </Notice>
                )}
              </Card>

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
                    Generating a replacement cannot change this frozen registry. Credential import
                    is deferred until a reviewed private format exists.
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
                  <Card title="Ballot selection">
                    <p className="form-hint">{election ? approvalRuleText(election) : ""}</p>
                    <fieldset className="selection-fieldset" disabled={busy || abstaining}>
                      <legend>{presentation.selectionHeading}</legend>
                      <div className="selection-options">
                        {confirmation.candidates.map((option) => {
                          const checked = selectedOptionIds.includes(option.machine_id_hex);
                          const disabled = !checked && selectionAtMax;
                          return (
                            <label className="selection-option" key={option.machine_id_hex}>
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
                              <span className="selection-option-id">
                                {option.machine_id_text ?? option.machine_id_hex}
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
                        Abstain
                      </label>
                    )}
                    <div className="selection-status" aria-live="polite">
                      <Pill tone={selection?.valid ? "ok" : "neutral"}>{selectionLiveText}</Pill>
                      {selection && (
                        <span>
                          Required: {selection.approval_min}-{selection.approval_max}; lifecycle{" "}
                          {selection.lifecycle_state}
                        </span>
                      )}
                    </div>
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
                  </Card>

                  <Card title="Anonymous eligibility proof">
                    <Notice tone="info">
                      Your eligibility proof hides which eligible voter you are. Your ballot
                      choice is not permanently sealed and may become public as part of the
                      verifiable election record.
                    </Notice>
                    <div className="field-list">
                      <Field label="Workflow">
                        <Pill tone={workflowTone(workflow?.workflow_state)}>
                          {workflow?.workflow_state ?? "SelectionIncomplete"}
                        </Pill>
                      </Field>
                      <Field label="Preparation">
                        <span className="field-value">
                          {workflow?.prepared_ballot.message ?? "No ballot has been prepared."}
                        </span>
                      </Field>
                    </div>
                    {busy && <Notice tone="info">Creating anonymous eligibility proof…</Notice>}
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
                      <>
                        <Card title="Review prepared ballot">
                          <div className="field-list">
                            <Field label="Selected options">
                              <span className="field-value">
                                {workflow.prepared_ballot.summary.selected_display_labels.join(", ") || "Abstention"}
                              </span>
                            </Field>
                            <Field label="Package digest">
                              <HashValue value={workflow.prepared_ballot.summary.package_digest_hex} />
                            </Field>
                            <Field label="Local verification">
                              <Pill tone="ok">Verified</Pill>
                            </Field>
                          </div>
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
                          <div className="field-list">
                            <Field label="Submission">
                              <span className="field-value">
                                Choose how to submit. The verified ballot package stays in the
                                Rust backend; this screen never sends ballot bytes itself.
                              </span>
                            </Field>
                          </div>
                          {transport && (
                            <>
                              <Notice tone={transport.development_transport ? "warn" : "info"}>
                                {transport.message}
                              </Notice>
                              <div className="selection-options" role="radiogroup" aria-label="Submission options">
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
                                <label className="selection-option">
                                  <input
                                    type="radio"
                                    name="private-route"
                                    checked={privateRoute === "OfflineExport"}
                                    disabled={busy || !transport.offline_export_available}
                                    onChange={() => setPrivateRoute("OfflineExport")}
                                  />
                                  <span className="selection-option-label">Offline ballot file</span>
                                  <span className="selection-option-desc">Save the verified ballot package and transfer it separately to the election organizer.</span>
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
                                  {privateRoute === "OfflineExport" ? "Save ballot file" : "Submit privately"}
                                </button>
                              </div>
                            </>
                          )}
                          {privateResult && (
                            <Notice tone={receiptStateIsAccepted(privateResult.receipt_state) ? "ok" : "info"}>
                              {receiptStateText(privateResult.receipt_state)}
                              {privateResult.reduced_anonymity && " Reduced anonymity / small population."}
                            </Notice>
                          )}
                        </Card>
                        {exported && (
                          <Notice tone="ok">
                            Ballot file saved. Deliver this ballot file to the election organizer
                            through the approved intake process.
                          </Notice>
                        )}
                      </>
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
