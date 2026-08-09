import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickBallotPackagePath, pickGovernanceDocument } from "../api/dialog";
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
  selectionAtApprovalMax,
  selectionSummaryText,
  workflowTone,
} from "../voterWorkflow";
import { useAppState } from "../state/AppState";
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
 * Vote (voter) — confirmation boundary (Slice 5A8).
 *
 * This is read-only confirmation only. When an election is loaded, the screen
 * shows exactly the values that are cryptographically bound by the election
 * manifest, clearly labels the application-local presentation type as
 * non-canonical, and reports governance document status honestly. The
 * "Continue" action advances only to a deferred placeholder — credential
 * handling and proof generation are NOT enabled in this slice and are never
 * simulated.
 */
export function Vote() {
  const { election, shellAvailable } = useAppState();
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

  async function loadConfirmation(path: string | null) {
    if (!election || !shellAvailable) return;
    setBusy(true);
    setError(null);
    try {
      const c = await api.voterConfirmation(path);
      setConfirmation(c);
    } catch (err) {
      captureError(err);
      setConfirmation(null);
    } finally {
      setBusy(false);
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
    try {
      const digest = await api.computeGovernanceDocumentDigest(path);
      setGovDocDigest(digest);
      const c = await api.voterConfirmation(path);
      setConfirmation(c);
    } catch (err) {
      captureError(err);
    } finally {
      setBusy(false);
    }
  }

  async function onClearGovernanceDocument() {
    setGovDocDigest(null);
    await loadConfirmation(null);
  }

  async function onGenerateCredential() {
    if (!election || !shellAvailable) return;
    setBusy(true);
    setError(null);
    try {
      const status = await api.generateVoterGovernanceCredential();
      setCredential(status);
      if (selectionStage) await refreshWorkflow(true);
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
    const path = await pickBallotPackagePath();
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      await api.exportPreparedVoterBallot(path);
      setExported(true);
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
        Review the cryptographically bound election details before voting. This is the confirmation
        boundary before the session-only governance credential and eligibility check. Proof
        construction and package export remain local; this screen never submits a vote.
      </p>

      {!election && (
        <Notice tone="info">
          No election is loaded. Load one from the Manage Election screen to review its ballot.
        </Notice>
      )}

      <BackendErrorNotice error={error} onDismiss={() => setError(null)} />

      {confirmation && (
        <>
          <Card title={BOUND_SECTION_LABEL}>
            <Notice tone="info">
              These values are cryptographically bound by the election manifest.
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
              Optionally select the local governance document to check whether its digest matches the
              bound governance source. This is read-only; no document content is parsed or
              transmitted.
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
              I reviewed the cryptographically bound election details.
            </label>
            <div className="action-row">
              <button
                type="button"
                className="btn btn-primary"
                disabled={!confirmed || !confirmationContinueAvailable(confirmation) || busy}
                onClick={() => setCredentialStage(true)}
              >
                Continue
              </button>
            </div>
            <p className="form-hint">
              Continuing does not generate a proof, create a nullifier, accept a ballot selection,
              or submit a vote.
            </p>
          </Card>

          {credentialStage && (
            <>
              <Card title="Governance credential">
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
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={onGenerateCredential}
                    disabled={busy}
                  >
                    Generate new credential
                  </button>
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
                  {credential?.enrollment_notice ??
                    "A generated public governance key must be enrolled before the election is frozen."}
                </p>
              </Card>

              <Card title="Eligibility">
                <div className="field-list">
                  <Field label="Public governance key">
                    {credential?.public_governance_key_hex ? (
                      <>
                        <span className="field-value">{publicKeyDisplay(credential)}</span>
                        <CopyButton value={credential.public_governance_key_hex} />
                      </>
                    ) : (
                      <span className="field-value">Not loaded</span>
                    )}
                  </Field>
                  <Field label="Registry status">
                    <Pill tone={eligibilityTone}>
                      {credential?.eligibility_label ?? "No credential loaded"}
                    </Pill>
                  </Field>
                </div>
                {credential?.eligibility === "NotEligible" && (
                  <Notice tone="warn">
                    This public governance key is not in the frozen voter registry.
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

                  <Card title="Privacy proof">
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
                    {busy && <Notice tone="info">Generating privacy proof…</Notice>}
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
                        Generate privacy proof
                      </button>
                    </div>
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
                              Export ballot package
                            </button>
                          </div>
                          <div className="field-list">
                            <Field label="Private submission">
                              <span className="field-value">
                                Choose an explicit route. Rust retains the canonical ballot package;
                                this screen never sends ballot bytes itself.
                              </span>
                            </Field>
                          </div>
                          {transport && (
                            <>
                              <Notice tone={transport.development_transport ? "warn" : "info"}>
                                {transport.message}
                              </Notice>
                              <div className="selection-options" role="radiogroup" aria-label="Private submission route">
                                <label className="selection-option">
                                  <input
                                    type="radio"
                                    name="private-route"
                                    checked={privateRoute === "ManagedTor"}
                                    disabled={busy || !transport.managed_tor_available}
                                    onChange={() => setPrivateRoute("ManagedTor")}
                                  />
                                  <span className="selection-option-label">Managed Tor</span>
                                  <span className="selection-option-id">Preferred private online route</span>
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
                                  <span className="selection-option-id">Optional alternative privacy route</span>
                                </label>
                                <label className="selection-option">
                                  <input
                                    type="radio"
                                    name="private-route"
                                    checked={privateRoute === "OfflineExport"}
                                    disabled={busy || !transport.offline_export_available}
                                    onChange={() => setPrivateRoute("OfflineExport")}
                                  />
                                  <span className="selection-option-label">Offline file</span>
                                  <span className="selection-option-id">No online transmission</span>
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
                                  {privateRoute === "OfflineExport" ? "Export offline ballot file" : "Submit privately"}
                                </button>
                              </div>
                            </>
                          )}
                          {privateResult && (
                            <Notice tone={privateResult.receipt_state === "ACCEPTED" ? "ok" : "info"}>
                              {privateResult.receipt_state === "ACCEPTED"
                                ? "ACCEPTED: the exact canonical ballot was accepted by the election intake."
                                : `Submission status: ${privateResult.receipt_state}.`}
                              {privateResult.reduced_anonymity && " Reduced anonymity / small population."}
                            </Notice>
                          )}
                        </Card>
                        {exported && (
                          <Notice tone="ok">
                            Ballot package exported. Deliver this canonical ballot package through the approved election intake process.
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
