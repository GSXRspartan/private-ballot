import { useEffect, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickGovernanceDocument } from "../api/dialog";
import type {
  GuiCommandError,
  GuiGovernanceDocumentDigestV1,
  GuiVoterElectionConfirmationV1,
} from "../api/types";
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
  Placeholder,
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
  const [confirmed, setConfirmed] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [error, setError] = useState<GuiCommandError | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setConfirmation(null);
    setGovDocDigest(null);
    setConfirmed(false);
    setAdvanced(false);
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

  const docStatus = confirmation?.governance_document_status ?? null;
  const matchTone = documentMatchTone(docStatus?.status);

  return (
    <>
      <h1 className="screen-header">Vote</h1>
      <p className="screen-lede">
        Review the cryptographically bound election details before voting. This is the confirmation
        boundary: credential import and proof construction are not yet enabled and are never
        simulated. Voter key generation is a separately reviewed change.
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
                onClick={() => setAdvanced(true)}
              >
                Continue
              </button>
            </div>
            {advanced && (
              <Placeholder>
                {confirmation.next_stage_placeholder}
              </Placeholder>
            )}
            <p className="form-hint">
              Continuing does not start credential handling or proof generation, and does not
              accept a ballot selection.
            </p>
          </Card>
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
