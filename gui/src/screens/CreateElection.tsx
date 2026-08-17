import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickDirectory, pickGovernanceDocument, pickRegistryCborFile } from "../api/dialog";
import type {
  GuiBallotPresentationType,
  GuiCommandError,
  GuiElectionCreationResultV1,
  GuiElectionDraftPreviewV1,
  GuiElectionExportResultV1,
  GuiElectionSummaryV1,
  GuiGovernanceDocumentDigestV1,
  GuiSavedVoterCredentialsV1,
  GuiVoterCredentialStatusV1,
} from "../api/types";
import { presentationIdentifier } from "../api/client";
import { NavSection } from "../components/AppFrame";
import {
  approvalRulePreview,
  acquireElectionDraft,
  type CreateDraftOption,
  type CreateElectionStep,
  draftIsReady,
  freezeAvailable,
  isUncastableApprovalConfig,
  hydrateCreateElectionSession,
  newCreateElectionSession,
  NO_QUORUM_STATEMENT,
  optionNoun,
  optionSetNoun,
  optionValidationErrors,
  parseVoterHexList,
  presentationLabel,
  runAction as executeAction,
} from "../creation";
import type { DraftInitializationState } from "../creation";
import {
  ADVANCED_PIN_LABEL,
  RECOMMENDED_PIN_LABEL,
  documentMatchShortLabel,
  documentMatchTone,
  formatByteSize,
  isGitCommitPin,
  pinFormatTone,
  pinKindLabel,
} from "../governance";
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
import { VoterCredentialCard } from "../components/VoterCredentialCard";

type Step = CreateElectionStep;

const STEPS: { id: Step; label: string }[] = [
  { id: "basics", label: "Basics" },
  { id: "governance", label: "Governance source" },
  { id: "voters", label: "Eligible voters" },
  { id: "options", label: "Ballot options" },
  { id: "rules", label: "Voting rules" },
  { id: "review", label: "Review" },
  { id: "frozen", label: "Freeze & Export" },
];

/**
 * Create Election (organizer): a real wizard for constructing a new election
 * package from non-secret public inputs. The frontend collects ordinary
 * strings and public keys; Rust validates every field, builds the canonical
 * registry, candidate set, and manifest, derives all commitments, and freezes
 * the election through the existing lifecycle. After freeze, the draft is
 * immutable (enforced by the backend) and a frozen session is loaded.
 */
export function CreateElection({ onNavigate }: { onNavigate: (s: NavSection) => void }) {
  const {
    refreshElection,
    refreshParticipation,
    refreshWorkspaces,
    recordAction,
    shellAvailable,
    createElectionSession,
    updateCreateElectionSession,
    replaceCreateElectionSession,
  } = useAppState();
  const session = createElectionSession ?? newCreateElectionSession();
  const {
    step,
    ballotType,
    electionIdText,
    proposalQuestion,
    governanceRevision,
    voterText,
    options,
    approvalMin,
    approvalMax,
    allowAbstention,
    frozen,
    exportResult,
    governanceDocPath,
    governanceDocDigest,
  } = session;

  const [preview, setPreview] = useState<GuiElectionDraftPreviewV1 | null>(null);
  const [localError, setLocalError] = useState<GuiCommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const [draftInitialization, setDraftInitialization] =
    useState<DraftInitializationState>("initializing");
  const draftRequestRef = useRef<Promise<boolean> | null>(null);
  const errorNoticeRef = useRef<HTMLDivElement | null>(null);
  const [confirmFreeze, setConfirmFreeze] = useState(false);
  const [bootstrapCredential, setBootstrapCredential] =
    useState<GuiVoterCredentialStatusV1 | null>(null);
  const [savedCredentials, setSavedCredentials] =
    useState<GuiSavedVoterCredentialsV1 | null>(null);

  function captureError(error: unknown) {
    if (error instanceof BackendError) setLocalError(error.payload);
    else
      setLocalError({
        code: "GUI_UNEXPECTED_ERROR",
        category: "INVALID_INPUT",
        context: null,
        message: "an unexpected frontend/backend boundary error occurred",
      });
  }

  useEffect(() => {
    if (localError) {
      errorNoticeRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      errorNoticeRef.current?.focus();
    }
  }, [localError]);

  function updateSession(update: (current: typeof session) => typeof session) {
    updateCreateElectionSession(update);
  }

  function setDraftNotReadyError() {
    setLocalError({
      code: "GUI_DRAFT_NOT_READY",
      category: "INVALID_LIFECYCLE_TRANSITION",
      context: "draft",
      message: "the election draft is still being prepared; wait for it to finish or retry",
    });
  }

  async function acquireDraft(): Promise<boolean> {
    if (draftRequestRef.current) return draftRequestRef.current;

    setBusy(true);
    setLocalError(null);
    const request = (async () => {
      try {
        await acquireElectionDraft(
          api.getOrCreateElectionDraft,
          setDraftInitialization,
          (authoritativePreview) => {
            setPreview(authoritativePreview);
            if (!createElectionSession) {
              replaceCreateElectionSession(hydrateCreateElectionSession(authoritativePreview));
            }
          },
        );
        await refreshBootstrapCredential();
        return true;
      } catch (error) {
        captureError(error);
        return false;
      } finally {
        draftRequestRef.current = null;
        setBusy(false);
      }
    })();
    draftRequestRef.current = request;
    return request;
  }

  async function startFreshDraft(): Promise<boolean> {
    if (draftRequestRef.current) return draftRequestRef.current;

    setBusy(true);
    setLocalError(null);
    setDraftInitialization("initializing");
    const request = (async () => {
      try {
        await api.startElectionDraft();
        const authoritativePreview = await api.getOrCreateElectionDraft();
        setPreview(authoritativePreview);
        replaceCreateElectionSession(hydrateCreateElectionSession(authoritativePreview));
        setDraftInitialization("ready");
        return true;
      } catch (error) {
        setDraftInitialization("failed");
        captureError(error);
        return false;
      } finally {
        draftRequestRef.current = null;
        setBusy(false);
      }
    })();
    draftRequestRef.current = request;
    return request;
  }

  useEffect(() => {
    void acquireDraft();
  }, []);

  async function run<T>(fn: () => Promise<T>): Promise<T | null> {
    setBusy(true);
    setLocalError(null);
    try {
      const result = await fn();
      setBusy(false);
      return result;
    } catch (error) {
      captureError(error);
      setBusy(false);
      return null;
    }
  }

  async function runAction(fn: () => Promise<unknown>): Promise<boolean> {
    setBusy(true);
    setLocalError(null);
    try {
      return await executeAction(fn, captureError);
    } finally {
      setBusy(false);
    }
  }

  async function commitBasics(): Promise<boolean> {
    if (!draftIsReady(draftInitialization)) {
      setDraftNotReadyError();
      return false;
    }
    const ok = await runAction(() =>
      api.setDraftBasics(electionIdText, proposalQuestion, governanceRevision),
    );
    if (!ok) return false;
    const ok2 = await runAction(() =>
      api.setDraftPresentation(presentationIdentifier(ballotType)),
    );
    return ok2;
  }

  async function commitVoters(keys: string[]): Promise<boolean> {
    return runAction(() => api.setDraftVoters(keys));
  }

  async function commitOptions(): Promise<boolean> {
    const payload = options.map((o) => ({
      machine_id_text: o.id,
      display_name: o.label,
    }));
    return runAction(() => api.setDraftOptions(payload));
  }

  async function commitRules(): Promise<boolean> {
    return runAction(() =>
      api.setDraftRules(approvalMin, approvalMax, allowAbstention),
    );
  }

  async function refreshPreview() {
    const p = await run(() => api.previewDraft());
    if (p) setPreview(p);
    return p;
  }

  function stepIndex(): number {
    return STEPS.findIndex((s) => s.id === step);
  }

  function goNext(target: Step) {
    updateSession((current) => ({ ...current, step: target }));
  }

  // ---- Basics ------------------------------------------------------------
  async function onBasicsNext() {
    if (!draftIsReady(draftInitialization)) {
      setDraftNotReadyError();
      return;
    }
    if (
      electionIdText.trim().length === 0 ||
      proposalQuestion.trim().length === 0 ||
      governanceRevision.trim().length === 0
    ) {
      setLocalError({
        code: "GUI_DRAFT_INCOMPLETE",
        category: "INVALID_INPUT",
        context: "draft",
        message: "election identifier, ballot question, and governance source revision are required",
      });
      return;
    }
    if (await commitBasics()) goNext("governance");
  }

  // ---- Governance source / document -------------------------------------
  async function onSelectGovernanceDocument() {
    const path = await pickGovernanceDocument("Select governance document");
    if (!path) return;
    const digest = await run(() => api.setDraftGovernanceDocument(path));
    if (!digest) return;
    updateSession((current) => ({ ...current, governanceDocPath: path, governanceDocDigest: digest }));
    await refreshPreview();
  }

  async function onClearGovernanceDocument() {
    const ok = await runAction(() => api.clearDraftGovernanceDocument());
    if (!ok) return;
    updateSession((current) => ({ ...current, governanceDocPath: null, governanceDocDigest: null }));
    await refreshPreview();
  }

  async function onUseDocumentDigestAsRevision() {
    const ok = await runAction(() => api.useGovernanceDocumentDigestAsRevision());
    if (!ok) return;
    const p = await refreshPreview();
    if (p) {
      updateSession((current) => ({
        ...current,
        governanceRevision: p.governance_source_revision ?? "",
      }));
    }
  }

  async function onGovernanceNext() {
    const ok = await runAction(() => api.setDraftGovernanceSourceRevision(governanceRevision));
    if (!ok) return;
    await refreshPreview();
    goNext("voters");
  }

  async function refreshSavedCredentials() {
    const saved = await api.listSavedVoterCredentials();
    setSavedCredentials(saved);
    return saved;
  }

  async function refreshBootstrapCredential() {
    const [status, saved] = await Promise.all([
      api.voterGovernanceCredentialStatus(),
      api.listSavedVoterCredentials(),
    ]);
    setBootstrapCredential(status);
    setSavedCredentials(saved);
    return status;
  }

  async function applyBootstrapCredentialStatus(status: GuiVoterCredentialStatusV1) {
    setBootstrapCredential(status);
    await refreshSavedCredentials();
  }

  async function onCreateBootstrapCredential(passphrase: string) {
    const status = await api.createDurableVoterCredential(passphrase);
    await applyBootstrapCredentialStatus(status);
  }

  async function onUnlockBootstrapCredential(publicKeyHex: string, passphrase: string) {
    const status = await api.unlockSavedVoterCredential(publicKeyHex, passphrase);
    await applyBootstrapCredentialStatus(status);
  }

  async function onImportBootstrapCredential(
    path: string,
    passphrase: string,
    persistLocally: boolean,
  ) {
    const status = await api.importVoterCredential(path, passphrase, persistLocally);
    await applyBootstrapCredentialStatus(status);
  }

  async function onBackupBootstrapCredential(path: string, passphrase: string) {
    await api.backupVoterCredential(path, passphrase);
  }

  async function onClearBootstrapCredential() {
    const status = await api.clearVoterCredentialFromMemory();
    await applyBootstrapCredentialStatus(status);
  }

  async function onDeleteBootstrapSavedCredential(publicKeyHex: string) {
    await api.deleteSavedVoterCredential(publicKeyHex);
    await refreshBootstrapCredential();
  }

  // ---- Voters ------------------------------------------------------------
  const parsedVoters = parseVoterHexList(voterText);

  async function onVotersNext() {
    if (parsedVoters.errors.length > 0) {
      setLocalError({
        code: "GUI_MALFORMED_PUBLIC_KEY",
        category: "INVALID_INPUT",
        context: "voters",
        message: parsedVoters.errors[0] ?? "a governance public key is malformed",
      });
      return;
    }
    if (parsedVoters.keys.length === 0) {
      setLocalError({
        code: "GUI_DRAFT_INCOMPLETE",
        category: "INVALID_INPUT",
        context: "voters",
        message: "add at least one eligible voter governance public key",
      });
      return;
    }
    if (await commitVoters(parsedVoters.keys)) goNext("options");
  }

  async function onImportRegistryFile() {
    const path = await pickRegistryCborFile("Import canonical voter registry");
    if (!path) return;
    const ok = await runAction(() => api.importRegistryToDraft(path));
    if (!ok) return;
    // After import, refresh the preview to learn the imported key count and
    // surface them in the textarea (hex, one per line).
    const p = await run(() => api.previewDraft());
    if (p) {
      setPreview(p);
      updateSession((current) => ({
        ...current,
        voterText: p.voters.map((v) => v.public_key_hex).join("\n"),
      }));
    }
  }

  // ---- Options -----------------------------------------------------------
  const optionErrors = optionValidationErrors(
    options.map((o) => ({ machine_id_text: o.id, display_name: o.label })),
  );

  function addOption() {
    updateSession((current) => ({ ...current, options: [...current.options, { id: "", label: "" }] }));
  }
  function updateOption(index: number, patch: Partial<CreateDraftOption>) {
    updateSession((current) => ({
      ...current,
      options: current.options.map((option, itemIndex) =>
        itemIndex === index ? { ...option, ...patch } : option,
      ),
    }));
  }
  function removeOption(index: number) {
    updateSession((current) => ({
      ...current,
      options: current.options.filter((_, itemIndex) => itemIndex !== index),
    }));
  }

  async function onOptionsNext() {
    if (options.length === 0) {
      setLocalError({
        code: "GUI_DRAFT_INCOMPLETE",
        category: "INVALID_INPUT",
        context: "options",
        message: "add at least one ballot option",
      });
      return;
    }
    if (optionErrors.length > 0) {
      setLocalError({
        code: "GUI_DRAFT_INCOMPLETE",
        category: "INVALID_INPUT",
        context: "options",
        message: optionErrors[0],
      });
      return;
    }
    if (await commitOptions()) goNext("rules");
  }

  // ---- Rules -------------------------------------------------------------
  async function onRulesNext() {
    if (approvalMin > approvalMax) {
      setLocalError({
        code: "INVALID_SELECTION_LIMITS",
        category: "INVALID_INPUT",
        context: "rules",
        message: "minimum selections exceed maximum selections",
      });
      return;
    }
    if (isUncastableApprovalConfig(approvalMin, approvalMax, allowAbstention)) {
      setLocalError({
        code: "GUI_UNCASTABLE_APPROVAL_LIMITS",
        category: "INVALID_INPUT",
        context: "rules",
        message: "At least one selection must be allowed when abstaining is disabled.",
      });
      return;
    }
    if (await commitRules()) {
      const p = await refreshPreview();
      if (p) goNext("review");
    }
  }

  // ---- Review / Freeze ---------------------------------------------------
  useEffect(() => {
    if (step === "review") void refreshPreview();
  }, [step]);

  async function onFreeze() {
    setConfirmFreeze(false);
    const result = await run(() => api.freezeElection());
    if (!result) return;
    updateSession((current) => ({ ...current, frozen: result, step: "frozen" }));
    await refreshElection();
    void refreshParticipation();
    void refreshWorkspaces();
    recordAction(
      `Froze election ${result.summary.election_id_text ?? result.summary.election_id_hex}`,
    );
  }

  // ---- Export ------------------------------------------------------------
  async function onExport() {
    const dir = await pickDirectory("Choose export directory", "electionExport");
    if (!dir) return;
    const result = await run(() => api.exportElectionArtifacts(dir));
    if (result) {
      updateSession((current) => ({ ...current, exportResult: result }));
      recordAction("Exported election artifacts");
    }
  }

  async function onOpenVoting() {
    await runAction(async () => {
      await api.openVoting();
      await refreshElection();
      void refreshWorkspaces();
      recordAction("Opened voting");
    });
  }

  async function restart() {
    if (!(await startFreshDraft())) return;
  }

  const presentation = ballotType;
  const readOnly = frozen !== null;
  const ready = draftIsReady(draftInitialization);

  return (
    <>
      <h1 className="screen-header">Create Election</h1>
      <p className="screen-lede">
        Set up a new election step by step: name it, record what is being voted on, list the
        eligible voters and ballot options, set the voting rules, then review and freeze
        everything. Freezing locks the election and produces the files voters and verifiers use.
        You only ever handle voters&rsquo; public keys here — never their private credentials.
      </p>

      <div ref={errorNoticeRef} tabIndex={-1}>
        <BackendErrorNotice error={localError ?? null} onDismiss={() => setLocalError(null)} />
      </div>
      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: creating an election requires the desktop application.
        </Notice>
      )}

      {!ready && (
        <Card title="Create election">
          {draftInitialization === "initializing" ? (
            <p className="field-value">Preparing a new election...</p>
          ) : (
            <>
              <p className="field-value">
                A new election draft could not be prepared. Retry to continue.
              </p>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void acquireDraft()}
                disabled={busy}
              >
                Retry
              </button>
            </>
          )}
        </Card>
      )}

      {ready && (
        <>
          <VoterCredentialCard
            title="Voter credential bootstrap"
            status={bootstrapCredential}
            savedCredentials={savedCredentials}
            shellAvailable={shellAvailable}
            busy={busy}
            context="bootstrap"
            onCreate={onCreateBootstrapCredential}
            onUnlock={onUnlockBootstrapCredential}
            onImport={onImportBootstrapCredential}
            onBackup={onBackupBootstrapCredential}
            onClear={onClearBootstrapCredential}
            onDeleteSaved={onDeleteBootstrapSavedCredential}
            onError={captureError}
          />
          <ol className="stepper" aria-label="Creation steps">
        {STEPS.map((s, i) => {
          const state =
            s.id === step ? "current" : i < stepIndex() || readOnly ? "done" : "todo";
          return (
            <li key={s.id} className={`stepper-item stepper-${state}`}>
              <span className="stepper-index" aria-hidden="true">
                {i + 1}
              </span>
              <span className="stepper-label">{s.label}</span>
            </li>
          );
        })}
          </ol>

      {step === "basics" && (
        <BasicsStep
          ballotType={ballotType}
          setBallotType={(ballotType) => updateSession((current) => ({ ...current, ballotType }))}
          electionIdText={electionIdText}
          setElectionIdText={(electionIdText) =>
            updateSession((current) => ({ ...current, electionIdText }))
          }
          proposalQuestion={proposalQuestion}
          setProposalQuestion={(proposalQuestion) =>
            updateSession((current) => ({ ...current, proposalQuestion }))
          }
          governanceRevision={governanceRevision}
          setGovernanceRevision={(governanceRevision) =>
            updateSession((current) => ({ ...current, governanceRevision }))
          }
          busy={busy}
          onNext={onBasicsNext}
        />
      )}

      {step === "governance" && (
        <GovernanceStep
          preview={preview}
          governanceRevision={governanceRevision}
          setGovernanceRevision={(governanceRevision) =>
            updateSession((current) => ({ ...current, governanceRevision }))
          }
          governanceDocPath={governanceDocPath}
          governanceDocDigest={governanceDocDigest}
          busy={busy}
          onSelectDocument={onSelectGovernanceDocument}
          onClearDocument={onClearGovernanceDocument}
          onUseDigestAsRevision={onUseDocumentDigestAsRevision}
          onApplyRevision={async () => {
            const ok = await runAction(() =>
              api.setDraftGovernanceSourceRevision(governanceRevision),
            );
            if (!ok) return;
            await refreshPreview();
          }}
          onNext={onGovernanceNext}
          onBack={() => goNext("basics")}
        />
      )}

      {step === "voters" && (
        <VotersStep
          voterText={voterText}
          setVoterText={(voterText) => updateSession((current) => ({ ...current, voterText }))}
          parsed={parsedVoters}
          busy={busy}
          onImportRegistryFile={onImportRegistryFile}
          onNext={onVotersNext}
          onBack={() => goNext("basics")}
        />
      )}

      {step === "options" && (
        <OptionsStep
          presentation={presentation}
          options={options}
          addOption={addOption}
          updateOption={updateOption}
          removeOption={removeOption}
          optionErrors={optionErrors}
          busy={busy}
          onNext={onOptionsNext}
          onBack={() => goNext("voters")}
        />
      )}

      {step === "rules" && (
        <RulesStep
          approvalMin={approvalMin}
          setApprovalMin={(approvalMin) => updateSession((current) => ({ ...current, approvalMin }))}
          approvalMax={approvalMax}
          setApprovalMax={(approvalMax) => updateSession((current) => ({ ...current, approvalMax }))}
          allowAbstention={allowAbstention}
          setAllowAbstention={(allowAbstention) =>
            updateSession((current) => ({ ...current, allowAbstention }))
          }
          optionCount={options.length}
          busy={busy}
          onNext={onRulesNext}
          onBack={() => goNext("options")}
        />
      )}

      {(step === "review" || step === "frozen") && (
        <ReviewStep
          preview={preview}
          frozen={frozen}
          presentation={presentation}
          busy={busy}
          readOnly={readOnly}
          exportResult={exportResult}
          onFreeze={() => setConfirmFreeze(true)}
          onExport={onExport}
          onOpenVoting={onOpenVoting}
          onManage={() => onNavigate("manage")}
          onRestart={restart}
          onBack={() => goNext("rules")}
        />
      )}

      {confirmFreeze && (
        <FreezeConfirmation
          preview={preview}
          busy={busy}
          onConfirm={onFreeze}
          onCancel={() => setConfirmFreeze(false)}
        />
      )}
        </>
      )}
    </>
  );
}

// ----------------------------------------------------------------- Basics

function BasicsStep(props: {
  ballotType: GuiBallotPresentationType;
  setBallotType: (t: GuiBallotPresentationType) => void;
  electionIdText: string;
  setElectionIdText: (v: string) => void;
  proposalQuestion: string;
  setProposalQuestion: (v: string) => void;
  governanceRevision: string;
  setGovernanceRevision: (v: string) => void;
  busy: boolean;
  onNext: () => void;
}) {
  return (
    <>
      <Card title="Ballot type">
        <div className="radio-group" role="radiogroup" aria-label="Ballot type">
          {(["Candidate", "GovernanceProposal", "BallotMeasure"] as const).map((type) => (
            <label key={type} className="radio-option">
              <input
                type="radio"
                name="ballot-type"
                value={type}
                checked={props.ballotType === type}
                onChange={() => props.setBallotType(type)}
              />
              {presentationLabel(type)}
            </label>
          ))}
        </div>
        <p className="form-hint">
          Choose how this election should be presented. This changes the wording voters see;
          the voting and verification rules stay the same.
        </p>
        <DetailsSection summary="Technical details">
          <p className="form-hint">
            Current ballot types use the same underlying V1 voting protocol; the choice changes
            the presentation wording, not the cryptography.
          </p>
        </DetailsSection>
      </Card>

      <Card title="Election identifier">
        <label className="field-label" htmlFor="election-id">
          Election identifier (text)
        </label>
        <input
          id="election-id"
          className="text-input"
          value={props.electionIdText}
          onChange={(e) => props.setElectionIdText(e.target.value)}
          placeholder="e.g. pilot-election-001"
        />
        <p className="form-hint">
          A short, unique name for this election. It becomes part of the locked election
          definition, so voters can check they are voting in the right election.
        </p>
      </Card>

      <Card title="Ballot question">
        <label className="field-label" htmlFor="proposal-question">
          Ballot question
        </label>
        <input
          id="proposal-question"
          className="text-input"
          value={props.proposalQuestion}
          onChange={(e) => props.setProposalQuestion(e.target.value)}
          placeholder="e.g. Should the council adopt RFC-0185?"
        />
        <p className="form-hint">
          This exact question is written into the version-two election manifest and covered by
          the manifest hash shown to voters and verifiers.
        </p>
      </Card>

      <Card title="Governance source">
        <label className="field-label" htmlFor="governance-revision">
          Governance source revision
        </label>
        <input
          id="governance-revision"
          className="text-input"
          value={props.governanceRevision}
          onChange={(e) => props.setGovernanceRevision(e.target.value)}
          placeholder="e.g. rfc-pr-185:f9e86cca"
        />
        <p className="form-hint">
          Records the source material that defines what is being voted on (for example, a
          proposal document revision), so voters and verifiers can confirm they are using the
          same information. You can refine this on the next step.
        </p>
        <Notice tone="info">
          The election files are the source of truth. Review the governance source and ballot
          options carefully before freezing the election, because voters will use the frozen
          information.
        </Notice>
        <DetailsSection summary="Technical details">
          <p className="form-hint">
            New elections use a version-two manifest with the proposal question appended to the
            canonical manifest fields. The proof protocol version remains unchanged.
          </p>
        </DetailsSection>
      </Card>

      <StepNav busy={props.busy} onNext={props.onNext} nextLabel="Continue" />
    </>
  );
}

// ------------------------------------------------------------- Governance

function GovernanceStep(props: {
  preview: GuiElectionDraftPreviewV1 | null;
  governanceRevision: string;
  setGovernanceRevision: (v: string) => void;
  governanceDocPath: string | null;
  governanceDocDigest: GuiGovernanceDocumentDigestV1 | null;
  busy: boolean;
  onSelectDocument: () => void;
  onClearDocument: () => void;
  onUseDigestAsRevision: () => void;
  onApplyRevision: () => void;
  onNext: () => void;
  onBack: () => void;
}) {
  const pin = props.preview?.governance_source_pin ?? null;
  const docStatus = props.preview?.governance_document_status ?? null;
  const doc = props.governanceDocDigest;
  const formatTone = pinFormatTone(pin);
  const matchTone = documentMatchTone(docStatus?.status);

  return (
    <>
      <Card title="Governance source pin">
        <p className="form-hint">
          This records exactly which source material defines what is being voted on, so voters
          and verifiers can confirm they are using the same proposal or election information.
          The reference must be permanent: a moving target such as <em>latest</em> or
          <em> main</em> cannot be pinned.
        </p>
        <DetailsSection summary="Technical details">
          <p className="form-hint">
            {RECOMMENDED_PIN_LABEL}. {ADVANCED_PIN_LABEL}. The bound reference must be immutable;
            a mutable phrase such as <em>latest</em> or <em>main</em> is not accepted as a
            recognized immutable pin.
          </p>
        </DetailsSection>
        <label className="field-label" htmlFor="governance-source-revision">
          Governance source revision
        </label>
        <input
          id="governance-source-revision"
          className="text-input"
          value={props.governanceRevision}
          onChange={(e) => props.setGovernanceRevision(e.target.value)}
          placeholder="blake3:<64 hex> (recommended) or git:<40 hex>"
        />
        <div className="action-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={props.onApplyRevision}
            disabled={props.busy}
          >
            Apply revision
          </button>
        </div>
        {pin && (
          <div className="field-list">
            <Field label="Pin kind">
              <Pill tone={formatTone === "ok" ? "ok" : formatTone === "warn" ? "warn" : "neutral"}>
                {pinKindLabel(pin)}
              </Pill>
            </Field>
            <Field label="Format">
              <span className="field-value">
                {pin.format_valid
                  ? "Valid immutable reference format"
                  : pin.message}
              </span>
            </Field>
            {pin.digest_hex && (
              <Field label="Bound digest">
                <HashValue value={pin.digest_hex} />
                {pin.digest_hex && <CopyButton value={pin.digest_hex} />}
              </Field>
            )}
            {pin.git_sha_hex && (
              <Field label="Bound Git SHA">
                <HashValue value={pin.git_sha_hex} />
              </Field>
            )}
          </div>
        )}
        <Notice tone="info">
          Format validity is not cryptographic verification. A green &ldquo;Matched&rdquo; status
          appears below only when the selected document digest actually equals the bound reference.
        </Notice>
      </Card>

      <Card title="Governance document">
        <p className="form-hint">
          Select the local governance document associated with this election. The document is treated
          as immutable raw bytes for hashing and archival; its semantics are not parsed.
        </p>
        {doc ? (
          <div className="field-list">
            <Field label="Filename">
              <span className="field-value">{doc.display_filename}</span>
            </Field>
            <Field label="Byte size">
              <span className="field-value">{formatByteSize(doc.bytes)}</span>
            </Field>
            <Field label="Digest algorithm">
              <span className="field-value">{doc.digest_algorithm_id}</span>
            </Field>
            <Field label="Document digest">
              <HashValue value={doc.digest_hex} />
              <CopyButton value={doc.digest_hex} />
            </Field>
            <Field label="Selected path">
              <span className="field-value">{props.governanceDocPath}</span>
            </Field>
          </div>
        ) : (
          <p className="field-value">No governance document selected.</p>
        )}
        <div className="action-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={props.onSelectDocument}
            disabled={props.busy}
          >
            {doc ? "Replace document" : "Select document"}
          </button>
          {doc && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={props.onClearDocument}
              disabled={props.busy}
            >
              Clear
            </button>
          )}
          {doc && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={props.onUseDigestAsRevision}
              disabled={props.busy || isGitCommitPin(pin)}
            >
              Use this document digest as the pin
            </button>
          )}
        </div>
        {docStatus && (
          <div className="field-list">
            <Field label="Source ↔ document status">
              <Pill tone={matchTone === "ok" ? "ok" : matchTone === "error" ? "error" : matchTone === "warn" ? "warn" : "neutral"}>
                {documentMatchShortLabel(docStatus.status)}
              </Pill>
            </Field>
            <Field label="Detail">
              <span className="field-value">{docStatus.status_label}</span>
            </Field>
          </div>
        )}
      </Card>

      <StepNav busy={props.busy} onNext={props.onNext} onBack={props.onBack} nextLabel="Continue" />
    </>
  );
}

// ----------------------------------------------------------------- Voters

function VotersStep(props: {
  voterText: string;
  setVoterText: (v: string) => void;
  parsed: { keys: string[]; errors: string[] };
  busy: boolean;
  onImportRegistryFile: () => void;
  onNext: () => void;
  onBack: () => void;
}) {
  return (
    <>
      <Card title="Eligible voters">
        <p className="form-hint">
          The election defines who is eligible to vote. Add each eligible voter&rsquo;s public
          voting key, one per line. When voting, each voter&rsquo;s app creates an anonymous
          proof that they belong to this eligible set — the proof does not reveal which eligible
          member they are. You only ever handle public keys here, never private credentials.
        </p>
        <div className="voters-header">
          <span className="field-value">
            {props.parsed.keys.length} eligible voter{props.parsed.keys.length === 1 ? "" : "s"}
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={props.onImportRegistryFile}
          >
            Import canonical registry
          </button>
        </div>
        <label className="field-label" htmlFor="voter-text">
          Governance public keys (hex, one per line)
        </label>
        <textarea
          id="voter-text"
          className="text-input voter-textarea"
          value={props.voterText}
          onChange={(e) => props.setVoterText(e.target.value)}
          rows={8}
          spellCheck={false}
          placeholder={
            "6a493210f7499cd17fecb510ae0a23fda0d4b58a1b48d4ecc0f4cbc9423e86f2\n" +
            "7858e0c0c4ad4ad27a6f9e9d4b6a5b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a"
          }
        />
        <p className="form-hint">
          Add one public voting key per line (64 hexadecimal characters). This text box is a
          convenience input; the exported voter list is produced in the verified election file
          format. The organizer never handles voter credentials.
        </p>
        {props.parsed.errors.length > 0 && (
          <Notice tone="warn">{props.parsed.errors[0]}</Notice>
        )}
      </Card>

      <StepNav busy={props.busy} onNext={props.onNext} onBack={props.onBack} nextLabel="Continue" />
    </>
  );
}

// ----------------------------------------------------------------- Options

function OptionsStep(props: {
  presentation: GuiBallotPresentationType;
  options: CreateDraftOption[];
  addOption: () => void;
  updateOption: (index: number, patch: Partial<CreateDraftOption>) => void;
  removeOption: (index: number) => void;
  optionErrors: string[];
  busy: boolean;
  onNext: () => void;
  onBack: () => void;
}) {
  const noun = optionNoun(props.presentation);
  return (
    <>
      <Card title={optionSetNoun(props.presentation)}>
        <div className="options-header">
          <span className="field-value">
            {props.options.length} {noun}
            {props.options.length === 1 ? "" : "s"}
          </span>
          <button type="button" className="btn btn-secondary" onClick={props.addOption}>
            Add {noun}
          </button>
        </div>
        <p className="form-hint">
          Add everything voters can choose. Each entry needs two parts, and both are required.
          The <strong>stable ID</strong> is a short machine-readable identifier used to bind
          this response into the election, for example{" "}
          <span className="hash">actually-anonymous</span>. Voters normally do not see it. The{" "}
          <strong>response label</strong> is the text voters will see. Display order here is
          cosmetic; the saved option list is sorted by stable ID.
        </p>
        <div className="option-editor">
          {props.options.map((option, index) => (
            <div key={index} className="option-edit-row">
              <input
                className="text-input option-edit-id"
                value={option.id}
                onChange={(e) => props.updateOption(index, { id: e.target.value })}
                placeholder="stable ID, e.g. actually-anonymous"
                aria-label={`Stable ID for ${noun} ${index + 1}`}
              />
              <input
                className="text-input option-edit-label"
                value={option.label}
                onChange={(e) => props.updateOption(index, { label: e.target.value })}
                placeholder="label voters will see"
                aria-label={`Response label for ${noun} ${index + 1}`}
              />
              <button
                type="button"
                className="btn btn-secondary btn-remove"
                onClick={() => props.removeOption(index)}
                aria-label={`Remove ${noun} ${index + 1}`}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
        {props.optionErrors.length > 0 && (
          <Notice tone="warn">{props.optionErrors[0]}</Notice>
        )}
      </Card>

      <StepNav busy={props.busy} onNext={props.onNext} onBack={props.onBack} nextLabel="Continue" />
    </>
  );
}

// ----------------------------------------------------------------- Rules

function RulesStep(props: {
  approvalMin: number;
  setApprovalMin: (n: number) => void;
  approvalMax: number;
  setApprovalMax: (n: number) => void;
  allowAbstention: boolean;
  setAllowAbstention: (b: boolean) => void;
  optionCount: number;
  busy: boolean;
  onNext: () => void;
  onBack: () => void;
}) {
  return (
    <>
      <Card title="Voting rules">
        <p className="form-hint">
          Decide how many responses each voter may choose, and whether voters may abstain
          (submit an empty selection). These rules are locked in when the election is frozen.
        </p>
        <div className="field-list">
          <Field label="Minimum selections">
            <input
              type="number"
              className="text-input number-input"
              min={0}
              max={props.optionCount}
              value={props.approvalMin}
              onChange={(e) => props.setApprovalMin(Number(e.target.value))}
            />
          </Field>
          <Field label="Maximum selections">
            <input
              type="number"
              className="text-input number-input"
              min={0}
              max={props.optionCount}
              value={props.approvalMax}
              onChange={(e) => props.setApprovalMax(Number(e.target.value))}
            />
          </Field>
          <Field label="Abstaining">
            <label className="radio-option">
              <input
                type="checkbox"
                checked={props.allowAbstention}
                onChange={(e) => props.setAllowAbstention(e.target.checked)}
              />
              Allow voters to abstain (submit an empty selection)
            </label>
          </Field>
        </div>
        <p className="form-hint">
          {approvalRulePreview(props.approvalMin, props.approvalMax, props.allowAbstention)}
        </p>
        <Notice tone="info">{NO_QUORUM_STATEMENT}</Notice>
        <DetailsSection summary="Technical details">
          <p className="form-hint">
            These limits are recorded as approval rules (minimum/maximum approvals and the
            abstention flag) in the canonical election definition.
          </p>
          <p className="form-hint">
            Proof suite: the production Triptych prototype suite is used by default and is not
            selectable.
          </p>
        </DetailsSection>
      </Card>

      <StepNav busy={props.busy} onNext={props.onNext} onBack={props.onBack} nextLabel="Review" />
    </>
  );
}

// ----------------------------------------------------------------- Review

function ReviewStep(props: {
  preview: GuiElectionDraftPreviewV1 | null;
  frozen: GuiElectionCreationResultV1 | null;
  presentation: GuiBallotPresentationType;
  busy: boolean;
  readOnly: boolean;
  exportResult: GuiElectionExportResultV1 | null;
  onFreeze: () => void;
  onExport: () => void;
  onOpenVoting: () => void;
  onManage: () => void;
  onRestart: () => void;
  onBack: () => void;
}) {
  const p = props.preview;
  const summary: GuiElectionSummaryV1 | null = props.frozen?.summary ?? null;

  if (props.readOnly && summary) {
    return (
      <FrozenView
        summary={summary}
        presentation={props.presentation}
        exportResult={props.exportResult}
        busy={props.busy}
        onExport={props.onExport}
        onOpenVoting={props.onOpenVoting}
        onManage={props.onManage}
        onRestart={props.onRestart}
      />
    );
  }

  if (!p) {
    return (
      <Card title="Review">
        <p className="field-value">Loading review…</p>
      </Card>
    );
  }

  return (
    <>
      <Card title="Review election">
        <Notice tone="info">
          Freezing locks the election definition, eligible voter registry, and ballot options.
          Changes become impossible without creating a new election.
        </Notice>
        <div className="field-list">
          <Field label="Election ID">
            <span className="field-value">{p.election_id_text ?? p.election_id_hex ?? "\u2014"}</span>
          </Field>
          <Field label="Ballot question">
            <span className="field-value">{p.proposal_question ?? "\u2014"}</span>
          </Field>
          <Field label="Governance source">
            <span className="field-value">{p.governance_source_revision ?? "\u2014"}</span>
          </Field>
          {p.governance_source_pin && (
            <Field label="Source pin format">
              <span className="field-value">
                {p.governance_source_pin.format_valid
                  ? `${pinKindLabel(p.governance_source_pin)} — valid immutable reference format`
                  : p.governance_source_pin.message}
              </span>
            </Field>
          )}
          {p.governance_document && (
            <Field label="Governance document">
              <span className="field-value">
                {p.governance_document.display_filename} · {formatByteSize(p.governance_document.bytes)}
              </span>
            </Field>
          )}
          {p.governance_document_status && (
            <Field label="Source ↔ document">
              <span className="field-value">
                {documentMatchShortLabel(p.governance_document_status.status)} —{" "}
                {p.governance_document_status.status_label}
              </span>
            </Field>
          )}
          <Field label="Ballot type">
            <span className="field-value">{presentationLabel(props.presentation)}</span>
          </Field>
          <Field label="Proof suite">
            <span className="field-value">{p.proof_suite_id}</span>
          </Field>
          <Field label="Voting rules">
            <span className="field-value">
              {approvalRulePreview(p.approval_min, p.approval_max, p.allow_abstention)}
            </span>
          </Field>
          <Field label="Quorum">
            <span className="field-value">{NO_QUORUM_STATEMENT}</span>
          </Field>
        </div>
      </Card>

      <Card title="Eligibility">
        <div className="field-list">
          <Field label="Eligible voters">
            <span className="field-value">{p.voter_count}</span>
          </Field>
          <Field label="Registry commitment">
            <HashValue value={p.registry_commitment_hex} />
            {p.registry_commitment_hex && <CopyButton value={p.registry_commitment_hex} />}
          </Field>
        </div>
      </Card>

      <Card title={optionSetNoun(props.presentation)}>
        <div className="field-list">
          <Field label="Option count">
            <span className="field-value">{p.options.length}</span>
          </Field>
          <Field label="Option-set commitment">
            <HashValue value={p.candidate_set_commitment_hex} />
            {p.candidate_set_commitment_hex && (
              <CopyButton value={p.candidate_set_commitment_hex} />
            )}
          </Field>
        </div>
        <DetailsSection summary={`All ${optionNoun(props.presentation)}s`}>
          <ul className="option-list">
            {p.options.map((o) => (
              <li key={o.machine_id_hex} className="option-item">
                <span className="option-marker" aria-hidden="true" />
                <span>{o.display_name}</span>
                <span className="hash option-id">{o.machine_id_text ?? o.machine_id_hex}</span>
              </li>
            ))}
          </ul>
        </DetailsSection>
      </Card>

      <Card title="Final binding">
        <div className="field-list">
          <Field label="Manifest hash">
            <HashValue value={p.manifest_hash_hex} />
            {p.manifest_hash_hex && <CopyButton value={p.manifest_hash_hex} />}
          </Field>
          <Field label="Manifest schema">
            <span className="field-value">
              {p.manifest_hash_hex ? "ElectionManifestV2" : "\u2014"}
            </span>
          </Field>
        </div>
        <p className="form-hint">
          {p.complete
            ? "The draft is complete and ready to freeze."
            : `Missing: ${p.missing.join(", ")}.`}
        </p>
      </Card>

      <StepNav
        busy={props.busy}
        onNext={props.onFreeze}
        onBack={props.onBack}
        nextLabel="Freeze Election"
        nextDisabled={!freezeAvailable(p)}
      />
    </>
  );
}

function FrozenView(props: {
  summary: GuiElectionSummaryV1;
  presentation: GuiBallotPresentationType;
  exportResult: GuiElectionExportResultV1 | null;
  busy: boolean;
  onExport: () => void;
  onOpenVoting: () => void;
  onManage: () => void;
  onRestart: () => void;
}) {
  const s = props.summary;
  return (
    <>
      <Card title="Election frozen">
        <Notice tone="ok">
          Election frozen. The manifest, registry, and option set are now immutable.
        </Notice>
        <div className="field-list">
          <Field label="Lifecycle">
            <LifecyclePill state={s.lifecycle_state} />
          </Field>
          <Field label="Election ID">
            <span className="field-value">{s.election_id_text ?? s.election_id_hex}</span>
          </Field>
          <Field label="Ballot question">
            <span className="field-value">{s.proposal_question ?? "\u2014"}</span>
          </Field>
          <Field label="Manifest schema">
            <span className="field-value">ElectionManifestV{s.manifest_schema_version}</span>
          </Field>
          <Field label="Manifest hash">
            <HashValue value={s.manifest_hash_hex} />
            <CopyButton value={s.manifest_hash_hex} />
          </Field>
          <Field label="Registry commitment">
            <HashValue value={s.registry_commitment_hex} />
            <CopyButton value={s.registry_commitment_hex} />
          </Field>
          <Field label="Option-set commitment">
            <HashValue value={s.candidate_set_commitment_hex} />
            <CopyButton value={s.candidate_set_commitment_hex} />
          </Field>
        </div>
        <p className="form-hint">
          Presentation type ({presentationLabel(props.presentation)}) is application-local and is
          not part of the canonical manifest; it will not appear when the exported files are
          reloaded through Manage Election.
        </p>
      </Card>

      <Card title="Export">
        <p className="field-value">
          Save the election files before opening voting. Voters load these files to vote, and
          verifiers use them to check the election record.
        </p>
        <button
          type="button"
          className="btn btn-primary"
          onClick={props.onExport}
          disabled={props.busy}
        >
          Export Election Package
        </button>
        {props.exportResult && (
          <div className="field-list export-result">
            <Field label="Directory">
              <span className="field-value">{props.exportResult.directory}</span>
            </Field>
            {props.exportResult.files.map((f) => (
              <Field key={f.path} label={f.path}>
                <span className="field-value">
                  {f.bytes} bytes · <span className="hash">{f.digest_hex}</span>
                </span>
              </Field>
            ))}
          </div>
        )}
      </Card>

      <Card title="Next: manage this election">
        <p className="field-value">
          Your election is created and frozen. Continue to Manage Election — the single place
          that controls this election&rsquo;s lifecycle: open voting, then close, tally, verify,
          and finalize. Opening voting is a separate deliberate action that means the election
          starts accepting ballots from eligible voters.
        </p>
        <div className="action-row">
          <button
            type="button"
            className="btn btn-primary"
            onClick={props.onManage}
          >
            Continue to Manage Election
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={props.onOpenVoting}
            disabled={props.busy}
          >
            Open Voting now
          </button>
          <button type="button" className="btn btn-secondary" onClick={props.onRestart}>
            Start another
          </button>
        </div>
      </Card>
    </>
  );
}

// --------------------------------------------------------------- Modal

function FreezeConfirmation(props: {
  preview: GuiElectionDraftPreviewV1 | null;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <ConfirmDialog
      title="Freeze election?"
      body={
        <>
          <p>
            Freezing locks the election definition, eligible voter registry, and ballot options.
            Changes become impossible without creating a new election.
          </p>
          {props.preview?.manifest_hash_hex && (
            <p>
              Manifest hash: <span className="hash">{props.preview.manifest_hash_hex}</span>
            </p>
          )}
        </>
      }
      confirmLabel="Freeze Election"
      busy={props.busy}
      onConfirm={props.onConfirm}
      onCancel={props.onCancel}
    />
  );
}

// --------------------------------------------------------------- Nav

function StepNav(props: {
  busy: boolean;
  onNext: () => void;
  onBack?: () => void;
  nextLabel: string;
  nextDisabled?: boolean;
}) {
  return (
    <div className="action-row step-nav">
      {props.onBack && (
        <button
          type="button"
          className="btn btn-secondary"
          onClick={props.onBack}
          disabled={props.busy}
        >
          Back
        </button>
      )}
      <button
        type="button"
        className="btn btn-primary"
        onClick={props.onNext}
        disabled={props.busy || props.nextDisabled === true}
      >
        {props.nextLabel}
      </button>
    </div>
  );
}
