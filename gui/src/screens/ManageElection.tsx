import { useState } from "react";

import { api, BackendError } from "../api/client";
import {
  pickBallotPackageFile,
  pickDirectory,
  pickElectionArtifact,
  pickGovernanceDocument,
} from "../api/dialog";
import type {
  GuiArchiveWriteResultV1,
  GuiCommandError,
  GuiTallySummaryV1,
} from "../api/types";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { intakeCanImport, intakeResultMessage, intakeResultTitle } from "../intake";
import {
  canShowTally,
  canWriteFinalArchive,
  coarseBucketLabel,
  describeLeadingOutcome,
  formatPercent,
  participationAccessibleText,
  participationIsDisclosed,
  participationVisibilityLabel,
} from "../lifecycle";
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
  Placeholder,
} from "../components/ui";
import { LockIcon } from "../components/icons";
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
  const [archiveResult, setArchiveResult] = useState<GuiArchiveWriteResultV1 | null>(null);
  const [localError, setLocalError] = useState<GuiCommandError | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);

  const presentation = presentationFor(election);
  const lifecycle = election?.lifecycle_state ?? null;
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

  return (
    <>
      <h1 className="screen-header">Manage Election</h1>
      <p className="screen-lede">
        Organizer tools for one election: load the election files, open and close voting,
        accept submitted ballots, compute the tally, and write the verifiable election record.
      </p>

      <BackendErrorNotice error={backendError} onDismiss={dismissError} />
      <BackendErrorNotice error={finalArchiveError ? null : localError} onDismiss={clearLocalError} />
      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: commands are disabled because the desktop shell is not running.
        </Notice>
      )}

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
        {shellAvailable && election && !selectedArtifactPaths && (
          <Notice tone="info">
            An election is already loaded from durable recovery state
            {election.election_id_text ? ` (${election.election_id_text})` : ""}. Its lifecycle,
            ballot intake, and tally controls below operate on that recovered session. The
            original source files are not needed to continue — choose files here only to load a
            different election.
          </Notice>
        )}
      </Card>

      {election && (
        <>
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
              <Field label="Manifest hash">
                <HashValue value={election.manifest_hash_hex} />
                <CopyButton value={election.manifest_hash_hex} />
              </Field>
            </div>
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
      )}

      {shellAvailable && !election && (
        <Notice tone="info">Load an election to enable these controls.</Notice>
      )}

      <div className="card-grid">
        <Card title="Open Voting">
          <p className="card-body">
            Opening voting means the election starts accepting ballots from eligible voters.
            The election definition stays locked. Voting stays open until you close it.
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

        <Card title="Private ballot intake">
          <p className="card-body">
            Ballots submitted privately over Tor are handed off into an app-owned intake inbox
            for this election. Sync brings them into this authoritative election record through
            the same checks as an imported ballot: a ballot is accepted only once, and an exact
            resend is never counted twice.
          </p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "OPEN" || syncBusy}
            onClick={() => void onSyncPrivateIntake()}
          >
            {syncBusy ? "Syncing…" : "Sync accepted ballots"}
          </button>
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
          <DetailsSection summary="Operator setup (advanced)">
            <p className="card-body">
              Point the controlled Tor intake process at this app-data root so accepted ballots
              are written into the election intake inbox this app reads. The election sub-folder
              is derived from the election manifest, so a different election can never reuse it.
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

        <Card title="Close Voting">
          <p className="card-body">
            Closing voting is permanent: after voting is closed, no new ballots can be accepted
            for this election. This cannot be undone.
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
                    Hidden while voting is open
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
              <ParticipationTrack summary={participation} />
              {participationSealed && lifecycle === "OPEN" && (
                <p className="card-body">Voting is in progress. Participation is hidden until voting closes.</p>
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
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!canAct || lifecycle !== "VERIFIED"}
              onClick={() => void runLifecycle("finalize")}
            >
              Finalize
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

        <Card title="Anchor">
          <Placeholder>
            Anchor submission runs through the Phase 4 operator application, not this screen.
            Inspect the resulting snapshot and evidence on the Anchor and Evidence screens.
            Anchoring is optional and non-binding.
          </Placeholder>
        </Card>
      </div>

      {confirmClose && (
        <ConfirmDialog
          title="Close voting?"
          body={
            <>
              <p>
                After voting is closed, no new ballots can be accepted for this election.
              </p>
              <p>
                <strong>This cannot be undone.</strong>
              </p>
            </>
          }
          confirmLabel="Close Voting"
          confirmTone="danger"
          busy={lifecycleBusy}
          onConfirm={() => void onConfirmClose()}
          onCancel={() => setConfirmClose(false)}
        />
      )}
    </>
  );
}
