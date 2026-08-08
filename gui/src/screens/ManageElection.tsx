import { useState } from "react";

import { api, BackendError } from "../api/client";
import { pickElectionArtifact } from "../api/dialog";
import type {
  GuiArchiveWriteResultV1,
  GuiCommandError,
  GuiTallySummaryV1,
} from "../api/types";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { canShowTally } from "../lifecycle";
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
  Placeholder,
} from "../components/ui";

function describeLeading(tally: GuiTallySummaryV1): string {
  if ("NoApprovals" in tally.leading) return "No approvals recorded";
  if ("SingleLeader" in tally.leading) {
    const leader = tally.leading.SingleLeader;
    return `Leading: ${leader.display_name || leader.candidate_id_hex} (${leader.approvals})`;
  }
  const tie = tally.leading.Tie;
  return `Unresolved tie between ${tie.candidate_ids_hex.length} options (${tie.approvals} each)`;
}

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
    backendError,
    shellAvailable,
    loadElection,
    unloadElection,
    runLifecycle,
    recordAction,
    dismissError,
    selectedArtifactPaths,
  } = useAppState();

  const [manifestPath, setManifestPath] = useState("");
  const [registryPath, setRegistryPath] = useState("");
  const [optionSetPath, setOptionSetPath] = useState("");
  const [packagePath, setPackagePath] = useState("");
  const [archiveDir, setArchiveDir] = useState("");
  const [intakeNote, setIntakeNote] = useState<string | null>(null);
  const [tally, setTally] = useState<GuiTallySummaryV1 | null>(null);
  const [archiveResult, setArchiveResult] = useState<GuiArchiveWriteResultV1 | null>(null);
  const [localError, setLocalError] = useState<GuiCommandError | null>(null);

  const presentation = presentationFor(election);
  const lifecycle = election?.lifecycle_state ?? null;
  const canAct = shellAvailable && election !== null;
  const canLoad = shellAvailable && manifestPath !== "" && registryPath !== "" && optionSetPath !== "";
  const tallyAvailable = canShowTally(lifecycle);

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
    const picked = await pickElectionArtifact("Choose election manifest");
    if (picked !== null) setManifestPath(picked);
  };
  const onPickRegistry = async () => {
    clearLocalError();
    const picked = await pickElectionArtifact("Choose voter registry");
    if (picked !== null) setRegistryPath(picked);
  };
  const onPickOptionSet = async () => {
    clearLocalError();
    const picked = await pickElectionArtifact("Choose candidate / option set");
    if (picked !== null) setOptionSetPath(picked);
  };

  const onLoad = async () => {
    clearLocalError();
    try {
      await loadElection(manifestPath, registryPath, optionSetPath);
      setTally(null);
      setArchiveResult(null);
    } catch (error) {
      showError(error);
    }
  };

  const onIntake = async () => {
    clearLocalError();
    setIntakeNote(null);
    try {
      const result = await api.intakeBallotPackage(packagePath);
      setIntakeNote(
        result.accepted
          ? `Accepted as submission #${result.sequence}.`
          : `Rejected (${result.code}) as submission #${result.sequence}.`,
      );
      recordAction(
        result.accepted
          ? `Accepted ballot #${result.sequence}`
          : `Rejected ballot #${result.sequence} (${result.code})`,
      );
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

  const onWriteArchive = async () => {
    clearLocalError();
    try {
      const result = await api.writeArchive(archiveDir);
      setArchiveResult(result);
      recordAction("Wrote offline archive");
    } catch (error) {
      showError(error);
    }
  };

  return (
    <>
      <h1 className="screen-header">Manage Election</h1>
      <p className="screen-lede">
        Load the validated artifact triple, then walk the append-only lifecycle. Every step
        delegates to gui-core; this screen contains no protocol logic and never edits the frozen
        canonical artifacts.
      </p>

      <BackendErrorNotice error={backendError} onDismiss={dismissError} />
      <BackendErrorNotice error={localError} onDismiss={clearLocalError} />
      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: commands are disabled because the desktop shell is not running.
        </Notice>
      )}

      <Card title="Load Election">
        <p className="card-body">
          Loading validates canonical encodings, recomputes both commitments and the manifest
          hash, enforces the production proof-suite policy, and freezes the lifecycle. The session
          starts in FROZEN; review the summary before opening voting. Filenames are shown for
          convenience only — identity is derived from the decoded bytes.
        </p>
        <div className="form-row">
          <label htmlFor="manifest-path">Election manifest</label>
          <div className="file-row">
            <button
              id="manifest-path"
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickManifest()}
            >
              Choose file
            </button>
            <span className="file-name" aria-live="polite">
              {basename(manifestPath) || "no file selected"}
            </span>
          </div>
        </div>
        <div className="form-row">
          <label htmlFor="registry-path">Voter registry</label>
          <div className="file-row">
            <button
              id="registry-path"
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickRegistry()}
            >
              Choose file
            </button>
            <span className="file-name" aria-live="polite">
              {basename(registryPath) || "no file selected"}
            </span>
          </div>
        </div>
        <div className="form-row">
          <label htmlFor="optionset-path">Candidate / option set</label>
          <div className="file-row">
            <button
              id="optionset-path"
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onPickOptionSet()}
            >
              Choose file
            </button>
            <span className="file-name" aria-live="polite">
              {basename(optionSetPath) || "no file selected"}
            </span>
          </div>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canLoad}
            onClick={() => void onLoad()}
          >
            Load and Validate Election
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
              </div>
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

      <div className="card-grid">
        <Card title="Open Voting">
          <p className="card-body">Opens ballot intake. Append-only; cannot be undone.</p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "FROZEN"}
            onClick={() => void runLifecycle("open")}
          >
            Open voting
          </button>
        </Card>

        <Card title="Ballot intake">
          <p className="card-body">
            Ingest one canonical ballot package file. The first valid ballot for a nullifier
            counts; duplicates and invalid packages are rejected deterministically.
          </p>
          <div className="form-row">
            <label htmlFor="package-path">Ballot package path</label>
            <input
              id="package-path"
              type="text"
              value={packagePath}
              onChange={(e) => setPackagePath(e.target.value)}
              placeholder="ballot-package.cbor"
            />
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "OPEN" || !packagePath}
            onClick={() => void onIntake()}
          >
            Ingest ballot
          </button>
          {intakeNote && <p className="card-body">{intakeNote}</p>}
        </Card>

        <Card title="Close Voting">
          <p className="card-body">Closes acceptance permanently; late ballots never count.</p>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canAct || lifecycle !== "OPEN"}
            onClick={() => void runLifecycle("close")}
          >
            Close voting
          </button>
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
            <p className="card-body">Results are sealed until voting closes.</p>
          )}
          {tally && tallyAvailable && (
            <div className="field-list">
              <Field label="Accepted ballots">{tally.accepted_ballots}</Field>
              <Field label="Abstentions">{tally.abstentions}</Field>
              <Field label="Outcome">{describeLeading(tally)}</Field>
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

        <Card title="Archive">
          <p className="card-body">
            Writes the canonical offline archive (manifest, registry, option set, submissions,
            archive manifest) with atomic file writes.
          </p>
          <div className="form-row">
            <label htmlFor="archive-dir">Target directory (new or empty)</label>
            <input
              id="archive-dir"
              type="text"
              value={archiveDir}
              onChange={(e) => setArchiveDir(e.target.value)}
              placeholder="archive output directory"
            />
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canAct || !archiveDir}
              onClick={() => void onWriteArchive()}
            >
              Write archive
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!canAct || lifecycle !== "VERIFIED"}
              onClick={() => void runLifecycle("finalize")}
            >
              Finalize
            </button>
          </div>
          {archiveResult && (
            <div className="field-list">
              <Field label="Archive hash">
                <HashValue value={archiveResult.archive_hash_hex} />
                <CopyButton value={archiveResult.archive_hash_hex} />
              </Field>
              <Field label="Files written">{archiveResult.files.length}</Field>
            </div>
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
    </>
  );
}
