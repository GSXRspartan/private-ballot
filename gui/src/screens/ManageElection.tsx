import { useState } from "react";

import { api, BackendError } from "../api/client";
import type { GuiArchiveWriteResultV1, GuiTallySummaryV1 } from "../api/types";
import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
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

/**
 * Manage Election (organizer): Review/Freeze, Open Voting, Close Voting,
 * Verify, Archive, Anchor — as step cards. Loading artifacts and the
 * lifecycle transitions call real gui-core commands; ballot intake, tally,
 * and archive writing are also real. Anchor *submission* is a placeholder:
 * only inspection wrappers exist in this phase.
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
  } = useAppState();

  const [manifestPath, setManifestPath] = useState("");
  const [registryPath, setRegistryPath] = useState("");
  const [optionSetPath, setOptionSetPath] = useState("");
  const [packagePath, setPackagePath] = useState("");
  const [archiveDir, setArchiveDir] = useState("");
  const [intakeNote, setIntakeNote] = useState<string | null>(null);
  const [tally, setTally] = useState<GuiTallySummaryV1 | null>(null);
  const [archiveResult, setArchiveResult] = useState<GuiArchiveWriteResultV1 | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const presentation = presentationFor(election);
  const lifecycle = election?.lifecycle_state ?? null;
  const canAct = shellAvailable && election !== null;

  const showError = (error: unknown) => {
    setLocalError(
      error instanceof BackendError
        ? `${error.payload.code}: ${error.payload.message}`
        : "unexpected boundary error",
    );
  };

  const onLoad = async () => {
    setLocalError(null);
    try {
      await loadElection(manifestPath, registryPath, optionSetPath);
      setTally(null);
      setArchiveResult(null);
    } catch (error) {
      showError(error);
    }
  };

  const onIntake = async () => {
    setLocalError(null);
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
    setLocalError(null);
    try {
      const result = await api.currentTally();
      setTally(result);
      recordAction("Computed tally");
    } catch (error) {
      showError(error);
    }
  };

  const onWriteArchive = async () => {
    setLocalError(null);
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
        delegates to gui-core; this screen contains no protocol logic.
      </p>

      <BackendErrorNotice message={backendError} />
      <BackendErrorNotice message={localError} />
      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: commands are disabled because the desktop shell is not running.
        </Notice>
      )}

      <Card title="1 · Load artifacts (Review / Freeze)">
        <p className="card-body">
          Loading validates canonical encodings, recomputes both commitments and the manifest
          hash, enforces the production proof-suite policy, and freezes the lifecycle. The
          session starts in FROZEN; review the summary before opening voting.
        </p>
        <div className="form-row">
          <label htmlFor="manifest-path">Election manifest path</label>
          <input
            id="manifest-path"
            type="text"
            value={manifestPath}
            onChange={(e) => setManifestPath(e.target.value)}
            placeholder="election-manifest.cbor"
          />
        </div>
        <div className="form-row">
          <label htmlFor="registry-path">Voter registry path</label>
          <input
            id="registry-path"
            type="text"
            value={registryPath}
            onChange={(e) => setRegistryPath(e.target.value)}
            placeholder="voter-registry.cbor"
          />
        </div>
        <div className="form-row">
          <label htmlFor="optionset-path">Option set (candidate set) path</label>
          <input
            id="optionset-path"
            type="text"
            value={optionSetPath}
            onChange={(e) => setOptionSetPath(e.target.value)}
            placeholder="candidate-set.cbor"
          />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!shellAvailable || !manifestPath || !registryPath || !optionSetPath}
            onClick={() => void onLoad()}
          >
            Load and freeze
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!canAct}
            onClick={() => void unloadElection()}
          >
            Unload session
          </button>
        </div>
      </Card>

      {election && (
        <Card title="Frozen election summary">
          <div className="field-list">
            <Field label="Election">
              {election.election_id_text ?? election.election_id_hex}
            </Field>
            <Field label="Lifecycle">
              <LifecyclePill state={lifecycle} />
            </Field>
            <Field label="Ballot kind">{election.ballot_kind}</Field>
            <Field label="Confidentiality">{election.ballot_confidentiality}</Field>
            <Field label="Approval rule">{approvalRuleText(election)}</Field>
            <Field label="Registered voters">{election.voter_count}</Field>
            <Field label="Proof suite">{election.proof_suite_id}</Field>
            <Field label="Governance revision">{election.governance_source_revision}</Field>
            <Field label="Manifest hash">
              <HashValue value={election.manifest_hash_hex} />
            </Field>
            <Field label="Registry commitment">
              <HashValue value={election.registry_commitment_hex} />
            </Field>
            <Field label="Option-set commitment">
              <HashValue value={election.candidate_set_commitment_hex} />
            </Field>
          </div>
          <h3>{presentation.optionSetNoun}</h3>
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
        </Card>
      )}

      <div className="card-grid">
        <Card title="2 · Open Voting">
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

        <Card title="3 · Ballot intake">
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

        <Card title="4 · Close Voting">
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

        <Card title="5 · Tally">
          <p className="card-body">
            Deterministic approval tally over accepted ballots. A tie is reported as a tie.
          </p>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!canAct}
            onClick={() => void onTally()}
          >
            Compute tally
          </button>
          {tally && (
            <div className="field-list">
              <Field label="Accepted ballots">{tally.accepted_ballots}</Field>
              <Field label="Abstentions">{tally.abstentions}</Field>
              <Field label="Outcome">{describeLeading(tally)}</Field>
            </div>
          )}
        </Card>

        <Card title="6 · Verify">
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

        <Card title="7 · Archive">
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
              </Field>
              <Field label="Files written">{archiveResult.files.length}</Field>
            </div>
          )}
        </Card>

        <Card title="8 · Anchor">
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
