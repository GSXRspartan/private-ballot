import { useState } from "react";

import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { NavSection } from "../components/AppFrame";
import {
  coarseBucketLabel,
  formatPercent,
  participationAccessibleText,
  participationIsDisclosed,
  participationVisibilityLabel,
  resultVisibilityLabel,
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
  Pill,
} from "../components/ui";
import { LockIcon } from "../components/icons";
import { ParticipationTrack } from "../components/ParticipationTrack";

/**
 * Home dashboard. When no election is loaded it shows a calm empty state with
 * Load Election and Create Election actions — no election loaded is a NORMAL
 * application state, never an error. When an election is loaded it displays
 * real backend-derived values only — no fabricated participation counts,
 * ballot counts, or dates. Participation and results are gated by the
 * backend's application-local disclosure policy; sealed values are never
 * shown.
 */
export function Home({ onNavigate }: { onNavigate?: (section: NavSection) => void }) {
  const {
    election,
    electionAuthority,
    participation,
    recentActions,
    backendError,
    shellAvailable,
    workspaces,
    activeWorkspaceIds,
    dismissError,
    resumeElectionWorkspace,
    deleteElectionWorkspace,
  } = useAppState();
  // The workspace this session has active (loaded session and/or in-progress
  // draft). The backend delete guard is fail-closed and refuses to delete the
  // active workspace, so Home must not offer a Delete that would fail — it
  // offers "Resume" instead. This keeps the "No election loaded" empty state
  // from contradicting an undeletable active draft (Failure 2).
  const isActiveWorkspace = (workspaceId: string) =>
    workspaceId === activeWorkspaceIds?.session_workspace_id ||
    workspaceId === activeWorkspaceIds?.draft_workspace_id;
  // The workspace pending an explicit delete confirmation (null = no dialog).
  const [pendingDelete, setPendingDelete] = useState<{
    workspaceId: string;
    label: string;
  } | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const presentation = presentationFor(election);
  const sealed =
    participation !== null && participation.participation_visibility === "SEALED_UNTIL_CLOSE";
  const resultsSealed =
    participation !== null && participation.result_visibility === "SEALED";
  const disclosed = participationIsDisclosed(participation);
  const resumableWorkspaces = workspaces.slice(0, 5);

  async function resumeWorkspace(workspaceId: string, lifecycleState: string) {
    const result = await resumeElectionWorkspace(workspaceId);
    if (result.draft || lifecycleState === "DRAFT") {
      onNavigate?.("create");
      return;
    }
    onNavigate?.("manage");
  }

  async function confirmDeleteWorkspace() {
    if (!pendingDelete) return;
    setDeleteBusy(true);
    try {
      await deleteElectionWorkspace(pendingDelete.workspaceId);
      setPendingDelete(null);
    } catch {
      // The backend error is surfaced by AppState's BackendErrorNotice; keep the
      // dialog open so the user can see it failed and retry or cancel.
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <>
      <h1 className="screen-header">Home</h1>
      <p className="screen-lede">
        Tari Private Ballot lets eligible community members vote without revealing which voter
        cast a ballot. The saved election archive can be independently verified. Optional Ootle
        anchoring does not determine the result.
      </p>

      {!shellAvailable && (
        <Notice tone="info">
          The frontend is running in browser preview without the desktop shell. Backend-backed
          cards stay empty; no sample data is shown.
        </Notice>
      )}
      <BackendErrorNotice error={backendError} onDismiss={dismissError} />

      {election ? (
        <>
        <div className="card-grid">
          <Card title="Current election">
            <div className="card-value">
              {election.proposal_question ??
                election.election_id_text ??
                "Untitled election"}
            </div>
            <div className="field-list">
              {election.proposal_question && election.election_id_text && (
                <Field label="Election">{election.election_id_text}</Field>
              )}
              <Field label="Lifecycle">
                <LifecyclePill state={election.lifecycle_state} />
              </Field>
              <Field label="Eligible voters">{election.voter_count}</Field>
              <Field label="Ballot kind">{election.ballot_kind}</Field>
              <Field label={presentation.optionSetNoun}>
                {election.candidates.length}
              </Field>
              {/* ROLE TRUTH (mirrors the backend authority model): an
                  organizer workspace is durable local recovery state; an
                  imported voter election deliberately has none — its lifecycle
                  knowledge lives in signed status statements instead. */}
              {electionAuthority === "imported_voter" ? (
                <Field label="Role">Voter copy (public artifacts)</Field>
              ) : electionAuthority === "organizer" ? (
                <Field label="Role">Ballot office</Field>
              ) : (
                <Field label="Recovery">Recovery state saved locally</Field>
              )}
            </div>
            {onNavigate && (
              <div className="btn-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate("manage")}
                >
                  Open Manage Election
                </button>
              </div>
            )}
            <DetailsSection summary="Technical details & fingerprints">
              <div className="field-list">
                <Field label="Election ID">
                  <HashValue value={election.election_id_hex} />
                  <CopyButton value={election.election_id_hex} label="Copy ID" />
                </Field>
                <Field label="Manifest schema">
                  ElectionManifestV{election.manifest_schema_version}
                </Field>
                <Field label="Manifest hash">
                  <HashValue value={election.manifest_hash_hex} />
                  <CopyButton value={election.manifest_hash_hex} label="Copy" />
                </Field>
                <Field label="Registry commitment">
                  <HashValue value={election.registry_commitment_hex} />
                  <CopyButton value={election.registry_commitment_hex} label="Copy" />
                </Field>
                <Field label="Option-set commitment">
                  <HashValue value={election.candidate_set_commitment_hex} />
                  <CopyButton value={election.candidate_set_commitment_hex} label="Copy" />
                </Field>
                <Field label="Proof suite">{election.proof_suite_id}</Field>
                <Field label="Confidentiality">{election.ballot_confidentiality}</Field>
                <Field label="Governance source">
                  {election.governance_source_revision}
                </Field>
              </div>
            </DetailsSection>
          </Card>

          <Card title="Voting rules">
            <div className="field-list">
              <Field label="Approval rule">{approvalRuleText(election)}</Field>
              <Field label="Abstention">
                {election.abstention_allowed ? "permitted" : "not permitted"}
              </Field>
            </div>
          </Card>

          <Card title="Archive status">
            {election.lifecycle_state === "FINALIZED" ? (
              <>
                <div className="card-body">
                  Election finalized — ready to write the final archive.
                </div>
                <p className="card-body">
                  Write the final offline archive from Manage Election, then verify it on the
                  Archive screen. Archive integrity is confirmed by the verifier in the session
                  where you run it, separately from the election being finalized.
                </p>
              </>
            ) : (
              <>
                <div className="card-body">No final archive yet</div>
                <p className="card-body">
                  The final archive is written from Manage Election after the election is
                  finalized (close, tally, mark verified, then finalize).
                </p>
              </>
            )}
          </Card>

          <Card title="Anchor status">
            <div className="card-body">No anchor state loaded in this session</div>
            <p className="card-body">
              Anchoring is optional and non-binding. Inspect a snapshot on the Anchor screen.
            </p>
          </Card>
        </div>

        <div className="analytics-grid">
          <Card title="Participation">
            {participation ? (
              <>
                <div
                  className="metric-head"
                  role="img"
                  aria-label={participationAccessibleText(participation)}
                >
                  {sealed ? (
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
                  {disclosed && participation.accepted_ballots !== null && (
                    <span className="metric-sub">
                      {participation.accepted_ballots} of {participation.eligible_voters} eligible voters
                    </span>
                  )}
                </div>
                <ParticipationTrack summary={participation} />
                {sealed && (
                  <p className="card-body">Participation is hidden until voting closes.</p>
                )}
                {participation.small_electorate && !sealed && election?.lifecycle_state === "OPEN" && (
                  <p className="card-body">
                    Small electorate: live detail is hidden while voting is open.
                  </p>
                )}
                {participation.small_electorate && !sealed && election?.lifecycle_state !== "OPEN" && (
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

          <Card title="Accepted ballots">
            {participation && participation.accepted_ballots !== null ? (
              <div className="metric-head">
                <span className="metric-value">{participation.accepted_ballots}</span>
              </div>
            ) : (
              <div className="metric-head">
                <span className="metric-value metric-sealed">
                  <LockIcon label="Hidden" />
                  Hidden while voting is open
                </span>
              </div>
            )}
            <p className="card-body">
              {sealed
                ? "Accepted-ballot count is hidden until voting closes."
                : "Accepted ballots are deduplicated by registry-scoped nullifier."}
            </p>
          </Card>

          <Card title="Eligible voters">
            {election ? (
              <div className="metric-head">
                <span className="metric-value">{election.voter_count}</span>
                <span className="metric-sub">registered</span>
              </div>
            ) : (
              <p className="card-body">No election loaded.</p>
            )}
          </Card>

          <Card title="Lifecycle">
            <div className="metric-head">
              <LifecyclePill state={election?.lifecycle_state ?? null} />
            </div>
            <p className="card-body">
              Results: {participation ? resultVisibilityLabel(participation.result_visibility) : "—"}.
            </p>
          </Card>

          <Card title="Results">
            {resultsSealed || !participation ? (
              <div
                className="result-bars-sealed"
                role="img"
                aria-label="Results are sealed until voting closes."
              >
                <div className="result-bars-sealed-label">
                  <LockIcon label="Sealed" />
                  Locked
                </div>
                <p className="card-body">Results are sealed until voting closes.</p>
              </div>
            ) : (
              <p className="card-body">
                Results are available. Open Manage Election to view the final result bars; the
                tally is recomputed deterministically from the accepted ballots.
              </p>
            )}
          </Card>
        </div>
        </>
      ) : (
        <>
          {resumableWorkspaces.length > 0 && (
            <Card title="Resume Election">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Election</th>
                    <th scope="col">Status</th>
                    <th scope="col">Accepted ballots</th>
                    <th scope="col">Role</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {resumableWorkspaces.map((workspace) => (
                    <tr key={workspace.workspace_id}>
                      <td>
                        {workspace.question_preview ??
                          workspace.election_manifest_hash_hex ??
                          workspace.workspace_id}
                      </td>
                      <td>
                        <LifecyclePill state={workspace.lifecycle_state} />
                      </td>
                      <td>{workspace.accepted_ballot_count}</td>
                      <td>
                        {/* ROLE TRUTH: only workspaces with durable
                            organizer-authority provenance restore ballot-office
                            controls; anything else resumes as a voter view.
                            Surfaced here so the role is visible BEFORE
                            resuming. The "Ballot office" role pill uses the
                            brand/selection tone (Tari Purple), NOT the
                            success-green tone, because this describes a ROLE
                            rather than a positive lifecycle state. */}
                        {workspace.lifecycle_state === "DRAFT" ? (
                          <Pill tone="brand">Draft</Pill>
                        ) : workspace.organizer_workspace ? (
                          <Pill tone="brand">Ballot office</Pill>
                        ) : (
                          <Pill tone="neutral">Voter copy</Pill>
                        )}
                      </td>
                      <td>
                        <div className="action-row">
                          <button
                            type="button"
                            className="btn btn-primary"
                            onClick={() =>
                              void resumeWorkspace(
                                workspace.workspace_id,
                                workspace.lifecycle_state,
                              )
                            }
                          >
                            Resume
                          </button>
                          {isActiveWorkspace(workspace.workspace_id) ? (
                            <span className="form-hint">
                              In progress — your current draft. Resume to continue editing.
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary"
                              onClick={() =>
                                setPendingDelete({
                                  workspaceId: workspace.workspace_id,
                                  label:
                                    workspace.question_preview ??
                                    workspace.election_manifest_hash_hex ??
                                    workspace.workspace_id,
                                })
                              }
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="form-hint">
                Delete removes only the local organizer workspace from this device. Exported
                canonical election files and finalized archives are not affected.
              </p>
            </Card>
          )}

          <Card title="No election loaded">
            <div className="empty-state">
              <div className="card-body">
                Load an election shared by an organizer, or create a new election to get
                started.
              </div>
              <div className="btn-row">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => onNavigate?.("manage")}
                >
                  Load Election
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate?.("create")}
                >
                  Create Election
                </button>
              </div>
            </div>
          </Card>
        </>
      )}

      <Card title="Recent actions">
        {recentActions.length === 0 ? (
          <div className="card-body">No actions recorded in this session.</div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {recentActions.map((action) => (
                <tr key={`${action.at}-${action.label}`}>
                  <td>{new Date(action.at).toLocaleString()}</td>
                  <td>{action.label}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {pendingDelete && (
        <ConfirmDialog
          title="Delete local election workspace?"
          body={
            <>
              <p>
                Election:
                <br />
                <strong>{pendingDelete.label}</strong>
              </p>
              <p>
                This removes the local organizer workspace from this device. Exported canonical
                election files or finalized archives outside the app-data workspace are not
                deleted.
              </p>
            </>
          }
          confirmLabel="Delete election"
          confirmTone="danger"
          busy={deleteBusy}
          onConfirm={() => void confirmDeleteWorkspace()}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </>
  );
}
