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
  CopyButton,
  Field,
  HashValue,
  LifecyclePill,
  Notice,
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
    participation,
    recentActions,
    backendError,
    shellAvailable,
    workspaces,
    dismissError,
    resumeElectionWorkspace,
  } = useAppState();
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
              {election.election_id_text ?? "Untitled election"}
            </div>
            <div className="field-list">
              <Field label="Election ID">
                <HashValue value={election.election_id_hex} />
                <CopyButton value={election.election_id_hex} label="Copy ID" />
              </Field>
              <Field label="Lifecycle">
                <LifecyclePill state={election.lifecycle_state} />
              </Field>
              <Field label="Recovery">Recovery state saved locally</Field>
              <Field label="Manifest schema">
                ElectionManifestV{election.manifest_schema_version}
              </Field>
              {election.proposal_question && (
                <Field label="Ballot question">{election.proposal_question}</Field>
              )}
              <Field label="Ballot kind">{election.ballot_kind}</Field>
              <Field label="Eligible voters">{election.voter_count}</Field>
              <Field label={presentation.optionSetNoun}>
                {election.candidates.length}
              </Field>
            </div>
          </Card>

          <Card title="Election fingerprints">
            <div className="field-list">
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
            </div>
          </Card>

          <Card title="Voting rules">
            <div className="field-list">
              <Field label="Proof suite">{election.proof_suite_id}</Field>
              <Field label="Confidentiality">{election.ballot_confidentiality}</Field>
              <Field label="Approval rule">{approvalRuleText(election)}</Field>
              <Field label="Abstention">
                {election.abstention_allowed ? "permitted" : "not permitted"}
              </Field>
              <Field label="Governance source">
                {election.governance_source_revision}
              </Field>
            </div>
          </Card>

          <Card title="Archive status">
            <div className="card-body">No archive loaded in this session</div>
            <p className="card-body">
              Write an offline archive from Manage Election after the election is verified.
            </p>
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
                Results are disclosed. Open Manage Election to compute the tally and view final
                result bars.
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
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() =>
                            void resumeWorkspace(
                              workspace.workspace_id,
                              workspace.lifecycle_state,
                            )
                          }
                        >
                          Resume
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
    </>
  );
}
