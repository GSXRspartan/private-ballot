import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
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

/**
 * Home dashboard. When no election is loaded it shows a calm empty state with a
 * Load Election primary action. When an election is loaded it displays real
 * backend-derived values only — no fabricated participation counts, ballot
 * counts, or dates.
 */
export function Home({ onNavigate }: { onNavigate?: (section: "manage") => void }) {
  const { election, recentActions, backendError, shellAvailable, dismissError } = useAppState();
  const presentation = presentationFor(election);

  return (
    <>
      <h1 className="screen-header">Home</h1>
      <p className="screen-lede">
        Offline-first private ballot client. The offline archive is authoritative; Ootle
        anchoring is optional and non-binding.
      </p>

      {!shellAvailable && (
        <Notice tone="info">
          The frontend is running in browser preview without the desktop shell. Backend-backed
          cards stay empty; no sample data is shown.
        </Notice>
      )}
      <BackendErrorNotice error={backendError} onDismiss={dismissError} />

      {election ? (
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
              <Field label="Ballot kind">{election.ballot_kind}</Field>
              <Field label="Eligible voters">{election.voter_count}</Field>
              <Field label={presentation.optionSetNoun}>
                {election.candidates.length}
              </Field>
            </div>
          </Card>

          <Card title="Election bindings">
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

          <Card title="Participation">
            <div className="card-body">Not available</div>
            <p className="card-body">
              Participation and ballot counts are shown only after ballots are ingested and a tally
              is computed on the Manage Election screen.
            </p>
          </Card>
        </div>
      ) : (
        <Card title="No election loaded">
          <div className="card-body">
            Load the three canonical election artifacts (manifest, voter registry, and
            candidate/option set) to inspect a real election.
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate?.("manage")}
            >
              Load Election
            </button>
          </div>
        </Card>
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
