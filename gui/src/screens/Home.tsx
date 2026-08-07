import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
  Field,
  HashValue,
  LifecyclePill,
  Notice,
  Pill,
} from "../components/ui";

/**
 * Home dashboard: status cards only. Complete workflows live on their own
 * screens; this dashboard summarizes the current election, hashes, anchor
 * and verification status, and recent actions.
 */
export function Home() {
  const { election, recentActions, backendError, shellAvailable } = useAppState();

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
      <BackendErrorNotice message={backendError} />

      <div className="card-grid">
        <Card title="Current election">
          {election ? (
            <>
              <div className="card-value">
                {election.election_id_text ?? "Untitled election"}
              </div>
              <div className="field-list">
                <Field label="Election ID">
                  <HashValue value={election.election_id_hex} />
                </Field>
                <Field label="Registered voters">{election.voter_count}</Field>
                <Field label="Ballot options">{election.candidates.length}</Field>
              </div>
            </>
          ) : (
            <div className="card-body">No election loaded in this session.</div>
          )}
        </Card>

        <Card title="Election lifecycle">
          <div className="card-value">
            <LifecyclePill state={election?.lifecycle_state ?? null} />
          </div>
          <div className="card-body">
            DRAFT → FROZEN → OPEN → CLOSED → VERIFIED → FINALIZED. Transitions are
            append-only and enforced by the backend.
          </div>
        </Card>

        <Card title="Manifest hash">
          {election ? (
            <HashValue value={election.manifest_hash_hex} />
          ) : (
            <div className="card-body">Recomputed when an election is loaded.</div>
          )}
        </Card>

        <Card title="Archive hash">
          <div className="card-body">
            Shown after the organizer writes an archive (Manage Election → Archive) or after
            verifying an existing archive on the Archive screen.
          </div>
        </Card>

        <Card title="Anchor status">
          <div className="card-body">
            Inspect a durable anchor snapshot on the Anchor screen to see the lifecycle phase,
            submission state, and receipt verification. Anchoring never affects the offline
            result.
          </div>
        </Card>

        <Card title="Verification status">
          <div className="card-body">
            Verify an archive directory on the Archive screen. Every ballot proof is replayed
            and the tally and archive hash are recomputed offline.
          </div>
        </Card>
      </div>

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

      <p className="form-hint">
        <Pill tone="warn">Non-production prototype</Pill> No binding election is conducted with
        this software.
      </p>
    </>
  );
}
