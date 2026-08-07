import { useState } from "react";

import { api, BackendError } from "../api/client";
import type {
  GuiAnchorConfigInspectionV1,
  GuiAnchorSnapshotInspectionV1,
} from "../api/types";
import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
  Field,
  HashValue,
  Notice,
  Pill,
} from "../components/ui";

function phasePill(snapshot: GuiAnchorSnapshotInspectionV1) {
  if (snapshot.phase_is_terminal_success) return <Pill tone="ok">{snapshot.phase}</Pill>;
  if (snapshot.phase_is_terminal) return <Pill tone="error">{snapshot.phase}</Pill>;
  return <Pill tone="info">{snapshot.phase}</Pill>;
}

/**
 * Anchor: structured, read-only inspection of the Phase 4 anchor artifacts
 * (application config and durable lifecycle snapshot). No walletd redesign,
 * no network contact, no driver changes: these are the gui-core inspection
 * wrappers equivalent to the CLI modes.
 */
export function Anchor() {
  const { shellAvailable, recordAction } = useAppState();
  const [configPath, setConfigPath] = useState("");
  const [snapshotPath, setSnapshotPath] = useState("");
  const [config, setConfig] = useState<GuiAnchorConfigInspectionV1 | null>(null);
  const [snapshot, setSnapshot] = useState<GuiAnchorSnapshotInspectionV1 | null>(null);
  const [error, setError] = useState<string | null>(null);

  const showError = (err: unknown) =>
    setError(
      err instanceof BackendError
        ? `${err.payload.code}: ${err.payload.message}`
        : "unexpected boundary error",
    );

  const onInspectConfig = async () => {
    setError(null);
    try {
      const inspection = await api.inspectAnchorConfig(configPath);
      setConfig(inspection);
      setSnapshotPath((current) => current || inspection.snapshot_path);
      recordAction("Inspected anchor config");
    } catch (err) {
      showError(err);
    }
  };

  const onInspectSnapshot = async () => {
    setError(null);
    try {
      const inspection = await api.inspectAnchorSnapshot(snapshotPath);
      setSnapshot(inspection);
      recordAction(`Inspected anchor snapshot (${inspection.phase})`);
    } catch (err) {
      showError(err);
    }
  };

  return (
    <>
      <h1 className="screen-header">Anchor</h1>
      <p className="screen-lede">
        Optional, non-binding Ootle anchoring of the election archive. Inspection is read-only
        and offline; the offline archive remains authoritative regardless of anchor state.
      </p>

      {!shellAvailable && (
        <Notice tone="info">Browser preview: inspection requires the desktop shell.</Notice>
      )}
      <BackendErrorNotice message={error} />

      <Card title="Anchor configuration">
        <div className="form-row">
          <label htmlFor="anchor-config-path">Config file path</label>
          <input
            id="anchor-config-path"
            type="text"
            value={configPath}
            onChange={(e) => setConfigPath(e.target.value)}
            placeholder="anchor-config.cbor"
          />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!shellAvailable || !configPath}
            onClick={() => void onInspectConfig()}
          >
            Inspect config
          </button>
        </div>
        {config && (
          <div className="field-list">
            <Field label="Network">{config.network}</Field>
            <Field label="Manifest hash">
              <HashValue value={config.manifest_hash_hex} />
            </Field>
            <Field label="Archive hash">
              <HashValue value={config.archive_hash_hex} />
            </Field>
            <Field label="Anchor digest">
              <HashValue value={config.anchor_digest_hex} />
            </Field>
            <Field label="Fee account">{config.account_reference}</Field>
            <Field label="Max fee">{config.max_fee}</Field>
            <Field label="Seal signer">{config.seal_signer}</Field>
            <Field label="Receipt attempts">{config.receipt_query_max_attempts}</Field>
          </div>
        )}
      </Card>

      <Card title="Lifecycle snapshot">
        <div className="form-row">
          <label htmlFor="anchor-snapshot-path">Snapshot file path</label>
          <input
            id="anchor-snapshot-path"
            type="text"
            value={snapshotPath}
            onChange={(e) => setSnapshotPath(e.target.value)}
            placeholder="anchor-snapshot.cbor"
          />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!shellAvailable || !snapshotPath}
            onClick={() => void onInspectSnapshot()}
          >
            Inspect snapshot
          </button>
        </div>

        {snapshot && (
          <>
            <div className="field-list">
              <Field label="Anchor status">{phasePill(snapshot)}</Field>
              <Field label="Lifecycle state">
                {snapshot.phase_is_terminal
                  ? snapshot.phase_is_terminal_success
                    ? "terminal (success)"
                    : "terminal (failed)"
                  : "in progress"}
              </Field>
              <Field label="Snapshot digest">
                <HashValue value={snapshot.snapshot_digest_hex} />
              </Field>
              <Field label="Transaction">
                {snapshot.submitted_transaction_id ?? "not submitted"}
              </Field>
              <Field label="Poll attempts">
                {snapshot.poll_attempts_consumed} of {snapshot.poll_attempts_max}
              </Field>
              {snapshot.diagnostic && <Field label="Diagnostic">{snapshot.diagnostic}</Field>}
            </div>

            {snapshot.walletd.length > 0 && (
              <>
                <h3>Walletd submissions</h3>
                <table className="data">
                  <thead>
                    <tr>
                      <th scope="col">Request</th>
                      <th scope="col">Decision</th>
                      <th scope="col">Submission</th>
                      <th scope="col">Transaction</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshot.walletd.map((entry) => (
                      <tr key={entry.sequence}>
                        <td>{entry.project_request_id}</td>
                        <td>{entry.decision}</td>
                        <td>{entry.submission_state}</td>
                        <td>{entry.transaction_id ?? "—"}</td>
                        <td>{entry.effective_status ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            {snapshot.receipts.length > 0 && (
              <>
                <h3>Receipt queries</h3>
                <table className="data">
                  <thead>
                    <tr>
                      <th scope="col">Transaction</th>
                      <th scope="col">Query state</th>
                      <th scope="col">Final status</th>
                      <th scope="col">Verified</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshot.receipts.map((entry) => (
                      <tr key={entry.sequence}>
                        <td>{entry.transaction_id}</td>
                        <td>{entry.query_state}</td>
                        <td>{entry.final_status ?? "—"}</td>
                        <td>
                          {entry.verified ? (
                            <Pill tone="ok">verified</Pill>
                          ) : (
                            <Pill tone="neutral">no</Pill>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </>
        )}
      </Card>

      <Notice tone="info">
        The anchor proves commitment existence on Ootle; it never decides the election. Evidence
        records are inspected on the Evidence screen.
      </Notice>
    </>
  );
}
