import { useEffect, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickCborFile } from "../api/dialog";
import { boundArchiveResult } from "../archive/archiveBinding";
import type {
  GuiAnchorConfigInspectionV1,
  GuiAnchorSnapshotInspectionV1,
  GuiCommandError,
  GuiV2LiveAnchorHydratedStateV1,
} from "../api/types";
import type { NavSection } from "../components/AppFrame";
import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
  CopyButton,
  DetailsSection,
  Field,
  HashValue,
  Notice,
  Pill,
} from "../components/ui";
import {
  summarizeV2AnchorState,
  v2AnchorBadgeLabel,
  v2AnchorBadgeTone,
} from "../anchor/v2AnchorStatus";

function phasePill(snapshot: GuiAnchorSnapshotInspectionV1) {
  if (snapshot.phase_is_terminal_success) return <Pill tone="ok">{snapshot.phase}</Pill>;
  if (snapshot.phase_is_terminal) return <Pill tone="error">{snapshot.phase}</Pill>;
  return <Pill tone="info">{snapshot.phase}</Pill>;
}

/**
 * Anchor: dedicated READ-ONLY V2 anchor status screen for the currently
 * verified archive. It hydrates the app-owned V2 lifecycle/evidence sidecars
 * through `inspect_v2_live_anchor_state` and never contacts walletd or the
 * network. Publishing lives on Manage Election.
 *
 * The legacy V1 CBOR-file inspection (anchor-config.cbor / anchor-snapshot.cbor)
 * remains available under an Advanced disclosure for historical compatibility
 * — normal current V2 users should not be asked to select those files.
 */
export function Anchor({
  onNavigate,
}: { onNavigate?: (section: NavSection) => void } = {}) {
  const { shellAvailable, recordAction, archiveView } = useAppState();
  // A verification result is only shown here if it was actually produced for
  // the currently entered directory; the same binding rule Archive uses.
  const verifiedArchive = boundArchiveResult(
    archiveView.verification,
    archiveView.directory,
  );
  const archiveDirectory = archiveView.directory;

  const [configPath, setConfigPath] = useState("");
  const [snapshotPath, setSnapshotPath] = useState("");
  const [config, setConfig] = useState<GuiAnchorConfigInspectionV1 | null>(null);
  const [snapshot, setSnapshot] = useState<GuiAnchorSnapshotInspectionV1 | null>(null);
  const [error, setError] = useState<GuiCommandError | null>(null);
  const [v2AnchorState, setV2AnchorState] =
    useState<GuiV2LiveAnchorHydratedStateV1 | null>(null);
  const [v2InspectionError, setV2InspectionError] = useState<GuiCommandError | null>(null);

  const showError = (err: unknown) =>
    setError(
      err instanceof BackendError
        ? err.payload
        : {
            code: "GUI_UNEXPECTED_ERROR",
            category: "INVALID_INPUT",
            context: null,
            message: "an unexpected frontend/backend boundary error occurred",
          },
    );

  const commandError = (err: unknown): GuiCommandError =>
    err instanceof BackendError
      ? err.payload
      : {
          code: "GUI_UNEXPECTED_ERROR",
          category: "INVALID_INPUT",
          context: null,
          message: "an unexpected frontend/backend boundary error occurred",
        };

  const onPickConfig = async () => {
    const picked = await pickCborFile("Choose anchor config file");
    if (picked !== null) setConfigPath(picked);
  };

  const onPickSnapshot = async () => {
    const picked = await pickCborFile("Choose anchor snapshot file");
    if (picked !== null) setSnapshotPath(picked);
  };

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

  // Auto-hydrate V2 state for the CURRENTLY verified archive. Reset when the
  // directory changes; a stale response for the previous directory is
  // discarded on completion.
  useEffect(() => {
    setV2AnchorState(null);
    setV2InspectionError(null);
  }, [archiveDirectory]);

  useEffect(() => {
    if (!shellAvailable) return;
    if (!verifiedArchive || !verifiedArchive.verified) return;
    const submittedDirectory = archiveDirectory;
    let cancelled = false;
    void (async () => {
      try {
        const hydrated = await api.inspectV2LiveAnchorState(submittedDirectory);
        if (cancelled) return;
        setV2AnchorState(hydrated);
      } catch (err) {
        if (cancelled) return;
        setV2InspectionError(commandError(err));
        setV2AnchorState(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [archiveDirectory, verifiedArchive, shellAvailable]);

  const v2Summary = summarizeV2AnchorState(v2AnchorState);

  return (
    <>
      <h1 className="screen-header">Anchor</h1>
      <p className="screen-lede">
        Tari Ootle anchoring is optional and non-binding. It publishes a public aggregate
        integrity record for the finalized election. Individual ballots are never published to
        Ootle. The independently verified offline archive remains authoritative.
      </p>

      {!shellAvailable && (
        <Notice tone="info">Browser preview: inspection requires the desktop shell.</Notice>
      )}
      <BackendErrorNotice error={error} onDismiss={() => setError(null)} />

      {!verifiedArchive || !verifiedArchive.verified ? (
        <Card title="Verify a final archive first">
          <p className="card-body">
            Open Archive and independently verify the election record before inspecting its
            anchor binding. Nothing on this screen contacts the network, but the anchor
            status is scoped to a verified archive.
          </p>
          <div className="action-row">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate?.("archive")}
              disabled={!onNavigate}
            >
              Open Archive
            </button>
          </div>
        </Card>
      ) : (
        <Card title="Tari Ootle anchor">
          {v2InspectionError && (
            <Notice tone="warn">
              Could not read V2 anchor state: {v2InspectionError.message}
            </Notice>
          )}
          {v2Summary === null && !v2InspectionError && (
            <p className="form-hint">Loading current anchor state…</p>
          )}

          {v2Summary && v2Summary.kind === "verified" && (
            <>
              <div className="field-list">
                <Field label="Status">
                  <Pill tone={v2AnchorBadgeTone(v2Summary.kind)}>
                    {v2AnchorBadgeLabel(v2Summary.kind)}
                  </Pill>
                </Field>
                {verifiedArchive.proposal_question && (
                  <Field label="Ballot question">
                    <span className="field-value">{verifiedArchive.proposal_question}</span>
                  </Field>
                )}
                {v2Summary.network && <Field label="Network">{v2Summary.network}</Field>}
                {v2Summary.transactionId && (
                  <Field label="Transaction">
                    <span className="hash">{v2Summary.transactionId}</span>
                    <CopyButton value={v2Summary.transactionId} />
                  </Field>
                )}
                <Field label="Receipt">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Canonical public summary">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Anchor digest">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Evidence">
                  <Pill tone="ok">Written</Pill>
                </Field>
                <Field label="Evidence path">
                  <span className="hash">{v2Summary.evidencePath}</span>
                  <CopyButton value={v2Summary.evidencePath} />
                </Field>
              </div>
              <p className="form-hint">
                Ootle anchoring is aggregate and non-binding: it publishes only a public
                summary derived from the verified archive. Individual ballots, voter
                identities, credentials, and nullifiers are never published.
              </p>
              <DetailsSection summary="Advanced V2 anchor details">
                <div className="field-list">
                  {v2Summary.templateAddress && (
                    <Field label="Template address">
                      <span className="hash">{v2Summary.templateAddress}</span>
                    </Field>
                  )}
                  {v2Summary.templateModule && (
                    <Field label="Template module">{v2Summary.templateModule}</Field>
                  )}
                  {v2Summary.templateFunction && (
                    <Field label="Template function">{v2Summary.templateFunction}</Field>
                  )}
                  {v2Summary.templateTopic && (
                    <Field label="Canonical event topic">
                      <span className="hash">{v2Summary.templateTopic}</span>
                    </Field>
                  )}
                  {v2Summary.templateArtifactDigestHex && (
                    <Field label="Template artifact digest">
                      <HashValue value={v2Summary.templateArtifactDigestHex} />
                    </Field>
                  )}
                  {v2Summary.expectedDigestHex && (
                    <Field label="Anchor digest (raw)">
                      <HashValue value={v2Summary.expectedDigestHex} />
                    </Field>
                  )}
                  {v2Summary.phase && (
                    <Field label="Lifecycle state">{v2Summary.phase}</Field>
                  )}
                  <Field label="Lifecycle sidecar">
                    <span className="hash">{v2Summary.lifecyclePath}</span>
                  </Field>
                </div>
              </DetailsSection>
            </>
          )}

          {v2Summary && v2Summary.kind === "no-anchor" && (
            <>
              <p className="card-body">
                <strong>No Ootle anchor published for this archive.</strong>
              </p>
              <p className="form-hint">
                Anchoring is optional. The archive remains valid and independently verifiable
                without one. Publishing lives on Manage Election.
              </p>
              <div className="action-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate?.("manage")}
                  disabled={!onNavigate}
                >
                  Open Manage Election
                </button>
              </div>
            </>
          )}

          {v2Summary &&
            (v2Summary.kind === "submitted-unverified" ||
              v2Summary.kind === "recoverable") && (
              <>
                <Notice tone="warn">
                  <strong>Existing anchor needs verification.</strong> A transaction has been
                  submitted for this archive but the receipt has not been verified. Verify it
                  from Manage Election — do not submit another transaction from this screen.
                </Notice>
                <div className="field-list">
                  {v2Summary.transactionId && (
                    <Field label="Transaction">
                      <span className="hash">{v2Summary.transactionId}</span>
                      <CopyButton value={v2Summary.transactionId} />
                    </Field>
                  )}
                  {v2Summary.network && <Field label="Network">{v2Summary.network}</Field>}
                  {v2Summary.phase && (
                    <Field label="Lifecycle phase">{v2Summary.phase}</Field>
                  )}
                </div>
                <div className="action-row">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => onNavigate?.("manage")}
                    disabled={!onNavigate}
                  >
                    Open Manage Election to verify existing anchor
                  </button>
                </div>
              </>
            )}

          {v2Summary && v2Summary.kind === "failed" && (
            <>
              <Notice tone="error">
                <strong>Anchor lifecycle terminated in FAILED.</strong>{" "}
                {v2Summary.failureReason ?? "See Manage Election for details."}
              </Notice>
              <div className="action-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate?.("manage")}
                  disabled={!onNavigate}
                >
                  Open Manage Election
                </button>
              </div>
            </>
          )}
        </Card>
      )}

      <DetailsSection summary="Legacy V1 anchor verification">
        <p className="form-hint">
          Historical compatibility only. Current V2 anchor verification is shown above and
          reads app-owned JSON sidecars automatically — normal V2 users should not need to
          browse for these files.
        </p>
        <Card title="Legacy V1 anchor configuration (anchor-config.cbor)">
          <div className="form-row">
            <label htmlFor="anchor-config-path">Config file path</label>
            <div className="file-row">
              <input
                id="anchor-config-path"
                type="text"
                value={configPath}
                onChange={(e) => setConfigPath(e.target.value)}
                placeholder="anchor-config.cbor"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable}
                onClick={() => void onPickConfig()}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable || !configPath}
              onClick={() => void onInspectConfig()}
            >
              Inspect config
            </button>
          </div>
          {shellAvailable && !configPath && (
            <p className="form-hint">Choose an anchor config file to continue.</p>
          )}
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

        <Card title="Legacy V1 election snapshot (anchor-snapshot.cbor)">
          <p className="form-hint">
            The saved election snapshot records the legacy V1 anchor status for this election.
          </p>
          <div className="form-row">
            <label htmlFor="anchor-snapshot-path">Snapshot file path</label>
            <div className="file-row">
              <input
                id="anchor-snapshot-path"
                type="text"
                value={snapshotPath}
                onChange={(e) => setSnapshotPath(e.target.value)}
                placeholder="anchor-snapshot.cbor"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable}
                onClick={() => void onPickSnapshot()}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
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
                {snapshot.diagnostic && (
                  <Field label="Diagnostic">{snapshot.diagnostic}</Field>
                )}
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
      </DetailsSection>

      <Notice tone="info">
        Anchoring is optional and non-binding. Election outcomes come from the independently
        verified election archive. Voters never send an Ootle transaction; only the public
        aggregate summary is published, never individual ballots.
      </Notice>
    </>
  );
}
