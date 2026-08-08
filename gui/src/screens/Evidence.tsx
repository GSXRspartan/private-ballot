import { useState } from "react";

import { api, BackendError } from "../api/client";
import type { GuiAnchorEvidenceInspectionV1, GuiCommandError } from "../api/types";
import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
  Field,
  HashValue,
  Notice,
  Pill,
} from "../components/ui";

/**
 * Evidence: inspection of a canonical anchor evidence record — the durable,
 * digest-verified statement of what the anchor lifecycle observed. Read-only
 * and offline, via the gui-core inspection wrapper.
 */
export function Evidence() {
  const { shellAvailable, recordAction } = useAppState();
  const [path, setPath] = useState("");
  const [evidence, setEvidence] = useState<GuiAnchorEvidenceInspectionV1 | null>(null);
  const [error, setError] = useState<GuiCommandError | null>(null);

  const onInspect = async () => {
    setError(null);
    try {
      const inspection = await api.inspectAnchorEvidence(path);
      setEvidence(inspection);
      recordAction(`Inspected anchor evidence (${inspection.final_status})`);
    } catch (err) {
      setEvidence(null);
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
    }
  };

  return (
    <>
      <h1 className="screen-header">Evidence</h1>
      <p className="screen-lede">
        An evidence record binds the election manifest hash, archive hash, anchor digest,
        transaction id, and ledger position into one canonical, digest-verified artifact for
        human review.
      </p>

      {!shellAvailable && (
        <Notice tone="info">Browser preview: inspection requires the desktop shell.</Notice>
      )}
      <BackendErrorNotice error={error} onDismiss={() => setError(null)} />

      <Card title="Anchor evidence record">
        <div className="form-row">
          <label htmlFor="evidence-path">Evidence file path</label>
          <input
            id="evidence-path"
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="anchor-evidence.cbor"
          />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!shellAvailable || !path}
            onClick={() => void onInspect()}
          >
            Inspect evidence
          </button>
        </div>

        {evidence && (
          <>
            <div className="field-list">
              <Field label="Final status">
                <Pill tone={evidence.final_status.includes("ACCEPT") ? "ok" : "warn"}>
                  {evidence.final_status}
                </Pill>
              </Field>
              <Field label="Receipt source">{evidence.receipt_source}</Field>
              <Field label="Phase">{evidence.phase}</Field>
              <Field label="Network">{evidence.network}</Field>
              <Field label="Record digest">
                <HashValue value={evidence.record_digest_hex} />
              </Field>
              <Field label="Manifest hash">
                <HashValue value={evidence.manifest_hash_hex} />
              </Field>
              <Field label="Archive hash">
                <HashValue value={evidence.archive_hash_hex} />
              </Field>
              <Field label="Anchor digest">
                <HashValue value={evidence.anchor_digest_hex} />
              </Field>
              <Field label="Transaction">{evidence.transaction_id ?? "none"}</Field>
              <Field label="Ledger position">
                {evidence.ledger_position !== null ? evidence.ledger_position : "none"}
              </Field>
              <Field label="Snapshot digest">
                <HashValue value={evidence.snapshot_digest_hex} />
              </Field>
            </div>
            <h3>Human review summary</h3>
            <p className="card-body">{evidence.human_review_summary}</p>
          </>
        )}
      </Card>

      <Notice tone="warn">
        Anchor evidence is a non-binding commitment proof. Election outcomes derive from the
        offline archive only.
      </Notice>
    </>
  );
}
