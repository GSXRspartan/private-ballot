import { useState } from "react";

import { api, BackendError } from "../api/client";
import type { GuiArchiveVerificationV1, GuiCommandError } from "../api/types";
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
 * Archive: full offline replay verification of an archive directory through
 * the gui-core verifier, plus the archive summary view (manifest, registry,
 * ballot options, accepted/rejected ballots, archive hash, verification
 * status). The offline archive is authoritative.
 */
export function Archive() {
  const { shellAvailable, settings, recordAction } = useAppState();
  const [directory, setDirectory] = useState(settings.exportDirectory);
  const [result, setResult] = useState<GuiArchiveVerificationV1 | null>(null);
  const [error, setError] = useState<GuiCommandError | null>(null);
  const [running, setRunning] = useState(false);

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

  const onVerify = async () => {
    setError(null);
    setRunning(true);
    try {
      const verification = await api.verifyArchive(directory);
      setResult(verification);
      recordAction(
        verification.verified ? "Archive verification passed" : "Archive verification failed",
      );
    } catch (err) {
      setResult(null);
      showError(err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <h1 className="screen-header">Archive</h1>
      <p className="screen-lede">
        Verify a complete offline election archive. Every file digest is checked, every ballot
        proof is replayed through the real ingestion pipeline, the tally is recomputed, and the
        archive hash is rebuilt from the bytes on disk.
      </p>

      {!shellAvailable && (
        <Notice tone="info">
          Browser preview: verification requires the desktop shell.
        </Notice>
      )}
      <BackendErrorNotice error={error} onDismiss={() => setError(null)} />

      <Card title="Verify archive directory">
        <div className="form-row">
          <label htmlFor="archive-path">Archive directory</label>
          <input
            id="archive-path"
            type="text"
            value={directory}
            onChange={(e) => setDirectory(e.target.value)}
            placeholder="path to an archive directory"
          />
          <span className="form-hint">
            Must contain election-manifest.cbor, candidate-set.cbor, voter-registry.cbor,
            submissions/, and archive-manifest.cbor.
          </span>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!shellAvailable || !directory || running}
            onClick={() => void onVerify()}
          >
            {running ? "Verifying…" : "Verify archive"}
          </button>
        </div>
      </Card>

      {result && (
        <>
          <Card title="Verification status">
            <div className="field-list">
              <Field label="Result">
                {result.verified ? (
                  <Pill tone="ok">Verified</Pill>
                ) : (
                  <Pill tone="error">Failed</Pill>
                )}
              </Field>
              {result.failure_stage && (
                <Field label="First failing stage">{result.failure_stage}</Field>
              )}
              {result.failure_code && <Field label="Failure code">{result.failure_code}</Field>}
              <Field label="Transcript complete">
                {result.transcript_complete ? "yes" : "no"}
              </Field>
              <Field label="Archive hash consistent">
                {result.archive_hash_consistent ? "yes" : "no"}
              </Field>
            </div>
          </Card>

          <div className="card-grid">
            <Card title="Manifest">
              <div className="field-list">
                <Field label="Election manifest hash">
                  <HashValue value={result.election_manifest_hash_hex} />
                </Field>
              </div>
            </Card>

            <Card title="Archive hash">
              <div className="field-list">
                <Field label="Archived">
                  <HashValue value={result.archive_hash_hex} />
                </Field>
                <Field label="Recomputed">
                  <HashValue value={result.recomputed_archive_hash_hex} />
                </Field>
              </div>
            </Card>

            <Card title="Ballots">
              <div className="field-list">
                <Field label="Packages">{result.ballot_package_count}</Field>
                <Field label="Accepted ballots">{result.accepted_count}</Field>
                <Field label="Rejected ballots">{result.rejected_count}</Field>
                {result.tally && (
                  <Field label="Abstentions">{result.tally.abstentions}</Field>
                )}
              </div>
            </Card>
          </div>

          {result.tally && (
            <Card title="Recomputed tally — ballot options">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Option</th>
                    <th scope="col">Machine ID</th>
                    <th scope="col">Approvals</th>
                  </tr>
                </thead>
                <tbody>
                  {result.tally.counts.map((count) => (
                    <tr key={count.candidate_id_hex}>
                      <td>{count.display_name || "—"}</td>
                      <td>
                        <span className="hash">
                          {count.candidate_id_text ?? count.candidate_id_hex}
                        </span>
                      </td>
                      <td>{count.approvals}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          <Card title="Registry and catalog files">
            <p className="card-body">
              The registry and option set are validated during replay: their recomputed
              commitments must equal the manifest&rsquo;s. Catalog membership is strict —
              missing and unexpected files both fail verification.
            </p>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">Present</th>
                  <th scope="col">Digest</th>
                </tr>
              </thead>
              <tbody>
                {result.files.map((file) => (
                  <tr key={file.path}>
                    <td>
                      <span className="hash">{file.path}</span>
                    </td>
                    <td>{file.present ? "yes" : "no"}</td>
                    <td>
                      {file.digest_ok ? (
                        <Pill tone="ok">match</Pill>
                      ) : (
                        <Pill tone="error">mismatch</Pill>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
    </>
  );
}
