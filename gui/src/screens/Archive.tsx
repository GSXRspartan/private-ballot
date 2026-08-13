import { useState } from "react";

import { api, BackendError } from "../api/client";
import { pickCborFile, pickDirectory } from "../api/dialog";
import type {
  GuiArchiveVerificationV1,
  GuiCommandError,
  GuiTransportAnchorVerificationV1,
} from "../api/types";
import { useAppState } from "../state/AppState";
import {
  BackendErrorNotice,
  Card,
  DetailsSection,
  Field,
  HashValue,
  Notice,
  Pill,
} from "../components/ui";
import { aggregateStateText } from "../voterWorkflow";

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
  const [anchorEvidencePath, setAnchorEvidencePath] = useState("");
  const [transportAnchor, setTransportAnchor] = useState<GuiTransportAnchorVerificationV1 | null>(null);
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

  const onPickDirectory = async () => {
    const picked = await pickDirectory("Choose archive directory");
    if (picked !== null) setDirectory(picked);
  };

  const onPickAnchorEvidence = async () => {
    const picked = await pickCborFile("Choose anchor evidence file");
    if (picked !== null) setAnchorEvidencePath(picked);
  };

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

  const onVerifyTransportAnchor = async () => {
    setError(null);
    setRunning(true);
    try {
      const verification = await api.verifyTransportArchiveAnchor(directory, anchorEvidencePath);
      setTransportAnchor(verification);
      recordAction(`Transport archive anchor is ${verification.state}`);
    } catch (err) {
      setTransportAnchor(null);
      showError(err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <h1 className="screen-header">Archive</h1>
      <p className="screen-lede">
        Archive verification independently checks the saved election record: it rechecks the
        accepted ballots, rebuilds the tally, and confirms that the files agree with the
        election data. Anyone with the archive folder can run this check.
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
          <div className="file-row">
            <input
              id="archive-path"
              type="text"
              value={directory}
              onChange={(e) => setDirectory(e.target.value)}
              placeholder="path to an archive directory"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable || running}
              onClick={() => void onPickDirectory()}
            >
              Browse
            </button>
          </div>
          <span className="form-hint">
            The folder saved when the election record was written. Technical details: it must
            contain election-manifest.cbor, candidate-set.cbor, voter-registry.cbor,
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
        {shellAvailable && !directory && (
          <p className="form-hint">Choose an archive directory to continue.</p>
        )}
      </Card>

      <Card title="Check final anchor record">
        <p className="form-hint">
          If this election was optionally anchored on Ootle, you can check here whether the
          saved anchor record matches this archive. This check is informational only and does
          not change the election result.
        </p>
        <DetailsSection summary="Technical details">
          <p className="form-hint">
            Verifies an existing finalized Phase 4 evidence record against this completed
            archive. Submitted or unverified anchors remain INCLUDED, not ANCHORED; this
            does not imply a voter transaction exists.
          </p>
        </DetailsSection>
        <div className="form-row">
          <label htmlFor="transport-anchor-evidence">Anchor evidence file</label>
          <div className="file-row">
            <input
              id="transport-anchor-evidence"
              type="text"
              value={anchorEvidencePath}
              onChange={(e) => setAnchorEvidencePath(e.target.value)}
              placeholder="anchor-evidence.cbor"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable || running}
              onClick={() => void onPickAnchorEvidence()}
            >
              Browse
            </button>
          </div>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!shellAvailable || !directory || !anchorEvidencePath || running}
            onClick={() => void onVerifyTransportAnchor()}
          >
            Check final anchor record
          </button>
        </div>
        {shellAvailable && (!directory || !anchorEvidencePath) && (
          <p className="form-hint">
            Choose an archive directory and an anchor evidence file to continue.
          </p>
        )}
        {transportAnchor && (
          <div className="field-list">
            <Field label="Transport state">
              <Pill tone={transportAnchor.state === "ANCHORED" ? "ok" : "neutral"}>
                {transportAnchor.state}
              </Pill>
            </Field>
            <Field label="Archive finality">
              {transportAnchor.archive_finalized ? "finalized" : "not finalized"}
            </Field>
            <Field label="Meaning">{aggregateStateText(transportAnchor.state)}</Field>
            <Field label="Archive binding">{transportAnchor.transport_binding_verified ? "verified" : "not verified"}</Field>
            <Field label="Phase 4 anchor">{transportAnchor.anchor_verified ? "verified" : "not verified"}</Field>
          </div>
        )}
      </Card>

      {result && (
        <>
          <Card title="Result at a glance">
            <div className="field-list">
              <Field label="Archive integrity">
                {result.verified ? (
                  <Pill tone="ok">Verified</Pill>
                ) : (
                  <Pill tone="error">Failed</Pill>
                )}
              </Field>
              <Field label="Election finality">
                {result.finalized ? (
                  <Pill tone="ok">Finalized election verified</Pill>
                ) : (
                  <Pill tone="warn">Intermediate archive - not finalized</Pill>
                )}
              </Field>
              <Field label="Accepted ballots">{result.accepted_count}</Field>
              <Field label="Rejected ballots">{result.rejected_count}</Field>
              <Field label="Archive hash">
                {result.archive_hash_consistent ? "Matches" : "Mismatch"}
              </Field>
              <Field label="Recomputed result">
                {result.tally ? "tally recomputed" : "not available"}
              </Field>
            </div>
            <p className="form-hint">
              Rejected ballots are valid audit evidence — for example, the same ballot imported
              twice — and are never hidden. Raw hashes, machine IDs, and component-level detail
              are in the sections below.
            </p>
            {result.finalized ? (
              <p className="form-hint">
                This archive verifies as a finalized election archive. Optional Ootle anchoring,
                when present, is aggregate evidence over the archive commitment.
              </p>
            ) : (
              <p className="form-hint">
                This archive may verify internally, but it is an intermediate archive, not a
                finalized election archive, and is not eligible for live Ootle anchoring.
              </p>
            )}
          </Card>

          <Card title="Verification status">
            <div className="field-list">
              {result.failure_stage && (
                <Field label="First failing stage">{result.failure_stage}</Field>
              )}
              {result.failure_code && <Field label="Failure code">{result.failure_code}</Field>}
              <Field label="Transcript complete">
                {result.transcript_complete ? "yes" : "no"}
              </Field>
              <Field label="Catalog files checked">{result.file_count}</Field>
            </div>
          </Card>

          <Card title="Governance source">
            <p className="card-body">
              Archive integrity proves the catalog digests match the bytes on disk; it does not
              by itself prove the archived governance document matches the bound
              governance source pin. The fact below is a distinct, separate check.
            </p>
            <div className="field-list">
              <Field label="Governance supporting document">
                {result.files.some(
                  (f) => f.path === "governance/source.bin" && f.present,
                ) ? (
                  <Pill tone="ok">Present</Pill>
                ) : (
                  <Pill tone="neutral">Absent</Pill>
                )}
              </Field>
              <Field label="Governance source pin">
                {(() => {
                  const fact = result.governance_source_matches_pin;
                  switch (fact) {
                    case "Matched":
                      return <Pill tone="ok">Matched</Pill>;
                    case "Mismatch":
                      return <Pill tone="error">Mismatch</Pill>;
                    case "Missing":
                      return <Pill tone="error">Missing</Pill>;
                    case "OperatorAttested":
                      return <Pill tone="warn">Operator-attested</Pill>;
                    case "NotApplicable":
                    default:
                      return <Pill tone="neutral">Not applicable</Pill>;
                  }
                })()}
              </Field>
              {result.governance_source_matches_pin === "OperatorAttested" && (
                <Field label="Note">
                  <span className="field-value">
                    Git reference correspondence is not independently verified by this
                    application; it is operator-attested.
                  </span>
                </Field>
              )}
              {result.governance_source_matches_pin === "NotApplicable" && (
                <Field label="Note">
                  <span className="field-value">
                    Bound reference is not a recognized immutable pin format; the
                    governance-source cross-check does not apply.
                  </span>
                </Field>
              )}
            </div>
          </Card>

          <Card title="Transport archive binding">
            <p className="card-body">
              A verified binding is a hash-covered archive constituent. It is not, by itself,
              proof that an Ootle anchor was finalized.
            </p>
            <div className="field-list">
              <Field label="Binding">
                {result.transport_binding_present ? (
                  <Pill tone={result.transport_binding_verified ? "ok" : "error"}>
                    {result.transport_binding_verified ? "Verified" : "Invalid"}
                  </Pill>
                ) : (
                  <Pill tone="neutral">Not present</Pill>
                )}
              </Field>
              {result.transport_batch_set_commitment_hex && (
                <Field label="Final batch-set commitment">
                  <HashValue value={result.transport_batch_set_commitment_hex} />
                </Field>
              )}
              {result.transport_accepted_count !== null && (
                <Field label="Transport accepted count">
                  {result.transport_accepted_count}
                </Field>
              )}
              {result.transport_reduced_anonymity !== null && (
                <Field label="Reduced anonymity">
                  {result.transport_reduced_anonymity ? "reported" : "not reported"}
                </Field>
              )}
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
              missing and unexpected files both fail verification. Canonical election artifacts
              (manifest, registry, candidate-set) are distinct from the governance supporting
              document, if present.
            </p>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">Role</th>
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
                    <td>{archiveFileRole(file.path)}</td>
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

/** Classifies one archive content file as a canonical election artifact or a
 *  governance supporting document (Slice 5A8). The governance document is
 *  supporting evidence, not a fourth canonical election artifact. */
function archiveFileRole(path: string): string {
  switch (path) {
    case "election-manifest.cbor":
    case "voter-registry.cbor":
    case "candidate-set.cbor":
      return "Canonical election artifact";
    case "governance/source.bin":
      return "Governance supporting document";
    default:
      return path.startsWith("submissions/") ? "Ballot package" : "Content file";
  }
}
