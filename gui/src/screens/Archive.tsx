import { useEffect, useRef, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickCborFile, pickDirectory } from "../api/dialog";
import { rememberDirectory } from "../api/directoryMemory";
import {
  archiveResultIsStale,
  boundArchiveResult,
  boundTransportAnchorResult,
  transportAnchorResultIsStale,
} from "../archive/archiveBinding";
import type {
  GuiCommandError,
  GuiV2LiveAnchorHydratedStateV1,
} from "../api/types";
import { useAppState } from "../state/AppState";
import type { NavSection } from "../components/AppFrame";
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
import { aggregateStateText } from "../voterWorkflow";
import {
  summarizeV2AnchorState,
  v2AnchorBadgeLabel,
  v2AnchorBadgeTone,
} from "../anchor/v2AnchorStatus";

/**
 * Archive: full offline replay verification of an archive directory through
 * the gui-core verifier, plus a compact result summary and the current V2
 * anchor status (hydrated read-only from the app-owned sidecars). The offline
 * archive is authoritative; the V2 anchor status is optional and never
 * modified from this screen.
 */
export function Archive({
  onNavigate,
}: { onNavigate?: (section: NavSection) => void } = {}) {
  const { shellAvailable, recordAction, archiveView, updateArchiveView } = useAppState();
  const directory = archiveView.directory;
  const anchorEvidencePath = archiveView.anchorEvidencePath;

  const result = boundArchiveResult(archiveView.verification, directory);
  const transportAnchor = boundTransportAnchorResult(
    archiveView.transportAnchor,
    directory,
    anchorEvidencePath,
  );

  const setDirectory = (value: string) =>
    updateArchiveView({ directory: value, verification: null, transportAnchor: null });
  const setAnchorEvidencePath = (value: string) =>
    updateArchiveView({ anchorEvidencePath: value, transportAnchor: null });

  const [error, setError] = useState<GuiCommandError | null>(null);
  const [running, setRunning] = useState(false);
  // Hydrated V2 anchor state for the CURRENTLY verified directory, refreshed
  // whenever the directory changes or a verification completes. Never contacts
  // walletd or the indexer — inspect_v2_live_anchor_state only reads app-owned
  // sidecars. Stored per-directory so a stale response is discarded on switch.
  const [v2AnchorState, setV2AnchorState] =
    useState<GuiV2LiveAnchorHydratedStateV1 | null>(null);
  const [v2InspectionError, setV2InspectionError] = useState<GuiCommandError | null>(null);

  const currentInputsRef = useRef({ directory, anchorEvidencePath });
  currentInputsRef.current = { directory, anchorEvidencePath };

  const unverifiedRemembered = directory !== "" && result === null;

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

  const onPickDirectory = async () => {
    const picked = await pickDirectory("Choose archive directory", "archive");
    if (picked !== null) setDirectory(picked);
  };

  const onPickAnchorEvidence = async () => {
    const picked = await pickCborFile("Choose anchor evidence file");
    if (picked !== null) setAnchorEvidencePath(picked);
  };

  // Reset V2 state whenever the directory changes (including verification
  // reset). The next successful verify (or manual refresh) re-hydrates it.
  useEffect(() => {
    setV2AnchorState(null);
    setV2InspectionError(null);
  }, [directory]);

  // Re-hydrate V2 anchor state whenever a verified archive is loaded. This is
  // a strictly read-only projection of app-owned sidecars — never network.
  useEffect(() => {
    if (!shellAvailable) return;
    if (!result || !result.verified) return;
    const submittedDirectory = directory;
    let cancelled = false;
    void (async () => {
      try {
        const hydrated = await api.inspectV2LiveAnchorState(submittedDirectory);
        if (cancelled) return;
        if (submittedDirectory !== currentInputsRef.current.directory) return;
        setV2AnchorState(hydrated);
      } catch (err) {
        if (cancelled) return;
        if (submittedDirectory !== currentInputsRef.current.directory) return;
        setV2InspectionError(commandError(err));
        setV2AnchorState(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [directory, result, shellAvailable]);

  const onVerify = async () => {
    const submittedDirectory = directory;
    setError(null);
    setRunning(true);
    try {
      const verification = await api.verifyArchive(submittedDirectory);
      if (archiveResultIsStale(submittedDirectory, currentInputsRef.current.directory)) return;
      updateArchiveView({
        verification: { result: verification, verifiedDirectory: submittedDirectory },
      });
      rememberDirectory("archive", submittedDirectory);
      recordAction(
        verification.verified ? "Archive verification passed" : "Archive verification failed",
      );
    } catch (err) {
      if (!archiveResultIsStale(submittedDirectory, currentInputsRef.current.directory)) {
        updateArchiveView({ verification: null });
        showError(err);
      }
    } finally {
      setRunning(false);
    }
  };

  const onVerifyTransportAnchor = async () => {
    const submitted = { archiveDirectory: directory, evidencePath: anchorEvidencePath };
    setError(null);
    setRunning(true);
    try {
      const verification = await api.verifyTransportArchiveAnchor(
        submitted.archiveDirectory,
        submitted.evidencePath,
      );
      const current = {
        archiveDirectory: currentInputsRef.current.directory,
        evidencePath: currentInputsRef.current.anchorEvidencePath,
      };
      if (transportAnchorResultIsStale(submitted, current)) return;
      updateArchiveView({
        transportAnchor: {
          result: verification,
          checkedArchiveDirectory: submitted.archiveDirectory,
          checkedEvidencePath: submitted.evidencePath,
        },
      });
      recordAction(`Transport archive anchor is ${verification.state}`);
    } catch (err) {
      const current = {
        archiveDirectory: currentInputsRef.current.directory,
        evidencePath: currentInputsRef.current.anchorEvidencePath,
      };
      if (!transportAnchorResultIsStale(submitted, current)) {
        updateArchiveView({ transportAnchor: null });
        showError(err);
      }
    } finally {
      setRunning(false);
    }
  };

  const v2Summary = summarizeV2AnchorState(v2AnchorState);

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
        {shellAvailable && unverifiedRemembered && (
          <Notice tone="info">
            This archive location is remembered from an earlier selection. Its integrity is not
            confirmed until you run Verify archive in this session — a remembered location is
            never treated as proof that the archive still verifies.
          </Notice>
        )}
      </Card>

      {result && (
        <>
          {result.verified ? (
            <Card title="Archive verified">
              <Notice tone="ok">
                <strong>ARCHIVE VERIFIED.</strong>{" "}
                {result.finalized
                  ? "Finalized election verified."
                  : "Intermediate archive verified (not yet finalized)."}
              </Notice>
              <div className="field-list">
                {result.proposal_question && (
                  <Field label="Ballot question">
                    <span className="field-value">{result.proposal_question}</span>
                  </Field>
                )}
                <Field label="Accepted ballots">{result.accepted_count}</Field>
                <Field label="Rejected ballots">{result.rejected_count}</Field>
                <Field label="Archive hash">
                  {result.archive_hash_consistent ? (
                    <Pill tone="ok">Matches</Pill>
                  ) : (
                    <Pill tone="error">Mismatch</Pill>
                  )}
                </Field>
                <Field label="Tally">
                  {result.tally ? (
                    <Pill tone="ok">Recomputed successfully</Pill>
                  ) : (
                    <Pill tone="neutral">Not available</Pill>
                  )}
                </Field>
                <Field label="Files verified">{result.file_count}</Field>
              </div>
              <p className="form-hint">
                The saved election record passed independent verification. Its expected files,
                integrity hashes, eligible-voter registry, accepted ballots, and recomputed
                result are internally consistent. Rejected ballots (e.g. duplicate imports) are
                audit evidence and are never hidden.
              </p>
            </Card>
          ) : (
            <Card title="Archive verification failed">
              <Notice tone="error">
                <strong>ARCHIVE VERIFICATION FAILED.</strong> Failure details below are not
                collapsed; do not treat this archive as verified.
              </Notice>
              <div className="field-list">
                {result.failure_stage && (
                  <Field label="First failing stage">{result.failure_stage}</Field>
                )}
                {result.failure_code && (
                  <Field label="Failure code">{result.failure_code}</Field>
                )}
                <Field label="Accepted ballots">{result.accepted_count}</Field>
                <Field label="Rejected ballots">{result.rejected_count}</Field>
                <Field label="Archive hash">
                  {result.archive_hash_consistent ? "Matches" : "Mismatch"}
                </Field>
                <Field label="Transcript complete">
                  {result.transcript_complete ? "yes" : "no"}
                </Field>
              </div>
              {result.files.some((f) => !f.present || !f.digest_ok) && (
                <>
                  <p className="card-body">Files that failed the catalog check:</p>
                  <table className="data">
                    <thead>
                      <tr>
                        <th scope="col">File</th>
                        <th scope="col">Present</th>
                        <th scope="col">Digest</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.files
                        .filter((file) => !file.present || !file.digest_ok)
                        .map((file) => (
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
                </>
              )}
            </Card>
          )}

          {result.verified && (
            <Card title="Ootle anchor">
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
                    {v2Summary.network && (
                      <Field label="Network">{v2Summary.network}</Field>
                    )}
                    <Field label="Evidence">
                      <span className="hash">{v2Summary.evidencePath}</span>
                      <CopyButton value={v2Summary.evidencePath} />
                    </Field>
                  </div>
                  <div className="action-row">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => onNavigate?.("anchor")}
                      disabled={!onNavigate}
                    >
                      Open Anchor screen
                    </button>
                  </div>
                </>
              )}
              {v2Summary &&
                (v2Summary.kind === "submitted-unverified" ||
                  v2Summary.kind === "recoverable") && (
                  <>
                    <Notice tone="warn">
                      <strong>Anchor submitted · verification pending.</strong> Verify the
                      existing anchor from Manage Election. Do not submit another transaction.
                    </Notice>
                    <div className="field-list">
                      {v2Summary.transactionId && (
                        <Field label="Transaction">
                          <span className="hash">{v2Summary.transactionId}</span>
                          <CopyButton value={v2Summary.transactionId} />
                        </Field>
                      )}
                      {v2Summary.network && (
                        <Field label="Network">{v2Summary.network}</Field>
                      )}
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
                        Open Manage Election
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
              {v2Summary && v2Summary.kind === "no-anchor" && (
                <>
                  <p className="card-body">
                    <strong>No Ootle anchor published.</strong>
                  </p>
                  <p className="form-hint">
                    Anchoring is optional and non-binding. This archive remains independently
                    verifiable and authoritative without an Ootle anchor.
                  </p>
                </>
              )}
            </Card>
          )}

          <DetailsSection summary="Advanced verification details">
            <Card title="Verification status">
              <div className="field-list">
                {result.failure_stage && (
                  <Field label="First failing stage">{result.failure_stage}</Field>
                )}
                {result.failure_code && (
                  <Field label="Failure code">{result.failure_code}</Field>
                )}
                <Field label="Transcript complete">
                  {result.transcript_complete ? "yes" : "no"}
                </Field>
                <Field label="Election finality">
                  {result.finalized ? "finalized" : "not finalized"}
                </Field>
                <Field label="Catalog files checked">{result.file_count}</Field>
              </div>
            </Card>

            <Card title="Governance source">
              <p className="card-body">
                Archive integrity proves the catalog digests match the bytes on disk; it does
                not by itself prove the archived governance document matches the bound
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
                  <Field label="Manifest schema">
                    {result.election_manifest_schema_version === null
                      ? "unknown"
                      : `ElectionManifestV${result.election_manifest_schema_version}`}
                  </Field>
                  {result.proposal_question && (
                    <Field label="Ballot question">{result.proposal_question}</Field>
                  )}
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
              <Card title="Recomputed tally — technical detail">
                <p className="card-body">
                  Includes machine identifiers for each ballot option. The default tally view
                  above summarizes just the response label and count.
                </p>
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
                missing and unexpected files both fail verification. Canonical election
                artifacts (manifest, registry, candidate-set) are distinct from the governance
                supporting document, if present.
              </p>
              <p className="form-hint">
                Files checked: {result.file_count} · Expected files:{" "}
                {result.files.every((f) => f.present) ? "present" : "some missing"} ·
                Digest checks:{" "}
                {result.files.every((f) => f.digest_ok) ? "all match" : "one or more mismatches"}
              </p>
              <DetailsSection summary={`Show verified file catalogue (${result.file_count})`}>
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
              </DetailsSection>
            </Card>

            {result.tally && (
              <Card title="Recomputed tally — summary">
                <p className="form-hint">
                  Default summary of the recomputed tally, without raw machine identifiers.
                </p>
                <ul className="option-list">
                  {result.tally.counts.map((count) => (
                    <li key={count.candidate_id_hex} className="option-item">
                      <span>{count.display_name || "—"}</span>
                      <span>— {count.approvals}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </DetailsSection>

          <DetailsSection summary="Legacy V1 verification">
            <Card title="Verify legacy V1 anchor evidence (anchor-evidence.cbor)">
              <p className="form-hint">
                Historical compatibility only. Current V2 anchor verification is shown above
                and reads app-owned JSON evidence sidecars automatically — you do not need to
                choose a file. This section remains for older archives whose anchor evidence
                was written as anchor-evidence.cbor.
              </p>
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
                  Check legacy V1 anchor record
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
                  <Field label="Meaning">
                    {aggregateStateText(transportAnchor.state)}
                  </Field>
                  <Field label="Archive binding">
                    {transportAnchor.transport_binding_verified ? "verified" : "not verified"}
                  </Field>
                  <Field label="Phase 4 anchor">
                    {transportAnchor.anchor_verified ? "verified" : "not verified"}
                  </Field>
                </div>
              )}
            </Card>
          </DetailsSection>
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
