import { useCallback, useEffect, useState } from "react";

import { api, BackendError } from "../api/client";
import { pickCborFile, pickV2AnchorEvidenceJson } from "../api/dialog";
import { boundArchiveResult } from "../archive/archiveBinding";
import type {
  GuiAnchorEvidenceInspectionV1,
  GuiCommandError,
  GuiLiveAnchorV2ResultV1,
  GuiV2AnchorEvidenceFileV1,
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

/**
 * Evidence: read-only inspector for the current V2 public-anchor evidence
 * produced for the currently verified election archive, plus a legacy V1
 * inspection surface retained under Advanced.
 *
 * Normal path (current V2): auto-discover the `*.v2-anchor-evidence.json`
 * sidecar the app wrote beside the verified archive, cryptographically
 * re-verify the canonical public summary against the archive
 * (`verify_v2_public_anchor_evidence`), and present the evidence together
 * with the archive/anchor bindings it certifies. No JavaScript-side
 * verifier exists; the Rust helpers already used by the anchor lifecycle
 * are the authority.
 *
 * On-chain receipt state is NEVER re-verified from this screen. When the
 * persisted lifecycle records `RECEIPT_VERIFIED` we display "Previously
 * verified"; we do not claim a fresh on-chain verification the code did not
 * actually run.
 *
 * Advanced: manual V2 JSON file selection (cross-checked against the loaded
 * verified archive) and historical V1 CBOR inspection.
 */
export function Evidence({
  onNavigate,
}: { onNavigate?: (section: NavSection) => void } = {}) {
  const { shellAvailable, recordAction, archiveView } = useAppState();
  const verifiedArchive = boundArchiveResult(
    archiveView.verification,
    archiveView.directory,
  );
  const archiveDirectory = archiveView.directory;

  const [v2AnchorState, setV2AnchorState] =
    useState<GuiV2LiveAnchorHydratedStateV1 | null>(null);
  const [v2Inspection, setV2Inspection] =
    useState<GuiLiveAnchorV2ResultV1 | null>(null);
  const [v2Error, setV2Error] = useState<GuiCommandError | null>(null);
  const [v2Loading, setV2Loading] = useState(false);

  const [manualPath, setManualPath] = useState("");
  const [manualEvidence, setManualEvidence] =
    useState<GuiV2AnchorEvidenceFileV1 | null>(null);
  const [manualInspection, setManualInspection] =
    useState<GuiLiveAnchorV2ResultV1 | null>(null);
  const [manualError, setManualError] = useState<GuiCommandError | null>(null);

  const [legacyPath, setLegacyPath] = useState("");
  const [legacyEvidence, setLegacyEvidence] =
    useState<GuiAnchorEvidenceInspectionV1 | null>(null);
  const [legacyError, setLegacyError] = useState<GuiCommandError | null>(null);

  const asCommandError = (err: unknown): GuiCommandError =>
    err instanceof BackendError
      ? err.payload
      : {
          code: "GUI_UNEXPECTED_ERROR",
          category: "INVALID_INPUT",
          context: null,
          message: "an unexpected frontend/backend boundary error occurred",
        };

  // Reset auto-discovered state when the archive changes.
  useEffect(() => {
    setV2AnchorState(null);
    setV2Inspection(null);
    setV2Error(null);
    setV2Loading(false);
  }, [archiveDirectory]);

  const verifyHydrated = useCallback(
    async (
      submittedDirectory: string,
      hydrated: GuiV2LiveAnchorHydratedStateV1,
    ): Promise<GuiLiveAnchorV2ResultV1 | null> => {
      if (!hydrated.evidence_present) return null;
      if (!hydrated.payload_hex || !hydrated.expected_digest_hex) return null;
      try {
        const result = await api.verifyV2PublicAnchorEvidence(
          submittedDirectory,
          hydrated.payload_hex,
          hydrated.expected_digest_hex,
        );
        return result;
      } catch (err) {
        setV2Error(asCommandError(err));
        return null;
      }
    },
    [],
  );

  // Auto-discover + verify V2 evidence for the currently verified archive.
  useEffect(() => {
    if (!shellAvailable) return;
    if (!verifiedArchive || !verifiedArchive.verified) return;
    const submittedDirectory = archiveDirectory;
    let cancelled = false;
    setV2Loading(true);
    void (async () => {
      try {
        const hydrated = await api.inspectV2LiveAnchorState(submittedDirectory);
        if (cancelled) return;
        setV2AnchorState(hydrated);
        if (hydrated.evidence_present) {
          const result = await verifyHydrated(submittedDirectory, hydrated);
          if (cancelled) return;
          setV2Inspection(result);
        }
      } catch (err) {
        if (cancelled) return;
        setV2Error(asCommandError(err));
        setV2AnchorState(null);
        setV2Inspection(null);
      } finally {
        if (!cancelled) setV2Loading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [archiveDirectory, verifiedArchive, shellAvailable, verifyHydrated]);

  const onPickManualJson = async () => {
    const picked = await pickV2AnchorEvidenceJson();
    if (picked !== null) setManualPath(picked);
  };

  const onInspectManualJson = async () => {
    setManualError(null);
    setManualInspection(null);
    setManualEvidence(null);
    try {
      const parsed = await api.readV2PublicAnchorEvidenceFile(manualPath);
      setManualEvidence(parsed);
      // Cross-check against the currently verified archive when one is
      // available: this proves the evidence file is bound to the archive the
      // operator is looking at. When no verified archive is loaded, or when
      // the JSON references a different directory, we display the parsed
      // record but do not claim cryptographic archive binding.
      const boundedDirectory =
        verifiedArchive && verifiedArchive.verified ? archiveDirectory : null;
      if (
        boundedDirectory !== null &&
        parsed.archive_directory === boundedDirectory
      ) {
        const result = await api.verifyV2PublicAnchorEvidence(
          boundedDirectory,
          parsed.payload_hex,
          parsed.anchor_digest_hex,
        );
        setManualInspection(result);
        recordAction("Inspected V2 anchor evidence (manual · verified)");
      } else {
        recordAction("Inspected V2 anchor evidence (manual · schema only)");
      }
    } catch (err) {
      setManualError(asCommandError(err));
    }
  };

  const onPickLegacyEvidence = async () => {
    const picked = await pickCborFile("Choose anchor evidence file");
    if (picked !== null) setLegacyPath(picked);
  };

  const onInspectLegacy = async () => {
    setLegacyError(null);
    try {
      const inspection = await api.inspectAnchorEvidence(legacyPath);
      setLegacyEvidence(inspection);
      recordAction(`Inspected legacy V1 anchor evidence (${inspection.final_status})`);
    } catch (err) {
      setLegacyEvidence(null);
      setLegacyError(asCommandError(err));
    }
  };

  const digestsAgree = (a: string | null | undefined, b: string | null | undefined) =>
    Boolean(a) && Boolean(b) && a!.toLowerCase() === b!.toLowerCase();

  const bindingsAgree = (
    hydrated: GuiV2LiveAnchorHydratedStateV1,
    result: GuiLiveAnchorV2ResultV1,
  ) =>
    hydrated.template_address === result.template_address &&
    hydrated.template_module === result.template_module &&
    hydrated.template_function === result.template_function &&
    hydrated.template_topic === result.template_event_topic &&
    (hydrated.template_artifact_digest_hex ?? "").toLowerCase() ===
      result.template_artifact_digest_hex.toLowerCase();

  return (
    <>
      <h1 className="screen-header">Evidence</h1>
      <p className="screen-lede">
        Review the saved evidence that links this election archive to its Ootle anchor record.
        This evidence does not determine or change the election result.
      </p>

      <DetailsSection summary="Technical details">
        <p className="card-body">
          V2 anchor evidence binds the election archive hash, canonical public summary bytes,
          anchor digest, event-template binding, transaction id, and network into one
          JSON record beside the verified archive. Verification recomputes the digest and
          replays the canonical payload from the archive; the archive itself remains the
          authoritative record of the election outcome.
        </p>
      </DetailsSection>

      {!shellAvailable && (
        <Notice tone="info">Browser preview: inspection requires the desktop shell.</Notice>
      )}
      <BackendErrorNotice error={v2Error} onDismiss={() => setV2Error(null)} />

      {!verifiedArchive || !verifiedArchive.verified ? (
        <Card title="Verify a final archive first">
          <p className="card-body">
            Open Archive and independently verify the election record before inspecting its
            V2 anchor evidence. Nothing on this screen contacts the network, but evidence is
            scoped to a verified archive.
          </p>
          <p className="form-hint">
            Choose an evidence file to continue.
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
        <Card title="V2 anchor evidence">
          {v2Loading && !v2AnchorState && (
            <p className="form-hint">Reading V2 evidence for this archive…</p>
          )}

          {!v2Loading && v2AnchorState && !v2AnchorState.evidence_present && (
            <>
              <p className="card-body">
                <strong>No V2 anchor evidence found for this archive.</strong>
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

          {v2AnchorState && v2AnchorState.evidence_present && v2Inspection && (
            <>
              <div className="field-list">
                <Field label="Evidence file">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Election">
                  {v2Inspection.election_id}
                </Field>
                {verifiedArchive.proposal_question && (
                  <Field label="Ballot question">
                    <span className="field-value">{verifiedArchive.proposal_question}</span>
                  </Field>
                )}
                <Field label="Archive">
                  <Pill tone="ok">Matches</Pill>
                </Field>
                <Field label="Archive hash">
                  <HashValue value={v2Inspection.archive_hash_hex} />
                  <CopyButton value={v2Inspection.archive_hash_hex} />
                </Field>
                <Field label="Canonical public summary">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Anchor digest">
                  <Pill tone="ok">Verified</Pill>
                </Field>
                <Field label="Anchor digest (raw)">
                  <HashValue value={v2Inspection.v2_anchor_digest_hex} />
                  <CopyButton value={v2Inspection.v2_anchor_digest_hex} />
                </Field>
                <Field label="Template binding">
                  {v2AnchorState.template_address &&
                  bindingsAgree(v2AnchorState, v2Inspection) ? (
                    <Pill tone="ok">Verified</Pill>
                  ) : (
                    <Pill tone="warn">Not cross-checked</Pill>
                  )}
                </Field>
                <Field label="Transaction">
                  {v2AnchorState.transaction_id ? (
                    <>
                      <span className="hash">{v2AnchorState.transaction_id}</span>
                      <CopyButton value={v2AnchorState.transaction_id} />
                    </>
                  ) : (
                    "none"
                  )}
                </Field>
                <Field label="Network">{v2Inspection.network}</Field>
                <Field label="Eligible voters">
                  {v2Inspection.eligible_voter_count.toLocaleString()}
                </Field>
                <Field label="Accepted ballots">
                  {v2Inspection.accepted_ballot_count.toLocaleString()}
                </Field>
                <Field label="Rejected ballots">
                  {v2Inspection.rejected_ballot_count.toLocaleString()}
                </Field>
                <Field label="Ballot kind">{v2Inspection.ballot_kind}</Field>
                <Field label="Confidentiality mode">
                  {v2Inspection.confidentiality_mode}
                </Field>
                <Field label="Receipt status">
                  {v2AnchorState.receipt_verified ? (
                    <>
                      <Pill tone="ok">Previously verified</Pill>{" "}
                      <span className="form-hint">
                        (from persisted lifecycle; not re-fetched from the indexer)
                      </span>
                    </>
                  ) : (
                    <Pill tone="warn">Not verified in this session</Pill>
                  )}
                </Field>
                <Field label="Evidence path">
                  <span className="hash">{v2AnchorState.evidence_path}</span>
                  <CopyButton value={v2AnchorState.evidence_path} />
                </Field>
              </div>

              <h3>Tally</h3>
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Option</th>
                    <th scope="col">Machine id</th>
                    <th scope="col">Votes</th>
                  </tr>
                </thead>
                <tbody>
                  {v2Inspection.tally.map((row) => (
                    <tr key={row.machine_id_hex}>
                      <td>{row.display_label}</td>
                      <td>
                        <span className="hash">{row.machine_id_hex}</span>
                      </td>
                      <td>{row.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <h3>Readable public summary</h3>
              <pre className="hash" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                {formatPublicSummary(v2Inspection.public_summary_json)}
              </pre>

              <div className="action-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate?.("anchor")}
                  disabled={!onNavigate}
                >
                  Open Anchor
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate?.("archive")}
                  disabled={!onNavigate}
                >
                  Open Archive
                </button>
              </div>

              <DetailsSection summary="Technical details">
                <div className="field-list">
                  <Field label="Evidence schema">
                    <span className="hash">TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V1</span>
                  </Field>
                  {v2AnchorState.template_address && (
                    <Field label="Template address">
                      <span className="hash">{v2AnchorState.template_address}</span>
                    </Field>
                  )}
                  {v2AnchorState.template_module && (
                    <Field label="Template module">{v2AnchorState.template_module}</Field>
                  )}
                  {v2AnchorState.template_function && (
                    <Field label="Template function">{v2AnchorState.template_function}</Field>
                  )}
                  {v2AnchorState.template_topic && (
                    <Field label="Canonical event topic">
                      <span className="hash">{v2AnchorState.template_topic}</span>
                    </Field>
                  )}
                  {v2AnchorState.template_artifact_digest_hex && (
                    <Field label="Template artifact digest">
                      <HashValue value={v2AnchorState.template_artifact_digest_hex} />
                    </Field>
                  )}
                  <Field label="Manifest hash">
                    <HashValue value={v2Inspection.manifest_hash_hex} />
                  </Field>
                  <Field label="Voter registry commitment">
                    <HashValue value={v2Inspection.registry_commitment_hex} />
                  </Field>
                  <Field label="Ballot option commitment">
                    <HashValue value={v2Inspection.option_set_commitment_hex} />
                  </Field>
                  <Field label="Archive finalized">
                    {v2Inspection.archive_finalized ? "yes" : "no"}
                  </Field>
                  <Field label="Proof suite">{v2Inspection.proof_suite}</Field>
                  <Field label="Canonical payload (hex)">
                    <span className="hash">
                      {truncateHex(v2AnchorState.payload_hex ?? "—")}
                    </span>
                  </Field>
                  <Field label="Digest agreement">
                    {digestsAgree(
                      v2AnchorState.expected_digest_hex,
                      v2Inspection.v2_anchor_digest_hex,
                    )
                      ? "hydrated digest matches recomputed digest"
                      : "digest mismatch"}
                  </Field>
                </div>
              </DetailsSection>
            </>
          )}

          {v2AnchorState &&
            v2AnchorState.evidence_present &&
            !v2Inspection &&
            !v2Loading && (
              <Notice tone="error">
                <strong>V2 evidence failed verification.</strong> The evidence file exists
                beside this archive but did not verify against it. See the technical details
                notice above for the specific check that failed.
              </Notice>
            )}
        </Card>
      )}

      <DetailsSection summary="Advanced: load V2 evidence from another location">
        <Card title="Manual V2 evidence (*.v2-anchor-evidence.json)">
          <p className="form-hint">
            For copied evidence, independent verification, or evidence stored elsewhere.
            Cross-checks against the currently verified archive when one is loaded and its
            path matches the file's archive_directory. Reading and validation happen in the
            Rust shell.
          </p>
          <BackendErrorNotice error={manualError} onDismiss={() => setManualError(null)} />
          <div className="form-row">
            <label htmlFor="manual-v2-evidence-path">V2 evidence file path</label>
            <div className="file-row">
              <input
                id="manual-v2-evidence-path"
                type="text"
                value={manualPath}
                onChange={(e) => setManualPath(e.target.value)}
                placeholder="election.v2-anchor-evidence.json"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable}
                onClick={() => void onPickManualJson()}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!shellAvailable || !manualPath}
              onClick={() => void onInspectManualJson()}
            >
              Inspect V2 evidence file
            </button>
          </div>
          {shellAvailable && !manualPath && (
            <p className="form-hint">Choose a V2 evidence file to continue.</p>
          )}

          {manualEvidence && (
            <div className="field-list">
              <Field label="Schema">
                <span className="hash">{manualEvidence.schema}</span>
              </Field>
              <Field label="Archive directory (as declared in the file)">
                <span className="hash">{manualEvidence.archive_directory}</span>
              </Field>
              <Field label="Transaction">
                <span className="hash">{manualEvidence.transaction_id}</span>
                <CopyButton value={manualEvidence.transaction_id} />
              </Field>
              <Field label="Network">{manualEvidence.network}</Field>
              <Field label="Template address">
                <span className="hash">{manualEvidence.template_address}</span>
              </Field>
              <Field label="Template module">{manualEvidence.template_module}</Field>
              <Field label="Template function">{manualEvidence.template_function}</Field>
              <Field label="Canonical event topic">
                <span className="hash">{manualEvidence.template_topic}</span>
              </Field>
              <Field label="Template artifact digest">
                <HashValue value={manualEvidence.template_artifact_digest_hex} />
              </Field>
              <Field label="Anchor digest">
                <HashValue value={manualEvidence.anchor_digest_hex} />
                <CopyButton value={manualEvidence.anchor_digest_hex} />
              </Field>
              <Field label="Cryptographic archive binding">
                {manualInspection ? (
                  <Pill tone="ok">Verified against loaded archive</Pill>
                ) : verifiedArchive && verifiedArchive.verified ? (
                  <Pill tone="warn">
                    Not cross-checked (file's archive_directory ≠ loaded archive)
                  </Pill>
                ) : (
                  <Pill tone="warn">
                    Not cross-checked (no verified archive loaded)
                  </Pill>
                )}
              </Field>
            </div>
          )}
        </Card>
      </DetailsSection>

      <DetailsSection summary="Legacy V1 evidence verification (historical)">
        <p className="form-hint">
          Retained for historical V1 evidence. Current V2 anchors use
          <code> *.v2-anchor-evidence.json </code>
          files; the picker below still accepts the older CBOR format so historical
          <code> anchor-evidence.cbor </code>
          files remain inspectable.
        </p>
        <Card title="Legacy V1 anchor evidence (anchor-evidence.cbor)">
          <BackendErrorNotice error={legacyError} onDismiss={() => setLegacyError(null)} />
          <div className="form-row">
            <label htmlFor="legacy-evidence-path">Legacy evidence file path</label>
            <div className="file-row">
              <input
                id="legacy-evidence-path"
                type="text"
                value={legacyPath}
                onChange={(e) => setLegacyPath(e.target.value)}
                placeholder="anchor-evidence.cbor"
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!shellAvailable}
                onClick={() => void onPickLegacyEvidence()}
              >
                Browse
              </button>
            </div>
          </div>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable || !legacyPath}
              onClick={() => void onInspectLegacy()}
            >
              Inspect legacy evidence
            </button>
          </div>
          {legacyEvidence && (
            <>
              <div className="field-list">
                <Field label="Final status">
                  <Pill tone={legacyEvidence.final_status.includes("ACCEPT") ? "ok" : "warn"}>
                    {legacyEvidence.final_status}
                  </Pill>
                </Field>
                <Field label="Receipt source">{legacyEvidence.receipt_source}</Field>
                <Field label="Phase">{legacyEvidence.phase}</Field>
                <Field label="Network">{legacyEvidence.network}</Field>
                <Field label="Record digest">
                  <HashValue value={legacyEvidence.record_digest_hex} />
                </Field>
                <Field label="Manifest hash">
                  <HashValue value={legacyEvidence.manifest_hash_hex} />
                </Field>
                <Field label="Archive hash">
                  <HashValue value={legacyEvidence.archive_hash_hex} />
                </Field>
                <Field label="Anchor digest">
                  <HashValue value={legacyEvidence.anchor_digest_hex} />
                </Field>
                <Field label="Transaction">{legacyEvidence.transaction_id ?? "none"}</Field>
                <Field label="Ledger position">
                  {legacyEvidence.ledger_position !== null
                    ? legacyEvidence.ledger_position
                    : "none"}
                </Field>
                <Field label="Snapshot digest">
                  <HashValue value={legacyEvidence.snapshot_digest_hex} />
                </Field>
              </div>
              <h4>Human review summary</h4>
              <p className="card-body">{legacyEvidence.human_review_summary}</p>
            </>
          )}
        </Card>
      </DetailsSection>

      <Notice tone="warn">
        Anchor evidence is a non-binding record of the archive commitment. Election outcomes
        come from the independently verified election archive.
      </Notice>
    </>
  );
}

/** Pretty-prints the canonical `public_summary` JSON for READ ONLY display.
 *  The canonical bytes for hashing are `public_summary_json` verbatim; any
 *  digest recomputation happens in Rust from the exact hex bytes, never from
 *  the pretty form. Falls back to the raw string if parsing fails. */
function formatPublicSummary(raw: string): string {
  try {
    const parsed = JSON.parse(raw);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return raw;
  }
}

/** Truncates a long hex string for a summary readout, showing the head and
 *  tail. Displays the full length in characters so operators can spot short
 *  or truncated payloads. */
function truncateHex(hex: string): string {
  const total = hex.length;
  if (total <= 96) return hex;
  return `${hex.slice(0, 48)}…${hex.slice(-24)} (${total} chars)`;
}
