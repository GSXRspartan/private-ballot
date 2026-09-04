/**
 * TypeScript mirrors of the gui-core view models (serde JSON projection).
 *
 * These types describe the exact serialized shape of the Rust DTOs returned
 * by the typed Tauri commands. Field names are the serde defaults (the Rust
 * field names). No protocol data crosses the boundary outside these bounded
 * view models, and none of them contains secret-bearing fields.
 */

export interface GuiCandidateSummaryV1 {
  machine_id_hex: string;
  machine_id_text: string | null;
  display_name: string;
}

export interface GuiElectionSummaryV1 {
  election_id_hex: string;
  election_id_text: string | null;
  lifecycle_state: string | null;
  manifest_schema_version: number;
  manifest_hash_hex: string;
  registry_commitment_hex: string;
  candidate_set_commitment_hex: string;
  voter_count: number;
  proof_suite_id: string;
  ballot_kind: string;
  ballot_confidentiality: string;
  approval_min: number;
  approval_max: number;
  abstention_allowed: boolean;
  governance_source_revision: string;
  proposal_question: string | null;
  candidates: GuiCandidateSummaryV1[];
}

export interface GuiElectionWorkspaceSummaryV1 {
  workspace_id: string;
  election_manifest_hash_hex: string | null;
  question_preview: string | null;
  lifecycle_state: string;
  /** Display-only, NON-AUTHORITATIVE count of ballot packages durably stored in
   *  this workspace revision. Derived without proof replay, so it counts every
   *  stored package (accepted, duplicate, and rejected alike) and is an upper
   *  bound on the accepted count — never the verified accepted tally. The
   *  authoritative accepted count comes only from an opened election's
   *  participation summary. */
  stored_ballot_count: number;
  last_revision: number;
  updated_at_unix_secs: number | null;
  finalized: boolean;
  /** True only when the durable workspace carries valid ORGANIZER-AUTHORITY
   *  provenance (fail-closed: session workspaces without it are voter-only). */
  organizer_workspace: boolean;
}

export interface GuiElectionWorkspaceResumeResultV1 {
  workspace: GuiElectionWorkspaceSummaryV1;
  election: GuiElectionSummaryV1 | null;
  draft: GuiElectionDraftPreviewV1 | null;
  /** Whether the resumed workspace restores organizer authority. */
  organizer_workspace: boolean;
}

/** The ROLE the backend holds for the active election session. `organizer`
 *  only after freeze or organizer-workspace resume; `imported_voter` for a
 *  session loaded from public artifacts. Backend-enforced; the UI mirrors it. */
export type GuiElectionAuthorityV1 = "organizer" | "imported_voter";

/** Public authority projection of the active session (`null` when none). */
export interface ActiveElectionAuthorityV1 {
  authority: GuiElectionAuthorityV1;
}

/** Backend-issued ids of the workspaces this session currently has active. Both
 *  are public opaque ids (the same ids returned by `list_election_workspaces`).
 *  Used to keep the Home view consistent with the fail-closed delete guard: the
 *  active draft/session is offered "Resume", never a "Delete" the guard refuses. */
export interface ActiveWorkspaceIdsV1 {
  session_workspace_id: string | null;
  draft_workspace_id: string | null;
}

export type GuiIntakeCategory =
  | "Accepted"
  | "Duplicate"
  | "WrongElection"
  | "MalformedProof"
  | "UnsupportedSuite"
  | "Invalid";

export interface GuiBallotIntakeResultV1 {
  accepted: boolean;
  code: string;
  category: GuiIntakeCategory;
  package_digest_hex: string;
}

/** Aggregate result of one durable private-intake inbox sync pass. Counts only;
 *  no plaintext, proof, nullifier, credential, or network identity. */
export interface GuiPrivateIntakeSyncSummaryV1 {
  discovered: number;
  newly_accepted: number;
  duplicates: number;
  rejected: number;
}

export interface GuiTallyCountV1 {
  candidate_id_hex: string;
  candidate_id_text: string | null;
  display_name: string;
  approvals: number;
}

// `GuiLeadingResultV1` is an externally-tagged serde enum. Its unit variant
// `NoApprovals` serializes as the BARE STRING "NoApprovals" (not an object),
// while the data-bearing variants serialize as single-key objects. Modelling
// the unit variant as an object here previously caused a render-time crash:
// `"NoApprovals" in tally.leading` throws a TypeError when `tally.leading` is a
// string primitive, which is exactly the zero-approvals / zero-ballot case.
export type GuiLeadingResultV1 =
  | "NoApprovals"
  | { SingleLeader: { candidate_id_hex: string; display_name: string; approvals: number } }
  | { Tie: { candidate_ids_hex: string[]; approvals: number } };

export interface GuiTallySummaryV1 {
  accepted_ballots: number;
  abstentions: number;
  counts: GuiTallyCountV1[];
  leading: GuiLeadingResultV1;
}

/** Participation visibility policy (application-local, non-canonical).
 *  Mirrors `tari_cc_private_ballot_gui_core::ParticipationVisibility`. */
export type ParticipationVisibility =
  | "LIVE"
  | "COARSE"
  | "SEALED_UNTIL_CLOSE";

/** Result disclosure state (mirrors the 5A4 tally gate). */
export type ResultVisibility = "SEALED" | "DISCLOSED";

/** Coarse participation bucket shown when the policy is COARSE. */
export type CoarseParticipationBucket =
  | "ZeroToTwentyFour"
  | "TwentyFiveToFortyNine"
  | "FiftyToSeventyFour"
  | "SeventyFiveToNinetyNine"
  | "OneHundred";

/** Privacy-aware participation summary derived from authoritative backend
 *  state. Numeric participation fields are null while sealed, so a modified
 *  frontend cannot retrieve sealed counts. `eligible_voters` is always
 *  present because it is public registry information. */
export interface GuiParticipationSummaryV1 {
  lifecycle_state: string;
  participation_visibility: ParticipationVisibility;
  result_visibility: ResultVisibility;
  eligible_voters: number;
  accepted_ballots: number | null;
  participation_basis_points: number | null;
  remaining_eligible_capacity: number | null;
  coarse_bucket: CoarseParticipationBucket | null;
  small_electorate: boolean;
}

export interface GuiArchiveFileSummaryV1 {
  path: string;
  digest_hex: string;
  bytes: number;
}

export interface GuiArchiveWriteResultV1 {
  directory: string;
  archive_hash_hex: string;
  election_manifest_hash_hex: string;
  files: GuiArchiveFileSummaryV1[];
  archive_manifest_path: string;
}

export interface GuiArchiveFileCheckV1 {
  path: string;
  present: boolean;
  digest_ok: boolean;
}

export interface GuiArchiveVerificationV1 {
  verified: boolean;
  finalized: boolean;
  failure_stage: string | null;
  failure_code: string | null;
  file_count: number;
  files: GuiArchiveFileCheckV1[];
  ballot_package_count: number;
  accepted_count: number;
  rejected_count: number;
  transcript_complete: boolean;
  tally: GuiTallySummaryV1 | null;
  archive_hash_hex: string | null;
  recomputed_archive_hash_hex: string | null;
  archive_hash_consistent: boolean;
  election_manifest_hash_hex: string | null;
  election_manifest_schema_version: number | null;
  proposal_question: string | null;
  /** Distinct application-level fact about whether the archived governance
   *  document matches the bound `governance_source_revision` pin. This is
   *  SEPARATE from `verified` (archive integrity): archive integrity proves
   *  catalog/disk consistency, not governance-source correspondence. The UI
   *  must not collapse these into one ambiguous "Verified" badge. */
  governance_source_matches_pin: GuiGovernanceArchivePinFactV1;
  transport_binding_present: boolean;
  transport_binding_verified: boolean;
  transport_batch_set_commitment_hex: string | null;
  transport_accepted_count: number | null;
  transport_reduced_anonymity: boolean | null;
}

/** Anchor-deployment capabilities of the running build. When
 *  `transport_binding_provenance_available` is false, this build cannot produce
 *  a transport-bound (anchor-eligible) finalized archive, so the GUI must
 *  present live anchoring as unavailable — a capability/readiness limitation,
 *  never an archive-integrity failure. */
export interface GuiAnchorDeploymentCapabilitiesV1 {
  transport_binding_provenance_available: boolean;
}

export interface GuiTransportAnchorVerificationV1 {
  state: "INCLUDED" | "ANCHORED";
  transport_binding_verified: boolean;
  archive_verified: boolean;
  archive_finalized: boolean;
  anchor_verified: boolean;
  transport_batch_set_commitment_hex: string | null;
}

/** Distinct archive-verification fact describing the relationship between the
 *  bound `governance_source_revision` pin and the archived
 *  `governance/source.bin` document. Mirrors the Rust
 *  `GuiGovernanceArchivePinFactV1` enum. */
export type GuiGovernanceArchivePinFactV1 =
  | "Matched"
  | "Mismatch"
  | "Missing"
  | "OperatorAttested"
  | "NotApplicable";

export interface GuiAnchorConfigInspectionV1 {
  network: string;
  walletd_endpoint: string;
  indexer_endpoint: string;
  account_reference: string;
  fee_component: string;
  seal_signer: string;
  max_fee: number;
  request_timeout_secs: number | null;
  receipt_query_max_attempts: number;
  manifest_hash_hex: string;
  archive_hash_hex: string;
  anchor_digest_hex: string;
  snapshot_path: string;
  evidence_path: string;
  backoff_base_secs: number;
  backoff_cap_secs: number;
  ttl_secs: number | null;
}

export interface GuiWalletdSnapshotSummaryV1 {
  project_request_id: string;
  walletd_request_id: number;
  network: string;
  account_reference: string;
  anchor_digest_hex: string;
  anchor_payload: string;
  max_fee: number;
  transaction_fingerprint_hex: string;
  decision: string;
  submission_state: string;
  transaction_id: string | null;
  effective_status: string | null;
  retry_count: number;
  sequence: number;
  diagnostic: string | null;
}

export interface GuiReceiptSnapshotSummaryV1 {
  project_request_id: string;
  walletd_request_id: number;
  transaction_id: string;
  network: string;
  account_reference: string;
  anchor_digest_hex: string;
  anchor_payload: string;
  transaction_fingerprint_hex: string;
  query_state: string;
  final_status: string | null;
  verified: boolean;
  sequence: number;
  diagnostic: string | null;
}

export interface GuiAnchorSnapshotInspectionV1 {
  snapshot_digest_hex: string;
  phase: string;
  phase_is_terminal: boolean;
  phase_is_terminal_success: boolean;
  poll_attempts_consumed: number;
  poll_attempts_max: number;
  submitted_transaction_id: string | null;
  diagnostic: string | null;
  walletd: GuiWalletdSnapshotSummaryV1[];
  receipts: GuiReceiptSnapshotSummaryV1[];
}

export interface GuiAnchorEvidenceInspectionV1 {
  record_digest_hex: string;
  final_status: string;
  receipt_source: string;
  phase: string;
  network: string;
  manifest_hash_hex: string;
  archive_hash_hex: string;
  anchor_digest_hex: string;
  transaction_id: string | null;
  ledger_position: number | null;
  snapshot_digest_hex: string;
  human_review_summary: string;
}

/** Schema-validated projection of a V2 public-anchor evidence JSON file
 *  (`*.v2-anchor-evidence.json`). Every field is public binding data — no
 *  secret material is ever present in a V2 evidence file. The `schema` field
 *  is retained as-is so the UI can display exactly what the file declared. */
export interface GuiV2AnchorEvidenceFileV1 {
  schema: string;
  archive_directory: string;
  transaction_id: string;
  network: string;
  template_address: string;
  template_module: string;
  template_function: string;
  template_topic: string;
  template_artifact_digest_hex: string;
  anchor_digest_hex: string;
  payload_hex: string;
}

/** Request for one bounded live anchor lifecycle step (organizer-only).
 *
 * The frontend cannot see or supply the walletd bearer secret. It only
 * signals whether to attach one via `use_walletd_auth`. When set, the shell
 * resolves the credential from OS-backed secure storage (Windows Credential
 * Manager / macOS Keychain / Secret Service) populated once by the user
 * through `connect_walletd`. `WALLETD_AUTH_TOKEN` remains a dev/CI-only
 * fallback and is never the normal product path. */
export interface GuiLiveAnchorStepRequestV1 {
  config_path: string;
  archive_directory: string;
  use_walletd_auth: boolean;
  decision: "approve" | "reject" | "none";
}

/** Presence and metadata for the walletd credential. Never carries the
 * raw key: `connect_walletd` / `reconnect_walletd` accept it as a
 * write-only argument, and the frontend only ever sees this status. */
export interface WalletdCredentialStatusV1 {
  /** True when a credential is present in OS-backed storage. */
  stored: boolean;
  /** True when the development-only env var is set (diagnostic only). */
  env_fallback_present: boolean;
  /** Human-readable name of the OS credential store. */
  store_label: string;
  /** Development-only env var name (for diagnostics). */
  env_var_name: string;
}

/** Bounded walletd readiness kind. The backend maps every raw error into
 * exactly one of these variants; the frontend never sees an HTTP status. */
export type WalletdReadinessKindV1 =
  | "ready"
  | "no_credential"
  | "auth_rejected"
  | "permission_denied"
  | "call_failed"
  | "unreachable";

/** Result of one walletd readiness probe. */
export interface WalletdReadinessV1 {
  kind: WalletdReadinessKindV1;
  endpoint: string;
  network: string | null;
  summary: string;
}

/** One public wallet account descriptor for the anchor setup assistant.
 *  Every field is public identity/ledger data; no secret is present. */
export interface GuiWalletdAnchorAccountV1 {
  name: string | null;
  component_address: string;
  owner_public_key_hex: string;
  key_index: number | null;
  is_default: boolean;
  is_confirmed_on_chain: boolean;
}

/** Result of listing the connected wallet's accounts for auto-fill. */
export interface GuiWalletdAnchorAccountsV1 {
  kind: WalletdReadinessKindV1;
  endpoint: string;
  network: string | null;
  accounts: GuiWalletdAnchorAccountV1[];
  summary: string;
}

/** Read-only, secret-free walletd connection diagnostic. No token/API key. */
export interface WalletdConnectionDiagnosticsV1 {
  endpoint_normalized: string;
  saved_credential: boolean;
  tcp_loopback_attempted: boolean;
  tcp_loopback_reachable: boolean;
  unauthenticated_wallet_get_info_attempted: boolean;
  unauthenticated_wallet_get_info_result: WalletdDiagnosticStageResultV1;
  accounts_list_attempted: boolean;
  accounts_list_result: WalletdDiagnosticStageResultV1;
  final_result_kind:
    | "ready"
    | "no_saved_credential"
    | "auth_rejected"
    | "permission_denied"
    | "call_failed"
    | "unreachable";
  network: string | null;
  account_count: number | null;
  selected_account_name: string | null;
  selected_account_component: string | null;
}

export interface WalletdDiagnosticStageResultV1 {
  status: "not_attempted" | "success" | "failed";
  category:
    | "tokio_reactor_io_driver_failure"
    | "tokio_runtime_context"
    | "connection_refused"
    | "timeout"
    | "http_response"
    | "json_rpc_decode_error"
    | "other_reqwest_transport_error"
    | null;
  message: string;
}

/** Bounded readiness kind for the production transport authority public root. */
export type ProductionTransportAuthorityReadinessKindV1 =
  | "unprovisioned"
  | "ready"
  | "malformed";

/** Organizer-safe view of the configured production transport authority PUBLIC
 *  root. Never contains a private key: the public key is shown only as a
 *  BLAKE3 fingerprint. */
export interface ProductionTransportAuthorityReadinessV1 {
  kind: ProductionTransportAuthorityReadinessKindV1;
  code: string;
  root_key_id: string | null;
  public_key_fingerprint_hex: string | null;
  network: string | null;
  label: string | null;
  summary: string;
  /** True only in a dev/test build compiling managed-tor fake roots. */
  managed_tor_build: boolean;
}

/** Operator-supplied public-pin configuration request. PUBLIC material only. */
export interface ProductionTransportAuthorityConfigureRequestV1 {
  network: string;
  root_key_id: string;
  /** 64 lower-hex characters (32-byte Ed25519 PUBLIC key). Never a private key. */
  root_public_key_hex: string;
  label: string | null;
}

/** Result of one bounded live anchor lifecycle step. */
export interface GuiLiveAnchorStepResultV1 {
  machine_code: string;
  phase: string;
  phase_is_terminal: boolean;
  phase_is_terminal_success: boolean;
  transaction_id: string | null;
  next_backoff_secs: number | null;
  diagnostic: string | null;
  evidence_path: string;
  evidence_written: boolean;
  snapshot_path: string;
  network: string;
  manifest_hash_hex: string;
  archive_hash_hex: string;
  anchor_digest_hex: string;
}

/** Request to generate a live anchor config from a verified finalized archive. */
export interface GuiLiveAnchorConfigRequestV1 {
  archive_directory: string;
  output_config_path: string;
  network: string;
  walletd_endpoint: string;
  indexer_endpoint: string;
  /** Published v0.39.2 event-template address for the selected network. */
  template_address: string;
  /** Event-template module name (shared template-contract constant). */
  template_module: string;
  /** Full stored event topic (module-derived template-contract constant). */
  template_event_topic: string;
  /** Lowercase BLAKE3-256 digest of the compiled template artifact. */
  template_artifact_digest_hex: string;
  /** Bounded number of epochs after the indexer's observed epoch. */
  max_epoch_delta: number;
  account_reference: string;
  fee_component: string;
  seal_signer_kind: string;
  seal_signer_id: string;
  declared_seal_public_key: string;
  dedicated_organizer_wallet_attested: boolean;
  max_fee: number;
  required_accepted_ballot_floor: number;
  reduced_anonymity_acknowledged: boolean;
  snapshot_path: string;
  evidence_path: string;
  backoff_base_secs: number;
  backoff_cap_secs: number;
  receipt_query_attempts: number;
  request_timeout_secs: number | null;
  ttl_secs: number | null;
}

/** Machine status of a single validated operator field. */
export interface GuiLiveAnchorFieldStatusV1 {
  /** Stable field identifier (matches the request field names). */
  field: string;
  /** Whether this field passed offline validation. */
  ok: boolean;
  /** `OK`, `OK_NEEDS_LIVE_CHECK`, or a specific `GUI_LIVE_ANCHOR_*` code. */
  code: string;
  message: string;
  remediation: string | null;
  /** Normalized, non-secret representation of the accepted value. */
  normalized: string | null;
  /** Whether a definitive verdict needs a live walletd/indexer call. */
  needs_live_check: boolean;
}

/** Structured, read-only preflight result for the whole operator config. */
export interface GuiLiveAnchorPreflightResultV1 {
  ok: boolean;
  fields: GuiLiveAnchorFieldStatusV1[];
  first_error_code: string | null;
  first_error_field: string | null;
  accepted_ballot_count: number | null;
  reduced_anonymity: boolean | null;
  any_needs_live_check: boolean;
}

/** Request to build or verify a V2 richer public anchor payload. */
export interface GuiLiveAnchorV2RequestV1 {
  archive_directory: string;
  network: string;
  template_address: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  template_artifact_digest_hex: string;
}

/** One public tally row in the V2 result. */
export interface GuiV2TallyRowV1 {
  display_label: string;
  machine_id_hex: string;
  count: number;
}

/** Result of building/verifying the V2 richer public anchor payload. */
export interface GuiLiveAnchorV2ResultV1 {
  v2_anchor_digest_hex: string;
  /** Hex-encoded canonical public-summary bytes (evidence transport form). */
  payload_hex: string;
  /** Readable canonical public-summary UTF-8 string — the exact bytes the V2
   * template puts on-chain in the `public_summary` metadata field. */
  public_summary_json: string;
  network: string;
  /** Exact canonical election identifier text (e.g. "500-votertest-01") — the
   *  same UTF-8 string that appears verbatim inside public_summary_json and
   *  as the on-chain `election_id` metadata value. */
  election_id: string;
  /** Lowercase-hex of the same election identifier bytes (kept for evidence
   *  transport parity; two views of the same data). */
  election_id_hex: string;
  ballot_question: string;
  ballot_kind: string;
  confidentiality_mode: string;
  proof_suite: string;
  manifest_hash_hex: string;
  archive_hash_hex: string;
  registry_commitment_hex: string;
  option_set_commitment_hex: string;
  eligible_voter_count: number;
  accepted_ballot_count: number;
  rejected_ballot_count: number;
  tally: GuiV2TallyRowV1[];
  archive_finalized: boolean;
  template_address: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  template_artifact_digest_hex: string;
}

export interface GuiV2AnchorPublishPreparationV1 {
  template_address: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  anchor_digest_hex: string;
  arguments: string[];
  /** Readable canonical public summary — the exact `public_summary` value the
   * template will emit on-chain. Surfaced here so the preview can display it
   * without slicing the argument list. */
  public_summary_json: string;
}

/** One manually-gated V2 walletd lifecycle transition. */
export interface GuiV2LiveAnchorStepRequestV1 {
  archive_directory: string;
  payload_hex: string;
  expected_digest_hex: string;
  fee_component: string;
  seal_signer_kind: string;
  seal_signer_id: string;
  max_fee: number;
  max_epoch_delta: number;
  walletd_endpoint: string;
  indexer_endpoint: string;
  use_walletd_auth: boolean;
  decision: "none" | "approve";
}

export interface GuiV2LiveAnchorStepResultV1 {
  phase: string;
  waiting_for_wallet_approval: boolean;
  transaction_id: string | null;
  walletd_request_id: number | null;
  estimated_required_fee: number | null;
  selected_max_fee: number | null;
  wallet_request_status: string;
  rejection_reason: string | null;
  retry_required: boolean;
  lifecycle_path: string;
  evidence_path: string;
  failure_path: string;
  receipt_verified: boolean;
  failure_reason: string | null;
}

/** Read-only projection of the persisted V2 anchor lifecycle for a given
 *  finalized archive directory. Used by the organizer UI on mount so an
 *  already-submitted (but unverified) transaction is surfaced for recovery
 *  instead of the fresh Build/Prepare/Submit controls that would create a
 *  duplicate wallet request and republish a new anchor. */
export interface GuiV2LiveAnchorHydratedStateV1 {
  lifecycle_present: boolean;
  evidence_present: boolean;
  failure_present: boolean;
  archive_directory: string;
  lifecycle_path: string;
  evidence_path: string;
  failure_path: string;
  payload_hex: string | null;
  expected_digest_hex: string | null;
  network: string | null;
  template_address: string | null;
  template_module: string | null;
  template_function: string | null;
  template_topic: string | null;
  template_artifact_digest_hex: string | null;
  fee_component: string | null;
  seal_signer_kind: string | null;
  seal_signer_id: string | null;
  max_fee: number | null;
  estimated_required_fee: number | null;
  selected_max_fee: number | null;
  max_epoch: number | null;
  walletd_request_id: number | null;
  phase: string | null;
  transaction_id: string | null;
  failure_reason: string | null;
  recoverable: boolean;
  blocks_fresh_publish: boolean;
  receipt_verified: boolean;
}

/** Result of generating a live anchor config. */
export interface GuiLiveAnchorConfigResultV1 {
  config_path: string;
  input_provenance: string;
  manifest_hash_hex: string;
  archive_hash_hex: string;
  anchor_digest_hex: string;
  accepted_ballot_count: number;
  required_accepted_ballot_floor: number;
  reduced_anonymity: boolean;
  reduced_anonymity_acknowledged: boolean;
  fee_component: string;
  declared_seal_public_key: string;
  seal_assurance: string;
  dedicated_organizer_wallet_attested: boolean;
  config_file_blake3_256: string;
  config_file_bytes: number;
  /** Pinned event-template address written into the V4 config. */
  template_address: string;
  /** Pinned full event topic written into the V4 config. */
  template_event_topic: string;
  /** Configured max-epoch window written into the V4 config. */
  max_epoch_delta: number;
}

export interface GuiTrustedOotleDeploymentV1 {
  schema: string;
  network: string;
  template_address: string;
  template_artifact_digest_hex: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  locked_at_unix_ms: number;
}

export interface GuiTrustedOotleDeploymentFixedV1 {
  schema: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
}

export interface GuiTrustedOotleDeploymentStatusV1 {
  locked: boolean;
  deployment: GuiTrustedOotleDeploymentV1 | null;
  fixed: GuiTrustedOotleDeploymentFixedV1;
}

/** Separate V2 public-summary deployment lock. It can never stand in for V1. */
export interface GuiTrustedOotleDeploymentV2 {
  schema: string;
  network: string;
  template_address: string;
  template_artifact_digest_hex: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  locked_at_unix_ms: number;
}

export interface GuiTrustedOotleDeploymentFixedV2 {
  schema: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  /** BLAKE3-256 of the reviewed V2 WASM the lock will accept. The frontend
   *  pre-fills this so a normal organizer never has to compute or paste it;
   *  the backend still checks the submitted value equals this constant. */
  expected_artifact_digest_hex: string;
  /** Human display name for the reviewed WASM. */
  expected_artifact_display_name: string;
}

export interface GuiTrustedOotleDeploymentStatusV2 {
  locked: boolean;
  deployment: GuiTrustedOotleDeploymentV2 | null;
  fixed: GuiTrustedOotleDeploymentFixedV2;
}

export interface GuiTrustedOotleDeploymentLockRequestV2 {
  network: string;
  template_address: string;
  template_artifact_digest_hex: string;
}

export interface GuiTrustedOotleDeploymentLockRequestV1 {
  network: string;
  template_address: string;
  selected_wasm_path: string;
}

export interface GuiTrustedOotleTemplateWasmInspectionV1 {
  display_filename: string;
  bytes: number;
  digest_algorithm_id: string;
  digest_hex: string;
}

/** Bounded command error payload (mirror of the shell's CommandError). */
export interface GuiCommandError {
  code: string;
  category: string;
  context: string | null;
  message: string;
}

export interface ShellInfoV1 {
  application: string;
  shell_version: string;
  gui_core_boundary: string;
  binding_notice: string;
}

// ---------------------------------------------------------------------------
// Organizer election creation (Slice 5A6).
//
// The frontend collects ordinary strings and public keys; Rust validates every
// field and builds the canonical types. No field carries secret material.
// ---------------------------------------------------------------------------

/** Application-local ballot presentation vocabulary (non-canonical). */
export type GuiBallotPresentationType =
  | "Candidate"
  | "GovernanceProposal"
  | "BallotMeasure";

/** Stable identifier string for a presentation type. */
export type PresentationIdentifier =
  | "CANDIDATE"
  | "GOVERNANCE_PROPOSAL"
  | "BALLOT_MEASURE"
  | "candidate"
  | "governance-proposal"
  | "ballot-measure";

export interface GuiDraftOptionV1 {
  machine_id_hex: string;
  machine_id_text: string | null;
  display_name: string;
}

export interface GuiDraftVoterV1 {
  public_key_hex: string;
  public_key_abbrev: string;
}

/** Pre-freeze review of the current draft. Commitments and the manifest hash
 *  are null until the relevant sections are complete. */
export interface GuiElectionDraftPreviewV1 {
  election_id_hex: string | null;
  election_id_text: string | null;
  proposal_question: string | null;
  governance_source_revision: string | null;
  proof_suite_id: string;
  approval_min: number | null;
  approval_max: number | null;
  allow_abstention: boolean;
  voter_count: number;
  registry_commitment_hex: string | null;
  voters: GuiDraftVoterV1[];
  options: GuiDraftOptionV1[];
  candidate_set_commitment_hex: string | null;
  manifest_hash_hex: string | null;
  presentation: GuiBallotPresentationType;
  complete: boolean;
  missing: string[];
  frozen: boolean;
  creation_result: GuiElectionCreationResultV1 | null;
  presentation_is_canonical: boolean;
  governance_source_pin: GuiGovernanceSourcePinV1;
  governance_document: GuiGovernanceDocumentDigestV1 | null;
  governance_document_status: GuiGovernanceDocumentStatusV1;
}

/** Result of a successful freeze. `presentation_is_canonical` is always false
 *  for version one: the presentation type does not survive export/import. */
export interface GuiElectionCreationResultV1 {
  summary: GuiElectionSummaryV1;
  presentation: GuiBallotPresentationType;
  presentation_is_canonical: boolean;
}

export interface GuiElectionExportFileV1 {
  path: string;
  absolute_path: string;
  bytes: number;
  digest_hex: string;
}

export interface GuiElectionExportResultV1 {
  directory: string;
  manifest_hash_hex: string;
  registry_commitment_hex: string;
  candidate_set_commitment_hex: string;
  files: GuiElectionExportFileV1[];
}

// ---------------------------------------------------------------------------
// Slice 5A8: governance source pinning, document archival, voter confirmation.
//
// Application-level governance evidence. The governance document is supporting
// evidence, NOT a fourth canonical election artifact. No voter secret material
// crosses the boundary in any of these types.
// ---------------------------------------------------------------------------

/** Stable machine-readable kind code for a governance source pin. */
export type GuiGovernancePinKind = "BLAKE3_DIGEST" | "GIT_COMMIT" | "UNRECOGNIZED";

/** Structured validation result for one `governance_source_revision` string.
 *  `format_valid` is NOT cryptographic verification — only an immutable-shape
 *  check. A green "Matched" status is reported separately by
 *  `GuiGovernanceDocumentStatusV1`. */
export interface GuiGovernanceSourcePinV1 {
  normalized: string;
  kind: GuiGovernancePinKind;
  format_valid: boolean;
  digest_hex: string | null;
  git_sha_hex: string | null;
  message: string;
}

/** Metadata for one selected governance document (non-secret). */
export interface GuiGovernanceDocumentDigestV1 {
  display_filename: string;
  bytes: number;
  digest_algorithm_id: string;
  digest_hex: string;
}

/** Stable machine-readable match status code. */
export type GuiGovernanceMatchStatus =
  | "MATCHED"
  | "MISMATCH"
  | "OPERATOR_ATTESTED"
  | "UNVERIFIED_REFERENCE"
  | "NOT_APPLICABLE";

/** Structured result of matching a governance document against a bound pin. */
export interface GuiGovernanceDocumentStatusV1 {
  governance_source_revision: string;
  pin: GuiGovernanceSourcePinV1;
  document: GuiGovernanceDocumentDigestV1 | null;
  status: GuiGovernanceMatchStatus;
  status_label: string;
}

/** Cryptographically bound values shown to the voter as authoritative. */
export interface GuiVoterBoundFieldsV1 {
  election_id_hex: string;
  election_id_text: string | null;
  proposal_question: string | null;
  ballot_kind: string;
  ballot_confidentiality: string;
  manifest_hash_hex: string;
  governance_source_revision: string;
  proof_suite_id: string;
  approval_min: number;
  approval_max: number;
  abstention_allowed: boolean;
  option_display_labels: string[];
}

/** Auditor-facing advanced commitments. */
export interface GuiVoterAdvancedDetailsV1 {
  option_machine_ids_hex: string[];
  registry_commitment_hex: string;
  candidate_set_commitment_hex: string;
  voter_count: number;
}

/** The complete voter confirmation view model. Read-only confirmation only. */
export interface GuiVoterElectionConfirmationV1 {
  bound: GuiVoterBoundFieldsV1;
  advanced: GuiVoterAdvancedDetailsV1;
  candidates: GuiCandidateSummaryV1[];
  governance_document_status: GuiGovernanceDocumentStatusV1;
  presentation_is_canonical: boolean;
  presentation_notice: string;
  next_stage_placeholder: string;
  no_proposal_question_notice: string | null;
}

// ---------------------------------------------------------------------------
// Slice 5A9: voter governance credential boundary.
//
// These are public status DTOs only. There is intentionally no field for a
// private scalar, credential bytes, seed, mnemonic, wallet key, proof,
// nullifier, ballot package, or registry index.
// ---------------------------------------------------------------------------

export type GuiVoterCredentialOriginV1 =
  | "Generated"
  | "DurableCreated"
  | "UnlockedSaved"
  | "ImportedSession"
  | "ImportedSaved"
  | "MemoryOnly";

export type GuiVoterEligibilityV1 =
  | "NotChecked"
  | "Eligible"
  | "NotEligible";

export interface GuiVoterCredentialStatusV1 {
  credential_loaded: boolean;
  credential_origin: GuiVoterCredentialOriginV1 | null;
  public_governance_key_hex: string | null;
  public_governance_key_abbrev: string | null;
  eligibility: GuiVoterEligibilityV1;
  eligibility_label: string;
  can_continue: boolean;
  session_only: boolean;
  session_notice: string;
  saved_locally: boolean;
  wallet_key_warning: string;
  enrollment_notice: string;
}

export interface GuiVoterCredentialFileSummaryV1 {
  public_governance_key_hex: string;
  public_governance_key_abbrev: string;
  format_version: number;
  saved_locally: boolean;
  is_default: boolean;
}

export interface GuiSavedVoterCredentialsV1 {
  saved_credential_count: number;
  skipped_invalid_count: number;
  credentials: GuiVoterCredentialFileSummaryV1[];
}

export interface GuiVoterCredentialBackupResultV1 {
  public_governance_key_hex: string;
  public_governance_key_abbrev: string;
  format_version: number;
}

export interface GuiSavedVoterCredentialDeleteResultV1 {
  public_governance_key_hex: string;
  public_governance_key_abbrev: string;
  deleted: boolean;
}

// ---------------------------------------------------------------------------
// Slice 5A10A: voter ballot session, selection, and stale-state architecture.
//
// These are public workflow DTOs only. They contain no secret, proof,
// nullifier, package bytes, registry member index, or prover randomness.
// ---------------------------------------------------------------------------

export type GuiVoterWorkflowStateV1 =
  | "ReviewRequired"
  | "CredentialMissing"
  | "CredentialNotEligible"
  | "ElectionNotOpen"
  | "SelectionIncomplete"
  | "SelectionReady"
  | "PreparingProof"
  | "PreparedBallotReady"
  | "BallotCast"
  | "CastPending";

/** Durable local cast state for the loaded election + credential. Defence in
 *  depth only: the election-scoped nullifier remains the authoritative one-vote
 *  rule. `NOT_CAST` while the ballot may still be reconsidered; `CAST` once it
 *  has been exported/cast; `CAST_PENDING` during crash recovery (locked). */
export type GuiVoterCastLockStateV1 = "NOT_CAST" | "CAST_PENDING" | "CAST";

export interface GuiVoterElectionBindingV1 {
  election_id_hex: string;
  manifest_hash_hex: string;
  registry_commitment_hex: string;
  candidate_set_commitment_hex: string;
}

export interface GuiVoterSelectionStatusV1 {
  selection_loaded: boolean;
  selected_option_ids_hex: string[];
  selected_display_labels: string[];
  selected_count: number;
  approval_min: number;
  approval_max: number;
  abstention_allowed: boolean;
  abstaining: boolean;
  valid: boolean;
  lifecycle_state: string;
  can_prepare_ballot: boolean;
  selection_revision: number;
  message: string;
}

export interface GuiPreparedBallotStatusV1 {
  state: string;
  operation_id: number | null;
  ready_to_export: boolean;
  summary: GuiPreparedBallotSummaryV1 | null;
  message: string;
}

export interface GuiPreparedBallotSummaryV1 {
  election_id_hex: string;
  manifest_hash_hex: string;
  selected_option_ids_hex: string[];
  selected_display_labels: string[];
  abstaining: boolean;
  proof_suite_id: string;
  canonical_package_bytes: number;
  package_digest_hex: string;
  locally_verified: boolean;
  ready_to_export: boolean;
}

export interface GuiPreparedBallotExportV1 {
  canonical_package_bytes: number;
  package_digest_hex: string;
}

/** Safe private-transport availability projection. It intentionally contains
 * no descriptor, endpoint, key, envelope, or retry material. */
export interface GuiPrivateTransportAvailabilityV1 {
  managed_tor_available: boolean;
  split_trust_relay_available: boolean;
  offline_export_available: boolean;
  development_transport: boolean;
  message: string;
}

export type GuiPrivateRouteV1 = "ManagedTor" | "SplitTrustRelay" | "OfflineExport";

/** Reduced result from Rust's private-submission coordinator. No intake
 * sequence, duplicate reference, nullifier, secret, or transport internals
 * cross the Tauri boundary. */
export interface GuiPrivateSubmissionResultV1 {
  route: GuiPrivateRouteV1;
  receipt_state: string;
  retry_status: string;
  reduced_anonymity: boolean;
}

export interface GuiVoterWorkflowStatusV1 {
  election_binding: GuiVoterElectionBindingV1;
  credential: GuiVoterCredentialStatusV1;
  selection: GuiVoterSelectionStatusV1;
  prepared_ballot: GuiPreparedBallotStatusV1;
  workflow_state: GuiVoterWorkflowStateV1;
  can_prepare_ballot: boolean;
  credential_generation: number;
  selection_revision: number;
  preparation_generation: number;
  preparation_notice: string;
  cast_lock_state: GuiVoterCastLockStateV1;
}

// ---------------------------------------------------------------------------
// managed-tor: controlled-test managed Tor transport (voter side).
//
// These DTOs are produced only when the Tauri shell is compiled with the
// `managed-tor` feature AND the user has explicitly configured a test
// transport. No secret material crosses the boundary.
// ---------------------------------------------------------------------------

/** Safe metadata returned after a private-transport release attempt. `CAST`
 *  only once an authenticated receipt is verified and persisted; otherwise
 *  `CAST_PENDING`. `released` is delivery authentication, NOT organizer
 *  acceptance, tally inclusion, or Ootle anchoring. */
export interface GuiPrivateReleaseResultV1 {
  cast_lock_state: string;
  receipt_state: string;
  released: boolean;
  package_digest_hex: string;
  /**
   * Bounded, privacy-safe stage label describing why an uncertain
   * (CAST_PENDING) attempt did not complete, for the controlled-test Advanced/
   * diagnostics panel only. `null` on success. Never carries any secret,
   * ballot, or network-identity material — only which processing stage
   * classified the outcome.
   */
  diagnostic_stage: string | null;
}

/** Status of the voter-side managed-Tor test transport. */
export interface ManagedTorStatusV1 {
  configured: boolean;
  tor_running: boolean;
  socks_ready: boolean;
  socks_addr: string | null;
  onion_hostname: string | null;
  descriptor_fingerprint: string | null;
  message: string;
}

/** Read-only voter Tor availability probe result. */
export interface VoterTorStatusV1 {
  tor_found: boolean;
  /** The path the backend would use (allowlist or remembered); diagnostic only. */
  resolved_tor_path: string | null;
}

/**
 * Status of the organizer near-one-click private ballot intake. Carries only
 * organizer-safe aggregates and diagnostics; never any private key material.
 * The optional diagnostic fields (onion, fingerprint, ports, paths) are surfaced
 * only under an Advanced disclosure — normal operation needs none of them.
 */
export interface OrganizerIntakeStatusV1 {
  tor_found: boolean;
  transport_provisioned: boolean;
  intake_running: boolean;
  /** The running intake is bound to the CURRENTLY loaded election. */
  election_bound: boolean;
  ready: boolean;
  /**
   * A start attempt is recorded but a REQUIRED owned component (the Tor child or
   * the collector worker) has since died. Terminal but recoverable — a restart
   * clears it. Distinguishes a genuine start failure from an in-progress start,
   * so the UI never sits in an indefinite "Starting…".
   */
  failed: boolean;
  /** Bounded, path-free, non-sensitive reason for `failed` (e.g.
   * `organizer-tor-datadir-lock`); `null` unless `failed` is true. */
  failure_reason: string | null;
  accepted_ballots: number;
  /** Lifecycle the running collector would currently sign into status answers
   * (backend-authoritative fence). `null` while no intake is running. */
  published_lifecycle: string | null;
  /** Monotonic generation the running collector would currently sign. */
  status_generation: number | null;
  /** Authoritative session lifecycle observed during the same status call.
   * A disagreement with `published_lifecycle` is healed automatically within
   * one heartbeat and surfaces here for troubleshooting. */
  authoritative_lifecycle: string | null;
  onion_hostname: string | null;
  descriptor_fingerprint: string | null;
  collector_addr: string | null;
  tor_data_dir: string | null;
  voter_bundle_path: string | null;
  durable_inbox_dir: string | null;
  message: string;
}

/** Result of exporting the voter-safe public transport bundle. */
export interface VoterBundleExportResultV1 {
  written_path: string;
}

/** Result of exporting one authenticated election-status artifact. */
export interface GuiElectionStatusExportResultV1 {
  written_path: string;
  /** Lifecycle state that was signed (stable machine code). */
  lifecycle_state: string;
  /** Monotonic generation reserved for this statement. */
  generation: number;
}

/** Voter-safe projection of one applied election-status statement. */
export interface AppliedElectionStatusResultV1 {
  effective_state: string;
  advanced: boolean;
  generation: number;
}

/** Result of importing one authenticated election-status artifact. */
export interface GuiElectionStatusImportResultV1 {
  applied: AppliedElectionStatusResultV1;
  /** Refreshed public summary of the active election after application. */
  election_summary: GuiElectionSummaryV1;
}
