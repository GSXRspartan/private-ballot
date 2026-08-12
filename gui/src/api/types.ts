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
  candidates: GuiCandidateSummaryV1[];
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

export interface GuiTallyCountV1 {
  candidate_id_hex: string;
  candidate_id_text: string | null;
  display_name: string;
  approvals: number;
}

export type GuiLeadingResultV1 =
  | { NoApprovals: null }
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
  /** Distinct application-level fact about whether the archived governance
   *  document matches the bound `governance_source_revision` pin. This is
   *  SEPARATE from `verified` (archive integrity): archive integrity proves
   *  catalog/disk consistency, not governance-source correspondence. The UI
   *  must not collapse these into one ambiguous "Verified" badge. */
  governance_source_matches_pin: GuiGovernanceArchivePinFactV1;
  transport_binding_present: boolean;
  transport_binding_verified: boolean;
  transport_batch_set_commitment_hex: string | null;
}

export interface GuiTransportAnchorVerificationV1 {
  state: "INCLUDED" | "ANCHORED";
  transport_binding_verified: boolean;
  archive_verified: boolean;
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
  no_proposal_question_notice: string;
}

// ---------------------------------------------------------------------------
// Slice 5A9: voter governance credential boundary.
//
// These are public status DTOs only. There is intentionally no field for a
// private scalar, credential bytes, seed, mnemonic, wallet key, proof,
// nullifier, ballot package, or registry index.
// ---------------------------------------------------------------------------

export type GuiVoterCredentialOriginV1 = "Generated";

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
  wallet_key_warning: string;
  enrollment_notice: string;
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
  | "SelectionIncomplete"
  | "SelectionReady"
  | "PreparingProof"
  | "PreparedBallotReady";

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
}
