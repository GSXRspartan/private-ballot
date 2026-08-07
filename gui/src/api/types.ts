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
  sequence: number;
  nullifier_hex: string | null;
  duplicate_of_sequence: number | null;
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
}

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
