import {
  decodeExecuteResultBase64,
  decodeExecuteResultJson,
  ExecutionResultDecodeError,
  type DecodedEventMetadataEntry,
  type DecodedExecuteResult,
} from "./executeResult.ts";

export const ANCHOR_EVENT_DIGEST_KEY_V2 = "anchor_digest_v2";
export const ANCHOR_EVENT_NETWORK_KEY_V2 = "network";
export const ANCHOR_EVENT_ELECTION_ID_KEY_V2 = "election_id";
export const ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2 = "public_summary";

export interface ExpectedAnchorTemplate {
  templateAddressHex: string;
  eventTopic: string;
}

export interface ExpectedAnchorEventPayload {
  anchorDigestHex: string;
  network: string;
  electionId: string;
  publicSummary: string;
}

export type AnchorVerificationFailureKind =
  | "wrong_transaction"
  | "fee_only_acceptance"
  | "rejected_transaction"
  | "malformed_result"
  | "wrong_event_template"
  | "wrong_event_topic"
  | "missing_anchor_event"
  | "duplicate_anchor_events"
  | "unexpected_event_metadata"
  | "malformed_anchor_event"
  | "wrong_anchor_digest";

export interface VerifiedAnchorEvidence {
  transactionIdHex: string;
  epoch: number | null;
  eventIndex: number;
}

export type AnchorVerificationOutcome =
  | { kind: "verified"; evidence: VerifiedAnchorEvidence }
  | { kind: "pending" }
  | {
      kind: "terminal_failure";
      failure: AnchorVerificationFailureKind;
      message: string;
    };

export function anchorFailureMessage(
  failure: AnchorVerificationFailureKind,
): string {
  switch (failure) {
    case "wrong_transaction":
      return "the verified transaction id does not match the submitted transaction";
    case "fee_only_acceptance":
      return "only the fee intent committed; the anchor was not published";
    case "rejected_transaction":
      return "the transaction was rejected";
    case "malformed_result":
      return "the transaction result is malformed";
    case "wrong_event_template":
      return "the anchor event was emitted by a different template";
    case "wrong_event_topic":
      return "the anchor event carries a different topic";
    case "missing_anchor_event":
      return "the transaction emitted no anchor event";
    case "duplicate_anchor_events":
      return "the transaction emitted more than one anchor event";
    case "unexpected_event_metadata":
      return "the anchor event carries unexpected metadata";
    case "malformed_anchor_event":
      return "the anchor event metadata is malformed";
    case "wrong_anchor_digest":
      return "the on-chain anchor digest does not match this election's anchor";
  }
}

function isLowercaseHex64(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

export function parseResultEnvelope(json: unknown):
  | { kind: "pending" }
  | { kind: "rejected"; details: string }
  | {
      kind: "finalized";
      committed: boolean;
      executionResult: string | Record<string, unknown> | null;
      abortDetails: string | null;
    }
  | { kind: "malformed" } {
  if (typeof json !== "object" || json === null) {
    return { kind: "malformed" };
  }
  const result = (json as { result?: unknown }).result;
  if (typeof result === "string") {
    return result === "Pending" ? { kind: "pending" } : { kind: "malformed" };
  }
  if (typeof result !== "object" || result === null) {
    return { kind: "malformed" };
  }
  const variantKeys = Object.keys(result as Record<string, unknown>);
  if (variantKeys.length !== 1) {
    return { kind: "malformed" };
  }
  const [variantKey] = variantKeys;
  const variant = (result as Record<string, unknown>)[variantKey];
  if (variantKey === "Finalized" && typeof variant === "object" && variant !== null) {
    const record = variant as Record<string, unknown>;
    const committed = record.final_decision === "Commit";
    const rawExecutionResult = record.execution_result;
    const executionResult = typeof rawExecutionResult === "string"
      ? rawExecutionResult
      : typeof rawExecutionResult === "object" && rawExecutionResult !== null && !Array.isArray(rawExecutionResult)
        ? rawExecutionResult as Record<string, unknown>
        : null;
    const abortDetails =
      typeof record.abort_details === "string" ? record.abort_details : null;
    return {
      kind: "finalized",
      committed,
      executionResult,
      abortDetails,
    };
  }
  if (variantKey === "Rejected" && typeof variant === "object" && variant !== null) {
    const details = (variant as Record<string, unknown>).details;
    return {
      kind: "rejected",
      details: typeof details === "string" ? details : "rejected",
    };
  }
  return { kind: "malformed" };
}

export function verifyV2AnchorExecutionResult(
  expectedTransactionHex: string,
  expectedTemplate: ExpectedAnchorTemplate,
  expectedPayload: ExpectedAnchorEventPayload,
  decoded: DecodedExecuteResult,
): VerifiedAnchorEvidence {
  if (!isLowercaseHex64(expectedTransactionHex)) {
    throw new Error("expected transaction id must be 64 lowercase hex characters");
  }
  if (decoded.transactionHashHex !== expectedTransactionHex) {
    throw new VerificationFailure("wrong_transaction");
  }
  if (decoded.resultVariant === "fee_only") {
    throw new VerificationFailure("fee_only_acceptance");
  }
  if (decoded.resultVariant === "reject") {
    throw new VerificationFailure("rejected_transaction");
  }

  const candidates: { eventIndex: number; metadata: DecodedEventMetadataEntry[] }[] = [];
  for (const event of decoded.events) {
    const hasV2Digest = event.metadata.some((entry) => entry.key === ANCHOR_EVENT_DIGEST_KEY_V2);
    if (
      event.templateAddressHex === expectedTemplate.templateAddressHex &&
      event.topic !== expectedTemplate.eventTopic
    ) {
      throw new VerificationFailure("wrong_event_topic");
    }
    if (
      event.topic === expectedTemplate.eventTopic &&
      event.templateAddressHex !== expectedTemplate.templateAddressHex
    ) {
      throw new VerificationFailure("wrong_event_template");
    }
    if (
      event.topic === expectedTemplate.eventTopic ||
      hasV2Digest
    ) {
      candidates.push({
        eventIndex: event.eventIndex,
        metadata: event.metadata.map((entry) => ({ ...entry })),
      });
    }
  }
  if (candidates.length === 0) {
    throw new VerificationFailure("missing_anchor_event");
  }
  if (candidates.length > 1) {
    throw new VerificationFailure("duplicate_anchor_events");
  }

  const candidate = candidates[0];
  if (
    decoded.events[candidate.eventIndex].templateAddressHex !==
    expectedTemplate.templateAddressHex
  ) {
    throw new VerificationFailure("wrong_event_template");
  }
  if (decoded.events[candidate.eventIndex].topic !== expectedTemplate.eventTopic) {
    throw new VerificationFailure("wrong_event_topic");
  }
  if (candidate.metadata.length !== 4) {
    throw new VerificationFailure("unexpected_event_metadata");
  }

  const expected: [string, string][] = [
    [ANCHOR_EVENT_DIGEST_KEY_V2, expectedPayload.anchorDigestHex],
    [ANCHOR_EVENT_NETWORK_KEY_V2, expectedPayload.network],
    [ANCHOR_EVENT_ELECTION_ID_KEY_V2, expectedPayload.electionId],
    [ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2, expectedPayload.publicSummary],
  ];
  for (const [key, value] of expected) {
    const entries = candidate.metadata.filter((entry) => entry.key === key);
    if (entries.length !== 1) {
      throw new VerificationFailure("malformed_anchor_event");
    }
    // The matching anchor event's fields are strictly typed strings. A number
    // or any other decoded value is never string-compared or normalized.
    if (typeof entries[0].value !== "string") {
      throw new VerificationFailure("malformed_anchor_event");
    }
    if (entries[0].value !== value) {
      throw new VerificationFailure(
        key === ANCHOR_EVENT_DIGEST_KEY_V2 ? "wrong_anchor_digest" : "malformed_anchor_event",
      );
    }
  }

  return {
    transactionIdHex: decoded.transactionHashHex,
    epoch: decoded.epoch,
    eventIndex: candidate.eventIndex,
  };
}

export class VerificationFailure extends Error {
  readonly kind: AnchorVerificationFailureKind;

  constructor(kind: AnchorVerificationFailureKind) {
    super(anchorFailureMessage(kind));
    this.name = "VerificationFailure";
    this.kind = kind;
  }
}

export function verifyV2AnchorTransaction(
  expectedTransactionHex: string,
  expectedTemplate: ExpectedAnchorTemplate,
  expectedPayload: ExpectedAnchorEventPayload,
  responseJson: unknown,
): AnchorVerificationOutcome {
  const envelope = parseResultEnvelope(responseJson);
  if (envelope.kind === "pending") {
    return { kind: "pending" };
  }
  if (envelope.kind === "rejected") {
    return {
      kind: "terminal_failure",
      failure: "rejected_transaction",
      message: `${anchorFailureMessage("rejected_transaction")} (${envelope.details})`,
    };
  }
  if (envelope.kind === "malformed") {
    return {
      kind: "terminal_failure",
      failure: "malformed_result",
      message: anchorFailureMessage("malformed_result"),
    };
  }
  if (!envelope.committed) {
    return {
      kind: "terminal_failure",
      failure: "rejected_transaction",
      message: envelope.abortDetails
        ? `${anchorFailureMessage("rejected_transaction")} (${envelope.abortDetails})`
        : anchorFailureMessage("rejected_transaction"),
    };
  }
  if (envelope.executionResult === null) {
    return {
      kind: "terminal_failure",
      failure: "malformed_result",
      message: anchorFailureMessage("malformed_result"),
    };
  }
  let decoded: DecodedExecuteResult;
  try {
    decoded = typeof envelope.executionResult === "string"
      ? decodeExecuteResultBase64(envelope.executionResult)
      : decodeExecuteResultJson(envelope.executionResult);
  } catch (error) {
    return {
      kind: "terminal_failure",
      failure: "malformed_result",
      message:
        error instanceof ExecutionResultDecodeError
          ? `${anchorFailureMessage("malformed_result")} (${error.message})`
          : anchorFailureMessage("malformed_result"),
    };
  }
  try {
    const evidence = verifyV2AnchorExecutionResult(
      expectedTransactionHex,
      expectedTemplate,
      expectedPayload,
      decoded,
    );
    return { kind: "verified", evidence };
  } catch (error) {
    if (error instanceof VerificationFailure) {
      return {
        kind: "terminal_failure",
        failure: error.kind,
        message: error.message,
      };
    }
    throw error;
  }
}
