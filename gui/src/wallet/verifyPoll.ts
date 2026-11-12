import {
  verifyV2AnchorTransaction,
  type AnchorVerificationOutcome,
  type ExpectedAnchorEventPayload,
  type ExpectedAnchorTemplate,
} from "./verifyReceipt.ts";

export interface VerifyPollOptions {
  attempts: number;
  intervalMs: number;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export async function pollUntilVerified(
  fetchResult: () => Promise<unknown>,
  expectedTransactionHex: string,
  expectedTemplate: ExpectedAnchorTemplate,
  expectedPayload: ExpectedAnchorEventPayload,
  options: VerifyPollOptions,
): Promise<AnchorVerificationOutcome> {
  const sleep = options.sleep ?? defaultSleep;
  let lastOutcome: AnchorVerificationOutcome | null = null;
  for (let attempt = 0; attempt < options.attempts; attempt++) {
    let json: unknown;
    try {
      json = await fetchResult();
    } catch {
      lastOutcome = { kind: "pending" };
      await sleep(options.intervalMs);
      continue;
    }
    const outcome = verifyV2AnchorTransaction(
      expectedTransactionHex,
      expectedTemplate,
      expectedPayload,
      json,
    );
    if (outcome.kind !== "pending") {
      return outcome;
    }
    lastOutcome = outcome;
    await sleep(options.intervalMs);
  }
  return lastOutcome ?? { kind: "pending" };
}
