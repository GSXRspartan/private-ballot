import type { ExpectedAnchorEventPayload, ExpectedAnchorTemplate } from "./verifyReceipt.ts";
import { encodeCborTextLiteral } from "./cborLiteral.ts";
import {
  V2_CANONICAL_RECEIPT_TOPIC_PREFIX,
  V2_EVENT_TOPIC_SUFFIX,
} from "./anchorDeploymentConfig.ts";

export interface AnchorBundleV1 {
  schemaVersion: 1;
  network: string;
  template: {
    address: string;
    module: string;
    function: string;
    eventTopic: string;
    artifactDigestHex: string;
  };
  anchorArgs: {
    anchorDigestHex: string;
    network: string;
    electionId: string;
    publicSummary: string;
  };
}

export type AnchorBundleInvalid =
  | "schema_version"
  | "network"
  | "template_address"
  | "template_module"
  | "template_function"
  | "event_topic"
  | "artifact_digest"
  | "anchor_digest"
  | "event_network"
  | "network_mismatch"
  | "election_id"
  | "public_summary";

export class AnchorBundleError extends Error {
  readonly reason: AnchorBundleInvalid;

  constructor(reason: AnchorBundleInvalid) {
    super(`the anchor bundle is not usable (${reason})`);
    this.name = "AnchorBundleError";
    this.reason = reason;
  }
}

function isLowercaseHex64(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function bounded(value: string, max: number, min: number = 1): boolean {
  return value.length >= min && value.length <= max;
}

export function parseAnchorBundle(json: unknown): AnchorBundleV1 {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new AnchorBundleError("schema_version");
  }
  const record = json as Record<string, unknown>;
  if (record.schemaVersion !== 1) {
    throw new AnchorBundleError("schema_version");
  }
  const network = record.network;
  if (typeof network !== "string" || !bounded(network, 32)) {
    throw new AnchorBundleError("network");
  }
  const template = record.template;
  if (typeof template !== "object" || template === null || Array.isArray(template)) {
    throw new AnchorBundleError("template_address");
  }
  const t = template as Record<string, unknown>;
  if (
    typeof t.address !== "string" ||
    !t.address.startsWith("template_") ||
    !isLowercaseHex64(t.address.slice("template_".length)) ||
    !bounded(t.address, 128)
  ) {
    throw new AnchorBundleError("template_address");
  }
  if (typeof t.module !== "string" || !bounded(t.module, 128)) {
    throw new AnchorBundleError("template_module");
  }
  if (typeof t.function !== "string" || !bounded(t.function, 128)) {
    throw new AnchorBundleError("template_function");
  }
  if (typeof t.eventTopic !== "string" || !bounded(t.eventTopic, 256)) {
    throw new AnchorBundleError("event_topic");
  }
  if (typeof t.artifactDigestHex !== "string" || !isLowercaseHex64(t.artifactDigestHex)) {
    throw new AnchorBundleError("artifact_digest");
  }
  const anchorArgs = record.anchorArgs;
  if (typeof anchorArgs !== "object" || anchorArgs === null || Array.isArray(anchorArgs)) {
    throw new AnchorBundleError("anchor_digest");
  }
  const a = anchorArgs as Record<string, unknown>;
  if (typeof a.anchorDigestHex !== "string" || !isLowercaseHex64(a.anchorDigestHex)) {
    throw new AnchorBundleError("anchor_digest");
  }
  if (typeof a.network !== "string" || !bounded(a.network, 32)) {
    throw new AnchorBundleError("event_network");
  }
  if (a.network !== network) {
    throw new AnchorBundleError("network_mismatch");
  }
  if (typeof a.electionId !== "string" || !bounded(a.electionId, 128)) {
    throw new AnchorBundleError("election_id");
  }
  if (
    typeof a.publicSummary !== "string" ||
    !bounded(a.publicSummary, 256 * 1024)
  ) {
    throw new AnchorBundleError("public_summary");
  }
  return {
    schemaVersion: 1,
    network,
    template: {
      address: t.address,
      module: t.module,
      function: t.function,
      eventTopic: t.eventTopic,
      artifactDigestHex: t.artifactDigestHex,
    },
    anchorArgs: {
      anchorDigestHex: a.anchorDigestHex,
      network: a.network,
      electionId: a.electionId,
      publicSummary: a.publicSummary,
    },
  };
}

export function parseAnchorBundleJson(text: string): AnchorBundleV1 {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new AnchorBundleError("schema_version");
  }
  return parseAnchorBundle(json);
}

export function bundleExpectedTemplate(bundle: AnchorBundleV1): ExpectedAnchorTemplate {
  return {
    templateAddressHex: bundle.template.address.slice("template_".length),
    eventTopic: bundle.template.eventTopic,
  };
}

export function bundleExpectedPayload(bundle: AnchorBundleV1): ExpectedAnchorEventPayload {
  return bundle.anchorArgs;
}

export function bundleDigestKey(bundle: AnchorBundleV1): string {
  return `pb-anchor-bundle:${bundle.network}:${bundle.template.artifactDigestHex}:${bundle.anchorArgs.anchorDigestHex}`;
}

export function buildAnchorInstructions(bundle: AnchorBundleV1): unknown[] {
  return [
    {
      CallFunction: {
        // The display form is `template_<hex>`, while the transaction schema
        // serializes TemplateAddress itself as the bare 32-byte hex value.
        address: bundle.template.address.slice("template_".length),
        function: bundle.template.function,
        args: bundleAnchorArgsAsLiterals(bundle).map((value) => ({
          Literal: encodeCborTextLiteral(value),
        })),
      },
    },
  ];
}

export function bundleAnchorArgsAsLiterals(bundle: AnchorBundleV1): string[] {
  return [
    bundle.anchorArgs.anchorDigestHex,
    bundle.anchorArgs.network,
    bundle.anchorArgs.electionId,
    bundle.anchorArgs.publicSummary,
  ];
}

export function canonicalEventTopicFromBindingTopic(fullTopic: string): string {
  const suffix = fullTopic.slice(fullTopic.lastIndexOf(".") + 1);
  if (suffix !== V2_EVENT_TOPIC_SUFFIX) {
    throw new AnchorBundleError("event_topic");
  }
  return `${V2_CANONICAL_RECEIPT_TOPIC_PREFIX}.${suffix}`;
}

export interface DesktopBundleSource {
  network: string;
  templateAddress: string;
  templateArtifactDigestHex: string;
  templateModule: string;
  templateFunction: string;
  preparation: {
    templateEventTopic: string;
    anchorDigestHex: string;
    arguments: string[];
    publicSummaryJson: string;
  };
}

export function buildBundleFromDesktop(source: DesktopBundleSource): AnchorBundleV1 {
  const args = source.preparation.arguments;
  if (
    args.length !== 4 ||
    args[0] !== source.preparation.anchorDigestHex ||
    args[3] !== source.preparation.publicSummaryJson
  ) {
    throw new AnchorBundleError("anchor_digest");
  }
  return parseAnchorBundle({
    schemaVersion: 1,
    network: source.network,
    template: {
      address: source.templateAddress,
      module: source.templateModule,
      function: source.templateFunction,
      eventTopic: canonicalEventTopicFromBindingTopic(source.preparation.templateEventTopic),
      artifactDigestHex: source.templateArtifactDigestHex,
    },
    anchorArgs: {
      anchorDigestHex: args[0],
      network: args[1],
      electionId: args[2],
      publicSummary: args[3],
    },
  });
}

export interface ClipboardLike {
  writeText(text: string): Promise<void>;
}

export async function copyBundleToClipboard(
  bundle: AnchorBundleV1,
  clipboard: ClipboardLike | null,
): Promise<void> {
  if (!clipboard || typeof clipboard.writeText !== "function") {
    throw new Error("the clipboard is not available in this environment");
  }
  await clipboard.writeText(JSON.stringify(bundle, null, 2));
}
