export interface AnchorDeploymentTemplateConfig {
  address: string;
  module: string;
  function: string;
  eventTopic: string;
  artifactDigestHex: string;
}

export type AnchorDeploymentStatus = "current" | "superseded" | "historical" | "unverified";

/** Public release identity only. No wallet, organizer, voter, or election data belongs here. */
export interface AnchorDeploymentRegistryEntry {
  network: string;
  status: AnchorDeploymentStatus;
  template: AnchorDeploymentTemplateConfig;
  publishTransactionId: string | null;
  notes: string;
}

export interface AnchorDeploymentConfig {
  esmeralda: AnchorDeploymentTemplateConfig | null;
  mainnet: AnchorDeploymentTemplateConfig | null;
}

export const ESMERALDA_V2_TEMPLATE_ADDRESS =
  "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee";
export const ESMERALDA_V2_ARTIFACT_DIGEST_HEX =
  "ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908";

export const MAINNET_V2_ARTIFACT_DIGEST_HEX =
  "6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830";
export const MAINNET_V2_TEMPLATE_ADDRESS =
  "template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb";
export const MAINNET_V2_PUBLISH_TRANSACTION_ID =
  "a898f8daaa0ae25095a02f69e5753e38dfe4a9c99c546d26297e08b81a3aa79c";

export const V2_TEMPLATE_MODULE = "tari_private_ballot_anchor_v2";
export const V2_TEMPLATE_FUNCTION = "publish_anchor_v2";
export const V2_EVENT_TOPIC_SUFFIX = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";
export const V2_CANONICAL_RECEIPT_TOPIC_PREFIX = "TariPrivateBallotAnchorV2";

export function v2CanonicalReceiptTopic(): string {
  return `${V2_CANONICAL_RECEIPT_TOPIC_PREFIX}.${V2_EVENT_TOPIC_SUFFIX}`;
}

function deployment(
  address: string,
  artifactDigestHex: string,
): AnchorDeploymentTemplateConfig {
  return {
    address,
    module: V2_TEMPLATE_MODULE,
    function: V2_TEMPLATE_FUNCTION,
    eventTopic: v2CanonicalReceiptTopic(),
    artifactDigestHex,
  };
}

/**
 * Browser-side projection of the checked-in release registry. It intentionally
 * records historical deployments but only exposes a unique `current` entry to
 * the request-creation path. The Rust deployment registry carries the same
 * public identities for native release tooling.
 */
export const RELEASED_V2_DEPLOYMENT_REGISTRY: readonly AnchorDeploymentRegistryEntry[] = [
  {
    network: "mainnet",
    status: "current",
    template: deployment(MAINNET_V2_TEMPLATE_ADDRESS, MAINNET_V2_ARTIFACT_DIGEST_HEX),
    publishTransactionId: MAINNET_V2_PUBLISH_TRANSACTION_ID,
    notes: "Reviewed Mainnet V2 deployment; selectable for new browser anchor requests.",
  },
  {
    network: "esmeralda",
    status: "historical",
    template: deployment(ESMERALDA_V2_TEMPLATE_ADDRESS, ESMERALDA_V2_ARTIFACT_DIGEST_HEX),
    publishTransactionId: null,
    notes: "Pre-reset Esmeralda V2 deployment retained for evidence only; never selectable for new requests.",
  },
];

export function currentDeploymentForNetwork(
  network: string,
): AnchorDeploymentTemplateConfig | null {
  const entries = RELEASED_V2_DEPLOYMENT_REGISTRY.filter((entry) =>
    entry.network === network && entry.status === "current"
  );
  // A missing or ambiguous release state must never be used to create a request.
  return entries.length === 1 ? entries[0].template : null;
}

export function anchorDeploymentConfig(): AnchorDeploymentConfig {
  return {
    esmeralda: currentDeploymentForNetwork("esmeralda"),
    mainnet: currentDeploymentForNetwork("mainnet"),
  };
}

export function deploymentForNetwork(
  config: AnchorDeploymentConfig,
  network: string,
): AnchorDeploymentTemplateConfig | null {
  if (network === "esmeralda") return config.esmeralda;
  if (network === "mainnet") return config.mainnet;
  return null;
}

export function mainnetPublishBlocker(
  config: AnchorDeploymentConfig,
): string | null {
  return config.mainnet === null
    ? "Mainnet anchor publishing is disabled until exactly one current Mainnet V2 deployment is configured."
    : null;
}
