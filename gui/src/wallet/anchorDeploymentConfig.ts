export interface AnchorDeploymentTemplateConfig {
  address: string;
  module: string;
  function: string;
  eventTopic: string;
  artifactDigestHex: string;
}

export interface AnchorDeploymentConfig {
  esmeralda: AnchorDeploymentTemplateConfig;
  mainnet: AnchorDeploymentTemplateConfig | null;
}

export const ESMERALDA_V2_TEMPLATE_ADDRESS =
  "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee";
export const ESMERALDA_V2_ARTIFACT_DIGEST_HEX =
  "ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908";

export const MAINNET_V2_ARTIFACT_DIGEST_HEX =
  "6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830";
export const MAINNET_V2_TEMPLATE_ADDRESS = "";

export const V2_TEMPLATE_MODULE = "tari_private_ballot_anchor_v2";
export const V2_TEMPLATE_FUNCTION = "publish_anchor_v2";
export const V2_EVENT_TOPIC_SUFFIX = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";
export const V2_CANONICAL_RECEIPT_TOPIC_PREFIX = "TariPrivateBallotAnchorV2";

export function v2CanonicalReceiptTopic(): string {
  return `${V2_CANONICAL_RECEIPT_TOPIC_PREFIX}.${V2_EVENT_TOPIC_SUFFIX}`;
}

function esmeraldaConfig(): AnchorDeploymentTemplateConfig {
  return {
    address: ESMERALDA_V2_TEMPLATE_ADDRESS,
    module: V2_TEMPLATE_MODULE,
    function: V2_TEMPLATE_FUNCTION,
    eventTopic: v2CanonicalReceiptTopic(),
    artifactDigestHex: ESMERALDA_V2_ARTIFACT_DIGEST_HEX,
  };
}

export function anchorDeploymentConfig(): AnchorDeploymentConfig {
  const mainnet =
    MAINNET_V2_TEMPLATE_ADDRESS.length > 0
      ? {
          address: MAINNET_V2_TEMPLATE_ADDRESS,
          module: V2_TEMPLATE_MODULE,
          function: V2_TEMPLATE_FUNCTION,
          eventTopic: v2CanonicalReceiptTopic(),
          artifactDigestHex: MAINNET_V2_ARTIFACT_DIGEST_HEX,
        }
      : null;
  return { esmeralda: esmeraldaConfig(), mainnet };
}

export function deploymentForNetwork(
  config: AnchorDeploymentConfig,
  network: string,
): AnchorDeploymentTemplateConfig | null {
  if (network === "esmeralda") {
    return config.esmeralda;
  }
  if (network === "mainnet") {
    return config.mainnet;
  }
  return null;
}

export function mainnetPublishBlocker(
  config: AnchorDeploymentConfig,
): string | null {
  return config.mainnet === null
    ? "Mainnet anchor publishing is disabled until a configured mainnet V2 template address is released."
    : null;
}
