import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  AnchorBundleError,
  bundleAnchorArgsAsLiterals,
  bundleDigestKey,
  buildAnchorInstructions,
  parseAnchorBundle,
  parseAnchorBundleJson,
} from "../src/wallet/anchorBundle.ts";
import {
  ESMERALDA_V2_TEMPLATE_ADDRESS,
  anchorDeploymentConfig,
  deploymentForNetwork,
  mainnetPublishBlocker,
} from "../src/wallet/anchorDeploymentConfig.ts";
import { encodeCborTextLiteral } from "../src/wallet/cborLiteral.ts";

function validBundle(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    network: "esmeralda",
    template: {
      address: ESMERALDA_V2_TEMPLATE_ADDRESS,
      module: "tari_private_ballot_anchor_v2",
      function: "publish_anchor_v2",
      eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
      artifactDigestHex: anchorDeploymentConfig().esmeralda.artifactDigestHex,
    },
    anchorArgs: {
      anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
      network: "esmeralda",
      electionId: "5e50e17c401682fb38dbea349a4c2713",
      publicSummary: '{"election_id":"5e50e17c401682fb38dbea349a4c2713"}',
    },
  };
}

describe("anchor bundle parsing", () => {
  it("accepts a well-formed bundle and exposes verifier expectations", () => {
    const bundle = parseAnchorBundle(validBundle());
    assert.equal(bundle.network, "esmeralda");
    assert.equal(
      bundle.template.address,
      "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee",
    );
    assert.deepEqual(bundleAnchorArgsAsLiterals(bundle), [
      "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
      "esmeralda",
      "5e50e17c401682fb38dbea349a4c2713",
      '{"election_id":"5e50e17c401682fb38dbea349a4c2713"}',
    ]);
  });

  it("parses from JSON text and rejects malformed JSON", () => {
    assert.doesNotThrow(() => parseAnchorBundleJson(JSON.stringify(validBundle())));
    assert.throws(() => parseAnchorBundleJson("{not json"), AnchorBundleError);
  });

  it("rejects each malformed field with a bounded reason", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["schema_version", { ...validBundle(), schemaVersion: 2 }],
      ["network", { ...validBundle(), network: "" }],
      ["template_address", {
        ...validBundle(),
        template: {
          ...validBundle().template,
          address: "template_UPPERHEXHEXHEXHEXHEXHEXHEXHEXHEXHEXHEXHEXHEXHEXHE",
        },
      }],
      ["artifact_digest", {
        ...validBundle(),
        template: {
          ...validBundle().template,
          artifactDigestHex: "abcd",
        },
      }],
      ["anchor_digest", {
        ...validBundle(),
        anchorArgs: {
          ...validBundle().anchorArgs,
          anchorDigestHex: "ZZ",
        },
      }],
      ["election_id", {
        ...validBundle(),
        anchorArgs: { ...validBundle().anchorArgs, electionId: "" },
      }],
      ["public_summary", {
        ...validBundle(),
        anchorArgs: { ...validBundle().anchorArgs, publicSummary: "" },
      }],
    ];
    for (const [expectedReason, malformed] of cases) {
      try {
        parseAnchorBundle(malformed);
        assert.fail(`expected rejection for ${expectedReason}`);
      } catch (error) {
        assert.ok(error instanceof AnchorBundleError);
        assert.equal((error as AnchorBundleError).reason, expectedReason);
      }
    }
  });

  it("builds the canonical CallFunction instruction with CBOR literal args", () => {
    const bundle = parseAnchorBundle(validBundle());
    const instructions = buildAnchorInstructions(bundle);
    assert.equal(instructions.length, 1);
    const call = instructions[0] as { CallFunction: Record<string, unknown> };
    const callFn = call.CallFunction;
    assert.equal(callFn.address, ESMERALDA_V2_TEMPLATE_ADDRESS);
    assert.equal(callFn.function, "publish_anchor_v2");
    const args = callFn.args as Array<{ Literal: string }>;
    assert.equal(args.length, 4);
    // Literal hex is the tari_bor CBOR of each string value (Rust vectors).
    assert.equal(args[0].Literal, encodeCborTextLiteral(bundle.anchorArgs.anchorDigestHex));
    assert.equal(args[1].Literal, encodeCborTextLiteral(bundle.anchorArgs.network));
    assert.equal(args[2].Literal, encodeCborTextLiteral(bundle.anchorArgs.electionId));
    assert.equal(args[3].Literal, encodeCborTextLiteral(bundle.anchorArgs.publicSummary));
  });

  it("keys recovery by network + artifact + anchor digest, never by secrets", () => {
    const bundle = parseAnchorBundle(validBundle());
    const key = bundleDigestKey(bundle);
    assert.match(key, /^pb-anchor-bundle:esmeralda:/);
    assert.equal(key.includes("publicSummary"), false);
    assert.equal(key.includes("election"), false);
  });
});

describe("deployment configuration", () => {
  it("keeps the esmeralda deployment configured from the verified record", () => {
    const config = anchorDeploymentConfig();
    assert.equal(config.esmeralda.module, "tari_private_ballot_anchor_v2");
    assert.equal(config.esmeralda.function, "publish_anchor_v2");
    assert.equal(
      config.esmeralda.eventTopic,
      "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    );
    assert.equal(
      config.esmeralda.address,
      "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee",
    );
  });

  it("disables mainnet publishing while no mainnet template address is configured", () => {
    const config = anchorDeploymentConfig();
    assert.equal(config.mainnet, null);
    assert.match(
      mainnetPublishBlocker(config) ?? "",
      /disabled until a configured mainnet V2 template address/,
    );
    assert.equal(deploymentForNetwork(config, "mainnet"), null);
    assert.equal(mainnetPublishBlocker(config) !== null, true);
  });
});
