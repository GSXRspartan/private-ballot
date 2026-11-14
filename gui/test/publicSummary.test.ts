import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { parseCanonicalPublicSummaryV2 } from "../src/wallet/publicSummary.ts";

function canonical(): string {
  return JSON.stringify({
    schema: "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2", version: 2, network: "mainnet",
    election_id: "election-1", question: "Adopt?", eligible_voters: 2, accepted_ballots: 2,
    rejected_ballots: 0, results: [{ label: "Yes", machine_id: "01", votes: 2 }],
    ballot_kind: "approval", confidentiality_mode: "aggregate", proof_suite: "triptych-v1",
    manifest_hash: "11".repeat(32), archive_hash: "22".repeat(32),
    voter_registry_commitment: "33".repeat(32), ballot_option_commitment: "44".repeat(32),
    archive_finalized: true, finalized_timestamp_unix_secs: null,
    template_address: "template_" + "55".repeat(32), template_module: "tari_private_ballot_anchor_v2",
    template_function: "publish_anchor_v2", template_event_topic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    template_artifact_digest: "66".repeat(32),
  });
}

describe("canonical V2 public summary", () => {
  it("accepts the native field order and exposes its bound election identity", () => {
    const parsed = parseCanonicalPublicSummaryV2(canonical());
    assert.equal(parsed.network, "mainnet");
    assert.equal(parsed.electionId, "election-1");
    assert.equal(parsed.archiveHashHex, "22".repeat(32));
  });

  it("rejects reordered, expanded, or non-finalized summary text", () => {
    assert.throws(() => parseCanonicalPublicSummaryV2(canonical().replace('"version":2,"network"', '"network":"mainnet","version":2,"network"')));
    assert.throws(() => parseCanonicalPublicSummaryV2(canonical().replace('"archive_finalized":true', '"archive_finalized":false')));
    assert.throws(() => parseCanonicalPublicSummaryV2(canonical().replace('"schema"', '"unexpected":1,"schema"')));
  });
});
