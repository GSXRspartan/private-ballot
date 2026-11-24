# First real Mainnet V2 anchor — independent verification report

Scope: read-only verification of the first funded Tari Ootle Mainnet anchor
published through the Hosted Private Ballot website with Sapient. Nothing in
this report was produced by re-submitting a transaction.

## Subject

| Item | Value |
|---|---|
| Transaction ID | `28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2` |
| Explorer | https://explorer.tari.mw/tx/28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2 |
| Network | `mainnet`, network byte `0` (both indexers, epoch `39295`) |
| Election | `pb-staging-browser-e2e-1795362392453` |
| V2 template | `template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb` |
| Template artifact digest | `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830` |
| Anchor digest | `a6cb28b68e8e821c6257183bb16b29bc9d0e42f4e20bdc771cdf55dfd7528588` |
| Archive hash | `c3112b3b6a14acbb95a3ff021e0a9ffca67df54c0d55ceef26f4e3fa040c0bd7` |
| Event topic | `TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` |
| Event function | `publish_anchor_v2` |

## Sources (independent of the website's "Verified" message)

- `https://indexer-a.ootle.tari.com/network` and `https://indexer-b.ootle.tari.com/network`
- `https://indexer-a.ootle.tari.com/transactions/{tx}/result?include_proof=true`
- `https://indexer-a.ootle.tari.com/transaction-receipts/{tx}`
- `https://indexer-b.ootle.tari.com/transaction-receipts/{tx}`
- `https://indexer-a.ootle.tari.com/transactions/events?topic=TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2`
- `https://indexer-b.ootle.tari.com/transactions/events?topic=TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2`

The REST routes are the public indexer API documented by
`docs.rs/tari_indexer_client` (`get_transaction_result` →
`/transactions/{transaction_id}/result`, `get_transaction_receipt` →
`/transaction-receipts/{address}`, `query_transaction_events` →
`/transactions/events`). See also the Tari exchange-integration guide's
"Checking the indexer directly" section.

## Observed result

- Both indexers report `{"network":"mainnet","network_byte":0,"epoch":39295}`.
- Indexer-a transaction result: `{"Finalized":{"final_decision":"Commit", ...}}`,
  `abort_details: null`, `finalized_time: "2026-11-23 07:04:13.0"`.
  There is no `Rejected` branch, no `Abort`, and no `FeeIntentCommit`.
- The response includes a proven receipt (`proof.anchor` epoch `39295`, shard
  group `1..=256`, height `83`, block
  `16eefa43094a825670e3b406baca6b8887e031fee36708f29b65e6890a60e937`,
  state root `3ff64911fca2d4a2ca0614a3e83e9ee96ef05c784003ebc2fd45d66bc33366ad`)
  with quorum certificates and a `value_proof`.
- Indexer-b's `/transactions/{tx}/result` answered 404, but indexer-b served the
  identical durable receipt and identical event. This is consistent with
  result lookups being local to the indexer that received the submission,
  while receipts and events are synced from the network. Finality is therefore
  established from indexer-a's finalized result plus the two independently
  synced receipt copies, not from a single UI message.

## Decoded receipt and event

The project's own strict decoders
(`gui/src/wallet/executeResult.ts`, `gui/src/wallet/transactionReceipt.ts`)
were run against the raw base64 CBOR from the indexers:

- Execution result: transaction hash equals the subject transaction id,
  `execute_epoch = 39270`, `resultVariant = "accept"` (not `fee_only`, not
  `reject`), two events: `std.vault.pay_fee` and the V2 anchor event.
- Durable receipt: outcome `Commit` (variant 0, not `FeeIntentCommit`),
  epoch `39270`, two events.
- `verifyV2AnchorExecutionResult` and `verifyDurableTransactionReceiptBase64`
  both returned identical evidence:
  `{ transactionIdHex: <subject tx>, epoch: 39270, eventIndex: 1 }`.

The V2 event has exactly four text metadata fields, all matching the expected
identity byte-for-byte:

| Field | Observed value |
|---|---|
| `anchor_digest_v2` | `a6cb28b68e8e821c6257183bb16b29bc9d0e42f4e20bdc771cdf55dfd7528588` |
| `election_id` | `pb-staging-browser-e2e-1795362392453` |
| `network` | `mainnet` |
| `public_summary` | canonical `TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2` v2 JSON |

Template binding in the event: template `ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb`,
module `tari_private_ballot_anchor_v2`, function `publish_anchor_v2`, event
topic `TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2`
(the emitted receipt topic; the ABI binding topic is the lowercase-module form),
artifact digest `6ea3448e...06830`.

### Public information published

The canonical summary contains only aggregate/public fields: schema, version,
network, election id, question, eligible/accepted/rejected counts, tally
labels with machine ids and vote counts, ballot kind, confidentiality mode,
proof suite, manifest hash, archive hash, voter-registry commitment,
ballot-option commitment, `archive_finalized`, finalized timestamp (null), and
the template identity fields. No voter credential, nullifier, invitation,
ballot plaintext, signing seed, or local path appears in the event. This matches
the fixed-shape V2 payload and its `assert_v2_public_payload_is_leak_free`
guard (`crates/anchor/src/public_payload_v2.rs`).

The demonstration election had two eligible voters and two accepted ballots;
its result is `No=2`, `Yes=0`. It is a `NON_BINDING_APPROVAL_PILOT` with
`PUBLIC` confidentiality mode — no anonymity beyond those two voters is
claimed.

## Actual fee

The CBOR `FeeReceipt` fields are
`(total_fee_payment = 5000, total_fees_paid = 3477, overcharge = 0, breakdown, exhaust_burn = 3477)`
and the `std.vault.pay_fee` instruction carries `amount = 5000` microTARI.
The realized **fee paid was 3477 microTARI (0.003477 TARI)**, matching the
independent Sapient dry-run evidence (`total_fees_required = 3477`) recorded in
`docs/hosted/mainnet-fee-preflight-design.md`. The authorized ceiling was
5000 microTARI (0.005 TARI) and was not exceeded.

## Duplicate anchor check

The topic-filtered event query on **both** indexers returned exactly one event
for this topic, with the same transaction id and the same event CBOR
(SHA-256 `448f065189cbb627996544cdce862a296a7ca0c17c48f09bb0dd2d94ab7aed37`).
No second funded anchor publication for this election was found.

## Reproduce

```powershell
$tx = "28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2"
curl.exe "https://indexer-a.ootle.tari.com/network"
curl.exe "https://indexer-a.ootle.tari.com/transactions/$tx/result?include_proof=true"
curl.exe "https://indexer-a.ootle.tari.com/transaction-receipts/$tx"
curl.exe "https://indexer-b.ootle.tari.com/transaction-receipts/$tx"
curl.exe "https://indexer-a.ootle.tari.com/transactions/events?topic=TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2"
curl.exe "https://indexer-b.ootle.tari.com/transactions/events?topic=TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2"
```

Feed the `execution_result` and `receipt` base64 strings into the project
decoders; see `gui/test/mainnetAnchorReceipt.test.ts`, whose fixture
(`gui/test/mainnetAnchorVectors.generated.ts`) was generated from these exact
read-only responses.

## Conclusion

Chain finality: **VERIFIED** (finalized `Commit`, proven receipt, full
execution `accept`, exact V2 event). Fee-intent-only, rejection, and incomplete
execution are excluded. The browser's "Verified" message is corroborated by
independent chain evidence and is not the basis of this conclusion.
