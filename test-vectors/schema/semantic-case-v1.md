# Semantic rejection case schema V1

`scenario.json` contains:

- `schema`: `phase2-semantic-rejection-case-v1`;
- `vector_id`: stable case identifier;
- `scenario`: public-API scenario selector;
- `execution`: `constructed-public-api-scenario`.

`expected.json` contains:

- `schema`: `phase2-semantic-rejection-expected-v1`;
- the matching `vector_id`;
- `accepted: false`;
- the exact `expected_rejection_code`.

The Rust harness is authoritative for scenario construction. JSON files are
public metadata and are not canonical CBOR, signed protocol objects, or hash
preimages.
