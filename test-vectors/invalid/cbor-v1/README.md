# Canonical CBOR hostile corpus V1

This corpus targets the protocol's strict canonical CBOR boundary and the
currently implemented version-one registry, candidate-set, and approval-payload
decoders.

The corpus is deterministic and dependency-free. It is not a substitute for a
coverage-guided fuzzing engine or an independently implemented decoder.

Case order has no protocol meaning. Vector identifiers are stable and must not
be silently reused for different bytes or expected rejection codes.
