# Private ballot transport privacy claims V1

## Claim discipline

These statements are allowed only for a future implementation that conforms to
the architecture, authenticates its transport descriptor, and passes independent
review. They are not claims for this documentation-only slice.

| May say | Required qualification |
| --- | --- |
| Eligibility is cryptographic, not account-based. | Depends on existing Triptych verification, frozen registry, and election-scoped nullifier. |
| In Tor onion mode the gateway does not receive direct voter IP in the normal design. | Not against client compromise, collusion, bad logs, or global traffic analysis. |
| In relay mode origin and readable ballot are separated. | Requires standard OHTTP/HPKE, authenticated config, independent operators, and non-collusion. |
| Private-route failure does not silently direct-send a ballot. | Requires the production route policy and UI. |
| Published batch evidence omits exact ingress time/source metadata. | Requires the deployment logging/archive policy to be enforced. |
| A voter can independently verify inclusion. | Only after reviewed commitment and inclusion verification are implemented. |
| No voter needs tTARI, a Tari wallet, or a voter Ootle transaction. | Ootle anchoring is operator-side evidence only. |
| Offline export remains available. | It is not an Internet-anonymity mechanism. |

## Statements the project must not make

| Do not say | Reason |
| --- | --- |
| Impossible to trace / anonymous against a global adversary | Timing, compromise, and global observation remain. |
| Tor makes voting anonymous | Tor mitigates ordinary source exposure, not malware, traffic analysis, or censorship. |
| Relay cannot identify you | It sees a source network connection. |
| Gateway never learns who you are | Collusion, logs, client compromise, and external data can defeat separation. |
| Vote content is cryptographically secret | Current V1 ballot confidentiality is PUBLIC. |
| Coercion resistant / receipt-free | Inclusion material can support coercion or vote selling. |
| Received receipt proves vote counted | It proves only opaque collection, not validity, acceptance, or inclusion. |
| No one can suppress a ballot | A service can drop/delay; evidence can detect but not compel delivery. |
| Blockchain voting is free | Operators incur infrastructure/Ootle costs; voters do not pay in this design. |

Before any public Internet release, documentation must name the route,
descriptor fingerprint, operator model, batch policy, retention policy,
small-election limitation, and verified receipt behavior. Otherwise the UI
offers offline export rather than a privacy promise.
