# Private ballot Internet transport threat model V1

## Scope

This is a proposed design threat model, not implementation evidence. It covers
future delivery of exact canonical BallotPackageV1 bytes to the 5A11 intake
boundary. Current V1 ballots have PUBLIC ballot confidentiality: anonymous
eligibility, private transport, and ballot-content secrecy are distinct.

| Threat | Status | Protection, limitation, or assumption |
| --- | --- | --- |
| Malformed or malicious voter package | Protected | Strict bounded decode and existing proof/payload verification reject it. |
| Duplicate voter, replay, different Tor circuits | Protected | Election-scoped nullifier accepts at most the first valid ballot. |
| Gateway invents a valid vote | Partially protected | Frozen registry plus Triptych eligibility/nullifier prevent it without a credential; compromised credential/client remains a risk. |
| Malicious gateway | Partially protected | It can suppress, delay, log readable ballots, or lie until independent commitment/inclusion evidence exposes inconsistency. |
| Malicious privacy relay | Partially protected | It sees network source metadata but not compliant HPKE/OHTTP plaintext; it can drop, delay, fingerprint, or log. |
| Relay and gateway collude | Not protected | They can correlate relay source metadata with gateway-readable ballots. |
| Passive ISP or hostile local network | Partially protected | Tor hides origin/destination relation under normal assumptions; timing and volume remain visible. |
| Tor exit | Protected in onion mode | Onion-service traffic has no Tor exit; compromised relays can still aid stronger traffic analysis. |
| Malicious organizer | Partially protected | Cannot invent eligible proof without credential, but controls availability, policy, and distribution. |
| Server/memory compromise | Not protected | Keys, queue, plaintext, and logs may be exposed; isolation and retention limits only reduce impact. |
| Log compromise | Partially protected | Policy avoids source-to-ballot records; unsafe defaults or forensic data can still deanonymize. |
| External/global network observer | Not protected | Batching and padding reduce simple correlation, not global traffic analysis. |
| DoS/censorship | Partially protected | Limits, queues, alternate private route, and offline export help but cannot guarantee availability. |
| Modification/replay | Protected | Authenticated envelope plus exact validation and nullifier rule reject alteration/second acceptance. |
| Delayed submission | Partially protected | Policy/lifecycle provide status but cannot stop blocking until close. |
| Ballot suppression | Partially protected | Collector receipt plus missing inclusion exposes non-inclusion; it cannot force a silent service. |
| Forged receipt | Partially protected | Requires descriptor-pinned signatures; descriptor authentication is not yet implemented. |
| Malicious client or malware | Not protected | It can reveal secret/selection or use an unsafe route before encryption. |
| Voter disclosure, coercion, vote selling | Not protected | Local package, receipt, and inclusion proof may be shown to a coercer. |

## Timing, size, and small-election limits

Immediate public release or per-ballot success exposes a timing link. The future
system holds opaque padded requests, requires both an elapsed-time and a
population threshold, then seals/shuffles a batch. Election-close processing of
an underpopulated batch is allowed only with a clear reduced-anonymity marker.
A one-voter batch, voter self-announcement, few unvoted members, and
distinctive outcome remain statistical disclosure problems.

A descriptor-selected fixed envelope size hides ordinary YES/NO/ABSTAIN and
selection-count length differences. It does not conceal an over-limit attempt,
packet timing, transfer existence, route choice, or a compromised device.

## DoS controls without voter identity

Reject oversized packets before allocation; use bounded queues, memory, worker
concurrency, per-connection timeouts, cheap envelope checks before expensive
proof verification, and aggregate short-lived connection throttles. Measure
queue depth and coarse failure counts, not voter identifiers. Do not use
cookies, permanent client tokens, voter API keys, third-party analytics, or
CAPTCHAs that become identity side channels. Proof-of-work is not default and
needs a separate accessibility/fingerprinting review. Tor limits must not treat
a shared source as a voter identity.

## Logging policy

| Component | Minimal allowed | Prohibited |
| --- | --- | --- |
| Client | Local user-visible status; opt-in diagnostics | Credentials, package/proof contents, durable network IDs, telemetry/analytics. |
| Tor component | Service health, protected and short-retained | Application-to-circuit correlation and default exported debug logs. |
| Relay | Aggregate counters and coarse error classes | Request bodies, IP plus request ID, forwarding headers, cookies, exact event time. |
| Collector | Queue health and coarse batch counts | Ciphertext after handoff, circuit/source metadata paired with package/batch, high-resolution intake time. |
| Gateway | Aggregate verification outcomes and batch ID | Routine ballot/proof logging, IP/forwarded headers, receipt secrets, per-request tracing. |

Use coarse periodic aggregation, documented short retention, access control, and
deletion verification. Disable/scrub crash dumps, packet capture, debug tracing,
and APM on sensitive paths.

## Proxy and cloud requirements

Nginx, Apache, Caddy, CDNs, WAFs, load balancers, and clouds commonly preserve
IP, timing, headers, URLs, sizes, TLS/session data, trace IDs, and bodies.
Sensitive paths must disable access/body logging; strip X-Forwarded-For and
PROXY protocol before the gateway; disable CDN/WAF analytics/replay; and treat
any TLS terminator as part of the sensitive boundary. Cloud request logs, flow
logs, centralized SIEM, tracing/APM, error trackers, crash dumps, backups, and
support captures require explicit minimization/opt-out. Operators must verify
effective configuration before activation.

## Receipt-freeness and residual assumptions

A voter who can prove inclusion of an exact package and knows its plaintext
selection can often demonstrate that information to a coercer. The pilot may
eventually claim individual inclusion verification, not coercion resistance,
receipt-freeness, or vote-selling prevention. Those need major cryptographic and
UX redesign and are out of V1 scope.

The design assumes an honest voter device and displayed configuration; normal Tor
origin separation rather than a global adversary; non-colluding relay/gateway in
split-trust mode; adequate batch policy; authenticated transport keys; and the
existing Triptych/registry/lifecycle/nullifier checks.
