# Transport admission and close V1

Implemented semantics (authoritative two-state lifecycle fence):

* The organizer GUI owns one AUTHORITATIVE append-only election lifecycle
  (`FROZEN -> OPEN -> CLOSED -> VERIFIED -> FINALIZED`). Every committed
  transition is published to the running private-intake collector's
  authoritative fence; the collector worker never decides lifecycle truth
  itself.
* CLOSE fences the collector BEFORE the authoritative close commit (fail
  closed), so a submission whose admission begins after the close can never
  pass an OPEN fence or be ACCEPTED past the cutoff. OPEN publishes only after
  its own commit succeeds, so an early OPEN can never admit ballots before the
  election truly opened.
* While the fence is not `OPEN`, every envelope is refused (503) before any
  decryption, validation, or durable work. No receipt can claim acceptance
  outside the authoritative open state. Client clocks, relay arrival, and
  queue arrival are not authority.
* A ballot whose admission began while `OPEN` may finish its durable hand-off:
  the collector writes the exact canonical package into an app-owned,
  election-scoped, CONTENT-ADDRESSED durable inbox ALWAYS before an ACCEPTED
  receipt is issued. A write failure fails the request closed so a retry
  self-heals the hand-off.
* Organizer inbox reconciliation is permitted while `CLOSED` so such
  already-admitted packages are never orphaned by a crash between collector
  acceptance and workspace reconciliation. Generic/new ballot import remains
  forbidden at `CLOSED` on every application path, and reconciliation is
  refused outright once results are sealed (`VERIFIED`/`FINALIZED`).

Accepted residual trust assumption (local host, not remote): during the
`CLOSED -> VERIFIED` drain window, reconciliation trusts PRESENCE in the
election-scoped app-owned durable inbox. There is deliberately no per-file
attestation of pre-close admission: every secret that could produce one lives
on the same organizer host, so such evidence would add nothing against an
attacker who can already write there (and could tamper with the durable
workspace equally). An attacker with organizer-host filesystem write access
could therefore plant a package in that directory during this window and have
it reconciled by the next sync. This is a LOCAL-HOST trust-boundary risk, NOT
a remote collector bypass: the network admission fence refuses everything not
admitted while `OPEN`, and remote voters cannot write the inbox.
