# walletd Distribution Recommendation

Status: RECOMMENDED for initial public source. Redistribution model, upstream
licensing, and provenance remain a HUMAN DECISION before any release that
ships walletd bytes.

## Known runtime (development)

The development runtime observed on the maintainer's machine during
controlled-alpha work:

- Version: `walletd 0.39.2`
- SHA-256: `0B833CBF3ECBF8D3D33DAFF8CECCA900C602436A3C22A7D8ECD65014FC932C3A`

Only the binary was present in the maintainer's isolated runtime folder; no
local license/provenance file accompanied it. Upstream licensing, official
distribution channel, and update process for `walletd` are outside the scope
of this repository and must be reconfirmed from upstream Tari/Ootle sources
before any redistribution decision.

## Options

**A. User installs walletd separately (RECOMMENDED for the initial public
source release).**

- The app assumes an operator-installed walletd reachable at the operator's
  chosen JSON-RPC URL (typically `http://127.0.0.1:5100/json_rpc`).
- The public repository does not carry a walletd binary, an installer for
  walletd, or an auto-download step.
- Public docs explain how to install a compatible walletd from upstream and
  how to point the app at it.
- Advantages: no redistribution risk, no update responsibility, no installer
  trust question, no license/provenance ambiguity.
- Trade-off: extra step for operators.

**B. Helper downloads official upstream walletd on demand.**

- The app fetches walletd from a fixed upstream URL, verifies a pinned
  hash, and stores it in the operator's user-scoped data directory.
- Advantages: near-one-click, provenance is a fixed upstream artifact.
- Trade-offs: an updater is a new attack surface; requires stable upstream
  URLs and hashes; requires ongoing responsibility for pinned versions.

**C. Separate upstream-derived release asset.**

- Ship a companion release archive alongside a Private Ballot release
  containing a specific walletd version with hashes and its upstream
  license.
- Advantages: single-download experience for operators without an in-app
  updater.
- Trade-offs: this **is** redistribution — requires explicit upstream
  license and provenance confirmation.

**D. Bundled installer (NOT recommended for initial public source).**

- The MSI/NSIS installer includes walletd.
- Trade-offs: full redistribution responsibility, most restrictive on
  upstream licensing, hardest to update.

## Recommendation

Ship the initial public source under Option A. Do not bundle, embed, or copy
walletd into the Git tree. Do not sign or checksum a walletd binary as if it
were a project deliverable. Reconsider Options B or C only after upstream
licensing, provenance, and update policy are documented and reviewed by the
maintainer.

## Public source requirements regardless of option chosen

- No walletd binary is committed to Git.
- No `walletd.exe` / equivalent is included in the shipped `.msi` / `.exe`
  installer built from this repository, unless Option D is explicitly chosen
  after a licensing review.
- No wallet API key, wallet database, seed material, or credentials from a
  real walletd runtime are ever committed, staged, uploaded, or attached to a
  release.
