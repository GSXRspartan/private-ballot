# Hosted Mode privacy disclosure (staging text)

Used verbatim by the Hosted Mode page. Do not soften these statements.

## What Hosted Mode protects

- Ballot cryptography runs **client-side** in your browser (WebAssembly).
- Your **voter secret never leaves the browser**: it is held in memory
  for the active tab session only — never in the URL, local storage,
  server storage, or logs.
- The backend verifies the **cryptographic envelope** (Triptych proof +
  public payload) before accepting anything. This is the same canonical
  package a Desktop archive contains.

## What Hosted Mode does NOT protect

- Hosted Mode is **NOT network-anonymous**. Desktop/Tor remains the
  stronger privacy mode.
- Your network provider, Cloudflare, and the VPS can observe **transport
  metadata**: your IP address, request timing, request sizes, and which
  election you interacted with.
- Cloudflare may retain its own edge logs (IPs, user agents, request
  paths) under its own retention policy, separate from what Private
  Ballot stores (which is: election packages, ballots, nullifiers,
  receipts — **no IP addresses, no secrets, no witnesses**).
- Private Ballot never derives voter identity from IP and never stores
  it. The backend does not log client IPs.
- A compromised browser, a malicious extension, or a proof-generator
  vulnerability in the browser environment is out of scope for the
  hosted deployment. Review the frontend bundle (zero runtime
  dependencies, no CDNs, no analytics) if that matters to you.

## What the staging operator sees

- Backend logs: method, path, status, duration only.
- Database: public election data + accepted ballot packages + receipts.
- Nothing else. No voter secret can appear in either; a storage test
  (`stored_ballot_does_not_contain_voter_secret`) guards this.
