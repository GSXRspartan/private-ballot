# One-Computer Managed Tor Integration Test — Runbook

> **INTERNAL developer/test document.** This is NOT the public Guide. The Tor
> feature is controlled-test-only under the `managed-tor-test` cargo feature.
> Do not use it for a binding or consequential election.

This runbook performs a MANUAL REAL one-computer test of the managed Tor
private-ballot transport using an installed `tor.exe`. All automated tests
remain loopback/fake-Tor only; this document is for the human-run rehearsal.

## Prerequisites

- Windows with PowerShell.
- An already-installed `tor.exe` (Tor Expert Bundle or equivalent). Know its
  **absolute** path.
- The election workspace artifacts (manifest.cbor, registry.cbor,
  option-set.cbor) produced by the organizer Create Election workflow.
- A clean test directory **outside** the repo.

## PowerShell variables to set first

Open a PowerShell terminal and set these once (all three terminals reuse them):

```powershell
$Repo = "C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot"

# REPLACE with your real tor.exe absolute path:
$TorExe = "C:\REPLACE\WITH\REAL\tor.exe"

# REPLACE with a clean test directory outside the repo:
$TestRoot = "C:\private-ballot-one-pc-test"

# REPLACE with your exported election artifact paths:
$Manifest = "C:\REPLACE\WITH\REAL\manifest.cbor"
$Registry = "C:\REPLACE\WITH\REAL\registry.cbor"
$OptionSet = "C:\REPLACE\WITH\REAL\option-set.cbor"
```

## Build the managed-tor-test binaries

```powershell
cd $Repo

# Provision + intake binaries (transport-gateway with the feature):
cargo +stable-x86_64-pc-windows-msvc build `
    -p tari-cc-private-ballot-transport-gateway `
    --features managed-tor-test --bins --locked --offline

# Tauri app with the feature (voter side):
cd gui\src-tauri
cargo +stable-x86_64-pc-windows-msvc build --features managed-tor-test --locked --offline
cd $Repo
```

You can verify `--help` parses without launching Tor:

```powershell
& "$Repo\target\debug\private-ballot-tor-test-provision.exe" --help
& "$Repo\target\debug\private-ballot-tor-test-intake.exe" --help
```

---

## TERMINAL 1 — Provision once

Run this in a **separate** PowerShell terminal after setting the variables
above.

### 1. Create the test root

```powershell
New-Item -ItemType Directory -Force -Path $TestRoot | Out-Null
```

### 2. Provision transport

This starts `tor.exe` to discover the hidden-service hostname, signs the
descriptor, writes the organizer private bundle and the voter public bundle,
then stops `tor.exe`.

```powershell
cargo +stable-x86_64-pc-windows-msvc run `
    -p tari-cc-private-ballot-transport-gateway `
    --features managed-tor-test `
    --bin private-ballot-tor-test-provision -- `
    $Manifest $Registry $OptionSet $TorExe $TestRoot
```

### Expected output

```
organizer torrc written to <test-root>\organizer-torrc
tor.exe started; discovering hidden-service hostname...
organizer hidden service: <56-char>.onion
tor.exe stopped (hostname is persistent for the intake phase).
descriptor fingerprint: <64-hex>
organizer private bundle: <test-root>\organizer-private
voter public bundle: <test-root>\voter-public-bundle.cbor

Next: start the organizer intake (see docs/TOR_ONE_COMPUTER_TEST.md):
  ...
provisioning complete
```

### 3. Confirm outputs

```powershell
# The persisted hidden-service hostname:
Get-Content "$TestRoot\organizer-hidden-service\hostname"

# The voter public bundle (copy this to the voter side later):
Test-Path "$TestRoot\voter-public-bundle.cbor"
```

---

## TERMINAL 2 — Organizer intake (stays running)

Open a **second** PowerShell terminal and set the same variables, then:

```powershell
cargo +stable-x86_64-pc-windows-msvc run `
    -p tari-cc-private-ballot-transport-gateway `
    --features managed-tor-test `
    --bin private-ballot-tor-test-intake -- `
    $Manifest $Registry $OptionSet $TorExe $TestRoot
```

### Expected output

```
organizer private bundle loaded
descriptor verified under test root
election: <election title>
collector: 127.0.0.1:<ephemeral port>
tor: starting (pid may vary)
hidden service: <56-char>.onion

Private Ballot controlled Tor intake
Election: <election title>
Descriptor verified
Collector: 127.0.0.1:<port>
Hidden service: <56-char>.onion
Tor: running
Accepted ballots: 0
PRIVATE INTAKE READY
```

Leave Terminal 2 running. The intake reuses the persisted hidden-service
identity from Terminal 1's provisioning. The collector binds to a loopback
ephemeral port; the torrc is rewritten with the actual port.

To stop: press **Ctrl+C** or close the terminal. The hidden-service identity
in `$TestRoot\organizer-hidden-service\` is preserved for restarts.

After a ballot is accepted, the intake prints:

```
Accepted ballots: 1
```

After a duplicate/rejected ballot, the count remains unchanged.

---

## TERMINAL 3 — Voter GUI

Open a **third** PowerShell terminal and set the same variables, then:

```powershell
cd $Repo\gui\src-tauri
cargo +stable-x86_64-pc-windows-msvc run --features managed-tor-test --locked --offline
```

The Tauri desktop application launches. This is the feature-enabled build that
includes the managed-Tor test transport UI.

### 4. Load the election

In the Vote screen, load the same three canonical artifacts:
`$Manifest`, `$Registry`, `$OptionSet`.

### 5. Unlock / create a durable voter credential

Generate or unlock a governance credential. Confirm it is **Eligible** for
the frozen registry.

### 6. Configure the voter test transport

After preparing the ballot, the **Private submission (controlled test)** card
appears. Enter:

- **tor.exe absolute path**: `$TorExe` (your absolute path)
- **Voter Tor data directory**: `$TestRoot\voter-tor`
- **Voter-public bundle path**: `$TestRoot\voter-public-bundle.cbor`

Click **Configure test transport**. The status shows the organizer onion
hostname and descriptor fingerprint.

### 7. Start managed Tor

Click **Start private transport**. The backend starts `tor.exe` directly (no
shell) and polls the real SOCKS5 readiness probe. Status changes to **Tor
ready** once a CURRENT SOCKS5 no-auth negotiation succeeds against the loopback
listener — not merely because the Tor process was started earlier.

> **Tor ready** reflects a current readiness check. If Tor dies after initial
> startup, the status truthfully reports not-ready, and a private submit/retry
> runs a FRESH readiness preflight BEFORE crossing the durable release
> boundary. A failed preflight never creates a `CAST_PENDING` record. Starting
> Tor does NOT release the ballot. No ballot bytes leave the process until you
> explicitly click Submit.

### 8. Choose ballot option A and prepare

Select option A, click **Prepare ballot**. Confirm the prepared-ballot summary
appears (eligibility proof ready, identity not attached, not yet cast).

### 9. CHANGE choice before cast

Click **Change my choice**, select option B, and **Prepare** again. This proves
the choice is changeable before release.

### 10. Submit privately

Click **Submit privately**. The backend crosses the durable `CAST_PENDING`
boundary BEFORE any network bytes leave, then transmits the exact staged
envelope through the SOCKS5-tunnelled HTTP POST to the organizer onion.

### 11. Observe PENDING / receipt / CAST

The status should change to **Cast** with an authenticated receipt. The notice
makes clear: delivery authenticated != final archive / Ootle anchor.

### 12. Organizer accepted count == 1

Check Terminal 2 — it should now show:

```
Accepted ballots: 1
```

### 13. Restart voter app and confirm cast lock

Close and relaunch the test GUI (Terminal 3). Load the same election, unlock
the same credential. Confirm the election shows **CAST / locked** — you cannot
prepare another ballot for the same election.

### 14. Duplicate/retry behavior

If a retry is attempted, the intake count remains 1 (the election-scoped
nullifier is the authoritative one-vote rule).

---

## PRE-PENDING FAILURE TEST (safe negative)

Before submitting, stop the managed Tor (click **Stop private transport**, or
kill `tor.exe`). The status truthfully reports **not ready** (a current readiness
check fails; the controller object existing alone is not enough). Attempt to
submit privately — the fresh readiness preflight fails BEFORE the release
boundary: the ballot remains **NotCast** and changeable, no durable PENDING is
created, no bytes are staged, and no carrier is invoked. Restart Tor and the
status returns to ready.

---

## SCREENSHOT CHECKPOINTS

The best screenshot moments:

- **A** — Ballot screen with the election question/options.
- **B** — Prepared anonymous ballot: eligibility proof ready, identity not
  attached, election bound, not yet cast.
- **C** — Change choice before cast (option A to option B).
- **D** — Managed Tor ready / private submission available (shows the public
  onion hostname).
- **E** — Submission completed with authenticated receipt / CAST (with the
  truthful note that receipt != final archive / Ootle anchor).
- **F** — Organizer accepted ballot count == 1 (Terminal 2).
- **G** — Duplicate anonymous vote rejected / count remains 1 (if a safe retry
  is attempted).
- **H/I** — Final archive verification and Ootle anchor are LATER (not in this
  slice).

## SCREENSHOT PRIVACY

**Never screenshot or share:**
- voter credential secret / passphrase / private key
- organizer signing key, gateway receiver secret, receipt signing secret
- hidden-service private key files (`organizer-hidden-service/*`)
- the `organizer-private` bundle contents
- raw sensitive app-data paths

**Safe to screenshot (public):**
- election question
- anonymous proof status
- public onion hostname (`<56-char>.onion`)
- descriptor fingerprint
- accepted ballot count
- authenticated receipt status (public archive commitment, eventual Ootle
  evidence)

---

## How it works

1. **Provision once**: discovers the Tor hidden-service identity, signs the
   descriptor, writes the organizer private bundle and voter public bundle.
2. **Intake**: reuses the persisted identity, binds the loopback collector,
   starts Tor, discovers the runtime hidden-service hostname, REQUIRES the
   runtime hostname to equal the signed descriptor onion, and ONLY THEN starts
   the collector service loop and prints `PRIVATE INTAKE READY`. `READY` is
   printed only after runtime onion equality is verified AND the collector
   worker is confirmed running. A pre-verification failure reaps Tor, drops the
   collector listener, and never prints `READY`.
3. **Voter**: loads the voter public bundle, starts managed Tor, submits the
   prepared ballot through the shared durable release boundary via the real Tor
   SOCKS5 carrier. A fresh readiness preflight runs BEFORE the release
   boundary; if Tor is no longer ready, no `CAST_PENDING` is created.

Tor mitigates submission network metadata. The cryptographic ballot protocol
provides anonymous eligibility and linkability properties. These are distinct
concepts; Tor alone does not provide voting anonymity.
