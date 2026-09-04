<#
.SYNOPSIS
    Physical distributed voter load runner (Private Ballot).

.DESCRIPTION
    Orchestrates ONE distributed voter cohort submission on ONE host
    (desktop or VPS) using `tari-cc-private-ballot-cli distributed-submit`.

    Two mutually exclusive Tor modes:

      MODE A - Managed Tor (recommended):
        -TorExe <absolute path to an existing tor.exe>. The CLI validates the
        executable with the SAME policy as the production managed-Tor feature
        (absolute path, real regular file, no symlinks/reparse points, no
        control characters), reserves a fresh loopback SOCKS port, starts an
        ISOLATED Tor process (its own DataDirectory under this run's output
        directory - never the production Private Ballot Tor state), waits for
        REAL SOCKS5 readiness, submits the whole cohort through Tor, and then
        stops/reaps ONLY the Tor process it started. Tor is NOT bundled,
        downloaded, or auto-installed; the operator supplies the executable.

      MODE B - Existing SOCKS (legacy, preserved):
        -TorSocks <ip:port>, e.g. 127.0.0.1:9050, for a Tor SOCKS listener the
        operator starts manually. This is the exact workflow of the prior
        physical 500-voter run.

    Supplying both -TorExe and -TorSocks is rejected as ambiguous; the runner
    never guesses. There is NO clearnet fallback: if Tor fails, the run fails.

    This runner is ORCHESTRATION ONLY. All security-sensitive Tor lifecycle
    mechanics live in the Rust CLI. The offline scale harness
    (tools\load-test\RUN_SCALE_QUALIFICATION.ps1) is a DIFFERENT system:
    in-process, NO Tor, NO physical networking.

.PARAMETER TorExe
    Absolute path to an already-installed tor.exe (MODE A, managed).
    Example: C:\Tor\tor.exe. Mutually exclusive with -TorSocks.

.PARAMETER TorSocks
    ip:port of an already-running local Tor SOCKS listener (MODE B, legacy).
    Example: 127.0.0.1:9050. Mutually exclusive with -TorExe.

.PARAMETER Manifest
    Election manifest CBOR from the organizer.

.PARAMETER Registry
    voter-registry.cbor from the organizer.

.PARAMETER Candidates
    candidate-set.cbor from the organizer.

.PARAMETER VoterPublicBundle
    voter-public-bundle.cbor (voter public transport bundle) from the organizer.

.PARAMETER Credentials
    Directory with this host's encrypted .tcbcred voter credential partition
    (produced by `distributed-cohort` + `distributed-partition`).

.PARAMETER Results
    Output JSON report path. Default: <OutputDir>\results.json.

.PARAMETER CohortSize
    Number of voters this host submits (CLI --count). 0 submits all
    credentials in -Credentials. Default 0.

.PARAMETER StartIndex
    One-based index into the credential directory (CLI --start-index). Default 1.

.PARAMETER Partition
    Host label (e.g. "desktop" or "vps") used in the run id and metadata.

.PARAMETER OutputDir
    Per-run evidence directory. Default:
    tools\load-test\distributed\runs\<partition>-<timestamp>.

.PARAMETER Choice
    round-robin (default) or all:<candidate-id-hex> (CLI --choice).

.PARAMETER Concurrency
    Must be 1 (the driver is sequential). Default 1.

.PARAMETER PassphraseEnv
    Environment variable holding the test credential passphrase.
    Default TARI_BALLOT_LOAD_PASSPHRASE. The passphrase is NEVER recorded.

.PARAMETER CliExe
    Optional path to a prebuilt tari-cc-private-ballot-cli(.exe). If omitted,
    the runner builds it with `cargo build -p tari-cc-private-ballot-cli --release`.

.EXAMPLE
    PS host A (desktop cohort, managed Tor):
    .\tools\load-test\distributed\RUN_DISTRIBUTED_VOTER_LOAD.ps1 `
        -TorExe "C:\Tor\tor.exe" `
        -Manifest "C:\election\election-manifest.cbor" `
        -Registry "C:\election\voter-registry.cbor" `
        -Candidates "C:\election\candidate-set.cbor" `
        -VoterPublicBundle "C:\transport\voter-public-bundle.cbor" `
        -Credentials "C:\runs\desktop-voters" `
        -Partition "desktop" `
        -CohortSize 250 `
        -OutputDir "C:\PrivateBallotLoadRuns\desktop"

.EXAMPLE
    PS host B (VPS cohort, managed Tor, independent Tor process):
    .\RUN_DISTRIBUTED_VOTER_LOAD.ps1 `
        -TorExe "C:\Tor\tor.exe" `
        ... -Partition "vps" -CohortSize 250 -OutputDir "C:\PrivateBallotLoadRuns\vps"

.NOTES
    Set the passphrase env var before running:
        $env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
    Failure evidence (bounded tor-stderr log) is preserved under the run
    directory whenever a managed Tor start fails.
#>
[CmdletBinding()]
param(
    [string]$TorExe,
    [string]$TorSocks,
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$Registry,
    [Parameter(Mandatory = $true)][string]$Candidates,
    [Parameter(Mandatory = $true)][string]$VoterPublicBundle,
    [Parameter(Mandatory = $true)][string]$Credentials,
    [string]$Results,
    [int]$CohortSize = 0,
    [int]$StartIndex = 1,
    [string]$Partition = "host",
    [string]$OutputDir,
    [string]$Choice = "round-robin",
    [int]$Concurrency = 1,
    [string]$PassphraseEnv = "TARI_BALLOT_LOAD_PASSPHRASE",
    [string]$CliExe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-RunnerMetadata {
    param(
        [object]$Metadata,
        [string]$OutputPath
    )
    $Metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Fail-closed mode resolution: exactly one of -TorExe / -TorSocks.
# ---------------------------------------------------------------------------
$torExeSupplied = -not [string]::IsNullOrWhiteSpace($TorExe)
$torSocksSupplied = -not [string]::IsNullOrWhiteSpace($TorSocks)
if ($torExeSupplied -and $torSocksSupplied) {
    throw "Supply either -TorExe (managed Tor) or -TorSocks (existing listener), not both; refusing to guess."
}
if (-not $torExeSupplied -and -not $torSocksSupplied) {
    throw "Supply -TorExe (managed Tor) or -TorSocks (existing SOCKS listener)."
}
if ($torExeSupplied) {
    $resolvedTorExe = [System.IO.Path]::GetFullPath($TorExe)
    if (-not [System.IO.Path]::IsPathRooted($resolvedTorExe)) {
        throw "-TorExe must be an absolute path (no PATH lookup is performed)."
    }
    if (-not (Test-Path -LiteralPath $resolvedTorExe -PathType Leaf)) {
        throw "-TorExe not found: $resolvedTorExe (the runner does NOT download or install Tor)"
    }
    # Final validation (reparse points, control characters, etc.) is performed
    # by the shared Rust policy inside the CLI.
    $cliTorArgs = @("--tor-exe", $resolvedTorExe)
} else {
    $cliTorArgs = @("--tor-socks", $TorSocks)
}

# ---------------------------------------------------------------------------
# Resolve the CLI (prebuilt binary, else cargo build --release).
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($CliExe)) {
    cargo build -p tari-cc-private-ballot-cli --release
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build of tari-cc-private-ballot-cli failed"
    }
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
    $CliExe = Join-Path $repoRoot "target\release\tari-cc-private-ballot-cli.exe"
}
if (-not (Test-Path -LiteralPath $CliExe -PathType Leaf)) {
    throw "CLI executable not found: $CliExe"
}

# ---------------------------------------------------------------------------
# Per-run evidence directory.
# ---------------------------------------------------------------------------
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir)) {
        $scriptDir = (Get-Location).Path
    }
    $OutputDir = Join-Path $scriptDir "runs"
}
$OutputDir = Join-Path $OutputDir "$Partition-$timestamp"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if ([string]::IsNullOrWhiteSpace($Results)) {
    $Results = Join-Path $OutputDir "results.json"
} else {
    $resultsParent = Split-Path -Parent $Results
    if ($resultsParent) {
        New-Item -ItemType Directory -Force -Path $resultsParent | Out-Null
    }
}

$runId = "$Partition-$timestamp"
$startedUtc = (Get-Date).ToUniversalTime().ToString("o")
$commitSha = $null
try {
    $commitSha = (git rev-parse HEAD).Trim()
} catch {
    $commitSha = $null
}

# Passphrase: env var only, never recorded, never logged.
if (-not (Get-Item -Path "env:$PassphraseEnv" -ErrorAction SilentlyContinue)) {
    throw "set the $PassphraseEnv environment variable to the test credential passphrase"
}

$cliArgs = @(
    "distributed-submit",
    "--manifest", (Resolve-Path -LiteralPath $Manifest).Path,
    "--registry", (Resolve-Path -LiteralPath $Registry).Path,
    "--candidates", (Resolve-Path -LiteralPath $Candidates).Path,
    "--voter-public-bundle", (Resolve-Path -LiteralPath $VoterPublicBundle).Path,
    "--credentials", (Resolve-Path -LiteralPath $Credentials).Path
) + $cliTorArgs + @(
    "--results", $Results,
    "--start-index", "$StartIndex",
    "--concurrency", "1",
    "--run-id", $runId,
    "--passphrase-env", $PassphraseEnv
)
if ($CohortSize -gt 0) {
    $cliArgs += @("--count", "$CohortSize")
}
if ($Choice -and $Choice -ne "round-robin") {
    $cliArgs += @("--choice", $Choice)
}

Write-Host "Private Ballot distributed voter load run: $runId"
Write-Host "Tor mode: $(if ($torExeSupplied) { 'managed-tor (CLI owns an isolated Tor process)' } else { 'existing-socks (operator-managed listener)' })"
Write-Host "Results:  $Results"

# The CLI performs validation, Tor startup/readiness (managed mode), the
# cohort submission through Tor, evidence writing, and Tor stop/reap.
& $CliExe @cliArgs
$cliExit = $LASTEXITCODE
$finishedUtc = (Get-Date).ToUniversalTime().ToString("o")

# Non-secret run metadata. Never records passphrases, onion private keys,
# voter credentials, walletd API keys, or Tor private state.
$metadata = [ordered]@{
    metadata_type        = "TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_RUN_METADATA_V1"
    runner_success       = ($cliExit -eq 0)
    started_utc          = $startedUtc
    finished_utc         = $finishedUtc
    commit_sha           = $commitSha
    cli_version          = "tari-cc-private-ballot-cli 0.1.0"
    partition            = $Partition
    run_id               = $runId
    cohort_size          = $CohortSize
    start_index          = $StartIndex
    tor_mode             = $(if ($torExeSupplied) { "managed-tor" } else { "existing-socks" })
    tor_executable_basename = $(if ($torExeSupplied) { [System.IO.Path]::GetFileName($resolvedTorExe) } else { $null })
    results_file         = $Results
    report_file          = $Results
    cli_exit_code        = $cliExit
    concurrency          = 1
}
Write-RunnerMetadata -Metadata $metadata -OutputPath (Join-Path $OutputDir "run-metadata.json")

if ($cliExit -ne 0) {
    Write-Error "distributed-submit failed (exit $cliExit). If managed Tor was used, its isolated runtime evidence (bounded tor-stderr log) is preserved next to the results file."
    exit $cliExit
}

Write-Host "Run complete. Results: $Results"
exit 0
