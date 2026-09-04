<#
.SYNOPSIS
    Runs the Release scale qualification harness at a chosen registry size and
    stores a machine-readable CSV result.

.DESCRIPTION
    Wraps the TEST-ONLY `release_scale_qualification` integration harness
    (crates/gui-core/tests/release_scale_qualification.rs). It sets the known
    working MSVC/vcpkg build environment, performs disk-space and runtime-cap
    safety checks, runs the harness in --release for one scale, and appends one
    timestamped CSV row under scale-qualification-results\.

    It NEVER touches real user election workspaces (the harness uses per-run OS
    temp scratch), NEVER publishes a live Ootle transaction (anchor preparation
    is offline only), and NEVER uses production credentials.

.PARAMETER Voters
    Registry size to qualify. Supported: 50, 100, 500, 1000, 2048, 4096.
    (50 is retained for regression.) The protocol maximum is 4096; larger values
    are rejected.

.PARAMETER All
    Run every supported scale sequentially (100, 500, 1000, 2048, 4096), each
    preceded by its own disk/runtime safety check. Does NOT run automatically
    without this switch. 50 is not included in -All (use -Voters 50 explicitly).

.PARAMETER MaxSeconds
    Hard runtime cap per scale. If the harness process runs longer it is killed
    and the run is recorded as TIMEOUT (scratch preserved). Default scales with
    the registry size.

.PARAMETER MinFreeGB
    Minimum free space (GiB) required on the scratch drive before a scale runs.
    Default scales with the registry size.

.EXAMPLE
    .\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 100

.EXAMPLE
    .\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -All
#>
[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single', Mandatory = $true)]
    [int] $Voters,

    [Parameter(ParameterSetName = 'All', Mandatory = $true)]
    [switch] $All,

    [int] $MaxSeconds = 0,
    [double] $MinFreeGB = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Script lives at <repo>/tools/load-test/RUN_SCALE_QUALIFICATION.ps1 — the repo
# root is two directories up. Callers may still invoke it from any working
# directory; the harness itself runs against $RepoRoot.
$RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$ResultsDir = Join-Path $RepoRoot 'scale-qualification-results'
$SupportedScales = @(50, 100, 500, 1000, 2048, 4096)
$ProtocolMax = 4096

# Per-scale default disk and runtime budgets (rough, generous; the 4096 durable
# snapshot is large — see SCALE_QUALIFICATION_HARNESS.md).
$DefaultMinFreeGB = @{ 50 = 1;  100 = 1;  500 = 2;   1000 = 4;   2048 = 10;  4096 = 30 }
$DefaultMaxSeconds = @{ 50 = 300; 100 = 600; 500 = 1800; 1000 = 3600; 2048 = 10800; 4096 = 21600 }

function Set-BuildEnvironment {
    # Known working MSVC/vcpkg toolchain. VCPKG_ROOT and the Visual Studio
    # BuildTools path are developer-machine specific; the script honors any
    # already-exported values first so contributors can point at their own
    # vcpkg / BuildTools installs without editing this file. Only fall back to
    # illustrative Windows defaults when nothing is exported.
    if (-not $env:RUSTUP_TOOLCHAIN) {
        $env:RUSTUP_TOOLCHAIN = '1.97.1-x86_64-pc-windows-msvc'
    }
    if (-not $env:VCPKG_ROOT) {
        $env:VCPKG_ROOT = 'C:\path\to\vcpkg'          # override for your machine
    }
    if (-not $env:VCPKG_DEFAULT_TRIPLET) {
        $env:VCPKG_DEFAULT_TRIPLET = 'x64-windows-static-md'
    }
    if (-not $env:VCPKGRS_TRIPLET) {
        $env:VCPKGRS_TRIPLET = 'x64-windows-static-md'
    }
    if (-not $env:VCPKG_VISUAL_STUDIO_PATH) {
        $env:VCPKG_VISUAL_STUDIO_PATH = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
    }
    $env:OPENSSL_DIR              = "$($env:VCPKG_ROOT)\installed\x64-windows-static-md"
    $env:OPENSSL_INCLUDE_DIR      = "$($env:OPENSSL_DIR)\include"
    $env:OPENSSL_LIB_DIR          = "$($env:OPENSSL_DIR)\lib"
    $env:OPENSSL_STATIC           = '1'
    $env:LIB                      = "$($env:OPENSSL_DIR)\lib;$($env:LIB)"
}

function Get-ScratchFreeGB {
    $tempRoot = if ($env:TEMP) { $env:TEMP } else { $env:TMP }
    if (-not $tempRoot) { $tempRoot = $RepoRoot }
    $qualifier = (Split-Path -Qualifier $tempRoot)
    if (-not $qualifier) { $qualifier = 'C:' }
    $driveLetter = $qualifier.TrimEnd(':')
    $drive = Get-PSDrive -Name $driveLetter -ErrorAction Stop
    return [math]::Round($drive.Free / 1GB, 2)
}

function Invoke-OneScale {
    param([int] $Scale)

    if ($Scale -gt $ProtocolMax) {
        throw "Voters $Scale exceeds the protocol maximum of $ProtocolMax."
    }
    if ($SupportedScales -notcontains $Scale) {
        throw "Voters $Scale is not a supported scale ($($SupportedScales -join ', '))."
    }

    $minFree = if ($MinFreeGB -gt 0) { $MinFreeGB } else { $DefaultMinFreeGB[$Scale] }
    $maxSecs = if ($MaxSeconds -gt 0) { $MaxSeconds } else { $DefaultMaxSeconds[$Scale] }

    $freeGB = Get-ScratchFreeGB
    Write-Host "[$Scale] scratch drive free: $freeGB GiB (required >= $minFree GiB)"
    if ($freeGB -lt $minFree) {
        throw "[$Scale] insufficient free disk: $freeGB GiB < required $minFree GiB. Aborting before run."
    }

    New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $ResultsDir "scale-$Scale-$stamp.csv"
    $logPath = Join-Path $ResultsDir "scale-$Scale-$stamp.log"

    $env:BALLOT_SCALE_REGISTRY = "$Scale"
    $env:BALLOT_SCALE_CSV = $csvPath

    Write-Host "[$Scale] starting (cap ${maxSecs}s). CSV: $csvPath"
    $startedAt = Get-Date

    $cargoArgs = @(
        'test', '-p', 'tari-cc-private-ballot-gui-core',
        '--release', '--features', 'test-support',
        '--test', 'release_scale_qualification',
        'release_scale_qualification',
        '--', '--ignored', '--nocapture', '--test-threads=1'
    )

    $proc = Start-Process -FilePath 'cargo' -ArgumentList $cargoArgs `
        -WorkingDirectory $RepoRoot -NoNewWindow -PassThru `
        -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.err"

    $completed = $proc.WaitForExit($maxSecs * 1000)
    if (-not $completed) {
        Write-Warning "[$Scale] runtime cap ${maxSecs}s exceeded; terminating. Scratch and partial log preserved."
        try { $proc.Kill($true) } catch { try { $proc.Kill() } catch {} }
        $proc.WaitForExit()
        return [pscustomobject]@{ Scale = $Scale; Result = 'TIMEOUT'; Csv = $csvPath; Log = $logPath }
    }

    # Finalize the exit code: after a timed WaitForExit, the parameterless call
    # ensures the code and redirected-stream flush are complete (a redirected
    # Start-Process can otherwise leave ExitCode unreadable).
    $proc.WaitForExit()
    $elapsed = [int]((Get-Date) - $startedAt).TotalSeconds
    $exitCode = try { $proc.ExitCode } catch { $null }

    # Merge stderr into the log for a single artifact.
    if (Test-Path "$logPath.err") {
        Get-Content "$logPath.err" | Add-Content -Path $logPath
        Remove-Item "$logPath.err" -ErrorAction SilentlyContinue
    }

    # AUTHORITATIVE signal: the harness writes a CSV row whose `result` column is
    # PASS only after every assertion passed. Trust that over the (occasionally
    # unreadable) process exit code.
    $csvPass = $false
    if (Test-Path $csvPath) {
        $lastRow = Get-Content $csvPath | Where-Object { $_ -and ($_ -notmatch '^timestamp,') } | Select-Object -Last 1
        if ($lastRow -and ($lastRow -match ',PASS,')) { $csvPass = $true }
    }
    $result = if ($csvPass) { 'PASS' } else { 'FAIL' }
    Write-Host "[$Scale] $result in ${elapsed}s (exit $exitCode)."
    if ($result -eq 'PASS') {
        Get-Content $csvPath | Select-Object -Last 1 | ForEach-Object { Write-Host "[$Scale] $_" }
    } else {
        Write-Warning "[$Scale] see $logPath (scratch preserved by the harness on failure)."
    }
    return [pscustomobject]@{ Scale = $Scale; Result = $result; Csv = $csvPath; Log = $logPath }
}

Set-BuildEnvironment

if ($PSCmdlet.ParameterSetName -eq 'All') {
    $scales = @(100, 500, 1000, 2048, 4096)
    Write-Host "Running scales sequentially: $($scales -join ', ')"
    $summary = @()
    foreach ($s in $scales) {
        try {
            $summary += Invoke-OneScale -Scale $s
        } catch {
            Write-Warning $_.Exception.Message
            $summary += [pscustomobject]@{ Scale = $s; Result = 'ABORTED'; Csv = ''; Log = '' }
            # A safety-check abort (e.g. disk) stops the remaining, larger scales.
            break
        }
    }
    Write-Host "`n==== Scale qualification summary ===="
    $summary | Format-Table -AutoSize
} else {
    Invoke-OneScale -Scale $Voters | Format-Table -AutoSize
}
