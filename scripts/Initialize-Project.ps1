$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git was not found in PATH."
}

if (-not (Test-Path ".git")) {
    git init

    if ($LASTEXITCODE -ne 0) {
        throw "git init failed with exit code $LASTEXITCODE."
    }
}

git status

if ($LASTEXITCODE -ne 0) {
    throw "git status failed with exit code $LASTEXITCODE."
}

Write-Host ""
Write-Host "Project initialized locally." -ForegroundColor Green
Write-Host "Review START-HERE.md and docs\PHASE1_PROTOCOL_SPEC_v0.1.md before committing."