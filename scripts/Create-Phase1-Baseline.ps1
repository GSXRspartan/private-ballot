$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Test-Path ".git")) {
    throw "Run scripts\Initialize-Project.ps1 first."
}

git add `
    .gitignore `
    README.md `
    START-HERE.md `
    ROADMAP.md `
    PHASE_STATUS.md `
    docs `
    scripts

if ($LASTEXITCODE -ne 0) {
    throw "git add failed with exit code $LASTEXITCODE."
}

git diff --cached --check

if ($LASTEXITCODE -ne 0) {
    throw "The staged files failed git diff --cached --check."
}

git status --short

if ($LASTEXITCODE -ne 0) {
    throw "git status failed with exit code $LASTEXITCODE."
}

Write-Host ""
Write-Host "Review the staged files above." -ForegroundColor Yellow
Write-Host 'When satisfied, run: git commit -m "docs: establish private ballot phase 1 baseline"'