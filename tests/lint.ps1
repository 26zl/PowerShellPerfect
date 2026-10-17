# Run the CI PSScriptAnalyzer check locally: the pinned version with PSScriptAnalyzerSettings.psd1, tests/ excluded.
#   pwsh -NoProfile -File tests/lint.ps1             # installs the pinned PSScriptAnalyzer for the current user when missing
#   pwsh -NoProfile -File tests/lint.ps1 -NoInstall  # fail instead of installing
param([switch]$NoInstall)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
# Keep in step with .github/workflows/ci.yml.
$pinnedPSSAVersion = '1.25.0'
$have = Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [version]$pinnedPSSAVersion }
if (-not $have) {
    if ($NoInstall) { throw "PSScriptAnalyzer $pinnedPSSAVersion is not installed." }
    Install-Module -Name PSScriptAnalyzer -RequiredVersion $pinnedPSSAVersion -Force -Scope CurrentUser -ErrorAction Stop
}
Import-Module PSScriptAnalyzer -RequiredVersion $pinnedPSSAVersion -ErrorAction Stop
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
$results = Get-ChildItem -LiteralPath $repoRoot -Filter *.ps1 -File |
    ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Settings $settings }
if ($results) {
    $results | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
    exit 1
}
Write-Host "PSScriptAnalyzer $pinnedPSSAVersion`: clean" -ForegroundColor Green
