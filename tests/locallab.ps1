# Run the tracked local test and installation harness from the repository root.
#
# Typical usage:
#   pwsh -NoProfile -File tests/locallab.ps1                        # run all checks (sandboxed; nothing outside the repo changes)
#   pwsh -NoProfile -File tests/locallab.ps1 -Install               # checks + install this checkout live without tools (setup.ps1 -CiMode)
#   pwsh -NoProfile -File tests/locallab.ps1 -FullInstall           # checks + setup.ps1 -LocalRepo (winget tools, font, wizard prompts)
#   pwsh -NoProfile -File tests/locallab.ps1 -Wizard                # checks + setup.ps1 -LocalRepo -Wizard (implies -FullInstall)
#   pwsh -NoProfile -File tests/locallab.ps1 -Functional            # also run tests/ci-functional.ps1 (sandboxed, mocked network)
#   pwsh -NoProfile -File tests/locallab.ps1 -Restore               # restore profile(s) from last backup
# The test steps refuse to run in an elevated shell unless -AllowElevated is passed (use that only in a disposable VM).

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$SkipLint,
    [switch]$SkipParse,
    [switch]$SkipSmoke,
    [switch]$SkipTest,
    [switch]$Functional,
    [switch]$Install,
    [switch]$FullInstall,
    [switch]$Wizard,
    [switch]$Restore,
    [switch]$AllowElevated
)

# -Wizard implies -FullInstall (wizard only meaningful when driving setup.ps1)
if ($Wizard -and -not $FullInstall) { $FullInstall = $true }

$ErrorActionPreference = 'Stop'
# Resolve repoRoot as the parent of tests/.
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
. (Join-Path $repoRoot 'tests\lib\Sandbox.ps1')

$script:failures = @()
$script:step = 0
function Step { param([string]$Name)
    $script:step++
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $script:step, $Name) -ForegroundColor Cyan
}
function Fail { param([string]$Name, [string]$Detail)
    Write-Host "  FAIL  $Name  $Detail" -ForegroundColor Red
    $script:failures += "${Name}: $Detail"
}
function Ok { param([string]$Name, [string]$Detail = '')
    if ($Detail) { Write-Host "  OK    $Name  ($Detail)" -ForegroundColor Green }
    else { Write-Host "  OK    $Name" -ForegroundColor Green }
}

# --- Restore flow: find latest backup and put it back ---
if ($Restore) {
    Step 'Restore live profile from backup'
    $backups = Get-ChildItem -Path $env:TEMP -Directory -Filter 'psp-locallab-backup-*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if (-not $backups) {
        Fail 'Restore' "No psp-locallab-backup-* directory found in $env:TEMP"
        exit 1
    }
    $latest = $backups[0]
    Write-Host "  Using: $($latest.FullName)" -ForegroundColor DarkGray
    $docsRoot = Split-Path (Split-Path $PROFILE)
    $targets = @(
        @{ Src = Join-Path $latest.FullName 'PowerShell\Microsoft.PowerShell_profile.ps1'; Dst = Join-Path $docsRoot 'PowerShell\Microsoft.PowerShell_profile.ps1' }
        @{ Src = Join-Path $latest.FullName 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'; Dst = Join-Path $docsRoot 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1' }
    )
    foreach ($t in $targets) {
        if (Test-Path $t.Src) {
            if ($PSCmdlet.ShouldProcess($t.Dst, "Restore from $($t.Src)")) {
                Copy-Item -LiteralPath $t.Src -Destination $t.Dst -Force
                Ok 'restored' $t.Dst
            }
        }
        else {
            Write-Host "  (skip: $($t.Src) not in backup)" -ForegroundColor DarkGray
        }
    }
    exit 0
}

# Test steps change nothing outside their sandboxes, but an elevated mistake could reach machine-wide state.
if (-not ($SkipLint -and $SkipParse -and $SkipSmoke -and $SkipTest -and -not $Functional)) {
    try { Assert-PspTestSafety -AllowElevated:$AllowElevated -ScriptName 'tests/locallab.ps1' }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 2 }
}
$elevatedArgs = if ($AllowElevated) { @('-AllowElevated') } else { @() }

# --- Validate files exist ---
Step 'Repo structure'
foreach ($f in @('Microsoft.PowerShell_profile.ps1', 'setup.ps1', 'setprofile.ps1', 'theme.json', 'terminal-config.json', 'tests/ci-functional.ps1', 'tests/unit.ps1', 'PSScriptAnalyzerSettings.psd1')) {
    if (Test-Path $f) { Ok $f }
    else { Fail $f 'missing'; }
}

# --- 1. PSScriptAnalyzer (same version and settings as CI) ---
if (-not $SkipLint) {
    Step 'PSScriptAnalyzer (tests/lint.ps1)'
    $lintOutput = & pwsh -NoProfile -NonInteractive -File tests/lint.ps1 2>&1
    if ($LASTEXITCODE -eq 0) { Ok 'lint' 'clean' }
    else {
        $lintOutput | ForEach-Object { Write-Host "  $_" }
        Fail 'lint' "exit $LASTEXITCODE"
    }
}

# --- 2. PS5 parse-check (uses real powershell.exe) ---
if (-not $SkipParse) {
    Step 'PS5 parse-check'
    $ps5 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps5)) {
        Write-Host '  SKIP  powershell.exe not available on this host' -ForegroundColor DarkGray
    }
    else {
        $bad = 0
        foreach ($file in (Get-ChildItem -Filter *.ps1 -Recurse -File | Where-Object { $_.Name -notlike '_*.ps1' })) {
            $p = $file.FullName
            $out = & $ps5 -NoProfile -Command "`$t=`$null; `$e=`$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$p', [ref]`$t, [ref]`$e); if (`$e.Count -gt 0) { foreach (`$x in `$e) { Write-Host ('  L' + `$x.Extent.StartLineNumber + ': ' + `$x.Message) }; exit 1 }" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  FAIL: $p" -ForegroundColor Red
                Write-Host $out
                $bad++
            }
        }
        if ($bad -gt 0) { Fail 'PS5 parse' "$bad file(s) failed" }
        else { Ok 'PS5 parse' 'clean' }
    }
}

# --- 3. Non-interactive smoke load inside a sandbox (your profile_user.ps1 and plugins are not run) ---
if (-not $SkipSmoke) {
    Step 'Smoke-test non-interactive load (sandboxed)'
    $smoke = "& { param(`$repo) . (Join-Path `$repo 'tests\lib\Sandbox.ps1'); `$sb = New-PspSandbox -Name 'locallab'; Enter-PspSandbox -Sandbox `$sb; try { `$WarningPreference = 'SilentlyContinue'; `$Error.Clear(); . (Join-Path `$repo 'Microsoft.PowerShell_profile.ps1'); if (`$Error.Count) { exit 1 } } finally { Exit-PspSandbox -Sandbox `$sb } } '$($repoRoot -replace "'", "''")'"
    pwsh -NoProfile -NonInteractive -Command $smoke 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok 'smoke' 'loaded without errors' }
    else { Fail 'smoke' "exit $LASTEXITCODE" }
}

# --- 4. Optional: test.ps1 local test suite (includes tests/unit.ps1) ---
if (-not $SkipTest -and (Test-Path 'tests/test.ps1')) {
    Step 'Run tests/test.ps1 (-SkipPS5)'
    $testOutput = & pwsh -NoProfile -File tests/test.ps1 -SkipPS5 @elevatedArgs 2>&1
    $tail = ($testOutput | Select-Object -Last 3) -join [Environment]::NewLine
    Write-Host $tail -ForegroundColor DarkGray
    if ($LASTEXITCODE -eq 0) { Ok 'tests/test.ps1' }
    else { Fail 'tests/test.ps1' "exit $LASTEXITCODE" }
}

# --- 5. Optional: ci-functional.ps1 (sandboxed, third-party endpoints mocked) ---
if ($Functional) {
    Step 'Run ci-functional.ps1'
    & pwsh -NoProfile -File tests/ci-functional.ps1 @elevatedArgs
    if ($LASTEXITCODE -eq 0) { Ok 'tests/ci-functional.ps1' }
    else { Fail 'tests/ci-functional.ps1' "exit $LASTEXITCODE" }
}

# --- 6. Install to live profile dirs (replaces GitHub version) ---
if ($Install -or $FullInstall) {
    if ($script:failures.Count -gt 0) {
        Write-Host ''
        Write-Host "Install blocked: $($script:failures.Count) check(s) failed above." -ForegroundColor Red
        exit 1
    }

    Step 'Backup current live profile(s)'
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDir = Join-Path $env:TEMP "psp-locallab-backup-$timestamp"
    $docsRoot = Split-Path (Split-Path $PROFILE)
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $pairs = @(
        @{ Name = 'PowerShell'; Path = Join-Path $docsRoot 'PowerShell\Microsoft.PowerShell_profile.ps1' }
        @{ Name = 'WindowsPowerShell'; Path = Join-Path $docsRoot 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1' }
    )
    foreach ($p in $pairs) {
        if (Test-Path $p.Path) {
            $dst = Join-Path $backupDir "$($p.Name)\Microsoft.PowerShell_profile.ps1"
            New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
            Copy-Item -LiteralPath $p.Path -Destination $dst -Force
            Ok 'backed up' "$($p.Name) -> $dst"
        }
        else { Write-Host "  (skip: $($p.Path) not present)" -ForegroundColor DarkGray }
    }
    Write-Host "  Backup: $backupDir" -ForegroundColor DarkGray
    Write-Host '  Restore with: pwsh -NoProfile -File tests/locallab.ps1 -Restore' -ForegroundColor DarkGray

    if ($FullInstall) {
        $label = if ($Wizard) { 'setup.ps1 -LocalRepo -Wizard (interactive: theme/scheme/font/features)' }
                 else { 'setup.ps1 -LocalRepo (full install: tools, fonts, WT settings)' }
        Step $label
        if ($Wizard) { & './setup.ps1' -LocalRepo $repoRoot -Wizard }
        else { & './setup.ps1' -LocalRepo $repoRoot }
        if ($LASTEXITCODE -eq 0) { Ok 'setup.ps1' } else { Fail 'setup.ps1' "exit $LASTEXITCODE" }
    }
    else {
        # -CiMode installs the profile, configs and Windows Terminal settings (recorded, so Uninstall-Profile reverts them)
        # without winget tools, fonts, PowerShell Gallery modules or prompts.
        Step 'setup.ps1 -LocalRepo -CiMode (profile, configs, WT settings; no tools)'
        & './setup.ps1' -LocalRepo $repoRoot -CiMode -SkipWizard
        if ($LASTEXITCODE -eq 0) { Ok 'setup.ps1 -CiMode' } else { Fail 'setup.ps1 -CiMode' "exit $LASTEXITCODE" }
        Write-Host '  PSReadLine colors apply on next pwsh launch.' -ForegroundColor DarkGray
    }
}

# --- Summary ---
Write-Host ''
Write-Host '=========================================' -ForegroundColor Cyan
if ($script:failures.Count -eq 0) {
    Write-Host "  All checks passed ($script:step step(s))" -ForegroundColor Green
    if ($Install -or $FullInstall) {
        Write-Host '  Local profile is now live. Open a new pwsh to try it.' -ForegroundColor Green
    }
    elseif (-not $Restore) {
        Write-Host '  To install this version live:  pwsh -NoProfile -File tests/locallab.ps1 -Install' -ForegroundColor DarkGray
    }
    exit 0
}
else {
    Write-Host "  $($script:failures.Count) failure(s):" -ForegroundColor Red
    $script:failures | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    exit 1
}
