# locallab.ps1
# Local test + install harness. Tracked in git; run from repo root.
#
# Typical usage:
#   pwsh -NoProfile -File tests/locallab.ps1                        # run all non-destructive checks
#   pwsh -NoProfile -File tests/locallab.ps1 -Install               # tests + replace live profile (minimal)
#   pwsh -NoProfile -File tests/locallab.ps1 -FullInstall           # tests + setup.ps1 -LocalRepo (winget tools too)
#   pwsh -NoProfile -File tests/locallab.ps1 -Wizard                # tests + setup.ps1 -LocalRepo -Wizard (implies -FullInstall)
#   pwsh -NoProfile -File tests/locallab.ps1 -Functional            # also run tests/ci-functional.ps1 (elevated recommended)
#   pwsh -NoProfile -File tests/locallab.ps1 -Restore               # restore profile(s) from last backup

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
    [switch]$Restore
)

# -Wizard implies -FullInstall (wizard only meaningful when driving setup.ps1)
if ($Wizard -and -not $FullInstall) { $FullInstall = $true }

$ErrorActionPreference = 'Stop'
# This script lives in tests/. repoRoot is the parent directory (where setup.ps1 + profile live).
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

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

# --- Validate files exist ---
Step 'Repo structure'
foreach ($f in @('Microsoft.PowerShell_profile.ps1', 'setup.ps1', 'setprofile.ps1', 'theme.json', 'terminal-config.json', 'tests/ci-functional.ps1')) {
    if (Test-Path $f) { Ok $f }
    else { Fail $f 'missing'; }
}

# --- 1. PSScriptAnalyzer (mirror CI) ---
if (-not $SkipLint) {
    Step 'PSScriptAnalyzer'
    try {
        if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
            Install-Module PSScriptAnalyzer -Force -Scope CurrentUser -ErrorAction Stop
        }
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $excluded = @(
            'PSAvoidUsingWriteHost', 'PSAvoidUsingWMICmdlet',
            'PSUseShouldProcessForStateChangingFunctions', 'PSUseBOMForUnicodeEncodedFile',
            'PSReviewUnusedParameter', 'PSUseSingularNouns'
        )
        # Mirror tests/lint.ps1 and CI: exclude all tests/ harnesses (they intentionally use aliases,
        # generate strings that match the secrets regex, etc.) and any untracked _*.ps1 scratch files.
        $testHarnesses = @('ci-functional.ps1', 'rawhunt.ps1', 'test.ps1', 'locallab.ps1', 'lint.ps1')
        $results = Invoke-ScriptAnalyzer -Path . -Recurse -ExcludeRule $excluded |
            Where-Object { $_.ScriptName -notin $testHarnesses -and $_.ScriptName -notlike '_*.ps1' }
        $hits = @($results | Where-Object Severity -in 'Error', 'Warning')
        if ($hits) {
            $hits | Format-Table ScriptName, Line, RuleName, Message -AutoSize | Out-String | Write-Host
            Fail 'lint' "$($hits.Count) warnings/errors"
        }
        else { Ok 'lint' 'clean' }
    }
    catch { Fail 'lint' $_.Exception.Message }
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

# --- 3. Non-interactive smoke load ---
if (-not $SkipSmoke) {
    Step 'Smoke-test non-interactive load'
    $env:CI = 'true'
    try {
        pwsh -NoProfile -NonInteractive -Command ". './Microsoft.PowerShell_profile.ps1'; if (`$LASTEXITCODE) { exit `$LASTEXITCODE }" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok 'smoke' 'loaded' }
        else { Fail 'smoke' "exit $LASTEXITCODE" }
    }
    finally { Remove-Item env:CI -ErrorAction SilentlyContinue }
}

# --- 4. Optional: test.ps1 local test suite ---
if (-not $SkipTest -and (Test-Path 'tests/test.ps1')) {
    Step 'Run tests/test.ps1 (-SkipPS5)'
    $testOutput = & pwsh -NoProfile -File tests/test.ps1 -SkipPS5 2>&1
    $tail = ($testOutput | Select-Object -Last 3) -join [Environment]::NewLine
    Write-Host $tail -ForegroundColor DarkGray
    if ($LASTEXITCODE -eq 0) { Ok 'tests/test.ps1' }
    else { Fail 'tests/test.ps1' "exit $LASTEXITCODE" }
}

# --- 5. Optional: ci-functional.ps1 ---
if ($Functional) {
    Step 'Run ci-functional.ps1'
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $elevated) {
        Write-Host '  Note: not elevated. Forcing GITHUB_ACTIONS=true so setup step runs in CiMode.' -ForegroundColor Yellow
        $env:GITHUB_ACTIONS = 'true'
    }
    try {
        & pwsh -NoProfile -File tests/ci-functional.ps1
        if ($LASTEXITCODE -eq 0) { Ok 'tests/ci-functional.ps1' }
        else { Fail 'tests/ci-functional.ps1' "exit $LASTEXITCODE" }
    }
    finally {
        if (-not $elevated) { Remove-Item env:GITHUB_ACTIONS -ErrorAction SilentlyContinue }
    }
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
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $elevated) { Write-Warning 'Not elevated. setup.ps1 needs admin for fonts/winget. Consider rerunning from an elevated pwsh.' }
        if ($Wizard) { & './setup.ps1' -LocalRepo $repoRoot -Wizard }
        else { & './setup.ps1' -LocalRepo $repoRoot }
        if ($LASTEXITCODE -eq 0) { Ok 'setup.ps1' } else { Fail 'setup.ps1' "exit $LASTEXITCODE" }
    }
    else {
        Step 'setprofile.ps1 (minimal: copy profile to PS5 + PS7)'
        & './setprofile.ps1'
        if ($LASTEXITCODE -eq 0) { Ok 'setprofile.ps1' } else { Fail 'setprofile.ps1' "exit $LASTEXITCODE" }

        # setprofile.ps1 only copies the profile .ps1; refresh cached JSON configs too so
        # new schema fields (psreadline.colors, windowsTerminal.themeDefinition, etc.) take
        # effect on next pwsh launch without requiring a full setup.ps1 or Update-Profile.
        Step 'Refresh cached configs (theme.json, terminal-config.json)'
        $cacheDir = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
        if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
        foreach ($cfg in @('theme.json', 'terminal-config.json')) {
            $src = Join-Path $repoRoot $cfg
            $dst = Join-Path $cacheDir $cfg
            if (Test-Path $src) {
                Copy-Item -LiteralPath $src -Destination $dst -Force
                Ok 'refreshed' $cfg
            }
        }
        # Apply WT tab-bar theme + color scheme directly to WT settings.json. Mirrors the
        # subset of Update-Profile Phase 6 / setup.ps1 step [10/10] needed for the cosmetic
        # bits to take effect live, without doing network downloads or tool installs.
        # PSReadLine colors apply automatically when the new profile loads.
        Step 'Apply WT theme to settings.json (live)'
        $wtCandidates = @(
            Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
            Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'
            Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe\LocalState\settings.json'
            Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json'
        )
        $wtPath = $wtCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $wtPath) {
            Write-Host '  (skip: Windows Terminal not installed)' -ForegroundColor DarkGray
        }
        else {
            try {
                $themeJson = Get-Content (Join-Path $repoRoot 'theme.json') -Raw | ConvertFrom-Json -ErrorAction Stop
                $wtRaw = Get-Content $wtPath -Raw
                $q = [char]34
                $jsoncPat = "(?m)(?<=^([^$q]*$q[^$q]*$q)*[^$q]*)\s*//.*`$"
                $wt = ($wtRaw -replace $jsoncPat, '') | ConvertFrom-Json -ErrorAction Stop
                $backup = "$wtPath.locallab-$((Get-Date).ToString('yyyyMMdd-HHmmss')).bak"
                Copy-Item -LiteralPath $wtPath -Destination $backup -Force
                # Upsert custom theme
                if ($themeJson.windowsTerminal.themeDefinition) {
                    $td = [PSCustomObject]$themeJson.windowsTerminal.themeDefinition
                    if (-not $wt.PSObject.Properties['themes']) {
                        $wt | Add-Member -NotePropertyName 'themes' -NotePropertyValue @() -Force
                    }
                    $wt.themes = @(@($wt.themes | Where-Object { $_ -and $_.name -ne $td.name }) + $td)
                }
                if ($themeJson.windowsTerminal.theme) {
                    if ($wt.PSObject.Properties['theme']) { $wt.theme = $themeJson.windowsTerminal.theme }
                    else { $wt | Add-Member -NotePropertyName 'theme' -NotePropertyValue $themeJson.windowsTerminal.theme -Force }
                }
                # Upsert color scheme
                if ($themeJson.windowsTerminal.scheme) {
                    $sd = [PSCustomObject]$themeJson.windowsTerminal.scheme
                    if (-not $wt.PSObject.Properties['schemes']) {
                        $wt | Add-Member -NotePropertyName 'schemes' -NotePropertyValue @() -Force
                    }
                    $wt.schemes = @(@($wt.schemes | Where-Object { $_ -and $_.name -ne $sd.name }) + $sd)
                }
                $out = $wt | ConvertTo-Json -Depth 100
                [System.IO.File]::WriteAllText($wtPath, $out, [System.Text.UTF8Encoding]::new($false))
                Ok 'applied' "WT themes/schemes upserted; backup: $backup"
            }
            catch { Fail 'apply WT theme' $_.Exception.Message }
        }
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
