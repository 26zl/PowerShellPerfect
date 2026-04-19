# PSScriptAnalyzer suppression: this file intentionally calls profile functions
# by their short names (gc, ls, cat, uptime, eventlog) to exercise those definitions.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '')]
param(
    [switch]$VerboseOutput,
    [switch]$StrictNetwork
)

$ErrorActionPreference = 'Stop'

# This script lives in tests/. Resolve repo root (parent of tests/) so all relative
# references to Microsoft.PowerShell_profile.ps1, setup.ps1, theme.json etc. still work.
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$profilePath = Join-Path $repoRoot 'Microsoft.PowerShell_profile.ps1'

$passed = 0
$failed = 0
$skipped = 0

$script:executedCommands = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:skippedCommands = @{}
$script:commandFailures = @()
$script:networkSoftFails = @()
$script:installReady = $false

$script:origLocalAppData = $env:LOCALAPPDATA
$script:origProfileVar = $PROFILE
$script:origCiVar = $env:CI

$script:sandboxRoot = $null
$script:sandboxPs7Dir = $null
$script:sandboxPs5Dir = $null
$script:sandboxPs7Profile = $null
$script:sandboxPs5Profile = $null
$script:sandboxCacheDir = $null

# Write test result (PASS/FAIL/SKIP) and update counters
function Write-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'SKIP')][string]$Status,
        [string]$Detail
    )

    switch ($Status) {
        'PASS' {
            Write-Host "  PASS  $Name" -ForegroundColor Green
            $script:passed++
        }
        'FAIL' {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            if ($Detail) { Write-Host "        $Detail" -ForegroundColor Yellow }
            $script:failed++
        }
        'SKIP' {
            Write-Host "  SKIP  $Name" -ForegroundColor DarkGray
            if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGray }
            $script:skipped++
        }
    }
}

# Run a test case with optional skip predicate
function Invoke-TestCase {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Code,
        [scriptblock]$SkipWhen,
        [string]$SkipReason
    )

    if ($SkipWhen) {
        $shouldSkip = $false
        try {
            $shouldSkip = [bool](& $SkipWhen)
        }
        catch {
            $shouldSkip = $true
            if (-not $SkipReason) { $SkipReason = "Skip predicate failed: $_" }
        }

        if ($shouldSkip) {
            Write-Result -Name $Name -Status 'SKIP' -Detail $SkipReason
            return
        }
    }

    try {
        $output = & { $ErrorActionPreference = 'Stop'; & $Code } 2>&1
        $errorRecords = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        if ($errorRecords.Count -gt 0) { throw $errorRecords[0].ToString() }

        if ($VerboseOutput -and $output) {
            foreach ($line in $output) {
                Write-Host "        $line" -ForegroundColor DarkGray
            }
        }

        Write-Result -Name $Name -Status 'PASS'
    }
    catch {
        Write-Result -Name $Name -Status 'FAIL' -Detail $_.Exception.Message
    }
}

# Register command as executed for coverage audit
function Register-ExecutedCommand {
    param([Parameter(Mandatory)][string]$Name)
    if ($script:skippedCommands.ContainsKey($Name)) { $script:skippedCommands.Remove($Name) }
    [void]$script:executedCommands.Add($Name)
}

# Register command as skipped with reason for coverage audit
function Register-SkippedCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason
    )
    if (-not $script:executedCommands.Contains($Name)) {
        $script:skippedCommands[$Name] = $Reason
    }
}

# Detect if error message indicates a network/connectivity issue (for soft-fail in probes)
function Test-IsNetworkIssue {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    $patterns = @(
        '(?i)timeout'
        '(?i)timed out'
        '(?i)unable to connect'
        '(?i)could not connect'
        '(?i)connection.*(closed|failed|forcibly|refused|reset)'
        '(?i)remote name could not be resolved'
        '(?i)no such host'
        '(?i)name or service not known'
        '(?i)dns'
        '(?i)network'
        '(?i)unreachable'
        '(?i)TLS'
        '(?i)SSL'
        '(?i)HttpRequestException'
        '(?i)temporar'
        '(?i)service unavailable'
        '(?i)\b(429|500|502|503|504)\b'
        '(?i)lookup failed'
        '(?i)could not fetch'
        '(?i)failed to retrieve public ip'
        '(?i)whois lookup failed'
        '(?i)failed to upload the document'
    )
    foreach ($pattern in $patterns) {
        if ($Message -match $pattern) { return $true }
    }
    return $false
}

# Run a single command probe and record result for coverage audit
function Invoke-CommandProbe {
    param(
        [Parameter(Mandatory)][string]$Command,
        [scriptblock]$Code,
        [string]$SkipReason
    )

    if ($SkipReason) {
        Register-SkippedCommand -Name $Command -Reason $SkipReason
        Write-Host "    SKIP  $Command ($SkipReason)" -ForegroundColor DarkGray
        return
    }

    if (-not $Code) {
        Register-SkippedCommand -Name $Command -Reason 'No probe script provided'
        Write-Host "    SKIP  $Command (No probe script provided)" -ForegroundColor DarkGray
        return
    }

    try {
        $output = & { $ErrorActionPreference = 'Stop'; & $Code } 2>&1
        $errorRecords = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        if ($errorRecords.Count -gt 0) { throw $errorRecords[0].ToString() }

        if ($VerboseOutput -and $output) {
            foreach ($line in $output) {
                Write-Host "        $line" -ForegroundColor DarkGray
            }
        }

        Register-ExecutedCommand -Name $Command
        Write-Host "    OK    $Command" -ForegroundColor Green
    }
    catch {
        $msg = $_.Exception.Message
        if (Test-IsNetworkIssue -Message $msg) {
            Register-ExecutedCommand -Name $Command
            $script:networkSoftFails += "${Command}: $msg"
            Write-Host "    NET   $Command ($msg)" -ForegroundColor Yellow
            if ($StrictNetwork) { $script:commandFailures += "${Command}: $msg" }
            return
        }

        $script:commandFailures += "${Command}: $msg"
        Write-Host "    FAIL  $Command ($msg)" -ForegroundColor Red
    }
}

# Restore environment and remove sandbox dir after test run
function Restore-SandboxEnvironment {
    if ($null -ne $script:origLocalAppData) {
        $env:LOCALAPPDATA = $script:origLocalAppData
    }

    if ($script:origProfileVar) {
        Set-Variable -Name PROFILE -Scope Global -Value $script:origProfileVar
    }

    if ([string]::IsNullOrWhiteSpace($script:origCiVar)) {
        Remove-Item env:CI -ErrorAction SilentlyContinue
    }
    else {
        $env:CI = $script:origCiVar
    }

    if ($script:sandboxRoot -and (Test-Path $script:sandboxRoot)) {
        Remove-Item -Path $script:sandboxRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host '========== Functional CI Suite (Full Command Coverage) ==========' -ForegroundColor Cyan
Write-Host ''

if (-not (Test-Path $profilePath)) {
    throw "Profile not found: $profilePath"
}

try {
Invoke-TestCase -Name 'Full install flow on host (setup.ps1)' -Code {
    # Run the real setup.ps1 against the current host to validate the full install flow
    # (winget tools, fonts, Windows Terminal settings).
    #
    # Behavior:
    # - In CI/non-admin environments: call setup.ps1 -CiMode so admin-only steps are skipped
    #   but the rest of the flow still executes.
    # - Locally (non-CI): require elevation so users see the real install behavior.

    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isCiHost = [bool]$env:GITHUB_ACTIONS -or [bool]$env:CI

    if (-not $isElevated -and -not $isCiHost) {
        throw 'setup.ps1 requires an elevated (Administrator) shell when run locally. Run tests/ci-functional.ps1 from an elevated pwsh so the full install flow can be validated.'
    }

    $setupPath = Join-Path $repoRoot 'setup.ps1'
    if (-not (Test-Path $setupPath)) {
        throw "setup.ps1 not found at $setupPath"
    }

    Write-Host '  Running setup.ps1 against host environment (full install flow).' -ForegroundColor Yellow
    # Hashtable splatting is required for named parameters.
    # Array splatting passes elements positionally, which would bind '-LocalRepo'
    # to the first positional param ($Opacity) and fail the int conversion.
    $setupArgs = @{ LocalRepo = $repoRoot }
    if ($isCiHost -and -not $isElevated) {
        $setupArgs['CiMode'] = $true
    }
    & $setupPath @setupArgs

    # Verify setup actually installed files (setup.ps1 uses return, not exit 1, so
    # $LASTEXITCODE is always 0 - we must check artifacts directly)
    $docsRoot = Split-Path (Split-Path $PROFILE)
    $ps7Profile = Join-Path $docsRoot 'PowerShell' 'Microsoft.PowerShell_profile.ps1'
    $ps5Profile = Join-Path $docsRoot 'WindowsPowerShell' 'Microsoft.PowerShell_profile.ps1'
    if (-not (Test-Path $ps7Profile)) { throw "setup.ps1 did not install PS7 profile at $ps7Profile" }
    if (-not (Test-Path $ps5Profile)) { throw "setup.ps1 did not install PS5 profile at $ps5Profile" }
    $cacheDir = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
    if (-not (Test-Path $cacheDir)) { throw "setup.ps1 did not create cache dir at $cacheDir" }
}

Invoke-TestCase -Name 'Install profile in sandbox' -Code {
    $script:installReady = $false
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)

    $script:sandboxRoot = Join-Path $env:TEMP "psp-ci-install-$([System.IO.Path]::GetRandomFileName())"
    $sandboxLocal = Join-Path $script:sandboxRoot 'Local'
    $sandboxDocs = Join-Path $script:sandboxRoot 'Documents'
    $script:sandboxPs7Dir = Join-Path $sandboxDocs 'PowerShell'
    $script:sandboxPs5Dir = Join-Path $sandboxDocs 'WindowsPowerShell'
    $script:sandboxPs7Profile = Join-Path $script:sandboxPs7Dir 'Microsoft.PowerShell_profile.ps1'
    $script:sandboxPs5Profile = Join-Path $script:sandboxPs5Dir 'Microsoft.PowerShell_profile.ps1'
    $script:sandboxCacheDir = Join-Path $sandboxLocal 'PowerShellProfile'

    New-Item -ItemType Directory -Path $script:sandboxPs7Dir, $script:sandboxPs5Dir, $script:sandboxCacheDir -Force | Out-Null

    $env:LOCALAPPDATA = $sandboxLocal
    Set-Variable -Name PROFILE -Scope Global -Value $script:sandboxPs7Profile

    & (Join-Path $repoRoot 'setprofile.ps1') | Out-Null

    if (-not (Test-Path $script:sandboxPs7Profile)) { throw "Missing installed profile: $($script:sandboxPs7Profile)" }
    if (-not (Test-Path $script:sandboxPs5Profile)) { throw "Missing installed profile: $($script:sandboxPs5Profile)" }

    Copy-Item (Join-Path $repoRoot 'theme.json') (Join-Path $script:sandboxCacheDir 'theme.json') -Force
    Copy-Item (Join-Path $repoRoot 'terminal-config.json') (Join-Path $script:sandboxCacheDir 'terminal-config.json') -Force
    [System.IO.File]::WriteAllText((Join-Path $script:sandboxCacheDir 'user-settings.json'), '{}', $utf8NoBom)

    # These emulate install artifacts and are validated by the uninstall phase.
    [System.IO.File]::WriteAllText((Join-Path $script:sandboxCacheDir 'omp-init.ps1'), '# init', $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $script:sandboxCacheDir 'zoxide-init.ps1'), '# init', $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $script:sandboxPs7Dir 'profile_user.ps1'), '# user override', $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $script:sandboxPs5Dir 'profile_user.ps1'), '# user override', $utf8NoBom)

    $smokeOutput = pwsh -NoProfile -NonInteractive -Command ". '$($script:sandboxPs7Profile)'" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $sample = ($smokeOutput | Select-Object -First 5) -join '; '
        throw "Installed profile failed to load in sandbox smoke test: $sample"
    }

    $script:installReady = $true
}

Invoke-TestCase -Name 'Execute full command matrix' -Code {
    $script:executedCommands.Clear()
    $script:skippedCommands = @{}
    $script:commandFailures = @()
    $script:networkSoftFails = @()

    $env:LOCALAPPDATA = Join-Path $script:sandboxRoot 'Local'
    Set-Variable -Name PROFILE -Scope Global -Value $script:sandboxPs7Profile
    $env:CI = 'true'
    . $script:sandboxPs7Profile

    $workspace = Join-Path $env:TEMP "psp-ci-func-$([System.IO.Path]::GetRandomFileName())"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $startLocation = Get-Location
    $tcpListener = $null
    $httpJob = $null
    $httpPort = $null

    try {
        New-Item -ItemType Directory -Path $workspace -Force | Out-Null

        $textFile = Join-Path $workspace 'sample.txt'
        $jsonFile = Join-Path $workspace 'sample.json'
        $zipSourceDir = Join-Path $workspace 'zip-src'
        $zipFile = Join-Path $workspace 'sample.zip'
        $sedFile = Join-Path $workspace 'sed-target.txt'
        $touchFile = Join-Path $workspace 'touch-created.txt'
        $nfFile = Join-Path $workspace 'nf-created.txt'
        $mkcdDir = Join-Path $workspace 'mkcd-dir'
        $extractDir = Join-Path $workspace 'extract-target'

        [System.IO.File]::WriteAllText($textFile, "line1`nline2`nline3`nline4`nline5", $utf8NoBom)
        [System.IO.File]::WriteAllText($jsonFile, '{"name":"ci","nested":{"a":1}}', $utf8NoBom)
        [System.IO.File]::WriteAllText($sedFile, 'foo bar baz', $utf8NoBom)
        New-Item -ItemType Directory -Path $zipSourceDir -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $zipSourceDir 'inside.txt'), 'zip-content', $utf8NoBom)
        Compress-Archive -Path (Join-Path $zipSourceDir '*') -DestinationPath $zipFile -Force

        # Temp git repo for git command probes
        $gitRepo = Join-Path $workspace 'git-repo'
        New-Item -ItemType Directory -Path $gitRepo -Force | Out-Null
        $beforeGit = Get-Location
        try {
            Set-Location $gitRepo
            git init --quiet
            git config user.email 'ci@example.com'
            git config user.name 'CI'
            [System.IO.File]::WriteAllText((Join-Path $gitRepo 'readme.txt'), 'initial', $utf8NoBom)
            git add .
            git commit -m 'initial' --quiet
        }
        finally {
            Set-Location $beforeGit
        }

        # Local TCP listener for deterministic checkport/portscan probes
        $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $tcpListener.Start()
        $localPort = ([System.Net.IPEndPoint]$tcpListener.LocalEndpoint).Port

        # Local HTTP endpoint for deterministic http probe
        $httpPortProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $httpPortProbe.Start()
        $httpPort = ([System.Net.IPEndPoint]$httpPortProbe.LocalEndpoint).Port
        $httpPortProbe.Stop()
        $httpJob = Start-Job -ScriptBlock {
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add("http://127.0.0.1:$($using:httpPort)/")
            $listener.Start()
            try {
                $context = $listener.GetContext()
                $payload = '{"ok":true}'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = 'application/json'
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.OutputStream.Close()
            }
            finally {
                if ($listener.IsListening) { $listener.Stop() }
                $listener.Close()
            }
        }
        Start-Sleep -Milliseconds 200

        # Environment feature detection
        $clipboardReady = [bool](Get-Command Set-Clipboard -ErrorAction SilentlyContinue) -and [bool](Get-Command Get-Clipboard -ErrorAction SilentlyContinue)
        $clipboardSkipReason = $null
        if ($clipboardReady) {
            try {
                Set-Clipboard 'psp-ci-probe'
                $probeText = (Get-Clipboard -Raw | Out-String).Trim()
                if ($probeText -ne 'psp-ci-probe') { throw 'Clipboard roundtrip mismatch' }
            }
            catch {
                $clipboardReady = $false
                $clipboardSkipReason = "Clipboard unavailable in this host: $($_.Exception.Message)"
            }
        }
        else {
            $clipboardSkipReason = 'Set-Clipboard/Get-Clipboard not available'
        }

        $hasDocker = [bool](Get-Command docker -ErrorAction SilentlyContinue)
        $dockerRunning = $false
        if ($hasDocker) {
            docker info *> $null
            $dockerRunning = ($LASTEXITCODE -eq 0)
        }
        $dockerSkipReason = if (-not $hasDocker) { 'docker not installed' } elseif (-not $dockerRunning) { 'docker daemon not running' } else { $null }

        Write-Host '  Command probes:' -ForegroundColor Cyan
        # Profile and updates
        Invoke-CommandProbe -Command 'Show-Help' -Code { Show-Help }
        Invoke-CommandProbe -Command 'path' -Code {
            $pathOut = path | Out-String
            if ([string]::IsNullOrWhiteSpace($pathOut)) { throw 'path returned empty output' }
        }
        Invoke-CommandProbe -Command 'prompt' -Code {
            $p = prompt
            if ([string]::IsNullOrWhiteSpace($p)) { throw 'prompt returned empty string' }
        }
        Invoke-CommandProbe -Command 'Get-SystemBootTime' -Code {
            $boot = Get-SystemBootTime
            if (-not $boot) { throw 'Get-SystemBootTime returned null' }
        }
        Invoke-CommandProbe -Command 'Resolve-PreferredEditor' -Code {
            $editor = Resolve-PreferredEditor
            if ([string]::IsNullOrWhiteSpace($editor)) { throw 'Resolve-PreferredEditor returned empty value' }
        }
        Invoke-CommandProbe -Command 'reload' -SkipReason 'Reloads profile mid-test'
        Invoke-CommandProbe -Command 'Restart-TerminalToApply' -SkipReason 'Exits process and restarts terminal'
        Invoke-CommandProbe -Command 'Edit-Profile' -SkipReason 'Opens interactive editor'
        Invoke-CommandProbe -Command 'ep' -SkipReason 'Alias to Edit-Profile (opens interactive editor)'
        Invoke-CommandProbe -Command 'edit' -SkipReason 'Opens interactive editor'
        # Update flows are network/mutation-heavy; we can't run them end-to-end in CI, but at
        # least verify the parameter contract so renames/removals don't silently break muscle
        # memory, and drive the safe early-exit paths each function exposes.
        Invoke-CommandProbe -Command 'Update-Profile' -Code {
            $cmd = Get-Command Update-Profile
            foreach ($p in @('Force', 'SkipHashCheck', 'ExpectedSha256', 'WhatIf')) {
                if (-not $cmd.Parameters.ContainsKey($p)) { throw "Update-Profile missing expected parameter: $p" }
            }
            # -WhatIf must trip the ShouldProcess gate BEFORE the Phase 1 downloads so
            # no psp-profile-*.ps1 / psp-theme-*.json / psp-terminal-*.json appears in %TEMP%.
            $filters = @('psp-profile-*.ps1', 'psp-theme-*.json', 'psp-terminal-*.json')
            $pre = foreach ($f in $filters) { Get-ChildItem -Path $env:TEMP -Filter $f -ErrorAction SilentlyContinue }
            Update-Profile -WhatIf -Confirm:$false | Out-Null
            $post = foreach ($f in $filters) { Get-ChildItem -Path $env:TEMP -Filter $f -ErrorAction SilentlyContinue }
            if (@($post).Count -gt @($pre).Count) {
                throw "Update-Profile -WhatIf created temp files (download ran): $(($post | Select-Object -ExpandProperty Name) -join ', ')"
            }
        }
        Invoke-CommandProbe -Command 'Update-PowerShell' -Code {
            # Safe early exits: PS5 prints a guidance message and returns; PS7 without winget
            # prints a warning. Either way the function must not throw on first invocation.
            Update-PowerShell *> $null
        }
        Invoke-CommandProbe -Command 'Update-Tools' -Code {
            # Safe early exit when winget is absent; with winget we still need skip because
            # it would actually mutate installed tools. Only run when winget is unavailable.
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                Write-Host '        (skipping live invocation; winget present in CI host)' -ForegroundColor DarkGray
            }
            else {
                Update-Tools *> $null
            }
            $cmd = Get-Command Update-Tools
            if (-not $cmd) { throw 'Update-Tools missing' }
        }
        Invoke-CommandProbe -Command 'Clear-ProfileCache' -Code {
            $origLocal = $env:LOCALAPPDATA
            try {
                $fakeLocal = Join-Path $workspace 'localappdata'
                $fakeCache = Join-Path $fakeLocal 'PowerShellProfile'
                $fakePlugins = Join-Path $fakeCache 'plugins'
                New-Item -ItemType Directory -Path $fakePlugins -Force | Out-Null
                [System.IO.File]::WriteAllText((Join-Path $fakeCache 'transient.cache'), 'x', $utf8NoBom)
                [System.IO.File]::WriteAllText((Join-Path $fakeCache 'user-settings.json'), '{}', $utf8NoBom)
                [System.IO.File]::WriteAllText((Join-Path $fakePlugins 'myplugin.ps1'), '# user plugin', $utf8NoBom)
                $env:LOCALAPPDATA = $fakeLocal
                Clear-ProfileCache
                if (Test-Path (Join-Path $fakeCache 'transient.cache')) { throw 'Clear-ProfileCache did not remove transient file' }
                if (-not (Test-Path (Join-Path $fakeCache 'user-settings.json'))) { throw 'Clear-ProfileCache removed user-settings.json' }
                if (-not (Test-Path (Join-Path $fakePlugins 'myplugin.ps1'))) { throw 'Clear-ProfileCache removed user plugin' }
            }
            finally {
                $env:LOCALAPPDATA = $origLocal
            }
        }
        Invoke-CommandProbe -Command 'Clear-Cache' -Code { Clear-Cache -WhatIf -Confirm:$false | Out-Null }
        Invoke-CommandProbe -Command 'Uninstall-Profile' -Code { Uninstall-Profile -All -WhatIf -Confirm:$false | Out-Null }
        Invoke-CommandProbe -Command 'Invoke-ProfileWizard' -Code {
            # SupportsShouldProcess lets us drive the invocation path without network download.
            # -WhatIf returns before Invoke-DownloadWithRetry, so this is safe in CI.
            # We also verify the ShouldProcess gate actually prevents the temp download by
            # ensuring no psp-reconfigure-*.ps1 files exist in %TEMP% after the -WhatIf call.
            $preFiles = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*.ps1' -ErrorAction SilentlyContinue)
            Invoke-ProfileWizard -WhatIf -Confirm:$false | Out-Null
            $postFiles = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*.ps1' -ErrorAction SilentlyContinue)
            if ($postFiles.Count -gt $preFiles.Count) {
                throw "Invoke-ProfileWizard -WhatIf created temp files it should not have: $($postFiles.Name -join ', ')"
            }
            $cmd = Get-Command Invoke-ProfileWizard
            foreach ($p in @('Resume', 'NoElevate', 'ExpectedSha256', 'SkipHashCheck', 'WhatIf')) {
                if (-not $cmd.Parameters.ContainsKey($p)) { throw "Invoke-ProfileWizard missing expected parameter: $p" }
            }
        }
        Invoke-CommandProbe -Command 'Reconfigure-Profile' -Code {
            $alias = Get-Alias Reconfigure-Profile -ErrorAction SilentlyContinue
            if (-not $alias) { throw 'Reconfigure-Profile alias missing' }
            if ($alias.ResolvedCommandName -ne 'Invoke-ProfileWizard') { throw "Reconfigure-Profile points to $($alias.ResolvedCommandName), expected Invoke-ProfileWizard" }
        }
        Invoke-CommandProbe -Command 'Invoke-DownloadWithRetry' -SkipReason 'Internal helper (covered by setup tests)'
        Invoke-CommandProbe -Command 'Invoke-WithTimeout' -SkipReason 'Internal helper (used by OMP/zoxide init)'
        Invoke-CommandProbe -Command 'Merge-JsonObject' -SkipReason 'Internal helper nested in Update-Profile'

        # Git
        Invoke-CommandProbe -Command 'gs' -Code {
            $before = Get-Location
            try { Set-Location $gitRepo; gs | Out-Null } finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'ga' -Code {
            $before = Get-Location
            try {
                Set-Location $gitRepo
                [System.IO.File]::WriteAllText((Join-Path $gitRepo 'ga.txt'), 'ga', $utf8NoBom)
                ga
                $status = git status --porcelain
                if ($status -notmatch 'A\s+ga\.txt') { throw "ga did not stage file: $status" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'gc' -Code {
            $before = Get-Location
            try {
                Set-Location $gitRepo
                gc 'ci gc commit'
                $last = (git log -1 --pretty=%s | Out-String).Trim()
                if ($last -ne 'ci gc commit') { throw "gc commit mismatch: $last" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'gcom' -Code {
            $before = Get-Location
            try {
                Set-Location $gitRepo
                [System.IO.File]::WriteAllText((Join-Path $gitRepo 'gcom.txt'), 'gcom', $utf8NoBom)
                gcom 'ci gcom commit'
                $last = (git log -1 --pretty=%s | Out-String).Trim()
                if ($last -ne 'ci gcom commit') { throw "gcom commit mismatch: $last" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'gpush' -SkipReason 'No remote configured in CI sandbox repo'
        Invoke-CommandProbe -Command 'gpull' -SkipReason 'No remote configured in CI sandbox repo'
        Invoke-CommandProbe -Command 'gcl' -SkipReason 'Requires network clone target'
        Invoke-CommandProbe -Command 'lazyg' -SkipReason 'Includes push to remote'
        Invoke-CommandProbe -Command 'g' -SkipReason 'Depends on local zoxide jump target'

        # Files and navigation
        Invoke-CommandProbe -Command 'ls' -Code { ls $workspace | Out-Null }
        Invoke-CommandProbe -Command 'la' -Code { la $workspace | Out-Null }
        Invoke-CommandProbe -Command 'll' -Code { ll $workspace | Out-Null }
        Invoke-CommandProbe -Command 'lt' -Code { lt $workspace | Out-Null }
        Invoke-CommandProbe -Command 'cat' -Code { cat $textFile | Out-Null }
        Invoke-CommandProbe -Command 'ff' -Code {
            $before = Get-Location
            try {
                Set-Location $workspace
                $result = ff 'sample'
                $txt = ($result | Out-String)
                if ($txt -notmatch 'sample\.txt') { throw "ff output missing sample.txt: $txt" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'touch' -Code {
            touch $touchFile
            if (-not (Test-Path $touchFile)) { throw 'touch did not create file' }
        }
        Invoke-CommandProbe -Command 'nf' -Code {
            nf $nfFile
            if (-not (Test-Path $nfFile)) { throw 'nf did not create file' }
        }
        Invoke-CommandProbe -Command 'mkcd' -Code {
            $before = Get-Location
            try {
                mkcd $mkcdDir
                if ([System.IO.Path]::GetFullPath((Get-Location).Path) -ne [System.IO.Path]::GetFullPath($mkcdDir)) { throw "mkcd did not change directory to $mkcdDir" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'head' -Code {
            $h = @((head $textFile 2) | Where-Object { $_ -is [string] })
            if ($h.Count -ne 2) { throw "head expected 2 lines, got $($h.Count)" }
        }
        Invoke-CommandProbe -Command 'tail' -Code {
            $t = @((tail $textFile 2) | Where-Object { $_ -is [string] })
            if ($t.Count -ne 2) { throw "tail expected 2 lines, got $($t.Count)" }
        }
        Invoke-CommandProbe -Command 'file' -Code { file $textFile | Out-Null }
        Invoke-CommandProbe -Command 'sizeof' -Code {
            $size = sizeof $textFile
            if (-not $size) { throw 'sizeof returned empty value' }
        }
        Invoke-CommandProbe -Command 'trash' -SkipReason 'Shell.Application recycle-bin COM is unreliable in headless CI'
        Invoke-CommandProbe -Command 'extract' -Code {
            New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
            $before = Get-Location
            try {
                Set-Location $extractDir
                extract $zipFile
                $inside = Get-ChildItem -Path $extractDir -Recurse -Filter 'inside.txt' -ErrorAction SilentlyContinue
                if (-not $inside) { throw 'extract did not create inside.txt' }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'docs' -Code {
            $before = Get-Location
            try {
                docs
                if (-not (Test-Path (Get-Location).Path)) { throw 'docs did not navigate to existing path' }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'dtop' -Code {
            $before = Get-Location
            try {
                dtop
                if (-not (Test-Path (Get-Location).Path)) { throw 'dtop did not navigate to existing path' }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'cdh' -Code {
            # Seed the stack by cd'ing through two dirs, invoking Invoke-PromptStage
            # manually since the probe does not render a prompt.
            $before = Get-Location
            try {
                $sub = Join-Path $workspace 'cdh-probe'
                New-Item -ItemType Directory -Path $sub -Force | Out-Null
                Set-Location -LiteralPath $sub
                Invoke-PromptStage
                Set-Location -LiteralPath $workspace
                Invoke-PromptStage
                $out = cdh | Out-String
                if ($out -notmatch 'cdh-probe') { throw "cdh output missing seeded entry: $out" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'cdb' -Code {
            $before = Get-Location
            try {
                $sub = Join-Path $workspace 'cdb-probe'
                New-Item -ItemType Directory -Path $sub -Force | Out-Null
                Set-Location -LiteralPath $sub
                Invoke-PromptStage
                Set-Location -LiteralPath $workspace
                Invoke-PromptStage
                cdb 1
                if ((Get-Location).Path -ne $sub) { throw "cdb 1 did not navigate back; got $((Get-Location).Path)" }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'duration' -Code {
            # Ensure a command is present in Get-History before calling duration
            Get-Date | Out-Null
            $out = duration | Out-String
            if ([string]::IsNullOrWhiteSpace($out)) { throw 'duration produced no output' }
        }
        Invoke-CommandProbe -Command 'Test-ProfileHealth' -Code {
            $report = Test-ProfileHealth
            if (-not $report) { throw 'Test-ProfileHealth returned no rows' }
            $expected = @('Tools', 'Caches', 'Config', 'PATH', 'Modules')
            foreach ($cat in $expected) {
                if (-not ($report | Where-Object Category -eq $cat)) { throw "Test-ProfileHealth missing category: $cat" }
            }
        }
        Invoke-CommandProbe -Command 'psp-doctor' -Code {
            $alias = Get-Alias psp-doctor -ErrorAction SilentlyContinue
            if (-not $alias) { throw 'psp-doctor alias missing' }
            if ($alias.ResolvedCommandName -ne 'Test-ProfileHealth') { throw "psp-doctor points to $($alias.ResolvedCommandName)" }
        }
        Invoke-CommandProbe -Command 'bak' -Code {
            bak $textFile
            $baks = Get-ChildItem -Path $workspace -Filter 'sample.txt.*.bak' -ErrorAction SilentlyContinue
            if (-not $baks) { throw 'bak did not create backup file' }
        }

        # Unix-like
        Invoke-CommandProbe -Command 'grep' -Code {
            $result = grep 'line' $workspace | Out-String
            if ($result -notmatch 'line') { throw 'grep output missing expected content' }
        }
        Invoke-CommandProbe -Command 'sed' -Code {
            sed $sedFile 'bar' 'qux'
            $content = Get-Content $sedFile -Raw
            if ($content -notmatch 'qux') { throw "sed did not replace target text: $content" }
        }
        Invoke-CommandProbe -Command 'which' -Code {
            $w = which pwsh | Out-String
            if ([string]::IsNullOrWhiteSpace($w)) { throw 'which pwsh returned empty output' }
        }
        Invoke-CommandProbe -Command 'pgrep' -Code {
            $r = pgrep 'pwsh'
            if (-not $r) { throw 'pgrep did not return any pwsh process' }
        }
        Invoke-CommandProbe -Command 'pkill' -SkipReason 'Destructive process termination command'
        Invoke-CommandProbe -Command 'export' -Code {
            export 'PSP_TEST_VAR' 'ci'
            if ($env:PSP_TEST_VAR -ne 'ci') { throw 'export did not set env var' }
        }
        # System and network
        Invoke-CommandProbe -Command 'admin' -SkipReason 'Opens elevated terminal UI'
        Invoke-CommandProbe -Command 'su' -SkipReason 'Alias to admin (opens elevated terminal UI)'
        Invoke-CommandProbe -Command 'pubip' -Code { pubip | Out-Null }
        Invoke-CommandProbe -Command 'localip' -Code { localip | Out-Null }
        Invoke-CommandProbe -Command 'uptime' -Code { uptime | Out-Null }
        Invoke-CommandProbe -Command 'sysinfo' -Code { sysinfo | Out-Null }
        Invoke-CommandProbe -Command 'df' -Code { df | Out-Null }
        Invoke-CommandProbe -Command 'flushdns' -SkipReason 'Requires elevated permissions in many environments'
        Invoke-CommandProbe -Command 'ports' -Code { ports | Out-Null }
        Invoke-CommandProbe -Command 'checkport' -SkipReason 'Test-NetConnection can fail on hosted runners without stable adapter metadata'
        Invoke-CommandProbe -Command 'portscan' -Code { portscan '127.0.0.1' -Ports @($localPort) | Out-Null }
        Invoke-CommandProbe -Command 'tlscert' -Code { tlscert 'example.com' | Out-Null }
        Invoke-CommandProbe -Command 'ipinfo' -Code { ipinfo '8.8.8.8' | Out-Null }
        Invoke-CommandProbe -Command 'whois' -Code { whois 'example.com' | Out-Null }
        Invoke-CommandProbe -Command 'nslook' -Code { nslook 'localhost' | Out-Null }
        Invoke-CommandProbe -Command 'env' -Code { env 'PATH' | Out-Null }
        Invoke-CommandProbe -Command 'svc' -Code { svc -Count 1 | Out-Null }
        Invoke-CommandProbe -Command 'eventlog' -Code { eventlog 1 | Out-Null }
        Invoke-CommandProbe -Command 'weather' -Code { weather 'Oslo' | Out-Null }
        Invoke-CommandProbe -Command 'speedtest' -SkipReason 'Long-running network benchmark'
        Invoke-CommandProbe -Command 'wifipass' -SkipReason 'Requires WLAN profile context and often elevation'
        Invoke-CommandProbe -Command 'hosts' -SkipReason 'Opens elevated editor UI'
        Invoke-CommandProbe -Command 'winutil' -SkipReason 'Remote-script wrapper is unit-tested separately; live run intentionally skipped'
        Invoke-CommandProbe -Command 'harden' -SkipReason 'Launches external hardening tool / GUI on developer machines'

        # Security and crypto
        $sha256 = $null
        Invoke-CommandProbe -Command 'hash' -Code {
            $script:sha256 = (hash $textFile -Algorithm SHA256 | Out-String).Trim()
            if (-not $script:sha256 -or $script:sha256.Length -ne 64) { throw "invalid SHA256 hash output: $script:sha256" }
        }
        Invoke-CommandProbe -Command 'checksum' -Code {
            if (-not $script:sha256) { throw 'hash probe did not populate SHA256 value' }
            checksum $textFile $script:sha256 | Out-Null
        }
        Invoke-CommandProbe -Command 'genpass' -Code {
            $p = genpass 16
            if (-not $p -or $p.Length -ne 16) { throw 'genpass did not return 16-character password' }
        } -SkipReason $clipboardSkipReason
        Invoke-CommandProbe -Command 'b64' -Code {
            $enc = (b64 'hello world' | Out-String).Trim()
            if ([string]::IsNullOrWhiteSpace($enc)) { throw 'b64 returned empty value' }
        }
        Invoke-CommandProbe -Command 'b64d' -Code {
            $dec = (b64d 'aGVsbG8gd29ybGQ=' | Out-String).Trim()
            if ($dec -ne 'hello world') { throw "b64d returned unexpected value: $dec" }
        }
        Invoke-CommandProbe -Command 'jwtd' -Code {
            $sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            jwtd $sampleJwt | Out-Null
        }
        Invoke-CommandProbe -Command 'uuid' -Code { uuid | Out-Null } -SkipReason $clipboardSkipReason
        Invoke-CommandProbe -Command 'epoch' -Code {
            $now = [int64]((epoch | Out-String).Trim())
            if ($now -le 0) { throw "epoch now is invalid: $now" }
            $d = epoch 0
            if (-not $d -or $d.Year -ne 1970) { throw "epoch 0 conversion failed: $d" }
        }
        Invoke-CommandProbe -Command 'urlencode' -Code {
            $enc = (urlencode 'hello world' | Out-String).Trim()
            if ($enc -notmatch 'hello') { throw "urlencode returned unexpected value: $enc" }
        }
        Invoke-CommandProbe -Command 'urldecode' -Code {
            $dec = (urldecode 'hello%20world' | Out-String).Trim()
            if ($dec -ne 'hello world') { throw "urldecode returned unexpected value: $dec" }
        }
        Invoke-CommandProbe -Command 'vtscan' -SkipReason 'Requires VirusTotal API key and uploads content'
        Invoke-CommandProbe -Command 'vt' -Code {
            if (Get-Command vt.exe -ErrorAction SilentlyContinue) { vt --help | Out-Null }
            else { vt | Out-Null }
        }

        # Developer
        Invoke-CommandProbe -Command 'killport' -SkipReason 'Destructive process termination command'
        Invoke-CommandProbe -Command 'Stop-ListeningPort' -SkipReason 'Interactive fzf picker; destructive'
        Invoke-CommandProbe -Command 'killports' -SkipReason 'Alias to Stop-ListeningPort'
        Invoke-CommandProbe -Command 'Find-FileLocker' -Code {
            # Lock a temp file and verify Find-FileLocker reports our own PID.
            $lockFile = Join-Path $workspace 'lock-probe.txt'
            [System.IO.File]::WriteAllText($lockFile, 'x', $utf8NoBom)
            $stream = [System.IO.File]::Open($lockFile, 'Open', 'ReadWrite', 'None')
            try {
                $lockers = @(Find-FileLocker $lockFile)
                $selfPid = $PID
                if (-not ($lockers | Where-Object PID -eq $selfPid)) { throw "Find-FileLocker did not report self PID $selfPid for locked file" }
            }
            finally { $stream.Close(); $stream.Dispose() }
        }
        Invoke-CommandProbe -Command 'Stop-StuckProcess' -SkipReason 'Destructive process termination'
        Invoke-CommandProbe -Command 'Remove-LockedItem' -SkipReason 'Destructive: kills processes and deletes'
        Invoke-CommandProbe -Command 'http' -Code {
            $response = http "http://127.0.0.1:$httpPort/" -Method GET | Out-String
            if ($response -notmatch '"ok"\s*:\s*true') { throw "unexpected http response: $response" }
            Wait-Job -Job $httpJob -Timeout 5 | Out-Null
            Receive-Job -Job $httpJob | Out-Null
        }
        Invoke-CommandProbe -Command 'prettyjson' -Code {
            $pretty = prettyjson $jsonFile | Out-String
            if ($pretty -notmatch '"name"\s*:\s*"ci"') { throw 'prettyjson output missing expected key/value' }
        }
        Invoke-CommandProbe -Command 'hb' -Code { hb $textFile | Out-Null } -SkipReason $clipboardSkipReason
        Invoke-CommandProbe -Command 'timer' -Code { timer { Start-Sleep -Milliseconds 5 } | Out-Null }
        Invoke-CommandProbe -Command 'watch' -SkipReason 'Infinite loop by design'

        # Docker
        Invoke-CommandProbe -Command 'dps' -Code { dps | Out-Null } -SkipReason $dockerSkipReason
        Invoke-CommandProbe -Command 'dpa' -Code { dpa | Out-Null } -SkipReason $dockerSkipReason
        Invoke-CommandProbe -Command 'dimg' -Code { dimg 2>$null | Out-Null } -SkipReason $dockerSkipReason
        Invoke-CommandProbe -Command 'dlogs' -SkipReason 'Requires running container name'
        Invoke-CommandProbe -Command 'dex' -SkipReason 'Requires running container name'
        Invoke-CommandProbe -Command 'dstop' -SkipReason 'Destructive: stops running containers'
        Invoke-CommandProbe -Command 'dprune' -SkipReason 'Destructive: prunes docker resources'

        # SSH and remote
        Invoke-CommandProbe -Command 'ssh' -SkipReason 'Wraps native ssh.exe; would initiate real TCP connect'
        Invoke-CommandProbe -Command 'Copy-SshKey' -SkipReason 'Requires reachable remote host'
        Invoke-CommandProbe -Command 'ssh-copy-key' -SkipReason 'Alias requiring reachable remote host'
        Invoke-CommandProbe -Command 'keygen' -SkipReason 'Writes SSH keys to user profile'
        Invoke-CommandProbe -Command 'rdp' -SkipReason 'Opens Remote Desktop UI'
        Invoke-CommandProbe -Command 'wsl' -SkipReason 'Wraps wsl.exe; would launch a distro shell'
        Invoke-CommandProbe -Command 'Get-WslDistro' -Code {
            # Parses wsl -l -v; safe to call. May return empty list if no distros installed on runner.
            Get-WslDistro | Out-Null
        }
        Invoke-CommandProbe -Command 'Enter-WslHere' -SkipReason 'Opens interactive WSL shell'
        Invoke-CommandProbe -Command 'wsl-here' -SkipReason 'Alias to Enter-WslHere (interactive)'
        Invoke-CommandProbe -Command 'ConvertTo-WslPath' -SkipReason 'Requires at least one installed WSL distro'
        Invoke-CommandProbe -Command 'ConvertTo-WindowsPath' -SkipReason 'Requires at least one installed WSL distro'
        Invoke-CommandProbe -Command 'Stop-Wsl' -SkipReason 'Destructive: terminates running distros'
        Invoke-CommandProbe -Command 'Get-WslIp' -SkipReason 'Requires a running WSL distro'
        Invoke-CommandProbe -Command 'Get-WslFile' -SkipReason 'Requires a running WSL distro (UNC path access)'
        Invoke-CommandProbe -Command 'Show-WslTree' -SkipReason 'Requires a running WSL distro'
        Invoke-CommandProbe -Command 'wsl-tree' -SkipReason 'Alias to Show-WslTree; requires a running WSL distro'
        Invoke-CommandProbe -Command 'Open-WslExplorer' -SkipReason 'Opens Windows Explorer; requires running distro'
        Invoke-CommandProbe -Command 'wsl-explorer' -SkipReason 'Alias to Open-WslExplorer'

        # Clipboard
        Invoke-CommandProbe -Command 'cpy' -Code { cpy 'psp-ci-clipboard' } -SkipReason $clipboardSkipReason
        Invoke-CommandProbe -Command 'pst' -Code {
            $text = (pst | Out-String).Trim()
            if ($text -ne 'psp-ci-clipboard') { throw "pst returned unexpected text: $text" }
        } -SkipReason $clipboardSkipReason
        $invokeClipboardSkipReason = if ($clipboardSkipReason) { $clipboardSkipReason } else { 'Clipboard insertion behavior is host-dependent in headless sessions' }
        Invoke-CommandProbe -Command 'Invoke-Clipboard' -SkipReason $invokeClipboardSkipReason
        Invoke-CommandProbe -Command 'icb' -SkipReason $invokeClipboardSkipReason

        # Sysadmin / Linux-feel
        Invoke-CommandProbe -Command 'journal' -Code { journal -Count 5 | Out-Null }
        Invoke-CommandProbe -Command 'lsblk' -Code { lsblk | Out-Null }
        Invoke-CommandProbe -Command 'htop' -SkipReason 'Launches interactive TUI process viewer'
        Invoke-CommandProbe -Command 'mtr' -SkipReason 'Long-running traceroute + per-hop ping loop'
        Invoke-CommandProbe -Command 'fwallow' -SkipReason 'Mutates Windows Firewall rules (requires elevation)'
        Invoke-CommandProbe -Command 'fwblock' -SkipReason 'Mutates Windows Firewall rules (requires elevation)'

        # Cybersec
        Invoke-CommandProbe -Command 'nscan' -SkipReason 'Requires nmap binary'
        Invoke-CommandProbe -Command 'sigcheck' -Code {
            $sysExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (-not (Test-Path $sysExe)) { throw "Expected signed host binary not found: $sysExe" }
            sigcheck $sysExe | Out-Null
        }
        Invoke-CommandProbe -Command 'ads' -Code {
            $adsFile = Join-Path $workspace 'ads-target.txt'
            [System.IO.File]::WriteAllText($adsFile, 'primary', $utf8NoBom)
            Set-Content -LiteralPath $adsFile -Stream 'zone.hint' -Value 'ci-marker'
            $result = @(ads $adsFile)
            $match = $result | Where-Object { $_.Stream -eq 'zone.hint' }
            if (-not $match) { throw "ads did not return object for zone.hint stream" }
        }
        Invoke-CommandProbe -Command 'defscan' -SkipReason 'Triggers Windows Defender scan'
        Invoke-CommandProbe -Command 'pwnd' -Code { pwnd 'password' | Out-Null }
        Invoke-CommandProbe -Command 'certcheck' -Code { certcheck 'example.com' | Out-Null }
        Invoke-CommandProbe -Command 'entropy' -Code { entropy $textFile | Out-Null }

        # Developer+
        Invoke-CommandProbe -Command 'serve' -SkipReason 'Long-running HTTP server (blocks)'
        Invoke-CommandProbe -Command 'gitignore' -Code {
            $before = Get-Location
            try {
                $giDir = Join-Path $workspace 'gi-target'
                New-Item -ItemType Directory -Path $giDir -Force | Out-Null
                Set-Location $giDir
                gitignore 'python' | Out-Null
                if (-not (Test-Path (Join-Path $giDir '.gitignore'))) { throw 'gitignore did not create .gitignore' }
            }
            finally { Set-Location $before }
        }
        Invoke-CommandProbe -Command 'gcof' -SkipReason 'Interactive fzf branch picker'
        Invoke-CommandProbe -Command 'envload' -Code {
            $envFile = Join-Path $workspace 'probe.env'
            [System.IO.File]::WriteAllText($envFile, "PSP_ENVLOAD_TEST=ok`n# comment`nexport PSP_ENVLOAD_QUOTED=`"quoted value`"", $utf8NoBom)
            envload $envFile | Out-Null
            if ($env:PSP_ENVLOAD_TEST -ne 'ok') { throw "envload did not set PSP_ENVLOAD_TEST: $env:PSP_ENVLOAD_TEST" }
            if ($env:PSP_ENVLOAD_QUOTED -ne 'quoted value') { throw "envload did not strip quotes: $env:PSP_ENVLOAD_QUOTED" }
        }
        Invoke-CommandProbe -Command 'tldr' -Code { tldr 'ls' | Out-Null }
        Invoke-CommandProbe -Command 'repeat' -Code {
            $script:repeatCount = 0
            repeat 3 { $script:repeatCount++ } | Out-Null
            if ($script:repeatCount -ne 3) { throw "repeat expected 3 iterations, got $script:repeatCount" }
        }
        Invoke-CommandProbe -Command 'mkvenv' -SkipReason 'Creates Python venv directory and activates it'

        # Detection / AST
        Invoke-CommandProbe -Command 'outline' -Code {
            $entries = @(outline $profilePath)
            $fnHit = $entries | Where-Object { $_.Kind -eq 'Function' -and $_.Name -eq 'Update-Profile' }
            if (-not $fnHit) { throw 'outline did not emit Function entry for Update-Profile' }
        }
        Invoke-CommandProbe -Command 'psym' -Code { psym 'Update-Profile' $repoRoot | Out-Null }
        Invoke-CommandProbe -Command 'lint' -SkipReason 'Requires PSScriptAnalyzer module; covered by lint job'
        Invoke-CommandProbe -Command 'Find-DeadCode' -Code {
            $fixture = Join-Path $workspace 'dead.ps1'
            [System.IO.File]::WriteAllText($fixture, "function used { param(`$a, `$b) `$a }`nused 1 2", $utf8NoBom)
            Find-DeadCode $fixture | Out-Null
        }
        Invoke-CommandProbe -Command 'Test-Profile' -Code { Test-Profile | Out-Null }
        Invoke-CommandProbe -Command 'Get-PwshVersions' -Code { Get-PwshVersions | Out-Null }
        Invoke-CommandProbe -Command 'modinfo' -Code {
            $info = @(modinfo 'PSReadLine')
            if (-not $info) { throw 'modinfo returned nothing for PSReadLine' }
            if ($info[0].Name -ne 'PSReadLine') { throw "modinfo Name mismatch: $($info[0].Name)" }
        }
        Invoke-CommandProbe -Command 'psgrep' -Code { psgrep 'Update-Profile' $repoRoot -Kind Function | Out-Null }

        # Extensibility
        Invoke-CommandProbe -Command 'Register-ProfileHook' -Code {
            $script:hookFired = 0
            Register-ProfileHook -EventName 'OnProfileLoad' -Action { $script:hookFired++ }
            if ($script:PSP.Hooks.OnProfileLoad.Count -lt 1) { throw 'Register-ProfileHook did not add hook' }
        }
        Invoke-CommandProbe -Command 'Register-HelpSection' -Code {
            $before = $script:PSP.HelpSections.Count
            Register-HelpSection -Title 'CI Probe Section' -Lines @('line one', 'line two')
            if ($script:PSP.HelpSections.Count -ne $before + 1) { throw 'Register-HelpSection did not add section' }
        }
        Invoke-CommandProbe -Command 'Register-ProfileCommand' -Code {
            $before = $script:PSP.Commands.Count
            Register-ProfileCommand -Name 'probe-cmd' -Category 'Probe' -Synopsis 'ci probe'
            if ($script:PSP.Commands.Count -ne $before + 1) { throw 'Register-ProfileCommand did not add command' }
        }
        Invoke-CommandProbe -Command 'Get-ProfileCommand' -Code {
            $all = Get-ProfileCommand
            if (-not $all -or $all.Count -lt 50) { throw "Get-ProfileCommand returned only $($all.Count) entries" }
            $filtered = Get-ProfileCommand -Category 'Git'
            if (-not $filtered -or $filtered.Count -lt 3) { throw 'Category filter returned too few' }
        }
        Invoke-CommandProbe -Command 'Start-ProfileTour' -SkipReason 'Interactive walkthrough (Read-Host loop)'
        Invoke-CommandProbe -Command 'Add-TrustedDirectory' -Code {
            $origSettingsPath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\user-settings.json'
            $origContent = if (Test-Path $origSettingsPath) { Get-Content $origSettingsPath -Raw } else { $null }
            try {
                $trustDir = Join-Path $workspace 'trust-target'
                New-Item -ItemType Directory -Path $trustDir -Force | Out-Null
                Add-TrustedDirectory -Path $trustDir -Confirm:$false
                if ($script:PSP.TrustedDirs -notcontains (Resolve-Path $trustDir).ProviderPath) {
                    throw 'Add-TrustedDirectory did not register dir'
                }
                # Regression: parse-failure must NOT overwrite existing user-settings.json.
                [System.IO.File]::WriteAllText($origSettingsPath, '{ this is not valid json', $utf8NoBom)
                $preCorruptContent = Get-Content $origSettingsPath -Raw
                $trustDir2 = Join-Path $workspace 'trust-target-2'
                New-Item -ItemType Directory -Path $trustDir2 -Force | Out-Null
                $trustedBefore = @($script:PSP.TrustedDirs).Count
                Add-TrustedDirectory -Path $trustDir2 -Confirm:$false -ErrorAction SilentlyContinue
                $postContent = Get-Content $origSettingsPath -Raw
                if ($postContent -ne $preCorruptContent) { throw 'Add-TrustedDirectory overwrote corrupt user-settings.json instead of aborting' }
                # Regression: failed Save must roll back in-memory Add so state matches disk.
                $trustedAfter = @($script:PSP.TrustedDirs).Count
                if ($trustedAfter -ne $trustedBefore) { throw "Add-TrustedDirectory did not roll back in-memory state (before=$trustedBefore after=$trustedAfter)" }
            }
            finally {
                if ($origContent) { [System.IO.File]::WriteAllText($origSettingsPath, $origContent, $utf8NoBom) }
            }
        }
        Invoke-CommandProbe -Command 'Remove-TrustedDirectory' -Code {
            $origSettingsPath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\user-settings.json'
            $origContent = if (Test-Path $origSettingsPath) { Get-Content $origSettingsPath -Raw } else { $null }
            try {
                $trustDir = Join-Path $workspace 'untrust-target'
                New-Item -ItemType Directory -Path $trustDir -Force | Out-Null
                Add-TrustedDirectory -Path $trustDir -Confirm:$false
                Remove-TrustedDirectory -Path $trustDir -Confirm:$false
                if ($script:PSP.TrustedDirs -contains (Resolve-Path $trustDir).ProviderPath) {
                    throw 'Remove-TrustedDirectory did not remove dir'
                }
            }
            finally {
                if ($origContent) { [System.IO.File]::WriteAllText($origSettingsPath, $origContent, $utf8NoBom) }
            }
        }
        Invoke-CommandProbe -Command 'Set-TerminalBackground' -Code {
            $origSettingsPath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\user-settings.json'
            $origContent = if (Test-Path $origSettingsPath) { Get-Content $origSettingsPath -Raw } else { $null }
            try {
                $bgImg = Join-Path $workspace 'probe-bg.png'
                # Minimal PNG header + IEND to satisfy file-exists check
                $pngBytes = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
                [System.IO.File]::WriteAllBytes($bgImg, $pngBytes)
                Set-TerminalBackground -Path $bgImg -Opacity 0.5 -Confirm:$false
                $settings = Get-Content $origSettingsPath -Raw | ConvertFrom-Json
                if (-not $settings.defaults.backgroundImage) { throw 'Set-TerminalBackground did not persist image' }
                Set-TerminalBackground -Clear -Confirm:$false
                $settings2 = Get-Content $origSettingsPath -Raw | ConvertFrom-Json
                if ($settings2.defaults.PSObject.Properties['backgroundImage']) { throw 'Set-TerminalBackground -Clear did not remove image' }
            }
            finally {
                if ($origContent) { [System.IO.File]::WriteAllText($origSettingsPath, $origContent, $utf8NoBom) }
            }
        }
    }
    finally {
        if ($httpJob) {
            Stop-Job -Job $httpJob -ErrorAction SilentlyContinue | Out-Null
            Receive-Job -Job $httpJob -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $httpJob -Force -ErrorAction SilentlyContinue
        }
        if ($tcpListener) {
            try { $tcpListener.Stop() } catch { $null = $_ }
        }
        Set-Location $startLocation
        Remove-Item -Path $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($script:networkSoftFails.Count -gt 0) {
        Write-Host "    Network soft-fails: $($script:networkSoftFails.Count)" -ForegroundColor Yellow
        if ($VerboseOutput) {
            foreach ($line in $script:networkSoftFails) { Write-Host "      $line" -ForegroundColor Yellow }
        }
    }

    if ($script:commandFailures.Count -gt 0) {
        $sample = ($script:commandFailures | Select-Object -First 5) -join '; '
        throw "$($script:commandFailures.Count) command probe(s) failed. Sample: $sample"
    }
} -SkipWhen { -not $script:installReady } -SkipReason 'Sandbox install failed'

Invoke-TestCase -Name 'Coverage audit against profile exports' -Code {
    $tokens = $null
    $parseErrors = $null
    $profileAst = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "Profile parse errors: $($parseErrors.Count)" }

    $allFns = $profileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object Name | Sort-Object -Unique

    $profileRaw = Get-Content $profilePath -Raw
    $aliasNames = [regex]::Matches($profileRaw, 'Set-Alias\s+-Name\s+([A-Za-z0-9\-]+)\s+-Value\s+([A-Za-z0-9\-]+)') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    # Internal helper functions that are not direct end-user commands
    $internalOnly = @(
        'Get-ExternalCommandPath'
        'Get-OhMyPoshInstallInfo'
        'Get-OhMyPoshMsiProductCode'
        'Get-OhMyPoshExecutablePath'
        'Get-ProfileToolExecutablePath'
        'Get-ProfileToolVersionText'
        'Test-WingetPackageInstalled'
        'Invoke-OhMyPoshCommand'
        'Get-OhMyPoshPromptContext'
        'Get-OhMyPoshPromptText'
        'Merge-JsonObject'
        'Invoke-DownloadWithRetry'
        'Invoke-WithTimeout'
        'Restart-TerminalToApply'
        'Clear-OhMyPoshCaches'
        'Write-JournalLine'
        'Invoke-PromptStage'
        'Invoke-ProfileHook'
        'Save-TrustedDirectories'
        'Read-UserSettingsForWrite'
        'Get-WindowsTerminalSettingsPath'
        'Push-TabTitle'
        'Pop-TabTitle'
        'Resolve-WslUncPath'
        'Initialize-RestartManagerType'
    )
    $commandFns = $allFns | Where-Object { $internalOnly -notcontains $_ }

    $coveredNames = @([string[]]$script:executedCommands + [string[]]$script:skippedCommands.Keys) | Sort-Object -Unique
    $missingFns = $commandFns | Where-Object { $coveredNames -notcontains $_ }
    $missingAliases = $aliasNames | Where-Object { $coveredNames -notcontains $_ }

    if ($missingFns -or $missingAliases) {
        if ($missingFns) { Write-Host "        Missing functions: $($missingFns -join ', ')" -ForegroundColor Red }
        if ($missingAliases) { Write-Host "        Missing aliases: $($missingAliases -join ', ')" -ForegroundColor Red }
        throw 'Coverage gaps found'
    }

    $skipWithoutReason = $script:skippedCommands.GetEnumerator() |
        Where-Object { [string]::IsNullOrWhiteSpace($_.Value) } |
        ForEach-Object { $_.Key }
    if ($skipWithoutReason.Count -gt 0) {
        throw "Skip entries missing reason: $($skipWithoutReason -join ', ')"
    }

    $allExports = @($commandFns + $aliasNames) | Sort-Object -Unique
    $execPct = if ($allExports.Count -gt 0) { [math]::Round(($script:executedCommands.Count / $allExports.Count) * 100) } else { 0 }
    $detail = "functions=$($commandFns.Count), aliases=$($aliasNames.Count), executed=$($script:executedCommands.Count), skipped=$($script:skippedCommands.Count), network-soft-fails=$($script:networkSoftFails.Count), exec%=$execPct"
    Write-Host "        $detail" -ForegroundColor DarkGray
} -SkipWhen { -not $script:installReady } -SkipReason 'Sandbox install failed'

Invoke-TestCase -Name 'Uninstall profile from sandbox' -Code {
    if (-not $script:sandboxPs7Profile -or -not (Test-Path $script:sandboxPs7Profile)) {
        throw 'Sandbox PS7 profile missing before uninstall'
    }
    if (-not $script:sandboxPs5Profile -or -not (Test-Path $script:sandboxPs5Profile)) {
        throw 'Sandbox PS5 profile missing before uninstall'
    }

    $env:LOCALAPPDATA = Join-Path $script:sandboxRoot 'Local'
    Set-Variable -Name PROFILE -Scope Global -Value $script:sandboxPs7Profile
    $env:CI = 'true'
    . $script:sandboxPs7Profile

    Uninstall-Profile -RemoveUserData -Confirm:$false

    if (Test-Path $script:sandboxPs7Profile) { throw 'PS7 profile still exists after uninstall' }
    if (Test-Path $script:sandboxPs5Profile) { throw 'PS5 profile still exists after uninstall' }
    if (Test-Path (Join-Path $script:sandboxPs7Dir 'profile_user.ps1')) { throw 'PS7 profile_user.ps1 still exists after uninstall' }
    if (Test-Path (Join-Path $script:sandboxPs5Dir 'profile_user.ps1')) { throw 'PS5 profile_user.ps1 still exists after uninstall' }

    if (Test-Path $script:sandboxCacheDir) {
        $remaining = Get-ChildItem -Path $script:sandboxCacheDir -ErrorAction SilentlyContinue
        if ($remaining.Count -gt 0) {
            throw "Cache directory still contains files after uninstall: $($remaining.Name -join ', ')"
        }
    }
} -SkipWhen { -not $script:installReady } -SkipReason 'Sandbox install failed'
}
finally {
    Restore-SandboxEnvironment
}

Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
$total = $passed + $failed + $skipped
$color = if ($failed -gt 0) { 'Red' } elseif ($skipped -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  $passed passed, $failed failed, $skipped skipped ($total total)" -ForegroundColor $color
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

if ($failed -gt 0) { exit 1 }
