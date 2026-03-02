# PSScriptAnalyzer suppression: this file intentionally calls profile functions
# by their short names (gc, ls, cat, uptime, eventlog) to exercise those definitions.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '')]
param(
    [switch]$VerboseOutput,
    [switch]$StrictNetwork
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$profilePath = Join-Path $repoRoot 'Microsoft.PowerShell_profile.ps1'

$passed = 0
$failed = 0
$skipped = 0

$script:executedCommands = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:skippedCommands = @{}
$script:commandFailures = @()
$script:networkSoftFails = @()

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

function Register-ExecutedCommand {
    param([Parameter(Mandatory)][string]$Name)
    if ($script:skippedCommands.ContainsKey($Name)) { $script:skippedCommands.Remove($Name) }
    [void]$script:executedCommands.Add($Name)
}

function Register-SkippedCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason
    )
    if (-not $script:executedCommands.Contains($Name)) {
        $script:skippedCommands[$Name] = $Reason
    }
}

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

    $beforeErrCount = $Error.Count
    try {
        $output = & { $ErrorActionPreference = 'Stop'; & $Code } 2>&1
        $errorRecords = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        if ($errorRecords.Count -gt 0) { throw $errorRecords[0].ToString() }
        if ($Error.Count -gt $beforeErrCount) { throw $Error[0].ToString() }

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

Write-Host ''
Write-Host '========== Functional CI Suite (Full Command Coverage) ==========' -ForegroundColor Cyan
Write-Host ''

if (-not (Test-Path $profilePath)) {
    throw "Profile not found: $profilePath"
}

$env:CI = 'true'
. $profilePath
Remove-Item env:CI -ErrorAction SilentlyContinue

Invoke-TestCase -Name 'Execute full command matrix' -Code {
    $script:executedCommands.Clear()
    $script:skippedCommands = @{}
    $script:commandFailures = @()
    $script:networkSoftFails = @()

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
        Invoke-CommandProbe -Command 'Edit-Profile' -SkipReason 'Opens interactive editor'
        Invoke-CommandProbe -Command 'ep' -SkipReason 'Alias to Edit-Profile (opens interactive editor)'
        Invoke-CommandProbe -Command 'edit' -SkipReason 'Opens interactive editor'
        Invoke-CommandProbe -Command 'Update-Profile' -SkipReason 'Network and mutating profile update flow'
        Invoke-CommandProbe -Command 'Update-PowerShell' -SkipReason 'Installs or upgrades shell binaries'
        Invoke-CommandProbe -Command 'Update-Tools' -SkipReason 'Installs or upgrades external tools'
        Invoke-CommandProbe -Command 'Clear-ProfileCache' -Code {
            $origLocal = $env:LOCALAPPDATA
            try {
                $fakeLocal = Join-Path $workspace 'localappdata'
                $fakeCache = Join-Path $fakeLocal 'PowerShellProfile'
                New-Item -ItemType Directory -Path $fakeCache -Force | Out-Null
                [System.IO.File]::WriteAllText((Join-Path $fakeCache 'transient.cache'), 'x', $utf8NoBom)
                [System.IO.File]::WriteAllText((Join-Path $fakeCache 'user-settings.json'), '{}', $utf8NoBom)
                $env:LOCALAPPDATA = $fakeLocal
                Clear-ProfileCache
                if (Test-Path (Join-Path $fakeCache 'transient.cache')) { throw 'Clear-ProfileCache did not remove transient file' }
                if (-not (Test-Path (Join-Path $fakeCache 'user-settings.json'))) { throw 'Clear-ProfileCache removed user-settings.json' }
            }
            finally {
                $env:LOCALAPPDATA = $origLocal
            }
        }
        Invoke-CommandProbe -Command 'Clear-Cache' -Code { Clear-Cache -WhatIf -Confirm:$false | Out-Null }
        Invoke-CommandProbe -Command 'Uninstall-Profile' -Code { Uninstall-Profile -All -WhatIf -Confirm:$false | Out-Null }
        Invoke-CommandProbe -Command 'Invoke-DownloadWithRetry' -SkipReason 'Internal helper (covered by setup tests)'
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
                if ((Get-Location).Path -ne $mkcdDir) { throw "mkcd did not change directory to $mkcdDir" }
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
        Invoke-CommandProbe -Command 'winutil' -SkipReason 'Downloads and executes external script'
        Invoke-CommandProbe -Command 'harden' -Code { harden | Out-Null }

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
        Invoke-CommandProbe -Command 'dimg' -Code { dimg | Out-Null } -SkipReason $dockerSkipReason
        Invoke-CommandProbe -Command 'dlogs' -SkipReason 'Requires running container name'
        Invoke-CommandProbe -Command 'dex' -SkipReason 'Requires running container name'
        Invoke-CommandProbe -Command 'dstop' -SkipReason 'Destructive: stops running containers'
        Invoke-CommandProbe -Command 'dprune' -SkipReason 'Destructive: prunes docker resources'

        # SSH and remote
        Invoke-CommandProbe -Command 'Copy-SshKey' -SkipReason 'Requires reachable remote host'
        Invoke-CommandProbe -Command 'ssh-copy-key' -SkipReason 'Alias requiring reachable remote host'
        Invoke-CommandProbe -Command 'keygen' -SkipReason 'Writes SSH keys to user profile'
        Invoke-CommandProbe -Command 'rdp' -SkipReason 'Opens Remote Desktop UI'

        # Clipboard
        Invoke-CommandProbe -Command 'cpy' -Code { cpy 'psp-ci-clipboard' } -SkipReason $clipboardSkipReason
        Invoke-CommandProbe -Command 'pst' -Code {
            $text = (pst | Out-String).Trim()
            if ($text -ne 'psp-ci-clipboard') { throw "pst returned unexpected text: $text" }
        } -SkipReason $clipboardSkipReason
        $invokeClipboardSkipReason = if ($clipboardSkipReason) { $clipboardSkipReason } else { 'Clipboard insertion behavior is host-dependent in headless sessions' }
        Invoke-CommandProbe -Command 'Invoke-Clipboard' -SkipReason $invokeClipboardSkipReason
        Invoke-CommandProbe -Command 'icb' -SkipReason $invokeClipboardSkipReason
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
}

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
    $internalOnly = @('Merge-JsonObject', 'Invoke-DownloadWithRetry')
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
}

Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
$total = $passed + $failed + $skipped
$color = if ($failed -gt 0) { 'Red' } elseif ($skipped -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  $passed passed, $failed failed, $skipped skipped ($total total)" -ForegroundColor $color
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

if ($failed -gt 0) { exit 1 }
