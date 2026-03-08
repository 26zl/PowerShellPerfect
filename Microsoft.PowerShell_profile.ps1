### PowerShell Profile (26zl)
### https://github.com/26zl/PowerShellPerfect

$profileStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Normalize agent detection: if the host sets a known agent/AI env var, set AI_AGENT so the rest of the profile only checks one name
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) {
    $env:AI_AGENT = '1'
}

# Non-interactive mode detection (sandboxed/AI/CI/SSH-pipe sessions skip network calls and UI setup)
# Set AI_AGENT (or CI) when running in any AI/agent/automation context to skip interactive init
$isInteractive = [Environment]::UserInteractive -and
-not [bool]$env:CI -and
-not [bool]$env:AI_AGENT -and
-not ($host.Name -eq 'Default Host') -and
-not $(try { [Console]::IsOutputRedirected } catch { $false }) -and
-not ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '(?i)^-NonI' })

$repo_root = "https://raw.githubusercontent.com/26zl"
$repo_name = "PowerShellPerfect"

# Cache directory outside Documents (avoids Controlled Folder Access / ransomware protection blocks)
$cacheDir = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }

# JSONC comment-stripping regex (built via variable to avoid PS5 parser bug with [^"] in strings)
$_q = [char]34
$jsoncCommentPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*`$"

# Opt-out of telemetry if running as admin (only set once)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin -and -not [System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

# Canonical tool list - single source of truth for install, upgrade, cache invalidation, and version tracking.
# Cache: init-script filename in $cacheDir that must be deleted when the tool is upgraded (or $null).
# VerCmd: argument(s) to get the tool version for pre/post-upgrade display.
$script:ProfileTools = @(
    @{ Name = "Oh My Posh"; Id = "JanDeDobbeleer.OhMyPosh"; Cmd = "oh-my-posh"; Cache = $null; VerCmd = "version"; UpgradeStrategy = "preserve-direct" }
    @{ Name = "eza"; Id = "eza-community.eza"; Cmd = "eza"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "zoxide"; Id = "ajeetdsouza.zoxide"; Cmd = "zoxide"; Cache = "zoxide-init.ps1"; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "fzf"; Id = "junegunn.fzf"; Cmd = "fzf"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "bat"; Id = "sharkdp.bat"; Cmd = "bat"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "ripgrep"; Id = "BurntSushi.ripgrep.MSVC"; Cmd = "rg"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
)

# Run a scriptblock in a job with timeout; returns result or $null on timeout/failure.
# Used for native init commands where we want an explicit timeout but can pass a resolved exe path.
function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSec = 15,
        [object[]]$ArgumentList = @()
    )
    $job = $null
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        $null = Wait-Job $job -Timeout $TimeoutSec
        if ($job.State -ne 'Completed') {
            if ($job.State -eq 'Running') { Stop-Job $job -ErrorAction SilentlyContinue }
            return $null
        }
        Receive-Job $job
    }
    catch { return $null }
    finally {
        if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue }
    }
}

# Download helper with retry, size validation, and corrupt-file cleanup
function Invoke-DownloadWithRetry {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$OutFile,
        [int]$TimeoutSec = 10,
        [int]$MaxAttempts = 2,
        [int]$BackoffSec = 2
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            Invoke-RestMethod -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec -ErrorAction Stop
            if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
                throw 'Downloaded file is missing or empty'
            }
            return
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                Write-Warning "Download failed (attempt $attempt/$MaxAttempts): $_  Retrying in ${BackoffSec}s..."
                Start-Sleep -Seconds $BackoffSec
            }
            else {
                throw $_
            }
        }
    }
}

# Get the full path to an external command
function Get-ExternalCommandPath {
    param(
        [Parameter(Mandatory)]
        [string]$CommandName
    )

    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    if ($cmd.Path) { return $cmd.Path }
    if ($cmd.Source) { return $cmd.Source }
    if ($cmd.Definition) { return $cmd.Definition }
    return $null
}

# Merge PSCustomObject overrides recursively so nested user/theme/terminal keys are preserved.
function Merge-JsonObject {
    param(
        $base,
        $override
    )

    if (-not $base -or -not $override) { return }
    foreach ($prop in $override.PSObject.Properties) {
        $baseVal = $base.PSObject.Properties[$prop.Name]
        if ($baseVal -and $baseVal.Value -is [PSCustomObject] -and $prop.Value -is [PSCustomObject]) {
            Merge-JsonObject $baseVal.Value $prop.Value
        }
        else {
            $base | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
    }
}

# Specific helper to get the path to oh-my-posh executable for cache clearing (since it has a built-in cache clear command instead of a file-based cache)
function Get-OhMyPoshExecutablePath {
    $resolvedPath = Get-ExternalCommandPath -CommandName 'oh-my-posh'
    if ($resolvedPath) {
        return $resolvedPath
    }

    $candidatePaths = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\oh-my-posh\bin\oh-my-posh.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\oh-my-posh\oh-my-posh.exe'),
        (Join-Path $env:ProgramFiles 'oh-my-posh\bin\oh-my-posh.exe')
    )

    $pf86 = [System.Environment]::GetEnvironmentVariable('ProgramFiles(x86)', 'Process')
    if ($pf86) {
        $candidatePaths += (Join-Path $pf86 'oh-my-posh\bin\oh-my-posh.exe')
    }

    foreach ($candidatePath in ($candidatePaths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidatePath)) { continue }

        $candidateDir = Split-Path -Path $candidatePath -Parent
        $pathEntries = @($env:PATH -split ';' | Where-Object { $_ })
        if ($pathEntries -notcontains $candidateDir) {
            $env:PATH = $candidateDir + ';' + $env:PATH
        }

        return $candidatePath
    }

    return $null
}

# Return OMP install path and kind (windowsapps vs direct) for upgrade logic
function Get-OhMyPoshInstallInfo {
    $path = Get-OhMyPoshExecutablePath
    if (-not $path) {
        return [PSCustomObject]@{
            Path        = $null
            InstallKind = 'missing'
        }
    }

    $windowsAppsRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    $installKind = if ($path -like "$windowsAppsRoot*") { 'windowsapps' } else { 'direct' }
    return [PSCustomObject]@{
        Path        = $path
        InstallKind = $installKind
    }
}

# Resolve executable path for a profile tool (OMP uses Get-OhMyPoshInstallInfo, others use Get-Command)
function Get-ProfileToolExecutablePath {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Tool
    )

    if ($Tool.Cmd -eq 'oh-my-posh') {
        return (Get-OhMyPoshInstallInfo).Path
    }

    return Get-ExternalCommandPath -CommandName $Tool.Cmd
}

# Get version string for a profile tool by running its VerCmd
function Get-ProfileToolVersionText {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Tool,
        [Parameter(Mandatory)]
        [string]$ExecutablePath
    )

    $versionArgs = @()
    if ($Tool.VerCmd -is [System.Array]) {
        $versionArgs = @($Tool.VerCmd)
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Tool.VerCmd)) {
        $versionArgs = @([string]$Tool.VerCmd)
    }

    try {
        $versionLine = & $ExecutablePath @versionArgs 2>$null |
            Where-Object { $_ -match '\d+\.\d+' } |
            Select-Object -First 1
        if ($versionLine) {
            return $versionLine.Trim()
        }
    }
    catch {
        return $null
    }

    return $null
}

# Invoke oh-my-posh with explicit UTF-8 stdio and explicit arguments so prompt rendering
# never depends on opaque internal init/cache state.
function Invoke-OhMyPoshCommand {
    param(
        [Parameter(Mandatory)]
        [string]$ExecutablePath,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $process = New-Object System.Diagnostics.Process
    $startInfo = $process.StartInfo
    $startInfo.FileName = $ExecutablePath
    if ($startInfo.PSObject.Properties.Match('ArgumentList').Count -gt 0) {
        $Arguments | ForEach-Object { $null = $startInfo.ArgumentList.Add($_) }
    }
    else {
        $escapedArgs = $Arguments | ForEach-Object {
            $s = $_ -replace '(\\+)"', '$1$1"'
            $s = $s -replace '(\\+)$', '$1$1'
            $s = $s -replace '"', '\"'
            "`"$s`""
        }
        $startInfo.Arguments = $escapedArgs -join ' '
    }

    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    if ($PWD.Provider.Name -eq 'FileSystem') {
        try {
            if (Test-Path -LiteralPath $PWD.ProviderPath) {
                $startInfo.WorkingDirectory = $PWD.ProviderPath
            }
        }
        catch {
            Write-Verbose "Failed to set oh-my-posh working directory: $_"
        }
    }

    [void]$process.Start()

    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $stderr = $stderrTask.Result.Trim()
        if ($stderr) {
            $Host.UI.WriteErrorLine($stderr)
        }

        return $stdoutTask.Result
    }
    finally {
        $process.Dispose()
    }
}

# Gather context for oh-my-posh prompt rendering, including error code, execution time, stack count, terminal width, and non-filesystem working directory.
# This is used to provide consistent context to oh-my-posh for prompt rendering without relying on opaque internal state or caches.
function Get-OhMyPoshPromptContext {
    param(
        [bool]$OriginalSuccess,
        [AllowNull()]
        [object]$OriginalLastExitCode
    )

    $context = [ordered]@{
        NoExitCode    = $true
        ErrorCode     = 0
        ExecutionTime = 0
        StackCount    = 0
        NonFSWD       = $null
        TerminalWidth = 0
    }

    try {
        $locations = Get-Location -Stack
        if ($locations) {
            $context.StackCount = $locations.Count
        }
    }
    catch {
        $context.StackCount = 0
    }

    try {
        if ($PWD.Provider.Name -ne 'FileSystem') {
            $context.NonFSWD = $PWD.ToString()
        }
    }
    catch {
        $context.NonFSWD = $null
    }

    try {
        $terminalWidth = $Host.UI.RawUI.WindowSize.Width
        if ($terminalWidth) {
            $context.TerminalWidth = $terminalWidth
        }
    }
    catch {
        $context.TerminalWidth = 0
    }

    $lastHistory = Get-History -ErrorAction Ignore -Count 1
    if (($null -eq $lastHistory) -or ($script:OhMyPoshLastHistoryId -eq $lastHistory.Id)) {
        return [PSCustomObject]$context
    }

    $script:OhMyPoshLastHistoryId = $lastHistory.Id
    $context.NoExitCode = $false
    try {
        $context.ExecutionTime = [math]::Max(0, [int](($lastHistory.EndExecutionTime - $lastHistory.StartExecutionTime).TotalMilliseconds))
    }
    catch {
        $context.ExecutionTime = 0
    }

    if ($OriginalSuccess) {
        return [PSCustomObject]$context
    }

    $invocationInfo = $null
    try {
        $invocationInfo = $global:Error |
        Where-Object { $_.GetType().Name -eq 'ErrorRecord' } |
        Select-Object -First 1 -ExpandProperty InvocationInfo
    }
    catch {
        $invocationInfo = $null
    }

    if ($null -ne $invocationInfo -and $invocationInfo.HistoryId -eq $lastHistory.Id) {
        $context.ErrorCode = 1
        return [PSCustomObject]$context
    }

    if ($OriginalLastExitCode -is [int] -and $OriginalLastExitCode -ne 0) {
        $context.ErrorCode = $OriginalLastExitCode
        return [PSCustomObject]$context
    }

    $context.ErrorCode = 1
    return [PSCustomObject]$context
}

# Get the prompt text from oh-my-posh by invoking the executable with explicit arguments and context.
# This avoids relying on opaque internal state or caches for prompt rendering, and allows consistent prompts even in non-interactive contexts (like SSH or CI) where init scripts may not run.
function Get-OhMyPoshPromptText {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('primary', 'secondary')]
        [string]$Type,
        [Parameter(Mandatory)]
        [string]$ExecutablePath,
        [Parameter(Mandatory)]
        [string]$ConfigPath,
        [bool]$OriginalSuccess = $true,
        [AllowNull()]
        [object]$OriginalLastExitCode = 0
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "oh-my-posh config not found: $ConfigPath"
    }

    $arguments = @(
        'print'
        $Type
        '--config'
        $ConfigPath
        '--shell=pwsh'
        "--shell-version=$($PSVersionTable.PSVersion.ToString())"
    )

    if ($Type -eq 'primary') {
        $context = Get-OhMyPoshPromptContext -OriginalSuccess:$OriginalSuccess -OriginalLastExitCode $OriginalLastExitCode
        $arguments += @(
            "--status=$($context.ErrorCode)"
            "--no-status=$($context.NoExitCode)"
            "--execution-time=$($context.ExecutionTime)"
            "--stack-count=$($context.StackCount)"
            "--terminal-width=$($context.TerminalWidth)"
            '--job-count=0'
        )

        if ($context.NonFSWD) {
            $arguments += "--pswd=$($context.NonFSWD)"
        }
    }

    return Invoke-OhMyPoshCommand -ExecutablePath $ExecutablePath -Arguments $arguments
}

# Clear oh-my-posh cache by either deleting legacy cache files or invoking the built-in cache clear command (if available).
# Legacy cache files are detected by a special comment in the first line and are removed if found. The built-in command is used if the executable is available, and any errors during cache clearing are logged as warnings.
function Clear-OhMyPoshCaches {
    param(
        [switch]$Quiet
    )

    $docRoot = [Environment]::GetFolderPath('MyDocuments')
    $legacyCachePaths = @(
        (Join-Path $env:LOCALAPPDATA 'PowerShellProfile\omp-init.ps1')
        (Join-Path $docRoot 'PowerShell\omp-init.ps1')
        (Join-Path $docRoot 'WindowsPowerShell\omp-init.ps1')
    ) | Select-Object -Unique

    foreach ($legacyPath in $legacyCachePaths) {
        if (-not (Test-Path $legacyPath)) { continue }
        try {
            $firstLine = Get-Content $legacyPath -TotalCount 1 -ErrorAction Stop
            if ($firstLine -match '^# OMP_CACHE') {
                Remove-Item $legacyPath -Force -ErrorAction SilentlyContinue
                if (-not $Quiet) {
                    Write-Host "  Removed legacy OMP init cache: $legacyPath" -ForegroundColor DarkGray
                }
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Verbose "Failed to inspect/remove legacy OMP init cache '$legacyPath': $_"
            }
        }
    }

    $ompExecutablePath = Get-OhMyPoshExecutablePath
    if ($ompExecutablePath) {
        try {
            & $ompExecutablePath cache clear | Out-Null
            if ($LASTEXITCODE -ne 0 -and -not $Quiet) {
                Write-Warning "oh-my-posh cache clear exited with code $LASTEXITCODE."
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Warning "Failed to clear oh-my-posh cache: $_"
            }
        }
    }
}

# Check for Profile Updates (manual only)
function Update-Profile {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [switch]$SkipHashCheck,
        [switch]$Force
    )

    $tempProfile = Join-Path $env:TEMP "Microsoft.PowerShell_profile.ps1"
    $tempConfig = Join-Path $env:TEMP "theme.json"
    $tempTerminalConfig = Join-Path $env:TEMP "terminal-config.json"
    $userSettingsPath = Join-Path $cacheDir "user-settings.json"
    $userSettingsStatePath = Join-Path $cacheDir "user-settings.applied.sha256"

    $phaseErrors = @()
    $profileActuallyUpdated = $false
    $userSettingsHash = $null
    $userSettingsChanged = $false
    $userSettingsParsed = $false
    $userThemeOverridePresent = $false
    $userWindowsTerminalOverridePresent = $false
    $userTerminalDefaultsOverridePresent = $false
    $userKeybindingsOverridePresent = $false
    try {
        # Phase 1: Download profile and config
        $profileUrl = "$repo_root/$repo_name/main/Microsoft.PowerShell_profile.ps1"
        Invoke-DownloadWithRetry -Uri $profileUrl -OutFile $tempProfile

        $configUrl = "$repo_root/$repo_name/main/theme.json"
        $configDownloaded = $false
        try {
            Invoke-DownloadWithRetry -Uri $configUrl -OutFile $tempConfig
            $configDownloaded = $true
        }
        catch {
            Write-Warning "Could not download theme.json (non-fatal): $_"
            $phaseErrors += "theme.json download: $_"
        }

        $terminalConfigUrl = "$repo_root/$repo_name/main/terminal-config.json"
        $terminalConfigDownloaded = $false
        try {
            Invoke-DownloadWithRetry -Uri $terminalConfigUrl -OutFile $tempTerminalConfig
            $terminalConfigDownloaded = $true
        }
        catch {
            Write-Warning "Could not download terminal-config.json (non-fatal): $_"
            $phaseErrors += "terminal-config.json download: $_"
        }

        # Phase 2: Hash verification (profile .ps1 only)
        $oldHash = if (Test-Path $PROFILE) { (Get-FileHash -Path $PROFILE -Algorithm SHA256).Hash } else { "" }
        $newHash = (Get-FileHash -Path $tempProfile -Algorithm SHA256).Hash
        $profileChanged = $newHash -ne $oldHash

        # Check if config actually changed
        $configChanged = $false
        $cachedConfig = Join-Path $cacheDir "theme.json"
        if ($configDownloaded) {
            $newConfigHash = (Get-FileHash -Path $tempConfig -Algorithm SHA256).Hash
            $oldConfigHash = if (Test-Path $cachedConfig) { (Get-FileHash -Path $cachedConfig -Algorithm SHA256).Hash } else { "" }
            $configChanged = $newConfigHash -ne $oldConfigHash
        }

        # Check if terminal config actually changed
        $terminalConfigChanged = $false
        $cachedTerminalConfig = Join-Path $cacheDir "terminal-config.json"
        if ($terminalConfigDownloaded) {
            $newTerminalConfigHash = (Get-FileHash -Path $tempTerminalConfig -Algorithm SHA256).Hash
            $oldTerminalConfigHash = if (Test-Path $cachedTerminalConfig) { (Get-FileHash -Path $cachedTerminalConfig -Algorithm SHA256).Hash } else { "" }
            $terminalConfigChanged = $newTerminalConfigHash -ne $oldTerminalConfigHash
        }

        if (Test-Path $userSettingsPath) {
            try {
                $userSettingsHash = (Get-FileHash -Path $userSettingsPath -Algorithm SHA256).Hash
                $appliedUserSettingsHash = if (Test-Path $userSettingsStatePath) {
                    (Get-Content $userSettingsStatePath -Raw -ErrorAction Stop).Trim()
                }
                else {
                    ""
                }
                $userSettingsChanged = $userSettingsHash -ne $appliedUserSettingsHash
            }
            catch {
                Write-Warning "Could not fingerprint user-settings.json: $_"
                $phaseErrors += "user-settings fingerprint: $_"
                $userSettingsChanged = $true
            }
        }

        if (-not $profileChanged -and -not $configChanged -and -not $terminalConfigChanged -and -not $userSettingsChanged -and -not $Force) {
            Write-Host "Profile is up to date." -ForegroundColor Green
            return
        }

        # Combined hash verification - covers profile + config files (skipped when nothing changed upstream)
        if (-not $SkipHashCheck -and ($profileChanged -or $configChanged -or $terminalConfigChanged)) {
            $profileLabel = $newHash
            $configLabel = if ($configDownloaded) { $newConfigHash } else { "NONE" }
            $terminalLabel = if ($terminalConfigDownloaded) { $newTerminalConfigHash } else { "NONE" }
            $combinedInput = "profile:${profileLabel}:theme:${configLabel}:terminal:${terminalLabel}"
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $combinedHash = [BitConverter]::ToString(
                    $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedInput))
                ).Replace('-', '')
            }
            finally { $sha.Dispose() }

            if (-not $ExpectedSha256) {
                Write-Host "Downloaded file hashes:" -ForegroundColor Yellow
                Write-Host "  profile.ps1:       $newHash" -ForegroundColor Yellow
                if ($configDownloaded) {
                    Write-Host "  theme.json:        $newConfigHash" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  theme.json:        (not downloaded)" -ForegroundColor Yellow
                }
                if ($terminalConfigDownloaded) {
                    Write-Host "  terminal-config:   $newTerminalConfigHash" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  terminal-config:   (not downloaded)" -ForegroundColor Yellow
                }
                Write-Host "  combined:          $combinedHash" -ForegroundColor Yellow
                Write-Host "Verify at https://github.com/26zl/PowerShellPerfect" -ForegroundColor Yellow
                throw "Hash verification required. Re-run with -ExpectedSha256 '$combinedHash' or -SkipHashCheck."
            }
            $expected = $ExpectedSha256.ToUpperInvariant()
            if ($combinedHash -ne $expected) {
                throw "Combined hash mismatch. Expected $expected, got $combinedHash."
            }
        }

        # Phase 3: Copy profile to PS5/PS7 dirs (only if changed)
        if ($profileChanged) {
            if ($PSCmdlet.ShouldProcess($PROFILE, "Replace profile with downloaded version (hash: $newHash)")) {
                $docsRoot = Split-Path (Split-Path $PROFILE)
                $profileDirs = @(
                    Join-Path $docsRoot "PowerShell"
                    Join-Path $docsRoot "WindowsPowerShell"
                )
                $copySuccess = 0
                $copyFailed = @()
                foreach ($dir in $profileDirs) {
                    $target = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
                    if (Test-Path $dir) {
                        try {
                            Copy-Item -Path $tempProfile -Destination $target -Force -ErrorAction Stop
                            $copySuccess++
                        }
                        catch {
                            $copyFailed += $target
                            Write-Warning "Failed to copy profile to ${target}: $_"
                        }
                    }
                }
                if ($copySuccess -gt 0 -and $copyFailed.Count -eq 0) {
                    Write-Host "Profile updated ($copySuccess locations)." -ForegroundColor Green
                    $profileActuallyUpdated = $true
                }
                elseif ($copySuccess -gt 0) {
                    Write-Warning "Profile updated partially. Failed to write: $($copyFailed -join ', ')"
                    $profileActuallyUpdated = $true
                }
                else {
                    Write-Warning "Profile not updated -- no writable profile directories found."
                }
            }
        }
        else {
            Write-Host "Profile .ps1 unchanged, applying config updates..." -ForegroundColor Cyan
        }

        # Load config for remaining phases (cache is saved AFTER all phases so a failed WT write can be retried)
        $config = $null
        if ($configDownloaded) {
            try { $config = Get-Content $tempConfig -Raw | ConvertFrom-Json }
            catch { Write-Verbose "Failed to parse downloaded config: $_" }
        }
        elseif (Test-Path $cachedConfig) {
            try { $config = Get-Content $cachedConfig -Raw | ConvertFrom-Json }
            catch {
                Write-Warning "Corrupt cached config removed: $cachedConfig"
                Remove-Item $cachedConfig -Force -ErrorAction SilentlyContinue
            }
        }

        # Load terminal config for Phase 7
        $terminalConfig = $null
        if ($terminalConfigDownloaded) {
            try { $terminalConfig = Get-Content $tempTerminalConfig -Raw | ConvertFrom-Json }
            catch { Write-Verbose "Failed to parse downloaded terminal config: $_" }
        }
        elseif (Test-Path $cachedTerminalConfig) {
            try { $terminalConfig = Get-Content $cachedTerminalConfig -Raw | ConvertFrom-Json }
            catch {
                Write-Warning "Corrupt cached terminal config removed: $cachedTerminalConfig"
                Remove-Item $cachedTerminalConfig -Force -ErrorAction SilentlyContinue
            }
        }

        # Apply user-settings.json overrides (never downloaded, never overwritten)
        if (Test-Path $userSettingsPath) {
            try {
                $userSettings = Get-Content $userSettingsPath -Raw | ConvertFrom-Json
                $userSettingsParsed = $true
                $userThemeOverridePresent = $null -ne $userSettings.theme
                $userWindowsTerminalOverridePresent = $null -ne $userSettings.windowsTerminal
                $userTerminalDefaultsOverridePresent = $null -ne $userSettings.defaults
                $userKeybindingsOverridePresent = $null -ne $userSettings.keybindings
                if ($config -and $userSettings.theme) {
                    if (-not $config.theme) {
                        $config | Add-Member -NotePropertyName "theme" -NotePropertyValue ([PSCustomObject]@{}) -Force
                    }
                    Merge-JsonObject $config.theme $userSettings.theme
                }
                if ($config -and $userSettings.windowsTerminal) {
                    if (-not $config.windowsTerminal) {
                        $config | Add-Member -NotePropertyName "windowsTerminal" -NotePropertyValue ([PSCustomObject]@{}) -Force
                    }
                    Merge-JsonObject $config.windowsTerminal $userSettings.windowsTerminal
                }
                if ($terminalConfig -and $userSettings.defaults) {
                    if (-not $terminalConfig.defaults) {
                        $terminalConfig | Add-Member -NotePropertyName "defaults" -NotePropertyValue ([PSCustomObject]@{}) -Force
                    }
                    Merge-JsonObject $terminalConfig.defaults $userSettings.defaults
                }
                if ($terminalConfig -and $userSettings.keybindings) {
                    if (-not $terminalConfig.keybindings) {
                        $terminalConfig | Add-Member -NotePropertyName "keybindings" -NotePropertyValue @() -Force
                    }
                    $terminalConfig.keybindings = @($terminalConfig.keybindings) + @($userSettings.keybindings)
                }
                Write-Host "User overrides applied from user-settings.json" -ForegroundColor DarkGray
            }
            catch {
                Write-Warning "Failed to parse user-settings.json: $_"
            }
        }
        else {
            # Create starter template so users know the file exists
            $userSettingsTemplate = @'
{
    "_comment": "User overrides for terminal and theme settings. Only add keys you want to override.",
    "_examples": {
        "theme": { "name": "catppuccin", "url": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/catppuccin.omp.json" },
        "windowsTerminal": { "colorScheme": "One Half Dark", "cursorColor": "#ffffff" },
        "defaults": { "opacity": 90, "font": { "size": 14 } },
        "keybindings": [{ "keys": "ctrl+shift+t", "command": { "action": "newTab" } }]
    }
}
'@
            if ($PSCmdlet.ShouldProcess($userSettingsPath, "Create user-settings.json template")) {
                $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($userSettingsPath, $userSettingsTemplate, $utf8NoBom)
                Write-Host "Created user-settings.json template in $cacheDir" -ForegroundColor Green
            }
        }

        # Phase 4: OMP theme sync + orphan cleanup
        if ($config -and $config.theme -and $config.theme.name) {
            $themeName = $config.theme.name
            $themeUrl = $config.theme.url
            $localThemePath = Join-Path $cacheDir "$themeName.omp.json"
            $currentThemeReady = $false
            if (Test-Path $localThemePath) {
                try {
                    $existingThemeContent = Get-Content $localThemePath -Raw -ErrorAction Stop
                    if ([string]::IsNullOrWhiteSpace($existingThemeContent)) { throw 'Theme file is empty' }
                    $null = $existingThemeContent | ConvertFrom-Json
                    $currentThemeReady = $true
                }
                catch {
                    Write-Warning "Existing OMP theme '$themeName' is invalid at '$localThemePath': $_"
                }
            }

            $themeOverrideChanged = $userSettingsChanged -and $userThemeOverridePresent
            $shouldDownloadTheme = $Force -or (-not $currentThemeReady) -or $configChanged -or $themeOverrideChanged
            if ($shouldDownloadTheme -and $themeUrl) {
                if ($PSCmdlet.ShouldProcess($localThemePath, "Download OMP theme '$themeName'")) {
                    $tempThemePath = Join-Path $cacheDir ("{0}.{1}.download" -f $themeName, [System.IO.Path]::GetRandomFileName())
                    try {
                        Invoke-DownloadWithRetry -Uri $themeUrl -OutFile $tempThemePath
                        $downloadedThemeContent = Get-Content $tempThemePath -Raw -ErrorAction Stop
                        if ([string]::IsNullOrWhiteSpace($downloadedThemeContent)) { throw 'Downloaded theme file is empty' }
                        $null = $downloadedThemeContent | ConvertFrom-Json
                        Move-Item -Path $tempThemePath -Destination $localThemePath -Force
                        Write-Host "OMP theme '$themeName' updated." -ForegroundColor Green
                        $currentThemeReady = $true
                    }
                    catch {
                        Write-Warning "Failed to download/validate OMP theme: $_"
                        $phaseErrors += "OMP theme download: $_"
                    }
                    finally {
                        Remove-Item $tempThemePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            elseif ($shouldDownloadTheme -and -not $themeUrl -and -not $currentThemeReady) {
                Write-Warning "OMP theme '$themeName' is missing locally and no download URL is configured."
                $phaseErrors += "OMP theme missing URL: $themeName"
            }

            # Orphan cleanup - remove *.omp.json files that don't match current theme
            if (-not $currentThemeReady -and (Test-Path $localThemePath)) {
                try {
                    $currentThemeContent = Get-Content $localThemePath -Raw -ErrorAction Stop
                    if ([string]::IsNullOrWhiteSpace($currentThemeContent)) { throw 'Theme file is empty' }
                    $null = $currentThemeContent | ConvertFrom-Json
                    $currentThemeReady = $true
                }
                catch {
                    Write-Warning "Skipping orphan cleanup because current OMP theme '$themeName' is still invalid: $_"
                }
            }

            if ($currentThemeReady) {
                $ompFiles = Get-ChildItem -Path $cacheDir -Filter "*.omp.json" -ErrorAction SilentlyContinue
                foreach ($file in $ompFiles) {
                    if ($file.Name -ne "$themeName.omp.json") {
                        if ($PSCmdlet.ShouldProcess($file.FullName, "Remove orphaned OMP theme")) {
                            Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                            Write-Host "Removed orphaned theme: $($file.Name)" -ForegroundColor DarkGray
                        }
                    }
                }
            }
        }

        # Phase 5: Cache invalidation - clear all tool init caches declared in $script:ProfileTools
        if ($profileChanged -or $configChanged) {
            foreach ($tool in $script:ProfileTools) {
                if ($tool.Cache) {
                    $cachePath = Join-Path $cacheDir $tool.Cache
                    if (Test-Path $cachePath) {
                        if ($PSCmdlet.ShouldProcess($cachePath, "Invalidate $($tool.Name) init cache")) {
                            Remove-Item $cachePath -Force -ErrorAction SilentlyContinue
                            Write-Host "$($tool.Name) init cache cleared." -ForegroundColor DarkGray
                        }
                    }
                }
            }
        }

        # Phase 6: Windows Terminal sync
        $terminalOverridesChanged = $userSettingsChanged -and ($userWindowsTerminalOverridePresent -or $userTerminalDefaultsOverridePresent -or $userKeybindingsOverridePresent)
        if (($Force -or $profileChanged -or $configChanged -or $terminalConfigChanged -or $terminalOverridesChanged) -and (($config -and $config.windowsTerminal) -or $terminalConfig)) {
            $wtSettingsPath = Join-Path $env:LOCALAPPDATA "Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
            if (Test-Path $wtSettingsPath) {
                if ($PSCmdlet.ShouldProcess($wtSettingsPath, "Update Windows Terminal settings")) {
                    try {
                        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                        $backupPath = "$wtSettingsPath.$timestamp.bak"
                        Copy-Item $wtSettingsPath $backupPath -Force
                        Write-Host "WT backup: $backupPath" -ForegroundColor DarkGray

                        # Cleanup old WT backups (keep last 5)
                        $wtLocalState = Split-Path $wtSettingsPath
                        $oldBackups = Get-ChildItem -Path $wtLocalState -Filter "settings.json.*.bak" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -Skip 5
                        foreach ($old in $oldBackups) {
                            Remove-Item $old.FullName -Force -ErrorAction SilentlyContinue
                        }

                        # Read WT settings with retry (race condition mitigation if WT is writing)
                        $wt = $null
                        for ($wtAttempt = 1; $wtAttempt -le 2; $wtAttempt++) {
                            try {
                                $wtRaw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncCommentPattern, ''
                                $wt = $wtRaw | ConvertFrom-Json
                                break
                            }
                            catch {
                                if ($wtAttempt -lt 2) {
                                    Write-Warning "WT settings parse failed, retrying in 1s..."
                                    Start-Sleep -Seconds 1
                                }
                                else { throw }
                            }
                        }
                        if (-not $wt) { $wt = [PSCustomObject]@{} }

                        if (-not $wt.profiles) {
                            $wt | Add-Member -NotePropertyName "profiles" -NotePropertyValue ([PSCustomObject]@{}) -Force
                        }
                        if (-not $wt.profiles.defaults) {
                            $wt.profiles | Add-Member -NotePropertyName "defaults" -NotePropertyValue ([PSCustomObject]@{}) -Force
                        }
                        $defaults = $wt.profiles.defaults

                        # Terminal-config defaults first (font, opacity, scrollbar, etc.)
                        if ($terminalConfig -and $terminalConfig.defaults) {
                            $terminalConfig.defaults.PSObject.Properties | ForEach-Object {
                                $defaults | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
                            }
                        }

                        # Theme colors second (always win over terminal defaults)
                        if ($config -and $config.windowsTerminal) {
                            $schemeName = $config.windowsTerminal.colorScheme
                            if ($schemeName) {
                                $defaults | Add-Member -NotePropertyName "colorScheme" -NotePropertyValue $schemeName -Force
                            }
                            $cursorColor = $config.windowsTerminal.cursorColor
                            if ($cursorColor) {
                                $defaults | Add-Member -NotePropertyName "cursorColor" -NotePropertyValue $cursorColor -Force
                            }

                            # Upsert scheme definition
                            $schemeDef = $config.windowsTerminal.scheme
                            if ($schemeDef) {
                                if (-not $wt.schemes) {
                                    $wt | Add-Member -NotePropertyName "schemes" -NotePropertyValue @() -Force
                                }
                                $schemeDefName = if ($schemeDef.name) { $schemeDef.name } else { $schemeName }
                                $wt.schemes = @(@($wt.schemes | Where-Object { $_ -and $_.name -ne $schemeDefName }) + ([PSCustomObject]$schemeDef))
                            }
                        }

                        # Keybindings last
                        if ($terminalConfig -and $terminalConfig.keybindings) {
                            if (-not $wt.actions) {
                                $wt | Add-Member -NotePropertyName "actions" -NotePropertyValue @() -Force
                            }
                            foreach ($kb in $terminalConfig.keybindings) {
                                if (-not $kb -or [string]::IsNullOrWhiteSpace($kb.keys)) { continue }
                                $bindingId = "User.profile.$($kb.keys -replace '[^a-zA-Z0-9]', '')"
                                if ($wt.PSObject.Properties['keybindings']) {
                                    # New WT format: separate keybindings array references actions by id
                                    $existingIds = @($wt.keybindings | Where-Object { $_.keys -eq $kb.keys } | ForEach-Object { $_.id })
                                    if ($existingIds.Count -gt 0) {
                                        $wt.actions = @($wt.actions | Where-Object { $_ -and ($existingIds -notcontains $_.id) })
                                        $wt.keybindings = @($wt.keybindings | Where-Object { $_ -and $_.keys -ne $kb.keys })
                                    }
                                    $wt.actions = @($wt.actions) + ([PSCustomObject]@{ command = $kb.command; id = $bindingId })
                                    $wt.keybindings = @($wt.keybindings) + ([PSCustomObject]@{ id = $bindingId; keys = $kb.keys })
                                }
                                else {
                                    # Old WT format: keys directly in actions
                                    $wt.actions = @($wt.actions | Where-Object { $_ -and $_.keys -ne $kb.keys })
                                    $wt.actions = @($wt.actions) + ([PSCustomObject]@{ keys = $kb.keys; command = $kb.command })
                                }
                            }
                        }

                        # Ensure PowerShell profiles launch with -NoLogo
                        if ($wt.profiles.list) {
                            foreach ($prof in @($wt.profiles.list)) {
                                if (-not $prof) { continue }
                                $cmd = if ($prof.commandline) { $prof.commandline } else { '' }
                                $src = if ($prof.source) { $prof.source } else { '' }
                                $isPwsh = $cmd -match 'pwsh' -or $src -match 'Windows\.Terminal\.PowerShellCore'
                                $isPS5 = $cmd -match 'powershell\.exe' -or $prof.name -match 'Windows PowerShell'
                                if ($isPwsh -or $isPS5) {
                                    if ($cmd -and $cmd -notmatch '-NoLogo' -and $cmd -notmatch '(?i)-(Command|File|EncodedCommand)') {
                                        $prof | Add-Member -NotePropertyName "commandline" -NotePropertyValue "$cmd -NoLogo" -Force
                                    }
                                    elseif (-not $cmd -and $src) {
                                        # Source-only profiles: resolve executable and set commandline with -NoLogo
                                        $exe = if ($isPwsh) { 'pwsh.exe' } else { 'powershell.exe' }
                                        $prof | Add-Member -NotePropertyName "commandline" -NotePropertyValue "$exe -NoLogo" -Force
                                    }
                                }
                            }
                        }

                        $wtJson = $wt | ConvertTo-Json -Depth 10
                        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                        [System.IO.File]::WriteAllText($wtSettingsPath, $wtJson, $utf8NoBom)
                        Write-Host "Windows Terminal settings updated." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to update Windows Terminal settings: $_"
                        $phaseErrors += "Windows Terminal sync: $_"
                    }
                }
            }
        }

        # Phase 7: Install missing tools
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $missing = $script:ProfileTools | Where-Object { -not (Get-ProfileToolExecutablePath -Tool $_) }
            if ($missing) {
                Write-Host "Installing missing tools..." -ForegroundColor Cyan
                $installedTools = @()
                foreach ($tool in $missing) {
                    if ($PSCmdlet.ShouldProcess($tool.Name, "Install via winget")) {
                        Write-Host "  Installing $($tool.Name)..." -ForegroundColor Yellow
                        winget install -e --id $tool.Id --accept-source-agreements --accept-package-agreements
                        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335185 -or $LASTEXITCODE -eq -1978335189) {
                            Write-Host "  $($tool.Name) installed." -ForegroundColor Green
                            $installedTools += $tool
                        }
                        else {
                            Write-Warning "  $($tool.Name) install may have failed (exit code: $LASTEXITCODE)"
                        }
                    }
                }
                # Refresh PATH so newly installed tools are found
                if ($installedTools.Count -gt 0) {
                    $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', 'User')
                }
                # PSFzf module (required for fzf integration)
                if ((Get-Command fzf -ErrorAction SilentlyContinue) -and -not (Get-Module -ListAvailable -Name PSFzf)) {
                    if ($PSCmdlet.ShouldProcess('PSFzf', 'Install PowerShell module')) {
                        try {
                            Install-Module -Name PSFzf -Scope CurrentUser -Force -AllowClobber
                            Write-Host "  PSFzf module installed." -ForegroundColor Green
                        }
                        catch { Write-Warning "  Failed to install PSFzf: $_" }
                    }
                }
                # Invalidate init caches only for tools that were actually installed
                foreach ($tool in $installedTools) {
                    if ($tool.Cache) {
                        Remove-Item (Join-Path $cacheDir $tool.Cache) -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # Save configs to cache (after all phases so a failed WT write triggers retry next run)
        if ($configChanged) {
            if ($PSCmdlet.ShouldProcess($cachedConfig, "Save theme.json to cache")) {
                Copy-Item -Path $tempConfig -Destination $cachedConfig -Force
            }
        }
        if ($terminalConfigChanged) {
            if ($PSCmdlet.ShouldProcess($cachedTerminalConfig, "Save terminal-config.json to cache")) {
                Copy-Item -Path $tempTerminalConfig -Destination $cachedTerminalConfig -Force
            }
        }
        if (Test-Path $userSettingsPath) {
            if ($userSettingsParsed -and $userSettingsHash -and $phaseErrors.Count -eq 0) {
                if ($PSCmdlet.ShouldProcess($userSettingsStatePath, 'Save applied user-settings fingerprint')) {
                    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                    [System.IO.File]::WriteAllText($userSettingsStatePath, $userSettingsHash, $utf8NoBom)
                }
            }
        }
        elseif (Test-Path $userSettingsStatePath) {
            if ($PSCmdlet.ShouldProcess($userSettingsStatePath, 'Remove stale user-settings fingerprint')) {
                Remove-Item $userSettingsStatePath -Force -ErrorAction SilentlyContinue
            }
        }

        # Error summary
        if ($phaseErrors.Count -gt 0) {
            Write-Host ""
            Write-Host "Update completed with $($phaseErrors.Count) issue(s):" -ForegroundColor Yellow
            foreach ($err in $phaseErrors) {
                Write-Host "  - $err" -ForegroundColor Yellow
            }
        }

        if ($profileActuallyUpdated) {
            Restart-TerminalToApply -Message "Profile updated. Restarting terminal..."
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Unable to check for `$profile updates: $_"
    }
    finally {
        Remove-Item $tempProfile -ErrorAction SilentlyContinue
        Remove-Item $tempConfig -ErrorAction SilentlyContinue
        Remove-Item $tempTerminalConfig -ErrorAction SilentlyContinue
    }
}

# Check for new PowerShell (Core) releases and update via winget
function Update-PowerShell {
    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-Host "Windows PowerShell 5.1 is updated via Windows Update, not winget." -ForegroundColor Yellow
        Write-Host "This command checks for PowerShell 7+ (Core) updates only." -ForegroundColor Yellow
        return
    }
    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $currentVersion = $PSVersionTable.PSVersion
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $headers = @{}
        if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl -TimeoutSec 10 -Headers $headers
        if (-not $latestReleaseInfo.tag_name) { Write-Error "Invalid GitHub API response (missing tag_name)."; return }
        $latestVersionStr = $latestReleaseInfo.tag_name.Trim('v') -replace '-.*$', ''
        $latestVersion = [version]$latestVersionStr
        if ($currentVersion -lt $latestVersion) {
            Write-Host "Updating PowerShell ($currentVersion -> $latestVersion)..." -ForegroundColor Yellow
            Start-Process pwsh.exe -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -NoNewWindow
            Write-Host "PowerShell update started. Please restart your shell when complete." -ForegroundColor Magenta
        }
        else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -eq 403 -or $statusCode -eq 429) {
            Write-Warning 'GitHub API rate limit exceeded. Try again later or set $env:GITHUB_TOKEN to increase the limit.'
        }
        else {
            Write-Error "Failed to update PowerShell. Error: $_"
        }
    }
}
# Update installed profile tools via winget, while preserving direct/MSI Oh My Posh installs.
function Update-Tools {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "winget not found. Update-Tools only supports winget-managed upgrades."
        return
    }

    $installed = foreach ($tool in $script:ProfileTools) {
        $toolPath = Get-ProfileToolExecutablePath -Tool $tool
        if ($toolPath) {
            [PSCustomObject]@{
                Tool           = $tool
                ExecutablePath = $toolPath
            }
        }
    }

    if (-not $installed) {
        Write-Host "No profile tools detected. Run Update-Profile to install them." -ForegroundColor Yellow
        return
    }
    $upgraded = 0
    $failed = 0
    $preserved = 0
    foreach ($toolEntry in $installed) {
        $tool = $toolEntry.Tool
        $toolPath = $toolEntry.ExecutablePath

        if ($tool.UpgradeStrategy -eq 'preserve-direct' -and $tool.Cmd -eq 'oh-my-posh') {
            $ompInstall = Get-OhMyPoshInstallInfo
            if ($ompInstall.InstallKind -eq 'direct') {
                Write-Host "Skipping $($tool.Name) update to preserve direct/MSI install at $($ompInstall.Path)." -ForegroundColor DarkGray
                $preserved++
                continue
            }
        }

        # Capture pre-upgrade version
        $oldVer = Get-ProfileToolVersionText -Tool $tool -ExecutablePath $toolPath
        Write-Host "Updating $($tool.Name)..." -ForegroundColor Cyan
        winget upgrade --id $tool.Id --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            # Refresh PATH so the new binary is found for version check
            $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', 'User')
            $newToolPath = Get-ProfileToolExecutablePath -Tool $tool
            $newVer = if ($newToolPath) { Get-ProfileToolVersionText -Tool $tool -ExecutablePath $newToolPath } else { $null }
            if ($newVer -and $oldVer -and $newVer -ne $oldVer) {
                Write-Host "  $($tool.Name): $oldVer -> $newVer" -ForegroundColor Green
                if ($tool.Cache) {
                    Remove-Item (Join-Path $cacheDir $tool.Cache) -ErrorAction SilentlyContinue
                }
                $upgraded++
            }
            else {
                Write-Host "  $($tool.Name): already up to date ($oldVer)" -ForegroundColor DarkGray
            }
        }
        elseif ($LASTEXITCODE -ne -1978335189) { $failed++ }
    }
    if ($upgraded -gt 0) {
        Restart-TerminalToApply -Message "Tools updated. Restarting terminal..."
    }
    if ($failed -gt 0) {
        Write-Warning "$failed tool(s) failed to update. Check the output above."
    }
    if ($upgraded -eq 0 -and $failed -eq 0) {
        if ($preserved -gt 0) {
            Write-Host "All winget-managed tools are up to date. $preserved tool(s) were preserved." -ForegroundColor Green
        }
        else {
            Write-Host "All tools are up to date." -ForegroundColor Green
        }
    }
}

# Start a new terminal and exit the current one so changes take effect (interactive only; skips when -WhatIf).
# Same logic as setup.ps1 end block: prefer Windows Terminal (wt -w 0 = new tab in current window), else pwsh/powershell.
function Restart-TerminalToApply {
    param([string]$Message = "Update applied. Restarting terminal...")
    if (-not $isInteractive) { return }
    if ($WhatIfPreference) { return }
    $dir = (Get-Location).Path
    if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) {
        $dir = [Environment]::GetFolderPath('UserProfile')
    }
    $shellName = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
    Write-Host $Message -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-Host "Press Enter to restart (or close this window to cancel)..." -ForegroundColor Yellow
    try { $null = Read-Host } catch { $null = $_ }
    $wt = Get-Command wt.exe -ErrorAction SilentlyContinue
    if ($wt) {
        Start-Process -FilePath "wt.exe" -ArgumentList "-w", "0", "-d", $dir, $shellName, "-NoExit"
    }
    else {
        $shellExe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
        Start-Process -FilePath $shellExe -ArgumentList "-NoExit" -WorkingDirectory $dir
    }
    exit
}

# Clear user temp/browser caches (-IncludeSystemCaches for system dirs)
function Clear-Cache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$IncludeSystemCaches
    )

    Write-Host "Clearing cache..." -ForegroundColor Cyan

    $targets = @(
        @{ Name = "User Temp"; Path = "$env:TEMP\*"; Recurse = $true },
        @{ Name = "Internet Explorer Cache"; Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*"; Recurse = $true }
    )

    if ($IncludeSystemCaches) {
        $targets += @(
            @{ Name = "Windows Temp"; Path = "$env:SystemRoot\Temp\*"; Recurse = $true },
            @{ Name = "Windows Prefetch"; Path = "$env:SystemRoot\Prefetch\*"; Recurse = $false }
        )
    }

    foreach ($target in $targets) {
        if ($PSCmdlet.ShouldProcess($target.Path, "Clear $($target.Name)")) {
            Write-Host "Clearing $($target.Name)..." -ForegroundColor Yellow
            if ($target.Recurse) {
                Remove-Item -Path $target.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Remove-Item -Path $target.Path -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Cleared $($target.Name)." -ForegroundColor Green
        }
    }
}

# Admin Check and Prompt Customization (fallback when Oh My Posh is not loaded)
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
# PowerShell prompt (fallback when Oh My Posh is not loaded)
function prompt {
    if ($adminSuffix) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$script:FallbackPromptFunction = $Function:prompt
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Editor Configuration (lazy - resolves on first use)
# Override in profile_user.ps1, e.g.: $script:EditorPriority = @('nvim', 'code', 'notepad')
if ($null -eq $script:EditorPriority) {
    $script:EditorPriority = @('code', 'notepad')
}
$script:ResolvedEditor = $null

# Resolve preferred editor from EditorPriority or env EDITOR (used by edit/Edit-Profile)
function Resolve-PreferredEditor {
    if ($script:ResolvedEditor -and (Get-Command $script:ResolvedEditor -CommandType Application -ErrorAction SilentlyContinue)) {
        return $script:ResolvedEditor
    }

    $candidates = @()
    if ($env:EDITOR) { $candidates += $env:EDITOR }
    $candidates += @($script:EditorPriority)

    foreach ($candidate in ($candidates | Where-Object { $_ })) {
        if (Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue) {
            $script:ResolvedEditor = $candidate
            return $script:ResolvedEditor
        }
    }

    $script:ResolvedEditor = 'notepad'
    return $script:ResolvedEditor
}

# Open files with preferred editor (alias: edit)
function edit {
    $editor = Resolve-PreferredEditor
    & $editor @args
}

# Quick Access to Editing the Profile
function Edit-Profile {
    edit $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Create file or update its timestamp
function touch($file) {
    if (-not $file) { Write-Error "Usage: touch <file>"; return }
    if (Test-Path -LiteralPath $file) {
        (Get-Item -LiteralPath $file).LastWriteTime = Get-Date
    }
    else {
        New-Item -ItemType File -Path $file -Force | Out-Null
    }
}
# Recursive file search by name
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

# Network Utilities
function pubip {
    try {
        (Invoke-WebRequest https://ifconfig.me/ip -TimeoutSec 10 -UseBasicParsing).Content
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to retrieve public IP: $_"
    }
}

# Open WinUtil full-release (downloads to temp file, then executes locally)
function winutil {
    $scriptPath = Join-Path $env:TEMP "winutil.ps1"
    try {
        Invoke-RestMethod https://christitus.com/win -OutFile $scriptPath -TimeoutSec 10 -ErrorAction Stop
        & $scriptPath
    }
    catch {
        Write-Error "Failed to run WinUtil: $_"
    }
    finally {
        Remove-Item $scriptPath -ErrorAction SilentlyContinue
    }
}

# Launch Harden Windows Security (hss.exe) if installed
function harden {
    if (Get-Command "hss.exe" -ErrorAction SilentlyContinue) {
        Start-Process "hss.exe"
    }
    else {
        Write-Warning "hss.exe not found. Install Harden Windows Security from: https://github.com/HotCakeX/Harden-Windows-Security"
    }
}

# Open elevated Windows Terminal (detects PS edition)
function admin {
    $shell = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    if ($args.Count -gt 0) {
        $escaped = $args | ForEach-Object { if ($_ -match '\s') { "'$($_ -replace "'","''")'" } else { $_ } }
        $command = $escaped -join ' '
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        Start-Process wt -Verb runAs -ArgumentList "$shell -NoExit -EncodedCommand $encoded"
    }
    else {
        Start-Process wt -Verb runAs
    }
}

Set-Alias -Name su -Value admin
# System Uptime (PS5-compatible)
# Shared boot-time helper (PS5: WMI, PS7: Get-Uptime)
function Get-SystemBootTime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        $lastBoot = (Get-WmiObject win32_operatingsystem | Select-Object -First 1).LastBootUpTime
        [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
    }
    else {
        (Get-Uptime -Since)
    }
}

# Display system boot time and uptime
function uptime {
    try {
        $bootTime = Get-SystemBootTime
        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

        $uptime = (Get-Date) - $bootTime
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Blue
    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}
# Universal archive extractor (.zip, .tar, .gz, .7z, .rar)
function extract {
    param([Parameter(Mandatory)][string]$File)
    $resolved = Resolve-Path -LiteralPath $File -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $File"; return }
    $path = $resolved.Path
    $ext = [System.IO.Path]::GetExtension($path).ToLower()
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($path)
    if ([string]::Equals('.tar', [System.IO.Path]::GetExtension($baseName), [StringComparison]::OrdinalIgnoreCase)) { $ext = '.tar' + $ext }
    Write-Host "Extracting $path ..." -ForegroundColor Cyan
    switch ($ext) {
        '.zip' { Expand-Archive -LiteralPath $path -DestinationPath $pwd -Force }
        '.tar' { tar -xf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.gz' { tar -xzf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tgz' { tar -xzf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.bz2' { tar -xjf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.gz' {
            $outFile = Join-Path $pwd $baseName
            $in = [System.IO.File]::OpenRead($path)
            try {
                $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
                try {
                    $out = [System.IO.File]::Create($outFile)
                    try { $gz.CopyTo($out) }
                    finally { $out.Dispose() }
                }
                finally { $gz.Dispose() }
            }
            finally { $in.Dispose() }
            Write-Host "Extracted to $outFile" -ForegroundColor Green
        }
        '.7z' {
            if (-not (Get-Command 7z -ErrorAction SilentlyContinue)) { Write-Error "7z not found. Install with: winget install 7zip.7zip"; return }
            7z x "$path" -o"$pwd"
        }
        '.rar' {
            if (-not (Get-Command 7z -ErrorAction SilentlyContinue)) { Write-Error "7z not found. Install with: winget install 7zip.7zip"; return }
            7z x "$path" -o"$pwd"
        }
        default { Write-Error "Unsupported format: $ext" }
    }
}

# Hastebin-like upload function (PS5-compatible, no dependencies)
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }

    $FilePath = $args[0]

    if (Test-Path -LiteralPath $FilePath) {
        $Content = Get-Content -LiteralPath $FilePath -Raw
    }
    else {
        Write-Error "File path does not exist."
        return
    }

    $uri = "https://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop -TimeoutSec 10
        $hasteKey = $response.key
        $url = "https://bin.christitus.com/$hasteKey"
        Set-Clipboard $url
        Write-Output "$url copied to clipboard."
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to upload the document. Error: $_"
    }
}
# Grep Utility (PS5-compatible, no dependencies)
function grep {
    param([string]$regex, [string]$dir)
    if (-not $regex) { Write-Error "Usage: grep <regex> [dir] or <pipeline> | grep <regex>"; return }
    $hasInput = $MyInvocation.ExpectingInput
    if (Get-Command rg -ErrorAction SilentlyContinue) {
        if ($dir) { rg $regex $dir }
        elseif ($hasInput) { $input | rg $regex }
        else { rg $regex . }
    }
    else {
        if ($dir) { Get-ChildItem $dir -Recurse -File | Select-String $regex }
        elseif ($hasInput) { $input | Select-String $regex }
        else { Get-ChildItem . -Recurse -File | Select-String $regex }
    }
}

# Disk volume info
function df {
    get-volume
}

# Find and replace text in a file
function sed($file, $find, $replace) {
    if (-not $file -or -not (Test-Path -LiteralPath $file)) {
        Write-Warning "File not found: $file"
        return
    }
    if ($null -eq $find -or $find -eq '') { Write-Error "Usage: sed <file> <find> <replace>"; return }
    if ($null -eq $replace) { $replace = '' }
    $content = Get-Content -LiteralPath $file -Raw
    if ($null -eq $content -or $content.Length -eq 0) { Write-Warning "File is empty: $file"; return }
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $file).Path, $content.replace("$find", $replace), $utf8NoBom)
}

# Show the full path of a command
function which($name) {
    if (-not $name) { Write-Error "Usage: which <name>"; return }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { $cmd | Select-Object -ExpandProperty Definition; return }
    # Fall back to checking the current directory (like bash which for ./files)
    $local = Join-Path $pwd $name
    if (Test-Path $local) { (Resolve-Path $local).Path; return }
    Write-Error "which: $name not found"
}

# Identify file type via magic bytes (like Linux file command)
function file {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "file: cannot open '$Path' (No such file or directory)"; return }
    $fullPath = $resolved.Path
    $item = Get-Item -LiteralPath $fullPath
    if ($item.PSIsContainer) { Write-Host "$($fullPath): directory"; return }
    $size = $item.Length
    if ($size -eq 0) { Write-Host "$($fullPath): empty"; return }

    $readLen = [Math]::Min($size, 512)
    $stream = [System.IO.File]::OpenRead($fullPath)
    try {
        $bytes = New-Object byte[] $readLen
        [void]$stream.Read($bytes, 0, $readLen)
    }
    finally { $stream.Dispose() }

    $hex = -join ($bytes[0..([Math]::Min(3, $readLen - 1))] | ForEach-Object { '{0:X2}' -f $_ })
    $result = $null

    # Magic byte signatures (ordered by specificity)
    if ($hex.StartsWith('89504E47')) { $result = 'PNG image data' }
    elseif ($hex.StartsWith('FFD8FF')) { $result = 'JPEG image data' }
    elseif ($hex.StartsWith('47494638')) { $result = 'GIF image data' }
    elseif ($hex.StartsWith('424D')) { $result = 'BMP image data' }
    elseif ($hex.StartsWith('52494646') -and $readLen -ge 12) {
        $fourcc = [System.Text.Encoding]::ASCII.GetString($bytes, 8, 4)
        if ($fourcc -eq 'WEBP') { $result = 'WebP image data' }
        elseif ($fourcc -eq 'WAVE') { $result = 'WAVE audio' }
        elseif ($fourcc -eq 'AVI ') { $result = 'AVI video' }
        else { $result = "RIFF data ($fourcc)" }
    }
    elseif ($hex.StartsWith('25504446')) { $result = 'PDF document' }
    elseif ($hex.StartsWith('504B0304') -or $hex.StartsWith('504B0506') -or $hex.StartsWith('504B0708')) {
        # ZIP-based: check for Office/JAR/APK/EPUB markers
        $inner = [System.Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($readLen, 256))
        if ($inner -match 'word/') { $result = 'Microsoft Word document (DOCX)' }
        elseif ($inner -match 'xl/') { $result = 'Microsoft Excel spreadsheet (XLSX)' }
        elseif ($inner -match 'ppt/') { $result = 'Microsoft PowerPoint presentation (PPTX)' }
        elseif ($inner -match 'META-INF/') { $result = 'Java Archive (JAR)' }
        elseif ($inner -match 'AndroidManifest') { $result = 'Android application (APK)' }
        elseif ($inner -match 'mimetype.*epub') { $result = 'EPUB document' }
        else { $result = 'ZIP archive' }
    }
    elseif ($hex.StartsWith('4D5A')) { $result = 'PE32 executable (Windows)' }
    elseif ($hex.StartsWith('7F454C46')) { $result = 'ELF executable (Linux)' }
    elseif ($hex.StartsWith('FEEDFACE') -or $hex.StartsWith('FEEDFACF') -or $hex.StartsWith('CEFAEDFE') -or $hex.StartsWith('CFFAEDFE')) { $result = 'Mach-O executable (macOS)' }
    elseif ($hex.StartsWith('CAFEBABE')) { $result = 'Java class file' }
    elseif ($hex.StartsWith('1F8B')) { $result = 'gzip compressed data' }
    elseif ($hex.StartsWith('425A68')) { $result = 'bzip2 compressed data' }
    elseif ($hex.StartsWith('FD377A58')) { $result = 'XZ compressed data' }
    elseif ($hex.StartsWith('377ABCAF')) { $result = '7-zip archive' }
    elseif ($hex.StartsWith('526172')) { $result = 'RAR archive' }
    elseif ($readLen -ge 262 -and [System.Text.Encoding]::ASCII.GetString($bytes, 257, [Math]::Min(5, $readLen - 257)) -eq 'ustar') { $result = 'POSIX tar archive' }
    elseif ($hex.StartsWith('4F676753')) { $result = 'OGG audio' }
    elseif ($hex.StartsWith('664C6143')) { $result = 'FLAC audio' }
    elseif ($hex.StartsWith('494433') -or $hex.StartsWith('FFFB') -or $hex.StartsWith('FFF3') -or $hex.StartsWith('FFE3')) { $result = 'MP3 audio' }
    elseif ($readLen -ge 8 -and [System.Text.Encoding]::ASCII.GetString($bytes, 4, 4) -eq 'ftyp') {
        $brand = if ($readLen -ge 12) { [System.Text.Encoding]::ASCII.GetString($bytes, 8, 4).Trim() } else { '' }
        if ($brand -match '^mp4|^isom|^M4V|^MSNV') { $result = 'MP4 video' }
        elseif ($brand -match '^M4A|^mp4a') { $result = 'M4A audio' }
        elseif ($brand -match '^qt') { $result = 'QuickTime video' }
        elseif ($brand -match '^heic|^mif1') { $result = 'HEIF image' }
        else { $result = "ISO Media ($brand)" }
    }
    elseif ($hex.StartsWith('1A45DFA3')) { $result = 'Matroska video (MKV/WEBM)' }
    elseif ($hex.StartsWith('53514C69')) { $result = 'SQLite database' }
    elseif ($hex.StartsWith('D0CF11E0')) { $result = 'Microsoft Office legacy document (OLE2)' }
    elseif ($hex.StartsWith('00000100')) { $result = 'Windows icon (ICO)' }
    elseif ($hex.StartsWith('00000200')) { $result = 'Windows cursor (CUR)' }
    elseif ($hex.StartsWith('4C000000')) { $result = 'Windows shortcut (LNK)' }
    elseif ($hex.StartsWith('EFBBBF') -or $hex.StartsWith('FFFE') -or $hex.StartsWith('FEFF')) {
        $result = 'Unicode text (with BOM)'
    }
    else {
        # Check if content is printable ASCII/UTF-8 text
        $textSample = $bytes[0..([Math]::Min(255, $readLen - 1))]
        $nonText = ($textSample | Where-Object { $_ -lt 0x09 -or ($_ -gt 0x0D -and $_ -lt 0x20 -and $_ -ne 0x1B) -or $_ -eq 0x7F }).Count
        if ($nonText -eq 0) {
            $firstLine = [System.Text.Encoding]::UTF8.GetString($bytes, 0, [Math]::Min(128, $readLen))
            if ($firstLine -match '^#!.*python') { $result = 'Python script, ASCII text' }
            elseif ($firstLine -match '^#!.*bash|^#!.*/sh') { $result = 'Bourne shell script, ASCII text' }
            elseif ($firstLine -match '^#!.*perl') { $result = 'Perl script, ASCII text' }
            elseif ($firstLine -match '^#!.*ruby') { $result = 'Ruby script, ASCII text' }
            elseif ($firstLine -match '^#!.*node|^#!.*deno|^#!.*bun') { $result = 'JavaScript script, ASCII text' }
            elseif ($firstLine -match '^#!') { $result = 'script, ASCII text' }
            elseif ($firstLine -match '^\s*<\?xml') { $result = 'XML document, ASCII text' }
            elseif ($firstLine -match '^\s*<!DOCTYPE\s+html|^\s*<html') { $result = 'HTML document, ASCII text' }
            elseif ($firstLine -match '^\s*\{') { $result = 'JSON data, ASCII text' }
            elseif ($firstLine -match '^-----BEGIN') { $result = 'PEM certificate/key, ASCII text' }
            else { $result = 'ASCII text' }
        }
        else { $result = 'data' }
    }

    Write-Host "$($fullPath): $result ($([Math]::Round($size / 1KB, 1)) KB)"
}

# Set an environment variable in the current session
function export($name, $value) {
    if (-not $name) { Write-Error "Usage: export <name> <value>"; return }
    if ($null -eq $value) { Write-Error "Usage: export <name> <value>"; return }
    set-item -force -path "env:$name" -value $value;
}

# Kill process by name
function pkill($name) {
    if (-not $name) { Write-Error "Usage: pkill <name>"; return }
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
}

# List processes by name
function pgrep($name) {
    if (-not $name) { Write-Error "Usage: pgrep <name>"; return }
    Get-Process $name -ErrorAction SilentlyContinue
}

# Display first n lines of a file (default 10)
function head {
    param($Path, $n = 10)
    if (-not $Path) { Write-Error "Usage: head <path> [n]"; return }
    Get-Content -LiteralPath $Path -Head $n
}

# Display last n lines of a file (default 10, -f to follow)
function tail {
    param($Path, $n = 10, [switch]$f = $false)
    if (-not $Path) { Write-Error "Usage: tail <path> [n] [-f]"; return }
    Get-Content -LiteralPath $Path -Tail $n -Wait:$f
}

Set-Alias -Name nf -Value touch

# Directory Management
function mkcd { param($dir) if (-not $dir) { Write-Error "Usage: mkcd <dir>"; return }; mkdir $dir -Force -ErrorAction Stop | Out-Null; Set-Location $dir }

# Move item to Recycle Bin via Shell.Application COM
function trash($path) {
    if (-not $path) { Write-Error "Usage: trash <path>"; return }
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "Error: Item '$path' does not exist."
        return
    }

    $item = Get-Item -LiteralPath $path

    if ($item.PSIsContainer) {
        if (-not $item.Parent) { Write-Error "Cannot move root directory to Recycle Bin."; return }
        $parentPath = $item.Parent.FullName
    }
    else {
        $parentPath = $item.DirectoryName
    }

    $shell = New-Object -ComObject 'Shell.Application'
    try {
        $folder = $shell.NameSpace($parentPath)
        if (-not $folder) {
            Write-Host "Error: Cannot access parent folder '$parentPath'."
            return
        }
        $shellItem = $folder.ParseName($item.Name)
        if (-not $shellItem) {
            Write-Host "Error: Cannot find '$($item.Name)' in '$parentPath'."
            return
        }
        $shellItem.InvokeVerb('delete')
        Write-Host "Item '$($item.FullName)' has been moved to the Recycle Bin."
    }
    finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

### Quality of Life Aliases

# Navigation Shortcuts
function docs {
    $docs = [Environment]::GetFolderPath("MyDocuments")
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $HOME + "\Documents" }
    Set-Location -Path $docs
}

# Change directory to Desktop
function dtop {
    $dtop = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrWhiteSpace($dtop)) { $dtop = $HOME + "\Desktop" }
    Set-Location -Path $dtop
}

# Enhanced Listing (eza - modern ls replacement with icons and git status)
if (Get-Command eza -ErrorAction SilentlyContinue) {
    # Remove-Alias exists only in PS6+; PS5 needs Remove-Item on the Alias: drive
    if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
        Remove-Alias ls -Force -ErrorAction SilentlyContinue
    }
    else {
        Remove-Item Alias:\ls -Force -ErrorAction SilentlyContinue
    }
    # ls/la/ll/lt: directory listing via eza (icons, git status, tree)
    function ls { eza --icons @args }
    function la { eza -a --icons @args }
    function ll { eza -la --icons --git @args }
    function lt { eza --tree --icons --level=2 @args }
}
else {
    if ($isInteractive) { Write-Warning "eza not found. Install it with: winget install -e --id eza-community.eza" }
    # Fallback listing when eza not installed
    function la { Get-ChildItem -Force | Format-Table -AutoSize }
    function ll { Get-ChildItem -Force | Format-Table Mode, LastWriteTime, Length, Name -AutoSize }
    function lt { Get-ChildItem -Recurse -Depth 2 | Format-Table -AutoSize }
}

# Syntax-highlighted file viewer (bat - modern cat replacement)
if (-not $env:BAT_THEME) { $env:BAT_THEME = "TwoDark" }
if (Get-Command bat -ErrorAction SilentlyContinue) {
    if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
        Remove-Alias cat -Force -ErrorAction SilentlyContinue
    }
    else {
        Remove-Item Alias:\cat -Force -ErrorAction SilentlyContinue
    }
    # cat: syntax-highlighted output via bat (no paging)
    function cat { bat --paging=never @args }
}
else {
    if ($isInteractive) { Write-Warning "bat not found. Install it with: winget install -e --id sharkdp.bat" }
}

# Git Shortcuts
function gs { git status }

# Git add all
function ga { git add .; if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed (exit $LASTEXITCODE)" } }

# Remove built-in gc alias (Get-Content) so our function is reachable
if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
    Remove-Alias gc -Force -ErrorAction SilentlyContinue
}
else {
    Remove-Item Alias:\gc -Force -ErrorAction SilentlyContinue
}
# Git commit with message
function gc {
    if (-not $args) { Write-Error "Usage: gc <message> [git-flags]"; return }
    $msg = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    git commit -m $msg @rest
    if ($LASTEXITCODE -ne 0) { Write-Warning "git commit failed (exit $LASTEXITCODE)" }
}

# Remove built-in gp alias (Get-Process) so our function is reachable
function gpush { git push }

# Remove built-in gl alias (Get-ChildItem) so our function is reachable
function gpull { git pull }

# Jump to github directory via zoxide
function g {
    if (Get-Command __zoxide_z -ErrorAction SilentlyContinue) {
        __zoxide_z github
    }
    else {
        Write-Warning "zoxide is not initialized. Install zoxide and restart your shell."
    }
}

# Git clone shortcut
function gcl { git clone @args }

# Add all + commit
function gcom {
    if (-not $args) { Write-Error "Usage: gcom <message> [git-flags]"; return }
    git add .
    if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed. Commit skipped."; return }
    $msg = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    git commit -m $msg @rest
}
# Add all + commit + push
function lazyg {
    if (-not $args) { Write-Error "Usage: lazyg <message>"; return }
    gcom @args
    if ($LASTEXITCODE -eq 0) { git push }
    else { Write-Warning "Commit failed. Push skipped." }
}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns {
    Clear-DnsClientCache
    Write-Host "DNS has been flushed"
}

# Network Diagnostics
function ports {
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Sort-Object LocalPort |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Port    = $_.LocalPort
                Address = $_.LocalAddress
                PID     = $_.OwningProcess
                Process = if ($proc) { $proc.ProcessName } else { '-' }
            }
        } | Format-Table -AutoSize
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        netstat -ano | Select-String 'LISTENING'
    }
}

# Check if a specific port is open on a host (defaults to localhost)
function checkport {
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][int]$Port
    )
    $result = Test-NetConnection -ComputerName $Hostname -Port $Port -WarningAction SilentlyContinue
    if ($result -and $result.TcpTestSucceeded) {
        Write-Host "$Hostname`:$Port is OPEN" -ForegroundColor Green
    }
    else {
        Write-Host "$Hostname`:$Port is CLOSED/FILTERED" -ForegroundColor Red
    }
}

# List local IPv4 addresses (excluding loopback and APIPA)
function localip {
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize
}

# DNS Lookup (defaults to A record, specify type with -Type)
function nslook {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'ANY')][string]$Type = 'A'
    )
    Resolve-DnsName -Name $Domain -Type $Type | Format-Table -AutoSize
}

# Security & Crypto
function hash {
    param(
        [Parameter(Mandatory)][string]$File,
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')][string]$Algorithm = 'SHA256'
    )
    if (-not (Test-Path -LiteralPath $File)) { Write-Error "File not found: $File"; return }
    (Get-FileHash -LiteralPath $File -Algorithm $Algorithm).Hash
}

# Verify file integrity by comparing computed hash to expected value (auto-detects algorithm by length)
function checksum {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$Expected
    )
    if (-not (Test-Path -LiteralPath $File)) { Write-Error "File not found: $File"; return }
    $algo = switch ($Expected.Length) {
        32 { 'MD5' }
        40 { 'SHA1' }
        64 { 'SHA256' }
        96 { 'SHA384' }
        128 { 'SHA512' }
        default { 'SHA256' }
    }
    $actual = hash -File $File -Algorithm $algo
    if ($actual -eq $Expected.ToUpper()) {
        Write-Host "MATCH ($algo)" -ForegroundColor Green
    }
    else {
        Write-Host "MISMATCH ($algo)" -ForegroundColor Red
        Write-Host "Expected: $Expected"
        Write-Host "Actual:   $actual"
    }
}

# Generate a random password of specified length (default 20) and copy to clipboard
function genpass {
    param([ValidateRange(1, 1024)][int]$Length = 20)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?'
    $charCount = $chars.Length
    # Rejection threshold eliminates modulo bias (largest multiple of charCount that fits in a byte)
    $limit = 256 - (256 % $charCount)
    $result = [System.Text.StringBuilder]::new($Length)
    $buf = [byte[]]::new(1)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        while ($result.Length -lt $Length) {
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
            if ($buf[0] -lt $limit) { [void]$result.Append($chars[$buf[0] % $charCount]) }
        }
    }
    else {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        try {
            while ($result.Length -lt $Length) {
                $rng.GetBytes($buf)
                if ($buf[0] -lt $limit) { [void]$result.Append($chars[$buf[0] % $charCount]) }
            }
        }
        finally { $rng.Dispose() }
    }
    $password = $result.ToString()
    Set-Clipboard $password
    Write-Host "Password copied to clipboard." -ForegroundColor Green
    return $password
}

# Base64 encode/decode
function b64 {
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

# Base64 decode with error handling
function b64d {
    param([Parameter(Mandatory)][string]$Text)
    try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text)) }
    catch { Write-Error "Invalid Base64 input: $_" }
}

# VirusTotal file scanner (PS5-compatible, no dependencies)
function vtscan {
    param([Parameter(Mandatory)][string]$FilePath)
    $apiKey = if ($env:VTCLI_APIKEY) { $env:VTCLI_APIKEY } elseif ($env:VT_API_KEY) { $env:VT_API_KEY } else { $null }
    if (-not $apiKey) {
        Write-Host 'Set $env:VTCLI_APIKEY first (free key at https://www.virustotal.com/gui/my-apikey)' -ForegroundColor Red
        Write-Host 'Or run: vt init' -ForegroundColor Yellow
        return
    }
    $resolved = Resolve-Path -LiteralPath $FilePath -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $FilePath"; return }
    $file = Get-Item -LiteralPath $resolved
    $sizeMB = [math]::Round($file.Length / 1MB, 2)
    if ($file.Length -gt 32MB) {
        Write-Error "File too large ($sizeMB MB). VirusTotal free limit is 32 MB."
        return
    }
    $sha = (Get-FileHash $resolved -Algorithm SHA256).Hash.ToLower()
    $headers = @{ 'x-apikey' = $apiKey }
    $sizeLabel = if ($file.Length -ge 1MB) { "$sizeMB MB" } else { "$([math]::Round($file.Length / 1KB, 1)) KB" }
    Write-Host "`nFile:       $($file.Name) ($sizeLabel)" -ForegroundColor Cyan
    Write-Host "SHA256:     $sha" -ForegroundColor Cyan

    # Lookup by hash first
    $found = $false
    try {
        $report = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha" -Headers $headers -ErrorAction Stop
        $found = $true
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -ne 404) {
            Write-Error "VT API error: $_"
            return
        }
    }

    if ($found) {
        $stats = $report.data.attributes.last_analysis_stats
        if (-not $stats) {
            Write-Warning "Unexpected VirusTotal response (missing analysis stats)."
            return
        }
        $mal = [int]$stats.malicious
        $total = [int]$stats.malicious + [int]$stats.undetected + [int]$stats.harmless + [int]$stats.suspicious + [int]$stats.timeout
        if ($total -eq 0) { $total = 1 }
        $color = if ($mal -eq 0) { 'Green' } elseif ($mal -le 5) { 'Yellow' } else { 'Red' }
        Write-Host "Detections: $mal/$total" -ForegroundColor $color
        $vtLink = "https://www.virustotal.com/gui/file/$sha/detection"
        Write-Host "Link:       $vtLink" -ForegroundColor Cyan
        Start-Process $vtLink
        $results = $report.data.attributes.last_analysis_results
        $detections = if ($results) {
            $results.PSObject.Properties |
            Where-Object { $_.Value.category -eq 'malicious' } |
            Sort-Object { $_.Value.engine_name }
        }
        if ($detections) {
            Write-Host ''
            foreach ($d in $detections) {
                $engine = $d.Value.engine_name.PadRight(20)
                Write-Host "  $engine $($d.Value.result)" -ForegroundColor Red
            }
        }
        return
    }

    # File not known - upload
    Write-Host 'Hash not found, uploading...' -ForegroundColor Yellow
    $uploadUrl = 'https://www.virustotal.com/api/v3/files'
    if ($file.Length -gt 10MB) {
        try {
            $uploadUrl = (Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/files/upload_url' -Headers $headers -ErrorAction Stop).data
            if (-not $uploadUrl) { Write-Error "VirusTotal did not return an upload URL."; return }
            Write-Host 'Using large-file upload endpoint.' -ForegroundColor DarkGray
        }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Error "Failed to get upload URL: $_"
            return
        }
    }
    $boundary = [guid]::NewGuid().ToString('N')
    $fileBytes = [System.IO.File]::ReadAllBytes($resolved.Path)
    $enc = [System.Text.Encoding]::GetEncoding('iso-8859-1')
    $safeName = $file.Name -replace '["\r\n]', '_'
    $header = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$safeName`"`r`nContent-Type: application/octet-stream`r`n`r`n"
    $footer = "`r`n--$boundary--`r`n"
    $bodyBytes = $enc.GetBytes($header) + $fileBytes + $enc.GetBytes($footer)
    try {
        $resp = Invoke-WebRequest -Uri $uploadUrl `
            -Method Post -Headers $headers `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $bodyBytes -UseBasicParsing -ErrorAction Stop
        $parsed = $resp.Content | ConvertFrom-Json
        if (-not $parsed -or -not $parsed.data -or -not $parsed.data.links) {
            Write-Error "Unexpected VirusTotal upload response."
            return
        }
        $link = $parsed.data.links.self
        Write-Host "Uploaded. Analysis: $link" -ForegroundColor Green
        $vtLink = "https://www.virustotal.com/gui/file/$sha/detection"
        Write-Host "Link:       $vtLink" -ForegroundColor Cyan
        Start-Process $vtLink
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Upload failed: $_"
    }
}

if (-not (Get-Command vt.exe -ErrorAction SilentlyContinue)) {
    # Fallback when vt-cli not installed: show install instructions
    function vt {
        Write-Host 'vt-cli is not installed. Install with:' -ForegroundColor Red
        Write-Host '  winget install VirusTotal.vt-cli' -ForegroundColor Yellow
        Write-Host 'Then run: vt init' -ForegroundColor Yellow
    }
}

# Docker Shortcuts (conditional)
if (Get-Command docker -ErrorAction SilentlyContinue) {
    # dps/dpa/dimg: list containers and images
    function dps { docker ps @args }
    function dpa { docker ps -a @args }
    function dimg { docker images @args }
    # dlogs: follow container logs; dex: exec into container
    function dlogs {
        param([Parameter(Mandatory)][string]$Container)
        docker logs -f $Container
    }
    function dex {
        param(
            [Parameter(Mandatory)][string]$Container,
            [string]$Shell = 'bash'
        )
        docker exec -it $Container $Shell
    }
    # dstop: stop all running containers; dprune: system prune
    function dstop {
        $running = docker ps -q
        if ($running) { docker stop $running } else { Write-Host "No running containers." }
    }
    function dprune { docker system prune -f }
}

# System Admin
function svc {
    param(
        [string]$Name,
        [int]$Count = 25,
        [switch]$Live
    )
    $bootTime = Get-SystemBootTime
    do {
        if ($Live) { Clear-Host }
        try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
        catch { Write-Error "Failed to query system info: $_"; return }
        $totalMem = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        $usedMem = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 1)
        $memPct = if ($totalMem -gt 0) { [math]::Round($usedMem / $totalMem * 100) } else { 0 }
        $cpuLoad = try { [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average) } catch { 0 }
        $procCount = @(Get-Process).Count
        $up = (Get-Date) - $bootTime
        $upStr = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes
        Write-Host ''
        Write-Host ('  CPU: {0}%  |  Mem: {1}/{2} GB ({3}%)  |  Procs: {4}  |  Up: {5}' -f $cpuLoad, $usedMem, $totalMem, $memPct, $procCount, $upStr) -ForegroundColor Cyan
        Write-Host ('  ' + ('-' * 70)) -ForegroundColor DarkGray
        $procs = if ($Name) {
            Get-Process -Name "*$Name*" -ErrorAction SilentlyContinue
        }
        else {
            Get-Process
        }
        $procs | Sort-Object CPU -Descending | Select-Object -First $Count |
        Format-Table @{L = 'Name'; E = { $_.Name }; W = 25 },
        @{L = 'PID'; E = { $_.Id }; A = 'Right' },
        @{L = 'CPU(s)'; E = { [math]::Round($_.CPU, 1) }; A = 'Right' },
        @{L = 'Mem(MB)'; E = { [math]::Round($_.WorkingSet64 / 1MB, 1) }; A = 'Right' },
        @{L = 'Threads'; E = { try { $_.Threads.Count } catch { 0 } }; A = 'Right' } -AutoSize
        if ($Live) { Start-Sleep -Seconds 2 }
    } while ($Live)
}

# Reload profile in current session (useful after editing profile_user.ps1 or user-settings.json)
function reload { . $PROFILE }

# Clear profile cache (Oh My Posh and our own) to resolve issues with stale data or after manual edits to cache files. Terminal restart is required to see changes.
function Clear-ProfileCache {
    $cacheDir = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
    if (-not (Test-Path $cacheDir)) {
        Clear-OhMyPoshCaches -Quiet
        Write-Host "No cache directory found." -ForegroundColor Yellow
        return
    }
    $items = Get-ChildItem $cacheDir -Exclude "user-settings.json" -ErrorAction SilentlyContinue
    if (-not $items) {
        Clear-OhMyPoshCaches -Quiet
        Write-Host "Cache is already clean." -ForegroundColor Green
        return
    }
    foreach ($item in $items) {
        Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed $($item.Name)" -ForegroundColor DarkGray
    }
    Clear-OhMyPoshCaches -Quiet
    Restart-TerminalToApply -Message "Profile cache cleared. Restarting terminal..."
}

# Uninstall profile components with granular options. By default, only non-user data caches and PSFzf module are removed to allow for quick resets without data loss.
# Use -All to remove everything including user settings and fonts. Windows Terminal settings are handled in a way to allow easy restoration of previous state if not doing a hard reset.
function Uninstall-Profile {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$RemoveTools,
        [switch]$RemoveUserData,
        [switch]$RemoveFonts,
        [switch]$All,
        [switch]$HardResetWindowsTerminal
    )

    if ($All) { $RemoveTools = $true; $RemoveUserData = $true; $RemoveFonts = $true }
    $preserved = @()

    # Phase 1: Windows Terminal settings
    $wtSettingsPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
    if (Test-Path (Split-Path $wtSettingsPath)) {
        $wtLocalState = Split-Path $wtSettingsPath
        $backups = Get-ChildItem -Path $wtLocalState -Filter 'settings.json.*.bak' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

        if ($HardResetWindowsTerminal) {
            if (Test-Path $wtSettingsPath) {
                if ($PSCmdlet.ShouldProcess($wtSettingsPath, 'Delete WT settings for hard reset')) {
                    Remove-Item $wtSettingsPath -Force -ErrorAction SilentlyContinue
                    Write-Host '  Deleted Windows Terminal settings.json (WT will recreate defaults on next launch).' -ForegroundColor Green
                }
            }
            if ($backups) {
                foreach ($bak in $backups) {
                    if ($PSCmdlet.ShouldProcess($bak.FullName, 'Remove WT backup')) {
                        Remove-Item $bak.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        elseif ($backups) {
            $newest = $backups[0]
            if ($PSCmdlet.ShouldProcess($wtSettingsPath, "Restore WT settings from $($newest.Name)")) {
                Copy-Item -Path $newest.FullName -Destination $wtSettingsPath -Force
                Write-Host "  Restored WT settings from $($newest.Name)" -ForegroundColor Green
                # Only delete backups after a successful restore so they are not lost on a declined prompt
                foreach ($bak in $backups) {
                    if ($PSCmdlet.ShouldProcess($bak.FullName, 'Remove WT backup')) {
                        Remove-Item $bak.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }

    # Phase 2: Cache cleanup
    $cacheDir = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
    if (Test-Path $cacheDir) {
        $excludes = @()
        if (-not $RemoveUserData) { $excludes += 'user-settings.json'; $excludes += 'profile_user.ps1' }
        $cacheItems = Get-ChildItem $cacheDir -ErrorAction SilentlyContinue |
        Where-Object { $excludes -notcontains $_.Name }
        foreach ($item in $cacheItems) {
            if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove cache file')) {
                Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "  Removed $($item.Name)" -ForegroundColor DarkGray
            }
        }
        if (-not $RemoveUserData) { $preserved += 'user-settings.json (use -RemoveUserData to remove)' }
        # Remove empty cache dir
        $remaining = Get-ChildItem $cacheDir -ErrorAction SilentlyContinue
        if (-not $remaining) {
            if ($PSCmdlet.ShouldProcess($cacheDir, 'Remove empty cache directory')) {
                Remove-Item $cacheDir -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Clear-OhMyPoshCaches -Quiet

    # Phase 3: Uninstall PSFzf module
    # Note: In CI or agent runs (env:CI or env:AI_AGENT), we skip uninstalling PSFzf to avoid
    # mutating the host user's real module installation when ci-functional.ps1 is run locally.
    $isCiOrAgent = ($env:CI -or $env:AI_AGENT)
    if (Get-Module -ListAvailable -Name PSFzf) {
        if ($isCiOrAgent) {
            Write-Host '  Skipping PSFzf module uninstall under CI/agent environment.' -ForegroundColor DarkGray
        }
        elseif ($PSCmdlet.ShouldProcess('PSFzf', 'Uninstall module')) {
            $uninstalled = $false
            try {
                # Try to unload the module from the current session first
                Remove-Module -Name PSFzf -Force -ErrorAction SilentlyContinue
            }
            catch { $null = $_ }
            try {
                Uninstall-Module -Name PSFzf -AllVersions -Force -ErrorAction Stop
                Write-Host '  Uninstalled PSFzf module.' -ForegroundColor Green
                $uninstalled = $true
            }
            catch {
                Write-Warning "  Failed to uninstall PSFzf in current session: $_"
            }

            if (-not $uninstalled) {
                # Fallback: spawn a background shell to attempt uninstall so this session
                # does not keep the module "in use".
                $psExe = $null
                $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
                if ($cmd) {
                    $psExe = $cmd.Source
                }
                else {
                    $cmd = Get-Command powershell -ErrorAction SilentlyContinue
                    if ($cmd) { $psExe = $cmd.Source }
                }

                if ($psExe) {
                    try {
                        Start-Process -FilePath $psExe -ArgumentList @(
                            '-NoProfile'
                            '-NonInteractive'
                            '-Command'
                            "try { Uninstall-Module -Name PSFzf -AllVersions -Force -ErrorAction SilentlyContinue } catch { `$null = `$_ }"
                        ) -WindowStyle Hidden | Out-Null
                        Write-Host '  Scheduled PSFzf uninstall in background session.' -ForegroundColor Yellow
                    }
                    catch {
                        Write-Warning "  Failed to schedule PSFzf uninstall in background session: $_"
                    }
                }
                else {
                    Write-Warning '  Could not locate pwsh or powershell to retry PSFzf uninstall in a background session.'
                }
            }
        }
    }

    # Phase 4: Winget tools (opt-in)
    if ($RemoveTools -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        if ($isCiOrAgent) {
            Write-Host '  Skipping managed tool uninstall under CI/agent environment.' -ForegroundColor DarkGray
        }
        else {
            foreach ($tool in $script:ProfileTools) {
                if (Get-Command $tool.Cmd -ErrorAction SilentlyContinue) {
                    if ($PSCmdlet.ShouldProcess($tool.Name, 'Uninstall via winget')) {
                        try {
                            $wingetOutput = @(& winget uninstall -e --id $tool.Id --silent 2>&1)
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "  Uninstalled $($tool.Name)" -ForegroundColor Green
                            }
                            else {
                                $wingetMessage = (@($wingetOutput) -join ' ').Trim()
                                if (-not $wingetMessage) { $wingetMessage = 'no diagnostic output' }
                                Write-Warning "  Failed to uninstall $($tool.Name) (exit $LASTEXITCODE): $wingetMessage"
                            }
                        }
                        catch {
                            Write-Warning "  Failed to uninstall $($tool.Name): $_"
                        }
                    }
                }
            }
        }
    }
    elseif (-not $RemoveTools) { $preserved += 'Managed tools (use -RemoveTools to uninstall)' }
    elseif (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning '  winget not found - managed tools were not removed.'
    }

    # Phase 5: Nerd Fonts (opt-in, requires admin)
    if ($RemoveFonts) {
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isElevated) {
            Write-Warning '  Font removal requires an elevated (admin) terminal. Skipping.'
        }
        else {
            $fontDisplayName = 'CaskaydiaCove NF'
            try {
                $tcPath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\terminal-config.json'
                if (Test-Path $tcPath) {
                    $tc = Get-Content $tcPath -Raw | ConvertFrom-Json
                    if ($tc.fontInstall.displayName) { $fontDisplayName = $tc.fontInstall.displayName }
                }
            }
            catch { $null = $_ }
            $fontDir = Join-Path $env:SystemRoot 'Fonts'
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
            $fontFiles = Get-ChildItem $fontDir -Filter '*CaskaydiaCove*NF*.ttf' -ErrorAction SilentlyContinue
            if ($fontFiles) {
                foreach ($f in $fontFiles) {
                    if ($PSCmdlet.ShouldProcess($f.Name, 'Remove font file')) {
                        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                # Clean registry entries
                $regEntries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                if ($regEntries) {
                    $regEntries.PSObject.Properties | Where-Object { $_.Name -match 'Caskaydia' -and $_.Name -match 'NF' } | ForEach-Object {
                        if ($PSCmdlet.ShouldProcess($_.Name, 'Remove font registry entry')) {
                            Remove-ItemProperty -Path $regPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                Write-Host "  Removed $($fontDisplayName) font files." -ForegroundColor Green
            }
            else {
                Write-Host "  No Nerd Font files found to remove." -ForegroundColor DarkGray
            }
        }
    }
    else { $preserved += 'Nerd Fonts (use -RemoveFonts to remove, requires admin)' }

    # Phase 6: Remove telemetry opt-out env var
    $isElevatedNow = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
        if ($isElevatedNow) {
            if ($PSCmdlet.ShouldProcess('POWERSHELL_TELEMETRY_OPTOUT', 'Remove machine environment variable')) {
                [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', $null, [System.EnvironmentVariableTarget]::Machine)
                Write-Host '  Removed POWERSHELL_TELEMETRY_OPTOUT env var.' -ForegroundColor Green
            }
        }
        else {
            Write-Host '  Skipping POWERSHELL_TELEMETRY_OPTOUT removal (requires admin).' -ForegroundColor DarkGray
        }
    }

    # Phase 7: Profile files
    $docsRoot = Split-Path (Split-Path $PROFILE)
    $profileDirs = @(
        Join-Path $docsRoot 'PowerShell'
        Join-Path $docsRoot 'WindowsPowerShell'
    )
    foreach ($dir in $profileDirs) {
        $mainProfile = Join-Path $dir 'Microsoft.PowerShell_profile.ps1'
        if (Test-Path $mainProfile) {
            if ($PSCmdlet.ShouldProcess($mainProfile, 'Remove profile file')) {
                Remove-Item $mainProfile -Force -ErrorAction SilentlyContinue
                Write-Host "  Removed $mainProfile" -ForegroundColor DarkGray
            }
        }
        if ($RemoveUserData) {
            $userProf = Join-Path $dir 'profile_user.ps1'
            if (Test-Path $userProf) {
                if ($PSCmdlet.ShouldProcess($userProf, 'Remove user profile overrides')) {
                    Remove-Item $userProf -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed $userProf" -ForegroundColor DarkGray
                }
            }
        }
        elseif (Test-Path (Join-Path $dir 'profile_user.ps1')) {
            $preserved += "profile_user.ps1 in $dir (use -RemoveUserData to remove)"
        }
    }

    # Phase 8: Summary
    Write-Host ''
    if ($preserved) {
        Write-Host ''
        Write-Host 'Preserved:' -ForegroundColor Yellow
        foreach ($p in $preserved) { Write-Host "  - $p" -ForegroundColor DarkGray }
        Write-Host ''
        if (-not $All) {
            Write-Host 'Use Uninstall-Profile -All to remove everything.' -ForegroundColor Yellow
        }
    }
    Restart-TerminalToApply -Message "Uninstall complete. Restarting terminal..."
}

# Utility
function path { $env:PATH -split ';' | Where-Object { $_ } }

# Fetch current weather for a city or based on IP geolocation if no city is provided. Uses wttr.in with a fallback to Open-Meteo if wttr.in is unreachable.
function weather {
    param([string]$City)
    $encoded = if ($City) { [System.Uri]::EscapeDataString($City) } else { '' }
    # Try wttr.in first, fall back to Open-Meteo if unreachable
    $url = if ($encoded) { "https://wttr.in/${encoded}?format=3" } else { "https://wttr.in/?format=3" }
    try {
        $r = Invoke-RestMethod $url -TimeoutSec 10 -Headers @{ 'User-Agent' = 'curl' }
        $text = ($r | Out-String).Trim()
        if ($text -and $text -notmatch '(?i)unknown|error|not found') {
            $text
            return
        }
    }
    catch { if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }; $null = $_ }

    # Fallback: Open-Meteo (free, no API key)
    try {
        $loc = if ($City) {
            $geo = Invoke-RestMethod "https://geocoding-api.open-meteo.com/v1/search?name=$encoded&count=1" -TimeoutSec 5
            if (-not $geo -or -not $geo.results -or @($geo.results).Count -eq 0) { Write-Error "City '$City' not found."; return }
            $geo.results[0]
        }
        else {
            $ip = Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 5
            if (-not $ip -or -not $ip.loc -or $ip.loc -notmatch ',') { Write-Error "Could not determine location from IP."; return }
            $ll = $ip.loc -split ','
            if ($ll.Count -lt 2) { Write-Error "Malformed location data from IP lookup."; return }
            [PSCustomObject]@{ name = $ip.city; latitude = $ll[0]; longitude = $ll[1] }
        }
        if (-not $loc) { return }
        $lat = ([double]$loc.latitude).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $lon = ([double]$loc.longitude).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $wx = Invoke-RestMethod "https://api.open-meteo.com/v1/forecast?latitude=$lat&longitude=$lon&current=temperature_2m,weather_code" -TimeoutSec 5
        if (-not $wx -or -not $wx.current) { Write-Error "Weather API returned no data."; return }
        $temp = $wx.current.temperature_2m
        $unit = if ($wx.current_units -and $wx.current_units.temperature_2m) { $wx.current_units.temperature_2m } else { 'C' }
        Write-Host "$($loc.name): ${temp}${unit}" -ForegroundColor Cyan
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not fetch weather: $_"
    }
}

# Retrieve WiFi password for a given SSID or list all known WiFi profiles with their passwords. Uses netsh under the hood, so it only works on Windows and requires appropriate permissions to view passwords.
function wifipass {
    param([string]$SSID)
    try {
        if ($SSID) {
            $safeName = $SSID -replace '["\r\n`&|<>^;$(){}]', ''
            $output = netsh wlan show profile name="$safeName" key=clear 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Error "Profile '$safeName' not found."; return }
            $line = $output | Select-String 'Key Content'
            $parts = if ($line) { ($line -split ':', 2) } else { $null }
            if ($parts -and $parts.Count -gt 1) { Write-Host "$safeName : $($parts[1].Trim())" -ForegroundColor Green }
            else { Write-Host "$safeName : (no password stored)" -ForegroundColor Yellow }
        }
        else {
            $profiles = netsh wlan show profiles 2>&1 | Select-String 'All User Profile' | ForEach-Object {
                $p = ($_ -split ':', 2)
                if ($p.Count -gt 1) { $p[1].Trim() }
            } | Where-Object { $_ }
            foreach ($p in $profiles) {
                $p = $p -replace '["\r\n`&|<>^;$(){}]', ''
                $detail = netsh wlan show profile name="$p" key=clear 2>&1
                $key = $detail | Select-String 'Key Content'
                $keyParts = if ($key) { ($key -split ':', 2) } else { $null }
                $pass = if ($keyParts -and $keyParts.Count -gt 1) { $keyParts[1].Trim() } else { '(no password)' }
                Write-Host "${p} : $pass"
            }
        }
    }
    catch { Write-Error "Failed to query WiFi profiles: $_" }
}

# Open hosts file in preferred editor with admin rights. Uses Resolve-PreferredEditor to find the editor executable, and handles both GUI and terminal editors appropriately.
function hosts {
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $editor = Resolve-PreferredEditor
    $cmdInfo = Get-Command $editor -ErrorAction SilentlyContinue
    $editorPath = if ($cmdInfo -and $cmdInfo.Source) { $cmdInfo.Source } else { $editor }
    if ($cmdInfo -and $cmdInfo.CommandType -eq 'Application' -and $editorPath -match '\.(cmd|bat)$') {
        Start-Process cmd -Verb RunAs -WindowStyle Hidden -ArgumentList "/c `"$editorPath`" `"$hostsPath`""
    }
    else {
        Start-Process $editorPath $hostsPath -Verb RunAs
    }
}

# Simple download speed test by fetching a known file from Cloudflare's speed test endpoint and measuring the time taken. Provides a rough estimate of download speed in Mbps.
function speedtest {
    Write-Host "Testing download speed..." -ForegroundColor Cyan
    $url = "https://speed.cloudflare.com/__down?bytes=25000000"
    $start = Get-Date
    try {
        Invoke-RestMethod $url -TimeoutSec 30 -ErrorAction Stop | Out-Null
        $elapsed = [math]::Max(((Get-Date) - $start).TotalSeconds, 0.001)
        $mbps = [math]::Round((25 * 8) / $elapsed, 1)
        Write-Host "Download: ~${mbps} Mbps ($([math]::Round($elapsed, 1))s for 25 MB)" -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Speed test failed: $_"
    }
}

# Get size of a file or directory in a human-readable format. For directories, it sums the sizes of all contained files recursively. Handles errors gracefully and formats output with appropriate units.
function sizeof {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Error "Path not found: $Path"; return }
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $size = (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    }
    else {
        $size = $item.Length
    }
    if ($null -eq $size) { $size = 0 }
    if ($size -ge 1GB) { '{0:N2} GB' -f ($size / 1GB) }
    elseif ($size -ge 1MB) { '{0:N2} MB' -f ($size / 1MB) }
    elseif ($size -ge 1KB) { '{0:N2} KB' -f ($size / 1KB) }
    else { "$size bytes" }
}

# View recent system and application event logs with a simple command. By default, it shows the 20 most recent events from both System and Application logs, but you can adjust the count with the -Count parameter.
# The output includes timestamp, log name, level, event ID, and message, formatted in a readable table.
function eventlog {
    param([ValidateRange(1, 10000)][int]$Count = 20)
    Get-WinEvent -LogName System, Application -MaxEvents $Count -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated -Descending |
    Select-Object -First $Count TimeCreated, LogName, LevelDisplayName, Id, Message |
    Format-Table -AutoSize -Wrap
}

# SSH & Remote
if (Get-Command ssh -ErrorAction SilentlyContinue) {
    # Copy SSH public key to remote host (ssh-copy-id equivalent)
    function Copy-SshKey {
        param([Parameter(Mandatory)][string]$RemoteHost)
        $keyPath = if (Test-Path "$env:USERPROFILE\.ssh\id_ed25519.pub") { "$env:USERPROFILE\.ssh\id_ed25519.pub" }
        elseif (Test-Path "$env:USERPROFILE\.ssh\id_rsa.pub") { "$env:USERPROFILE\.ssh\id_rsa.pub" }
        else { $null }
        if (-not $keyPath) { Write-Error "No SSH public key found in $env:USERPROFILE\.ssh\"; return }
        $keyContent = Get-Content $keyPath -Raw
        if (-not $keyContent) { Write-Error "SSH key file is empty: $keyPath"; return }
        $key = $keyContent.Trim() -replace "`r", ''
        Write-Host "Copying $keyPath to $RemoteHost..." -ForegroundColor Cyan
        $key | ssh $RemoteHost "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
        if ($LASTEXITCODE -eq 0) { Write-Host "Key copied successfully." -ForegroundColor Green }
        else { Write-Error "Failed to copy key." }
    }
    Set-Alias -Name ssh-copy-key -Value Copy-SshKey

    # Generate a new SSH key pair with ed25519 algorithm. By default, it creates id_ed25519 in the user's .ssh directory, but you can specify a different name with the -Name parameter.
    # The function checks for existing keys to avoid overwriting and provides feedback on the generated key path.
    function keygen {
        param([string]$Name = 'id_ed25519')
        $keyPath = Join-Path "$env:USERPROFILE\.ssh" $Name
        ssh-keygen -t ed25519 -f $keyPath
    }
}

# Open Remote Desktop Connection to a specified computer. The computer name or IP address is required as a parameter. This function simply wraps the mstsc command for convenience.
function rdp {
    param([Parameter(Mandatory)][string]$Computer)
    mstsc "/v:$Computer"
}

# Developer Utilities
function killport {
    param([Parameter(Mandatory)][int]$Port)
    $connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if (-not $connections) { Write-Host "Nothing listening on port $Port." -ForegroundColor Yellow; return }
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    $killed = 0
    foreach ($procId in $pids) {
        if ($procId -eq 0 -or $procId -eq 4) {
            Write-Warning "Port $Port is owned by System (PID $procId) - skipping."
            continue
        }
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "Stopping $($proc.ProcessName) (PID $procId) on port $Port" -ForegroundColor Cyan
            try {
                Stop-Process -Id $procId -Force -ErrorAction Stop
                $killed++
            }
            catch { Write-Warning "Could not stop PID ${procId}: $_" }
        }
    }
    if ($killed -gt 0) { Write-Host "Port $Port freed." -ForegroundColor Green }
    else { Write-Warning "No processes were stopped on port $Port." }
}

# Make HTTP requests with flexible options for method, body, headers, and content type. By default, it performs a GET request and attempts to parse JSON responses for pretty output.
# It also handles binary responses gracefully and provides error details when requests fail.
function http {
    param(
        [Parameter(Mandatory)][string]$Url,
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD')]
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers
    )
    $params = @{
        Uri             = $Url
        Method          = $Method
        UseBasicParsing = $true
        TimeoutSec      = 30
        ErrorAction     = 'Stop'
    }
    if ($Body) { $params.Body = $Body; $params.ContentType = $ContentType }
    if ($Headers) { $params.Headers = $Headers }
    try {
        $response = Invoke-WebRequest @params
        $contentTypeHeader = [string]$response.Headers['Content-Type']
        if ($contentTypeHeader -and $contentTypeHeader -match 'octet-stream|image/|audio/|video/|application/zip|application/pdf') {
            Write-Host "Binary response ($contentTypeHeader), $($response.RawContentLength) bytes" -ForegroundColor Yellow
        }
        elseif ($contentTypeHeader -and $contentTypeHeader -match 'json') {
            $response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        else {
            $response.Content
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            Write-Host "$status $($_.Exception.Response.StatusCode)" -ForegroundColor Red
            # PS7 uses HttpResponseMessage (no GetResponseStream); PS5 uses HttpWebResponse
            if ($_.ErrorDetails.Message) {
                $_.ErrorDetails.Message
            }
            elseif ($_.Exception.Response | Get-Member -Name GetResponseStream -ErrorAction SilentlyContinue) {
                $reader = $null
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $reader.ReadToEnd()
                }
                catch { Write-Error "HTTP error (could not read response body)" }
                finally { if ($reader) { $reader.Dispose() } }
            }
        }
        else { Write-Error $_ }
    }
}

# Pretty-print JSON from a file or pipeline input. If a file path is provided, it reads and formats the JSON content. If JSON is piped in, it formats that instead.
# It handles errors gracefully and provides usage hints when no input is given.
function prettyjson {
    param(
        [Parameter(Position = 0)]
        [string]$File
    )
    try {
        $jsonInput = @($input)
        if ($jsonInput.Count -gt 0) {
            ($jsonInput -join "`n") | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        elseif ($File) {
            if (-not (Test-Path -LiteralPath $File)) { Write-Error "File not found: $File"; return }
            Get-Content -LiteralPath $File -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        else { Write-Error 'Usage: prettyjson <file> or <pipeline> | prettyjson' }
    }
    catch { Write-Error "Invalid JSON: $_" }
}

# JWT decode (strips Bearer prefix, decodes header + payload without verification)
function jwtd {
    param([Parameter(Mandatory)][string]$Token)
    $Token = $Token -replace '^Bearer\s+', ''
    $parts = $Token -split '\.'
    if ($parts.Count -lt 2) { Write-Error "Invalid JWT: expected at least 2 dot-separated parts"; return }
    foreach ($i in 0, 1) {
        $label = if ($i -eq 0) { 'Header' } else { 'Payload' }
        $b64 = $parts[$i].Replace('-', '+').Replace('_', '/')
        $mod = $b64.Length % 4
        if ($mod -eq 2) { $b64 += '==' }
        elseif ($mod -eq 3) { $b64 += '=' }
        try {
            $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            Write-Host "${label}:" -ForegroundColor Cyan
            $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        catch { Write-Error "Failed to decode ${label}: $_" }
    }
}

# Unix timestamp converter (no args = now, number = epoch to date, date string = date to epoch)
function epoch {
    param([string]$Value)
    $unixEpoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    if (-not $Value) {
        [int64]([DateTime]::UtcNow - $unixEpoch).TotalSeconds
        return
    }
    $num = [int64]0
    if ([int64]::TryParse($Value, [ref]$num)) {
        $secs = if ($num -gt 1000000000000) { [int64]($num / 1000) } else { $num }
        $unixEpoch.AddSeconds($secs).ToLocalTime()
    }
    else {
        try {
            $date = [DateTime]::Parse($Value)
            [int64]($date.ToUniversalTime() - $unixEpoch).TotalSeconds
        }
        catch { Write-Error "Could not parse: $Value" }
    }
}

# Generate UUID/GUID and copy to clipboard
function uuid {
    $id = [guid]::NewGuid().ToString()
    Set-Clipboard $id
    Write-Host "$id (copied)" -ForegroundColor Green
}

# URL encode / decode
function urlencode {
    param([Parameter(Mandatory)][string]$Text)
    [System.Uri]::EscapeDataString($Text)
}
# Decode URL-encoded string
function urldecode {
    param([Parameter(Mandatory)][string]$Text)
    [System.Uri]::UnescapeDataString($Text)
}

# Measure execution time of a scriptblock
function timer {
    param([Parameter(Mandatory)][scriptblock]$Command)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Command
    $sw.Stop()
    Write-Host ('Elapsed: {0:N3}s' -f $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
}

# Search/list environment variables
function env {
    param([string]$Pattern)
    $vars = Get-ChildItem env: | Sort-Object Name
    if ($Pattern) { $vars = $vars | Where-Object { $_.Name -match $Pattern -or $_.Value -match $Pattern } }
    $vars | Format-Table Name, Value -AutoSize -Wrap
}

# Check TLS certificate expiry and details for a domain
function tlscert {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$Port = 443
    )
    $tcp = $null; $ssl = $null; $cert = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Domain, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
            throw "Connection to ${Domain}:${Port} timed out after 5 seconds"
        }
        $tcp.EndConnect($async)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 10000
        $stream.WriteTimeout = 10000
        $ssl = New-Object System.Net.Security.SslStream($stream, $false, { $true })
        $ssl.AuthenticateAsClient($Domain)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $daysLeft = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $color = if ($daysLeft -lt 30) { 'Red' } elseif ($daysLeft -lt 90) { 'Yellow' } else { 'Green' }
        Write-Host "  Subject:     $($cert.Subject)" -ForegroundColor White
        Write-Host "  Issuer:      $($cert.Issuer)" -ForegroundColor White
        Write-Host "  Valid from:  $($cert.NotBefore)" -ForegroundColor White
        Write-Host "  Expires:     $($cert.NotAfter)" -ForegroundColor White
        Write-Host "  Days left:   $daysLeft" -ForegroundColor $color
        Write-Host "  Thumbprint:  $($cert.Thumbprint)" -ForegroundColor DarkGray
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to check certificate for ${Domain}:${Port} - $_"
    }
    finally {
        if ($cert) { $cert.Dispose() }
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

# Quick TCP port scan
function portscan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [int[]]$Ports = @(21, 22, 25, 53, 80, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017)
    )
    Write-Host "Scanning $Hostname..." -ForegroundColor Cyan
    $open = 0
    foreach ($port in $Ports) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $tcp.BeginConnect($Hostname, $port, $null, $null)
            $connected = $async.AsyncWaitHandle.WaitOne(500) -and $tcp.Connected
            try { $tcp.EndConnect($async) }
            catch { if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }; $null = $_ }
            if ($connected) {
                Write-Host ("  {0,-6} open" -f $port) -ForegroundColor Green
                $open++
            }
        }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Verbose "Port $port closed or filtered"
        }
        finally { $tcp.Dispose() }
    }
    if ($open -eq 0) { Write-Host "  No open ports found." -ForegroundColor Yellow }
    Write-Host ("Scan complete ({0}/{1} open)." -f $open, $Ports.Count) -ForegroundColor Cyan
}

# IP geolocation lookup (no args = your public IP)
function ipinfo {
    param([string]$IpAddress)
    $url = if ($IpAddress) { "http://ip-api.com/json/$IpAddress" } else { "http://ip-api.com/json/" }
    try {
        $info = Invoke-RestMethod -Uri $url -TimeoutSec 10
        if (-not $info) { Write-Error "IP lookup returned no data."; return }
        if ($info.status -eq 'fail') { Write-Error "Lookup failed: $($info.message)"; return }
        Write-Host "  IP:       $($info.query)" -ForegroundColor White
        Write-Host "  Location: $($info.city), $($info.regionName), $($info.country)" -ForegroundColor White
        Write-Host "  ISP:      $($info.isp)" -ForegroundColor White
        Write-Host "  Org:      $($info.org)" -ForegroundColor DarkGray
        Write-Host "  AS:       $($info.as)" -ForegroundColor DarkGray
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to lookup IP info: $_"
    }
}

# Quick timestamped backup of a file
function bak {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Error "File not found: $Path"; return }
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $dest = "$Path.$timestamp.bak"
    Copy-Item -LiteralPath $Path -Destination $dest -Force
    Write-Host "Backup: $dest" -ForegroundColor Green
}

# Repeat a command at intervals (like Linux watch)
function watch {
    param(
        [Parameter(Mandatory)][scriptblock]$Command,
        [int]$Interval = 2
    )
    Write-Host "Every ${Interval}s. Ctrl+C to stop." -ForegroundColor DarkGray
    while ($true) {
        Clear-Host
        Write-Host ("watch: every {0}s | {1}" -f $Interval, (Get-Date -Format "HH:mm:ss")) -ForegroundColor DarkGray
        Write-Host ""
        try { & $Command }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        try { Start-Sleep -Seconds $Interval }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        }
    }
}

# WHOIS domain lookup via RDAP (IANA standard, no external tools needed)
function whois {
    param([Parameter(Mandatory)][string]$Domain)
    $Domain = $Domain -replace '^https?://', '' -replace '/.*$', ''
    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$Domain" -TimeoutSec 10
        Write-Host "  Domain:     $($rdap.ldhName)" -ForegroundColor White
        Write-Host "  Status:     $(@($rdap.status) -join ', ')" -ForegroundColor White
        if ($rdap.entities) {
            $registrar = $rdap.entities | Where-Object { $_.roles -contains 'registrar' } | Select-Object -First 1
            if ($registrar -and $registrar.vcardArray -and @($registrar.vcardArray).Count -gt 1) {
                $fn = $registrar.vcardArray[1] | Where-Object { $_ -and $_[0] -eq 'fn' } | ForEach-Object { $_[3] }
                if ($fn) { Write-Host "  Registrar:  $fn" -ForegroundColor White }
            }
        }
        foreach ($ev in @($rdap.events)) {
            if (-not $ev) { continue }
            $label = switch ($ev.eventAction) {
                'registration' { 'Registered' }
                'expiration' { 'Expires' }
                'last changed' { 'Updated' }
                default { $ev.eventAction }
            }
            if ($label) {
                $date = ([DateTime]$ev.eventDate).ToString('yyyy-MM-dd')
                Write-Host "  ${label}:$((' ' * [math]::Max(1, 12 - $label.Length)))$date" -ForegroundColor White
            }
        }
        if ($rdap.nameservers) {
            $ns = ($rdap.nameservers | ForEach-Object { $_.ldhName }) -join ', '
            Write-Host "  Nameservers: $ns" -ForegroundColor DarkGray
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
            Write-Error "Domain not found: $Domain"
        }
        else { Write-Error "WHOIS lookup failed: $_" }
    }
}

# Clipboard Utilities
function cpy { if (-not $args) { Write-Error "Usage: cpy <text>"; return }; Set-Clipboard ($args -join ' ') }
# Paste from clipboard
function pst { Get-Clipboard }

# Safely insert clipboard text into the prompt buffer (never executes directly)
function Invoke-Clipboard {
    $clipboardText = Get-Clipboard -Raw
    if ([string]::IsNullOrWhiteSpace($clipboardText)) {
        Write-Host "Clipboard is empty." -ForegroundColor Yellow
        return
    }

    # Never execute clipboard contents. Insert into prompt buffer when available.
    try {
        if ($isInteractive -and (Get-Module PSReadLine -ErrorAction SilentlyContinue)) {
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert($clipboardText)
            return
        }
    }
    catch {
        Write-Warning "Could not insert clipboard into prompt buffer: $_"
    }

    Write-Output $clipboardText
}
Set-Alias -Name icb -Value Invoke-Clipboard

# Enhanced PSReadLine Configuration
$PSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    Colors                        = @{
        Command   = '#61AFEF'  # Blue
        Parameter = '#98C379'  # Green
        Operator  = '#56B6C2'  # Cyan
        Variable  = '#E5C07B'  # Yellow
        String    = '#98C379'  # Green
        Number    = '#D19A66'  # Orange
        Type      = '#61AFEF'  # Blue
        Comment   = '#5C6370'  # Gray
        Keyword   = '#C678DD'  # Soft purple
        Error     = '#E06C75'  # Red
    }
    BellStyle                     = 'None'
}
Set-PSReadLineOption @PSReadLineOptions

# PSReadLine features that require an interactive console host
if ($isInteractive -and (Get-Module PSReadLine)) {
    # Core-only prediction settings (PredictionSource/PredictionViewStyle don't exist on Desktop)
    # Guard against hosts without VT support (e.g. agent terminals, redirected output)
    if ($PSVersionTable.PSEdition -eq "Core") {
        $supportsPrediction = $false
        try {
            $supportsPrediction = [bool]$Host.UI.SupportsVirtualTerminal -and -not [Console]::IsOutputRedirected
        }
        catch {
            $supportsPrediction = $false
        }

        if ($supportsPrediction) {
            try {
                Set-PSReadLineOption -PredictionSource HistoryAndPlugin -ErrorAction Stop
                Set-PSReadLineOption -PredictionViewStyle ListView -ErrorAction Stop
            }
            catch {
                Write-Verbose "PSReadLine prediction unavailable: $_"
            }
        }
    }
    Set-PSReadLineOption -MaximumHistoryCount 10000

    # Custom key handlers
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
    Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
    Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
    Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
    Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo
    $smartPasteHandler = {
        try { Invoke-Clipboard }
        catch { [Microsoft.PowerShell.PSConsoleReadLine]::Ding() }
    }
    Set-PSReadLineKeyHandler -Chord 'Alt+v' -BriefDescription SmartPaste -Description 'Paste clipboard as one block into prompt' -ScriptBlock $smartPasteHandler

    # fzf integration via PSFzf (fuzzy history search on Ctrl+R, file finder on Ctrl+T)
    if (Get-Command fzf -ErrorAction SilentlyContinue) {
        if (-not $env:FZF_DEFAULT_COMMAND -and (Get-Command rg -ErrorAction SilentlyContinue)) {
            $env:FZF_DEFAULT_COMMAND = 'rg --files --hidden --glob "!.git"'
        }
        if (-not $env:FZF_DEFAULT_OPTS) {
            $env:FZF_DEFAULT_OPTS = '--height=40% --layout=reverse'
        }
        if (Get-Module -ListAvailable -Name PSFzf) {
            Import-Module PSFzf -ErrorAction SilentlyContinue
            if (Get-Module PSFzf) {
                Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
            }
        }
    }

    # Filter sensitive commands from history
    Set-PSReadLineOption -AddToHistoryHandler {
        param($line)
        $sensitive = @('password', 'secret', 'token', 'api[_-]?key', 'connectionstring', 'credential', 'bearer')
        $hasSensitive = $sensitive | Where-Object { $line -match $_ }
        return ($null -eq $hasSensitive)
    }
}

# Custom completion for common commands
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $customCompletions = @{
        'git'  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        'npm'  = @('install', 'start', 'run', 'test', 'build')
        'deno' = @('run', 'compile', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }

    if (-not $commandAst.CommandElements -or $commandAst.CommandElements.Count -eq 0) { return }
    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock

# dotnet completion (only if dotnet is installed)
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $dotnetScriptblock = {
        param($wordToComplete, $commandAst, $cursorPosition)
        dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $dotnetScriptblock
}

# Oh My Posh initialization (interactive only; render with explicit --config every prompt)
if ($isInteractive) {
    $ompExecutablePath = Get-OhMyPoshExecutablePath
    if ($ompExecutablePath) {
        # Read the selected theme from cached config; user-settings.json can override the theme name.
        $profileConfigPath = Join-Path $cacheDir "theme.json"
        $themeName = $null
        if (Test-Path $profileConfigPath) {
            try {
                $cfg = Get-Content $profileConfigPath -Raw | ConvertFrom-Json
                if ($cfg -and $cfg.theme -and $cfg.theme.name) { $themeName = $cfg.theme.name }
            }
            catch { Write-Verbose "Failed to parse theme.json: $_" }
        }

        $userSettingsStartup = Join-Path $cacheDir "user-settings.json"
        if (Test-Path $userSettingsStartup) {
            try {
                $userCfg = Get-Content $userSettingsStartup -Raw | ConvertFrom-Json
                if ($userCfg -and $userCfg.theme -and $userCfg.theme.name) { $themeName = $userCfg.theme.name }
            }
            catch { Write-Verbose "Failed to parse user-settings.json: $_" }
        }

        if (-not $themeName) {
            Write-Warning "No cached OMP theme is configured. Run Update-Profile or setup.ps1 to restore theme.json."
        }

        $localThemePath = if ($themeName) { Join-Path $cacheDir "$themeName.omp.json" } else { $null }
        if ($localThemePath -and -not (Test-Path $localThemePath)) {
            # Only recover from local legacy paths at startup. We intentionally avoid network/theme downloads here.
            $oldThemePath = Join-Path (Split-Path $PROFILE) "$themeName.omp.json"
            if (Test-Path $oldThemePath) {
                try { Move-Item $oldThemePath $localThemePath -Force -ErrorAction Stop }
                catch { Write-Warning "Could not migrate theme from Documents: $_" }
            }
        }

        if ($localThemePath -and (Test-Path $localThemePath)) {
            try {
                $themeContent = Get-Content $localThemePath -Raw -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($themeContent)) { throw 'Theme file is empty' }
                $null = $themeContent | ConvertFrom-Json
            }
            catch {
                Write-Warning "Configured OMP theme is invalid at '$localThemePath': $_"
                $localThemePath = $null
            }
        }

        if ($localThemePath -and (Test-Path $localThemePath)) {
            try {
                $null = Get-Content $localThemePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                # Explicit render mode avoids oh-my-posh's internal config/session cache silently
                # dropping back to the built-in default theme on some WindowsApps/MSIX installs.
                $script:OhMyPoshExecutablePath = $ompExecutablePath
                $script:OhMyPoshConfigPath = $localThemePath
                $script:OhMyPoshLastHistoryId = $null
                $env:VIRTUAL_ENV_DISABLE_PROMPT = 1
                $env:PYENV_VIRTUALENV_DISABLE_PROMPT = 1
                $env:POWERLINE_COMMAND = 'oh-my-posh'
                $env:POSH_SHELL = 'pwsh'
                $env:POSH_SHELL_VERSION = $PSVersionTable.PSVersion.ToString()
                $env:CONDA_PROMPT_MODIFIER = $false

                try {
                    if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
                        $secondaryPrompt = Get-OhMyPoshPromptText `
                            -Type 'secondary' `
                            -ExecutablePath $script:OhMyPoshExecutablePath `
                            -ConfigPath $script:OhMyPoshConfigPath
                        if (-not [string]::IsNullOrWhiteSpace($secondaryPrompt)) {
                            Set-PSReadLineOption -ContinuationPrompt ($secondaryPrompt -join "`n")
                        }
                    }
                }
                catch {
                    Write-Verbose "Failed to set oh-my-posh continuation prompt: $_"
                }

                $Function:prompt = {
                    $originalSuccess = $?
                    $originalLastExitCode = $global:LASTEXITCODE
                    try {
                        $output = Get-OhMyPoshPromptText `
                            -Type 'primary' `
                            -ExecutablePath $script:OhMyPoshExecutablePath `
                            -ConfigPath $script:OhMyPoshConfigPath `
                            -OriginalSuccess:$originalSuccess `
                            -OriginalLastExitCode $originalLastExitCode

                        if ([string]::IsNullOrWhiteSpace($output)) {
                            return & $script:FallbackPromptFunction
                        }

                        try {
                            if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
                                Set-PSReadLineOption -ExtraPromptLineCount (($output | Measure-Object -Line).Lines - 1)
                            }
                        }
                        catch {
                            Write-Verbose "Failed to update PSReadLine prompt line count: $_"
                        }

                        return ($output -join "`n")
                    }
                    catch {
                        Write-Warning "Failed to render oh-my-posh prompt with '$($script:OhMyPoshConfigPath)': $_"
                        return & $script:FallbackPromptFunction
                    }
                    finally {
                        $global:LASTEXITCODE = $originalLastExitCode
                    }
                }
            }
            catch {
                Write-Warning "Failed to initialize oh-my-posh with '$localThemePath': $_"
            }
        }
        elseif ($themeName) {
            Write-Warning "Configured OMP theme '$themeName' was not found locally at '$localThemePath'. Run Update-Profile or setup.ps1 to restore it."
        }
    }
    else {
        Write-Warning "oh-my-posh not found. Install the MSI build or use: winget install JanDeDobbeleer.OhMyPosh"
    }
}

# zoxide initialization (interactive only, cached for fast startup)
if ($isInteractive) {
    $zoxideExecutablePath = Get-ExternalCommandPath -CommandName 'zoxide'
    if ($zoxideExecutablePath) {
        $zoxideCachePath = Join-Path $cacheDir "zoxide-init.ps1"
        # PERF: Defer version/init until cache is missing/stale; use timeout to avoid hangs.
        # When cache exists and is non-empty, trust it (Update-Tools deletes cache on upgrade).
        $cacheValid = $false
        if (Test-Path $zoxideCachePath) {
            try {
                $fileSize = (Get-Item $zoxideCachePath).Length
                if ($fileSize -gt 0) {
                    $cacheContent = Get-Content $zoxideCachePath -First 1 -ErrorAction Stop
                    if ($cacheContent -match '^# ZOXIDE_CACHE_VERSION: .+') { $cacheValid = $true }
                }
            }
            catch { Write-Verbose "Zoxide cache read failed (will regenerate)." }
            if (-not $cacheValid) { Remove-Item $zoxideCachePath -Force -ErrorAction SilentlyContinue }
        }
        if (-not $cacheValid) {
            $zoxideVersionResult = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath --version 2>$null | Out-String).Trim()
            } -ArgumentList @($zoxideExecutablePath) -TimeoutSec 5
            $zoxideVersion = if ($zoxideVersionResult) { $zoxideVersionResult } else { 'unknown' }
            $initScript = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath init --cmd z powershell | Out-String)
            } -ArgumentList @($zoxideExecutablePath) -TimeoutSec 10
            if ($initScript) {
                $zoxideInitStr = @($initScript) -join "`n"
                $zoxideHeader = "# ZOXIDE_CACHE_VERSION: $zoxideVersion"
                $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($zoxideCachePath, ($zoxideHeader + "`n" + $zoxideInitStr), $utf8NoBom)
            }
            else {
                Write-Warning "zoxide init timed out or produced no output. Cache not written."
            }
        }
        try {
            . $zoxideCachePath
        }
        catch {
            Remove-Item $zoxideCachePath -Force -ErrorAction SilentlyContinue
            $zoxideVersionResult = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath --version 2>$null | Out-String).Trim()
            } -ArgumentList @($zoxideExecutablePath) -TimeoutSec 5
            $zoxideVersion = if ($zoxideVersionResult) { $zoxideVersionResult } else { 'unknown' }
            $initScript = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath init --cmd z powershell | Out-String)
            } -ArgumentList @($zoxideExecutablePath) -TimeoutSec 10
            if ($initScript) {
                $zoxideInitStr = @($initScript) -join "`n"
                $zoxideHeader = "# ZOXIDE_CACHE_VERSION: $zoxideVersion"
                $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($zoxideCachePath, ($zoxideHeader + "`n" + $zoxideInitStr), $utf8NoBom)
                try { . $zoxideCachePath } catch { Write-Warning "Failed to initialize zoxide: $_" }
            }
            else {
                Write-Warning "Failed to initialize zoxide: $_"
            }
        }
    }
    else {
        Write-Warning "zoxide not found. Install it with: winget install ajeetdsouza.zoxide"
    }
}

# Help Function (PS5-compatible - $PSStyle only exists in PS7.2+)
function Show-Help {
    if ($null -ne $PSStyle) {
        $c = $PSStyle.Foreground.Cyan; $g = $PSStyle.Foreground.Green
        $y = $PSStyle.Foreground.Yellow; $m = $PSStyle.Foreground.Magenta; $r = $PSStyle.Reset
    }
    else {
        $c = ""; $g = ""; $y = ""; $m = ""; $r = ""
    }
    $helpText = @"
${c}PowerShell Profile Help${r}
${y}=======================${r}

${c}Profile & Updates${r}
${g}Edit-Profile${r} / ${g}ep${r} - Open profile in preferred editor.
${g}edit${r} <file> - Open file in preferred editor.
${g}Update-Profile${r} - Sync profile, theme, caches, and WT settings. Use -Force to re-apply.
${g}Update-PowerShell${r} - Check for new PowerShell releases.
${g}Update-Tools${r} - Update winget-managed tools; direct/MSI Oh My Posh installs are preserved.
${g}Show-Help${r} - Show this help message.
${g}reload${r} - Reload the PowerShell profile.
${g}Clear-ProfileCache${r} - Reset profile caches plus OMP internal caches.
${g}Clear-Cache${r} [-IncludeSystemCaches] - Clear user/system temp caches.
${g}Uninstall-Profile${r} - Remove profile, caches, and WT changes. Use -All for everything, -HardResetWindowsTerminal to reset WT to defaults.

${c}Git${r}
${g}gs${r} - git status.  ${g}ga${r} - git add .  ${g}gc${r} <msg> - git commit -m.
${g}gpush${r} / ${g}gpull${r} - git push / pull.  ${g}gcl${r} <repo> - git clone.
${g}gcom${r} <msg> - add + commit.  ${g}lazyg${r} <msg> - add + commit + push.
${g}g${r} - zoxide jump to github dir.

${c}Files & Navigation${r}
${g}ls${r} / ${g}la${r} / ${g}ll${r} / ${g}lt${r} - eza listings (icons, hidden, long+git, tree).
${g}cat${r} <file> - Syntax-highlighted viewer (bat).
${g}ff${r} <name> - Find files recursively.  ${g}nf${r} <name> - Create new file.
${g}mkcd${r} <dir> - Create dir and cd into it.
${g}touch${r} <file> - Create file or update timestamp.
${g}trash${r} <path> - Move to Recycle Bin.
${g}extract${r} <file> - Universal extractor (.zip, .tar, .gz, .7z, .rar).
${g}file${r} <path> - Identify file type via magic bytes (like Linux file command).
${g}sizeof${r} <path> - Human-readable file/directory size.
${g}docs${r} / ${g}dtop${r} - Jump to Documents / Desktop.

${c}Unix-like${r}
${g}grep${r} <regex> [dir] - Search for pattern in files (uses ripgrep when available).
${g}head${r} <path> [n] / ${g}tail${r} <path> [n] [-f] - First/last n lines.
${g}sed${r} <file> <find> <replace> - Find and replace in file.
${g}which${r} <cmd> - Show command path.
${g}pkill${r} / ${g}pgrep${r} <name> - Kill / list processes by name.
${g}export${r} <name> <value> - Set environment variable.

${c}System & Network${r}
${g}admin${r} / ${g}su${r} - Open elevated terminal.
${g}pubip${r} - Public IP.  ${g}localip${r} - Local IPv4 addresses.
${g}uptime${r} - System uptime.  ${g}sysinfo${r} - Detailed system info.
${g}df${r} - Disk volumes.  ${g}flushdns${r} - Clear DNS cache.
${g}ports${r} - Listening TCP ports.  ${g}checkport${r} <host> <port> - Test TCP connectivity.
${g}portscan${r} <host> [-Ports n,n,...] - Quick TCP port scan.
${g}tlscert${r} <domain> [port] - Check TLS certificate expiry and details.
${g}ipinfo${r} [ip] - IP geolocation lookup (no args = your IP).
${g}whois${r} <domain> - WHOIS domain lookup (registrar, dates, nameservers).
${g}nslook${r} <domain> [type] - DNS lookup (A, MX, TXT, etc.).
${g}env${r} [pattern] - Search/list environment variables.
${g}svc${r} [name] [-Count n] [-Live] - htop-like process viewer.
${g}eventlog${r} [n] - Last n event log entries (default 20).
${g}path${r} - Display PATH entries one per line.
${g}weather${r} [city] - Quick weather lookup.
${g}speedtest${r} - Download speed test.
${g}wifipass${r} [ssid] - Show saved WiFi passwords.
${g}hosts${r} - Open hosts file in elevated editor.
${g}winutil${r} - Launch Chris Titus WinUtil.
${g}harden${r} - Open Harden Windows Security.

${c}Security & Crypto${r}
${g}hash${r} <file> [algo] - File hash (default SHA256).
${g}checksum${r} <file> <expected> - Verify file hash.
${g}genpass${r} [length] - Random password (default 20), copies to clipboard.
${g}b64${r} / ${g}b64d${r} <text> - Base64 encode / decode.
${g}jwtd${r} <token> - Decode JWT header and payload.
${g}uuid${r} - Generate random UUID (copies to clipboard).
${g}epoch${r} [value] - Unix timestamp converter (no args = now).
${g}urlencode${r} / ${g}urldecode${r} <text> - URL encode / decode.
${g}vtscan${r} <file> - Quick VirusTotal scan + open in browser. Uses ${g}`$env:VTCLI_APIKEY${r} or ${g}vt init${r}.
${g}vt${r} <subcommand> - Full VirusTotal CLI (vt-cli). Run ${g}vt --help${r} for details.

${c}Developer${r}
${g}killport${r} <port> - Kill process on a TCP port.
${g}http${r} <url> [-Method POST] [-Body '...'] - HTTP requests, auto-formats JSON.
${g}prettyjson${r} <file> - Pretty-print JSON (or pipe: ${g}cat data.json | prettyjson${r}).
${g}hb${r} <file> - Upload to hastebin, copy URL.
${g}timer${r} { command } - Measure execution time.
${g}watch${r} { command } [-Interval n] - Repeat command every n seconds (default 2).
${g}bak${r} <file> - Quick timestamped backup.

${c}Docker${r} (when installed)
${g}dps${r} / ${g}dpa${r} - Running / all containers.  ${g}dimg${r} - Images.
${g}dlogs${r} <container> - Follow logs.  ${g}dex${r} <container> [shell] - Exec into container.
${g}dstop${r} - Stop all.  ${g}dprune${r} - System prune.

${c}SSH & Remote${r} (ssh/keygen when installed)
${g}Copy-SshKey${r} / ${g}ssh-copy-key${r} <user@host> - Copy SSH key to remote.
${g}keygen${r} [name] - Generate ED25519 key pair.
${g}rdp${r} <host> - Launch RDP session.

${c}Clipboard${r}
${g}cpy${r} <text> - Copy to clipboard.  ${g}pst${r} - Paste from clipboard.
${g}icb${r} - Insert clipboard into prompt (never executes).

${c}Keybindings${r}
${g}Ctrl+R${r} - Fuzzy history search (fzf).  ${g}Ctrl+T${r} - Fuzzy file finder (fzf).
${g}Alt+V${r} - Smart paste into prompt.

Edit '${m}profile_user.ps1${r}' in your profile directory for customizations that survive updates.
"@
    Write-Host $helpText
}

# User overrides (survives Update-Profile)
$userProfile = Join-Path (Split-Path $PROFILE) "profile_user.ps1"
if (Test-Path $userProfile) {
    try { . $userProfile }
    catch { Write-Warning "Failed to load profile_user.ps1: $_" }
}

# Startup complete - show load time
$profileStopwatch.Stop()
if ($isInteractive) {
    Write-Host "Profile loaded in $($profileStopwatch.ElapsedMilliseconds)ms." -ForegroundColor DarkGray
    Write-Host "Use 'Show-Help' to display help" -ForegroundColor Yellow
}
