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

# Admin check (used by prompt suffix, firewall helpers, Get-SystemInfo, Invoke-ProfileWizard).
# A profile must not silently mutate machine-scope env vars; telemetry opt-out is handled by
# setup.ps1 with explicit user consent. Uninstall-Profile Phase 6 still cleans up legacy values.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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

# Extensibility core. $PSP is the public namespace plugins, profile_user.ps1, and user-settings.json extend.
# Hooks: OnProfileLoad fires once after all load steps; PrePrompt fires before every prompt; OnCd fires when $pwd changes.
# Features: toggles heavy/optional behavior. Commands: registry consumed by Get-ProfileCommand and Show-Help.
$script:PSP = @{
    Hooks        = @{
        OnProfileLoad = [System.Collections.Generic.List[scriptblock]]::new()
        PrePrompt     = [System.Collections.Generic.List[scriptblock]]::new()
        OnCd          = [System.Collections.Generic.List[scriptblock]]::new()
    }
    HelpSections = [System.Collections.Generic.List[object]]::new()
    Commands     = [System.Collections.Generic.List[object]]::new()
    Features     = @{
        psfzf            = $true
        predictions      = $true
        startupMessage   = $true
        perDirProfiles   = $true
        # transientPrompt collapses the previous prompt to a minimal form on Enter (p10k-style).
        # Requires a console host and PSReadLine; no-op in CI/non-interactive.
        transientPrompt  = $false
        # commandOverrides is a code-execution surface (JSON strings compiled to scriptblocks).
        # Default off so a user-settings.json edit cannot silently redefine commands; users must
        # opt in explicitly by setting features.commandOverrides = true.
        commandOverrides = $false
        # updateCheck hits the GitHub commits API at most once every 7 days (cached timestamp)
        # to notify when main has advanced past the applied version. Default off so users
        # running `irm | iex` inside scripts don't trigger a surprise network call per shell.
        updateCheck      = $false
    }
    # Scriptblock that returns the collapsed prompt string used when features.transientPrompt
    # is enabled. Override in profile_user.ps1 to customize. Return value is printed verbatim.
    TransientPrompt = { "$ " }
    TrustedDirs  = [System.Collections.Generic.List[string]]::new()
    LastPwd      = $null
    # Directory history stack - populated by Invoke-PromptStage on cd. Most-recent first.
    PwdHistory   = [System.Collections.Generic.List[string]]::new()
    PwdHistoryMax = 20
    # When set to $true, the next Invoke-PromptStage call skips pushing LastPwd onto
    # PwdHistory. Used by cdb so a stack-pop navigation does not re-push the directory
    # being consumed (which would create back-and-forth history loops on repeat cdb).
    SuppressPwdHistoryPush = $false
    # Tab-title base (without context prefix). Set at profile load; used by the PrePrompt
    # hook that prepends venv/aws/k8s/jobs indicators.
    BaseTitle    = $null
}

# Fire all scriptblocks registered for a hook event. Errors are isolated per hook.
function Invoke-ProfileHook {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('OnProfileLoad', 'PrePrompt', 'OnCd')][string]$EventName)
    if (-not $script:PSP -or -not $script:PSP.Hooks.ContainsKey($EventName)) { return }
    foreach ($h in $script:PSP.Hooks[$EventName]) {
        try { & $h }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning "Hook '$EventName' failed: $($_.Exception.Message)"
        }
    }
}

# Register a scriptblock to run on a profile lifecycle event (OnProfileLoad | PrePrompt | OnCd).
function Register-ProfileHook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OnProfileLoad', 'PrePrompt', 'OnCd')][string]$EventName,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $script:PSP.Hooks[$EventName].Add($Action)
}

# Add a section to Show-Help output. Use from plugins or profile_user.ps1 to advertise custom commands.
function Register-HelpSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Lines
    )
    $script:PSP.HelpSections.Add([PSCustomObject]@{ Title = $Title; Lines = $Lines })
}

# Add a command to the discovery registry consumed by Get-ProfileCommand.
function Register-ProfileCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [string]$Synopsis = ''
    )
    $script:PSP.Commands.Add([PSCustomObject]@{ Name = $Name; Category = $Category; Synopsis = $Synopsis })
}

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
            Invoke-RestMethod -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) {
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
                throw 'Downloaded file is missing or empty'
            }
            return
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                Write-Host "  Download failed (attempt $attempt/$MaxAttempts): $_  Retrying in ${BackoffSec}s..." -ForegroundColor Yellow
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

    if ($cmd.CommandType -eq 'Alias' -and $cmd.Definition -and $cmd.Definition -ne $CommandName) {
        return Get-ExternalCommandPath -CommandName $cmd.Definition
    }

    $pathCandidates = @($cmd.Path, $cmd.Source, $cmd.Definition) |
    Where-Object { $_ -and [System.IO.Path]::IsPathRooted([string]$_) } |
    Select-Object -Unique
    foreach ($pathCandidate in $pathCandidates) {
        if (Test-Path -LiteralPath $pathCandidate -PathType Leaf) {
            return $pathCandidate
        }
    }

    return $null
}

# Tab-title helpers used by long-running wrappers (ssh/dex/dlogs/serve/watch/journal -Follow)
# to make it obvious what each tab is doing. Push returns the prior title so Pop can restore
# it; both are silent on terminals that don't support title setting. LIFO-safe (nest freely).
function Push-TabTitle {
    param([Parameter(Mandatory)][string]$Title)
    $old = $null
    try { $old = $Host.UI.RawUI.WindowTitle } catch { $null = $_ }
    try { $Host.UI.RawUI.WindowTitle = $Title } catch { $null = $_ }
    return $old
}

function Pop-TabTitle {
    param([AllowNull()][string]$OldTitle)
    if ($null -eq $OldTitle) { return }
    try { $Host.UI.RawUI.WindowTitle = $OldTitle } catch { $null = $_ }
}

# Resolve the active Windows Terminal settings.json across install variants: Store, Preview,
# Canary, and unpackaged (GitHub zip). Returns the first existing path, or $null if WT is not
# installed. Callers that WRITE settings should use Get-WindowsTerminalSettingsPaths (plural)
# instead so all installed variants stay in sync; the singular helper is kept for single-variant
# reads (e.g. Uninstall-Profile restore picks the most-precedence variant's backup).
function Get-WindowsTerminalSettingsPath {
    $candidates = @(
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

# Resolve ALL existing Windows Terminal settings.json files across installed variants so writers
# can update every one a user has. Returns an array (possibly empty). Fixes the "wrote to Stable
# but Preview was the active terminal" class of bugs.
function Get-WindowsTerminalSettingsPaths {
    $candidates = @(
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json'
    )
    @($candidates | Where-Object { Test-Path -LiteralPath $_ })
}

# Merge PSCustomObject overrides recursively so nested user/theme/terminal keys are preserved.
function Merge-JsonObject {
    param(
        $base,
        $override
    )

    if ($null -eq $override) { return }
    if ($null -eq $base) { throw 'Merge-JsonObject: $base cannot be null (caller must pass an object to merge into).' }
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
    $candidatePaths = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\oh-my-posh\bin\oh-my-posh.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\oh-my-posh\oh-my-posh.exe'),
        (Join-Path $env:ProgramFiles 'oh-my-posh\bin\oh-my-posh.exe')
    )

    $pf86 = [System.Environment]::GetEnvironmentVariable('ProgramFiles(x86)', 'Process')
    if ($pf86) {
        $candidatePaths += (Join-Path $pf86 'oh-my-posh\bin\oh-my-posh.exe')
    }

    $resolvedPath = Get-ExternalCommandPath -CommandName 'oh-my-posh'
    $windowsAppsRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    if ($resolvedPath -and $resolvedPath -notlike "$windowsAppsRoot*") {
        return $resolvedPath
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

function Test-WingetPackageInstalled {
    param(
        [Parameter(Mandatory)]
        [string]$Id
    )

    $wingetPath = Get-ExternalCommandPath -CommandName 'winget'
    if (-not $wingetPath) { return $false }

    try {
        $wingetOutput = @(& $wingetPath list --id $Id --exact 2>&1)
        $wingetText = (@($wingetOutput) -join [Environment]::NewLine).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $wingetText) { return $false }
        if ($wingetText -match 'No installed package found') { return $false }
        return $wingetText -match [regex]::Escape($Id)
    }
    catch {
        return $false
    }
}

function Get-OhMyPoshMsiProductCode {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $entries = Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq 'Oh My Posh' }
    foreach ($entry in $entries) {
        foreach ($uninstallString in @($entry.QuietUninstallString, $entry.UninstallString)) {
            if ($uninstallString -and $uninstallString -match '\{[0-9A-Fa-f\-]{36}\}') {
                return $Matches[0]
            }
        }
    }

    return $null
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

    # Use randomized tempfile names so concurrent Update-Profile runs (and other processes
    # writing fixed-name files under %TEMP%) can't race or clobber each other.
    $tempSuffix = [System.IO.Path]::GetRandomFileName()
    $tempProfile = Join-Path $env:TEMP "psp-profile-$tempSuffix.ps1"
    $tempConfig = Join-Path $env:TEMP "psp-theme-$tempSuffix.json"
    $tempTerminalConfig = Join-Path $env:TEMP "psp-terminal-$tempSuffix.json"
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

    # Gate the network phase behind ShouldProcess so -WhatIf does not pull files from GitHub.
    # Descriptive action label covers the entire download+hash+copy flow because we cannot
    # know what will change without first downloading.
    $updateSource = "$repo_root/$repo_name/main"
    if (-not $PSCmdlet.ShouldProcess($updateSource, 'Download profile/theme/terminal-config and apply updates')) { return }

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

        # Phase 2: Hash verification (profile .ps1 only).
        # Check BOTH edition dirs, not just $PROFILE: a user running Update-Profile from PS7
        # when PS5 has a stale profile (or vice versa) needs the other edition resynced too.
        $newHash = (Get-FileHash -Path $tempProfile -Algorithm SHA256).Hash
        $_docsRoot = Split-Path (Split-Path $PROFILE)
        $_editionDirs = @(
            (Join-Path $_docsRoot 'PowerShell')
            (Join-Path $_docsRoot 'WindowsPowerShell')
        )
        $_installedProfiles = foreach ($_ed in $_editionDirs) {
            $_p = Join-Path $_ed 'Microsoft.PowerShell_profile.ps1'
            if (Test-Path $_p) { $_p }
        }
        $profileChanged = $false
        if (-not $_installedProfiles) {
            # Fresh install scenario - always copy
            $profileChanged = $true
        }
        else {
            foreach ($_ip in $_installedProfiles) {
                if ((Get-FileHash -Path $_ip -Algorithm SHA256).Hash -ne $newHash) {
                    $profileChanged = $true
                    break
                }
            }
        }

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
                Write-Host "Downloaded file hashes (computed over what was just fetched):" -ForegroundColor Yellow
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
                Write-Host "These hashes confirm FILE INTEGRITY of the current download (no truncation, no corruption)." -ForegroundColor DarkYellow
                Write-Host "To pin against a specific upstream commit, verify the SHA out-of-band first:" -ForegroundColor DarkYellow
                Write-Host "  https://github.com/26zl/PowerShellPerfect/commits/main" -ForegroundColor DarkYellow
                throw "Hash input required. Re-run with -ExpectedSha256 '$combinedHash' (reproducible install) or -SkipHashCheck."
            }
            $expected = $ExpectedSha256.ToUpperInvariant()
            if ($combinedHash -ne $expected) {
                throw "Combined hash mismatch. Expected $expected, got $combinedHash."
            }
        }

        # Phase 3: Copy profile to PS5/PS7 dirs (only if changed).
        # On a fresh install the current edition's profile dir may not exist yet; create it for
        # the edition that is actually running so the copy lands. We still avoid creating the
        # OTHER edition's dir (if the user does not have that edition installed we have no business
        # putting a profile there).
        if ($profileChanged) {
            if ($PSCmdlet.ShouldProcess($PROFILE, "Replace profile with downloaded version (hash: $newHash)")) {
                $docsRoot = Split-Path (Split-Path $PROFILE)
                $profileDirs = @(
                    Join-Path $docsRoot "PowerShell"
                    Join-Path $docsRoot "WindowsPowerShell"
                )
                $currentEditionDir = Split-Path $PROFILE
                if (-not (Test-Path $currentEditionDir)) {
                    try {
                        New-Item -ItemType Directory -Path $currentEditionDir -Force | Out-Null
                        Write-Host "Created profile directory: $currentEditionDir" -ForegroundColor DarkGray
                    }
                    catch {
                        Write-Warning "Failed to create profile directory $currentEditionDir`: $_"
                    }
                }
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
            # Create starter template so users know the file exists. Must match the template
            # created by setup.ps1 (around line 892) so users see the same override surface
            # regardless of which command created the file.
            $userSettingsTemplate = @'
{
    "_comment": "User overrides for terminal, theme, and profile behavior. Only add keys you want to override.",
    "_examples": {
        "theme": { "name": "catppuccin", "url": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/catppuccin.omp.json" },
        "windowsTerminal": { "colorScheme": "One Half Dark", "cursorColor": "#ffffff" },
        "defaults": {
            "opacity": 90,
            "font": { "size": 14 },
            "backgroundImage": "%USERPROFILE%\\Pictures\\bg.png",
            "backgroundImageOpacity": 0.3,
            "backgroundImageStretchMode": "uniformToFill",
            "backgroundImageAlignment": "center"
        },
        "keybindings": [{ "keys": "ctrl+shift+t", "command": { "action": "newTab" } }],
        "features": {
            "psfzf": true,
            "predictions": true,
            "startupMessage": true,
            "perDirProfiles": true,
            "_commandOverrides_note": "set commandOverrides to true ONLY if you also populate the commandOverrides section below. Default off because JSON strings get compiled to scriptblocks at profile load.",
            "commandOverrides": false
        },
        "commandOverrides": {
            "_note": "entries here are ignored unless features.commandOverrides = true",
            "gs": "git status --short"
        },
        "trustedDirs": []
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

        # Phase 6: Windows Terminal sync - iterate ALL installed WT variants so users running
        # Stable + Preview (or Canary) get every variant updated, not just the first found.
        $terminalOverridesChanged = $userSettingsChanged -and ($userWindowsTerminalOverridePresent -or $userTerminalDefaultsOverridePresent -or $userKeybindingsOverridePresent)
        if (($Force -or $profileChanged -or $configChanged -or $terminalConfigChanged -or $terminalOverridesChanged) -and (($config -and $config.windowsTerminal) -or $terminalConfig)) {
            $wtSettingsPaths = Get-WindowsTerminalSettingsPaths
            foreach ($wtSettingsPath in $wtSettingsPaths) {
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

                            # Upsert custom WT theme (tab bar colors, window chrome) from theme.json
                            $themeDef = $config.windowsTerminal.themeDefinition
                            $themeActive = $config.windowsTerminal.theme
                            if ($themeDef) {
                                if (-not $wt.themes) {
                                    $wt | Add-Member -NotePropertyName "themes" -NotePropertyValue @() -Force
                                }
                                $themeDefName = $themeDef.name
                                $wt.themes = @(@($wt.themes | Where-Object { $_ -and $_.name -ne $themeDefName }) + ([PSCustomObject]$themeDef))
                            }
                            if ($themeActive) {
                                if ($wt.PSObject.Properties['theme']) { $wt.theme = $themeActive }
                                else { $wt | Add-Member -NotePropertyName "theme" -NotePropertyValue $themeActive -Force }
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

                        # Depth 100: WT settings can have deeply nested action/command objects;
                        # depth 10 silently truncates those to their type name string and corrupts settings.
                        $wtJson = $wt | ConvertTo-Json -Depth 100
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

        # Refresh the applied-commit baseline used by the opt-in update-check so it starts
        # from the freshly-pulled version; best-effort - a network hiccup here is harmless.
        if ($profileActuallyUpdated) {
            try {
                $_upOwner = ($repo_root -replace '^https?://(raw\.)?githubusercontent\.com/', '').Trim('/')
                $_upApi = "https://api.github.com/repos/$_upOwner/$repo_name/commits/main"
                $_upResp = Invoke-RestMethod -Uri $_upApi -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
                if ($_upResp -and $_upResp.sha) {
                    $_upBaseline = Join-Path $cacheDir 'applied-commit.sha'
                    [System.IO.File]::WriteAllText($_upBaseline, $_upResp.sha, [System.Text.UTF8Encoding]::new($false))
                }
            }
            catch { $null = $_ }
        }

        # Restart the terminal whenever *anything* that the running session would load
        # differently has changed - not just the profile.ps1 itself. Without this, changes
        # to theme.json / terminal-config.json / user-settings.json land on disk but the
        # current shell still shows old prompt/features until the user manually reloads.
        $anyRuntimeChange = $profileActuallyUpdated -or $configChanged -or $terminalConfigChanged -or $userSettingsChanged
        if ($anyRuntimeChange) {
            $reason = if ($profileActuallyUpdated) { 'Profile updated' }
                      elseif ($configChanged) { 'Theme config updated' }
                      elseif ($terminalConfigChanged) { 'Terminal config updated' }
                      else { 'User settings updated' }
            Restart-TerminalToApply -Message "$reason. Restarting terminal..."
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
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl -TimeoutSec 10 -Headers $headers -UseBasicParsing
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
        # System paths affect every user on the box and require admin. SupportsShouldProcess
        # defaults to ConfirmImpact=Medium and $ConfirmPreference is High by default, so
        # -IncludeSystemCaches without -Confirm would otherwise delete silently. Require an
        # explicit y/N prompt (unless -Confirm:$false or -WhatIf was passed).
        if (-not $WhatIfPreference -and $ConfirmPreference -ne 'None') {
            Write-Host ''
            Write-Host 'You are about to clear SYSTEM caches (Windows\Temp, Windows\Prefetch).' -ForegroundColor Yellow
            Write-Host 'These paths affect every user on this machine and require admin.' -ForegroundColor Yellow
            $reply = Read-Host '  Continue? [y/N]'
            if ($reply -notmatch '^(?i:y|yes)$') {
                Write-Host 'Cancelled. User caches left untouched as well.' -ForegroundColor DarkGray
                return
            }
        }
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

# Show the execution time of the last command (fish-style `cmd_duration` / starship duration).
# Reads $MaximumHistoryCount-bounded Get-History so it works even with large histories.
function duration {
    $last = Get-History -Count 1 -ErrorAction SilentlyContinue
    if (-not $last) {
        Write-Host 'No history yet.' -ForegroundColor Yellow
        return
    }
    $span = $last.EndExecutionTime - $last.StartExecutionTime
    $cmd = $last.CommandLine
    if ($cmd.Length -gt 60) { $cmd = $cmd.Substring(0, 57) + '...' }
    $secs = [math]::Round($span.TotalSeconds, 3)
    Write-Host ("  {0}" -f $cmd) -ForegroundColor DarkGray
    Write-Host ("  {0}s  ({1:hh\:mm\:ss\.fff})" -f $secs, $span) -ForegroundColor Cyan
}

# Jump back N directories in the cd history stack. Default N=1 (previous directory).
# The stack is maintained by Invoke-PromptStage and bounded to $PSP.PwdHistoryMax.
# Consumes entries 1..N from the stack (so repeat cdb walks further back instead of
# oscillating) and sets SuppressPwdHistoryPush so the Set-Location doesn't cause the
# prompt hook to re-push the departure.
function cdb {
    [CmdletBinding()]
    param([int]$N = 1)
    if (-not $script:PSP -or -not $script:PSP.PwdHistory -or $script:PSP.PwdHistory.Count -eq 0) {
        Write-Host 'No directory history yet.' -ForegroundColor Yellow
        return
    }
    if ($N -lt 1 -or $N -gt $script:PSP.PwdHistory.Count) {
        Write-Host ("History has {0} entries; N must be 1..{0}." -f $script:PSP.PwdHistory.Count) -ForegroundColor Yellow
        return
    }
    $target = $script:PSP.PwdHistory[$N - 1]
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Warning "Directory no longer exists: $target (marked with '!' in cdh). Run 'cdh' to see the stack."
        return
    }
    # Pop the consumed entries (0..N-1) so the stack reflects where we actually are.
    for ($i = 0; $i -lt $N; $i++) { $script:PSP.PwdHistory.RemoveAt(0) }
    # Suppress auto-push on the Set-Location that follows - we already cleaned up the stack.
    $script:PSP.SuppressPwdHistoryPush = $true
    Set-Location -LiteralPath $target
}

# List the cd history stack (most-recent first). `cdb N` jumps to entry [N].
function cdh {
    if (-not $script:PSP -or -not $script:PSP.PwdHistory -or $script:PSP.PwdHistory.Count -eq 0) {
        Write-Host 'No directory history yet.' -ForegroundColor Yellow
        return
    }
    $i = 1
    foreach ($d in $script:PSP.PwdHistory) {
        $exists = Test-Path -LiteralPath $d
        $color = if ($exists) { 'White' } else { 'DarkGray' }
        $mark = if ($exists) { ' ' } else { '!' }
        Write-Host ("  [{0}]{1} {2}" -f $i, $mark, $d) -ForegroundColor $color
        $i++
    }
}

# Admin Check and Prompt Customization (fallback when Oh My Posh is not loaded)
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
# PowerShell prompt (fallback when Oh My Posh is not loaded)
# Shared prompt-stage helper: fires PrePrompt hooks, detects cd, fires OnCd, and auto-loads
# trusted .psprc.ps1 when the directory changes. Called from both fallback and OMP prompts.
function Invoke-PromptStage {
    if (-not $script:PSP) { return }
    Invoke-ProfileHook -EventName 'PrePrompt'
    try {
        $current = $PWD.ProviderPath
        if (-not $current) { return }
        if ($current -eq $script:PSP.LastPwd) { return }
        # Push previous pwd onto the history stack (most-recent first, bounded).
        # Explicit null check: empty List<string> is falsy under -and in PowerShell.
        # `cdb` sets SuppressPwdHistoryPush so its stack-pop navigation doesn't re-push the
        # just-consumed entry (which would make repeat cdb oscillate instead of walk back).
        if ($script:PSP.SuppressPwdHistoryPush) {
            $script:PSP.SuppressPwdHistoryPush = $false
        }
        elseif ($script:PSP.LastPwd -and $null -ne $script:PSP.PwdHistory) {
            $script:PSP.PwdHistory.Insert(0, $script:PSP.LastPwd)
            while ($script:PSP.PwdHistory.Count -gt $script:PSP.PwdHistoryMax) {
                $script:PSP.PwdHistory.RemoveAt($script:PSP.PwdHistory.Count - 1)
            }
        }
        $script:PSP.LastPwd = $current
        Invoke-ProfileHook -EventName 'OnCd'
        if (-not $script:PSP.Features.perDirProfiles) { return }
        $rc = Join-Path $current '.psprc.ps1'
        if (-not (Test-Path -LiteralPath $rc)) { return }
        if ($script:PSP.TrustedDirs -contains $current) {
            try { . $rc }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-Warning ".psprc.ps1 failed: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host ".psprc.ps1 found in this directory. Run Add-TrustedDirectory to auto-load it." -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "prompt stage: $($_.Exception.Message)"
    }
}

function prompt {
    Invoke-PromptStage
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

# Open WinUtil (Chris Titus) - safe-by-default: downloads a random tempfile, shows SHA256 + URL,
# and does NOT execute unless the caller opts in with -ExpectedSha256 <hash> (hash-pinned) or
# -Force (trust-on-download). Even then, execution is gated behind ShouldProcess so interactive
# users get a high-impact confirmation prompt and automation must opt out explicitly.
# Source: https://christitus.com/win (remote script, not hash-pinned by upstream).
function winutil {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [switch]$Force
    )
    if ($ExpectedSha256 -and $Force) {
        Write-Error 'Use either -ExpectedSha256 or -Force, not both.'
        return
    }
    $scriptPath = Join-Path $env:TEMP ("winutil-" + [System.IO.Path]::GetRandomFileName() + ".ps1")
    try {
        Invoke-RestMethod -Uri 'https://christitus.com/win' -OutFile $scriptPath -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).Length -eq 0) {
            throw 'Downloaded WinUtil script is empty.'
        }
        $actualHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash
        Write-Host "Source: https://christitus.com/win"
        Write-Host "SHA256: $actualHash" -ForegroundColor Cyan
        $downloadLabel = "WinUtil script from https://christitus.com/win (SHA256: $actualHash)"
        if ($ExpectedSha256) {
            if ($actualHash -ine $ExpectedSha256.Trim()) {
                Write-Error "SHA256 mismatch. Expected: $ExpectedSha256. Actual: $actualHash. Aborting."
                return
            }
            if (-not $PSCmdlet.ShouldProcess($downloadLabel, 'Execute downloaded WinUtil script (hash matched)')) {
                return
            }
            Write-Host "SHA256 matched expected value. Executing..." -ForegroundColor Green
            & $scriptPath
            return
        }
        if ($Force) {
            Write-Warning 'Executing an external script without hash pinning. Review the source and SHA256 first.'
            if (-not $PSCmdlet.ShouldProcess($downloadLabel, 'Execute downloaded WinUtil script without hash verification')) {
                return
            }
            Write-Host "Executing with -Force (no hash verification)..." -ForegroundColor Yellow
            & $scriptPath
            return
        }
        Write-Host ''
        Write-Host "NOT executing by default. Re-run with one of:" -ForegroundColor Yellow
        Write-Host "  winutil -ExpectedSha256 '$actualHash'   (pin this version)"
        Write-Host "  winutil -Force                          (trust without hash check)"
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to fetch WinUtil: $($_.Exception.Message)"
    }
    finally {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

# Launch Harden Windows Security (hss.exe) if installed. Even though this is a local binary,
# it is a system-hardening tool, so require an explicit ShouldProcess confirmation.
function harden {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    $hssPath = Get-ExternalCommandPath -CommandName 'hss.exe'
    if ($hssPath) {
        if ($PSCmdlet.ShouldProcess($hssPath, 'Launch Harden Windows Security')) {
            Start-Process $hssPath
        }
    }
    else {
        Write-Warning "hss.exe not found. Install Harden Windows Security from: https://github.com/HotCakeX/Harden-Windows-Security"
    }
}

# Open an elevated terminal. Prefers Windows Terminal (`wt`) so you get tabs/theming;
# falls back to a plain elevated pwsh/powershell window if wt isn't installed so the
# command works on vanilla Windows hosts too.
function admin {
    $shell = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    $hasWt = [bool](Get-Command wt -ErrorAction SilentlyContinue)
    if ($args.Count -gt 0) {
        $escaped = $args | ForEach-Object { if ($_ -match '\s') { "'$($_ -replace "'","''")'" } else { $_ } }
        $command = $escaped -join ' '
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        if ($hasWt) {
            Start-Process wt -Verb runAs -ArgumentList "$shell -NoExit -EncodedCommand $encoded"
        }
        else {
            Start-Process -FilePath $shell -Verb runAs -ArgumentList @('-NoExit', '-EncodedCommand', $encoded)
        }
    }
    elseif ($hasWt) {
        Start-Process wt -Verb runAs
    }
    else {
        Start-Process -FilePath $shell -Verb runAs
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
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop -TimeoutSec 10 -UseBasicParsing
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
    # Do not return the plaintext: at top-level, PowerShell would print it to the
    # terminal scrollback (and to any capturing pipeline/redirect), defeating the
    # clipboard-only contract. The clipboard is the sole delivery channel.
    return
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
    $sha = (Get-FileHash -LiteralPath $resolved.Path -Algorithm SHA256).Hash.ToLower()
    $headers = @{ 'x-apikey' = $apiKey }
    $sizeLabel = if ($file.Length -ge 1MB) { "$sizeMB MB" } else { "$([math]::Round($file.Length / 1KB, 1)) KB" }
    Write-Host "`nFile:       $($file.Name) ($sizeLabel)" -ForegroundColor Cyan
    Write-Host "SHA256:     $sha" -ForegroundColor Cyan

    # Lookup by hash first
    $found = $false
    try {
        $report = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha" -Headers $headers -ErrorAction Stop -UseBasicParsing
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
            $uploadUrl = (Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/files/upload_url' -Headers $headers -ErrorAction Stop -UseBasicParsing).data
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
        $old = Push-TabTitle "logs: $Container"
        try { docker logs -f $Container }
        finally { Pop-TabTitle $old }
    }
    function dex {
        param(
            [Parameter(Mandatory)][string]$Container,
            [string]$Shell = 'bash'
        )
        $old = Push-TabTitle "docker: $Container"
        try { docker exec -it $Container $Shell }
        finally { Pop-TabTitle $old }
    }
    # dstop: stop all running containers; dprune: system prune
    function dstop {
        $running = docker ps -q
        if ($running) { docker stop $running } else { Write-Host "No running containers." }
    }
    function dprune { docker system prune -f }
}

# WSL wrapper + QoL helpers. All defined only when wsl.exe is available.
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    # Wrapper: shows "wsl <distro>" in tab title during session. Uses & wsl.exe (with .exe
    # suffix) so PS resolves to the native binary, not this function (avoids recursion).
    function wsl {
        $distro = 'default'
        for ($i = 0; $i -lt $args.Count; $i++) {
            $a = [string]$args[$i]
            if ($a -eq '-d' -or $a -eq '--distribution') {
                if ($i + 1 -lt $args.Count) { $distro = [string]$args[$i + 1] }
                break
            }
        }
        $oldTitle = Push-TabTitle "wsl: $distro"
        try {
            if ($MyInvocation.ExpectingInput) { $input | & wsl.exe @args }
            else { & wsl.exe @args }
        }
        finally { Pop-TabTitle $oldTitle }
    }

    # List installed WSL distros with state + version. Parses wsl.exe -l -v output which is
    # UTF-16 with a null-byte-interspersed encoding that PowerShell decodes inconsistently.
    function Get-WslDistro {
        [CmdletBinding()]
        param()
        $raw = & wsl.exe -l -v 2>&1
        $results = @()
        foreach ($line in $raw) {
            $clean = ([string]$line) -replace "`0", ''
            if ($clean -match '^\s*(\*?)\s*([A-Za-z0-9._-]+)\s+(Running|Stopped|Installing|Uninstalling|Converting)\s+(\d+)') {
                $results += [PSCustomObject]@{
                    Default = ($matches[1] -eq '*')
                    Name    = $matches[2]
                    State   = $matches[3]
                    Version = [int]$matches[4]
                }
            }
        }
        $results
    }

    # Open a WSL shell in the current Windows directory. Uses wsl.exe --cd which auto-translates
    # Windows path via wslpath. Tab title set by the ssh wrapper pattern via the main 'wsl' fn.
    function Enter-WslHere {
        [CmdletBinding()]
        param([string]$Distro)
        $wslArgs = @('--cd', (Get-Location).ProviderPath)
        if ($Distro) { $wslArgs = @('-d', $Distro) + $wslArgs }
        wsl @wslArgs
    }
    Set-Alias -Name wsl-here -Value Enter-WslHere

    # Translate Windows path to WSL path via the in-distro 'wslpath -a' utility.
    # Two things worth knowing:
    #   1. wsl.exe drops single backslashes during argument handoff from Windows -> Linux
    #      ('C:\foo' arrives as 'C:foo' inside wslpath). We pre-normalize '\' -> '/' since
    #      wslpath accepts either form for Windows paths.
    #   2. The '--' end-of-options marker stops wslpath from treating paths that start with '-'
    #      (legal POSIX filename, e.g. '-foo') as flag arguments.
    function ConvertTo-WslPath {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Path,
            [string]$Distro
        )
        $normalized = $Path -replace '\\', '/'
        $wslArgs = @()
        if ($Distro) { $wslArgs += '-d', $Distro }
        $wslArgs += 'wslpath', '-a', '--', $normalized
        $result = (& wsl.exe @wslArgs 2>&1)
        if ($LASTEXITCODE -ne 0) { Write-Error ($result -join ' '); return }
        ($result | Select-Object -First 1).ToString().Trim()
    }

    # Translate WSL path to Windows path via 'wslpath -w'. Same protections as ConvertTo-WslPath.
    # Normalize '\' -> '/' to survive wsl.exe's backslash-dropping arg handoff.
    function ConvertTo-WindowsPath {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Path,
            [string]$Distro
        )
        $normalized = $Path -replace '\\', '/'
        $wslArgs = @()
        if ($Distro) { $wslArgs += '-d', $Distro }
        $wslArgs += 'wslpath', '-w', '--', $normalized
        $result = (& wsl.exe @wslArgs 2>&1)
        if ($LASTEXITCODE -ne 0) { Write-Error ($result -join ' '); return }
        ($result | Select-Object -First 1).ToString().Trim()
    }

    # Shutdown all WSL distros, or terminate a specific one. Useful when a distro hangs or
    # Docker Desktop / VPN adapters misbehave and need a clean restart.
    function Stop-Wsl {
        [CmdletBinding()]
        param([string]$Distro)
        if ($Distro) {
            & wsl.exe --terminate $Distro
            Write-Host "Terminated: $Distro" -ForegroundColor Green
        }
        else {
            & wsl.exe --shutdown
            Write-Host "All WSL distros stopped." -ForegroundColor Green
        }
    }

    # Get IPv4 address of a WSL distro. Useful for connecting from Windows to a service
    # running inside WSL (http server, db, etc.). Returns first IP if multiple.
    function Get-WslIp {
        [CmdletBinding()]
        param([string]$Distro)
        $wslArgs = @()
        if ($Distro) { $wslArgs += '-d', $Distro }
        $wslArgs += 'hostname', '-I'
        $out = (& wsl.exe @wslArgs 2>$null | Out-String).Trim()
        if (-not $out) { Write-Warning 'No IP returned; is the distro running?'; return }
        ($out -split '\s+')[0]
    }

    # List files inside a WSL distro via the \\wsl$\<Distro>\... UNC path. Returns FileInfo
    # objects (pipe-friendly): `Get-WslFile Debian /home | Where Name -like 'lenti*'`.
    # The distro must be running for the UNC path to be accessible.
    function Get-WslFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Distro,
            [Parameter(Position = 1)][string]$Path = '/',
            [switch]$Recurse,
            [switch]$Force
        )
        $uncRoot = '\\wsl$\' + $Distro
        $rel = ($Path -replace '^/', '') -replace '/', '\'
        $unc = if ($rel) { Join-Path $uncRoot $rel } else { $uncRoot }
        if (-not (Test-Path -LiteralPath $unc)) {
            Write-Error "Not accessible: $unc. Distro may be stopped (try: wsl -d $Distro echo ready) or path is wrong."
            return
        }
        Get-ChildItem -LiteralPath $unc -Recurse:$Recurse -Force:$Force
    }

    # Internal: resolve WSL UNC path + check reachable. Returns $null with error on failure.
    function Resolve-WslUncPath {
        param([string]$Distro, [string]$Path = '/')
        $uncRoot = '\\wsl$\' + $Distro
        $rel = ($Path -replace '^/', '') -replace '/', '\'
        $unc = if ($rel) { Join-Path $uncRoot $rel } else { $uncRoot }
        if (-not (Test-Path -LiteralPath $unc)) {
            Write-Error "Not accessible: $unc. Distro may be stopped (try: wsl -d $Distro echo ready) or path is wrong."
            return $null
        }
        return $unc
    }

    # Tree-view of a WSL directory. Uses eza when available (nice icons + colors), falls back
    # to Get-ChildItem -Recurse -Depth. Default depth=2 to avoid flooding on '/' ; bump with -Depth.
    function Show-WslTree {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Distro,
            [Parameter(Position = 1)][string]$Path = '/',
            [ValidateRange(1, 10)][int]$Depth = 2,
            [switch]$All
        )
        $unc = Resolve-WslUncPath -Distro $Distro -Path $Path
        if (-not $unc) { return }
        if (Get-Command eza -ErrorAction SilentlyContinue) {
            $ezaArgs = @('--tree', "--level=$Depth", '--icons', '--git-ignore')
            if ($All) { $ezaArgs += '-a' }
            & eza @ezaArgs $unc
        }
        else {
            # Fallback: PS-native tree. -Depth counts levels INTO the directory.
            Get-ChildItem -LiteralPath $unc -Recurse -Depth ($Depth - 1) -Force:$All |
            Select-Object Mode, Length, LastWriteTime, FullName
        }
    }
    Set-Alias -Name wsl-tree -Value Show-WslTree

    # Open Windows Explorer at a WSL distro path for native GUI browsing. Quickest way to
    # scroll through a whole distro filesystem visually, thumbnail previews for images, etc.
    function Open-WslExplorer {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Distro,
            [Parameter(Position = 1)][string]$Path = '/'
        )
        $unc = Resolve-WslUncPath -Distro $Distro -Path $Path
        if (-not $unc) { return }
        explorer.exe $unc
    }
    Set-Alias -Name wsl-explorer -Value Open-WslExplorer
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

# Diagnose a possibly-broken install: walks through tools, caches, fonts, PATH, modules,
# and plugins, reporting OK / WARN / FAIL per check. Users hitting weird prompts or missing
# predictions run this before filing an issue.
function Test-ProfileHealth {
    [CmdletBinding()]
    param()

    $results = @()

    # Managed tools
    foreach ($tool in $script:ProfileTools) {
        $path = Get-ProfileToolExecutablePath -Tool $tool
        if ($path) {
            $results += [pscustomobject]@{ Category = 'Tools'; Check = $tool.Name; Status = 'OK'; Detail = $path }
        }
        else {
            $results += [pscustomobject]@{ Category = 'Tools'; Check = $tool.Name; Status = 'FAIL'; Detail = 'not installed (Update-Profile or setup.ps1)' }
        }
    }

    # Disk caches
    foreach ($c in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json')) {
        $p = Join-Path $cacheDir $c
        if (-not (Test-Path $p)) {
            $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'WARN'; Detail = 'missing (will regenerate on next load)' }
            continue
        }
        $size = (Get-Item $p).Length
        if ($size -eq 0) {
            $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'FAIL'; Detail = 'empty file (corrupt)' }
            continue
        }
        if ($c -like '*.json') {
            try {
                $null = Get-Content $p -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'OK'; Detail = "$size bytes, parses" }
            }
            catch {
                $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'FAIL'; Detail = "JSON parse error: $($_.Exception.Message)" }
            }
        }
        else {
            $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'OK'; Detail = "$size bytes" }
        }
    }

    # User-settings.json (overrides)
    $us = Join-Path $cacheDir 'user-settings.json'
    if (Test-Path $us) {
        try {
            $null = Get-Content $us -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'OK'; Detail = 'parses' }
        }
        catch {
            $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'FAIL'; Detail = $_.Exception.Message }
        }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'WARN'; Detail = 'missing (no overrides applied)' }
    }

    # Font from terminal-config.json.fontInstall.displayName
    $tcPath = Join-Path $cacheDir 'terminal-config.json'
    if (Test-Path $tcPath) {
        try {
            $tc = Get-Content $tcPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $fontName = if ($tc.fontInstall) { $tc.fontInstall.displayName } else { $null }
            if ($fontName) {
                # System.Drawing ships on Windows PowerShell 5.1 and is available via the
                # System.Drawing.Common package on PS 7 Windows. On Linux/Mac PS the type
                # may not load; treat that as WARN (can't verify) rather than FAIL (missing).
                if (-not ('System.Drawing.Text.InstalledFontCollection' -as [type])) {
                    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
                }
                if (-not ('System.Drawing.Text.InstalledFontCollection' -as [type])) {
                    $results += [pscustomobject]@{ Category = 'Fonts'; Check = $fontName; Status = 'WARN'; Detail = 'System.Drawing unavailable on this host; cannot verify' }
                }
                else {
                    $installed = $false
                    try {
                        $fc = New-Object System.Drawing.Text.InstalledFontCollection
                        $installed = $fc.Families.Name -contains $fontName
                        $fc.Dispose()
                    }
                    catch { $null = $_ }
                    if ($installed) {
                        $results += [pscustomobject]@{ Category = 'Fonts'; Check = $fontName; Status = 'OK'; Detail = 'installed' }
                    }
                    else {
                        $results += [pscustomobject]@{ Category = 'Fonts'; Check = $fontName; Status = 'FAIL'; Detail = 'not installed (run setup.ps1 -Wizard or Update-Profile)' }
                    }
                }
            }
        }
        catch { $null = $_ }
    }

    # PATH - WindowsApps (winget shims location)
    $wapps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    if (($env:PATH -split ';') -contains $wapps) {
        $results += [pscustomobject]@{ Category = 'PATH'; Check = 'WindowsApps'; Status = 'OK'; Detail = 'in PATH' }
    }
    else {
        $results += [pscustomobject]@{ Category = 'PATH'; Check = 'WindowsApps'; Status = 'WARN'; Detail = 'missing (winget shims may not resolve)' }
    }

    # Modules
    if (Get-Module -ListAvailable -Name PSFzf) {
        $results += [pscustomobject]@{ Category = 'Modules'; Check = 'PSFzf'; Status = 'OK'; Detail = 'available' }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Modules'; Check = 'PSFzf'; Status = 'WARN'; Detail = 'not installed (Ctrl+R/Ctrl+T disabled)' }
    }
    $prl = Get-Module PSReadLine
    if ($prl) {
        $results += [pscustomobject]@{ Category = 'Modules'; Check = 'PSReadLine'; Status = 'OK'; Detail = "v$($prl.Version)" }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Modules'; Check = 'PSReadLine'; Status = 'FAIL'; Detail = 'not loaded' }
    }

    # Plugins
    $pluginDir = Join-Path $cacheDir 'plugins'
    if (Test-Path $pluginDir) {
        $plugins = @(Get-ChildItem $pluginDir -Filter *.ps1 -ErrorAction SilentlyContinue)
        $results += [pscustomobject]@{ Category = 'Plugins'; Check = 'user plugins'; Status = 'OK'; Detail = "$($plugins.Count) file(s) in $pluginDir" }
    }

    # Extensibility state
    $trustedCount = if ($script:PSP.TrustedDirs) { $script:PSP.TrustedDirs.Count } else { 0 }
    $results += [pscustomobject]@{ Category = 'Extension'; Check = 'trusted directories'; Status = 'OK'; Detail = "$trustedCount entries" }

    # Format + render
    $okCount = @($results | Where-Object Status -eq 'OK').Count
    $warnCount = @($results | Where-Object Status -eq 'WARN').Count
    $failCount = @($results | Where-Object Status -eq 'FAIL').Count

    Write-Host ''
    Write-Host 'Profile Health Check' -ForegroundColor Cyan
    Write-Host '===================='
    $fmt = '{0,-10} {1,-30} {2,-5} {3}'
    Write-Host ($fmt -f 'Category', 'Check', 'Stat', 'Detail') -ForegroundColor DarkGray
    foreach ($r in $results) {
        $color = switch ($r.Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'White' } }
        $detail = if ($r.Detail.Length -gt 80) { $r.Detail.Substring(0, 77) + '...' } else { $r.Detail }
        Write-Host ($fmt -f $r.Category, $r.Check, $r.Status, $detail) -ForegroundColor $color
    }
    Write-Host ''
    $summaryColor = if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("Summary: {0} OK, {1} WARN, {2} FAIL" -f $okCount, $warnCount, $failCount) -ForegroundColor $summaryColor

    # Return the objects too so scripts can query: Test-ProfileHealth | Where Status -eq 'FAIL'
    $results
}
Set-Alias -Name psp-doctor -Value Test-ProfileHealth -Scope Script

# Clear profile cache (Oh My Posh and our own) to resolve issues with stale data or after manual edits to cache files. Terminal restart is required to see changes.
function Clear-ProfileCache {
    $cacheDir = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
    if (-not (Test-Path $cacheDir)) {
        Clear-OhMyPoshCaches -Quiet
        Write-Host "No cache directory found." -ForegroundColor Yellow
        return
    }
    # Preserve user-owned content: user-settings.json (config) and plugins/ (user-installed scripts).
    # Everything else is regenerable cache and can be safely removed.
    $preservedNames = @('user-settings.json', 'plugins')
    $items = Get-ChildItem $cacheDir -ErrorAction SilentlyContinue | Where-Object { $preservedNames -notcontains $_.Name }
    if (-not $items) {
        Clear-OhMyPoshCaches -Quiet
        Write-Host "Cache is already clean." -ForegroundColor Green
        return
    }
    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  Removed $($item.Name)" -ForegroundColor DarkGray
    }
    Clear-OhMyPoshCaches -Quiet
    Restart-TerminalToApply -Message "Profile cache cleared. Restarting terminal..."
}

# Re-run setup.ps1 -Wizard so the user can pick a new OMP theme, WT scheme, font, and
# features without reinstalling from scratch. Downloads a fresh setup.ps1 to %TEMP%
# (to pick up the latest wizard logic) and relaunches elevated in a new pwsh window.
#
# Security: downloads remote code, so the user must either pin -ExpectedSha256 or explicitly
# confirm -SkipHashCheck. Exit code of the child process is captured so we do not claim
# "Wizard complete" on a failure.
function Invoke-ProfileWizard {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$Resume,
        [switch]$NoElevate,
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [switch]$SkipHashCheck
    )

    $setupUrl = "$repo_root/$repo_name/main/setup.ps1"
    $setupLocal = Join-Path ([System.IO.Path]::GetTempPath()) ("psp-reconfigure-{0}.ps1" -f ([System.IO.Path]::GetRandomFileName()))

    Write-Host "Downloading latest setup.ps1 from $setupUrl" -ForegroundColor Cyan
    if (-not $PSCmdlet.ShouldProcess($setupUrl, 'Download and execute remote setup.ps1')) { return }
    try { Invoke-DownloadWithRetry -Uri $setupUrl -OutFile $setupLocal }
    catch {
        Write-Warning "Download failed: $($_.Exception.Message)"
        return
    }

    try {
        $actualHash = (Get-FileHash -LiteralPath $setupLocal -Algorithm SHA256).Hash
        if ($ExpectedSha256) {
            if ($actualHash -ine $ExpectedSha256.Trim()) {
                Write-Error "SHA256 mismatch. Expected: $ExpectedSha256. Actual: $actualHash. Aborting."
                return
            }
            Write-Host "  Hash verified: $actualHash" -ForegroundColor Green
        }
        elseif (-not $SkipHashCheck) {
            Write-Host "  Downloaded setup.ps1 SHA256: $actualHash" -ForegroundColor Yellow
            Write-Host "  (Hash is computed over the download just made; it confirms integrity," -ForegroundColor DarkYellow
            Write-Host "   not upstream authenticity. Verify the commit out-of-band before pinning.)" -ForegroundColor DarkYellow
            Write-Host "  Pin it:  Invoke-ProfileWizard -ExpectedSha256 '$actualHash'" -ForegroundColor Yellow
            Write-Host "  Or skip: Invoke-ProfileWizard -SkipHashCheck" -ForegroundColor Yellow
            throw "Hash input required. Re-run with -ExpectedSha256 or -SkipHashCheck."
        }

        $shellArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $setupLocal, '-Wizard')
        if ($Resume) { $shellArgs += '-Resume' }

        $pwshExe = if ((Get-Command pwsh -ErrorAction SilentlyContinue)) { 'pwsh' } else { 'powershell' }
        $exitCode = 1

        if ($isAdmin -or $NoElevate) {
            & $pwshExe @shellArgs
            $exitCode = $LASTEXITCODE
        }
        else {
            Write-Host "Launching elevated wizard in a new window ..." -ForegroundColor Cyan
            $proc = Start-Process -FilePath $pwshExe -ArgumentList $shellArgs -Verb RunAs -Wait -PassThru
            $exitCode = if ($proc) { $proc.ExitCode } else { 1 }
        }

        if ($exitCode -eq 0) {
            Write-Host "Wizard complete. Reload your shell (run 'reload') to apply changes." -ForegroundColor Green
        }
        else {
            Write-Warning "Wizard exited with code $exitCode. Review the output above."
        }
    }
    finally {
        Remove-Item $setupLocal -Force -ErrorAction SilentlyContinue
    }
}
Set-Alias -Name Reconfigure-Profile -Value Invoke-ProfileWizard -Scope Script

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
    $wtSettingsPath = Get-WindowsTerminalSettingsPath
    if ($wtSettingsPath -and (Test-Path (Split-Path $wtSettingsPath))) {
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

    # Phase 4: Managed tools (winget by default, direct/MSI aware for Oh My Posh)
    if ($RemoveTools) {
        if ($isCiOrAgent) {
            Write-Host '  Skipping managed tool uninstall under CI/agent environment.' -ForegroundColor DarkGray
        }
        else {
            $wingetPath = Get-ExternalCommandPath -CommandName 'winget'
            foreach ($tool in $script:ProfileTools) {
                $toolPath = Get-ProfileToolExecutablePath -Tool $tool
                $wingetManaged = if ($wingetPath) { Test-WingetPackageInstalled -Id $tool.Id } else { $false }
                $removalMode = $null
                $ompMsiProductCode = $null

                if ($tool.Cmd -eq 'oh-my-posh') {
                    if ($wingetManaged) {
                        $removalMode = 'winget'
                    }
                    else {
                        $ompMsiProductCode = Get-OhMyPoshMsiProductCode
                    }

                    if ($ompMsiProductCode) {
                        $removalMode = 'msi'
                    }
                }
                elseif ($wingetManaged) {
                    $removalMode = 'winget'
                }

                if (-not $removalMode) {
                    if ($toolPath) {
                        $toolLocation = if (-not $wingetPath -and $tool.Cmd -ne 'oh-my-posh') { 'install present but winget is unavailable' }
                        elseif ($tool.Cmd -eq 'oh-my-posh') { 'direct/MSI install without winget registration' }
                        else { 'local install without winget registration' }
                        Write-Host "  Preserving $($tool.Name) ($toolLocation)." -ForegroundColor DarkGray
                    }
                    continue
                }

                if ($removalMode -eq 'winget') {
                    if ($PSCmdlet.ShouldProcess($tool.Name, 'Uninstall via winget')) {
                        try {
                            $wingetOutput = @(& $wingetPath uninstall -e --id $tool.Id --silent 2>&1)
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
                    continue
                }

                if ($removalMode -eq 'msi') {
                    if (-not $ompMsiProductCode) {
                        Write-Warning '  Could not locate an MSI product code for Oh My Posh.'
                        continue
                    }

                    if ($PSCmdlet.ShouldProcess($tool.Name, 'Uninstall via MSI')) {
                        try {
                            $msiProc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x', $ompMsiProductCode, '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
                            if ($msiProc.ExitCode -in @(0, 1605, 3010)) {
                                Write-Host "  Uninstalled $($tool.Name)" -ForegroundColor Green
                            }
                            else {
                                Write-Warning "  Failed to uninstall $($tool.Name) via MSI (exit $($msiProc.ExitCode))."
                            }
                        }
                        catch {
                            Write-Warning "  Failed to uninstall $($tool.Name) via MSI: $_"
                        }
                    }
                }
            }
        }
    }
    elseif (-not $RemoveTools) { $preserved += 'Managed tools (use -RemoveTools to uninstall)' }

    # Phase 5: Nerd Fonts (opt-in, requires admin)
    if ($RemoveFonts) {
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isElevated) {
            Write-Warning '  Font removal requires an elevated (admin) terminal. Skipping.'
        }
        else {
            # Derive the font filter from terminal-config.json's fontInstall.displayName so uninstall
            # mirrors whatever font the current install actually placed. Falls back to CaskaydiaCove
            # only if terminal-config.json is unreadable (install default).
            $fontDisplayName = 'CaskaydiaCove NF'
            try {
                $tcPath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\terminal-config.json'
                if (Test-Path $tcPath) {
                    $tc = Get-Content $tcPath -Raw | ConvertFrom-Json
                    if ($tc.fontInstall.displayName) { $fontDisplayName = $tc.fontInstall.displayName }
                }
            }
            catch { $null = $_ }
            $tokens = $fontDisplayName -split '\s+' | Where-Object { $_ }
            # Avoid -Filter globbing (which treats [ ] * ? as wildcards - can match unintended
            # files if displayName contains those chars). Use -match with an anchored regex on .ttf.
            $regexPattern = ($tokens | ForEach-Object { [regex]::Escape($_) }) -join '.*'
            $fontDir = Join-Path $env:SystemRoot 'Fonts'
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
            $fontFiles = Get-ChildItem $fontDir -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.ttf' -and $_.Name -match $regexPattern }
            if ($fontFiles) {
                foreach ($f in $fontFiles) {
                    if ($PSCmdlet.ShouldProcess($f.Name, 'Remove font file')) {
                        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                $regEntries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                if ($regEntries) {
                    $regEntries.PSObject.Properties | Where-Object { $_.Name -match $regexPattern } | ForEach-Object {
                        if ($PSCmdlet.ShouldProcess($_.Name, 'Remove font registry entry')) {
                            Remove-ItemProperty -Path $regPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                Write-Host "  Removed $fontDisplayName font files." -ForegroundColor Green
            }
            else {
                Write-Host "  No Nerd Font files matching '$fontDisplayName' found to remove." -ForegroundColor DarkGray
            }
        }
    }
    else { $preserved += 'Nerd Fonts (use -RemoveFonts to remove, requires admin)' }

    # Phase 6: Remove telemetry opt-out env var (only if we set it).
    # Ownership is tracked via $cacheDir\telemetry.owned (written by setup.ps1 when the user
    # answered yes to the opt-out prompt). Without the marker we leave the env var alone,
    # because other tools (or the user's own config) may depend on it.
    $isElevatedNow = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $telemetryMarker = Join-Path $env:LOCALAPPDATA 'PowerShellProfile\telemetry.owned'
    if ([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
        if (-not (Test-Path -LiteralPath $telemetryMarker)) {
            Write-Host '  Leaving POWERSHELL_TELEMETRY_OPTOUT alone (no ownership marker; value may belong to another tool or user setting).' -ForegroundColor DarkGray
        }
        elseif ($isElevatedNow) {
            if ($PSCmdlet.ShouldProcess('POWERSHELL_TELEMETRY_OPTOUT', 'Remove machine environment variable')) {
                [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', $null, [System.EnvironmentVariableTarget]::Machine)
                Remove-Item -LiteralPath $telemetryMarker -Force -ErrorAction SilentlyContinue
                Write-Host '  Removed POWERSHELL_TELEMETRY_OPTOUT env var.' -ForegroundColor Green
            }
        }
        else {
            Write-Host '  Skipping POWERSHELL_TELEMETRY_OPTOUT removal (requires admin).' -ForegroundColor DarkGray
        }
    }
    elseif (Test-Path -LiteralPath $telemetryMarker) {
        # Env var already gone; clean up the stale marker so repeat uninstalls stay idempotent.
        Remove-Item -LiteralPath $telemetryMarker -Force -ErrorAction SilentlyContinue
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
        $r = Invoke-RestMethod $url -TimeoutSec 10 -Headers @{ 'User-Agent' = 'curl' } -UseBasicParsing
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
            $geo = Invoke-RestMethod "https://geocoding-api.open-meteo.com/v1/search?name=$encoded&count=1" -TimeoutSec 5 -UseBasicParsing
            if (-not $geo -or -not $geo.results -or @($geo.results).Count -eq 0) { Write-Error "City '$City' not found."; return }
            $geo.results[0]
        }
        else {
            $ip = Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 5 -UseBasicParsing
            if (-not $ip -or -not $ip.loc -or $ip.loc -notmatch ',') { Write-Error "Could not determine location from IP."; return }
            $ll = $ip.loc -split ','
            if ($ll.Count -lt 2) { Write-Error "Malformed location data from IP lookup."; return }
            [PSCustomObject]@{ name = $ip.city; latitude = $ll[0]; longitude = $ll[1] }
        }
        if (-not $loc) { return }
        $lat = ([double]$loc.latitude).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $lon = ([double]$loc.longitude).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $wx = Invoke-RestMethod "https://api.open-meteo.com/v1/forecast?latitude=$lat&longitude=$lon&current=temperature_2m,weather_code" -TimeoutSec 5 -UseBasicParsing
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
        Start-Process -FilePath cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList @('/c', $editorPath, $hostsPath)
    }
    else {
        Start-Process -FilePath $editorPath -ArgumentList @($hostsPath) -Verb RunAs
    }
}

# Simple download speed test by fetching a known file from Cloudflare's speed test endpoint and measuring the time taken. Provides a rough estimate of download speed in Mbps.
function speedtest {
    Write-Host "Testing download speed..." -ForegroundColor Cyan
    $url = "https://speed.cloudflare.com/__down?bytes=25000000"
    $start = Get-Date
    $oldTitle = Push-TabTitle 'speedtest'
    try {
        Invoke-RestMethod $url -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop | Out-Null
        $elapsed = [math]::Max(((Get-Date) - $start).TotalSeconds, 0.001)
        $mbps = [math]::Round((25 * 8) / $elapsed, 1)
        Write-Host "Download: ~${mbps} Mbps ($([math]::Round($elapsed, 1))s for 25 MB)" -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Speed test failed: $_"
    }
    finally { Pop-TabTitle $oldTitle }
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
    # Wrapper: inject short ConnectTimeout and keepalive defaults so ssh.exe fails fast
    # instead of ignoring Ctrl+C during a hung TCP connect (long-standing Windows OpenSSH quirk).
    # User-supplied -o values take precedence because we only inject when the option is absent.
    function ssh {
        # Match both OpenSSH forms: '-o Key=Val' (space) and '-oKey=Val' (no space).
        # \s* = zero or more whitespace. Otherwise users passing '-oConnectTimeout=60' would
        # get our default injected ahead, and OpenSSH takes first-wins so their override loses.
        $argText = ($args -join ' ')
        $extra = @()
        if ($argText -notmatch '-o\s*ConnectTimeout') { $extra += '-o'; $extra += 'ConnectTimeout=10' }
        if ($argText -notmatch '-o\s*ServerAliveInterval') { $extra += '-o'; $extra += 'ServerAliveInterval=30' }
        if ($argText -notmatch '-o\s*ServerAliveCountMax') { $extra += '-o'; $extra += 'ServerAliveCountMax=3' }
        # Tab title: first non-flag, non-option-value arg is typically the target (user@host).
        # Skips flags (-X) and values of options that take one (-p 22, -i keyfile, etc.).
        $target = $null
        $skipNext = $false
        $flagsWithValue = @('-p', '-i', '-l', '-o', '-F', '-L', '-R', '-D', '-W', '-B', '-b', '-c', '-E', '-e', '-I', '-J', '-m', '-O', '-Q', '-S', '-w')
        foreach ($a in $args) {
            if ($skipNext) { $skipNext = $false; continue }
            if ($a -is [string] -and $a.StartsWith('-')) {
                if ($flagsWithValue -contains $a) { $skipNext = $true }
                continue
            }
            $target = [string]$a
            break
        }
        $oldTitle = if ($target) { Push-TabTitle "ssh $target" } else { $null }
        try {
            if ($MyInvocation.ExpectingInput) { $input | & ssh.exe @extra @args }
            else { & ssh.exe @extra @args }
        }
        finally { Pop-TabTitle $oldTitle }
    }

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

# Interactive port killer. Lists every listening TCP port with PID + process name,
# opens fzf (multi-select with Tab) or Out-GridView as fallback, kills everything picked.
# Perfect for "I started 5 dev servers today, which ones are still running?".
function Stop-ListeningPort {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $conns = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort)
    if (-not $conns) { Write-Host "No listening TCP ports." -ForegroundColor Yellow; return }
    $rows = foreach ($c in $conns) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port    = $c.LocalPort
            Address = $c.LocalAddress
            PID     = $c.OwningProcess
            Process = if ($proc) { $proc.ProcessName } else { '-' }
        }
    }
    $selected = @()
    if (Get-Command fzf -ErrorAction SilentlyContinue) {
        # Format each row into a single fzf line; parse selection back to PID via last column.
        $lines = $rows | ForEach-Object {
            ('{0,-7} {1,-20} {2,-8} {3}' -f $_.Port, $_.Address, $_.PID, $_.Process)
        }
        $picked = $lines | fzf --multi --header='Tab to multi-select, Enter to kill' --prompt='killport> '
        if (-not $picked) { Write-Host 'Nothing selected.' -ForegroundColor DarkGray; return }
        foreach ($line in @($picked)) {
            # PID is the third whitespace-separated column in our formatted line.
            $cols = $line -split '\s+' | Where-Object { $_ }
            if ($cols.Count -ge 3) {
                $selected += ($rows | Where-Object { [string]$_.PID -eq $cols[2] } | Select-Object -First 1)
            }
        }
    }
    else {
        $selected = @($rows | Out-GridView -Title 'Select ports to kill (Ctrl/Shift for multi)' -PassThru)
        if (-not $selected) { Write-Host 'Nothing selected.' -ForegroundColor DarkGray; return }
    }
    foreach ($row in $selected) {
        if ($row.PID -eq 0 -or $row.PID -eq 4) {
            Write-Warning "Skipping system PID $($row.PID) on port $($row.Port)."
            continue
        }
        if ($PSCmdlet.ShouldProcess("PID $($row.PID) ($($row.Process)) on port $($row.Port)", 'Stop process')) {
            try {
                Stop-Process -Id $row.PID -Force -ErrorAction Stop
                Write-Host ("Killed: {0} (PID {1}) on port {2}" -f $row.Process, $row.PID, $row.Port) -ForegroundColor Green
            }
            catch { Write-Warning ("Could not stop PID {0}: {1}" -f $row.PID, $_.Exception.Message) }
        }
    }
}
Set-Alias -Name killports -Value Stop-ListeningPort

# ==========================================================================
# Stuck processes / locked files
# ==========================================================================

# Internal: compile the Restart-Manager P/Invoke wrapper once per session.
# Uses the same Windows API Explorer uses when it says "The action can't be completed
# because the file is open in X". Reliable across NTFS, mapped drives, network shares.
function Initialize-RestartManagerType {
    if ('PSP.RestartManager' -as [type]) { return }
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace PSP {
    public static class RestartManager {
        [StructLayout(LayoutKind.Sequential)]
        struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
        const int CCH_RM_MAX_APP_NAME = 255;
        const int CCH_RM_MAX_SVC_NAME = 63;
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;
            public int ApplicationType; public uint AppStatus; public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
        [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint pSessionHandle);
        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
        public static List<int> WhoIsLocking(string path) {
            uint handle; string key = Guid.NewGuid().ToString();
            List<int> ids = new List<int>();
            int r = RmStartSession(out handle, 0, key);
            if (r != 0) throw new Exception("RmStartSession failed: " + r);
            try {
                r = RmRegisterResources(handle, 1, new string[] { path }, 0, null, 0, null);
                if (r != 0) throw new Exception("RmRegisterResources failed: " + r);
                uint needed = 0; uint count = 0; uint reason = 0;
                r = RmGetList(handle, out needed, ref count, new RM_PROCESS_INFO[0], ref reason);
                if (r == 234) {
                    RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed]; count = needed;
                    r = RmGetList(handle, out needed, ref count, info, ref reason);
                    if (r != 0) throw new Exception("RmGetList failed: " + r);
                    for (int i = 0; i < count; i++) ids.Add(info[i].Process.dwProcessId);
                }
                else if (r != 0) throw new Exception("RmGetList failed: " + r);
            }
            finally { RmEndSession(handle); }
            return ids;
        }
    }
}
'@ -ErrorAction Stop
}

# Find which processes are holding a file or directory open. Works for any reason a file
# is locked: antivirus scanning, Explorer preview, IDE index, shared mapping, etc.
function Find-FileLocker {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    try { Initialize-RestartManagerType }
    catch { Write-Error "Could not load Restart-Manager API: $($_.Exception.Message)"; return }
    $ids = [PSP.RestartManager]::WhoIsLocking($resolved.ProviderPath)
    if (-not $ids -or $ids.Count -eq 0) {
        Write-Host "No process is holding a lock on: $($resolved.ProviderPath)" -ForegroundColor Green
        return
    }
    foreach ($procId in $ids) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) {
            [PSCustomObject]@{
                PID         = $procId
                Name        = $p.ProcessName
                WindowTitle = $p.MainWindowTitle
                Started     = $p.StartTime
                Path        = try { $p.Path } catch { '<access denied>' }
            }
        }
        else {
            [PSCustomObject]@{
                PID = $procId; Name = '<terminated>'; WindowTitle = ''; Started = $null; Path = $null
            }
        }
    }
}

# Aggressively kill a process that won't die with ordinary Stop-Process. Escalates:
# Stop-Process -Force -> taskkill /F -> taskkill /F /T (child tree).
# Accepts process name (all instances), PID (single), or pipeline of either.
function Stop-StuckProcess {
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ByName', ValueFromPipeline)]
        [string[]]$Name,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int[]]$Id,
        [switch]$Tree
    )
    begin { $targets = [System.Collections.Generic.List[int]]::new() }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            foreach ($i in $Id) { [void]$targets.Add($i) }
        }
        else {
            foreach ($n in $Name) {
                $found = @(Get-Process -Name ($n -replace '\.exe$', '') -ErrorAction SilentlyContinue)
                if (-not $found) { Write-Warning "No process matching: $n"; continue }
                foreach ($p in $found) { [void]$targets.Add($p.Id) }
            }
        }
    }
    end {
        if ($targets.Count -eq 0) { return }
        $targets = $targets | Select-Object -Unique
        foreach ($procId in $targets) {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if (-not $p) { Write-Host "PID $procId already gone." -ForegroundColor DarkGray; continue }
            $label = "$($p.ProcessName) (PID $procId)"
            if (-not $PSCmdlet.ShouldProcess($label, 'Stop process (escalating)')) { continue }
            # Stage 1: Stop-Process -Force
            try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { $null = $_ }
            Start-Sleep -Milliseconds 200
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                Write-Host "Stopped: $label" -ForegroundColor Green
                continue
            }
            # Stage 2: taskkill /F (with /T if requested)
            $tkArgs = @('/F', '/PID', $procId)
            if ($Tree) { $tkArgs += '/T' }
            & taskkill.exe @tkArgs 2>&1 | Out-Null
            Start-Sleep -Milliseconds 300
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                Write-Host "Force-killed: $label" -ForegroundColor Yellow
            }
            else {
                Write-Error "Could not stop: $label. Likely needs SYSTEM privileges (protected process, antivirus, driver-held handle)."
            }
        }
    }
}

# Convenience: find what's holding a lock, kill those processes (aggressive), then delete.
# Backs off gracefully if the item still can't be removed (e.g. SYSTEM-held, in use by driver).
function Remove-LockedItem {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [switch]$Recurse,
        [switch]$KillSystem  # include PID 0/4 lockers (usually pointless, always dangerous)
    )
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    if (-not $PSCmdlet.ShouldProcess($resolved.ProviderPath, 'Kill lockers and delete')) { return }
    # Try a plain delete first. Fastest path when nothing is actually locking.
    try {
        Remove-Item -LiteralPath $resolved.ProviderPath -Recurse:$Recurse -Force -ErrorAction Stop
        Write-Host "Deleted: $($resolved.ProviderPath)" -ForegroundColor Green
        return
    }
    catch {
        Write-Host "Initial delete failed, investigating lockers..." -ForegroundColor Yellow
    }
    $lockers = @(Find-FileLocker -Path $resolved.ProviderPath)
    if (-not $lockers) {
        Write-Error "Delete failed but no lockers reported. Check permissions or path." -ErrorAction Continue
        return
    }
    Write-Host "Lockers found:" -ForegroundColor Cyan
    $lockers | Format-Table PID, Name, WindowTitle | Out-Host
    foreach ($l in $lockers) {
        if (-not $KillSystem -and ($l.PID -eq 0 -or $l.PID -eq 4 -or $l.Name -eq 'System')) {
            Write-Warning "Skipping system process $($l.Name) (PID $($l.PID)). Use -KillSystem to override (usually pointless)."
            continue
        }
        Stop-StuckProcess -Id $l.PID -Tree -Confirm:$false
    }
    Start-Sleep -Milliseconds 500
    try {
        Remove-Item -LiteralPath $resolved.ProviderPath -Recurse:$Recurse -Force -ErrorAction Stop
        Write-Host "Deleted after unlocking: $($resolved.ProviderPath)" -ForegroundColor Green
    }
    catch {
        Write-Error "Still locked after killing reported lockers: $($_.Exception.Message)"
        Write-Host 'Next steps: reboot, or check for SYSTEM/driver lock via Sysinternals Handle/Process Explorer.' -ForegroundColor DarkGray
    }
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
    $oldTitle = Push-TabTitle 'timer'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Command }
    finally {
        $sw.Stop()
        Pop-TabTitle $oldTitle
    }
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
        $info = Invoke-RestMethod -Uri $url -TimeoutSec 10 -UseBasicParsing
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
    $cmdLabel = ($Command.ToString().Trim() -replace '\s+', ' ')
    if ($cmdLabel.Length -gt 40) { $cmdLabel = $cmdLabel.Substring(0, 40) + '...' }
    $oldTitle = Push-TabTitle "watch: $cmdLabel"
    try {
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
    finally { Pop-TabTitle $oldTitle }
}

# WHOIS domain lookup via RDAP (IANA standard, no external tools needed)
function whois {
    param([Parameter(Mandatory)][string]$Domain)
    $Domain = $Domain -replace '^https?://', '' -replace '/.*$', ''
    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$Domain" -TimeoutSec 10 -UseBasicParsing
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

# Argument completers (tab-complete for custom commands)

# Common ports for fwallow/fwblock -Port
Register-ArgumentCompleter -CommandName fwallow, fwblock -ParameterName Port -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    @(22, 53, 80, 139, 143, 443, 445, 465, 587, 993, 995, 1194, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017) |
    Where-Object { [string]$_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new([string]$_, [string]$_, 'ParameterValue', [string]$_) }
}

# Available Windows event logs for journal -LogName
Register-ArgumentCompleter -CommandName journal -ParameterName LogName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    try {
        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object { $_.LogName -like "$wordToComplete*" } |
        Select-Object -First 25 |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new("'$($_.LogName)'", $_.LogName, 'ParameterValue', $_.LogName) }
    }
    catch { $null = $_ }
}

# Common gitignore.io templates for gitignore <language>
Register-ArgumentCompleter -CommandName gitignore -ParameterName Language -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    @('python', 'node', 'go', 'rust', 'java', 'windows', 'visualstudio', 'macos', 'linux',
        'vim', 'emacs', 'vscode', 'pycharm', 'intellij', 'sublimetext', 'ruby', 'swift',
        'kotlin', 'scala', 'cpp', 'c', 'dotnetcore', 'android', 'ios', 'unity', 'unreal',
        'jekyll', 'wordpress', 'laravel', 'django', 'flask', 'terraform', 'ansible',
        'docker', 'kubernetes', 'svelte', 'nextjs', 'gatsby', 'angular', 'react') |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

# Nmap modes for nscan -Mode (redundant with ValidateSet but gives richer descriptions)
Register-ArgumentCompleter -CommandName nscan -ParameterName Mode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    $modes = @{
        'Quick'    = 'Top ports with aggressive timing'
        'Full'     = 'All 65535 ports'
        'Services' = 'Service and default-script detection'
        'Stealth'  = 'SYN scan with fragmentation'
        'Vuln'     = 'Vuln NSE scripts + service detection'
        'Ports'    = 'Custom -Ports list'
    }
    $modes.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.Key, $_.Key, 'ParameterValue', $_.Value) }
}

# Defender scan modes
Register-ArgumentCompleter -CommandName defscan -ParameterName Mode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    @('Quick', 'Full') | Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

# Lint mode presets
Register-ArgumentCompleter -CommandName lint -ParameterName Mode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    $modes = @{
        'Standard' = 'Default PSScriptAnalyzer rule set'
        'Strict'   = 'Include Information-level issues'
        'Security' = 'Security-relevant rules only'
        'CI'       = 'Match the project CI ExcludeRule list'
    }
    $modes.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.Key, $_.Key, 'ParameterValue', $_.Value) }
}

# Existing trusted directories for Remove-TrustedDirectory -Path
Register-ArgumentCompleter -CommandName Remove-TrustedDirectory -ParameterName Path -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    if (-not $script:PSP) { return }
    $script:PSP.TrustedDirs | Where-Object { $_ -like "*$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new("'$_'", $_, 'ParameterValue', $_) }
}

# Set-TerminalBackground: StretchMode / Alignment with human-readable descriptions
Register-ArgumentCompleter -CommandName Set-TerminalBackground -ParameterName StretchMode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    $modes = @{
        'none'          = 'Original image size (no stretch)'
        'fill'          = 'Stretch to fill, ignore aspect ratio'
        'uniform'       = 'Scale to fit while preserving aspect'
        'uniformToFill' = 'Scale to fill while preserving aspect (crop)'
    }
    $modes.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.Key, $_.Key, 'ParameterValue', $_.Value) }
}

Register-ArgumentCompleter -CommandName Set-TerminalBackground -ParameterName Alignment -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    @('center', 'left', 'top', 'right', 'bottom', 'topLeft', 'topRight', 'bottomLeft', 'bottomRight') |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}

# WSL distro name completion for all WSL helpers that take a -Distro parameter.
# Calls Get-WslDistro at completion time; silently returns nothing if wsl.exe is unavailable.
Register-ArgumentCompleter -CommandName Enter-WslHere, ConvertTo-WslPath, ConvertTo-WindowsPath, Stop-Wsl, Get-WslIp, Get-WslFile, Show-WslTree, Open-WslExplorer -ParameterName Distro -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    if (-not (Get-Command Get-WslDistro -ErrorAction SilentlyContinue)) { return }
    try {
        Get-WslDistro | Where-Object { $_.Name -like "$wordToComplete*" } |
        ForEach-Object {
            $tip = "$($_.State), WSL$($_.Version)" + $(if ($_.Default) { ' (default)' } else { '' })
            [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $tip)
        }
    }
    catch { $null = $_ }
}

# Stop-StuckProcess -Name: live list of running processes (unique names).
Register-ArgumentCompleter -CommandName Stop-StuckProcess -ParameterName Name -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    try {
        Get-Process -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ProcessName -Unique |
        Where-Object { $_ -like "$wordToComplete*" } |
        Sort-Object |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
    }
    catch { $null = $_ }
}

# Register-ProfileHook -EventName completion
Register-ArgumentCompleter -CommandName Register-ProfileHook -ParameterName EventName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    $events = @{
        'OnProfileLoad' = 'Fires once after profile has loaded'
        'PrePrompt'     = 'Fires before every prompt render'
        'OnCd'          = 'Fires when the current directory changes'
    }
    $events.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.Key, $_.Key, 'ParameterValue', $_.Value) }
}

# Sysadmin / Linux-feel

# Tail Windows Event Log in journalctl style. Default: last 50 System events.
# -Follow polls every 2s for new entries. -Level filters by severity name.
function journal {
    param(
        [string]$LogName = 'System',
        [int]$Count = 50,
        [switch]$Follow,
        [ValidateSet('Critical', 'Error', 'Warning', 'Information', 'Verbose')]
        [string]$Level
    )
    $filter = @{ LogName = $LogName }
    if ($Level) {
        $filter.Level = switch ($Level) {
            'Critical' { 1 } 'Error' { 2 } 'Warning' { 3 } 'Information' { 4 } 'Verbose' { 5 }
        }
    }
    function Write-JournalLine {
        param($Entry)
        $color = switch ($Entry.LevelDisplayName) {
            'Critical' { 'Red' } 'Error' { 'Red' } 'Warning' { 'Yellow' } default { 'Gray' }
        }
        $msg = ($Entry.Message -replace "`r?`n", ' ')
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
        Write-Host ("{0} [{1,-11}] {2}: {3}" -f $Entry.TimeCreated, $Entry.LevelDisplayName, $Entry.ProviderName, $msg) -ForegroundColor $color
    }
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction SilentlyContinue
    if (-not $events) { Write-Host "No events matched." -ForegroundColor Yellow; return }
    $events | Sort-Object TimeCreated | ForEach-Object { Write-JournalLine $_ }
    if (-not $Follow) { return }
    Write-Host "Following $LogName. Ctrl+C to stop." -ForegroundColor DarkGray
    $lastTime = ($events | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
    $oldTitle = Push-TabTitle "journal: $LogName"
    try {
        while ($true) {
            Start-Sleep -Seconds 2
            $follow = $filter.Clone()
            $follow.StartTime = $lastTime.AddMilliseconds(1)
            $newEvents = Get-WinEvent -FilterHashtable $follow -ErrorAction SilentlyContinue
            if ($newEvents) {
                foreach ($entry in ($newEvents | Sort-Object TimeCreated)) {
                    Write-JournalLine $entry
                    $lastTime = $entry.TimeCreated
                }
            }
        }
    }
    finally { Pop-TabTitle $oldTitle }
}

# List disks and partitions in a pretty tree (Linux lsblk equivalent).
function lsblk {
    $disks = Get-Disk -ErrorAction SilentlyContinue | Sort-Object Number
    if (-not $disks) { Write-Warning "Get-Disk returned no disks."; return }
    foreach ($disk in $disks) {
        $sizeGB = [math]::Round($disk.Size / 1GB, 1)
        Write-Host ("Disk {0}: {1} ({2} GB, {3})" -f $disk.Number, $disk.FriendlyName, $sizeGB, $disk.BusType) -ForegroundColor Cyan
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | Sort-Object PartitionNumber
        foreach ($p in $partitions) {
            $pSize = [math]::Round($p.Size / 1GB, 1)
            $letter = if ($p.DriveLetter) { ('{0}:' -f $p.DriveLetter) } else { '' }
            $label = ''
            if ($p.DriveLetter) {
                $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
                if ($vol) {
                    $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 1)
                    $label = ("{0} [{1}, {2}/{3} GB]" -f $vol.FileSystemLabel, $vol.FileSystem, $usedGB, $pSize)
                }
            }
            Write-Host ("  {0,-3} {1,-6} {2,7} GB  {3,-22} {4}" -f $p.PartitionNumber, $letter, $pSize, $p.Type, $label)
        }
    }
}

# Interactive process viewer. Prefers btop/ntop/htop if installed, otherwise falls back
# to the existing 'svc -Live' helper so the command always does something useful.
function htop {
    foreach ($c in @('btop', 'ntop', 'htop')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { & $cmd.Source; return }
    }
    Write-Host 'No TUI process viewer installed. Tip: winget install aristocratos.btop4win' -ForegroundColor Yellow
    Write-Host 'Falling back to svc -Live.' -ForegroundColor DarkGray
    svc -Live
}

# Combined traceroute + per-hop ping (my traceroute). -Count pings per hop (default 3).
function mtr {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateRange(1, 50)][int]$Count = 3,
        [ValidateRange(1, 64)][int]$MaxHops = 30
    )
    $oldTitle = Push-TabTitle "mtr: $Target"
    try {
    Write-Host "Tracing route to $Target..." -ForegroundColor Cyan
    $trace = Test-NetConnection $Target -TraceRoute -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if (-not $trace -or -not $trace.TraceRoute) { Write-Error "Traceroute failed for $Target"; return }
    Write-Host ("  {0,-4} {1,-20} {2,7} {3,7} {4,7}  Samples" -f 'Hop', 'Address', 'Loss%', 'Avg', 'Best') -ForegroundColor DarkGray
    $i = 0
    foreach ($hop in @($trace.TraceRoute | Where-Object { $_ })) {
        $i++
        if ($i -gt $MaxHops) { break }
        $times = @()
        $lost = 0
        for ($j = 0; $j -lt $Count; $j++) {
            try {
                $p = Test-Connection -ComputerName $hop -Count 1 -ErrorAction Stop
                if ($p) {
                    $lat = if ($p.PSObject.Properties['ResponseTime']) { [int]$p.ResponseTime } elseif ($p.PSObject.Properties['Latency']) { [int]$p.Latency } else { 0 }
                    $times += $lat
                }
                else { $lost++ }
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                $lost++
            }
        }
        $lossPct = [math]::Round(($lost / $Count) * 100, 0)
        $avg = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 0) } else { '-' }
        $best = if ($times.Count) { ($times | Measure-Object -Minimum).Minimum } else { '-' }
        $color = if ($lossPct -gt 20) { 'Red' } elseif ($lossPct -gt 5) { 'Yellow' } else { 'Green' }
        Write-Host ("  {0,-4} {1,-20} {2,6}% {3,7} {4,7}   {5}" -f $i, $hop, $lossPct, $avg, $best, $times.Count) -ForegroundColor $color
    }
    }
    finally { Pop-TabTitle $oldTitle }
}

# Quick Windows Firewall allow rule. Requires elevation and confirms before changing
# global firewall state unless the caller passes -Confirm:$false.
function fwallow {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Port,
        [ValidateSet('TCP', 'UDP', 'Any')][string]$Protocol = 'TCP',
        [ValidateSet('Inbound', 'Outbound')][string]$Direction = 'Inbound'
    )
    if (-not $isAdmin) { Write-Error 'Firewall changes require an elevated shell.'; return }
    $splat = @{ DisplayName = $Name; Direction = $Direction; Action = 'Allow'; Protocol = $Protocol }
    if ($Port) { $splat.LocalPort = $Port }
    $portText = if ($Port) { " port $Port" } else { '' }
    if (-not $PSCmdlet.ShouldProcess($Name, "Add firewall allow rule ($Direction $Protocol$portText)")) { return }
    New-NetFirewallRule @splat | Out-Null
    Write-Host ("Allow rule added: {0} ({1} {2}{3})" -f $Name, $Direction, $Protocol, $portText) -ForegroundColor Green
}

# Quick Windows Firewall block rule. Requires elevation and confirms before changing
# global firewall state unless the caller passes -Confirm:$false.
function fwblock {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Port,
        [ValidateSet('TCP', 'UDP', 'Any')][string]$Protocol = 'TCP',
        [ValidateSet('Inbound', 'Outbound')][string]$Direction = 'Inbound'
    )
    if (-not $isAdmin) { Write-Error 'Firewall changes require an elevated shell.'; return }
    $splat = @{ DisplayName = $Name; Direction = $Direction; Action = 'Block'; Protocol = $Protocol }
    if ($Port) { $splat.LocalPort = $Port }
    $portText = if ($Port) { " port $Port" } else { '' }
    if (-not $PSCmdlet.ShouldProcess($Name, "Add firewall block rule ($Direction $Protocol$portText)")) { return }
    New-NetFirewallRule @splat | Out-Null
    Write-Host ("Block rule added: {0} ({1} {2}{3})" -f $Name, $Direction, $Protocol, $portText) -ForegroundColor Yellow
}

# Cybersec

# Nmap wrapper with curated scan profiles. Mode 'Ports' uses -Ports list.
function nscan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('Quick', 'Full', 'Services', 'Stealth', 'Vuln', 'Ports')]
        [string]$Mode = 'Quick',
        [int[]]$Ports
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        Write-Error 'nmap is not installed. Install with: winget install Insecure.Nmap'
        return
    }
    $nmapArgs = switch ($Mode) {
        'Quick' { @('-F', '-T4') }
        'Full' { @('-p-', '-T4') }
        'Services' { @('-sV', '-sC', '--top-ports', '1000') }
        'Stealth' { @('-sS', '-T2', '-f') }
        'Vuln' { @('--script', 'vuln', '-sV') }
        'Ports' { @() }
    }
    if ($Mode -eq 'Ports' -and $Ports) { $nmapArgs += @('-p', ($Ports -join ',')) }
    Write-Host ("nmap {0} {1}" -f ($nmapArgs -join ' '), $Target) -ForegroundColor DarkGray
    $oldTitle = Push-TabTitle "nscan $Mode`: $Target"
    try { nmap @nmapArgs $Target }
    finally { Pop-TabTitle $oldTitle }
}

# Authenticode signature inspector. Accepts file or directory. Reports status, signer, expiry.
function sigcheck {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $targets = if ((Get-Item $resolved).PSIsContainer) {
        Get-ChildItem -LiteralPath $resolved -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '^\.(exe|dll|sys|ps1|psm1|psd1|msi|cat|ocx|cpl)$' }
    }
    else { Get-Item -LiteralPath $resolved }
    foreach ($t in $targets) {
        $sig = Get-AuthenticodeSignature -LiteralPath $t.FullName -ErrorAction SilentlyContinue
        if (-not $sig) { continue }
        $color = switch ($sig.Status) {
            'Valid' { 'Green' } 'NotSigned' { 'DarkGray' } default { 'Red' }
        }
        Write-Host ''
        Write-Host ("File:      {0}" -f $t.FullName) -ForegroundColor Cyan
        Write-Host ("Status:    {0}" -f $sig.Status) -ForegroundColor $color
        if ($sig.StatusMessage) { Write-Host ("Message:   {0}" -f $sig.StatusMessage) -ForegroundColor DarkGray }
        if ($sig.SignerCertificate) {
            Write-Host ("Signer:    {0}" -f $sig.SignerCertificate.Subject)
            Write-Host ("Issuer:    {0}" -f $sig.SignerCertificate.Issuer)
            Write-Host ("Expires:   {0}" -f $sig.SignerCertificate.NotAfter)
            Write-Host ("Thumb:     {0}" -f $sig.SignerCertificate.Thumbprint) -ForegroundColor DarkGray
        }
        if ($sig.TimeStamperCertificate) {
            Write-Host ("Timestamp: {0}" -f $sig.TimeStamperCertificate.Subject) -ForegroundColor DarkGray
        }
    }
}

# List NTFS alternate data streams (a classic malware hiding spot). Works on files or dirs.
function ads {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $items = if ((Get-Item $resolved).PSIsContainer) {
        Get-ChildItem -LiteralPath $resolved -Recurse -File -ErrorAction SilentlyContinue
    }
    else { Get-Item -LiteralPath $resolved }
    # Emit structured objects so callers can filter/select/measure. PS's default formatter
    # still renders a human-readable table in the interactive case.
    foreach ($item in $items) {
        $streams = Get-Item -LiteralPath $item.FullName -Stream * -ErrorAction SilentlyContinue |
        Where-Object { $_.Stream -ne ':$DATA' }
        foreach ($s in $streams) {
            [PSCustomObject]@{
                File   = $item.FullName
                Stream = $s.Stream
                Length = $s.Length
            }
        }
    }
}

# Windows Defender scan wrapper. No path = Quick (or Full with -Mode Full). With path = custom.
function defscan {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Path,
        [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick'
    )
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        Write-Error 'Windows Defender cmdlets not available on this system.'
        return
    }
    $titleLabel = if ($Path) { "defscan: $Path" } else { "defscan: $Mode" }
    $oldTitle = Push-TabTitle $titleLabel
    try {
        if ($Path) {
            $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
            if (-not $resolved) { Write-Error "Path not found: $Path"; return }
            Write-Host ("Custom scan: {0}" -f $resolved.Path) -ForegroundColor Cyan
            Start-MpScan -ScanType CustomScan -ScanPath $resolved.Path
        }
        else {
            $scanType = if ($Mode -eq 'Full') { 'FullScan' } else { 'QuickScan' }
            Write-Host ("Running {0}..." -f $scanType) -ForegroundColor Cyan
            Start-MpScan -ScanType $scanType
        }
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            Write-Host 'Recent threats:' -ForegroundColor Yellow
            $threats | Select-Object -First 10 | Format-Table ThreatName, SeverityID, DetectionID -AutoSize
        }
        else { Write-Host 'No threats recorded.' -ForegroundColor Green }
    }
    finally { Pop-TabTitle $oldTitle }
}

# HaveIBeenPwned k-anonymity password check. Only first 5 SHA1 chars leave the machine.
function pwnd {
    param([Parameter(Mandatory)][string]$Candidate)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Candidate))
        $hashHex = [BitConverter]::ToString($hashBytes).Replace('-', '').ToUpper()
    }
    finally { $sha1.Dispose() }
    $prefix = $hashHex.Substring(0, 5)
    $suffix = $hashHex.Substring(5)
    try {
        $response = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$prefix" -Headers @{ 'Add-Padding' = 'true' } -TimeoutSec 10 -UseBasicParsing
        $lines = $response -split "`r?`n"
        $match = $lines | Where-Object { $_ -match ('^' + [regex]::Escape($suffix) + ':(\d+)') }
        if ($match) {
            $count = [int](($match -split ':')[1])
            if ($count -gt 0) {
                Write-Host ("PWNED: seen in {0} breach(es). Do not use this password." -f $count) -ForegroundColor Red
                return
            }
        }
        Write-Host 'Safe: password not found in known breaches.' -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "HIBP lookup failed: $_"
    }
}

# Full TLS cert probe: protocol, cipher, chain, SAN, SHA256 pin. Extends tlscert.
function certcheck {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$Port = 443
    )
    $tcp = $null; $ssl = $null; $chain = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $async = $tcp.BeginConnect($Domain, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { throw "Connection to ${Domain}:${Port} timed out" }
        $tcp.EndConnect($async)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 10000
        $ssl = [System.Net.Security.SslStream]::new($stream, $false, { $true })
        $ssl.AuthenticateAsClient($Domain)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chainValid = $chain.Build($cert)
        $daysLeft = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $expiryColor = if ($daysLeft -lt 30) { 'Red' } elseif ($daysLeft -lt 90) { 'Yellow' } else { 'Green' }
        Write-Host ("Host:         {0}:{1}" -f $Domain, $Port) -ForegroundColor Cyan
        Write-Host ("TLS:          {0}" -f $ssl.SslProtocol)
        Write-Host ("Cipher:       {0} {1} bits" -f $ssl.CipherAlgorithm, $ssl.CipherStrength)
        Write-Host ("Subject:      {0}" -f $cert.Subject)
        Write-Host ("Issuer:       {0}" -f $cert.Issuer)
        Write-Host ("Serial:       {0}" -f $cert.SerialNumber) -ForegroundColor DarkGray
        Write-Host ("SHA256 pin:   {0}" -f $cert.GetCertHashString('SHA256')) -ForegroundColor DarkGray
        Write-Host ("Not before:   {0}" -f $cert.NotBefore)
        Write-Host ("Not after:    {0}" -f $cert.NotAfter)
        Write-Host ("Days left:    {0}" -f $daysLeft) -ForegroundColor $expiryColor
        Write-Host ("Chain valid:  {0}" -f $chainValid) -ForegroundColor $(if ($chainValid) { 'Green' } else { 'Red' })
        $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($sanExt) {
            $san = ($sanExt.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ', ')
            Write-Host ("SAN:          {0}" -f $san) -ForegroundColor DarkGray
        }
        Write-Host 'Chain:' -ForegroundColor DarkGray
        foreach ($element in $chain.ChainElements) {
            $ec = $element.Certificate
            Write-Host ("  {0} (exp {1})" -f $ec.Subject, $ec.NotAfter.ToString('yyyy-MM-dd')) -ForegroundColor DarkGray
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "certcheck failed for ${Domain}:${Port} - $_"
    }
    finally {
        if ($chain) { $chain.Dispose() }
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

# Shannon entropy of file bytes (0.0 = uniform, 8.0 = random). High values hint at packing/encryption.
function entropy {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $bytes = [System.IO.File]::ReadAllBytes($resolved.Path)
    if ($bytes.Length -eq 0) { Write-Host 'Empty file.' -ForegroundColor Yellow; return }
    $counts = New-Object 'int[]' 256
    foreach ($b in $bytes) { $counts[$b]++ }
    $e = 0.0
    foreach ($c in $counts) {
        if ($c -gt 0) {
            $p = $c / $bytes.Length
            $e -= $p * [math]::Log($p, 2)
        }
    }
    $label = if ($e -gt 7.5) { 'very high (packed/encrypted)' }
    elseif ($e -gt 6.5) { 'high (compressed)' }
    elseif ($e -gt 4.5) { 'medium (code/data)' }
    else { 'low (plain text)' }
    $color = if ($e -gt 7.5) { 'Red' } elseif ($e -gt 6.5) { 'Yellow' } else { 'Green' }
    Write-Host ("File:    {0} ({1} bytes)" -f (Split-Path $resolved.Path -Leaf), $bytes.Length) -ForegroundColor Cyan
    Write-Host ("Entropy: {0:N3} / 8.000 ({1})" -f $e, $label) -ForegroundColor $color
}

# Developer

# One-line HTTP server for current (or given) directory. Prefers python -m http.server, then npx.
function serve {
    param(
        [int]$Port = 8000,
        [string]$Path = '.'
    )
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $oldTitle = Push-TabTitle "serve :$Port"
    try {
        if (Get-Command python -ErrorAction SilentlyContinue) {
            Write-Host ("Serving {0} on http://127.0.0.1:{1} (Ctrl+C to stop)" -f $resolved.Path, $Port) -ForegroundColor Cyan
            Push-Location $resolved.Path
            try { & python -m http.server $Port }
            finally { Pop-Location }
            return
        }
        if (Get-Command npx -ErrorAction SilentlyContinue) {
            Write-Host ("Serving {0} via npx http-server on http://127.0.0.1:{1}" -f $resolved.Path, $Port) -ForegroundColor Cyan
            Push-Location $resolved.Path
            try { & npx --yes http-server -p $Port }
            finally { Pop-Location }
            return
        }
        Write-Error 'Install python or node/npx first. E.g. winget install Python.Python.3.12'
    }
    finally { Pop-TabTitle $oldTitle }
}

# Generate a .gitignore from toptal.com/developers/gitignore/api. Multiple languages allowed.
function gitignore {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Language)
    $joined = ($Language -join ',').ToLower()
    try {
        $content = Invoke-RestMethod -Uri "https://www.toptal.com/developers/gitignore/api/$joined" -TimeoutSec 15 -UseBasicParsing
        if (-not $content) { Write-Error 'Empty response from gitignore service.'; return }
        $target = Join-Path (Get-Location) '.gitignore'
        if (Test-Path $target) {
            $backup = "$target.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
            Copy-Item $target $backup
            Write-Host ("Backed up existing .gitignore to {0}" -f $backup) -ForegroundColor DarkGray
        }
        [System.IO.File]::WriteAllText($target, $content, [System.Text.UTF8Encoding]::new($false))
        Write-Host ("Wrote .gitignore for: {0}" -f $joined) -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "gitignore fetch failed: $_"
    }
}

# Fuzzy git branch checkout using fzf. Handles local and remote branches.
function gcof {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Error 'git is not installed'; return }
    if (-not (Get-Command fzf -ErrorAction SilentlyContinue)) { Write-Error 'fzf is not installed (winget install junegunn.fzf)'; return }
    $branches = git branch --all --format='%(refname:short)' 2>$null | Where-Object { $_ -and $_ -notmatch '^origin/HEAD' }
    if (-not $branches) { Write-Error 'No branches found'; return }
    $selected = $branches | fzf --height 40% --reverse --prompt 'checkout> '
    if ($selected) {
        $clean = ($selected -replace '^origin/', '').Trim()
        git checkout $clean
    }
}

# Load a .env file into the current session. Handles export prefix and quoted values.
function envload {
    param([string]$Path = '.env')
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $loaded = 0
    Get-Content $resolved.Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        if ($line -match '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $k = $matches[1]; $v = $matches[2].Trim()
            if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
            elseif ($v.Length -ge 2 -and $v.StartsWith("'") -and $v.EndsWith("'")) { $v = $v.Substring(1, $v.Length - 2) }
            Set-Item -LiteralPath "env:$k" -Value $v
            $loaded++
        }
    }
    Write-Host ("Loaded {0} variable(s) from {1}" -f $loaded, $resolved.Path) -ForegroundColor Green
}

# Quick command-example lookup via tldr-pages. Uses native tldr client if installed.
function tldr {
    if (Get-Command tldr.exe -ErrorAction SilentlyContinue) { & tldr.exe @args; return }
    if (-not $args) { Write-Error 'Usage: tldr <command>'; return }
    $cmd = ($args[0]).ToString().ToLower()
    foreach ($platform in @('common', 'windows', 'linux', 'osx')) {
        try {
            $url = "https://raw.githubusercontent.com/tldr-pages/tldr/main/pages/$platform/$cmd.md"
            $page = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            Write-Host $page -ForegroundColor White
            return
        }
        catch { continue }
    }
    Write-Error "No tldr page found for '$cmd'. Install native client: winget install tldr-pages.tldr"
}

# Run a scriptblock N times. -UntilSuccess stops early on zero exit code.
function repeat {
    param(
        [Parameter(Mandatory, Position = 0)][ValidateRange(1, 10000)][int]$Count,
        [Parameter(Mandatory, Position = 1)][scriptblock]$Command,
        [switch]$UntilSuccess,
        [int]$DelaySeconds = 0
    )
    # Save the title ONCE; we re-Push on every iteration to update the counter in-place
    # and restore to the original on exit. Cheaper than Push/Pop per iteration.
    $originalTitle = $null
    try { $originalTitle = $Host.UI.RawUI.WindowTitle } catch { $null = $_ }
    try {
        for ($i = 1; $i -le $Count; $i++) {
            try { $Host.UI.RawUI.WindowTitle = "repeat $i/$Count" } catch { $null = $_ }
            Write-Host ("[{0}/{1}]" -f $i, $Count) -ForegroundColor DarkGray
            # Clear $LASTEXITCODE so a stale value from before this loop cannot cause -UntilSuccess
            # to terminate on iteration 1 when the scriptblock contains no native commands.
            $global:LASTEXITCODE = $null
            $threwError = $false
            try {
                & $Command
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-Host $_.Exception.Message -ForegroundColor Red
                $threwError = $true
            }
            if ($UntilSuccess -and -not $threwError -and ($null -eq $LASTEXITCODE -or $LASTEXITCODE -eq 0)) {
                Write-Host ("Success on attempt {0}." -f $i) -ForegroundColor Green
                return
            }
            if ($DelaySeconds -gt 0 -and $i -lt $Count) { Start-Sleep -Seconds $DelaySeconds }
        }
        if ($UntilSuccess) { Write-Warning ("Command did not succeed in {0} attempts." -f $Count) }
    }
    finally { Pop-TabTitle $originalTitle }
}

# Create a Python venv and activate it. Default folder: .venv.
function mkvenv {
    param(
        [string]$Name = '.venv',
        [string]$PythonPath
    )
    $python = if ($PythonPath) { $PythonPath }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { 'python' }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { 'py' }
    else { $null }
    if (-not $python) { Write-Error 'python not found on PATH (winget install Python.Python.3.12)'; return }
    Write-Host ("Creating venv at ./{0}..." -f $Name) -ForegroundColor Cyan
    & $python -m venv $Name
    if ($LASTEXITCODE -ne 0) { Write-Error 'venv creation failed'; return }
    $venvRoot = Resolve-Path -LiteralPath $Name
    $activate = Join-Path $venvRoot 'Scripts\Activate.ps1'
    if (-not (Test-Path $activate)) { $activate = Join-Path $venvRoot 'bin/Activate.ps1' }
    if (Test-Path $activate) {
        . $activate
        Write-Host ("Activated {0}." -f $Name) -ForegroundColor Green
    }
    else { Write-Warning "Created $Name but Activate.ps1 not found." }
}

# Detection / AST (inspired by vscode-powershell language service)

# Parse a .ps1 file and emit Function/Alias outline entries as objects. Pipe-friendly:
# `outline file.ps1 | Where Kind -eq Function`, `outline | Format-Table`, etc.
function outline {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolved.Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        foreach ($err in $parseErrors) {
            Write-Warning ("L{0}: {1}" -f $err.Extent.StartLineNumber, $err.Message)
        }
    }
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($f in $fns) {
        $paramNames = @()
        if ($f.Parameters) { $paramNames = $f.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }
        elseif ($f.Body -and $f.Body.ParamBlock) { $paramNames = $f.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }
        [PSCustomObject]@{
            Kind   = 'Function'
            Line   = $f.Extent.StartLineNumber
            Name   = $f.Name
            Params = ($paramNames -join ', ')
        }
    }
    $raw = Get-Content $resolved.Path -Raw
    $aliases = [regex]::Matches($raw, 'Set-Alias\s+-Name\s+(\S+)\s+-Value\s+(\S+)')
    foreach ($m in $aliases) {
        [PSCustomObject]@{
            Kind   = 'Alias'
            Line   = $null
            Name   = $m.Groups[1].Value
            Params = "-> $($m.Groups[2].Value)"
        }
    }
}

# AST-based symbol search across .ps1 files. Regex matches on function names.
function psym {
    param(
        [Parameter(Position = 0)][string]$Pattern,
        [Parameter(Position = 1)][string]$Root = '.'
    )
    $resolved = Resolve-Path -LiteralPath $Root -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Root not found: $Root"; return }
    $results = [System.Collections.Generic.List[object]]::new()
    Get-ChildItem -Path $resolved -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $tokens = $null; $parseErrors = $null
        $ast = $null
        try { $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) }
        catch { return }
        if (-not $ast) { return }
        $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        foreach ($f in $fns) {
            if ([string]::IsNullOrEmpty($Pattern) -or $f.Name -match $Pattern) {
                $results.Add([PSCustomObject]@{
                        Name = $f.Name
                        Line = $f.Extent.StartLineNumber
                        File = $_.FullName
                    })
            }
        }
    }
    if ($results.Count -eq 0) { Write-Host 'No matches.' -ForegroundColor Yellow; return }
    $results | Sort-Object Name | Format-Table Name, Line, File -AutoSize
}

# PSScriptAnalyzer wrapper with useful presets. -Fix applies auto-fixes where possible.
function lint {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Path = '.',
        [ValidateSet('Standard', 'Strict', 'Security', 'CI')][string]$Mode = 'Standard',
        [switch]$Fix
    )
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        Write-Error 'PSScriptAnalyzer not installed. Install-Module PSScriptAnalyzer -Scope CurrentUser'
        return
    }
    Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue
    $splat = @{ Path = $Path; Recurse = $true }
    switch ($Mode) {
        'Strict' { $splat.Severity = @('Error', 'Warning', 'Information') }
        'Security' {
            $splat.IncludeRule = @(
                'PSAvoidUsingPlainTextForPassword',
                'PSAvoidUsingUsernameAndPasswordParams',
                'PSUsePSCredentialType',
                'PSAvoidUsingConvertToSecureStringWithPlainText',
                'PSAvoidUsingInvokeExpression',
                'PSAvoidUsingComputerNameHardcoded'
            )
        }
        'CI' {
            $splat.ExcludeRule = @(
                'PSAvoidUsingWriteHost',
                'PSAvoidUsingWMICmdlet',
                'PSUseShouldProcessForStateChangingFunctions',
                'PSUseBOMForUnicodeEncodedFile',
                'PSReviewUnusedParameter',
                'PSUseSingularNouns'
            )
        }
    }
    if ($Fix) { $splat.Fix = $true }
    $results = Invoke-ScriptAnalyzer @splat
    if (-not $results) { Write-Host 'No issues found.' -ForegroundColor Green; return }
    $byRule = $results | Group-Object RuleName | Sort-Object Count -Descending
    Write-Host ''
    foreach ($g in $byRule) {
        Write-Host ("[{0}] {1}" -f $g.Count, $g.Name) -ForegroundColor Cyan
        foreach ($r in $g.Group) {
            $color = switch ($r.Severity) { 'Error' { 'Red' } 'Warning' { 'Yellow' } default { 'DarkGray' } }
            $rel = try { Resolve-Path -LiteralPath $r.ScriptPath -Relative } catch { $r.ScriptPath }
            Write-Host ("  {0,-40} L{1,-5} {2}" -f $rel, $r.Line, $r.Message) -ForegroundColor $color
        }
    }
    Write-Host ''
    Write-Host ("Total: {0}" -f $results.Count) -ForegroundColor Magenta
}

# AST walker that finds unused parameters and top-level functions with no call sites in the same file.
function Find-DeadCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolved.Path, [ref]$tokens, [ref]$parseErrors)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

    Write-Host 'Unused parameters:' -ForegroundColor Cyan
    $anyUnused = $false
    foreach ($f in $fns) {
        $params = @()
        if ($f.Body -and $f.Body.ParamBlock) { $params = $f.Body.ParamBlock.Parameters }
        foreach ($p in $params) {
            $name = $p.Name.VariablePath.UserPath
            $refs = $f.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $n.VariablePath.UserPath -eq $name -and
                    $n.Extent.StartOffset -ne $p.Name.Extent.StartOffset
                }, $true)
            if (-not $refs -or $refs.Count -eq 0) {
                Write-Host ("  {0} L{1}: `${2}" -f $f.Name, $p.Extent.StartLineNumber, $name) -ForegroundColor Yellow
                $anyUnused = $true
            }
        }
    }
    if (-not $anyUnused) { Write-Host '  (none)' -ForegroundColor DarkGray }

    Write-Host ''
    Write-Host 'Possibly uncalled functions (same-file check):' -ForegroundColor Cyan
    $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.CommandElements[0].Extent.Text }
    $anyUncalled = $false
    foreach ($f in $fns) {
        if ($calls -notcontains $f.Name) {
            Write-Host ("  {0} (L{1})" -f $f.Name, $f.Extent.StartLineNumber) -ForegroundColor Yellow
            $anyUncalled = $true
        }
    }
    if (-not $anyUncalled) { Write-Host '  (none)' -ForegroundColor DarkGray }
}

# Profile self-diagnostics: version, policy, caches, tools, environment flags.
function Test-Profile {
    Write-Host 'Profile Diagnostics' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ("  PS Version:        {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
    Write-Host ("  Language Mode:     {0}" -f $ExecutionContext.SessionState.LanguageMode)
    Write-Host ("  Execution Policy:  {0}" -f (Get-ExecutionPolicy))
    Write-Host ("  Profile Path:      {0}" -f $PROFILE)
    Write-Host ("  Profile Exists:    {0}" -f (Test-Path $PROFILE))
    $userOverride = Join-Path (Split-Path $PROFILE) 'profile_user.ps1'
    Write-Host ("  profile_user.ps1:  {0}" -f $(if (Test-Path $userOverride) { 'present' } else { 'absent' }))
    $cache = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
    Write-Host ("  Cache Dir:         {0}" -f $cache)
    if (Test-Path $cache) {
        $cacheFiles = Get-ChildItem $cache -File -ErrorAction SilentlyContinue
        Write-Host ("  Cache Files:       {0}" -f $cacheFiles.Count)
        foreach ($cf in $cacheFiles) {
            $sz = if ($cf.Length -gt 1024) { '{0} KB' -f [math]::Round($cf.Length / 1KB, 1) } else { '{0} B' -f $cf.Length }
            Write-Host ("    {0,-28} {1}" -f $cf.Name, $sz) -ForegroundColor DarkGray
        }
    }
    Write-Host ("  Modules Loaded:    {0}" -f (Get-Module).Count)
    Write-Host ''
    Write-Host 'Managed Tools:' -ForegroundColor Cyan
    foreach ($tool in $script:ProfileTools) {
        $found = Get-Command $tool.Cmd -ErrorAction SilentlyContinue
        $status = if ($found) { 'OK' } else { 'MISSING' }
        $color = if ($found) { 'Green' } else { 'Yellow' }
        Write-Host ("  {0,-14} {1}" -f $tool.Cmd, $status) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host 'Environment:' -ForegroundColor Cyan
    Write-Host ("  Interactive:       {0}" -f $isInteractive)
    Write-Host ("  Admin:             {0}" -f $isAdmin)
    Write-Host ("  CI:                {0}" -f [bool]$env:CI)
    Write-Host ("  AI_AGENT:          {0}" -f [bool]$env:AI_AGENT)
}

# Enumerate every installed PowerShell (5.1 Desktop + all Core/7+ locations).
function Get-PwshVersions {
    $found = [System.Collections.Generic.List[object]]::new()
    $ps5 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps5) {
        try {
            $ver = (& $ps5 -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null)
            if ($ver) { $found.Add([PSCustomObject]@{ Edition = 'Desktop'; Version = $ver; Path = $ps5 }) }
        }
        catch { $null = $_ }
    }
    $candidates = @()
    $candidates += (Get-Command pwsh -ErrorAction SilentlyContinue -All | ForEach-Object { $_.Source })
    $candidates += (Get-ChildItem 'C:\Program Files\PowerShell' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'pwsh.exe' })
    $candidates += (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WindowsApps" -Filter 'pwsh*.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $candidates = $candidates | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
    foreach ($path in $candidates) {
        try {
            $ver = & $path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
            if ($ver) { $found.Add([PSCustomObject]@{ Edition = 'Core'; Version = $ver; Path = $path }) }
        }
        catch { $null = $_ }
    }
    if ($found.Count -eq 0) { Write-Warning 'No PowerShell installations found.'; return }
    $found | Sort-Object Edition, Version | Format-Table Edition, Version, Path -AutoSize
}

# Inspect an installed module: all versions, path, exports, signature.
# Emits one PSCustomObject per installed version so callers can filter/select.
function modinfo {
    param([Parameter(Mandatory)][string]$Name)
    $installed = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Sort-Object Version -Descending
    if (-not $installed) { Write-Warning "Module not found: $Name"; return }
    foreach ($m in $installed) {
        $signed = $null
        $signer = $null
        if ($m.Path) {
            $sig = Get-AuthenticodeSignature -LiteralPath $m.Path -ErrorAction SilentlyContinue
            if ($sig) {
                $signed = [string]$sig.Status
                if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            }
        }
        [PSCustomObject]@{
            Name        = $m.Name
            Version     = $m.Version
            ModuleType  = $m.ModuleType
            Path        = $m.Path
            Author      = $m.Author
            Description = $m.Description
            Requires    = if ($m.RequiredModules) { ($m.RequiredModules | ForEach-Object { $_.Name }) -join ', ' } else { '' }
            Functions   = $m.ExportedFunctions.Count
            Cmdlets     = $m.ExportedCmdlets.Count
            Aliases     = $m.ExportedAliases.Count
            Signed      = $signed
            Signer      = $signer
        }
    }
}

# AST-based code-pattern search (grep but structural). -Kind narrows to one AST node type.
function psgrep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Pattern,
        [Parameter(Position = 1)][string]$Root = '.',
        [ValidateSet('Command', 'Variable', 'String', 'Function', 'Any')][string]$Kind = 'Any'
    )
    $resolved = Resolve-Path -LiteralPath $Root -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Root not found: $Root"; return }
    $predicate = switch ($Kind) {
        'Command' { { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.CommandElements[0].Extent.Text -match $Pattern } }
        'Variable' { { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -match $Pattern } }
        'String' { { param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match $Pattern } }
        'Function' { { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -match $Pattern } }
        'Any' { { param($n) $n.Extent.Text -match $Pattern } }
    }
    Get-ChildItem -Path $resolved -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_.FullName
        $tokens = $null; $parseErrors = $null
        $ast = $null
        try { $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) }
        catch { return }
        if (-not $ast) { return }
        $hits = $ast.FindAll($predicate, $true)
        foreach ($h in $hits) {
            $snippet = ($h.Extent.Text -split "`r?`n")[0].Trim()
            if ($snippet.Length -gt 120) { $snippet = $snippet.Substring(0, 120) + '...' }
            Write-Host ("{0}:{1}: {2}" -f $file, $h.Extent.StartLineNumber, $snippet)
        }
    }
}

# Enhanced PSReadLine Configuration. Colors read from theme.json (shipped palette) and
# then overridden from user-settings.json (wizard / manual overrides). EditMode/BellStyle
# remain here as behavior defaults (users override via profile_user.ps1 or Set-PSReadLineOption).
$_readlineColors = $null
try {
    $_cachedTheme = Join-Path $cacheDir 'theme.json'
    if (Test-Path $_cachedTheme) {
        $_themeConfig = Get-Content $_cachedTheme -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($_themeConfig.psreadline -and $_themeConfig.psreadline.colors) {
            $_readlineColors = @{}
            foreach ($prop in $_themeConfig.psreadline.colors.PSObject.Properties) {
                $_readlineColors[$prop.Name] = $prop.Value
            }
        }
    }
    # Merge user-settings.json.psreadline.colors on top so wizard/manual overrides win.
    $_userSettingsForRL = Join-Path $cacheDir 'user-settings.json'
    if (Test-Path $_userSettingsForRL) {
        $_rlUser = Get-Content $_userSettingsForRL -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($_rlUser.psreadline -and $_rlUser.psreadline.colors) {
            if ($null -eq $_readlineColors) { $_readlineColors = @{} }
            foreach ($prop in $_rlUser.psreadline.colors.PSObject.Properties) {
                $_readlineColors[$prop.Name] = $prop.Value
            }
        }
    }
}
catch { $null = $_ }
$PSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    BellStyle                     = 'None'
}
if ($_readlineColors) { $PSReadLineOptions.Colors = $_readlineColors }
Set-PSReadLineOption @PSReadLineOptions

# PSReadLine features that require an interactive console host
if ($isInteractive -and (Get-Module PSReadLine)) {
    # Core-only prediction settings (PredictionSource/PredictionViewStyle don't exist on Desktop)
    # Guard against hosts without VT support (e.g. agent terminals, redirected output)
    # Disable via user-settings.json: { "features": { "predictions": false } }
    if ($PSVersionTable.PSEdition -eq "Core" -and $script:PSP.Features.predictions) {
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

    # Transient prompt: on Enter, redraw the current prompt using a minimal scriptblock so
    # the scrollback shows just the collapsed form. The full prompt still renders for the
    # NEW line after AcceptLine. Opt-in via features.transientPrompt in user-settings.json.
    # Customize via `$script:PSP.TransientPrompt = { ... }` in profile_user.ps1.
    if ($script:PSP.Features.transientPrompt) {
        Set-PSReadLineKeyHandler -Key Enter -BriefDescription TransientPrompt -Description 'Collapse the prior prompt to a minimal form before accepting' -ScriptBlock {
            $parseErrors = $null
            [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$null, [ref]$null, [ref]$parseErrors, [ref]$null)
            if ($parseErrors.Count -eq 0) {
                $originalPrompt = $Function:prompt
                try {
                    $Function:prompt = {
                        if ($script:PSP -and $script:PSP.TransientPrompt) {
                            try { & $script:PSP.TransientPrompt } catch { '$ ' }
                        }
                        else { '$ ' }
                    }
                    [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
                }
                finally { $Function:prompt = $originalPrompt }
            }
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        }
    }

    # fzf integration via PSFzf (fuzzy history search on Ctrl+R, file finder on Ctrl+T)
    # Disable via user-settings.json: { "features": { "psfzf": false } }
    if ($script:PSP.Features.psfzf -and (Get-Command fzf -ErrorAction SilentlyContinue)) {
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

    # Native tool completers. Each tool emits its own PowerShell completion script; we cache
    # it to disk so shell start does not launch a subprocess per tool. Cache is cleared by
    # Update-Profile (tool upgrades) and Clear-ProfileCache.
    $_nativeCompleters = @(
        @{ Cmd = 'kubectl'; Cache = 'kubectl-completion.ps1'; Args = @('completion', 'powershell') }
        @{ Cmd = 'gh';      Cache = 'gh-completion.ps1';      Args = @('completion', '-s', 'powershell') }
        @{ Cmd = 'docker';  Cache = 'docker-completion.ps1';  Args = @('completion', 'powershell') }
    )
    foreach ($_nc in $_nativeCompleters) {
        if (-not (Get-Command $_nc.Cmd -ErrorAction SilentlyContinue)) { continue }
        $_ncCachePath = Join-Path $cacheDir $_nc.Cache
        $_ncReady = (Test-Path $_ncCachePath) -and ((Get-Item $_ncCachePath -ErrorAction SilentlyContinue).Length -gt 0)
        if (-not $_ncReady) {
            try {
                $_ncOutput = & $_nc.Cmd @($_nc.Args) 2>$null | Out-String
                if ($_ncOutput -and $_ncOutput.Trim().Length -gt 0) {
                    [System.IO.File]::WriteAllText($_ncCachePath, $_ncOutput, [System.Text.UTF8Encoding]::new($false))
                    $_ncReady = $true
                }
            }
            catch { $null = $_ }
        }
        if ($_ncReady) {
            try { . $_ncCachePath }
            catch {
                # Corrupt cache; delete so next load regenerates.
                Remove-Item -LiteralPath $_ncCachePath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Tab-title context indicators (starship / p10k style): prepend venv/conda/AWS/K8s/jobs
    # to the base window title on every prompt. Kubernetes context is read directly from
    # ~/.kube/config (file read, no subprocess). Jobs-count only appears when > 0.
    $script:PSP.BaseTitle = "PowerShell {0}{1}" -f $PSVersionTable.PSVersion, $adminSuffix
    Register-ProfileHook -EventName PrePrompt -Action {
        try {
            $parts = @()
            if ($env:VIRTUAL_ENV) { $parts += "venv:$(Split-Path $env:VIRTUAL_ENV -Leaf)" }
            if ($env:CONDA_DEFAULT_ENV) { $parts += "conda:$env:CONDA_DEFAULT_ENV" }
            if ($env:AWS_PROFILE) { $parts += "aws:$env:AWS_PROFILE" }
            if ($env:AWS_VAULT) { $parts += "aws-vault:$env:AWS_VAULT" }
            # Kubernetes context via direct file read - zero subprocess overhead per prompt.
            $kubeConfig = Join-Path $HOME '.kube/config'
            if (Test-Path -LiteralPath $kubeConfig) {
                try {
                    $match = Select-String -Path $kubeConfig -Pattern '^current-context:\s*(.+)$' -ErrorAction Stop | Select-Object -First 1
                    if ($match) {
                        # YAML may quote the context value (current-context: "foo" or 'foo');
                        # strip surrounding quotes so the tab title shows `foo` not `"foo"`.
                        $kubeCtx = $match.Matches[0].Groups[1].Value.Trim().Trim('"').Trim("'")
                        if ($kubeCtx) { $parts += "k8s:$kubeCtx" }
                    }
                }
                catch { $null = $_ }
            }
            $jobCount = @(Get-Job -State Running -ErrorAction SilentlyContinue).Count
            if ($jobCount -gt 0) { $parts += "jobs:$jobCount" }

            $prefix = if ($parts.Count -gt 0) { '[' + ($parts -join ' ') + '] ' } else { '' }
            $base = if ($script:PSP.BaseTitle) { $script:PSP.BaseTitle } else { '' }
            try { $Host.UI.RawUI.WindowTitle = $prefix + $base } catch { $null = $_ }
        }
        catch { $null = $_ }
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
                    Invoke-PromptStage
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

# Query the profile command registry. Core commands are seeded at load time; plugins may
# add more via Register-ProfileCommand. Filter by category substring or name substring.
function Get-ProfileCommand {
    [CmdletBinding()]
    param(
        [string]$Category,
        [string]$Name
    )
    $cmds = @($script:PSP.Commands)
    if ($Category) { $cmds = $cmds | Where-Object { $_.Category -like "*$Category*" } }
    if ($Name) { $cmds = $cmds | Where-Object { $_.Name -like "*$Name*" } }
    $cmds | Sort-Object Category, Name
}

# First-run walkthrough. Shows each category plus a handful of commands and pauses between sections.
function Start-ProfileTour {
    if (-not [Environment]::UserInteractive) { Write-Warning 'Tour requires an interactive session.'; return }
    $categories = @($script:PSP.Commands | Group-Object Category | Sort-Object Name)
    if ($categories.Count -eq 0) { Write-Warning 'Command registry is empty. Is the profile loaded?'; return }
    $oldTitle = Push-TabTitle 'profile tour'
    try {
    Write-Host ''
    Write-Host 'PowerShellPerfect Tour' -ForegroundColor Cyan
    Write-Host '======================' -ForegroundColor Cyan
    Write-Host 'Press Enter to see each category, Ctrl+C to quit.' -ForegroundColor DarkGray
    Write-Host ''
    $null = Read-Host 'Ready'
    foreach ($cat in $categories) {
        Write-Host ''
        Write-Host ("-- {0} ({1} commands) --" -f $cat.Name, $cat.Count) -ForegroundColor Cyan
        foreach ($entry in ($cat.Group | Sort-Object Name | Select-Object -First 8)) {
            $synopsis = if ($entry.Synopsis) { $entry.Synopsis } else { '' }
            Write-Host ("  {0,-22} {1}" -f $entry.Name, $synopsis) -ForegroundColor Gray
        }
        if ($cat.Group.Count -gt 8) {
            Write-Host ("  ...{0} more (Get-ProfileCommand -Category '{1}')" -f ($cat.Group.Count - 8), $cat.Name) -ForegroundColor DarkGray
        }
        $null = Read-Host 'Press Enter'
    }
    Write-Host ''
    Write-Host 'Extend the profile:' -ForegroundColor Cyan
    Write-Host '  profile_user.ps1   - dot-sourced last; persistent overrides'
    Write-Host '  plugins\*.ps1      - drop files in %LOCALAPPDATA%\PowerShellProfile\plugins'
    Write-Host '  user-settings.json - features toggles, commandOverrides, trustedDirs'
    Write-Host '  .psprc.ps1         - per-directory profile (opt-in via Add-TrustedDirectory)'
    Write-Host ''
    Write-Host 'Tour complete.' -ForegroundColor Green
    }
    finally { Pop-TabTitle $oldTitle }
}

# Trust the given directory so its .psprc.ps1 auto-loads on cd. Default: current directory.
# Persists to user-settings.json so the trust survives profile reloads.
function Add-TrustedDirectory {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (-not $Path) { $Path = (Get-Location).ProviderPath }
    # Resolve-Path must succeed: a raw (unresolved) string in TrustedDirs would never equal
    # $PWD.ProviderPath later, silently breaking the trust check on cd into that directory.
    $resolved = try { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath }
    catch {
        Write-Error "Cannot trust '$Path': path does not exist or is not resolvable."
        return
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        Write-Error "Cannot trust '$resolved': not a directory."
        return
    }
    if ($script:PSP.TrustedDirs -contains $resolved) {
        Write-Host "Already trusted: $resolved" -ForegroundColor DarkGray
        return
    }
    if (-not $PSCmdlet.ShouldProcess($resolved, 'Trust for .psprc.ps1 auto-load')) { return }
    $script:PSP.TrustedDirs.Add($resolved)
    # Belt-and-suspenders: even though Save-TrustedDirectories is supposed to return $false on
    # failure, wrap in try/catch so any unexpected throw still triggers rollback and we never
    # report "Trusted:" when disk state doesn't match memory.
    $saved = $false
    try { $saved = Save-TrustedDirectories }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "Save failed: $($_.Exception.Message)"
    }
    if (-not $saved) {
        [void]$script:PSP.TrustedDirs.Remove($resolved)
        Write-Warning "Trust was not persisted. Fix user-settings.json and retry."
        return
    }
    Write-Host "Trusted: $resolved" -ForegroundColor Green
    if (Test-Path -LiteralPath (Join-Path $resolved '.psprc.ps1')) {
        Write-Host 'Reloading .psprc.ps1 now...' -ForegroundColor DarkGray
        try { . (Join-Path $resolved '.psprc.ps1') }
        catch { Write-Warning ".psprc.ps1 failed: $($_.Exception.Message)" }
    }
}

# Remove a directory from the trust list. Default: current directory.
# Accepts stale/deleted paths so users can clean up entries for directories that no longer
# exist. Matching is case-insensitive to mirror Windows filesystem semantics.
function Remove-TrustedDirectory {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (-not $Path) { $Path = (Get-Location).ProviderPath }
    $resolved = try { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath } catch { $Path }
    # Case-insensitive match so Windows path casing differences don't hide the entry.
    $match = $script:PSP.TrustedDirs | Where-Object { $_ -ieq $resolved } | Select-Object -First 1
    if (-not $match) {
        Write-Host "Not trusted: $resolved" -ForegroundColor DarkGray
        return
    }
    $resolved = $match
    if (-not $PSCmdlet.ShouldProcess($resolved, 'Remove from trusted directories')) { return }
    [void]$script:PSP.TrustedDirs.Remove($resolved)
    $saved = $false
    try { $saved = Save-TrustedDirectories }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "Save failed: $($_.Exception.Message)"
    }
    if (-not $saved) {
        [void]$script:PSP.TrustedDirs.Add($resolved)
        Write-Warning "Untrust was not persisted. Fix user-settings.json and retry."
        return
    }
    Write-Host "Untrusted: $resolved" -ForegroundColor Yellow
}

# Set or clear the Windows Terminal background image.
# Persists to user-settings.json (so Update-Profile re-applies it) and writes the change
# live to WT settings.json so open windows reload without a restart.
# Pass -Clear (or omit -Path) to remove the background. WT supports jpg/png/gif/tif/bmp.
function Set-TerminalBackground {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Position = 0)][string]$Path,
        [ValidateRange(0.0, 1.0)][double]$Opacity = 0.3,
        [ValidateSet('none', 'fill', 'uniform', 'uniformToFill')][string]$StretchMode = 'uniformToFill',
        [ValidateSet('center', 'left', 'top', 'right', 'bottom', 'topLeft', 'topRight', 'bottomLeft', 'bottomRight')][string]$Alignment = 'center',
        # When set, resize the image to this pixel width (preserving aspect ratio) before
        # applying. Windows Terminal has no native size knob, so resizing the source file
        # is the only way to get a smaller watermark. Resized copy is cached in the profile
        # cache dir and re-used if you pass the same width again.
        [ValidateRange(32, 4096)][int]$ResizeWidth,
        [switch]$Clear
    )
    $bgProps = @('backgroundImage', 'backgroundImageOpacity', 'backgroundImageStretchMode', 'backgroundImageAlignment')
    if (-not $Clear -and -not $Path) { Write-Error 'Usage: Set-TerminalBackground <path> | Set-TerminalBackground -Clear'; return }
    $resolved = $null
    if (-not $Clear) {
        try { $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath }
        catch { Write-Error "Image not found: $Path"; return }
        if ($resolved -notmatch '\.(jpg|jpeg|png|gif|tif|tiff|bmp)$') {
            Write-Warning 'Unusual image extension. Windows Terminal supports jpg/png/gif/tif/bmp.'
        }
        # Resize step. Writes resized PNG into $cacheDir\bg-<sourcename>-<width>.png so the
        # same input+width combination re-uses a cached copy and the next call is instant.
        if ($ResizeWidth) {
            try {
                Add-Type -AssemblyName System.Drawing -ErrorAction Stop
                $srcName = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
                $resizedPath = Join-Path $cacheDir ("bg-{0}-{1}.png" -f $srcName, $ResizeWidth)
                $regen = $true
                if (Test-Path -LiteralPath $resizedPath) {
                    $srcTime = (Get-Item -LiteralPath $resolved).LastWriteTimeUtc
                    $cachedTime = (Get-Item -LiteralPath $resizedPath).LastWriteTimeUtc
                    if ($cachedTime -ge $srcTime) { $regen = $false }
                }
                if ($regen) {
                    $img = [System.Drawing.Image]::FromFile($resolved)
                    try {
                        $h = [int]($img.Height * ($ResizeWidth / $img.Width))
                        $bmp = [System.Drawing.Bitmap]::new($ResizeWidth, $h)
                        $g = [System.Drawing.Graphics]::FromImage($bmp)
                        try {
                            $g.InterpolationMode = 'HighQualityBicubic'
                            $g.DrawImage($img, 0, 0, $ResizeWidth, $h)
                            $bmp.Save($resizedPath, [System.Drawing.Imaging.ImageFormat]::Png)
                        }
                        finally { $g.Dispose(); $bmp.Dispose() }
                    }
                    finally { $img.Dispose() }
                    Write-Host ("Resized to {0}px wide: {1}" -f $ResizeWidth, $resizedPath) -ForegroundColor DarkGray
                }
                $resolved = $resizedPath
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-Warning "Resize failed (using original image): $($_.Exception.Message)"
            }
        }
    }

    # 1. Persist to user-settings.json under defaults.*
    $settingsPath = Join-Path $cacheDir 'user-settings.json'
    try {
        $settings = Read-UserSettingsForWrite -Path $settingsPath
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not read user-settings.json: $($_.Exception.Message). Background not persisted."
        return
    }
    if (-not $settings.PSObject.Properties['defaults']) {
        $settings | Add-Member -NotePropertyName 'defaults' -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    foreach ($p in $bgProps) {
        if ($settings.defaults.PSObject.Properties[$p]) { $settings.defaults.PSObject.Properties.Remove($p) }
    }
    if (-not $Clear) {
        $settings.defaults | Add-Member -NotePropertyName 'backgroundImage' -NotePropertyValue $resolved -Force
        $settings.defaults | Add-Member -NotePropertyName 'backgroundImageOpacity' -NotePropertyValue $Opacity -Force
        $settings.defaults | Add-Member -NotePropertyName 'backgroundImageStretchMode' -NotePropertyValue $StretchMode -Force
        $settings.defaults | Add-Member -NotePropertyName 'backgroundImageAlignment' -NotePropertyValue $Alignment -Force
    }
    if ($PSCmdlet.ShouldProcess($settingsPath, 'Persist terminal background in user-settings.json')) {
        $json = $settings | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($settingsPath, $json, [System.Text.UTF8Encoding]::new($false))
    }

    # 2. Apply live to WT settings.json so change is visible immediately. Iterate ALL installed
    # WT variants (Stable / Preview / Canary / unpackaged) so multi-variant users get a
    # consistent background everywhere, not just whichever comes first in precedence order.
    $wtSettingsPaths = Get-WindowsTerminalSettingsPaths
    if (-not $wtSettingsPaths -or $wtSettingsPaths.Count -eq 0) {
        Write-Host 'Windows Terminal settings.json not found (Store/Preview/Canary/unpackaged). Change persisted; will apply after next Update-Profile.' -ForegroundColor DarkGray
        return
    }
    foreach ($wtSettingsPath in $wtSettingsPaths) {
        try {
            $wtRaw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncCommentPattern, ''
            $wt = $wtRaw | ConvertFrom-Json
            if (-not $wt.profiles) { $wt | Add-Member -NotePropertyName 'profiles' -NotePropertyValue ([PSCustomObject]@{}) -Force }
            if (-not $wt.profiles.defaults) { $wt.profiles | Add-Member -NotePropertyName 'defaults' -NotePropertyValue ([PSCustomObject]@{}) -Force }
            foreach ($p in $bgProps) {
                if ($wt.profiles.defaults.PSObject.Properties[$p]) { $wt.profiles.defaults.PSObject.Properties.Remove($p) }
            }
            if (-not $Clear) {
                $wt.profiles.defaults | Add-Member -NotePropertyName 'backgroundImage' -NotePropertyValue $resolved -Force
                $wt.profiles.defaults | Add-Member -NotePropertyName 'backgroundImageOpacity' -NotePropertyValue $Opacity -Force
                $wt.profiles.defaults | Add-Member -NotePropertyName 'backgroundImageStretchMode' -NotePropertyValue $StretchMode -Force
                $wt.profiles.defaults | Add-Member -NotePropertyName 'backgroundImageAlignment' -NotePropertyValue $Alignment -Force
            }
            if ($PSCmdlet.ShouldProcess($wtSettingsPath, 'Apply terminal background live')) {
                $wtJson = $wt | ConvertTo-Json -Depth 100
                [System.IO.File]::WriteAllText($wtSettingsPath, $wtJson, [System.Text.UTF8Encoding]::new($false))
            }
        }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning "Live apply to WT settings.json failed for $wtSettingsPath`: $($_.Exception.Message)"
        }
    }
    if ($Clear) { Write-Host 'Terminal background cleared.' -ForegroundColor Yellow }
    else { Write-Host ("Terminal background: {0} (opacity {1}, {2}, {3})" -f $resolved, $Opacity, $StretchMode, $Alignment) -ForegroundColor Green }
}

# Internal: read user-settings.json into a PSCustomObject. Throws on unreadable/invalid JSON
# so callers MUST wrap in try/catch (throw is used rather than Write-Error so the behavior
# is identical regardless of the caller's $ErrorActionPreference). Returns an empty
# PSCustomObject when the file does not exist (first run).
function Read-UserSettingsForWrite {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [PSCustomObject]@{} }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return [PSCustomObject]@{} }
    return $raw | ConvertFrom-Json -ErrorAction Stop
}

# Internal: persist $script:PSP.TrustedDirs to user-settings.json under trustedDirs.
# Returns $true on success, $false if the file could not be read or written. Never throws
# (except PipelineStoppedException) so callers can rely on the bool for rollback decisions
# regardless of $ErrorActionPreference.
function Save-TrustedDirectories {
    $settingsPath = Join-Path $cacheDir 'user-settings.json'
    try {
        $settings = Read-UserSettingsForWrite -Path $settingsPath
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not read user-settings.json: $($_.Exception.Message). Trust changes not persisted."
        return $false
    }
    $dirs = @($script:PSP.TrustedDirs)
    if ($settings.PSObject.Properties['trustedDirs']) {
        $settings.trustedDirs = $dirs
    }
    else {
        $settings | Add-Member -NotePropertyName 'trustedDirs' -NotePropertyValue $dirs -Force
    }
    try {
        $json = $settings | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($settingsPath, $json, [System.Text.UTF8Encoding]::new($false))
        return $true
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not write user-settings.json: $($_.Exception.Message)"
        return $false
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
${g}duration${r} - Elapsed time of the last command.
${g}Test-ProfileHealth${r} / ${g}psp-doctor${r} - Diagnose install: tools, caches, fonts, PATH.
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
${g}cdb${r} [N] - cd back N entries in directory history (default 1, previous dir).
${g}cdh${r} - List the cd history stack (most-recent first).

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
${g}winutil${r} [-ExpectedSha256 <hash>] [-Force] - Safe-by-default Chris Titus WinUtil fetch. Shows SHA256 + URL, then requires explicit confirmation before any execution.
${g}harden${r} - Open Harden Windows Security (prompts before launch).

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
${g}killports${r} / ${g}Stop-ListeningPort${r} - Interactive picker: lists all listening ports, pick one or many via fzf, kill.
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
${g}ssh${r} <user@host> - Wraps ssh.exe with ConnectTimeout=10 + keepalive so hangs respond to Ctrl+C.
${g}Copy-SshKey${r} / ${g}ssh-copy-key${r} <user@host> - Copy SSH key to remote.
${g}keygen${r} [name] - Generate ED25519 key pair.
${g}rdp${r} <host> - Launch RDP session.

${c}WSL${r} (when wsl.exe is installed)
${g}wsl${r} [args] - Wraps wsl.exe; sets tab title to distro name.
${g}Get-WslDistro${r} - List distros with state + version + default flag.
${g}Enter-WslHere${r} [-Distro] / ${g}wsl-here${r} - Open WSL shell in the current Windows directory.
${g}Get-WslFile${r} <distro> [path] [-Recurse] - List files in a distro via UNC (pipe-friendly).
${g}Show-WslTree${r} / ${g}wsl-tree${r} <distro> [path] [-Depth N] - Tree view (eza when available).
${g}Open-WslExplorer${r} / ${g}wsl-explorer${r} <distro> [path] - Open in Windows Explorer (GUI).
${g}ConvertTo-WslPath${r} <winpath> / ${g}ConvertTo-WindowsPath${r} <wslpath> - Path translation.
${g}Get-WslIp${r} [-Distro] - IPv4 of a running distro (for connecting to services).
${g}Stop-Wsl${r} [-Distro] - Shutdown all distros, or terminate one by name.

${c}Sysadmin${r}
${g}journal${r} [log] [-Count n] [-Follow] [-Level ...] - Tail Windows Event Log (journalctl-style).
${g}lsblk${r} - List disks and partitions with volume info.
${g}htop${r} - Interactive process viewer (uses btop/ntop/htop if installed, else svc -Live).
${g}mtr${r} <host> - Traceroute with per-hop ping stats.
${g}fwallow${r} / ${g}fwblock${r} <name> [-Port n] - Quick Windows Firewall rule (needs admin; supports -WhatIf/-Confirm).
${g}Find-FileLocker${r} <path> - Show which processes hold a file/folder lock (uses Restart-Manager API, same as Explorer).
${g}Stop-StuckProcess${r} <name|-Id n> [-Tree] - Escalating kill for processes that ignore Stop-Process.
${g}Remove-LockedItem${r} <path> [-Recurse] - Find lockers, kill them, then delete. For "file is in use" errors.

${c}Cybersec${r}
${g}nscan${r} <target> [-Mode Quick/Full/Services/Stealth/Vuln/Ports] - Curated nmap profiles.
${g}sigcheck${r} <path> - Authenticode signature details (file or directory).
${g}ads${r} <path> - List NTFS alternate data streams.
${g}defscan${r} [path] [-Mode Quick/Full] - Windows Defender scan wrapper.
${g}pwnd${r} <password> - HIBP k-anonymity breach lookup (only first 5 SHA1 chars leave the host).
${g}certcheck${r} <host> [port] - Full TLS probe: chain, SAN, SHA256 pin, cipher.
${g}entropy${r} <file> - Shannon entropy (detect packed/encrypted payloads).

${c}Developer+${r}
${g}serve${r} [port] [path] - One-line HTTP server (python or npx).
${g}gitignore${r} <lang...> - Generate .gitignore from gitignore.io.
${g}gcof${r} - Fuzzy git branch checkout (fzf).
${g}envload${r} [path] - Load .env file into current session.
${g}tldr${r} <cmd> - Quick command-example lookup (tldr-pages).
${g}repeat${r} <count> { cmd } [-UntilSuccess] [-DelaySeconds n] - Repeat a scriptblock.
${g}mkvenv${r} [name] - Create and activate a Python venv.

${c}Detection & AST${r}
${g}outline${r} <file> - List functions/params/aliases via AST parser.
${g}psym${r} [pattern] [root] - Symbol search across .ps1 files.
${g}lint${r} [path] [-Mode Standard/Strict/Security/CI] [-Fix] - PSScriptAnalyzer wrapper.
${g}Find-DeadCode${r} <file> - Unused params and same-file uncalled functions.
${g}Test-Profile${r} - Profile diagnostics: version, policy, caches, tools, env.
${g}Get-PwshVersions${r} - Enumerate every installed PowerShell.
${g}modinfo${r} <name> - Module details: path, version(s), exports, signature.
${g}psgrep${r} <pattern> [-Kind Command/Variable/String/Function] - AST-based code search.

${c}Clipboard${r}
${g}cpy${r} <text> - Copy to clipboard.  ${g}pst${r} - Paste from clipboard.
${g}icb${r} - Insert clipboard into prompt (never executes).

${c}Keybindings${r}
${g}Ctrl+R${r} - Fuzzy history search (fzf).  ${g}Ctrl+T${r} - Fuzzy file finder (fzf).
${g}Alt+V${r} - Smart paste into prompt.

${c}Extensibility${r}
${g}Get-ProfileCommand${r} [-Category ...] [-Name ...] - Query the command registry.
${g}Start-ProfileTour${r} - Interactive walkthrough of every category.
${g}Register-ProfileHook${r} -Event OnProfileLoad/PrePrompt/OnCd -Action { ... } - Hook lifecycle events.
${g}Register-HelpSection${r} -Title ... -Lines @(...) - Add a section to this help.
${g}Register-ProfileCommand${r} -Name ... -Category ... [-Synopsis ...] - Add to command registry.
${g}Add-TrustedDirectory${r} / ${g}Remove-TrustedDirectory${r} [path] - Trust a dir so .psprc.ps1 auto-loads.

${c}Theme${r}
${g}Set-TerminalBackground${r} <image> [-Opacity 0.3] [-StretchMode ...] [-Alignment ...] - Set WT background image (live + persisted).
${g}Set-TerminalBackground${r} -Clear - Remove the background image.

Extend the profile without forking:
  ${m}profile_user.ps1${r}                        - dot-sourced last; PS-level overrides.
  ${m}%LOCALAPPDATA%\PowerShellProfile\plugins\*.ps1${r} - drop-in plugins (auto-loaded).
  ${m}user-settings.json${r}                      - features toggles, commandOverrides, trustedDirs.
  ${m}.psprc.ps1${r}                              - per-directory profile (opt-in via Add-TrustedDirectory).
    For lasting functions/aliases inside .psprc.ps1, use ${g}function global:foo${r} or ${g}Set-Alias -Scope Global${r}.
    ${y}`$env:VAR = ...${r} always persists. Plain function/alias definitions are scoped and disappear after prompt render.
"@
    Write-Host $helpText
    if ($script:PSP -and $script:PSP.HelpSections.Count -gt 0) {
        foreach ($section in $script:PSP.HelpSections) {
            Write-Host ''
            Write-Host ("${c}$($section.Title)${r}")
            foreach ($line in $section.Lines) { Write-Host $line }
        }
    }
}

# Seed the command registry so Get-ProfileCommand and Start-ProfileTour return useful results.
# Data-only; plugins and profile_user.ps1 may append via Register-ProfileCommand.
$script:_seedCommands = @(
    @{ Name = 'Update-Profile'; Category = 'Profile'; Synopsis = 'Sync profile, theme, caches, WT settings' }
    @{ Name = 'Update-PowerShell'; Category = 'Profile'; Synopsis = 'Check for new PowerShell releases' }
    @{ Name = 'Update-Tools'; Category = 'Profile'; Synopsis = 'Upgrade winget-managed tools' }
    @{ Name = 'Edit-Profile'; Category = 'Profile'; Synopsis = 'Open profile in preferred editor' }
    @{ Name = 'Show-Help'; Category = 'Profile'; Synopsis = 'Show this help message' }
    @{ Name = 'reload'; Category = 'Profile'; Synopsis = 'Reload the profile in-place' }
    @{ Name = 'Clear-ProfileCache'; Category = 'Profile'; Synopsis = 'Reset caches except user settings' }
    @{ Name = 'Clear-Cache'; Category = 'Profile'; Synopsis = 'Clear user/system temp caches' }
    @{ Name = 'Uninstall-Profile'; Category = 'Profile'; Synopsis = 'Remove profile, caches, WT changes' }
    @{ Name = 'Invoke-ProfileWizard'; Category = 'Profile'; Synopsis = 'Re-run install wizard (alias: Reconfigure-Profile)' }
    @{ Name = 'Test-Profile'; Category = 'Profile'; Synopsis = 'Profile diagnostics' }
    @{ Name = 'gs'; Category = 'Git'; Synopsis = 'git status' }
    @{ Name = 'ga'; Category = 'Git'; Synopsis = 'git add .' }
    @{ Name = 'gc'; Category = 'Git'; Synopsis = 'git commit -m' }
    @{ Name = 'gpush'; Category = 'Git'; Synopsis = 'git push' }
    @{ Name = 'gpull'; Category = 'Git'; Synopsis = 'git pull' }
    @{ Name = 'gcl'; Category = 'Git'; Synopsis = 'git clone' }
    @{ Name = 'gcom'; Category = 'Git'; Synopsis = 'add + commit' }
    @{ Name = 'lazyg'; Category = 'Git'; Synopsis = 'add + commit + push' }
    @{ Name = 'g'; Category = 'Git'; Synopsis = 'zoxide jump to github dir' }
    @{ Name = 'gcof'; Category = 'Git'; Synopsis = 'Fuzzy git branch checkout (fzf)' }
    @{ Name = 'gitignore'; Category = 'Git'; Synopsis = 'Generate .gitignore from gitignore.io' }
    @{ Name = 'ls'; Category = 'Files'; Synopsis = 'eza listing' }
    @{ Name = 'la'; Category = 'Files'; Synopsis = 'eza listing with hidden' }
    @{ Name = 'll'; Category = 'Files'; Synopsis = 'eza long + git listing' }
    @{ Name = 'lt'; Category = 'Files'; Synopsis = 'eza tree listing' }
    @{ Name = 'cat'; Category = 'Files'; Synopsis = 'Syntax-highlighted viewer (bat)' }
    @{ Name = 'ff'; Category = 'Files'; Synopsis = 'Find files recursively' }
    @{ Name = 'nf'; Category = 'Files'; Synopsis = 'Create new file' }
    @{ Name = 'touch'; Category = 'Files'; Synopsis = 'Create file or update timestamp' }
    @{ Name = 'mkcd'; Category = 'Files'; Synopsis = 'Create dir and cd into it' }
    @{ Name = 'trash'; Category = 'Files'; Synopsis = 'Move to Recycle Bin' }
    @{ Name = 'extract'; Category = 'Files'; Synopsis = 'Universal archive extractor' }
    @{ Name = 'file'; Category = 'Files'; Synopsis = 'Identify file type via magic bytes' }
    @{ Name = 'sizeof'; Category = 'Files'; Synopsis = 'Human-readable size' }
    @{ Name = 'docs'; Category = 'Files'; Synopsis = 'Jump to Documents' }
    @{ Name = 'dtop'; Category = 'Files'; Synopsis = 'Jump to Desktop' }
    @{ Name = 'cdb'; Category = 'Files'; Synopsis = 'cd back N entries in history (default 1)' }
    @{ Name = 'cdh'; Category = 'Files'; Synopsis = 'List the cd history stack' }
    @{ Name = 'duration'; Category = 'Profile'; Synopsis = 'Show elapsed time of the last command' }
    @{ Name = 'Test-ProfileHealth'; Category = 'Profile'; Synopsis = 'Diagnose install: tools, caches, fonts, PATH, modules' }
    @{ Name = 'psp-doctor'; Category = 'Profile'; Synopsis = 'Alias for Test-ProfileHealth' }
    @{ Name = 'bak'; Category = 'Files'; Synopsis = 'Timestamped backup' }
    @{ Name = 'grep'; Category = 'Unix'; Synopsis = 'Search for pattern in files' }
    @{ Name = 'head'; Category = 'Unix'; Synopsis = 'First n lines' }
    @{ Name = 'tail'; Category = 'Unix'; Synopsis = 'Last n lines' }
    @{ Name = 'sed'; Category = 'Unix'; Synopsis = 'Find and replace in file' }
    @{ Name = 'which'; Category = 'Unix'; Synopsis = 'Show command path' }
    @{ Name = 'pgrep'; Category = 'Unix'; Synopsis = 'List processes by name' }
    @{ Name = 'pkill'; Category = 'Unix'; Synopsis = 'Kill processes by name' }
    @{ Name = 'export'; Category = 'Unix'; Synopsis = 'Set environment variable' }
    @{ Name = 'env'; Category = 'System'; Synopsis = 'Search/list environment variables' }
    @{ Name = 'admin'; Category = 'System'; Synopsis = 'Open elevated terminal' }
    @{ Name = 'pubip'; Category = 'System'; Synopsis = 'Public IP' }
    @{ Name = 'localip'; Category = 'System'; Synopsis = 'Local IPv4 addresses' }
    @{ Name = 'uptime'; Category = 'System'; Synopsis = 'System uptime' }
    @{ Name = 'sysinfo'; Category = 'System'; Synopsis = 'Detailed system info' }
    @{ Name = 'df'; Category = 'System'; Synopsis = 'Disk volumes' }
    @{ Name = 'svc'; Category = 'System'; Synopsis = 'htop-like process viewer' }
    @{ Name = 'path'; Category = 'System'; Synopsis = 'Display PATH entries' }
    @{ Name = 'eventlog'; Category = 'System'; Synopsis = 'Last event log entries' }
    @{ Name = 'winutil'; Category = 'System'; Synopsis = 'Fetch Chris Titus WinUtil (safe-by-default; -ExpectedSha256/-Force to run)' }
    @{ Name = 'harden'; Category = 'System'; Synopsis = 'Open Harden Windows Security (prompts before launch)' }
    @{ Name = 'hosts'; Category = 'System'; Synopsis = 'Open hosts file (elevated)' }
    @{ Name = 'wifipass'; Category = 'System'; Synopsis = 'Show saved WiFi passwords' }
    @{ Name = 'journal'; Category = 'Sysadmin'; Synopsis = 'Tail Windows Event Log' }
    @{ Name = 'lsblk'; Category = 'Sysadmin'; Synopsis = 'List disks and partitions' }
    @{ Name = 'htop'; Category = 'Sysadmin'; Synopsis = 'Interactive process viewer' }
    @{ Name = 'mtr'; Category = 'Sysadmin'; Synopsis = 'Traceroute + per-hop ping' }
    @{ Name = 'fwallow'; Category = 'Sysadmin'; Synopsis = 'Quick firewall allow rule (supports -WhatIf/-Confirm)' }
    @{ Name = 'fwblock'; Category = 'Sysadmin'; Synopsis = 'Quick firewall block rule (supports -WhatIf/-Confirm)' }
    @{ Name = 'flushdns'; Category = 'Network'; Synopsis = 'Clear DNS cache' }
    @{ Name = 'ports'; Category = 'Network'; Synopsis = 'Listening TCP ports' }
    @{ Name = 'checkport'; Category = 'Network'; Synopsis = 'Test TCP connectivity' }
    @{ Name = 'portscan'; Category = 'Network'; Synopsis = 'Quick TCP port scan' }
    @{ Name = 'tlscert'; Category = 'Network'; Synopsis = 'TLS certificate details' }
    @{ Name = 'ipinfo'; Category = 'Network'; Synopsis = 'IP geolocation lookup' }
    @{ Name = 'whois'; Category = 'Network'; Synopsis = 'WHOIS domain lookup' }
    @{ Name = 'nslook'; Category = 'Network'; Synopsis = 'DNS lookup' }
    @{ Name = 'weather'; Category = 'Network'; Synopsis = 'Weather lookup' }
    @{ Name = 'speedtest'; Category = 'Network'; Synopsis = 'Download speed test' }
    @{ Name = 'hash'; Category = 'Cybersec'; Synopsis = 'File hash (default SHA256)' }
    @{ Name = 'checksum'; Category = 'Cybersec'; Synopsis = 'Verify file hash' }
    @{ Name = 'genpass'; Category = 'Cybersec'; Synopsis = 'Random password (clipboard)' }
    @{ Name = 'b64'; Category = 'Cybersec'; Synopsis = 'Base64 encode' }
    @{ Name = 'b64d'; Category = 'Cybersec'; Synopsis = 'Base64 decode' }
    @{ Name = 'jwtd'; Category = 'Cybersec'; Synopsis = 'Decode JWT' }
    @{ Name = 'uuid'; Category = 'Cybersec'; Synopsis = 'Generate UUID' }
    @{ Name = 'urlencode'; Category = 'Cybersec'; Synopsis = 'URL encode' }
    @{ Name = 'urldecode'; Category = 'Cybersec'; Synopsis = 'URL decode' }
    @{ Name = 'epoch'; Category = 'Cybersec'; Synopsis = 'Unix timestamp converter' }
    @{ Name = 'vtscan'; Category = 'Cybersec'; Synopsis = 'VirusTotal quick scan' }
    @{ Name = 'nscan'; Category = 'Cybersec'; Synopsis = 'Nmap wrapper' }
    @{ Name = 'sigcheck'; Category = 'Cybersec'; Synopsis = 'Authenticode signature details' }
    @{ Name = 'ads'; Category = 'Cybersec'; Synopsis = 'Alternate data streams' }
    @{ Name = 'defscan'; Category = 'Cybersec'; Synopsis = 'Defender scan wrapper' }
    @{ Name = 'pwnd'; Category = 'Cybersec'; Synopsis = 'HIBP breach check' }
    @{ Name = 'certcheck'; Category = 'Cybersec'; Synopsis = 'TLS cert chain + pinning' }
    @{ Name = 'entropy'; Category = 'Cybersec'; Synopsis = 'Shannon entropy' }
    @{ Name = 'killport'; Category = 'Developer'; Synopsis = 'Kill process on TCP port' }
    @{ Name = 'Stop-ListeningPort'; Category = 'Developer'; Synopsis = 'Interactive picker for listening ports (alias: killports)' }
    @{ Name = 'Find-FileLocker'; Category = 'Sysadmin'; Synopsis = 'Show processes holding a file/folder lock' }
    @{ Name = 'Stop-StuckProcess'; Category = 'Sysadmin'; Synopsis = 'Escalating kill: Stop-Process -> taskkill /F -> /F /T' }
    @{ Name = 'Remove-LockedItem'; Category = 'Sysadmin'; Synopsis = 'Find lockers, kill, and delete (combo)' }
    @{ Name = 'http'; Category = 'Developer'; Synopsis = 'HTTP requests with auto JSON format' }
    @{ Name = 'prettyjson'; Category = 'Developer'; Synopsis = 'Pretty-print JSON' }
    @{ Name = 'hb'; Category = 'Developer'; Synopsis = 'Upload to hastebin' }
    @{ Name = 'timer'; Category = 'Developer'; Synopsis = 'Measure execution time' }
    @{ Name = 'watch'; Category = 'Developer'; Synopsis = 'Repeat command every n seconds' }
    @{ Name = 'serve'; Category = 'Developer'; Synopsis = 'One-line HTTP server' }
    @{ Name = 'envload'; Category = 'Developer'; Synopsis = 'Load .env file' }
    @{ Name = 'tldr'; Category = 'Developer'; Synopsis = 'Quick command examples' }
    @{ Name = 'repeat'; Category = 'Developer'; Synopsis = 'Repeat scriptblock N times' }
    @{ Name = 'mkvenv'; Category = 'Developer'; Synopsis = 'Create + activate Python venv' }
    @{ Name = 'outline'; Category = 'Detection'; Synopsis = 'AST outline of a .ps1 file' }
    @{ Name = 'psym'; Category = 'Detection'; Synopsis = 'Symbol search across .ps1 files' }
    @{ Name = 'lint'; Category = 'Detection'; Synopsis = 'PSScriptAnalyzer wrapper with presets' }
    @{ Name = 'Find-DeadCode'; Category = 'Detection'; Synopsis = 'Unused params / uncalled fns' }
    @{ Name = 'Get-PwshVersions'; Category = 'Detection'; Synopsis = 'All installed PowerShell versions' }
    @{ Name = 'modinfo'; Category = 'Detection'; Synopsis = 'Module details' }
    @{ Name = 'psgrep'; Category = 'Detection'; Synopsis = 'AST-based code search' }
    @{ Name = 'Copy-SshKey'; Category = 'SSH'; Synopsis = 'Copy SSH key to remote' }
    @{ Name = 'wsl'; Category = 'WSL'; Synopsis = 'Wraps wsl.exe; shows distro in tab title' }
    @{ Name = 'Get-WslDistro'; Category = 'WSL'; Synopsis = 'List installed distros with state + version' }
    @{ Name = 'Enter-WslHere'; Category = 'WSL'; Synopsis = 'Open WSL in current Windows directory (alias: wsl-here)' }
    @{ Name = 'ConvertTo-WslPath'; Category = 'WSL'; Synopsis = 'Windows -> WSL path (wslpath -a)' }
    @{ Name = 'ConvertTo-WindowsPath'; Category = 'WSL'; Synopsis = 'WSL -> Windows path (wslpath -w)' }
    @{ Name = 'Stop-Wsl'; Category = 'WSL'; Synopsis = 'Shutdown all distros or terminate one' }
    @{ Name = 'Get-WslIp'; Category = 'WSL'; Synopsis = 'Get IPv4 of a running distro' }
    @{ Name = 'Get-WslFile'; Category = 'WSL'; Synopsis = 'List files inside a distro via UNC; pipe-friendly' }
    @{ Name = 'Show-WslTree'; Category = 'WSL'; Synopsis = 'Tree view of a distro path (alias: wsl-tree)' }
    @{ Name = 'Open-WslExplorer'; Category = 'WSL'; Synopsis = 'Open distro in Windows Explorer (alias: wsl-explorer)' }
    @{ Name = 'keygen'; Category = 'SSH'; Synopsis = 'Generate ed25519 key pair' }
    @{ Name = 'rdp'; Category = 'SSH'; Synopsis = 'Launch RDP session' }
    @{ Name = 'cpy'; Category = 'Clipboard'; Synopsis = 'Copy text to clipboard' }
    @{ Name = 'pst'; Category = 'Clipboard'; Synopsis = 'Paste from clipboard' }
    @{ Name = 'icb'; Category = 'Clipboard'; Synopsis = 'Insert clipboard into prompt' }
    @{ Name = 'Get-ProfileCommand'; Category = 'Extensibility'; Synopsis = 'Query command registry' }
    @{ Name = 'Start-ProfileTour'; Category = 'Extensibility'; Synopsis = 'Interactive walkthrough' }
    @{ Name = 'Register-ProfileHook'; Category = 'Extensibility'; Synopsis = 'Hook lifecycle events' }
    @{ Name = 'Register-HelpSection'; Category = 'Extensibility'; Synopsis = 'Add section to Show-Help' }
    @{ Name = 'Register-ProfileCommand'; Category = 'Extensibility'; Synopsis = 'Register a command for discovery' }
    @{ Name = 'Add-TrustedDirectory'; Category = 'Extensibility'; Synopsis = 'Trust a dir for .psprc.ps1 auto-load' }
    @{ Name = 'Remove-TrustedDirectory'; Category = 'Extensibility'; Synopsis = 'Remove trusted directory' }
    @{ Name = 'Set-TerminalBackground'; Category = 'Theme'; Synopsis = 'Set/clear WT background image (live + persisted)' }
)
foreach ($entry in $script:_seedCommands) {
    $script:PSP.Commands.Add([PSCustomObject]$entry)
}
Remove-Variable -Name _seedCommands -Scope Script -ErrorAction SilentlyContinue

# User overrides (survives Update-Profile)
$userProfile = Join-Path (Split-Path $PROFILE) "profile_user.ps1"
if (Test-Path $userProfile) {
    try { . $userProfile }
    catch { Write-Warning "Failed to load profile_user.ps1: $_" }
}

# Consume user-settings.json: feature toggles, command overrides, trusted directories.
# This runs AFTER profile_user.ps1 so explicit PS-level overrides still win over JSON commandOverrides.
$userSettingsPath = Join-Path $cacheDir 'user-settings.json'
$script:UserSettings = $null
if (Test-Path $userSettingsPath) {
    try {
        $_rawSettings = Get-Content $userSettingsPath -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($_rawSettings)) {
            $script:UserSettings = $_rawSettings | ConvertFrom-Json -ErrorAction Stop
        }
    }
    catch { Write-Warning "user-settings.json unreadable: $($_.Exception.Message)" }
}
if ($script:UserSettings) {
    if ($script:UserSettings.PSObject.Properties['features']) {
        foreach ($prop in $script:UserSettings.features.PSObject.Properties) {
            if ($script:PSP.Features.ContainsKey($prop.Name)) {
                # Handle string "false"/"0" -> $false explicitly. Bare [bool] coerces any non-empty string to $true.
                $val = $prop.Value
                if ($val -is [string]) {
                    $script:PSP.Features[$prop.Name] = ($val -notmatch '^(?i:false|0|no|off|)$')
                }
                else {
                    $script:PSP.Features[$prop.Name] = [bool]$val
                }
            }
        }
    }
    if ($script:UserSettings.PSObject.Properties['trustedDirs']) {
        foreach ($d in @($script:UserSettings.trustedDirs | Where-Object { $_ })) {
            [void]$script:PSP.TrustedDirs.Add([string]$d)
        }
    }
    if ($script:UserSettings.PSObject.Properties['commandOverrides']) {
        $_overrideCount = @($script:UserSettings.commandOverrides.PSObject.Properties).Count
        if (-not $script:PSP.Features.commandOverrides) {
            # Security-significant feature: commandOverrides compiles JSON strings to scriptblocks.
            # Default-off; warn loudly if the user has entries but hasn't enabled the feature.
            if ($_overrideCount -gt 0 -and $isInteractive -and $script:PSP.Features.startupMessage) {
                Write-Host ("commandOverrides ignored ({0} entries): set features.commandOverrides = true in user-settings.json to apply." -f $_overrideCount) -ForegroundColor DarkYellow
            }
        }
        else {
            $_appliedOverrides = @()
            foreach ($prop in $script:UserSettings.commandOverrides.PSObject.Properties) {
                $_ovName = $prop.Name
                # Skip underscore-prefixed keys so documentation markers like `_note` in
                # user-settings.json examples never get compiled as real commands.
                if ($_ovName -like '_*') { continue }
                $_ovBody = [string]$prop.Value
                if ([string]::IsNullOrWhiteSpace($_ovBody)) { continue }
                try {
                    Remove-Item "function:$_ovName" -ErrorAction SilentlyContinue
                    Remove-Item "alias:$_ovName" -ErrorAction SilentlyContinue
                    Set-Item "function:$_ovName" -Value ([scriptblock]::Create($_ovBody))
                    $_appliedOverrides += $_ovName
                }
                catch { Write-Warning "commandOverride '$_ovName' failed: $($_.Exception.Message)" }
            }
            # Visible notice every interactive load so JSON-sourced code execution is not invisible.
            if ($_appliedOverrides.Count -gt 0 -and $isInteractive -and $script:PSP.Features.startupMessage) {
                Write-Host ("commandOverrides active ({0}): {1}" -f $_appliedOverrides.Count, ($_appliedOverrides -join ', ')) -ForegroundColor Yellow
            }
        }
    }
}

# Auto-load plugins from $cacheDir\plugins\*.ps1. Dot-sourced so they inherit script scope
# and can call Register-* APIs freely. Errors are isolated per plugin.
$pluginDir = Join-Path $cacheDir 'plugins'
if (-not (Test-Path $pluginDir)) {
    try { New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null } catch { $null = $_ }
}
if (Test-Path $pluginDir) {
    foreach ($plugin in (Get-ChildItem -Path $pluginDir -Filter *.ps1 -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try { . $plugin.FullName }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning "Plugin '$($plugin.Name)' failed to load: $($_.Exception.Message)"
        }
    }
}

# Update-check (opt-in). Fires at most once every 7 days when features.updateCheck = true
# and $isInteractive. Hits GitHub's commits API (~1 KB response) with a 3-second timeout so
# a slow network does not stall profile load. The first check writes the current main SHA
# as a baseline and only informs; subsequent checks notify when main has moved past that
# baseline. Update-Profile refreshes the baseline on successful apply.
if ($isInteractive -and $script:PSP.Features.updateCheck) {
    try {
        $_ucStampFile = Join-Path $cacheDir 'last-update-check.txt'
        $_ucDoCheck = $true
        if (Test-Path $_ucStampFile) {
            $_ucRaw = (Get-Content $_ucStampFile -Raw -ErrorAction SilentlyContinue).Trim()
            $_ucLast = [datetime]::MinValue
            if ([datetime]::TryParse($_ucRaw, [ref]$_ucLast)) {
                if (((Get-Date) - $_ucLast).TotalDays -lt 7) { $_ucDoCheck = $false }
            }
        }
        if ($_ucDoCheck) {
            # $repo_root is "https://raw.githubusercontent.com/<owner>"; derive owner for the API URL.
            $_ucOwner = ($repo_root -replace '^https?://(raw\.)?githubusercontent\.com/', '').Trim('/')
            $_ucApi = "https://api.github.com/repos/$_ucOwner/$repo_name/commits/main"
            $_ucLatest = $null
            try {
                $_ucResp = Invoke-RestMethod -Uri $_ucApi -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
                $_ucLatest = $_ucResp.sha
            }
            catch { $null = $_ }
            if ($_ucLatest) {
                $_ucBaselineFile = Join-Path $cacheDir 'applied-commit.sha'
                $_ucStored = if (Test-Path $_ucBaselineFile) { (Get-Content $_ucBaselineFile -Raw -ErrorAction SilentlyContinue).Trim() } else { $null }
                if (-not $_ucStored) {
                    # First check: record baseline so future checks can compare without false negatives.
                    [System.IO.File]::WriteAllText($_ucBaselineFile, $_ucLatest, [System.Text.UTF8Encoding]::new($false))
                    Write-Host ("Update-check enabled. Baseline: {0}. You'll see a notification here when main moves past this commit." -f $_ucLatest.Substring(0, 7)) -ForegroundColor DarkGray
                }
                elseif ($_ucStored -ne $_ucLatest) {
                    Write-Host ("Update available: main is at {0}... (applied {1}...). Run: Update-Profile" -f $_ucLatest.Substring(0, 7), $_ucStored.Substring(0, 7)) -ForegroundColor Yellow
                }
                # Only stamp on successful API response; a silent API failure should not
                # lock the user out of update notifications for 7 days.
                [System.IO.File]::WriteAllText($_ucStampFile, (Get-Date).ToString('o'), [System.Text.UTF8Encoding]::new($false))
            }
        }
    }
    catch { $null = $_ }
}

# Fire OnProfileLoad hooks (user/plugin extensions).
Invoke-ProfileHook -EventName 'OnProfileLoad'

# Startup complete - show load time
$profileStopwatch.Stop()
if ($isInteractive -and $script:PSP.Features.startupMessage) {
    Write-Host "Profile loaded in $($profileStopwatch.ElapsedMilliseconds)ms." -ForegroundColor DarkGray
    Write-Host "Use 'Show-Help' or 'Start-ProfileTour' to explore." -ForegroundColor Yellow
}
