### Install PowerShellPerfect: profile, tools, fonts, theme, and Windows Terminal settings.

<#
.SYNOPSIS
    Install the PowerShellPerfect profile with its tools, Nerd Font, Oh My Posh theme and Windows Terminal settings.

.DESCRIPTION
    Downloads Microsoft.PowerShell_profile.ps1, theme.json and terminal-config.json from one commit of
    26zl/PowerShellPerfect (or uses a local checkout), verifies them, and only then changes anything.

    No administrator rights are needed: the Nerd Font is installed for the current user and the telemetry
    opt-out is set for the current user (both machine-wide when the shell is elevated). winget installs
    eza, zoxide, fzf, bat, ripgrep and Oh My Posh and accepts the winget source and package agreements for you.

    Each run is logged to %LOCALAPPDATA%\PowerShellProfile\logs\setup-<timestamp>.log. Use -WhatIf to see the
    changes without making them, and Uninstall-Profile to revert them.

.PARAMETER Ref
    Branch, release tag (vX.Y.Z) or commit to install from. The ref is resolved to a commit so all files come
    from the same commit. A release tag is verified against the SHA256SUMS.txt published with the release.

.PARAMETER ExpectedSha256
    Combined SHA-256 of the install bundle (profile, theme.json, terminal-config.json), as printed by a previous
    run. Setup stops before changing anything when the downloaded bundle does not match.

.PARAMETER SkipHashCheck
    Install without verifying the bundle (trust on first use).

.PARAMETER LocalRepo
    Install from a local folder instead of downloading. A folder that holds setup.ps1 next to the profile files
    is used automatically unless -Ref or -ExpectedSha256 is given. With -ExpectedSha256 the local files are checked.
    A git checkout stores .ps1 files with CRLF line endings, so its hash differs from a release's (which covers the
    published LF files); a local run prints the hash of the files it installs.

.PARAMETER Wizard
    Run the interactive wizard (theme, color scheme, font, editor, features) even when it would be skipped.

.PARAMETER SkipWizard
    Do not run the wizard.

.PARAMETER Resume
    Resume an interrupted wizard run.

.PARAMETER CiMode
    Non-interactive run for CI and tests: no winget, fonts, PowerShell Gallery modules or prompts.

.PARAMETER Opacity
    Windows Terminal opacity (0-100) instead of the terminal-config.json default.

.PARAMETER ColorScheme
    Windows Terminal color scheme name instead of the theme.json default.

.PARAMETER FontSize
    Windows Terminal font size instead of the terminal-config.json default.

.EXAMPLE
    & .\setup.ps1 -Ref v1.0.0
    Install release v1.0.0; the downloaded files are checked against the release's SHA256SUMS.txt.

.EXAMPLE
    & .\setup.ps1 -Ref main -ExpectedSha256 <hash>
    Install the main branch pinned to the bundle hash printed by an earlier run.

.EXAMPLE
    .\setup.ps1 -WhatIf
    Show what setup would change without changing anything.

.NOTES
    Exit codes: 0 = the profile is installed (optional tools that were skipped or failed are listed in the summary);
    1 = nothing was applied (verification failed, unsupported system) or the profile could not be installed.
    When setup runs as a script block (the README install command) it sets $LASTEXITCODE instead of exiting and
    removes the variables it created in the caller's session. Invoke-Expression (irm | iex) is not supported.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(0, 100)]
    [int]$Opacity = 75,

    [string]$ColorScheme,

    [ValidateRange(6, 30)]
    [int]$FontSize = 11,

    # Copy profile assets from a local repository instead of GitHub.
    [string]$LocalRepo = '',

    [switch]$CiMode,

    # Control the interactive setup wizard, defaults, and resumable state.
    [switch]$Wizard,
    [switch]$SkipWizard,
    [switch]$Resume,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSha256,
    [switch]$SkipHashCheck,

    # Branch, tag (vX.Y.Z) or commit to install from.
    [ValidatePattern('^(?!.*\.\.)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')]
    [string]$Ref = 'main'
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# Run as a script block (the README install command), $script: is the caller's scope; the end of this file removes
# the variables setup adds there.
$callerScriptVariables = if ($PSCommandPath) { $null } else { @(Get-Variable -Scope Script -ErrorAction Ignore | ForEach-Object { $_.Name }) }

# Normalize known agent env vars to AI_AGENT (same as profile).
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) {
    $env:AI_AGENT = '1'
}

# Enforce TLS 1.2 for HTTPS requests on Windows PowerShell 5.1.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }
}

$script:RepoOwner = '26zl'
$script:RepoName = 'PowerShellPerfect'
# Nerd Fonts release the curated fonts are pinned to; each Sha256 below comes from that release's SHA-256.txt.
$script:NerdFontVersion = '3.5.1'
# Oh My Posh release the wizard's theme catalog and the preset themes come from.
$script:OmpThemesRef = 'v31.8.0'
$script:PinnedOmpThemes = @{
    pure   = 'E0786DA374967BF4B4D3B107580AC86246C132679C309291F378D73C1E804E5A'
    atomic = '30B2794D47C4015BD3B83680D314F9884050493E7E26B638D0CDA4A97442B2AF'
}
$script:BoundParameterNames = @($PSBoundParameters.Keys)
$script:Bundle = $null
$script:WorkDir = $null
$script:SourceCommit = $null
$script:BundleSha256 = $null
$script:WizardFontInstalled = $false
$script:WizardOmpTheme = $null
$script:WizardEditor = $null
$script:WizardTelemetryHandled = $false
$script:TranscriptStarted = $false
$script:ErrorReported = $false
$script:IsElevated = $false
try { $script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $null = $_ }
$script:IsCiHost = $CiMode -or [bool]$env:GITHUB_ACTIONS -or [bool]$env:CI
$script:CanPrompt = [Environment]::UserInteractive -and -not $script:IsCiHost -and -not [bool]$env:AI_AGENT
if ($script:CanPrompt) { try { $null = [Console]::KeyAvailable } catch { $script:CanPrompt = $false } }

# Write host output, dropping colors when the NO_COLOR environment variable is set (https://no-color.org).
function Write-PspHost {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)][object[]]$Object,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [switch]$NoNewline,
        [object]$Separator
    )
    process {
        $splat = @{}
        if ($null -ne $Object) { $splat.Object = $(if ($Object.Count -eq 1) { $Object[0] } else { $Object }) }
        if ($NoNewline) { $splat.NoNewline = $true }
        if ($PSBoundParameters.ContainsKey('Separator')) { $splat.Separator = $Separator }
        if ([string]::IsNullOrEmpty($env:NO_COLOR)) {
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $splat.ForegroundColor = $ForegroundColor }
            if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $splat.BackgroundColor = $BackgroundColor }
        }
        Write-Host @splat
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
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            Invoke-RestMethod -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $OutFile) -or (Get-Item -LiteralPath $OutFile).Length -eq 0) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
                throw 'Downloaded file is missing or empty'
            }
            return
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                Write-PspHost "  Download failed (attempt $attempt/$MaxAttempts): $_  Retrying in ${BackoffSec}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $BackoffSec
            }
            else {
                throw $_
            }
        }
    }
}

# Return the combined SHA-256 that pins a whole install bundle (profile, theme.json, terminal-config.json).
function Get-CombinedSha256 {
    param([Parameter(Mandatory)][string[]]$Parts)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($Parts -join ':')))
        ).Replace('-', '')
    }
    finally { $sha.Dispose() }
}

# Resolve a branch, tag or commit to its full commit SHA through the GitHub API ($null when offline or rate-limited).
function Resolve-PspCommitSha {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Ref,
        [int]$TimeoutSec = 10
    )
    if ($Ref -match '^[0-9a-fA-F]{40}$') { return $Ref.ToLowerInvariant() }
    try {
        $uri = 'https://api.github.com/repos/{0}/{1}/commits/{2}' -f $Owner, $Repo, [Uri]::EscapeDataString($Ref)
        $headers = @{ 'User-Agent' = 'PowerShellPerfect'; Accept = 'application/vnd.github.sha' }
        if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
        $sha = [string](Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop)
        if ($sha.Trim() -match '^[0-9a-f]{40}$') { return $sha.Trim() }
    }
    catch { $null = $_ }
    return $null
}

# Return the SHA-256 values a release publishes in SHA256SUMS.txt, keyed by file name ($null when the ref is not a release tag or the file is unavailable).
function Get-PspReleaseChecksums {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Tag,
        [int]$TimeoutSec = 15
    )
    if ($Tag -notmatch '^v\d+\.\d+\.\d+$') { return $null }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('psp-sums-' + [System.IO.Path]::GetRandomFileName())
    try {
        $uri = 'https://github.com/{0}/{1}/releases/download/{2}/SHA256SUMS.txt' -f $Owner, $Repo, $Tag
        Invoke-RestMethod -Uri $uri -OutFile $tmp -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        $sums = @{}
        foreach ($line in [System.IO.File]::ReadAllLines($tmp)) {
            if ($line -match '^([0-9A-Fa-f]{64})\s+\*?(\S+)\s*$') { $sums[$Matches[2]] = $Matches[1].ToUpperInvariant() }
        }
        if ($sums.Count -eq 0) { return $null }
        return $sums
    }
    catch { return $null }
    finally { [System.IO.File]::Delete($tmp) }
}

# Run a native command and capture its output; stderr never becomes a terminating error under ErrorActionPreference Stop.
function Invoke-SetupNative {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @ArgumentList 2>&1 | Out-String
    [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

# Delete a temporary folder this script created, only when it has the expected prefix and sits under the temp folder.
function Remove-SafeTempDirectory {
    param(
        [AllowNull()][string]$Path,
        [string]$NamePrefix = 'psp-'
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { return }
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $rootFull = [System.IO.Path]::GetFullPath($resolved.ProviderPath)
    $rootName = Split-Path -Path $rootFull -Leaf
    if ($rootName -like "$NamePrefix*" -and $rootFull.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $rootFull -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
    }
    else {
        Write-PspHost "  Skipped temp cleanup outside expected temp root: $rootFull" -ForegroundColor Yellow
    }
}

# Return $true when github.com answers over HTTPS (works through corporate proxies and firewalls).
function Test-InternetConnection {
    try {
        $response = Invoke-WebRequest -Uri 'https://github.com' -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        Write-PspHost 'Internet connection is required but not available (cannot reach github.com).' -ForegroundColor Red
        return $false
    }
}

# Locate or download the profile, theme.json and terminal-config.json and verify them before anything is changed.
function Initialize-InstallBundle {
    $names = [ordered]@{ Profile = 'Microsoft.PowerShell_profile.ps1'; Theme = 'theme.json'; Terminal = 'terminal-config.json' }
    $files = @{}
    if ($LocalRepo) {
        foreach ($key in $names.Keys) {
            $candidate = Join-Path $LocalRepo $names[$key]
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Local repo is missing $($names[$key]): $LocalRepo" }
            $files[$key] = (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }
    else {
        if (-not (Test-InternetConnection)) { throw 'No internet connection.' }
        # Resolve the ref once so all three files come from the same commit (the ref itself is used when the API is unreachable).
        $script:SourceCommit = Resolve-PspCommitSha -Owner $script:RepoOwner -Repo $script:RepoName -Ref $Ref
        $sourceRef = if ($script:SourceCommit) { $script:SourceCommit } else { $Ref }
        $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('psp-setup-' + [System.IO.Path]::GetRandomFileName())
        [void][System.IO.Directory]::CreateDirectory($script:WorkDir)
        Write-PspHost "Downloading the install bundle from $($script:RepoOwner)/$($script:RepoName)@$sourceRef" -ForegroundColor DarkGray
        foreach ($key in $names.Keys) {
            $target = Join-Path $script:WorkDir $names[$key]
            $uri = 'https://raw.githubusercontent.com/{0}/{1}/{2}/{3}' -f $script:RepoOwner, $script:RepoName, $sourceRef, $names[$key]
            Invoke-DownloadWithRetry -Uri $uri -OutFile $target -TimeoutSec 30
            $files[$key] = $target
        }
    }

    $hashes = @{}
    foreach ($key in $names.Keys) { $hashes[$key] = (Get-FileHash -LiteralPath $files[$key] -Algorithm SHA256).Hash }
    $combined = Get-CombinedSha256 -Parts @("profile:$($hashes.Profile)", "theme:$($hashes.Theme)", "terminal:$($hashes.Terminal)")
    $script:BundleSha256 = $combined

    if ($SkipHashCheck) {
        Write-PspHost 'Install bundle not verified (-SkipHashCheck).' -ForegroundColor Yellow
    }
    elseif ($ExpectedSha256) {
        if ($combined -ne $ExpectedSha256.ToUpperInvariant()) {
            # A git checkout converts .ps1 files to CRLF, so a release hash never matches it.
            $localHint = if ($LocalRepo) { ' Release hashes cover the published files; a git checkout has CRLF line endings and hashes differently.' } else { '' }
            throw "Combined hash mismatch. Expected $($ExpectedSha256.ToUpperInvariant()), got $combined.$localHint"
        }
        Write-PspHost "Install bundle verified: $combined" -ForegroundColor Green
    }
    elseif ($LocalRepo) {
        Write-PspHost "Installing from local files in $LocalRepo (not hash-checked). Bundle hash of these files: $combined" -ForegroundColor DarkGray
    }
    else {
        # A release tag is checked against the SHA256SUMS.txt published with that release.
        $sums = Get-PspReleaseChecksums -Owner $script:RepoOwner -Repo $script:RepoName -Tag $Ref
        if ($sums) {
            foreach ($key in $names.Keys) {
                if ($sums[$names[$key]] -ne $hashes[$key]) { throw "$($names[$key]) does not match the SHA256SUMS.txt of release $Ref." }
            }
            Write-PspHost "Install bundle matches the SHA256SUMS.txt of release $Ref." -ForegroundColor Green
        }
        else {
            $sourceRef = if ($script:SourceCommit) { $script:SourceCommit } else { $Ref }
            Write-PspHost 'Downloaded install bundle hashes:' -ForegroundColor Yellow
            Write-PspHost "  profile.ps1:       $($hashes.Profile)" -ForegroundColor Yellow
            Write-PspHost "  theme.json:        $($hashes.Theme)" -ForegroundColor Yellow
            Write-PspHost "  terminal-config:   $($hashes.Terminal)" -ForegroundColor Yellow
            Write-PspHost "  combined:          $combined" -ForegroundColor Yellow
            Write-PspHost 'Release tags (-Ref vX.Y.Z) are verified automatically against the release''s SHA256SUMS.txt.' -ForegroundColor DarkYellow
            Write-PspHost "For a branch or commit, check it out-of-band first: https://github.com/$($script:RepoOwner)/$($script:RepoName)/commit/$sourceRef" -ForegroundColor DarkYellow
            throw "Hash input required. Re-run with -Ref $sourceRef -ExpectedSha256 '$combined' (or -SkipHashCheck)."
        }
    }
    return [PSCustomObject]$files
}

# Shared helpers are loaded from the verified profile, so setup and the profile run the same code.
$script:SharedFunctionNames = @(
    'Get-PspCacheDir', 'ConvertTo-NativeArgumentLine', 'Get-Utf8FileText', 'Write-Utf8FileAtomic', 'ConvertFrom-JsonC', 'Read-JsonFile',
    'Get-PspProp', 'Get-PspArray', 'Get-PspPath', 'Test-PspProp', 'Set-PspProp', 'Remove-PspProp', 'Copy-PspObject',
    'ConvertTo-PspCanonicalJson', 'Test-PspJsonEqual', 'Get-PspComponentPins', 'Get-PspInstallState', 'Set-PspInstallState',
    'Get-ExternalCommandPath', 'Update-SessionPathFromRegistry', 'Get-WindowsTerminalSettingsPaths', 'Merge-JsonObject',
    'Read-WtChangeManifest', 'Save-WtChangeManifest', 'Add-WtChangeRecord', 'Set-WtRecordedValue', 'Set-WtRecordedArrayItem',
    'Set-WtRecordedKeybinding', 'Set-WtRecordedNoLogo', 'Update-WindowsTerminalSettingsFile', 'Get-OhMyPoshExecutablePath',
    'Get-PspUserSettingsTemplate', 'Merge-PspUserSettings', 'Test-PspTrustedThemeUrl', 'Read-UserSettingsForWrite', 'Get-PspShellPath',
    'Get-WtProfileList', 'Test-PspProfileFile', 'Get-PspOriginalProfileSource'
)

# Return the source text of the shared helper functions defined at the top level of a profile file.
function Get-SharedFunctionDefinitions {
    param([Parameter(Mandatory)][string]$ProfilePath, [Parameter(Mandatory)][string[]]$Names)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ProfilePath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) { throw "The profile has $($parseErrors.Count) parse error(s): $($parseErrors[0].Message)" }
    $defined = @{}
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $defined[$statement.Name] = $statement.Extent.Text }
    }
    $missing = @($Names | Where-Object { -not $defined.ContainsKey($_) })
    if ($missing.Count -gt 0) { throw "The profile does not define: $($missing -join ', ')" }
    foreach ($name in $Names) { $defined[$name] }
}

# Define the install wizard's curated Windows Terminal color schemes.
$script:CuratedSchemes = @(
    @{ Name = 'Tokyo Night'; Desc = 'Cool blue-purple, balanced for long coding sessions (default)'
        Scheme = @{ name = 'Tokyo Night'; background = '#1a1b26'; foreground = '#a9b1d6'; cursorColor = '#a9b1d6'; selectionBackground = '#33467c'
            black = '#32344a'; red = '#f7768e'; green = '#9ece6a'; yellow = '#e0af68'; blue = '#7aa2f7'; purple = '#ad8ee6'; cyan = '#449dab'; white = '#787c99'
            brightBlack = '#444b6a'; brightRed = '#ff7a93'; brightGreen = '#b9f27c'; brightYellow = '#ff9e64'; brightBlue = '#7da6ff'; brightPurple = '#bb9af7'; brightCyan = '#0db9d7'; brightWhite = '#acb0d0' } }
    @{ Name = 'Gruvbox Dark'; Desc = 'Retro warm yellow/orange/red, low-contrast and easy on the eyes'
        Scheme = @{ name = 'Gruvbox Dark'; background = '#282828'; foreground = '#ebdbb2'; cursorColor = '#ebdbb2'; selectionBackground = '#665c54'
            black = '#282828'; red = '#cc241d'; green = '#98971a'; yellow = '#d79921'; blue = '#458588'; purple = '#b16286'; cyan = '#689d6a'; white = '#a89984'
            brightBlack = '#928374'; brightRed = '#fb4934'; brightGreen = '#b8bb26'; brightYellow = '#fabd2f'; brightBlue = '#83a598'; brightPurple = '#d3869b'; brightCyan = '#8ec07c'; brightWhite = '#ebdbb2' } }
    @{ Name = 'Dracula'; Desc = 'Dark purple with vibrant pink/green/cyan accents'
        Scheme = @{ name = 'Dracula'; background = '#282a36'; foreground = '#f8f8f2'; cursorColor = '#f8f8f2'; selectionBackground = '#44475a'
            black = '#21222c'; red = '#ff5555'; green = '#50fa7b'; yellow = '#f1fa8c'; blue = '#bd93f9'; purple = '#ff79c6'; cyan = '#8be9fd'; white = '#f8f8f2'
            brightBlack = '#6272a4'; brightRed = '#ff6e6e'; brightGreen = '#69ff94'; brightYellow = '#ffffa5'; brightBlue = '#d6acff'; brightPurple = '#ff92df'; brightCyan = '#a4ffff'; brightWhite = '#ffffff' } }
    @{ Name = 'Catppuccin Mocha'; Desc = 'Soft pastel dark; popular with modern dev community'
        Scheme = @{ name = 'Catppuccin Mocha'; background = '#1e1e2e'; foreground = '#cdd6f4'; cursorColor = '#f5e0dc'; selectionBackground = '#585b70'
            black = '#45475a'; red = '#f38ba8'; green = '#a6e3a1'; yellow = '#f9e2af'; blue = '#89b4fa'; purple = '#f5c2e7'; cyan = '#94e2d5'; white = '#bac2de'
            brightBlack = '#585b70'; brightRed = '#f38ba8'; brightGreen = '#a6e3a1'; brightYellow = '#f9e2af'; brightBlue = '#89b4fa'; brightPurple = '#f5c2e7'; brightCyan = '#94e2d5'; brightWhite = '#a6adc8' } }
    @{ Name = 'Nord'; Desc = 'Cool arctic blues and frosty whites, minimal contrast'
        Scheme = @{ name = 'Nord'; background = '#2e3440'; foreground = '#d8dee9'; cursorColor = '#d8dee9'; selectionBackground = '#4c566a'
            black = '#3b4252'; red = '#bf616a'; green = '#a3be8c'; yellow = '#ebcb8b'; blue = '#81a1c1'; purple = '#b48ead'; cyan = '#88c0d0'; white = '#e5e9f0'
            brightBlack = '#4c566a'; brightRed = '#bf616a'; brightGreen = '#a3be8c'; brightYellow = '#ebcb8b'; brightBlue = '#81a1c1'; brightPurple = '#b48ead'; brightCyan = '#8fbcbb'; brightWhite = '#eceff4' } }
    @{ Name = 'One Half Dark'; Desc = 'Atom-inspired, balanced mid-contrast'
        Scheme = @{ name = 'One Half Dark'; background = '#282c34'; foreground = '#dcdfe4'; cursorColor = '#a3b3cc'; selectionBackground = '#474e5d'
            black = '#282c34'; red = '#e06c75'; green = '#98c379'; yellow = '#e5c07b'; blue = '#61afef'; purple = '#c678dd'; cyan = '#56b6c2'; white = '#dcdfe4'
            brightBlack = '#5d677a'; brightRed = '#e06c75'; brightGreen = '#98c379'; brightYellow = '#e5c07b'; brightBlue = '#61afef'; brightPurple = '#c678dd'; brightCyan = '#56b6c2'; brightWhite = '#dcdfe4' } }
    @{ Name = 'Solarized Dark'; Desc = 'Ethan Schoonover classic, low eye strain'
        Scheme = @{ name = 'Solarized Dark'; background = '#002b36'; foreground = '#839496'; cursorColor = '#93a1a1'; selectionBackground = '#073642'
            black = '#073642'; red = '#dc322f'; green = '#859900'; yellow = '#b58900'; blue = '#268bd2'; purple = '#d33682'; cyan = '#2aa198'; white = '#eee8d5'
            brightBlack = '#002b36'; brightRed = '#cb4b16'; brightGreen = '#586e75'; brightYellow = '#657b83'; brightBlue = '#839496'; brightPurple = '#6c71c4'; brightCyan = '#93a1a1'; brightWhite = '#fdf6e3' } }
)

# Map curated Nerd Font release assets to their Windows display names; Name is the menu label Select-WizardItem renders and matches on.
# Sha256 is the hash of <Asset>.zip in Nerd Fonts $script:NerdFontVersion.
$script:CuratedFonts = @(
    @{ Name = 'CascadiaCode';   Asset = 'CascadiaCode';   DisplayName = 'CaskaydiaCove NF';    Desc = 'Microsoft Cascadia + icons (default)'; Sha256 = '1298BF92698AFA06185CF1D05E6AE05F2D8A1E8C3CB45DDF4C3035168AB342A1' }
    @{ Name = 'JetBrainsMono';  Asset = 'JetBrainsMono';  DisplayName = 'JetBrainsMono NF';    Desc = 'JetBrains flagship, tight + readable'; Sha256 = 'FAB782A66F7D3019DA64F6572DB9FC5D3A4BCB19F9FA13E2D8A62E3693D6396E' }
    @{ Name = 'FiraCode';       Asset = 'FiraCode';       DisplayName = 'FiraCode NF';         Desc = 'Popular ligature font'; Sha256 = '239395BAF60C89B2EAF4862B6B09DB0EF95605CD3E8EEF51C00345822A81A665' }
    @{ Name = 'Meslo';          Asset = 'Meslo';          DisplayName = 'MesloLGM NF';         Desc = 'p10k default, excellent rendering'; Sha256 = 'FB104893ECD8F57E8AFACBC0A7086B42657120448D056D6093C728A9AFB8E237' }
    @{ Name = 'Hack';           Asset = 'Hack';           DisplayName = 'Hack NF';             Desc = 'Simple + workhorse'; Sha256 = 'FA24DA7DE7CEFE7766614D27762570B20453C852FC1D5B657111666DF9A5E449' }
    @{ Name = 'Iosevka';        Asset = 'Iosevka';        DisplayName = 'Iosevka NF';          Desc = 'Narrow monospace, space-efficient'; Sha256 = '0512C8561FDCFED03C5CAE130D1C01F279CFAD19467337F9EAB98A2B730ECC50' }
)

# Define editor choices and optional winget package IDs.
# Defined before the wizard runs: PowerShell only registers a function once its
# definition statement executes, so anything Start-InstallWizard calls must appear above it.
$EditorCandidates = @(
    @{ Cmd = 'code'; Display = 'Visual Studio Code'; WingetId = 'Microsoft.VisualStudioCode' }
    @{ Cmd = 'nvim'; Display = 'Neovim'; WingetId = 'Neovim.Neovim' }
    @{ Cmd = 'vim'; Display = 'Vim'; WingetId = 'vim.vim' }
    @{ Cmd = 'msedit'; Display = 'Microsoft Edit'; WingetId = 'Microsoft.Edit' }
    @{ Cmd = 'subl'; Display = 'Sublime Text'; WingetId = 'SublimeHQ.SublimeText.4' }
    @{ Cmd = 'notepad++'; Display = 'Notepad++'; WingetId = 'Notepad++.Notepad++' }
    @{ Cmd = 'notepad'; Display = 'Notepad (always available)'; WingetId = $null }
)

# Return the raw URL of an Oh My Posh theme at the pinned Oh My Posh release.
function Get-OmpThemeUrl {
    param([Parameter(Mandatory)][string]$Name, [string]$Ref = $script:OmpThemesRef)
    'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/{0}/themes/{1}.omp.json' -f $Ref, $Name
}

# Return one wizard choice from stdin, Out-GridView, or fzf.
function Select-WizardItem {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][array]$Items,      # array of hashtables with .Name and .Desc
        [string]$DefaultName,                      # pre-selected (Enter to accept)
        [string]$Note,                             # explanation line printed under the title
        [switch]$AllowSkip                         # Enter with no default = skip
    )
    Write-PspHost ''
    Write-PspHost ("-- {0} --" -f $Title) -ForegroundColor Cyan
    if ($Note) { Write-PspHost $Note }
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $marker = if ($DefaultName -and $Items[$i].Name -eq $DefaultName) { '>' } else { ' ' }
        $desc = if ($Items[$i].Desc) { " - $($Items[$i].Desc)" } else { '' }
        Write-PspHost ("  {0} [{1,2}] {2}{3}" -f $marker, ($i + 1), $Items[$i].Name, $desc)
    }
    $defaultHint = if ($DefaultName) { " (Enter = $DefaultName)" } elseif ($AllowSkip) { ' (Enter = skip)' } else { '' }
    $prompt = "Pick 1-$($Items.Count)$defaultHint"
    do {
        $raw = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($raw)) {
            if ($DefaultName) { return $Items | Where-Object { $_.Name -eq $DefaultName } | Select-Object -First 1 }
            if ($AllowSkip) { return $null }
            continue
        }
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) {
            return $Items[$n - 1]
        }
        # Allow a partial name too; wildcard characters in the reply are matched literally.
        $pattern = '*' + [WildcardPattern]::Escape($raw) + '*'
        $match = $Items | Where-Object { $_.Name -like $pattern } | Select-Object -First 1
        if ($match) { return $match }
        Write-PspHost "  Invalid; try again." -ForegroundColor Yellow
    } while ($true)
}

# Return the Oh My Posh themes of the pinned release; URLs are built from the pinned ref, not taken from the API.
function Get-OmpThemeList {
    param([string]$Ref = $script:OmpThemesRef)
    $apiUrl = 'https://api.github.com/repos/JanDeDobbeleer/oh-my-posh/contents/themes?ref={0}' -f [Uri]::EscapeDataString($Ref)
    try {
        $resp = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 15 -UseBasicParsing -Headers @{ 'User-Agent' = 'PowerShellPerfect-setup' } -ErrorAction Stop
    }
    catch { return @() }
    $themes = foreach ($item in @($resp)) {
        $itemName = [string](Get-PspProp $item 'name')
        if ($itemName -notmatch '^([A-Za-z0-9._-]+)\.omp\.json$') { continue }
        $baseName = $Matches[1]
        @{ Name = $baseName; Desc = ''; Url = (Get-OmpThemeUrl -Name $baseName -Ref $Ref); Sha256 = $script:PinnedOmpThemes[$baseName] }
    }
    return @($themes | Sort-Object { $_.Name })
}

# Merge non-null wizard choices into user-settings.json; a file that exists but does not parse is never overwritten.
function Save-WizardChoices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][hashtable]$Choices,
        [Parameter(Mandatory)][string]$UserSettingsPath
    )
    # Comments and trailing commas are accepted on both PowerShell editions.
    try { $s = Read-UserSettingsForWrite -Path $UserSettingsPath }
    catch { throw "user-settings.json could not be read ($($_.Exception.Message)). Fix or move $UserSettingsPath and run the wizard again; nothing was saved." }

    # The wizard writes this file before the install steps lay down their template, which is then
    # skipped as "already exists", so carry the header that explains what the file is for.
    if (-not $s.PSObject.Properties['_comment']) {
        $s | Add-Member -NotePropertyName '_comment' -NotePropertyValue 'User overrides for terminal, theme, and profile behavior. Only add keys you want to override.' -Force
    }

    # theme (OMP)
    if ($Choices.Theme) {
        $themeObj = [PSCustomObject]@{ name = $Choices.Theme.Name; url = $Choices.Theme.Url }
        $themeSha = Get-PspProp $Choices.Theme 'Sha256'
        if ($themeSha) { $themeObj | Add-Member -NotePropertyName 'sha256' -NotePropertyValue $themeSha -Force }
        $s | Add-Member -NotePropertyName 'theme' -NotePropertyValue $themeObj -Force
    }
    # windowsTerminal.colorScheme + scheme (color scheme)
    if ($Choices.Scheme) {
        if (-not $s.PSObject.Properties['windowsTerminal']) { $s | Add-Member -NotePropertyName 'windowsTerminal' -NotePropertyValue ([PSCustomObject]@{}) -Force }
        $s.windowsTerminal | Add-Member -NotePropertyName 'colorScheme' -NotePropertyValue $Choices.Scheme.name -Force
        $s.windowsTerminal | Add-Member -NotePropertyName 'scheme' -NotePropertyValue ([PSCustomObject]$Choices.Scheme) -Force
    }
    # windowsTerminal.theme + themeDefinition (tab-bar + application chrome theme)
    if ($Choices.TabBar) {
        if (-not $s.PSObject.Properties['windowsTerminal']) { $s | Add-Member -NotePropertyName 'windowsTerminal' -NotePropertyValue ([PSCustomObject]@{}) -Force }
        $appTheme = if ($Choices.AppTheme) { $Choices.AppTheme } else { 'dark' }
        $td = [PSCustomObject]@{
            name   = 'PSP.WizardTabs'
            tab    = [PSCustomObject]@{ background = $Choices.TabBar; unfocusedBackground = $Choices.TabBar }
            tabRow = [PSCustomObject]@{ background = $Choices.TabBar; unfocusedBackground = $Choices.TabBar }
            window = [PSCustomObject]@{ applicationTheme = $appTheme }
        }
        $s.windowsTerminal | Add-Member -NotePropertyName 'theme' -NotePropertyValue 'PSP.WizardTabs' -Force
        $s.windowsTerminal | Add-Member -NotePropertyName 'themeDefinition' -NotePropertyValue $td -Force
    }
    # defaults (font + background + terminal appearance)
    if ($Choices.Font -or $Choices.Background -or $Choices.Terminal) {
        if (-not $s.PSObject.Properties['defaults']) { $s | Add-Member -NotePropertyName 'defaults' -NotePropertyValue ([PSCustomObject]@{}) -Force }
    }
    if ($Choices.Font) {
        $fontObj = if ($s.defaults.PSObject.Properties['font']) { $s.defaults.font } else { [PSCustomObject]@{} }
        $fontObj | Add-Member -NotePropertyName 'face' -NotePropertyValue $Choices.Font.DisplayName -Force
        $s.defaults | Add-Member -NotePropertyName 'font' -NotePropertyValue $fontObj -Force
    }
    if ($Choices.Background -and $Choices.Background.Path) {
        $s.defaults | Add-Member -NotePropertyName 'backgroundImage' -NotePropertyValue $Choices.Background.Path -Force
        $s.defaults | Add-Member -NotePropertyName 'backgroundImageOpacity' -NotePropertyValue $Choices.Background.Opacity -Force
        $s.defaults | Add-Member -NotePropertyName 'backgroundImageStretchMode' -NotePropertyValue 'uniformToFill' -Force
        $s.defaults | Add-Member -NotePropertyName 'backgroundImageAlignment' -NotePropertyValue 'center' -Force
    }
    # Store terminal appearance defaults while preserving the selected font face.
    if ($Choices.Terminal) {
        foreach ($k in @($Choices.Terminal.Keys)) {
            $v = $Choices.Terminal[$k]
            if ($k -eq 'fontSize') {
                $fontObj = if ($s.defaults.PSObject.Properties['font']) { $s.defaults.font } else { [PSCustomObject]@{} }
                $fontObj | Add-Member -NotePropertyName 'size' -NotePropertyValue $v -Force
                $s.defaults | Add-Member -NotePropertyName 'font' -NotePropertyValue $fontObj -Force
            }
            else {
                $s.defaults | Add-Member -NotePropertyName $k -NotePropertyValue $v -Force
            }
        }
    }
    # features
    if ($Choices.Features) {
        if (-not $s.PSObject.Properties['features']) { $s | Add-Member -NotePropertyName 'features' -NotePropertyValue ([PSCustomObject]@{}) -Force }
        foreach ($k in @($Choices.Features.Keys)) {
            $s.features | Add-Member -NotePropertyName $k -NotePropertyValue $Choices.Features[$k] -Force
        }
    }
    # Derive PSReadLine colors from the selected terminal scheme when requested.
    if ($Choices.PSReadLine -eq 'scheme' -and $Choices.Scheme) {
        $sc = $Choices.Scheme
        $rl = [PSCustomObject]@{
            Command   = $sc.brightCyan
            Parameter = $sc.cyan
            Operator  = $sc.yellow
            Variable  = $sc.foreground
            String    = $sc.green
            Number    = $sc.brightBlue
            Type      = $sc.brightGreen
            Comment   = $sc.brightBlack
            Keyword   = $sc.purple
            Error     = $sc.red
        }
        if (-not $s.PSObject.Properties['psreadline']) { $s | Add-Member -NotePropertyName 'psreadline' -NotePropertyValue ([PSCustomObject]@{}) -Force }
        $s.psreadline | Add-Member -NotePropertyName 'colors' -NotePropertyValue $rl -Force
    }
    if (-not $PSCmdlet.ShouldProcess($UserSettingsPath, 'Save wizard choices')) { return }
    $dir = Split-Path -Parent $UserSettingsPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # The previous file is kept as user-settings.json.bak (its comments are not carried into the rewritten file).
    Write-Utf8FileAtomic -Path $UserSettingsPath -Content ($s | ConvertTo-Json -Depth 20) -BackupPath "$UserSettingsPath.bak"
}

# Return a yes/no choice with Enter mapped to the default.
function Read-WizardYesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $true)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $raw = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    return ($raw -match '^(?i:y|yes)$')
}

# Rebuild resumed wizard choices from the curated lists and range checks, so an edited state file cannot inject values.
function Resolve-WizardState {
    param([AllowNull()][object]$Saved)
    $steps = @('Theme', 'Scheme', 'Font', 'TabBar', 'Terminal', 'PSReadLine', 'Background', 'Editor', 'Telemetry', 'Features')
    $valid = @{
        Theme = $null; Scheme = $null; Font = $null; Features = $null; Background = $null; TabBar = $null; AppTheme = $null
        Terminal = $null; PSReadLine = $null; Editor = $null; TelemetryOptOut = $null; CompletedSteps = @()
    }
    $theme = Get-PspProp $Saved 'Theme'
    $themeName = [string](Get-PspProp $theme 'Name')
    $themeUrl = [string](Get-PspProp $theme 'Url')
    if ($themeName -match '^[A-Za-z0-9._-]+$' -and (Test-PspTrustedThemeUrl $themeUrl)) {
        $themeSha = [string](Get-PspProp $theme 'Sha256')
        $valid.Theme = @{ Name = $themeName; Url = $themeUrl; Sha256 = $(if ($themeSha -match '^[A-Fa-f0-9]{64}$') { $themeSha } else { $null }) }
    }
    $schemeName = [string](Get-PspProp (Get-PspProp $Saved 'Scheme') 'name')
    $curatedScheme = $script:CuratedSchemes | Where-Object { $_.Scheme.name -eq $schemeName } | Select-Object -First 1
    if ($curatedScheme) { $valid.Scheme = $curatedScheme.Scheme }
    $fontName = [string](Get-PspProp (Get-PspProp $Saved 'Font') 'Name')
    $curatedFont = $script:CuratedFonts | Where-Object { $_.Name -eq $fontName } | Select-Object -First 1
    if ($curatedFont) { $valid.Font = $curatedFont }
    $tabBar = [string](Get-PspProp $Saved 'TabBar')
    if ($tabBar -match '^#[0-9A-Fa-f]{6}$') { $valid.TabBar = $tabBar }
    $appTheme = [string](Get-PspProp $Saved 'AppTheme')
    if ($appTheme -in 'dark', 'light') { $valid.AppTheme = $appTheme }
    $terminal = Get-PspProp $Saved 'Terminal'
    if ($terminal) {
        $term = [ordered]@{}
        $intRanges = @{ opacity = @(1, 100); fontSize = @(8, 24); historySize = @(100, 1000000) }
        foreach ($key in $intRanges.Keys) {
            $n = 0
            if ([int]::TryParse([string](Get-PspProp $terminal $key), [ref]$n) -and $n -ge $intRanges[$key][0] -and $n -le $intRanges[$key][1]) { $term[$key] = $n }
        }
        if ((Get-PspProp $terminal 'useAcrylic') -eq $true) { $term['useAcrylic'] = $true }
        $cursor = [string](Get-PspProp $terminal 'cursorShape')
        if ($cursor -in 'bar', 'block', 'vintage', 'emptyBox', 'filledBox', 'doubleUnderscore') { $term['cursorShape'] = $cursor }
        $padding = [string](Get-PspProp $terminal 'padding')
        if ($padding -match '^(\d{1,2}), \1, \1, \1$' -and [int]$Matches[1] -le 50) { $term['padding'] = $padding }
        $scrollbar = [string](Get-PspProp $terminal 'scrollbarState')
        if ($scrollbar -in 'visible', 'hidden', 'always') { $term['scrollbarState'] = $scrollbar }
        if ($term.Count -gt 0) { $valid.Terminal = $term }
    }
    $readline = [string](Get-PspProp $Saved 'PSReadLine')
    if ($readline -in 'default', 'scheme') { $valid.PSReadLine = $readline }
    $background = Get-PspProp $Saved 'Background'
    $bgPath = [string](Get-PspProp $background 'Path')
    $bgOpacity = 0.0
    if ($bgPath -and (Test-Path -LiteralPath $bgPath -PathType Leaf) -and [double]::TryParse([string](Get-PspProp $background 'Opacity'), [ref]$bgOpacity) -and $bgOpacity -ge 0.05 -and $bgOpacity -le 0.5) {
        $valid.Background = @{ Path = (Resolve-Path -LiteralPath $bgPath).ProviderPath; Opacity = $bgOpacity }
    }
    $editor = [string](Get-PspProp $Saved 'Editor')
    if ($EditorCandidates | Where-Object { $_.Cmd -eq $editor }) { $valid.Editor = $editor }
    $telemetry = Get-PspProp $Saved 'TelemetryOptOut'
    if ($telemetry -is [bool]) { $valid.TelemetryOptOut = $telemetry }
    $features = Get-PspProp $Saved 'Features'
    if ($features) {
        $known = [ordered]@{}
        foreach ($key in 'psfzf', 'predictions', 'startupMessage', 'perDirProfiles', 'commandOverrides') {
            $value = Get-PspProp $features $key
            if ($value -is [bool]) { $known[$key] = $value }
        }
        if ($known.Count -gt 0) { $valid.Features = $known }
    }
    $valid.CompletedSteps = @((Get-PspArray $Saved 'CompletedSteps') | Where-Object { $steps -contains [string]$_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    return $valid
}

# Interactive editor preference prompt - returns chosen Cmd string
function Select-PreferredEditor {
    $defaultChoice = $null
    Write-PspHost ""
    Write-PspHost "  Select your preferred code editor:" -ForegroundColor Cyan
    Write-PspHost ""
    for ($i = 0; $i -lt $EditorCandidates.Count; $i++) {
        $ed = $EditorCandidates[$i]
        $num = $i + 1
        $installed = [bool](Get-Command $ed.Cmd -ErrorAction Ignore)
        if ($installed) {
            if ($null -eq $defaultChoice) { $defaultChoice = $i }
            Write-PspHost "   $num) $($ed.Display) ($($ed.Cmd)) " -NoNewline -ForegroundColor White
            Write-PspHost '[installed]' -ForegroundColor Green
        }
        else {
            Write-PspHost "   $num) $($ed.Display) ($($ed.Cmd))" -ForegroundColor DarkGray
        }
    }
    if ($null -eq $defaultChoice) { $defaultChoice = 0 }
    $defaultNum = $defaultChoice + 1
    Write-PspHost ""
    $reply = Read-Host "  Choice [$defaultNum]"
    if ([string]::IsNullOrWhiteSpace($reply)) {
        return $EditorCandidates[$defaultChoice].Cmd
    }
    $parsed = 0
    $chosen = $null
    if ([int]::TryParse($reply, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $EditorCandidates.Count) {
        $chosen = $EditorCandidates[$parsed - 1]
    }
    else {
        Write-PspHost "  Invalid choice, using default." -ForegroundColor Yellow
        return $EditorCandidates[$defaultChoice].Cmd
    }
    if (-not (Get-Command $chosen.Cmd -ErrorAction Ignore)) {
        Write-PspHost "  '$($chosen.Cmd)' is not installed." -ForegroundColor Yellow
        $confirm = Read-Host "  Use anyway? [y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-PspHost "  Using default instead." -ForegroundColor Yellow
            return $EditorCandidates[$defaultChoice].Cmd
        }
    }
    return $chosen.Cmd
}

# Return the main wizard choices as a hashtable for Save-WizardChoices.
function Start-InstallWizard {
    param([string]$StatePath)

    $choices = @{
        Theme           = $null   # @{ Name='atomic'; Url='...'; Sha256='...' }
        Scheme          = $null   # full scheme hashtable
        Font            = $null   # curated font entry
        Features        = $null   # hashtable
        Background      = $null   # @{ Path='...'; Opacity=0.15 }
        TabBar          = $null   # hex string
        AppTheme        = $null   # 'dark' | 'light' - WT window.applicationTheme
        Terminal        = $null   # ordered hashtable: opacity, fontSize, useAcrylic, cursorShape, padding, scrollbarState, historySize
        PSReadLine      = $null   # 'default' | 'scheme' - scheme derives from chosen color scheme
        Editor          = $null   # cmd name (code, nvim, notepad, ...)
        TelemetryOptOut = $null   # $true = set POWERSHELL_TELEMETRY_OPTOUT (user, or machine-wide when elevated)
        CompletedSteps  = @()
    }

    # Increment the state version whenever the wizard choice schema changes.
    $WIZARD_STATE_SCHEMA = 3

    # Resume from state file if caller passed one that exists
    if ($StatePath -and (Test-Path -LiteralPath $StatePath)) {
        try {
            $prev = Read-JsonFile $StatePath
            $prevSchema = if (Test-PspProp $prev 'schemaVersion') { [int]$prev.schemaVersion } else { 1 }
            if ($prevSchema -ne $WIZARD_STATE_SCHEMA) {
                Write-PspHost ''
                Write-PspHost ("Wizard state schema mismatch (found v{0}, expected v{1}); starting fresh." -f $prevSchema, $WIZARD_STATE_SCHEMA) -ForegroundColor Yellow
                Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
            }
            else {
                # Detect concurrent use of the wizard state file.
                $otherPid = if (Test-PspProp $prev 'ownerPid') { [int]$prev.ownerPid } else { 0 }
                $otherAlive = $false
                if ($otherPid -gt 0 -and $otherPid -ne $PID) {
                    try {
                        $otherProc = Get-Process -Id $otherPid -ErrorAction Stop
                        if ($otherProc -and $otherProc.ProcessName -match '^(pwsh|powershell)$') { $otherAlive = $true }
                    }
                    catch { $otherAlive = $false }
                }
                if ($otherAlive) {
                    Write-PspHost ''
                    Write-PspHost ("Another setup.ps1 wizard (PID {0}) appears to be running with this state file." -f $otherPid) -ForegroundColor Yellow
                    if (-not (Read-WizardYesNo -Prompt '  Take over anyway? (the other run will silently overwrite on its next save)' -Default $false)) {
                        throw 'WizardCancelled: concurrent wizard detected.'
                    }
                }
                Write-PspHost ''
                Write-PspHost ("Found wizard state from {0}." -f (Get-PspProp $prev 'Timestamp')) -ForegroundColor Yellow
                if (Read-WizardYesNo -Prompt 'Resume?' -Default $true) {
                    $choices = Resolve-WizardState -Saved (Get-PspProp $prev 'Choices')
                    Write-PspHost ("Resuming from step after: {0}" -f ($choices.CompletedSteps -join ', ')) -ForegroundColor DarkGray
                }
                else { Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue }
            }
        }
        catch {
            if ($_.Exception.Message -like 'WizardCancelled*') { throw }
            Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
        }
    }

    function Save-State {
        if (-not $StatePath) { return }
        $snap = @{ schemaVersion = $WIZARD_STATE_SCHEMA; Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); ownerPid = $PID; Choices = $choices }
        $stateDir = Split-Path -Parent $StatePath
        if ($stateDir -and -not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
        Write-Utf8FileAtomic -Path $StatePath -Content ($snap | ConvertTo-Json -Depth 20)
    }

    Write-PspHost ''
    Write-PspHost '=========================================' -ForegroundColor Magenta
    Write-PspHost '  PowerShellPerfect Install Wizard' -ForegroundColor Magenta
    Write-PspHost '=========================================' -ForegroundColor Magenta
    Write-PspHost '  Pick your cosmetics. All 145+ commands and extensibility APIs ship regardless.' -ForegroundColor DarkGray
    Write-PspHost '  Press Enter at any prompt to accept default / skip that step.' -ForegroundColor DarkGray

    # STEP 0: Offer the default preset before the full wizard on new runs.
    if ($choices.CompletedSteps.Count -eq 0) {
        Write-PspHost ''
        Write-PspHost '-- Quick start --' -ForegroundColor Cyan
        Write-PspHost '  Preset: Tokyo Night scheme, CascadiaCode Nerd Font, your first installed editor,' -ForegroundColor DarkGray
        Write-PspHost '  scheme-derived PSReadLine colors, dark chrome, default features.' -ForegroundColor DarkGray
        if (Read-WizardYesNo -Prompt '  Use quick-start defaults and skip the 10 steps?' -Default $false) {
            $tokyoNight = $script:CuratedSchemes | Where-Object { $_.Name -eq 'Tokyo Night' } | Select-Object -First 1
            $cascadia   = $script:CuratedFonts | Where-Object { $_.Asset -eq 'CascadiaCode' } | Select-Object -First 1
            $choices.Theme           = @{ Name = 'atomic'; Url = (Get-OmpThemeUrl -Name 'atomic'); Sha256 = $script:PinnedOmpThemes['atomic'] }
            if ($tokyoNight) { $choices.Scheme = $tokyoNight.Scheme }
            if ($cascadia)   { $choices.Font = $cascadia }
            $choices.TabBar          = if ($tokyoNight) { $tokyoNight.Scheme.background } else { '#1a1b26' }
            $choices.AppTheme        = 'dark'
            $choices.Terminal        = $null  # keep terminal-config.json defaults
            $choices.PSReadLine      = 'scheme'
            $choices.Background      = $null
            # The first editor that is already installed, so the preset never installs one (Notepad is always there).
            $installedEditor = $EditorCandidates | Where-Object { Get-Command $_.Cmd -ErrorAction Ignore } | Select-Object -First 1
            $choices.Editor          = if ($installedEditor) { $installedEditor.Cmd } else { 'notepad' }
            $choices.TelemetryOptOut = $false
            $choices.Features        = [ordered]@{ psfzf = $true; predictions = $true; startupMessage = $true; perDirProfiles = $true; commandOverrides = $false }
            $choices.CompletedSteps  = @('Theme', 'Scheme', 'Font', 'TabBar', 'Terminal', 'PSReadLine', 'Background', 'Editor', 'Telemetry', 'Features')
            Save-State
            Write-PspHost '  Quick-start preset applied. Jumping to summary.' -ForegroundColor Green
        }
    }

    # STEP 1: OMP theme
    if ('Theme' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost ("[1/10] Fetching the Oh My Posh {0} theme catalog..." -f $script:OmpThemesRef) -ForegroundColor Cyan
        $themes = Get-OmpThemeList
        if ($themes.Count -eq 0) {
            Write-PspHost '  (network failed or empty; keeping default "pure")' -ForegroundColor Yellow
            $choices.Theme = @{ Name = 'pure'; Url = (Get-OmpThemeUrl -Name 'pure'); Sha256 = $script:PinnedOmpThemes['pure'] }
        }
        else {
            Write-PspHost ("  {0} themes available. Type number, partial name, or Enter for 'pure' default." -f $themes.Count) -ForegroundColor DarkGray
            $pick = Select-WizardItem -Title 'Oh My Posh theme' -Items $themes -DefaultName 'pure'
            if ($pick) { $choices.Theme = $pick }
        }
        $choices.CompletedSteps += 'Theme'
        Save-State
    }

    # STEP 2: color scheme
    if ('Scheme' -notin $choices.CompletedSteps) {
        $pick = Select-WizardItem -Title 'Windows Terminal color scheme' -Items $script:CuratedSchemes -DefaultName 'Tokyo Night'
        if ($pick) { $choices.Scheme = $pick.Scheme }
        $choices.CompletedSteps += 'Scheme'
        Save-State
    }

    # STEP 3: Nerd Font
    if ('Font' -notin $choices.CompletedSteps) {
        $pick = Select-WizardItem -Title 'Nerd Font variant' -Items $script:CuratedFonts -DefaultName 'CascadiaCode'
        if ($pick) { $choices.Font = $pick }
        $choices.CompletedSteps += 'Font'
        Save-State
    }

    # STEP 4: tab-bar color
    if ('TabBar' -notin $choices.CompletedSteps) {
        $schemeBg = if ($choices.Scheme) { $choices.Scheme.background } else { '#1a1b26' }
        $tabPresets = @(
            @{ Name = "Scheme match ($schemeBg)"; Desc = 'Seamless - tab bar same as terminal background'; Value = $schemeBg }
            @{ Name = 'Pure black (#000000)'; Desc = 'Maximum contrast'; Value = '#000000' }
            @{ Name = 'Warm brown (#2a221d)'; Desc = 'Muted dark'; Value = '#2a221d' }
            @{ Name = 'Custom hex'; Desc = 'Type your own #rrggbb'; Value = 'custom' }
            @{ Name = 'Skip'; Desc = 'Leave WT default'; Value = $null }
        )
        $tabNote = '  The strip at the top where tabs live. Default matches chosen color scheme background.'
        $pick = Select-WizardItem -Title 'Tab bar color' -Items $tabPresets -DefaultName "Scheme match ($schemeBg)" -Note $tabNote
        if ($pick -and $pick.Value -eq 'custom') {
            $hex = Read-Host '  Hex (e.g. #1e1e2e)'
            if ($hex -match '^#[0-9A-Fa-f]{6}$') { $choices.TabBar = $hex }
        }
        elseif ($pick -and $pick.Value) { $choices.TabBar = $pick.Value }

        # Select dark or light Windows Terminal window chrome.
        $wantLight = Read-WizardYesNo -Prompt '  Use light window chrome (title bar, borders)?' -Default $false
        $choices.AppTheme = if ($wantLight) { 'light' } else { 'dark' }

        $choices.CompletedSteps += 'TabBar'
        Save-State
    }

    # STEP 5: Collect optional terminal appearance overrides.
    if ('Terminal' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost '-- Terminal appearance --' -ForegroundColor Cyan
        Write-PspHost '  Enter to keep current default for each field.' -ForegroundColor DarkGray
        $term = [ordered]@{}

        $opRaw = Read-Host '  Opacity 1-100 (default 75)'
        $opInt = 0
        if ($opRaw -and [int]::TryParse($opRaw, [ref]$opInt) -and $opInt -ge 1 -and $opInt -le 100) {
            $term['opacity'] = $opInt
        }

        $acrylicPrompt = Read-WizardYesNo -Prompt '  Use acrylic (translucent blur behind terminal)?' -Default $false
        if ($acrylicPrompt) { $term['useAcrylic'] = $true }

        $fsRaw = Read-Host '  Font size 8-24 (default 11)'
        $fsInt = 0
        if ($fsRaw -and [int]::TryParse($fsRaw, [ref]$fsInt) -and $fsInt -ge 8 -and $fsInt -le 24) {
            $term['fontSize'] = $fsInt
        }

        Write-PspHost '  Cursor shape: 1=bar 2=block 3=vintage 4=emptyBox 5=filledBox 6=doubleUnderscore' -ForegroundColor DarkGray
        $csRaw = Read-Host '  Cursor shape (default bar)'
        $csMap = @{ '1' = 'bar'; '2' = 'block'; '3' = 'vintage'; '4' = 'emptyBox'; '5' = 'filledBox'; '6' = 'doubleUnderscore' }
        if ($csRaw -and $csMap.ContainsKey($csRaw)) { $term['cursorShape'] = $csMap[$csRaw] }
        elseif ($csRaw -and ($csMap.Values -contains $csRaw)) { $term['cursorShape'] = $csRaw }

        $padRaw = Read-Host '  Cell padding in pixels 0-50 (default 8)'
        $padInt = 0
        if ($padRaw -and [int]::TryParse($padRaw, [ref]$padInt) -and $padInt -ge 0 -and $padInt -le 50) {
            $term['padding'] = "$padInt, $padInt, $padInt, $padInt"
        }

        Write-PspHost '  Scrollbar: 1=visible 2=hidden 3=always' -ForegroundColor DarkGray
        $sbRaw = Read-Host '  Scrollbar (default visible)'
        $sbMap = @{ '1' = 'visible'; '2' = 'hidden'; '3' = 'always' }
        if ($sbRaw -and $sbMap.ContainsKey($sbRaw)) { $term['scrollbarState'] = $sbMap[$sbRaw] }
        elseif ($sbRaw -and ($sbMap.Values -contains $sbRaw)) { $term['scrollbarState'] = $sbRaw }

        $hsRaw = Read-Host '  History size 100-1000000 (default 20000)'
        $hsInt = 0
        if ($hsRaw -and [int]::TryParse($hsRaw, [ref]$hsInt) -and $hsInt -ge 100 -and $hsInt -le 1000000) {
            $term['historySize'] = $hsInt
        }

        if ($term.Count -gt 0) { $choices.Terminal = $term }
        $choices.CompletedSteps += 'Terminal'
        Save-State
    }

    # STEP 6: Keep, derive, or skip PSReadLine syntax colors.
    if ('PSReadLine' -notin $choices.CompletedSteps) {
        $rlOptions = @(
            @{ Name = 'theme.json default'; Desc = 'Keep the shipped palette'; Value = 'default' }
            @{ Name = 'Derive from color scheme'; Desc = 'Map scheme ANSI roles to syntax (Command, String, ...)'; Value = 'scheme' }
            @{ Name = 'Skip'; Desc = 'No override; edit user-settings.json later'; Value = $null }
        )
        $pick = Select-WizardItem -Title 'PSReadLine syntax colors' -Items $rlOptions -DefaultName 'Derive from color scheme'
        if ($pick -and $pick.Value) { $choices.PSReadLine = $pick.Value }
        $choices.CompletedSteps += 'PSReadLine'
        Save-State
    }

    # STEP 7: background image
    if ('Background' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost '-- Background image (optional) --' -ForegroundColor Cyan
        if (Read-WizardYesNo -Prompt 'Set a background image?' -Default $false) {
            $bgPath = Read-Host '  Path to image (png/jpg/gif)'
            if ($bgPath -and (Test-Path -LiteralPath $bgPath -PathType Leaf)) {
                $opRaw = Read-Host '  Opacity 0.05-0.50 (Enter = 0.10)'
                $op = 0.10
                $tmp = 0.0
                if ($opRaw -and [double]::TryParse($opRaw, [ref]$tmp) -and $tmp -ge 0.05 -and $tmp -le 0.50) { $op = $tmp }
                $choices.Background = @{ Path = (Resolve-Path -LiteralPath $bgPath).ProviderPath; Opacity = $op }
            }
            else { Write-PspHost '  (no file found; skipping)' -ForegroundColor Yellow }
        }
        $choices.CompletedSteps += 'Background'
        Save-State
    }

    # STEP 8: Editor preference
    if ('Editor' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost '-- Preferred editor --' -ForegroundColor Cyan
        $choices.Editor = Select-PreferredEditor
        $choices.CompletedSteps += 'Editor'
        Save-State
    }

    # STEP 9: Offer telemetry opt-out when it is not already configured.
    if ('Telemetry' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost '-- PowerShell telemetry --' -ForegroundColor Cyan
        if (Test-TelemetryOptOutSet) {
            Write-PspHost '  POWERSHELL_TELEMETRY_OPTOUT is already set. No change.' -ForegroundColor DarkGray
            $choices.TelemetryOptOut = $false
        }
        else {
            $scopeLabel = if ($script:IsElevated) { 'machine-wide' } else { 'for your user account' }
            $choices.TelemetryOptOut = Read-WizardYesNo -Prompt "  Opt out of PowerShell telemetry? Sets POWERSHELL_TELEMETRY_OPTOUT=true $scopeLabel" -Default $false
        }
        $choices.CompletedSteps += 'Telemetry'
        Save-State
    }

    # STEP 10: feature toggles
    if ('Features' -notin $choices.CompletedSteps) {
        Write-PspHost ''
        Write-PspHost '-- Profile feature toggles --' -ForegroundColor Cyan
        $features = [ordered]@{}
        $features['psfzf']          = Read-WizardYesNo -Prompt '  PSFzf fuzzy search (Ctrl+R history, Ctrl+T files)?' -Default $true
        $features['predictions']    = Read-WizardYesNo -Prompt '  PSReadLine predictions (autocomplete suggestions)?' -Default $true
        $features['startupMessage'] = Read-WizardYesNo -Prompt '  Show "Profile loaded in Xms" at startup?' -Default $true
        $features['perDirProfiles'] = Read-WizardYesNo -Prompt '  Auto-load approved .psprc.ps1 files on cd into trusted dirs?' -Default $true
        $features['commandOverrides'] = Read-WizardYesNo -Prompt '  Allow user-settings.json commandOverrides (JSON -> scriptblock)?' -Default $false
        $choices.Features = $features
        $choices.CompletedSteps += 'Features'
        Save-State
    }

    # SUMMARY + confirm
    Write-PspHost ''
    Write-PspHost '=========================================' -ForegroundColor Magenta
    Write-PspHost '  Summary of your choices' -ForegroundColor Magenta
    Write-PspHost '=========================================' -ForegroundColor Magenta
    Write-PspHost ("  OMP theme:    {0}" -f $(if ($choices.Theme) { $choices.Theme.Name } else { '(default)' }))
    Write-PspHost ("  Color scheme: {0}" -f $(if ($choices.Scheme) { $choices.Scheme.name } else { '(default)' }))
    Write-PspHost ("  Nerd Font:    {0}" -f $(if ($choices.Font) { $choices.Font.DisplayName } else { '(default)' }))
    Write-PspHost ("  Tab bar:      {0}" -f $(if ($choices.TabBar) { "$($choices.TabBar) ($($choices.AppTheme) chrome)" } else { '(WT default)' }))
    Write-PspHost '  Terminal:'
    if ($choices.Terminal) {
        foreach ($k in @($choices.Terminal.Keys)) {
            Write-PspHost ("    {0,-16} = {1}" -f $k, $choices.Terminal[$k])
        }
    }
    else { Write-PspHost '    (all defaults)' -ForegroundColor DarkGray }
    Write-PspHost ("  PSReadLine:   {0}" -f $(if ($choices.PSReadLine) { $choices.PSReadLine } else { '(theme.json default)' }))
    Write-PspHost ("  Background:   {0}" -f $(if ($choices.Background) { "$($choices.Background.Path) @ $($choices.Background.Opacity)" } else { '(none)' }))
    Write-PspHost ("  Editor:       {0}" -f $(if ($choices.Editor) { $choices.Editor } else { '(prompted outside wizard)' }))
    Write-PspHost ("  Telemetry:    {0}" -f $(if ($choices.TelemetryOptOut) { 'opt out' } else { 'keep (no change)' }))
    Write-PspHost '  Features:'
    if ($choices.Features) {
        foreach ($k in @($choices.Features.Keys)) {
            Write-PspHost ("    {0,-18} = {1}" -f $k, $choices.Features[$k])
        }
    }
    Write-PspHost ''
    if (-not (Read-WizardYesNo -Prompt 'Apply all choices?' -Default $true)) {
        Write-PspHost 'Wizard cancelled. Re-run setup.ps1 -Wizard to start over, or -Resume to continue.' -ForegroundColor Yellow
        throw 'WizardCancelled'
    }
    # The caller removes the state file once the choices are saved, so a failed save can be resumed.
    return $choices
}

# Install a Nerd Font release asset for the current user (machine-wide when elevated), rejecting an archive whose hash differs.
function Install-NerdFonts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [string]$FontName = 'CascadiaCode',
        [string]$FontDisplayName = 'CaskaydiaCove NF',
        [string]$Version = $script:NerdFontVersion,
        # SHA-256 of <FontName>.zip from the release's SHA-256.txt.
        [string]$Sha256
    )

    $tempRoot = $null
    try {
        if ($FontName -notmatch '^[A-Za-z0-9]+$' -or $Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid font asset '$FontName' or version '$Version'." }
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        $fontCollection = New-Object System.Drawing.Text.InstalledFontCollection
        $fontFamilies = $fontCollection.Families.Name
        $fontCollection.Dispose()
        if ($fontFamilies -contains "${FontDisplayName}") {
            Write-PspHost "  ${FontDisplayName} already installed." -ForegroundColor Green
            return $true
        }
        $scopeLabel = if ($script:IsElevated) { 'all users' } else { 'the current user' }
        if (-not $PSCmdlet.ShouldProcess("$FontDisplayName (Nerd Fonts v$Version)", "Download and install the font for $scopeLabel")) { return $true }
        Write-PspHost "  Installing ${FontDisplayName} v${Version}..." -ForegroundColor Yellow
        $fontZipUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/v${Version}/${FontName}.zip"
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("psp-font-" + [System.IO.Path]::GetRandomFileName())
        $zipFilePath = Join-Path $tempRoot "${FontName}.zip"
        $extractPath = Join-Path $tempRoot "extract"

        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
        Invoke-DownloadWithRetry -Uri $fontZipUrl -OutFile $zipFilePath -TimeoutSec 60 -MaxAttempts 2
        $zipHash = (Get-FileHash -LiteralPath $zipFilePath -Algorithm SHA256).Hash
        if ($Sha256) {
            if ($zipHash -ne $Sha256.ToUpperInvariant()) { throw "Font archive hash mismatch (expected $Sha256, got $zipHash)" }
        }
        else {
            Write-PspHost "  No pinned hash for ${FontName}.zip v${Version}; archive SHA-256 $zipHash (not verified)." -ForegroundColor Yellow
        }

        Expand-Archive -LiteralPath $zipFilePath -DestinationPath $extractPath -Force
        $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
        # A shell font install lands machine-wide when elevated and per-user otherwise, so
        # presence must be checked in both stores - watching only the system one makes the
        # wait loop below time out and report failure after a perfectly good install.
        $fontStores = @(
            (Join-Path $env:SystemRoot 'Fonts')
            (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts')
        )
        $fontFiles = Get-ChildItem -LiteralPath $extractPath -Recurse -Filter "*.ttf"
        $copied = 0
        foreach ($f in $fontFiles) {
            $fontFileName = $f.Name
            if (-not @($fontStores | Where-Object { Test-Path -LiteralPath (Join-Path $_ $fontFileName) })) {
                $destination.CopyHere($f.FullName, 0x10)
                $copied++
            }
        }
        # CopyHere is async - wait for fonts to arrive before deleting source
        $pending = $null
        if ($copied -gt 0) {
            $timeout = 60; $elapsed = 0
            while ($elapsed -lt $timeout) {
                $pending = $fontFiles | Where-Object {
                    $fontFileName = $_.Name
                    -not @($fontStores | Where-Object { Test-Path -LiteralPath (Join-Path $_ $fontFileName) })
                }
                if (-not $pending) { break }
                Start-Sleep -Milliseconds 500
                $elapsed += 0.5
            }
        }

        Remove-SafeTempDirectory -Path $tempRoot -NamePrefix 'psp-font-'
        $tempRoot = $null
        if ($copied -gt 0 -and $pending) {
            # Report a partial font installation when files do not appear before timeout.
            Write-PspHost "  Font copy timed out: $(@($pending).Count) of $copied file(s) did not install." -ForegroundColor Red
            return $false
        }
        Write-PspHost "  ${FontDisplayName} installed." -ForegroundColor Green
        return $true
    }
    catch {
        Remove-SafeTempDirectory -Path $tempRoot -NamePrefix 'psp-font-'
        Write-PspHost "  Failed to install ${FontDisplayName}: $_" -ForegroundColor Red
        return $false
    }
}

# Download an Oh My Posh theme into the cache folder, verifying its SHA-256 when one is known.
function Install-OhMyPoshTheme {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [string]$ThemeName,
        [Parameter(Mandatory)]
        [string]$ThemeUrl,
        [string]$Sha256
    )
    if ($ThemeName -notmatch '^[A-Za-z0-9._-]+$') {
        Write-PspHost "  Refusing theme with an invalid name: $ThemeName" -ForegroundColor Red
        return $false
    }
    $cacheDir = Get-PspCacheDir
    $themeFilePath = Join-Path $cacheDir "$ThemeName.omp.json"
    $tempThemePath = $null
    try {
        if (-not (Test-PspTrustedThemeUrl $ThemeUrl)) {
            throw "Refusing to download theme from untrusted host: $ThemeUrl"
        }
        $alreadyValid = $false
        if (Test-Path -LiteralPath $themeFilePath -PathType Leaf) {
            try {
                if ($null -ne (Read-JsonFile $themeFilePath)) {
                    $alreadyValid = -not $Sha256 -or ((Get-FileHash -LiteralPath $themeFilePath -Algorithm SHA256).Hash -eq $Sha256.ToUpperInvariant())
                }
            }
            catch { $null = $_ }
        }
        if ($alreadyValid) {
            Write-PspHost "  Theme '$ThemeName' already present." -ForegroundColor Green
            return $true
        }
        if (-not $PSCmdlet.ShouldProcess($themeFilePath, "Download Oh My Posh theme '$ThemeName'")) { return $true }
        if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
        $tempThemePath = Join-Path $cacheDir ("{0}.{1}.download" -f $ThemeName, [System.IO.Path]::GetRandomFileName())
        Invoke-DownloadWithRetry -Uri $ThemeUrl -OutFile $tempThemePath
        if ($null -eq (Read-JsonFile $tempThemePath)) { throw 'Downloaded theme file is empty' }
        if ($Sha256) {
            $actual = (Get-FileHash -LiteralPath $tempThemePath -Algorithm SHA256).Hash
            if ($actual -ne $Sha256.ToUpperInvariant()) { throw "Theme hash mismatch (expected $Sha256, got $actual)" }
        }
        Move-Item -LiteralPath $tempThemePath -Destination $themeFilePath -Force
        $tempThemePath = $null
        Write-PspHost "  Theme '$ThemeName' downloaded." -ForegroundColor Green
        return $true
    }
    catch {
        Write-PspHost "  Failed to download/validate theme: $_" -ForegroundColor Red
        return $false
    }
    finally {
        if ($tempThemePath) { Remove-Item -LiteralPath $tempThemePath -Force -ErrorAction SilentlyContinue }
    }
}

# Install or verify a winget package; winget accepts the source and package agreements for the user.
function Install-WingetPackage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Id
    )
    $winget = Get-Command winget -CommandType Application -ErrorAction Ignore | Select-Object -First 1
    if (-not $winget) {
        Write-PspHost "  winget not found. Skipping $Name." -ForegroundColor Yellow
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($Name, "Install with winget ($Id), accepting the winget source and package agreements")) { return $true }
    $result = Invoke-SetupNative -FilePath $winget.Source -ArgumentList @('install', '-e', '--id', $Id, '--accept-source-agreements', '--accept-package-agreements')
    if ($result.ExitCode -eq 0) {
        Write-PspHost "  $Name installed." -ForegroundColor Green
        return $true
    }
    elseif ($result.ExitCode -eq -1978335185 -or $result.ExitCode -eq -1978335189) {
        # -1978335185 = already installed (winget install)
        # -1978335189 = no applicable update (winget upgrade)
        Write-PspHost "  $Name already installed." -ForegroundColor Green
        return $true
    }
    else {
        Write-PspHost "  $Name install may have failed (exit code: $($result.ExitCode))" -ForegroundColor Red
        return $false
    }
}

# Return the editor to configure, installing the chosen one with winget when it is missing.
function Resolve-ConfiguredEditor {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$RequestedEditor)
    $chosen = $EditorCandidates | Where-Object { $_.Cmd -eq $RequestedEditor } | Select-Object -First 1
    $resolvedEditor = $RequestedEditor
    if ($chosen -and $chosen.WingetId -and -not (Get-Command $RequestedEditor -ErrorAction Ignore)) {
        if ($script:IsCiHost) {
            Write-PspHost "  CI mode: skipping editor install for $($chosen.Display)." -ForegroundColor DarkGray
            $resolvedEditor = 'notepad'
        }
        elseif (Install-WingetPackage -Name $chosen.Display -Id $chosen.WingetId) {
            # Exclude empty PATH entries that Windows could interpret as the current directory.
            Update-SessionPathFromRegistry
        }
        else {
            Write-PspHost "  Could not install $($chosen.Display). Using Notepad." -ForegroundColor Yellow
            $resolvedEditor = 'notepad'
        }
    }
    return $resolvedEditor
}

# Point the editor preference in each profile_user.ps1 at the chosen editor, keeping a .bak copy of the previous file.
function Set-PreferredEditorInProfiles {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$EditorName,
        [Parameter(Mandatory)][string]$CommentLabel,
        [Parameter(Mandatory)][string[]]$ProfileDirs
    )
    # The name ends up inside a single-quoted PowerShell string.
    $editorLine = "`$script:EditorPriority = @('{0}', 'notepad')" -f ($EditorName -replace "'", "''")
    foreach ($dir in $ProfileDirs) {
        $userProfilePath = Join-Path $dir 'profile_user.ps1'
        if (-not (Test-Path -LiteralPath $userProfilePath -PathType Leaf)) { continue }
        $content = Get-Utf8FileText $userProfilePath
        if ($content -match '(?m)^\$script:EditorPriority\s*=') {
            $updated = [regex]::Replace($content, '(?m)^\$script:EditorPriority\s*=[^\r\n]*', $editorLine.Replace('$', '$$'))
        }
        else {
            $updated = $content.TrimEnd() + "`r`n`r`n# --- Preferred editor ($CommentLabel) ---`r`n$editorLine`r`n"
        }
        if ($updated -ceq $content) { continue }
        if ($PSCmdlet.ShouldProcess($userProfilePath, "Set the preferred editor to $EditorName")) {
            Write-Utf8FileAtomic -Path $userProfilePath -Content $updated -BackupPath "$userProfilePath.bak"
        }
    }
}

# Return $true when POWERSHELL_TELEMETRY_OPTOUT is already set for this user or machine-wide.
function Test-TelemetryOptOutSet {
    [bool]([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) -or
    [bool]([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'User'))
}

# Set POWERSHELL_TELEMETRY_OPTOUT (machine-wide when elevated, otherwise for this user) and record it so uninstall removes only what setup set.
function Set-TelemetryOptOut {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$CacheDir)
    $scope = if ($script:IsElevated) { 'Machine' } else { 'User' }
    if (-not $PSCmdlet.ShouldProcess("POWERSHELL_TELEMETRY_OPTOUT ($scope)", 'Set to true')) { return }
    try {
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', $scope)
        if (-not (Test-Path -LiteralPath $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
        Write-Utf8FileAtomic -Path (Join-Path $CacheDir 'telemetry.owned') -Content ("set by setup.ps1 at {0}`nscope: {1}`n" -f (Get-Date -Format o), $scope)
        Write-PspHost "  Telemetry opt-out applied ($($scope.ToLowerInvariant()) scope)." -ForegroundColor Green
    }
    catch {
        Write-PspHost "  Failed to set POWERSHELL_TELEMETRY_OPTOUT: $_" -ForegroundColor Yellow
    }
}

# Copy the profile into both edition folders with backups; returns $true when every copy succeeded.
function Install-ProfileFiles {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string[]]$ProfileDirs)
    $allOk = $true
    foreach ($dir in $ProfileDirs) {
        $targetProfile = Join-Path $dir 'Microsoft.PowerShell_profile.ps1'
        if (-not $PSCmdlet.ShouldProcess($targetProfile, 'Install the profile (the current one is backed up)')) { continue }
        $staged = $null
        try {
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            # Stage next to the target first so a failed copy never leaves a partial profile.
            $staged = Join-Path $dir ('.psp-new-' + [System.IO.Path]::GetRandomFileName() + '.ps1')
            Copy-Item -LiteralPath $Source -Destination $staged -Force
            if (Test-Path -LiteralPath $targetProfile -PathType Leaf) {
                # Preserve the pre-install profile once as an immutable copy that rotation never deletes
                # and Uninstall-Profile restores; oldprofile* rotation below never matches this name.
                $originalBackup = Join-Path $dir 'profile.original.ps1'
                # Earlier versions could save an installed copy of this profile as the original; such a copy is replaced.
                $originalIsOurs = (Test-Path -LiteralPath $originalBackup) -and (Test-PspProfileFile -Path $originalBackup)
                if ($originalIsOurs -or -not (Test-Path -LiteralPath $originalBackup)) {
                    # The current profile, or when that is this profile already, the oldest backup that is not.
                    $originalSource = Get-PspOriginalProfileSource -Directory $dir
                    if ($originalSource) {
                        Copy-Item -LiteralPath $originalSource -Destination $originalBackup -Force
                        Write-PspHost "  Original profile saved to [$originalBackup]" -ForegroundColor DarkGray
                    }
                    elseif ($originalIsOurs) { Remove-Item -LiteralPath $originalBackup -Force }
                }
                # Keep the latest five timestamped profile backups; a failed backup stops this copy.
                $backupPath = Join-Path $dir ('oldprofile.{0}.ps1' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
                Copy-Item -LiteralPath $targetProfile -Destination $backupPath -Force
                Write-PspHost "  Backup saved to [$backupPath]" -ForegroundColor DarkGray
                Get-ChildItem -LiteralPath $dir -Filter 'oldprofile*.ps1' -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
                    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
            }
            Move-Item -LiteralPath $staged -Destination $targetProfile -Force
            $staged = $null
            Write-PspHost "  Profile installed at [$targetProfile]" -ForegroundColor Green

            # Create starter user override file if it doesn't exist (never overwrite)
            $userProfilePath = Join-Path $dir 'profile_user.ps1'
            if (-not (Test-Path -LiteralPath $userProfilePath)) {
                $userProfileContent = @'
### Persistent personal overrides loaded by the main profile.

# --- Preferred editor (used by the edit command) ---
# $script:EditorPriority = @('code', 'notepad')

# --- Custom aliases ---
# Set-Alias -Name myalias -Value Get-ChildItem

# --- Custom functions ---
# function hello { Write-Host "Hello, $env:USERNAME!" }

# --- Override PSReadLine colors ---
# Set-PSReadLineOption -Colors @{ Command = '#61AFEF'; String = '#98C379' }

# --- Import additional modules ---
# Import-Module posh-git
'@
                Write-Utf8FileAtomic -Path $userProfilePath -Content $userProfileContent
                Write-PspHost "  User override file created at [$userProfilePath]" -ForegroundColor Green
            }
            else {
                Write-PspHost "  User override file already exists at [$userProfilePath] (preserved)" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-PspHost "  Failed to install profile at [$targetProfile]: $_" -ForegroundColor Red
            $allOk = $false
        }
        finally {
            if ($staged) { Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue }
        }
    }
    return $allOk
}

# Run every install step after the bundle is verified; returns $true when the profile was installed.
function Invoke-SetupInstall {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][object]$Bundle)

    $configCachePath = Get-PspCacheDir
    if ($script:IsElevated) {
        Write-PspHost 'Running elevated is not required: fonts and the telemetry opt-out apply machine-wide, and the terminal is not restarted at the end.' -ForegroundColor DarkYellow
    }

    # Report restrictive execution policies; only the CurrentUser scope is ever changed, and only with consent.
    $currentUserPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if ($currentUserPolicy -eq 'AllSigned') {
        if ($script:CanPrompt -and -not $WhatIfPreference) {
            Write-PspHost "CurrentUser execution policy is 'AllSigned' (stricter than RemoteSigned)." -ForegroundColor Yellow
            $reply = Read-Host "  Downgrade to RemoteSigned so the profile can load unsigned scripts? [y/N]"
            if ($reply -match '^[Yy]' -and $PSCmdlet.ShouldProcess('CurrentUser execution policy', 'Set to RemoteSigned')) {
                Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                Write-PspHost "Execution policy set to RemoteSigned for CurrentUser." -ForegroundColor Green
            }
            else {
                Write-PspHost "  Kept AllSigned. Profile will not load unless all .ps1 files are signed." -ForegroundColor Yellow
            }
        }
        else {
            Write-PspHost "  CurrentUser policy is AllSigned. Skipping downgrade prompt (non-interactive)." -ForegroundColor Yellow
        }
    }
    elseif ($currentUserPolicy -in @('Restricted', 'Undefined')) {
        Write-PspHost "CurrentUser execution policy is '$currentUserPolicy'." -ForegroundColor Yellow
        Write-PspHost "  If the installed profile is blocked, opt in manually with:" -ForegroundColor DarkYellow
        Write-PspHost "  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor DarkYellow
    }
    if (-not $script:IsCiHost) {
        $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
        if ($machinePolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
            Write-PspHost "LocalMachine execution policy is '$machinePolicy'." -ForegroundColor Yellow
            Write-PspHost "  setup.ps1 leaves machine-wide policy unchanged. Change it manually only if you intend to affect all users." -ForegroundColor DarkYellow
        }
    }

    if (-not (Test-Path -LiteralPath $configCachePath) -and $PSCmdlet.ShouldProcess($configCachePath, 'Create the profile cache folder')) {
        New-Item -ItemType Directory -Path $configCachePath -Force | Out-Null
    }
    $userSettingsPath = Join-Path $configCachePath 'user-settings.json'

    # Run the wizard before downstream installation steps consume user settings.
    $wantWizard = ($Wizard -or $script:CanPrompt) -and -not $SkipWizard -and -not $WhatIfPreference
    if ($wantWizard) {
        $wizardState = Join-Path $configCachePath 'wizard-state.json'
        if (-not $Resume -and (Test-Path -LiteralPath $wizardState)) {
            # Remove wizard state older than 24 hours unless resume was requested.
            $age = (Get-Date) - (Get-Item -LiteralPath $wizardState).LastWriteTime
            if ($age.TotalHours -gt 24) { Remove-Item -LiteralPath $wizardState -Force -ErrorAction SilentlyContinue }
        }
        try {
            $wizChoices = Start-InstallWizard -StatePath $wizardState
            Save-WizardChoices -Choices $wizChoices -UserSettingsPath $userSettingsPath
            Remove-Item -LiteralPath $wizardState -Force -ErrorAction SilentlyContinue
            Write-PspHost ''
            Write-PspHost 'Wizard choices saved to user-settings.json.' -ForegroundColor Green

            # Install the selected Nerd Font and retain the default fallback on failure.
            if ($wizChoices.Font -and -not $script:IsCiHost) {
                Write-PspHost ("Installing Nerd Font: {0} v{1}..." -f $wizChoices.Font.DisplayName, $script:NerdFontVersion) -ForegroundColor Cyan
                $script:WizardFontInstalled = Install-NerdFonts -FontName $wizChoices.Font.Asset -FontDisplayName $wizChoices.Font.DisplayName -Version $script:NerdFontVersion -Sha256 $wizChoices.Font.Sha256
                if (-not $script:WizardFontInstalled) {
                    Write-PspHost "  Wizard font install did not complete; step [4/10] will retry with the default font." -ForegroundColor Yellow
                }
            }

            # Reuse wizard theme, editor and telemetry choices in later setup steps.
            $script:WizardOmpTheme = $wizChoices.Theme
            $script:WizardEditor = $wizChoices.Editor
            $script:WizardTelemetryHandled = ($null -ne $wizChoices.TelemetryOptOut)
            if ($wizChoices.TelemetryOptOut -and -not (Test-TelemetryOptOutSet)) { Set-TelemetryOptOut -CacheDir $configCachePath }
        }
        catch {
            if ($_.Exception.Message -eq 'WizardCancelled') {
                Write-PspHost 'Continuing setup without wizard overrides.' -ForegroundColor Yellow
            }
            else {
                Write-Warning ("Wizard failed: {0}. Continuing with defaults; run setup.ps1 -Wizard -Resume to finish it." -f $_.Exception.Message)
            }
        }
    }

    # theme.json (theme + WT metadata) and terminal-config.json (WT behavior) from the verified bundle.
    $profileConfig = $null
    $terminalConfig = $null
    try { $profileConfig = Read-JsonFile $Bundle.Theme }
    catch { Write-PspHost "Could not load theme.json. Theme and color scheme steps will be skipped." -ForegroundColor Yellow }
    try { $terminalConfig = Read-JsonFile $Bundle.Terminal }
    catch { Write-PspHost "Could not load terminal-config.json. Terminal behavior settings (font, scrollbar, keybindings) will not be applied." -ForegroundColor Yellow }
    foreach ($pair in @(@($Bundle.Theme, 'theme.json', $profileConfig), @($Bundle.Terminal, 'terminal-config.json', $terminalConfig))) {
        $cached = Join-Path $configCachePath $pair[1]
        if ($null -ne $pair[2] -and $PSCmdlet.ShouldProcess($cached, "Cache $($pair[1])")) { Copy-Item -LiteralPath $pair[0] -Destination $cached -Force }
    }

    # Apply user-settings.json overrides (never downloaded, never overwritten).
    $overrides = [PSCustomObject]@{ Managed = $true }
    $userSettingsUnreadable = $false
    if (Test-Path -LiteralPath $userSettingsPath) {
        try {
            $overrides = Merge-PspUserSettings -UserSettings (Read-JsonFile $userSettingsPath) -ThemeConfig $profileConfig -TerminalConfig $terminalConfig
            Write-PspHost "User overrides applied from user-settings.json" -ForegroundColor DarkGray
        }
        catch {
            # Without the file it is unknown whether another tool owns Windows Terminal's settings.json, so it is left alone.
            $overrides = [PSCustomObject]@{ Managed = $false }
            $userSettingsUnreadable = $true
            Write-PspHost "Failed to parse user-settings.json (left unchanged; Windows Terminal settings are skipped until it parses): $_" -ForegroundColor Yellow
        }
    }

    if (-not $script:IsCiHost -and -not (Get-Command winget -CommandType Application -ErrorAction Ignore)) {
        Write-PspHost "winget (App Installer) not found - skipping optional tool installs (eza, bat, fzf, zoxide, ripgrep, Oh My Posh)." -ForegroundColor Yellow
        Write-PspHost "  Install it later from the Microsoft Store or https://aka.ms/getwinget to add those tools." -ForegroundColor DarkYellow
    }

    Write-PspHost ""
    Write-PspHost "PowerShell Profile Setup" -ForegroundColor Cyan
    Write-PspHost "========================" -ForegroundColor Cyan
    Write-PspHost ""

    # Profile creation or update (install for both PS5 and PS7)
    Write-PspHost "[1/10] Profile" -ForegroundColor Cyan
    # Derive Documents root from $PROFILE.
    $docsRoot = Split-Path (Split-Path $PROFILE)
    $profileDirs = @(
        Join-Path $docsRoot "PowerShell"          # PS7 (Core)
        Join-Path $docsRoot "WindowsPowerShell"    # PS5 (Desktop)
    )
    $profileInstalled = Install-ProfileFiles -Source $Bundle.Profile -ProfileDirs $profileDirs

    # Create starter user-settings.json template if it doesn't exist (never overwrite)
    if (-not (Test-Path -LiteralPath $userSettingsPath)) {
        if ($PSCmdlet.ShouldProcess($userSettingsPath, 'Create the user-settings.json template')) {
            Write-Utf8FileAtomic -Path $userSettingsPath -Content (Get-PspUserSettingsTemplate)
            Write-PspHost "  User settings template created at [$userSettingsPath]" -ForegroundColor Green
        }
    }
    else {
        Write-PspHost "  User settings file already exists at [$userSettingsPath] (preserved)" -ForegroundColor DarkGray
    }

    # Use the wizard's editor choice or collect one interactively.
    Write-PspHost "[2/10] Editor preference" -ForegroundColor Cyan
    if ($script:WizardEditor) {
        Write-PspHost "  Using wizard choice: $($script:WizardEditor)" -ForegroundColor DarkGray
        $chosenEditor = Resolve-ConfiguredEditor -RequestedEditor ([string]$script:WizardEditor)
        Write-PspHost "  Editor set to: $chosenEditor" -ForegroundColor Green
        Set-PreferredEditorInProfiles -EditorName $chosenEditor -CommentLabel 'set by setup.ps1 wizard' -ProfileDirs $profileDirs
    }
    elseif ($script:CanPrompt -and -not $WhatIfPreference) {
        $chosenEditor = Resolve-ConfiguredEditor -RequestedEditor (Select-PreferredEditor)
        Write-PspHost "  Editor set to: $chosenEditor" -ForegroundColor Green
        Set-PreferredEditorInProfiles -EditorName $chosenEditor -CommentLabel 'set by setup.ps1' -ProfileDirs $profileDirs
    }
    else {
        Write-PspHost "  Skipped (non-interactive). Default: code, notepad" -ForegroundColor Yellow
    }

    # OMP Install
    Write-PspHost "[3/10] Oh My Posh" -ForegroundColor Cyan
    $ompPath = Get-OhMyPoshExecutablePath
    if ($ompPath -and $ompPath -notlike ((Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') + '*')) {
        Write-PspHost "  Oh My Posh already present at $ompPath (preserved)." -ForegroundColor Green
        $ompInstalled = $true
    }
    elseif ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping Oh My Posh install." -ForegroundColor DarkGray
        $ompInstalled = $true
    }
    else {
        $ompInstalled = Install-WingetPackage -Name "Oh My Posh" -Id "JanDeDobbeleer.OhMyPosh"
    }
    # Wizard OMP-theme override wins if present; otherwise use theme.json (with user-settings overrides).
    $configTheme = Get-PspProp $profileConfig 'theme'
    if ($script:WizardOmpTheme) {
        $themeInstalled = Install-OhMyPoshTheme -ThemeName $script:WizardOmpTheme.Name -ThemeUrl $script:WizardOmpTheme.Url -Sha256 ([string](Get-PspProp $script:WizardOmpTheme 'Sha256'))
    }
    elseif ((Get-PspProp $configTheme 'name') -and (Get-PspProp $configTheme 'url')) {
        $themeInstalled = Install-OhMyPoshTheme -ThemeName ([string]$configTheme.name) -ThemeUrl ([string]$configTheme.url) -Sha256 ([string](Get-PspProp $configTheme 'sha256'))
    }
    else {
        $reason = if (-not $profileConfig) { "theme.json missing" }
        elseif (-not (Get-PspProp $configTheme 'name')) { "theme name missing" }
        else { "theme URL missing" }
        Write-PspHost "  Skipped theme download ($reason)." -ForegroundColor Yellow
        $themeInstalled = $false
    }
    # Invalidate generated init caches.
    foreach ($cacheFile in @('zoxide-init.ps1', 'omp-init.ps1')) {
        $cachePath = Join-Path $configCachePath $cacheFile
        if ((Test-Path -LiteralPath $cachePath) -and $PSCmdlet.ShouldProcess($cachePath, 'Remove stale init cache')) {
            Remove-Item -LiteralPath $cachePath -Force -ErrorAction SilentlyContinue
        }
    }

    # Font Install
    Write-PspHost "[4/10] Nerd Fonts" -ForegroundColor Cyan
    $fontInstall = Get-PspProp $terminalConfig 'fontInstall'
    $fontName = [string](Get-PspProp $fontInstall 'name')
    if (-not $fontName) { $fontName = 'CascadiaCode' }
    $fontDisplayName = [string](Get-PspProp $fontInstall 'displayName')
    if (-not $fontDisplayName) { $fontDisplayName = 'CaskaydiaCove NF' }
    $fontVersion = [string](Get-PspProp $fontInstall 'version')
    if (-not $fontVersion) { $fontVersion = $script:NerdFontVersion }
    $fontSha256 = [string](Get-PspProp $fontInstall 'sha256')
    if (-not $fontSha256 -and $fontVersion -eq $script:NerdFontVersion) {
        $curated = $script:CuratedFonts | Where-Object { $_.Asset -eq $fontName } | Select-Object -First 1
        if ($curated) { $fontSha256 = $curated.Sha256 }
    }
    if ($script:WizardFontInstalled) {
        Write-PspHost "  Font already installed by wizard; skipping default." -ForegroundColor DarkGray
        $fontInstalled = $true
    }
    elseif ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping Nerd Font install." -ForegroundColor DarkGray
        $fontInstalled = $true
    }
    else {
        $fontInstalled = Install-NerdFonts -FontName $fontName -FontDisplayName $fontDisplayName -Version $fontVersion -Sha256 $fontSha256
    }

    # eza Install (modern ls replacement with icons and git status)
    Write-PspHost "[5/10] eza" -ForegroundColor Cyan
    $ezaInstalled = $true
    if ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping eza install." -ForegroundColor DarkGray
    }
    else {
        $ezaInstalled = Install-WingetPackage -Name "eza" -Id "eza-community.eza"
    }
    # Terminal-Icons is not used by this profile (eza shows icons); remove it only when the user says so.
    if ($script:CanPrompt -and -not $WhatIfPreference -and (Get-Module -ListAvailable -Name Terminal-Icons)) {
        Write-PspHost '  The Terminal-Icons module is installed. This profile does not load it (eza provides icons).' -ForegroundColor DarkGray
        if ((Read-WizardYesNo -Prompt '  Uninstall Terminal-Icons (all versions)? Other profiles that import it will lose it' -Default $false) -and
            $PSCmdlet.ShouldProcess('Terminal-Icons (all versions)', 'Uninstall module')) {
            try {
                Remove-Module Terminal-Icons -Force -ErrorAction SilentlyContinue
                Uninstall-Module Terminal-Icons -AllVersions -Force -ErrorAction Stop
                Write-PspHost '  Terminal-Icons uninstalled.' -ForegroundColor Green
            }
            catch { Write-PspHost "  Could not uninstall Terminal-Icons: $_" -ForegroundColor Yellow }
        }
    }

    # zoxide Install
    Write-PspHost "[6/10] zoxide" -ForegroundColor Cyan
    $zoxideInstalled = $true
    if ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping zoxide install." -ForegroundColor DarkGray
    }
    else {
        $zoxideInstalled = Install-WingetPackage -Name "zoxide" -Id "ajeetdsouza.zoxide"
    }

    # fzf + PSFzf Install (fuzzy finder for history and file search)
    Write-PspHost "[7/10] fzf" -ForegroundColor Cyan
    $fzfInstalled = $true
    if ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping fzf and PSFzf install." -ForegroundColor DarkGray
    }
    else {
        $fzfInstalled = Install-WingetPackage -Name "fzf" -Id "junegunn.fzf"
        if (-not (Get-Module -ListAvailable -Name PSFzf)) {
            $psfzfVersion = (Get-PspComponentPins).PSFzf
            if ($PSCmdlet.ShouldProcess("PSFzf $psfzfVersion", 'Install PowerShell module from the PowerShell Gallery (CurrentUser)')) {
                try {
                    Install-Module -Name PSFzf -RequiredVersion $psfzfVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Write-PspHost "  PSFzf $psfzfVersion installed." -ForegroundColor Green
                }
                catch {
                    Write-PspHost "  Failed to install PSFzf module: $_" -ForegroundColor Red
                    $fzfInstalled = $false
                }
            }
        }
        else {
            Write-PspHost "  PSFzf module already installed." -ForegroundColor Green
        }
    }

    # bat Install (syntax-highlighted cat replacement)
    Write-PspHost "[8/10] bat" -ForegroundColor Cyan
    $batInstalled = $true
    if ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping bat install." -ForegroundColor DarkGray
    }
    else {
        $batInstalled = Install-WingetPackage -Name "bat" -Id "sharkdp.bat"
    }

    # ripgrep Install (fast recursive grep, used by the grep function)
    Write-PspHost "[9/10] ripgrep" -ForegroundColor Cyan
    $rgInstalled = $true
    if ($script:IsCiHost) {
        Write-PspHost "  CI mode: skipping ripgrep install." -ForegroundColor DarkGray
    }
    else {
        $rgInstalled = Install-WingetPackage -Name "ripgrep" -Id "BurntSushi.ripgrep.MSVC"
    }

    # Apply font, theme and appearance to every Windows Terminal variant through the change-recording writer used by Update-Profile.
    Write-PspHost "[10/10] Windows Terminal" -ForegroundColor Cyan
    $wtSettingsPaths = @(Get-WindowsTerminalSettingsPaths)
    if (-not $overrides.Managed) {
        $skipReason = if ($userSettingsUnreadable) { 'user-settings.json could not be parsed, so settings.json is left alone' } else { 'user-settings.json sets windowsTerminal.manage = false, so settings.json is left to the tool that owns it' }
        Write-PspHost "  Skipped: $skipReason." -ForegroundColor DarkGray
        $wtSettingsPaths = @()
    }
    elseif ($wtSettingsPaths.Count -eq 0) {
        Write-PspHost "  Windows Terminal settings not found (skipped)." -ForegroundColor Yellow
    }
    $wtDefaults = Copy-PspObject (Get-PspProp $terminalConfig 'defaults')
    if ($null -eq $wtDefaults) { $wtDefaults = [PSCustomObject]@{} }
    # Script parameters override JSON values only when they are passed explicitly.
    if ($script:BoundParameterNames -contains 'FontSize') {
        $font = Get-PspProp $wtDefaults 'font'
        if ($font -isnot [System.Management.Automation.PSCustomObject]) { $font = [PSCustomObject]@{} }
        Set-PspProp $font 'size' $FontSize
        Set-PspProp $wtDefaults 'font' $font
    }
    if ($script:BoundParameterNames -contains 'Opacity') { Set-PspProp $wtDefaults 'opacity' $Opacity }
    $wtTheme = Copy-PspObject (Get-PspProp $profileConfig 'windowsTerminal')
    if ($script:BoundParameterNames -contains 'ColorScheme') {
        if ($null -eq $wtTheme) { $wtTheme = [PSCustomObject]@{} }
        Set-PspProp $wtTheme 'colorScheme' $ColorScheme
    }
    foreach ($wtSettingsPath in $wtSettingsPaths) {
        try {
            $wtArgs = @{
                Path            = $wtSettingsPath
                ManifestPath    = (Join-Path $configCachePath 'wt-changes.json')
                Defaults        = $wtDefaults
                WindowsTerminal = $wtTheme
                Keybindings     = Get-PspArray $terminalConfig 'keybindings'
                NoLogo          = $true
            }
            if (Update-WindowsTerminalSettingsFile @wtArgs) {
                $schemeLabel = if (Get-PspProp $wtTheme 'colorScheme') { $wtTheme.colorScheme } else { '(unchanged)' }
                Write-PspHost "  Windows Terminal configured: $wtSettingsPath (scheme: $schemeLabel)." -ForegroundColor Green
            }
        }
        catch {
            Write-PspHost "  Failed to configure Windows Terminal ($wtSettingsPath): $_" -ForegroundColor Red
        }
    }

    # Optional PowerShell telemetry opt-out (explicit consent).
    if (-not $script:WizardTelemetryHandled -and $script:CanPrompt -and -not $WhatIfPreference -and -not (Test-TelemetryOptOutSet)) {
        Write-PspHost ""
        $scopeLabel = if ($script:IsElevated) { 'machine-wide' } else { 'for your user account' }
        Write-PspHost "Opt out of PowerShell telemetry? This sets POWERSHELL_TELEMETRY_OPTOUT=true $scopeLabel." -ForegroundColor Cyan
        $answer = Read-Host "  [y/N]"
        if ($answer -match '^(?i:y|yes)$') { Set-TelemetryOptOut -CacheDir $configCachePath }
    }

    # Record what was installed so psp-doctor, the update check and Uninstall-Profile know the source.
    if ($profileInstalled -and $PSCmdlet.ShouldProcess((Join-Path $configCachePath 'installed.json'), 'Record the installed version and source')) {
        try {
            $installedVersion = [regex]::Match((Get-Utf8FileText $Bundle.Profile), "(?m)^\s*Version\s*=\s*'([^']+)'").Groups[1].Value
            $sourceKind = if ($LocalRepo) { 'local' } else { 'remote' }
            $refLabel = if ($LocalRepo) { $LocalRepo } else { $Ref }
            Set-PspInstallState -CacheDir $configCachePath -Version $installedVersion -Ref $refLabel -Commit $script:SourceCommit -BundleSha256 $script:BundleSha256 -Source $sourceKind
            if ($script:SourceCommit) { Write-Utf8FileAtomic -Path (Join-Path $configCachePath 'applied-commit.sha') -Content $script:SourceCommit }
        }
        catch { Write-PspHost "  Could not record the install state: $_" -ForegroundColor Yellow }
    }

    # Base the final result on profile installation while reporting optional tool failures as warnings.
    Write-PspHost ""
    $optionalOk = $themeInstalled -and $fontInstalled -and $ompInstalled -and $ezaInstalled -and $zoxideInstalled -and $fzfInstalled -and $batInstalled -and $rgInstalled
    if ($WhatIfPreference) {
        Write-PspHost "WhatIf: nothing was changed." -ForegroundColor Yellow
    }
    elseif (-not $profileInstalled) {
        Write-PspHost "Setup FAILED: the profile could not be installed. Check the messages above." -ForegroundColor Red
    }
    elseif (-not $optionalOk) {
        Write-PspHost "Setup complete - profile installed. Some optional tools were skipped or failed (see above); the profile works without them." -ForegroundColor Yellow
    }
    else {
        Write-PspHost "Setup complete!" -ForegroundColor Green
    }
    Write-PspHost ""
    return [bool]$profileInstalled
}

# Restart into a fresh terminal so the profile loads; an elevated setup only says so, to avoid handing the user an elevated shell.
function Restart-SetupTerminal {
    param([int]$ExitCode)
    if (-not $script:CanPrompt -or $WhatIfPreference) { return }
    if ($script:IsElevated) {
        Write-PspHost 'Open a new, non-elevated terminal to start using the profile.' -ForegroundColor Yellow
        return
    }
    Write-PspHost "Setup applied. Press Enter to restart the terminal (or close this window to cancel)..." -ForegroundColor Yellow
    try { $null = Read-Host } catch { $null = $_ }
    $dir = (Get-Location).Path
    if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) {
        $dir = [Environment]::GetFolderPath('UserProfile')
    }
    $shellExe = Get-PspShellPath
    $wt = Get-Command wt.exe -CommandType Application -ErrorAction Ignore | Select-Object -First 1
    if ($wt) {
        Start-Process -FilePath $wt.Source -ArgumentList (ConvertTo-NativeArgumentLine @('-w', '0', '-d', $dir, $shellExe, '-NoExit'))
    }
    else {
        Start-Process -FilePath $shellExe -ArgumentList '-NoExit' -WorkingDirectory $dir
    }
    if ($script:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { $null = $_ }; $script:TranscriptStarted = $false }
    if ($script:WorkDir) { Remove-SafeTempDirectory -Path $script:WorkDir -NamePrefix 'psp-setup-' }
    exit $ExitCode
}

# ---------------------------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------------------------
$exitCode = 1
try {
    $onWindows = (-not (Test-Path Variable:\IsWindows)) -or $IsWindows
    if (-not $onWindows) { throw 'setup.ps1 supports Windows only.' }
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 17763) {
        Write-PspHost "Windows build $build is older than Windows 10 1809: fonts can only be installed from an elevated shell." -ForegroundColor Yellow
    }
    if ($SkipHashCheck -and $ExpectedSha256) { throw 'Use either -ExpectedSha256 or -SkipHashCheck, not both.' }
    if ($LocalRepo -and ($script:BoundParameterNames -contains 'Ref')) { throw 'Use either -LocalRepo or -Ref, not both.' }

    # A folder holding setup.ps1 next to the profile files is a local checkout, unless the caller pinned a ref or hash.
    if ([string]::IsNullOrWhiteSpace($LocalRepo) -and $PSScriptRoot -and -not ($script:BoundParameterNames -contains 'Ref') -and -not $ExpectedSha256) {
        $here = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
        $repoFiles = @('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json', 'setprofile.ps1')
        $missing = @($repoFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $here $_) -PathType Leaf) })
        if ($here -ne $tempRoot -and $missing.Count -eq 0) {
            $LocalRepo = $here
            Write-PspHost "Using local repo checkout: $LocalRepo" -ForegroundColor DarkGray
        }
    }

    # Verify (or locate) the bundle before any local change.
    try { $script:Bundle = Initialize-InstallBundle }
    catch {
        Write-PspHost "Install bundle was not applied: $($_.Exception.Message)" -ForegroundColor Red
        Write-PspHost "No local setup changes were made." -ForegroundColor Yellow
        $script:ErrorReported = $true
        throw
    }

    # Load the shared helpers from the verified profile into this script's scope.
    foreach ($definition in (Get-SharedFunctionDefinitions -ProfilePath $script:Bundle.Profile -Names $script:SharedFunctionNames)) {
        . ([scriptblock]::Create($definition))
    }

    # Log the run (Write-Host output included) to the cache folder; dry runs are not logged.
    if (-not $WhatIfPreference) {
        try {
            $logDir = Join-Path (Get-PspCacheDir) 'logs'
            if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
            Get-ChildItem -LiteralPath $logDir -Filter 'setup-*.log' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -Skip 9 |
                ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
            $logPath = Join-Path $logDir ('setup-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Start-Transcript -LiteralPath $logPath -ErrorAction Stop | Out-Null
            $script:TranscriptStarted = $true
            Write-PspHost "Logging to $logPath" -ForegroundColor DarkGray
        }
        catch { Write-PspHost "  Could not start the setup log: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    $installed = Invoke-SetupInstall -Bundle $script:Bundle
    $exitCode = if ($installed -or $WhatIfPreference) { 0 } else { 1 }
    # A failed install keeps this window open with its messages.
    if ($installed) { Restart-SetupTerminal -ExitCode $exitCode }
}
catch {
    if (-not $script:ErrorReported) { Write-PspHost "Setup stopped: $($_.Exception.Message)" -ForegroundColor Red }
    $exitCode = 1
}
finally {
    if ($script:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { $null = $_ } }
    if ($script:WorkDir) { Remove-SafeTempDirectory -Path $script:WorkDir -NamePrefix 'psp-setup-' }
}

# Exit with the code when run as a file; a script block must not close the caller's shell or leave setup's variables in it.
if ($PSCommandPath) { exit $exitCode }
foreach ($name in @(Get-Variable -Scope Script -ErrorAction Ignore | ForEach-Object { $_.Name })) {
    if ($callerScriptVariables -notcontains $name) { Remove-Variable -Name $name -Scope Script -Force -ErrorAction Ignore -WhatIf:$false -Confirm:$false }
}
$global:LASTEXITCODE = $exitCode
