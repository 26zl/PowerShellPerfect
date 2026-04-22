### PowerShell Profile (26zl) setup script
### This script configures the PowerShell profile by installing necessary tools, fonts, and themes.
### It also sets up Windows Terminal with recommended settings. Run this script in an elevated PowerShell session to ensure all changes are applied correctly.

param(
    [ValidateRange(0, 100)]
    [int]$Opacity = 75,

    [string]$ColorScheme,

    [ValidateRange(6, 30)]
    [int]$FontSize = 11,

    # Path to a local repo clone. When set, profile/theme.json/terminal-config.json
    # are copied from this directory instead of downloaded from GitHub.
    # Used by ci-functional.ps1 to test local changes without a GitHub round-trip.
    [string]$LocalRepo = '',

    [switch]$CiMode,

    # Interactive wizard: asks user for OMP theme, color scheme, font, features, background.
    # Auto-enabled when interactive + not in CI + not AI-agent. -SkipWizard forces defaults.
    # -Resume continues from a prior incomplete wizard run (state in $env:TEMP\psp-wizard-state.json).
    [switch]$Wizard,
    [switch]$SkipWizard,
    [switch]$Resume,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSha256,
    [switch]$SkipHashCheck
)

# Normalize agent detection (same as profile): if host set a known agent var, set AI_AGENT so we only check one name
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) {
    $env:AI_AGENT = '1'
}

$RepoBase = "https://raw.githubusercontent.com/26zl/PowerShellPerfect/main"
$script:DownloadedProfilePath = $null
$script:DownloadedThemeConfigPath = $null
$script:DownloadedTerminalConfigPath = $null
$script:VerifiedInstallBundle = $false

# Auto-detect local repo: when the script sits next to Microsoft.PowerShell_profile.ps1 and
# -LocalRepo was not supplied, prefer the local checkout over a GitHub round-trip. This makes
# `.\setup.ps1` work as expected from a manual clone and matches README's "manual setup" doc.
# Skipped when piped via `irm | iex` because $PSScriptRoot is empty in that mode.
if ([string]::IsNullOrWhiteSpace($LocalRepo) -and $PSScriptRoot -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Microsoft.PowerShell_profile.ps1')) -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'theme.json')) -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'terminal-config.json'))) {
    $LocalRepo = $PSScriptRoot
    Write-Host "Using local repo checkout: $LocalRepo" -ForegroundColor DarkGray
}

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

function Initialize-RemoteInstallBundle {
    if ($LocalRepo -or $script:VerifiedInstallBundle) { return }

    $tempSuffix = [System.IO.Path]::GetRandomFileName()
    $bundleProfile = Join-Path $env:TEMP "psp-setup-profile-$tempSuffix.ps1"
    $bundleTheme = Join-Path $env:TEMP "psp-setup-theme-$tempSuffix.json"
    $bundleTerminal = Join-Path $env:TEMP "psp-setup-terminal-$tempSuffix.json"

    try {
        Invoke-DownloadWithRetry -Uri "$RepoBase/Microsoft.PowerShell_profile.ps1" -OutFile $bundleProfile -TimeoutSec 30
        Invoke-DownloadWithRetry -Uri "$RepoBase/theme.json" -OutFile $bundleTheme
        Invoke-DownloadWithRetry -Uri "$RepoBase/terminal-config.json" -OutFile $bundleTerminal

        $profileHash = (Get-FileHash -LiteralPath $bundleProfile -Algorithm SHA256).Hash
        $themeHash = (Get-FileHash -LiteralPath $bundleTheme -Algorithm SHA256).Hash
        $terminalHash = (Get-FileHash -LiteralPath $bundleTerminal -Algorithm SHA256).Hash
        $combinedHash = Get-CombinedSha256 -Parts @(
            "profile:$profileHash"
            "theme:$themeHash"
            "terminal:$terminalHash"
        )

        if (-not $SkipHashCheck) {
            if (-not $ExpectedSha256) {
                Write-Host "Downloaded install bundle hashes:" -ForegroundColor Yellow
                Write-Host "  profile.ps1:       $profileHash" -ForegroundColor Yellow
                Write-Host "  theme.json:        $themeHash" -ForegroundColor Yellow
                Write-Host "  terminal-config:   $terminalHash" -ForegroundColor Yellow
                Write-Host "  combined:          $combinedHash" -ForegroundColor Yellow
                throw "Hash input required. Re-run with -ExpectedSha256 '$combinedHash' or -SkipHashCheck."
            }

            if ($combinedHash -ne $ExpectedSha256.ToUpperInvariant()) {
                throw "Combined hash mismatch. Expected $($ExpectedSha256.ToUpperInvariant()), got $combinedHash."
            }
        }

        $script:DownloadedProfilePath = $bundleProfile
        $script:DownloadedThemeConfigPath = $bundleTheme
        $script:DownloadedTerminalConfigPath = $bundleTerminal
        $script:VerifiedInstallBundle = $true
    }
    catch {
        Remove-Item $bundleProfile, $bundleTheme, $bundleTerminal -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Test-IsTrustedRawGitHubUrl {
    param([Parameter(Mandatory)][string]$Url)
    try { $uri = [Uri]$Url } catch { return $false }
    if ($uri.Scheme -ne 'https') { return $false }
    return $uri.Host -in @('raw.githubusercontent.com', 'githubusercontent.com')
}

function Resolve-SetupSourcePath {
    param([Parameter(Mandatory)][ValidateSet('profile', 'theme', 'terminal')][string]$Kind)
    if ($LocalRepo) {
        switch ($Kind) {
            'profile' { return (Join-Path $LocalRepo 'Microsoft.PowerShell_profile.ps1') }
            'theme' { return (Join-Path $LocalRepo 'theme.json') }
            'terminal' { return (Join-Path $LocalRepo 'terminal-config.json') }
        }
    }

    Initialize-RemoteInstallBundle
    switch ($Kind) {
        'profile' { return $script:DownloadedProfilePath }
        'theme' { return $script:DownloadedThemeConfigPath }
        'terminal' { return $script:DownloadedTerminalConfigPath }
    }
}

# Curated color scheme library (used by install wizard).
# Each entry is a full Windows Terminal scheme definition. Users who want more
# can paste their own into user-settings.json.windowsTerminal.scheme.
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

# Curated Nerd Fonts (name = ryanoasis release asset name without .zip).
# DisplayName is what appears in Windows after install, used for WT "face" setting.
$script:CuratedFonts = @(
    @{ Asset = 'CascadiaCode';   DisplayName = 'CaskaydiaCove NF';    Desc = 'Microsoft Cascadia + icons (default)' }
    @{ Asset = 'JetBrainsMono';  DisplayName = 'JetBrainsMono NF';    Desc = 'JetBrains flagship, tight + readable' }
    @{ Asset = 'FiraCode';       DisplayName = 'FiraCode NF';         Desc = 'Popular ligature font' }
    @{ Asset = 'Meslo';          DisplayName = 'MesloLGM NF';         Desc = 'p10k default, excellent rendering' }
    @{ Asset = 'Hack';           DisplayName = 'Hack NF';             Desc = 'Simple + workhorse' }
    @{ Asset = 'Iosevka';        DisplayName = 'Iosevka NF';          Desc = 'Narrow monospace, space-efficient' }
)

# Install wizard (setup.ps1 -Wizard). Guarded so CI/non-interactive hosts skip.
# Internal: show a numbered pick list from stdin/Out-GridView/fzf. Returns the picked
# item (or the user's -Default if they press Enter/skip). Multi-select via fzf --multi
# not supported here; each wizard step picks one item.
function Select-WizardItem {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][array]$Items,      # array of hashtables with .Name and .Desc
        [string]$DefaultName,                      # pre-selected (Enter to accept)
        [switch]$AllowSkip                         # Enter with no default = skip
    )
    Write-Host ''
    Write-Host ("-- {0} --" -f $Title) -ForegroundColor Cyan
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $marker = if ($DefaultName -and $Items[$i].Name -eq $DefaultName) { '>' } else { ' ' }
        $desc = if ($Items[$i].Desc) { " - $($Items[$i].Desc)" } else { '' }
        Write-Host ("  {0} [{1,2}] {2}{3}" -f $marker, ($i + 1), $Items[$i].Name, $desc)
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
        # Allow fuzzy name match too
        $match = $Items | Where-Object { $_.Name -like "*$raw*" } | Select-Object -First 1
        if ($match) { return $match }
        Write-Host "  Invalid; try again." -ForegroundColor Yellow
    } while ($true)
}

# Internal: fetch latest Nerd Fonts release tag (e.g. 'v3.2.1' -> '3.2.1').
# Fallback to the version in terminal-config.json, then a hardcoded fallback.
function Get-LatestNerdFontVersion {
    try {
        $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/ryanoasis/nerd-fonts/releases/latest' `
            -TimeoutSec 15 -UseBasicParsing -Headers @{ 'User-Agent' = 'PowerShellPerfect-setup' } -ErrorAction Stop
        if ($rel.tag_name -match 'v?(\d+\.\d+\.\d+)') { return $matches[1] }
    }
    catch { $null = $_ }
    return '3.2.1'
}

# Internal: fetch the upstream OMP theme list from GitHub API. Returns array of
# @{ Name='atomic'; Url='https://...atomic.omp.json' }. Empty array on network failure.
function Get-OmpThemeList {
    $apiUrl = 'https://api.github.com/repos/JanDeDobbeleer/oh-my-posh/contents/themes?ref=main'
    try {
        $resp = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 15 -UseBasicParsing -Headers @{ 'User-Agent' = 'PowerShellPerfect-setup' } -ErrorAction Stop
    }
    catch { return @() }
    $themes = @()
    foreach ($item in $resp) {
        if ($item.name -like '*.omp.json') {
            $baseName = $item.name -replace '\.omp\.json$', ''
            $themes += @{ Name = $baseName; Desc = ''; Url = $item.download_url }
        }
    }
    return $themes | Sort-Object { $_.Name }
}

# Internal: write all wizard choices to user-settings.json via Merge-JsonObject.
# Overwrites in place so re-running the wizard applies the new set without piling
# up stale overrides. Choices is a hashtable with keys: Theme, Scheme, Font, Features,
# Background, TabBar. Any $null key is skipped (user chose 'keep current').
function Save-WizardChoices {
    param(
        [Parameter(Mandatory)][hashtable]$Choices,
        [Parameter(Mandatory)][string]$UserSettingsPath
    )
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $s = if (Test-Path $UserSettingsPath) {
        try { (Get-Content $UserSettingsPath -Raw | ConvertFrom-Json -ErrorAction Stop) }
        catch { [PSCustomObject]@{} }
    }
    else { [PSCustomObject]@{} }
    if ($null -eq $s) { $s = [PSCustomObject]@{} }

    # theme (OMP)
    if ($Choices.Theme) {
        $s | Add-Member -NotePropertyName 'theme' -NotePropertyValue ([PSCustomObject]@{ name = $Choices.Theme.Name; url = $Choices.Theme.Url }) -Force
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
    # Terminal appearance: opacity, useAcrylic, cursorShape, padding, scrollbarState, historySize
    # go straight into defaults; fontSize is nested under defaults.font.size so the wizard's
    # face pick (if any) is preserved.
    if ($Choices.Terminal) {
        foreach ($k in $Choices.Terminal.Keys) {
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
        foreach ($k in $Choices.Features.Keys) {
            $s.features | Add-Member -NotePropertyName $k -NotePropertyValue $Choices.Features[$k] -Force
        }
    }
    # PSReadLine: when 'scheme', derive a syntax palette from the chosen color scheme so the
    # shell reflects the picked theme without asking 10 hex questions. Profile reads
    # user-settings.json.psreadline.colors on top of theme.json's palette.
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
    $json = $s | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($UserSettingsPath, $json, $utf8)
}

# Yes/no prompt with default (Enter = default). Returns [bool].
function Read-WizardYesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $true)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $raw = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    return ($raw -match '^(?i:y|yes)$')
}

# Main wizard. Returns hashtable of choices; caller writes them via Save-WizardChoices.
function Start-InstallWizard {
    param([string]$StatePath)

    $choices = @{
        Theme           = $null   # @{ Name='atomic'; Url='...' }
        Scheme          = $null   # full scheme hashtable
        Font            = $null   # curated font entry
        Features        = $null   # hashtable
        Background      = $null   # @{ Path='...'; Opacity=0.15 }
        TabBar          = $null   # hex string
        AppTheme        = $null   # 'dark' | 'light' - WT window.applicationTheme
        Terminal        = $null   # ordered hashtable: opacity, fontSize, useAcrylic, cursorShape, padding, scrollbarState, historySize
        PSReadLine      = $null   # 'default' | 'scheme' - scheme derives from chosen color scheme
        Editor          = $null   # cmd name (code, nvim, notepad, ...) - moved in from setup.ps1 [2/10]
        TelemetryOptOut = $null   # $true = set POWERSHELL_TELEMETRY_OPTOUT machine-wide
        CompletedSteps  = @()
    }

    # Bump when the $choices shape changes (new fields, renamed keys, different step order).
    # Resume loads from state only when the stored version matches; mismatches start fresh so
    # stale state from an older setup.ps1 can't apply ghost fields to current logic.
    $WIZARD_STATE_SCHEMA = 2

    # Resume from state file if caller passed one that exists
    if ($StatePath -and (Test-Path $StatePath)) {
        try {
            $prev = Get-Content $StatePath -Raw | ConvertFrom-Json
            $prevSchema = if ($prev.PSObject.Properties['schemaVersion']) { [int]$prev.schemaVersion } else { 1 }
            if ($prevSchema -ne $WIZARD_STATE_SCHEMA) {
                Write-Host ''
                Write-Host ("Wizard state schema mismatch (found v{0}, expected v{1}); starting fresh." -f $prevSchema, $WIZARD_STATE_SCHEMA) -ForegroundColor Yellow
                Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
            }
            else {
                # Concurrency check: if the state file was written by a different, still-live
                # setup.ps1 process, two wizards are racing for the same state file. Warn the
                # user before we let this invocation stomp on the other one's progress.
                $otherPid = if ($prev.PSObject.Properties['ownerPid']) { [int]$prev.ownerPid } else { 0 }
                $otherAlive = $false
                if ($otherPid -gt 0 -and $otherPid -ne $PID) {
                    try {
                        $otherProc = Get-Process -Id $otherPid -ErrorAction Stop
                        if ($otherProc -and $otherProc.ProcessName -match '^(pwsh|powershell)$') { $otherAlive = $true }
                    }
                    catch { $otherAlive = $false }
                }
                if ($otherAlive) {
                    Write-Host ''
                    Write-Host ("Another setup.ps1 wizard (PID {0}) appears to be running with this state file." -f $otherPid) -ForegroundColor Yellow
                    if (-not (Read-WizardYesNo -Prompt '  Take over anyway? (the other run will silently overwrite on its next save)' -Default $false)) {
                        throw 'WizardCancelled: concurrent wizard detected.'
                    }
                }
                Write-Host ''
                Write-Host ("Found wizard state from {0}." -f $prev.Timestamp) -ForegroundColor Yellow
                if (Read-WizardYesNo -Prompt 'Resume?' -Default $true) {
                    foreach ($prop in $prev.Choices.PSObject.Properties) {
                        $choices[$prop.Name] = $prop.Value
                    }
                    Write-Host ("Resuming from step after: {0}" -f ($choices.CompletedSteps -join ', ')) -ForegroundColor DarkGray
                }
                else { Remove-Item $StatePath -Force -ErrorAction SilentlyContinue }
            }
        }
        catch {
            if ($_.Exception.Message -like 'WizardCancelled*') { throw }
            Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
        }
    }

    function Save-State {
        if (-not $StatePath) { return }
        $snap = @{ schemaVersion = $WIZARD_STATE_SCHEMA; Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); ownerPid = $PID; Choices = $choices }
        $json = $snap | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($StatePath, $json, [System.Text.UTF8Encoding]::new($false))
    }

    Write-Host ''
    Write-Host '=========================================' -ForegroundColor Magenta
    Write-Host '  PowerShellPerfect Install Wizard' -ForegroundColor Magenta
    Write-Host '=========================================' -ForegroundColor Magenta
    Write-Host '  Pick your cosmetics. All 130+ commands and extensibility APIs ship regardless.' -ForegroundColor DarkGray
    Write-Host '  Press Enter at any prompt to accept default / skip that step.' -ForegroundColor DarkGray

    # STEP 0: Quick start shortcut - offers a "just make it nice" preset that fills all 10
    # steps with sensible defaults and skips straight to the summary. Users who want to
    # customize say No and get the full wizard. Skipped when resuming (choices already loaded).
    if ($choices.CompletedSteps.Count -eq 0) {
        Write-Host ''
        Write-Host '-- Quick start --' -ForegroundColor Cyan
        Write-Host '  Preset: Tokyo Night scheme, CascadiaCode Nerd Font, VS Code editor,' -ForegroundColor DarkGray
        Write-Host '  scheme-derived PSReadLine colors, dark chrome, default features.' -ForegroundColor DarkGray
        if (Read-WizardYesNo -Prompt '  Use quick-start defaults and skip the 10 steps?' -Default $false) {
            $tokyoNight = $script:CuratedSchemes | Where-Object { $_.Name -eq 'Tokyo Night' } | Select-Object -First 1
            $cascadia   = $script:CuratedFonts | Where-Object { $_.DisplayName -match 'Cascadia' } | Select-Object -First 1
            $choices.Theme           = @{ Name = 'atomic'; Url = 'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/atomic.omp.json' }
            if ($tokyoNight) { $choices.Scheme = $tokyoNight.Scheme }
            if ($cascadia)   { $choices.Font = $cascadia }
            $choices.TabBar          = if ($tokyoNight) { $tokyoNight.Scheme.background } else { '#1a1b26' }
            $choices.AppTheme        = 'dark'
            $choices.Terminal        = $null  # keep terminal-config.json defaults
            $choices.PSReadLine      = 'scheme'
            $choices.Background      = $null
            $choices.Editor          = 'code'
            $choices.TelemetryOptOut = $false
            $choices.Features        = [ordered]@{ psfzf = $true; predictions = $true; startupMessage = $true; perDirProfiles = $true; commandOverrides = $false }
            $choices.CompletedSteps  = @('Theme', 'Scheme', 'Font', 'TabBar', 'Terminal', 'PSReadLine', 'Background', 'Editor', 'Telemetry', 'Features')
            Save-State
            Write-Host '  Quick-start preset applied. Jumping to summary.' -ForegroundColor Green
        }
    }

    # STEP 1: OMP theme
    if ('Theme' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '[1/10] Fetching Oh My Posh theme catalog...' -ForegroundColor Cyan
        $themes = Get-OmpThemeList
        if ($themes.Count -eq 0) {
            Write-Host '  (network failed or empty; keeping default "pure")' -ForegroundColor Yellow
            $choices.Theme = @{ Name = 'pure'; Url = 'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/pure.omp.json' }
        }
        else {
            Write-Host ("  {0} themes available. Type number, partial name, or Enter for 'pure' default." -f $themes.Count) -ForegroundColor DarkGray
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
        Write-Host ''
        Write-Host '-- Tab bar color --' -ForegroundColor Cyan
        Write-Host '  The strip at the top where tabs live. Default matches chosen color scheme background.'
        $schemeBg = if ($choices.Scheme) { $choices.Scheme.background } else { '#1a1b26' }
        $tabPresets = @(
            @{ Name = "Scheme match ($schemeBg)"; Desc = 'Seamless - tab bar same as terminal background'; Value = $schemeBg }
            @{ Name = 'Pure black (#000000)'; Desc = 'Maximum contrast'; Value = '#000000' }
            @{ Name = 'Warm brown (#2a221d)'; Desc = 'Muted dark'; Value = '#2a221d' }
            @{ Name = 'Custom hex'; Desc = 'Type your own #rrggbb'; Value = 'custom' }
            @{ Name = 'Skip'; Desc = 'Leave WT default'; Value = $null }
        )
        $pick = Select-WizardItem -Title 'Tab bar color' -Items $tabPresets -DefaultName "Scheme match ($schemeBg)"
        if ($pick -and $pick.Value -eq 'custom') {
            $hex = Read-Host '  Hex (e.g. #1e1e2e)'
            if ($hex -match '^#[0-9A-Fa-f]{6}$') { $choices.TabBar = $hex }
        }
        elseif ($pick -and $pick.Value) { $choices.TabBar = $pick.Value }

        # WT application theme controls window chrome (title bar, rounded corners) when a
        # custom themeDefinition is applied. 'dark' matches the curated color schemes; 'light'
        # inverts chrome for users on light system themes.
        $wantLight = Read-WizardYesNo -Prompt '  Use light window chrome (title bar, borders)?' -Default $false
        $choices.AppTheme = if ($wantLight) { 'light' } else { 'dark' }

        $choices.CompletedSteps += 'TabBar'
        Save-State
    }

    # STEP 5: Terminal appearance (opacity, font size, cursor, padding, scrollbar, history).
    # Each prompt accepts Enter = keep default (nothing is written for that field, so the
    # terminal-config.json default still wins). Invalid values are rejected silently.
    if ('Terminal' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- Terminal appearance --' -ForegroundColor Cyan
        Write-Host '  Enter to keep current default for each field.' -ForegroundColor DarkGray
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

        Write-Host '  Cursor shape: 1=bar 2=block 3=vintage 4=emptyBox 5=filledBox 6=doubleUnderscore' -ForegroundColor DarkGray
        $csRaw = Read-Host '  Cursor shape (default bar)'
        $csMap = @{ '1' = 'bar'; '2' = 'block'; '3' = 'vintage'; '4' = 'emptyBox'; '5' = 'filledBox'; '6' = 'doubleUnderscore' }
        if ($csRaw -and $csMap.ContainsKey($csRaw)) { $term['cursorShape'] = $csMap[$csRaw] }
        elseif ($csRaw -and ($csMap.Values -contains $csRaw)) { $term['cursorShape'] = $csRaw }

        $padRaw = Read-Host '  Cell padding in pixels 0-50 (default 8)'
        $padInt = 0
        if ($padRaw -and [int]::TryParse($padRaw, [ref]$padInt) -and $padInt -ge 0 -and $padInt -le 50) {
            $term['padding'] = "$padInt, $padInt, $padInt, $padInt"
        }

        Write-Host '  Scrollbar: 1=visible 2=hidden 3=always' -ForegroundColor DarkGray
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

    # STEP 6: PSReadLine syntax colors. Three options:
    #   1) Keep theme.json default (ship-time palette)
    #   2) Derive from chosen WT color scheme (maps scheme roles to PSReadLine roles)
    #   3) Skip - user edits user-settings.json.psreadline.colors manually later
    if ('PSReadLine' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- PSReadLine syntax colors --' -ForegroundColor Cyan
        $rlOptions = @(
            @{ Name = 'theme.json default'; Desc = 'Keep the shipped palette'; Value = 'default' }
            @{ Name = 'Derive from color scheme'; Desc = 'Map scheme ANSI roles to syntax (Command, String, ...)'; Value = 'scheme' }
            @{ Name = 'Skip'; Desc = 'No override; edit user-settings.json later'; Value = $null }
        )
        $pick = Select-WizardItem -Title 'PSReadLine colors' -Items $rlOptions -DefaultName 'theme.json default'
        if ($pick -and $pick.Value) { $choices.PSReadLine = $pick.Value }
        $choices.CompletedSteps += 'PSReadLine'
        Save-State
    }

    # STEP 7: background image
    if ('Background' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- Background image (optional) --' -ForegroundColor Cyan
        if (Read-WizardYesNo -Prompt 'Set a background image?' -Default $false) {
            $bgPath = Read-Host '  Path to image (png/jpg/gif)'
            if ($bgPath -and (Test-Path -LiteralPath $bgPath)) {
                $opRaw = Read-Host '  Opacity 0.05-0.50 (Enter = 0.10)'
                $op = 0.10
                $tmp = 0.0
                if ($opRaw -and [double]::TryParse($opRaw, [ref]$tmp) -and $tmp -ge 0.05 -and $tmp -le 0.50) { $op = $tmp }
                $choices.Background = @{ Path = (Resolve-Path $bgPath).ProviderPath; Opacity = $op }
            }
            else { Write-Host '  (no file found; skipping)' -ForegroundColor Yellow }
        }
        $choices.CompletedSteps += 'Background'
        Save-State
    }

    # STEP 8: Editor preference (was setup.ps1 [2/10] - moved into the wizard so all
    # interactive choices are in one place). The outer [2/10] step reads $choices.Editor
    # and only prompts on its own when the wizard was skipped.
    if ('Editor' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- Preferred editor --' -ForegroundColor Cyan
        $choices.Editor = Select-PreferredEditor
        $choices.CompletedSteps += 'Editor'
        Save-State
    }

    # STEP 9: Telemetry opt-out (was end-of-setup prompt - moved into the wizard).
    # Only ask if the env var is not already set so repeat runs do not nag.
    if ('Telemetry' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- PowerShell telemetry --' -ForegroundColor Cyan
        if ([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
            Write-Host '  POWERSHELL_TELEMETRY_OPTOUT is already set. No change.' -ForegroundColor DarkGray
            $choices.TelemetryOptOut = $false
        }
        else {
            $choices.TelemetryOptOut = Read-WizardYesNo -Prompt '  Opt out of PowerShell telemetry? Sets POWERSHELL_TELEMETRY_OPTOUT=true machine-wide' -Default $false
        }
        $choices.CompletedSteps += 'Telemetry'
        Save-State
    }

    # STEP 10: feature toggles
    if ('Features' -notin $choices.CompletedSteps) {
        Write-Host ''
        Write-Host '-- Profile feature toggles --' -ForegroundColor Cyan
        $features = [ordered]@{}
        $features['psfzf']          = Read-WizardYesNo -Prompt '  PSFzf fuzzy search (Ctrl+R history, Ctrl+T files)?' -Default $true
        $features['predictions']    = Read-WizardYesNo -Prompt '  PSReadLine predictions (autocomplete suggestions)?' -Default $true
        $features['startupMessage'] = Read-WizardYesNo -Prompt '  Show "Profile loaded in Xms" at startup?' -Default $true
        $features['perDirProfiles'] = Read-WizardYesNo -Prompt '  Auto-load .psprc.ps1 on cd into trusted dirs?' -Default $true
        $features['commandOverrides'] = Read-WizardYesNo -Prompt '  Allow user-settings.json commandOverrides (JSON -> scriptblock)?' -Default $false
        $choices.Features = $features
        $choices.CompletedSteps += 'Features'
        Save-State
    }

    # SUMMARY + confirm
    Write-Host ''
    Write-Host '=========================================' -ForegroundColor Magenta
    Write-Host '  Summary of your choices' -ForegroundColor Magenta
    Write-Host '=========================================' -ForegroundColor Magenta
    Write-Host ("  OMP theme:    {0}" -f $(if ($choices.Theme) { $choices.Theme.Name } else { '(default)' }))
    Write-Host ("  Color scheme: {0}" -f $(if ($choices.Scheme) { $choices.Scheme.name } else { '(default)' }))
    Write-Host ("  Nerd Font:    {0}" -f $(if ($choices.Font) { $choices.Font.DisplayName } else { '(default)' }))
    Write-Host ("  Tab bar:      {0}" -f $(if ($choices.TabBar) { "$($choices.TabBar) ($($choices.AppTheme) chrome)" } else { '(WT default)' }))
    Write-Host '  Terminal:'
    if ($choices.Terminal) {
        foreach ($k in $choices.Terminal.Keys) {
            Write-Host ("    {0,-16} = {1}" -f $k, $choices.Terminal[$k])
        }
    }
    else { Write-Host '    (all defaults)' -ForegroundColor DarkGray }
    Write-Host ("  PSReadLine:   {0}" -f $(if ($choices.PSReadLine) { $choices.PSReadLine } else { '(theme.json default)' }))
    Write-Host ("  Background:   {0}" -f $(if ($choices.Background) { "$($choices.Background.Path) @ $($choices.Background.Opacity)" } else { '(none)' }))
    Write-Host ("  Editor:       {0}" -f $(if ($choices.Editor) { $choices.Editor } else { '(prompted outside wizard)' }))
    Write-Host ("  Telemetry:    {0}" -f $(if ($choices.TelemetryOptOut) { 'opt out' } else { 'keep (no change)' }))
    Write-Host '  Features:'
    if ($choices.Features) {
        foreach ($k in $choices.Features.Keys) {
            Write-Host ("    {0,-18} = {1}" -f $k, $choices.Features[$k])
        }
    }
    Write-Host ''
    if (-not (Read-WizardYesNo -Prompt 'Apply all choices?' -Default $true)) {
        Write-Host 'Wizard cancelled. Re-run setup.ps1 -Wizard to start over, or -Resume to continue.' -ForegroundColor Yellow
        throw 'WizardCancelled'
    }

    # Clean up state file on success
    if ($StatePath -and (Test-Path $StatePath)) { Remove-Item $StatePath -Force -ErrorAction SilentlyContinue }
    return $choices
}

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$isCiHost = $CiMode -or [bool]$env:GITHUB_ACTIONS -or [bool]$env:CI

# Ensure the script can run with elevated privileges for local installs.
# In CI/non-admin mode we continue and skip admin-only steps instead of exiting.
# Hard-failure paths use `exit 1` (when run as a file) so callers and CI see a non-zero
# exit code. In `irm | iex` mode $PSCommandPath is empty, so we fall back to `return`
# to avoid terminating the user's shell.
if (-not $isElevated -and -not $isCiHost) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    if ($PSCommandPath) { exit 1 } else { return }
}
elseif (-not $isElevated -and $isCiHost) {
    Write-Host "Running setup.ps1 in CI/non-admin mode. Admin-only steps (LocalMachine execution policy, system-wide font install) will be skipped." -ForegroundColor Yellow
}

# ExecutionPolicy is security-sensitive. setup.ps1 must never silently relax it.
# We only surface guidance; users can opt in manually if their environment requires it.
$currentUserPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentUserPolicy -eq 'AllSigned') {
    $canPromptPolicy = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
    if ($canPromptPolicy) { try { $null = [Console]::KeyAvailable } catch { $canPromptPolicy = $false } }
    if ($canPromptPolicy) {
        Write-Host "CurrentUser execution policy is 'AllSigned' (stricter than RemoteSigned)." -ForegroundColor Yellow
        $reply = Read-Host "  Downgrade to RemoteSigned so the profile can load unsigned scripts? [y/N]"
        if ($reply -match '^[Yy]') {
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Write-Host "Execution policy set to RemoteSigned for CurrentUser." -ForegroundColor Green
        }
        else {
            Write-Host "  Kept AllSigned. Profile will not load unless all .ps1 files are signed." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  CurrentUser policy is AllSigned. Skipping downgrade prompt (non-interactive)." -ForegroundColor Yellow
    }
}
elseif ($currentUserPolicy -in @('Restricted', 'Undefined')) {
    Write-Host "CurrentUser execution policy is '$currentUserPolicy'." -ForegroundColor Yellow
    Write-Host "  If the installed profile is blocked, opt in manually with:" -ForegroundColor DarkYellow
    Write-Host "  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor DarkYellow
}
# Offer LocalMachine scope (covers all users and both PS editions) but don't force it.
# In CI/non-admin mode we skip this prompt entirely.
if (-not $isCiHost) {
    $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($machinePolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
        Write-Host "LocalMachine execution policy is '$machinePolicy'." -ForegroundColor Yellow
        Write-Host "  setup.ps1 leaves machine-wide policy unchanged. Change it manually only if you intend to affect all users." -ForegroundColor DarkYellow
    }
}

# Function to test internet connectivity (HTTPS - works through corporate proxies/firewalls)
function Test-InternetConnection {
    try {
        $response = Invoke-WebRequest -Uri "https://github.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $response.StatusCode -eq 200
    }
    catch {
        Write-Host "Internet connection is required but not available (cannot reach github.com)." -ForegroundColor Red
        return $false
    }
}

# Function to install Nerd Fonts
function Install-NerdFonts {
    param (
        [string]$FontName = "CascadiaCode",
        [string]$FontDisplayName = "CaskaydiaCove NF",
        [string]$Version = "3.2.1"
    )

    try {
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        $fontCollection = New-Object System.Drawing.Text.InstalledFontCollection
        $fontFamilies = $fontCollection.Families.Name
        $fontCollection.Dispose()
        if ($fontFamilies -notcontains "${FontDisplayName}") {
            Write-Host "  Installing ${FontDisplayName}..." -ForegroundColor Yellow
            $fontZipUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/v${Version}/${FontName}.zip"
            $zipFilePath = "$env:TEMP\${FontName}.zip"
            $extractPath = "$env:TEMP\${FontName}"

            $webClient = New-Object System.Net.WebClient
            try {
                $webClient.DownloadFile((New-Object System.Uri($fontZipUrl)), $zipFilePath)
            }
            finally {
                $webClient.Dispose()
            }
            if (-not (Test-Path $zipFilePath) -or (Get-Item $zipFilePath).Length -eq 0) {
                throw "Font download is missing or empty"
            }

            Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force
            $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
            $fontFiles = Get-ChildItem -Path $extractPath -Recurse -Filter "*.ttf"
            $copied = 0
            foreach ($f in $fontFiles) {
                if (-not (Test-Path "$env:SystemRoot\Fonts\$($f.Name)")) {
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
                        -not (Test-Path "$env:SystemRoot\Fonts\$($_.Name)")
                    }
                    if (-not $pending) { break }
                    Start-Sleep -Milliseconds 500
                    $elapsed += 0.5
                }
            }

            Remove-Item -Path $extractPath -Recurse -Force
            Remove-Item -Path $zipFilePath -Force
            if ($copied -gt 0 -and $pending) {
                # Partial install: some files never appeared under %SystemRoot%\Fonts within the
                # timeout. Report failure so callers can surface it instead of claiming success.
                Write-Host "  Font copy timed out: $(@($pending).Count) of $copied file(s) did not install." -ForegroundColor Red
                return $false
            }
            Write-Host "  ${FontDisplayName} installed." -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "  ${FontDisplayName} already installed." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "  Failed to install ${FontDisplayName}: $_" -ForegroundColor Red
        return $false
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

# Resolve the active Windows Terminal settings.json across install variants.
# DUPLICATED from Microsoft.PowerShell_profile.ps1's Get-WindowsTerminalSettingsPath.
# Keep these two copies in sync per CLAUDE.md "Structural Duplication" guidance.
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

# Return ALL existing WT settings.json across variants so step [10/10] writes to every
# installed variant (Stable + Preview + Canary + unpackaged). DUPLICATED from profile.
function Get-WindowsTerminalSettingsPaths {
    $candidates = @(
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json'
    )
    @($candidates | Where-Object { Test-Path -LiteralPath $_ })
}

# Resolve the real path of an external command, following aliases recursively.
# DUPLICATED from Microsoft.PowerShell_profile.ps1's Get-ExternalCommandPath.
# Keep these two copies in sync per CLAUDE.md "Structural Duplication" guidance.
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

# Resolve oh-my-posh executable path (Get-ExternalCommandPath or known install locations)
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

# Check for internet connectivity before proceeding (skip when using a local repo)
if (-not $LocalRepo -and -not (Test-InternetConnection)) {
    if ($PSCommandPath) { exit 1 } else { return }
}

# JSONC comment-stripping regex (built via variable to avoid PS5 parser bug with [^"] in strings)
$_q = [char]34
$jsoncCommentPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*`$"

# Download theme.json (single source of truth for theme + WT metadata)
$profileConfig = $null
$configCachePath = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
if (!(Test-Path -Path $configCachePath)) {
    New-Item -Path $configCachePath -ItemType "directory" -Force | Out-Null
}

# Install wizard. Writes user choices to user-settings.json BEFORE downstream steps, so
# the rest of setup.ps1 (WT sync, font install, cache writes) picks up those overrides
# via the existing user-settings merge logic. Non-interactive hosts always skip.
$canRunWizard = [Environment]::UserInteractive -and -not $isCiHost -and -not [bool]$env:AI_AGENT
$wantWizard = ($Wizard -or $canRunWizard) -and -not $SkipWizard
if ($wantWizard) {
    $wizardState = Join-Path $env:TEMP 'psp-wizard-state.json'
    if (-not $Resume -and (Test-Path $wizardState)) {
        # Stale state file from a previous aborted run; the wizard itself asks if we resume,
        # but if -Resume was not passed explicitly, clean out any state older than 24h.
        $age = (Get-Date) - (Get-Item $wizardState).LastWriteTime
        if ($age.TotalHours -gt 24) { Remove-Item $wizardState -Force -ErrorAction SilentlyContinue }
    }
    try {
        $wizChoices = Start-InstallWizard -StatePath $wizardState
        $userSettingsPath = Join-Path $configCachePath 'user-settings.json'
        Save-WizardChoices -Choices $wizChoices -UserSettingsPath $userSettingsPath
        Write-Host ''
        Write-Host 'Wizard choices saved to user-settings.json.' -ForegroundColor Green

        # If user picked a Nerd Font, override the version-pinned font install step
        # by re-invoking Install-NerdFonts with the chosen asset/display name + latest release.
        # Only mark WizardFontInstalled = $true when the install actually succeeded so step
        # [4/10] falls back to the default install instead of silently leaving no font.
        if ($wizChoices.Font) {
            $latestVer = Get-LatestNerdFontVersion
            Write-Host ("Installing Nerd Font: {0} v{1}..." -f $wizChoices.Font.DisplayName, $latestVer) -ForegroundColor Cyan
            $wizardFontOk = Install-NerdFonts -FontName $wizChoices.Font.Asset -FontDisplayName $wizChoices.Font.DisplayName -Version $latestVer
            if ($wizardFontOk) {
                $script:WizardFontInstalled = $true
            }
            else {
                Write-Host "  Wizard font install did not complete; step [4/10] will retry with the default font." -ForegroundColor Yellow
            }
        }

        # If OMP theme chosen, write its URL so downstream OMP install uses that instead of
        # theme.json's default. We do this by patching the fetched $profileConfig below.
        $script:WizardOmpTheme = $wizChoices.Theme

        # Expose editor + telemetry choices so [2/10] and the end-of-setup prompt skip
        # their own interactive prompts (the wizard already captured the user's answer).
        $script:WizardEditor = $wizChoices.Editor
        $script:WizardTelemetryHandled = ($null -ne $wizChoices.TelemetryOptOut)

        # Apply telemetry opt-out immediately (we are already elevated inside setup.ps1).
        # Ownership marker lets Uninstall-Profile know the value is ours and safe to remove.
        if ($wizChoices.TelemetryOptOut -and -not [System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
            try {
                [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
                $telemetryMarker = Join-Path $configCachePath 'telemetry.owned'
                [System.IO.File]::WriteAllText($telemetryMarker, "set by setup.ps1 wizard at $(Get-Date -Format o)`n", [System.Text.UTF8Encoding]::new($false))
                Write-Host 'Telemetry opt-out applied from wizard choice.' -ForegroundColor DarkGray
            }
            catch {
                Write-Host "  Failed to apply telemetry opt-out: $_" -ForegroundColor Yellow
            }
        }
    }
    catch {
        if ($_.Exception.Message -eq 'WizardCancelled') {
            Write-Host 'Continuing setup without wizard overrides.' -ForegroundColor Yellow
        }
        else {
            Write-Warning ("Wizard failed: {0}. Continuing with defaults." -f $_.Exception.Message)
        }
    }
}

try {
    $configTmp = Join-Path $env:TEMP ("psp-theme-" + [System.IO.Path]::GetRandomFileName() + ".json")
    Copy-Item (Resolve-SetupSourcePath -Kind 'theme') $configTmp -Force -ErrorAction Stop
    $profileConfig = Get-Content $configTmp -Raw | ConvertFrom-Json
    Copy-Item $configTmp (Join-Path $configCachePath "theme.json") -Force
    Remove-Item $configTmp -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Could not load theme.json. Theme and color scheme steps will be skipped." -ForegroundColor Yellow
}

# Download terminal-config.json (WT behavior settings: scrollbar, historySize, keybindings)
$terminalConfig = $null
try {
    $terminalConfigTmp = Join-Path $env:TEMP ("psp-terminal-" + [System.IO.Path]::GetRandomFileName() + ".json")
    Copy-Item (Resolve-SetupSourcePath -Kind 'terminal') $terminalConfigTmp -Force -ErrorAction Stop
    $terminalConfig = Get-Content $terminalConfigTmp -Raw | ConvertFrom-Json
    Copy-Item $terminalConfigTmp (Join-Path $configCachePath "terminal-config.json") -Force
    Remove-Item $terminalConfigTmp -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Could not load terminal-config.json. Terminal behavior settings (font, scrollbar, keybindings) will not be applied." -ForegroundColor Yellow
}

# Merge helper - deep-merges PSCustomObjects so nested keys are preserved
function Merge-JsonObject($base, $override) {
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

# Editor candidates for interactive selection. WingetId = $null means built-in (not installed via winget).
# WingetIds verified with: winget search --id <Id>
$EditorCandidates = @(
    @{ Cmd = 'code'; Display = 'Visual Studio Code'; WingetId = 'Microsoft.VisualStudioCode' }
    @{ Cmd = 'nvim'; Display = 'Neovim'; WingetId = 'Neovim.Neovim' }
    @{ Cmd = 'vim'; Display = 'Vim'; WingetId = 'vim.vim' }
    @{ Cmd = 'msedit'; Display = 'Microsoft Edit'; WingetId = 'Microsoft.Edit' }
    @{ Cmd = 'subl'; Display = 'Sublime Text'; WingetId = 'SublimeHQ.SublimeText.4' }
    @{ Cmd = 'notepad++'; Display = 'Notepad++'; WingetId = 'Notepad++.Notepad++' }
    @{ Cmd = 'notepad'; Display = 'Notepad (always available)'; WingetId = $null }
)

# Interactive editor preference prompt - returns chosen Cmd string
function Select-PreferredEditor {
    $defaultChoice = $null
    Write-Host ""
    Write-Host "  Select your preferred code editor:" -ForegroundColor Cyan
    Write-Host ""
    for ($i = 0; $i -lt $EditorCandidates.Count; $i++) {
        $ed = $EditorCandidates[$i]
        $num = $i + 1
        $installed = [bool](Get-Command $ed.Cmd -ErrorAction SilentlyContinue)
        if ($installed) {
            if ($null -eq $defaultChoice) { $defaultChoice = $i }
            Write-Host "   $num) $($ed.Display) ($($ed.Cmd)) " -NoNewline -ForegroundColor White
            Write-Host '[installed]' -ForegroundColor Green
        }
        else {
            Write-Host "   $num) $($ed.Display) ($($ed.Cmd))" -ForegroundColor DarkGray
        }
    }
    if ($null -eq $defaultChoice) { $defaultChoice = 0 }
    $defaultNum = $defaultChoice + 1
    Write-Host ""
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
        Write-Host "  Invalid choice, using default." -ForegroundColor Yellow
        return $EditorCandidates[$defaultChoice].Cmd
    }
    if (-not (Get-Command $chosen.Cmd -ErrorAction SilentlyContinue)) {
        Write-Host "  '$($chosen.Cmd)' is not installed." -ForegroundColor Yellow
        $confirm = Read-Host "  Use anyway? [y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "  Using default instead." -ForegroundColor Yellow
            return $EditorCandidates[$defaultChoice].Cmd
        }
    }
    return $chosen.Cmd
}

# Apply user-settings.json overrides (never downloaded, never overwritten)
$userSettingsPath = Join-Path $configCachePath "user-settings.json"
if (Test-Path $userSettingsPath) {
    try {
        $userSettings = Get-Content $userSettingsPath -Raw | ConvertFrom-Json
        if ($profileConfig -and $userSettings.theme) {
            if (-not $profileConfig.theme) {
                $profileConfig | Add-Member -NotePropertyName "theme" -NotePropertyValue ([PSCustomObject]@{}) -Force
            }
            Merge-JsonObject $profileConfig.theme $userSettings.theme
        }
        if ($profileConfig -and $userSettings.windowsTerminal) {
            if (-not $profileConfig.windowsTerminal) {
                $profileConfig | Add-Member -NotePropertyName "windowsTerminal" -NotePropertyValue ([PSCustomObject]@{}) -Force
            }
            Merge-JsonObject $profileConfig.windowsTerminal $userSettings.windowsTerminal
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
        Write-Host "Failed to parse user-settings.json: $_" -ForegroundColor Yellow
    }
}

# Check for winget availability
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget (App Installer) is required but not found." -ForegroundColor Red
    Write-Host "Install it from the Microsoft Store or https://aka.ms/getwinget" -ForegroundColor Yellow
    if ($PSCommandPath) { exit 1 } else { return }
}

Write-Host ""
Write-Host "PowerShell Profile Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Profile creation or update (install for both PS5 and PS7)
Write-Host "[1/10] Profile" -ForegroundColor Cyan
# Derive Documents root from $PROFILE (works correctly even when Documents is in OneDrive)
$docsRoot = Split-Path (Split-Path $PROFILE)
$profileDirs = @(
    Join-Path $docsRoot "PowerShell"          # PS7 (Core)
    Join-Path $docsRoot "WindowsPowerShell"    # PS5 (Desktop)
)
$profileInstalled = $true
foreach ($dir in $profileDirs) {
    $targetProfile = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
    try {
        if (!(Test-Path -Path $dir)) {
            New-Item -Path $dir -ItemType "directory" -Force | Out-Null
        }
        # Copy/download to temp first so a partial/corrupt download never overwrites the existing profile
        $tempDownload = Join-Path $env:TEMP ("psp-profile_download_" + (Split-Path $dir -Leaf) + "_" + [System.IO.Path]::GetRandomFileName() + ".ps1")
        Copy-Item (Resolve-SetupSourcePath -Kind 'profile') $tempDownload -Force -ErrorAction Stop
        if (Test-Path -Path $targetProfile -PathType Leaf) {
            # Timestamped + rolling so a second install never destroys the first backup.
            # Matches the WT settings backup pattern (keep last 5). Older "oldprofile.ps1"
            # (pre-timestamp format) is also swept by the rolling cleanup below.
            $backupStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $backupPath = Join-Path $dir ("oldprofile.$backupStamp.ps1")
            Copy-Item -Path $targetProfile -Destination $backupPath -Force
            Write-Host "  Backup saved to [$backupPath]" -ForegroundColor DarkGray
            $oldBackups = Get-ChildItem -Path $dir -Filter 'oldprofile*.ps1' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -Skip 5
            foreach ($old in $oldBackups) {
                Remove-Item $old.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        Move-Item -Path $tempDownload -Destination $targetProfile -Force
        Write-Host "  Profile installed at [$targetProfile]" -ForegroundColor Green

        # Create starter user override file if it doesn't exist (never overwrite)
        $userProfilePath = Join-Path $dir "profile_user.ps1"
        if (-not (Test-Path $userProfilePath)) {
            $userProfileContent = @'
### profile_user.ps1 - Personal overrides (survives Update-Profile)
### This file is dot-sourced at the end of the main profile.
### Uncomment or add your own customizations below.

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
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [System.IO.File]::WriteAllText($userProfilePath, $userProfileContent, $utf8NoBom)
            Write-Host "  User override file created at [$userProfilePath]" -ForegroundColor Green
        }
        else {
            Write-Host "  User override file already exists at [$userProfilePath] (preserved)" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  Failed to install profile at [$targetProfile]: $_" -ForegroundColor Red
        Remove-Item $tempDownload -ErrorAction SilentlyContinue
        $profileInstalled = $false
    }
}

# Create starter user-settings.json template if it doesn't exist (never overwrite)
$userSettingsTemplate = Join-Path $configCachePath "user-settings.json"
if (-not (Test-Path $userSettingsTemplate)) {
    $settingsContent = @'
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
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($userSettingsTemplate, $settingsContent, $utf8NoBom)
    Write-Host "  User settings template created at [$userSettingsTemplate]" -ForegroundColor Green
}
else {
    Write-Host "  User settings file already exists at [$userSettingsTemplate] (preserved)" -ForegroundColor DarkGray
}

function Set-PreferredEditorInProfiles {
    param(
        [Parameter(Mandatory)][string]$EditorName,
        [Parameter(Mandatory)][string]$CommentLabel
    )
    $editorLine = '$script:EditorPriority = @(' + "'$EditorName', 'notepad'" + ')'
    foreach ($dir in $profileDirs) {
        $userProfilePath = Join-Path $dir "profile_user.ps1"
        if (-not (Test-Path $userProfilePath)) { continue }
        $content = [System.IO.File]::ReadAllText($userProfilePath)
        if ($content -match '(?m)^\$script:EditorPriority\s*=') {
            $content = $content -replace '(?m)^\$script:EditorPriority\s*=.*$', $editorLine
        }
        else {
            $content = $content.TrimEnd() + "`r`n`r`n# --- Preferred editor ($CommentLabel) ---`r`n$editorLine`r`n"
        }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($userProfilePath, $content, $utf8NoBom)
    }
}

if ($script:DownloadedProfilePath) { Remove-Item $script:DownloadedProfilePath -Force -ErrorAction SilentlyContinue }
if ($script:DownloadedThemeConfigPath) { Remove-Item $script:DownloadedThemeConfigPath -Force -ErrorAction SilentlyContinue }
if ($script:DownloadedTerminalConfigPath) { Remove-Item $script:DownloadedTerminalConfigPath -Force -ErrorAction SilentlyContinue }

function Resolve-ConfiguredEditor {
    param([Parameter(Mandatory)][string]$RequestedEditor)
    $chosen = $EditorCandidates | Where-Object { $_.Cmd -eq $RequestedEditor } | Select-Object -First 1
    $resolvedEditor = $RequestedEditor
    if ($chosen -and $chosen.WingetId -and -not (Get-Command $RequestedEditor -ErrorAction SilentlyContinue)) {
        if ($isCiHost) {
            Write-Host "  CI mode: skipping editor install for $($chosen.Display)." -ForegroundColor DarkGray
            $resolvedEditor = 'notepad'
        }
        elseif (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host "  Installing $($chosen.Display) via winget..." -ForegroundColor Cyan
            $null = winget install -e --id $chosen.WingetId --accept-source-agreements --accept-package-agreements 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335185 -or $LASTEXITCODE -eq -1978335189) {
                # Filter null/empty before joining: a missing User PATH would otherwise produce
                # a trailing ';' in $env:PATH, which Windows path parsing has historically
                # interpreted as "include CWD" - a classic command-hijack surface during setup.
                $machinePath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
                $userPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
                $env:PATH = (@($machinePath, $userPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';'
                Write-Host "  $($chosen.Display) installed." -ForegroundColor Green
            }
            else {
                Write-Host "  Could not install $($chosen.Display) via winget. Using Notepad." -ForegroundColor Yellow
                $resolvedEditor = 'notepad'
            }
        }
        else {
            Write-Host "  winget not found. Using Notepad." -ForegroundColor Yellow
            $resolvedEditor = 'notepad'
        }
    }
    return $resolvedEditor
}

# Editor preference (interactive prompt writes $script:EditorPriority into profile_user.ps1).
# When the wizard already captured an editor choice we skip the prompt and use it directly.
Write-Host "[2/10] Editor preference" -ForegroundColor Cyan
$canPromptEditor = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
if ($canPromptEditor) { try { $null = [Console]::KeyAvailable } catch { $canPromptEditor = $false } }
if ($script:WizardEditor) {
    $chosenEditor = [string]$script:WizardEditor
    Write-Host "  Using wizard choice: $chosenEditor" -ForegroundColor DarkGray
    $chosenEditor = Resolve-ConfiguredEditor -RequestedEditor $chosenEditor
    Write-Host "  Editor set to: $chosenEditor" -ForegroundColor Green
    Set-PreferredEditorInProfiles -EditorName $chosenEditor -CommentLabel 'set by setup.ps1 wizard'
}
elseif ($canPromptEditor) {
    $chosenEditor = Select-PreferredEditor
    $chosenEditor = Resolve-ConfiguredEditor -RequestedEditor $chosenEditor
    Write-Host "  Editor set to: $chosenEditor" -ForegroundColor Green
    Set-PreferredEditorInProfiles -EditorName $chosenEditor -CommentLabel 'set by setup.ps1'
}
else {
    Write-Host "  Skipped (non-interactive). Default: code, notepad" -ForegroundColor Yellow
}

# Function to download Oh My Posh theme locally (skips download if file exists and is valid JSON)
function Install-OhMyPoshTheme {
    param (
        [Parameter(Mandatory)]
        [string]$ThemeName,
        [Parameter(Mandatory)]
        [string]$ThemeUrl
    )
    $themeFilePath = Join-Path $configCachePath "$ThemeName.omp.json"
    try {
        if (-not (Test-IsTrustedRawGitHubUrl -Url $ThemeUrl)) {
            throw "Refusing to download theme from untrusted host: $ThemeUrl"
        }
        $alreadyValid = $false
        if (Test-Path -LiteralPath $themeFilePath -PathType Leaf) {
            try {
                $null = Get-Content $themeFilePath -Raw -ErrorAction Stop | ConvertFrom-Json
                $alreadyValid = $true
            } catch { $null = $_ }
        }
        if (-not $alreadyValid) {
            Invoke-DownloadWithRetry -Uri $ThemeUrl -OutFile $themeFilePath
            $null = Get-Content $themeFilePath -Raw | ConvertFrom-Json
            Write-Host "  Theme '$ThemeName' downloaded." -ForegroundColor Green
        }
        else {
            Write-Host "  Theme '$ThemeName' already present." -ForegroundColor Green
        }
        return $true
    }
    catch {
        Write-Host "  Failed to download/validate theme: $_" -ForegroundColor Red
        Remove-Item $themeFilePath -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# Install or verify a winget package (deduplicates the 3x install pattern)
function Install-WingetPackage {
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Id
    )
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "  winget not found. Skipping $Name." -ForegroundColor Yellow
        return $false
    }
    $null = winget install -e --id $Id --accept-source-agreements --accept-package-agreements 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  $Name installed." -ForegroundColor Green
        return $true
    }
    elseif ($LASTEXITCODE -eq -1978335185 -or $LASTEXITCODE -eq -1978335189) {
        # -1978335185 = already installed (winget install)
        # -1978335189 = no applicable update (winget upgrade)
        Write-Host "  $Name already installed." -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "  $Name install may have failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
        return $false
    }
}

# OMP Install
Write-Host "[3/10] Oh My Posh" -ForegroundColor Cyan
$ompPath = Get-OhMyPoshExecutablePath
if ($ompPath -and $ompPath -notlike ((Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') + '*')) {
    Write-Host "  Oh My Posh already present at $ompPath (preserved)." -ForegroundColor Green
    $ompInstalled = $true
}
elseif ($isCiHost) {
    Write-Host "  CI mode: skipping Oh My Posh install." -ForegroundColor DarkGray
    $ompInstalled = $true
}
else {
    $ompInstalled = Install-WingetPackage -Name "Oh My Posh" -Id "JanDeDobbeleer.OhMyPosh"
}
# Wizard OMP-theme override wins if present; otherwise use theme.json default.
if ($script:WizardOmpTheme) {
    $themeInstalled = Install-OhMyPoshTheme -ThemeName $script:WizardOmpTheme.Name -ThemeUrl $script:WizardOmpTheme.Url
}
elseif ($profileConfig -and $profileConfig.theme -and $profileConfig.theme.name -and $profileConfig.theme.url) {
    $themeInstalled = Install-OhMyPoshTheme -ThemeName $profileConfig.theme.name -ThemeUrl $profileConfig.theme.url
}
else {
    $reason = if (-not $profileConfig) { "theme.json missing" }
    elseif (-not $profileConfig.theme -or -not $profileConfig.theme.name) { "theme name missing" }
    else { "theme URL missing" }
    Write-Host "  Skipped theme download ($reason)." -ForegroundColor Yellow
    $themeInstalled = $false
}
# Invalidate zoxide cache and any leftover legacy OMP init cache from older profile versions.
foreach ($cacheFile in @('zoxide-init.ps1', 'omp-init.ps1')) {
    Remove-Item (Join-Path $configCachePath $cacheFile) -Force -ErrorAction SilentlyContinue
}

# Font Install
Write-Host "[4/10] Nerd Fonts" -ForegroundColor Cyan
$fontName = "CascadiaCode"
$fontDisplayName = "CaskaydiaCove NF"
$fontVersion = "3.2.1"
if ($terminalConfig -and $terminalConfig.fontInstall) {
    if ($terminalConfig.fontInstall.name) { $fontName = $terminalConfig.fontInstall.name }
    if ($terminalConfig.fontInstall.displayName) { $fontDisplayName = $terminalConfig.fontInstall.displayName }
    if ($terminalConfig.fontInstall.version) { $fontVersion = $terminalConfig.fontInstall.version }
}
if ($script:WizardFontInstalled) {
    Write-Host "  Font already installed by wizard; skipping default." -ForegroundColor DarkGray
    $fontInstalled = $true
}
elseif ($isCiHost) {
    Write-Host "  CI mode: skipping Nerd Font install." -ForegroundColor DarkGray
    $fontInstalled = $true
}
else {
    $fontInstalled = Install-NerdFonts -FontName $fontName -FontDisplayName $fontDisplayName -Version $fontVersion
}

# eza Install (modern ls replacement with icons and git status)
Write-Host "[5/10] eza" -ForegroundColor Cyan
$ezaInstalled = $true
if ($isCiHost) {
    Write-Host "  CI mode: skipping eza install." -ForegroundColor DarkGray
}
else {
    $ezaInstalled = Install-WingetPackage -Name "eza" -Id "eza-community.eza"
}
# Clean up leftover Terminal-Icons if present
Remove-Module Terminal-Icons -Force -ErrorAction SilentlyContinue
Uninstall-Module Terminal-Icons -AllVersions -Force -ErrorAction SilentlyContinue

# zoxide Install
Write-Host "[6/10] zoxide" -ForegroundColor Cyan
$zoxideInstalled = $true
if ($isCiHost) {
    Write-Host "  CI mode: skipping zoxide install." -ForegroundColor DarkGray
}
else {
    $zoxideInstalled = Install-WingetPackage -Name "zoxide" -Id "ajeetdsouza.zoxide"
}

# fzf + PSFzf Install (fuzzy finder for history and file search)
Write-Host "[7/10] fzf" -ForegroundColor Cyan
$fzfInstalled = $true
if ($isCiHost) {
    Write-Host "  CI mode: skipping fzf install." -ForegroundColor DarkGray
}
else {
    $fzfInstalled = Install-WingetPackage -Name "fzf" -Id "junegunn.fzf"
}
if ($isCiHost) {
    Write-Host "  CI mode: skipping PSFzf module install." -ForegroundColor DarkGray
}
elseif (-not (Get-Module -ListAvailable -Name PSFzf)) {
    try {
        Install-Module -Name PSFzf -Scope CurrentUser -Force -AllowClobber
        Write-Host "  PSFzf module installed." -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to install PSFzf module: $_" -ForegroundColor Red
        $fzfInstalled = $false
    }
}
else {
    Write-Host "  PSFzf module already installed." -ForegroundColor Green
}

# bat Install (syntax-highlighted cat replacement)
Write-Host "[8/10] bat" -ForegroundColor Cyan
$batInstalled = $true
if ($isCiHost) {
    Write-Host "  CI mode: skipping bat install." -ForegroundColor DarkGray
}
else {
    $batInstalled = Install-WingetPackage -Name "bat" -Id "sharkdp.bat"
}

# ripgrep Install (fast recursive grep, used by the grep function)
Write-Host "[9/10] ripgrep" -ForegroundColor Cyan
$rgInstalled = $true
if ($isCiHost) {
    Write-Host "  CI mode: skipping ripgrep install." -ForegroundColor DarkGray
}
else {
    $rgInstalled = Install-WingetPackage -Name "ripgrep" -Id "BurntSushi.ripgrep.MSVC"
}

# Windows Terminal configuration (merges font, theme, and appearance into existing settings).
# Iterates ALL installed WT variants so Stable + Preview + Canary all receive the merge.
Write-Host "[10/10] Windows Terminal" -ForegroundColor Cyan
$wtSettingsPaths = Get-WindowsTerminalSettingsPaths
if (-not $wtSettingsPaths -or $wtSettingsPaths.Count -eq 0) {
    Write-Host "  Windows Terminal settings not found (skipped)." -ForegroundColor Yellow
}
foreach ($wtSettingsPath in $wtSettingsPaths) {
    try {
        # Backup original (ConvertTo-Json strips JSONC comments and may reorder keys)
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupPath = "$wtSettingsPath.$timestamp.bak"
        Copy-Item $wtSettingsPath $backupPath -Force
        Write-Host "  Backup saved to $backupPath" -ForegroundColor DarkGray

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
                    Write-Host "  WT settings parse failed, retrying in 1s..." -ForegroundColor Yellow
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

        # Apply terminal-config.json defaults (font, opacity, scrollbar, etc.)
        if ($terminalConfig -and $terminalConfig.defaults) {
            $terminalConfig.defaults.PSObject.Properties | ForEach-Object {
                $defaults | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
            }
        }

        # Script params override JSON values when explicitly passed (work even without terminal-config.json)
        if ($PSBoundParameters.ContainsKey('FontSize')) {
            if (-not $defaults.font) {
                $defaults | Add-Member -NotePropertyName "font" -NotePropertyValue ([PSCustomObject]@{}) -Force
            }
            $defaults.font | Add-Member -NotePropertyName "size" -NotePropertyValue $FontSize -Force
        }
        if ($PSBoundParameters.ContainsKey('Opacity')) {
            $defaults | Add-Member -NotePropertyName "opacity" -NotePropertyValue $Opacity -Force
        }

        # Explicit -ColorScheme param wins over config
        $cfgColorScheme = if ($PSBoundParameters.ContainsKey('ColorScheme')) { $ColorScheme }
        elseif ($profileConfig -and $profileConfig.windowsTerminal -and $profileConfig.windowsTerminal.colorScheme) { $profileConfig.windowsTerminal.colorScheme }
        else { $null }
        $cfgCursorColor = if ($profileConfig -and $profileConfig.windowsTerminal -and $profileConfig.windowsTerminal.cursorColor) { $profileConfig.windowsTerminal.cursorColor } else { $null }
        if ($cfgColorScheme) {
            $defaults | Add-Member -NotePropertyName "colorScheme" -NotePropertyValue $cfgColorScheme -Force
        }
        if ($cfgCursorColor) {
            $defaults | Add-Member -NotePropertyName "cursorColor" -NotePropertyValue $cfgCursorColor -Force
        }

        # Upsert color scheme from config
        if ($profileConfig -and $profileConfig.windowsTerminal -and $profileConfig.windowsTerminal.scheme) {
            $schemeDef = [PSCustomObject]$profileConfig.windowsTerminal.scheme
            if (-not $wt.schemes) {
                $wt | Add-Member -NotePropertyName "schemes" -NotePropertyValue @() -Force
            }
            $wt.schemes = @(@($wt.schemes | Where-Object { $_ -and $_.name -ne $schemeDef.name }) + $schemeDef)
        }

        # Upsert custom WT theme (tab bar colors, window chrome) from config
        if ($profileConfig -and $profileConfig.windowsTerminal -and $profileConfig.windowsTerminal.themeDefinition) {
            $themeDef = [PSCustomObject]$profileConfig.windowsTerminal.themeDefinition
            if (-not $wt.themes) {
                $wt | Add-Member -NotePropertyName "themes" -NotePropertyValue @() -Force
            }
            $wt.themes = @(@($wt.themes | Where-Object { $_ -and $_.name -ne $themeDef.name }) + $themeDef)
        }
        if ($profileConfig -and $profileConfig.windowsTerminal -and $profileConfig.windowsTerminal.theme) {
            if ($wt.PSObject.Properties['theme']) { $wt.theme = $profileConfig.windowsTerminal.theme }
            else { $wt | Add-Member -NotePropertyName "theme" -NotePropertyValue $profileConfig.windowsTerminal.theme -Force }
        }

        # Ensure PowerShell profiles launch with -NoLogo to suppress
        # the copyright banner and "Loading personal and system profiles took ..." message
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
                        $exe = if ($isPwsh) { 'pwsh.exe' } else { 'powershell.exe' }
                        $prof | Add-Member -NotePropertyName "commandline" -NotePropertyValue "$exe -NoLogo" -Force
                    }
                }
            }
        }

        # Apply keybindings from terminal-config.json
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

        # Depth 100: WT settings can have deeply nested action/command objects;
        # depth 10 silently truncates those to their type name string and corrupts settings.
        $wtJson = $wt | ConvertTo-Json -Depth 100
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($wtSettingsPath, $wtJson, $utf8NoBom)
        $schemeLabel = if ($cfgColorScheme) { $cfgColorScheme } else { "(unchanged)" }
        Write-Host "  Windows Terminal configured (scheme: $schemeLabel)." -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to configure Windows Terminal ($wtSettingsPath): $_" -ForegroundColor Red
    }
}

# Optional: PowerShell telemetry opt-out (explicit consent, machine-wide env var, requires admin).
# Previously this was written silently on every admin shell from the profile; moved here so users
# see the prompt and understand the scope. Skipped in non-interactive / CI / agent contexts and
# when not elevated (env var lives in HKLM).
$canPromptTelemetry = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
if ($canPromptTelemetry) { try { $null = [Console]::KeyAvailable } catch { $canPromptTelemetry = $false } }
$isElevatedSetup = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($script:WizardTelemetryHandled) {
    # Wizard already captured the user's choice and (if applicable) applied it; do not re-prompt.
}
elseif ($canPromptTelemetry -and $isElevatedSetup -and -not [System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine')) {
    Write-Host ""
    Write-Host "Opt out of PowerShell telemetry? This sets POWERSHELL_TELEMETRY_OPTOUT=true machine-wide." -ForegroundColor Cyan
    $answer = Read-Host "  [y/N]"
    if ($answer -match '^(?i:y|yes)$') {
        try {
            [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
            # Ownership marker so Uninstall-Profile knows this value is ours and safe to remove.
            # Without the marker, uninstall leaves an existing env var alone (user may have set
            # it themselves for other tools).
            try {
                $telemetryMarker = Join-Path $configCachePath 'telemetry.owned'
                [System.IO.File]::WriteAllText($telemetryMarker, "set by setup.ps1 at $(Get-Date -Format o)`n", [System.Text.UTF8Encoding]::new($false))
            }
            catch { $null = $_ }
            Write-Host "  Telemetry opt-out applied." -ForegroundColor Green
        }
        catch {
            Write-Host "  Failed to set env var: $_" -ForegroundColor Yellow
        }
    }
}

# Final summary
Write-Host ""
$allGood = $profileInstalled -and $themeInstalled -and $fontInstalled -and $ompInstalled -and $ezaInstalled -and $zoxideInstalled -and $fzfInstalled -and $batInstalled -and $rgInstalled
if ($allGood) {
    Write-Host "Setup complete!" -ForegroundColor Green
}
else {
    Write-Host "Setup completed with some issues. Check the messages above." -ForegroundColor Yellow
}
Write-Host ""
# AI_AGENT or CI = skip "Press Enter to restart" (agent/AI/automation context)
$canPromptExit = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
if ($canPromptExit) { try { $null = [Console]::KeyAvailable } catch { $canPromptExit = $false } }
# Same restart logic as profile's Restart-TerminalToApply: prefer WT (new tab), else pwsh/powershell. Applies for both .\setup.ps1 and irm | iex.
if ($canPromptExit) {
    Write-Host "Setup applied. Restarting terminal..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-Host "Press Enter to restart (or close this window to cancel)..." -ForegroundColor Yellow
    try { $null = Read-Host } catch { $null = $_ }
    $dir = (Get-Location).Path
    if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) {
        $dir = [Environment]::GetFolderPath('UserProfile')
    }
    $shellName = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {
        Start-Process -FilePath "wt.exe" -ArgumentList "-w", "0", "-d", $dir, $shellName, "-NoExit"
    }
    else {
        $shellExe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
        Start-Process -FilePath $shellExe -ArgumentList "-NoExit" -WorkingDirectory $dir
    }
    exit ([int](-not $allGood))
}
if ($MyInvocation.PSCommandPath) {
    exit ([int](-not $allGood))
}
