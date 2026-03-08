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

    [switch]$CiMode
)

# Normalize agent detection (same as profile): if host set a known agent var, set AI_AGENT so we only check one name
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) {
    $env:AI_AGENT = '1'
}

$RepoBase = "https://raw.githubusercontent.com/26zl/PowerShellPerfect/main"

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$isCiHost = $CiMode -or [bool]$env:GITHUB_ACTIONS -or [bool]$env:CI

# Ensure the script can run with elevated privileges for local installs.
# In CI/non-admin mode we continue and skip admin-only steps instead of exiting.
if (-not $isElevated -and -not $isCiHost) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    return
}
elseif (-not $isElevated -and $isCiHost) {
    Write-Host "Running setup.ps1 in CI/non-admin mode. Admin-only steps (LocalMachine execution policy, system-wide font install) will be skipped." -ForegroundColor Yellow
}

# Set execution policy so the profile can load on future sessions
$currentUserPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentUserPolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Host "Execution policy set to RemoteSigned for CurrentUser." -ForegroundColor Green
}
# Offer LocalMachine scope (covers all users and both PS editions) but don't force it.
# In CI/non-admin mode we skip this prompt entirely.
if (-not $isCiHost) {
    $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
    if ($machinePolicy -in @('Restricted', 'AllSigned', 'Undefined')) {
        $canPrompt = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
        if ($canPrompt) { try { $null = [Console]::KeyAvailable } catch { $canPrompt = $false } }
        if ($canPrompt) {
            $reply = Read-Host "  LocalMachine execution policy is '$machinePolicy'. Set to RemoteSigned for all users? [y/N]"
            if ($reply -match '^[Yy]') {
                Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
                Write-Host "Execution policy set to RemoteSigned for LocalMachine." -ForegroundColor Green
            }
            else {
                Write-Host "  Skipped LocalMachine policy. PS5 may not load the profile if CurrentUser is overridden." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  Skipped LocalMachine policy prompt (non-interactive mode)." -ForegroundColor Yellow
        }
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

            if ($copied -gt 0 -and $pending) {
                Write-Host "  Warning: font copy timed out, $(@($pending).Count) file(s) may not have installed." -ForegroundColor Yellow
            }
            Remove-Item -Path $extractPath -Recurse -Force
            Remove-Item -Path $zipFilePath -Force
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
            Invoke-RestMethod -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec -ErrorAction Stop
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

# Check for internet connectivity before proceeding (skip when using a local repo)
if (-not $LocalRepo -and -not (Test-InternetConnection)) {
    return
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

try {
    $configTmp = Join-Path $env:TEMP "theme.json"
    if ($LocalRepo) {
        Copy-Item (Join-Path $LocalRepo 'theme.json') $configTmp -Force -ErrorAction Stop
    }
    else {
        Invoke-DownloadWithRetry -Uri "$RepoBase/theme.json" -OutFile $configTmp
    }
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
    $terminalConfigTmp = Join-Path $env:TEMP "terminal-config.json"
    if ($LocalRepo) {
        Copy-Item (Join-Path $LocalRepo 'terminal-config.json') $terminalConfigTmp -Force -ErrorAction Stop
    }
    else {
        Invoke-DownloadWithRetry -Uri "$RepoBase/terminal-config.json" -OutFile $terminalConfigTmp
    }
    $terminalConfig = Get-Content $terminalConfigTmp -Raw | ConvertFrom-Json
    Copy-Item $terminalConfigTmp (Join-Path $configCachePath "terminal-config.json") -Force
    Remove-Item $terminalConfigTmp -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Could not load terminal-config.json. Terminal behavior settings (font, scrollbar, keybindings) will not be applied." -ForegroundColor Yellow
}

# Merge helper - deep-merges PSCustomObjects so nested keys are preserved
function Merge-JsonObject($base, $override) {
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
    return
}

Write-Host ""
Write-Host "PowerShell Profile Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Profile creation or update (install for both PS5 and PS7)
Write-Host "[1/10] Profile" -ForegroundColor Cyan
$profileUrl = "$RepoBase/Microsoft.PowerShell_profile.ps1"
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
        $tempDownload = Join-Path $env:TEMP "profile_download_$(Split-Path $dir -Leaf).ps1"
        if ($LocalRepo) {
            Copy-Item (Join-Path $LocalRepo 'Microsoft.PowerShell_profile.ps1') $tempDownload -Force
        }
        else {
            Invoke-DownloadWithRetry -Uri $profileUrl -OutFile $tempDownload -TimeoutSec 30
        }
        if (Test-Path -Path $targetProfile -PathType Leaf) {
            $backupPath = Join-Path $dir "oldprofile.ps1"
            Copy-Item -Path $targetProfile -Destination $backupPath -Force
            Write-Host "  Backup saved to [$backupPath]" -ForegroundColor DarkGray
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
    "_comment": "User overrides for terminal and theme settings. Only add keys you want to override.",
    "_examples": {
        "theme": { "name": "catppuccin", "url": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/catppuccin.omp.json" },
        "windowsTerminal": { "colorScheme": "One Half Dark", "cursorColor": "#ffffff" },
        "defaults": { "opacity": 90, "font": { "size": 14 } },
        "keybindings": [{ "keys": "ctrl+shift+t", "command": { "action": "newTab" } }]
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

# Editor preference (interactive prompt writes $script:EditorPriority into profile_user.ps1)
Write-Host "[2/10] Editor preference" -ForegroundColor Cyan
$canPromptEditor = [Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT
if ($canPromptEditor) { try { $null = [Console]::KeyAvailable } catch { $canPromptEditor = $false } }
if ($canPromptEditor) {
    $chosenEditor = Select-PreferredEditor
    # Install chosen editor via winget only if not already installed
    $chosen = $EditorCandidates | Where-Object { $_.Cmd -eq $chosenEditor } | Select-Object -First 1
    if ($chosen -and $chosen.WingetId -and -not (Get-Command $chosenEditor -ErrorAction SilentlyContinue)) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host "  Installing $($chosen.Display) via winget..." -ForegroundColor Cyan
            $null = winget install -e --id $chosen.WingetId --accept-source-agreements --accept-package-agreements 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335185 -or $LASTEXITCODE -eq -1978335189) {
                $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', 'User')
                Write-Host "  $($chosen.Display) installed." -ForegroundColor Green
            }
            else {
                Write-Host "  Could not install $($chosen.Display) via winget. Using Notepad." -ForegroundColor Yellow
                $chosenEditor = 'notepad'
            }
        }
        else {
            Write-Host "  winget not found. Using Notepad." -ForegroundColor Yellow
            $chosenEditor = 'notepad'
        }
    }
    Write-Host "  Editor set to: $chosenEditor" -ForegroundColor Green
    $editorLine = '$script:EditorPriority = @(' + "'$chosenEditor', 'notepad'" + ')'
    foreach ($dir in $profileDirs) {
        $userProfilePath = Join-Path $dir "profile_user.ps1"
        if (Test-Path $userProfilePath) {
            $content = [System.IO.File]::ReadAllText($userProfilePath)
            if ($content -match '(?m)^\$script:EditorPriority\s*=') {
                $content = $content -replace '(?m)^\$script:EditorPriority\s*=.*$', $editorLine
            }
            else {
                $content = $content.TrimEnd() + "`r`n`r`n# --- Preferred editor (set by setup.ps1) ---`r`n$editorLine`r`n"
            }
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [System.IO.File]::WriteAllText($userProfilePath, $content, $utf8NoBom)
        }
    }
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
$ompInstalled = Install-WingetPackage -Name "Oh My Posh" -Id "JanDeDobbeleer.OhMyPosh"
if ($profileConfig -and $profileConfig.theme -and $profileConfig.theme.name -and $profileConfig.theme.url) {
    $themeInstalled = Install-OhMyPoshTheme -ThemeName $profileConfig.theme.name -ThemeUrl $profileConfig.theme.url
}
else {
    $reason = if (-not $profileConfig) { "theme.json missing" }
    elseif (-not $profileConfig.theme -or -not $profileConfig.theme.name) { "theme name missing" }
    else { "theme URL missing" }
    Write-Host "  Skipped theme download ($reason)." -ForegroundColor Yellow
    $themeInstalled = $false
}
# Invalidate all cached init scripts so they regenerate with correct paths on next startup
Get-ChildItem -Path $configCachePath -Filter "*-init.ps1" -ErrorAction SilentlyContinue |
Remove-Item -Force -ErrorAction SilentlyContinue

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
$fontInstalled = Install-NerdFonts -FontName $fontName -FontDisplayName $fontDisplayName -Version $fontVersion

# eza Install (modern ls replacement with icons and git status)
Write-Host "[5/10] eza" -ForegroundColor Cyan
$ezaInstalled = Install-WingetPackage -Name "eza" -Id "eza-community.eza"
# Clean up leftover Terminal-Icons if present
Remove-Module Terminal-Icons -Force -ErrorAction SilentlyContinue
Uninstall-Module Terminal-Icons -AllVersions -Force -ErrorAction SilentlyContinue

# zoxide Install
Write-Host "[6/10] zoxide" -ForegroundColor Cyan
$zoxideInstalled = Install-WingetPackage -Name "zoxide" -Id "ajeetdsouza.zoxide"

# fzf + PSFzf Install (fuzzy finder for history and file search)
Write-Host "[7/10] fzf" -ForegroundColor Cyan
$fzfInstalled = Install-WingetPackage -Name "fzf" -Id "junegunn.fzf"
if (-not (Get-Module -ListAvailable -Name PSFzf)) {
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
$batInstalled = Install-WingetPackage -Name "bat" -Id "sharkdp.bat"

# ripgrep Install (fast recursive grep, used by the grep function)
Write-Host "[9/10] ripgrep" -ForegroundColor Cyan
$rgInstalled = Install-WingetPackage -Name "ripgrep" -Id "BurntSushi.ripgrep.MSVC"

# Windows Terminal configuration (merges font, theme, and appearance into existing settings)
Write-Host "[10/10] Windows Terminal" -ForegroundColor Cyan
$wtSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtSettingsPath) {
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

        $wtJson = $wt | ConvertTo-Json -Depth 10
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($wtSettingsPath, $wtJson, $utf8NoBom)
        $schemeLabel = if ($cfgColorScheme) { $cfgColorScheme } else { "(unchanged)" }
        Write-Host "  Windows Terminal configured (scheme: $schemeLabel)." -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to configure Windows Terminal: $_" -ForegroundColor Red
    }
}
else {
    Write-Host "  Windows Terminal settings not found (skipped)." -ForegroundColor Yellow
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
