### PowerShell Profile (26zl)
### https://github.com/26zl/PowerShellPerfect

$profileStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Non-interactive mode detection (sandboxed/AI/CI/SSH-pipe sessions skip network calls and UI setup)
$isInteractive = [Environment]::UserInteractive -and
-not [bool]$env:CI -and
-not [bool]$env:AGENT_ID -and
-not [bool]$env:CLAUDE_CODE -and
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
    @{ Name = "Oh My Posh"; Id = "JanDeDobbeleer.OhMyPosh"; Cmd = "oh-my-posh"; Cache = "omp-init.ps1"; VerCmd = "version" }
    @{ Name = "eza"; Id = "eza-community.eza"; Cmd = "eza"; Cache = $null; VerCmd = "--version" }
    @{ Name = "zoxide"; Id = "ajeetdsouza.zoxide"; Cmd = "zoxide"; Cache = "zoxide-init.ps1"; VerCmd = "--version" }
    @{ Name = "fzf"; Id = "junegunn.fzf"; Cmd = "fzf"; Cache = $null; VerCmd = "--version" }
    @{ Name = "bat"; Id = "sharkdp.bat"; Cmd = "bat"; Cache = $null; VerCmd = "--version" }
    @{ Name = "ripgrep"; Id = "BurntSushi.ripgrep.MSVC"; Cmd = "rg"; Cache = $null; VerCmd = "--version" }
)

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

    try {
        # Phase 1: Download profile and config
        $profileUrl = "$repo_root/$repo_name/main/Microsoft.PowerShell_profile.ps1"
        Invoke-RestMethod $profileUrl -OutFile $tempProfile -TimeoutSec 10 -ErrorAction Stop

        $configUrl = "$repo_root/$repo_name/main/theme.json"
        $configDownloaded = $false
        try {
            Invoke-RestMethod $configUrl -OutFile $tempConfig -TimeoutSec 10 -ErrorAction Stop
            $configDownloaded = $true
        }
        catch {
            Write-Warning "Could not download theme.json (non-fatal): $_"
        }

        $terminalConfigUrl = "$repo_root/$repo_name/main/terminal-config.json"
        $terminalConfigDownloaded = $false
        try {
            Invoke-RestMethod $terminalConfigUrl -OutFile $tempTerminalConfig -TimeoutSec 10 -ErrorAction Stop
            $terminalConfigDownloaded = $true
        }
        catch {
            Write-Warning "Could not download terminal-config.json (non-fatal): $_"
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

        if (-not $profileChanged -and -not $configChanged -and -not $terminalConfigChanged -and -not $Force) {
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
            $combinedHash = [BitConverter]::ToString(
                $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedInput))
            ).Replace('-', '')

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
                }
                elseif ($copySuccess -gt 0) {
                    Write-Warning "Profile updated partially. Failed to write: $($copyFailed -join ', ')"
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

        # Merge helper - deep-merges PSCustomObjects so nested keys are preserved
        function Merge-JsonObject($base, $override) {
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

        # Apply user-settings.json overrides (never downloaded, never overwritten)
        $userSettingsPath = Join-Path $cacheDir "user-settings.json"
        if (Test-Path $userSettingsPath) {
            try {
                $userSettings = Get-Content $userSettingsPath -Raw | ConvertFrom-Json
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
            $shouldDownloadTheme = (-not (Test-Path $localThemePath)) -or $profileChanged -or $configChanged
            if ($shouldDownloadTheme -and $themeUrl) {
                if ($PSCmdlet.ShouldProcess($localThemePath, "Download OMP theme '$themeName'")) {
                    try {
                        Invoke-RestMethod -Uri $themeUrl -OutFile $localThemePath -TimeoutSec 10 -ErrorAction Stop
                        # Validate: non-empty and parseable JSON
                        $themeSize = (Get-Item $localThemePath).Length
                        if ($themeSize -eq 0) { throw "Downloaded theme file is empty" }
                        $null = Get-Content $localThemePath -Raw | ConvertFrom-Json
                        Write-Host "OMP theme '$themeName' updated." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to download/validate OMP theme: $_"
                        Remove-Item $localThemePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            # Orphan cleanup - remove *.omp.json files that don't match current theme
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
        if (($Force -or $profileChanged -or $configChanged -or $terminalConfigChanged) -and (($config -and $config.windowsTerminal) -or $terminalConfig)) {
            $wtSettingsPath = Join-Path $env:LOCALAPPDATA "Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
            if (Test-Path $wtSettingsPath) {
                if ($PSCmdlet.ShouldProcess($wtSettingsPath, "Update Windows Terminal settings")) {
                    try {
                        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                        $backupPath = "$wtSettingsPath.$timestamp.bak"
                        Copy-Item $wtSettingsPath $backupPath -Force
                        Write-Host "WT backup: $backupPath" -ForegroundColor DarkGray

                        $wtRaw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncCommentPattern, ''
                        $wt = $wtRaw | ConvertFrom-Json

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
                        Write-Host "Windows Terminal settings updated." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to update Windows Terminal settings: $_"
                    }
                }
            }
        }

        # Phase 7: Install missing tools
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $missing = $script:ProfileTools | Where-Object { -not (Get-Command $_.Cmd -ErrorAction SilentlyContinue) }
            if ($missing) {
                Write-Host "Installing missing tools..." -ForegroundColor Cyan
                $installedTools = @()
                foreach ($tool in $missing) {
                    if ($PSCmdlet.ShouldProcess($tool.Name, "Install via winget")) {
                        Write-Host "  Installing $($tool.Name)..." -ForegroundColor Yellow
                        winget install -e --id $tool.Id --accept-source-agreements --accept-package-agreements
                        if ($LASTEXITCODE -eq 0) {
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

        if ($profileChanged) {
            Write-Host "Please restart your shell to reflect changes." -ForegroundColor Magenta
        }
    }
    catch {
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
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl -TimeoutSec 10
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
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
# Update installed profile tools via winget (skips tools not present on this machine)
function Update-Tools {
    $installed = $script:ProfileTools | Where-Object { Get-Command $_.Cmd -ErrorAction SilentlyContinue }
    if (-not $installed) {
        Write-Host "No profile tools detected. Run Update-Profile to install them." -ForegroundColor Yellow
        return
    }
    $upgraded = 0
    $failed = 0
    foreach ($tool in $installed) {
        # Capture pre-upgrade version
        $oldVer = try { (& $tool.Cmd $tool.VerCmd 2>$null | Where-Object { $_ -match '\d+\.\d+' } | Select-Object -First 1).Trim() } catch { $null }
        Write-Host "Updating $($tool.Name)..." -ForegroundColor Cyan
        winget upgrade --id $tool.Id --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            $newVer = try { (& $tool.Cmd $tool.VerCmd 2>$null | Where-Object { $_ -match '\d+\.\d+' } | Select-Object -First 1).Trim() } catch { $null }
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
        Write-Host "$upgraded tool(s) updated. Restart your shell to apply changes." -ForegroundColor Magenta
    }
    if ($failed -gt 0) {
        Write-Warning "$failed tool(s) failed to update. Check the output above."
    }
    if ($upgraded -eq 0 -and $failed -eq 0) {
        Write-Host "All tools are up to date." -ForegroundColor Green
    }
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
function prompt {
    if ($adminSuffix) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Editor Configuration (lazy - only resolves on first use)
function vim {
    if ($null -eq $script:EDITOR) {
        foreach ($e in 'code', 'sublime_text', 'notepad', 'nvim', 'vi') {
            if (Get-Command $e -CommandType Application -ErrorAction SilentlyContinue) { $script:EDITOR = $e; break }
        }
        if ($null -eq $script:EDITOR) { $script:EDITOR = 'notepad' }
    }
    & $script:EDITOR @args
}

# Quick Access to Editing the Profile
function Edit-Profile {
    vim $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Create file or update its timestamp
function touch($file) {
    if (-not $file) { Write-Error "Usage: touch <file>"; return }
    if (Test-Path $file) {
        (Get-Item $file).LastWriteTime = Get-Date
    }
    else {
        New-Item -ItemType File -Path $file | Out-Null
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
function uptime {
    try {
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
        }
        else {
            $bootTime = (Get-Uptime -Since)
        }

        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

        $uptime = (Get-Date) - $bootTime
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Blue
    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}
# Unzip Utility (PS5-compatible)
function unzip {
    param([Parameter(Mandatory)][string]$File)
    $resolved = Resolve-Path -LiteralPath $File -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $File"; return }
    if ($resolved.Path -notmatch '\.zip$') { Write-Error "Not a zip file: $File"; return }
    Write-Host "Extracting $($resolved.Path) to $pwd" -ForegroundColor Cyan
    Expand-Archive -Path $resolved.Path -DestinationPath $pwd -Force
}

function extract {
    param([Parameter(Mandatory)][string]$File)
    $resolved = Resolve-Path -LiteralPath $File -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $File"; return }
    $path = $resolved.Path
    $ext = [System.IO.Path]::GetExtension($path).ToLower()
    $name = [System.IO.Path]::GetFileNameWithoutExtension($path)
    if ($name.EndsWith('.tar')) { $ext = '.tar' + $ext; $name = [System.IO.Path]::GetFileNameWithoutExtension($name) }
    Write-Host "Extracting $path ..." -ForegroundColor Cyan
    switch ($ext) {
        '.zip' { Expand-Archive -Path $path -DestinationPath $pwd -Force }
        '.tar' { tar -xf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.gz' { tar -xzf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tgz' { tar -xzf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.bz2' { tar -xjf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.gz' { tar -xzf "$path" -C "$pwd"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
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

    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
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
    if (-not $file -or -not (Test-Path $file)) {
        Write-Warning "File not found: $file"
        return
    }
    if ($null -eq $find -or $find -eq '') { Write-Error "Usage: sed <file> <find> <replace>"; return }
    $content = Get-Content $file -Raw
    if (-not $content) { Write-Warning "File is empty: $file"; return }
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Resolve-Path $file).Path, $content.replace("$find", $replace), $utf8NoBom)
}

# Show the full path of a command
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

# Set an environment variable in the current session
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

# Kill process by name
function pkill($name) {
    if (-not $name) { Write-Error "Usage: pkill <name>"; return }
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
}

# List processes by name
function pgrep($name) {
    Get-Process $name -ErrorAction SilentlyContinue
}

# Display first n lines of a file (default 10)
function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

# Display last n lines of a file (default 10, -f to follow)
function tail {
    param($Path, $n = 10, [switch]$f = $false)
    Get-Content $Path -Tail $n -Wait:$f
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

# Move item to Recycle Bin via Shell.Application COM
function trash($path) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "Error: Item '$path' does not exist."
        return
    }

    $item = Get-Item -LiteralPath $path

    if ($item.PSIsContainer) {
        $parentPath = $item.Parent.FullName
    }
    else {
        $parentPath = $item.DirectoryName
    }

    $shell = New-Object -ComObject 'Shell.Application'
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

### Quality of Life Aliases

# Navigation Shortcuts
function docs {
    $docs = if (([Environment]::GetFolderPath("MyDocuments"))) { ([Environment]::GetFolderPath("MyDocuments")) } else { $HOME + "\Documents" }
    Set-Location -Path $docs
}

function dtop {
    $dtop = if ([Environment]::GetFolderPath("Desktop")) { [Environment]::GetFolderPath("Desktop") } else { $HOME + "\Desktop" }
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
    function ls { eza --icons @args }
    function la { eza -a --icons @args }
    function ll { eza -la --icons --git @args }
    function lt { eza --tree --icons --level=2 @args }
}
else {
    if ($isInteractive) { Write-Warning "eza not found. Install it with: winget install -e --id eza-community.eza" }
    function la { Get-ChildItem -Force | Format-Table -AutoSize }
    function ll { Get-ChildItem -Force | Format-Table -AutoSize }
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
    function cat { bat --paging=never @args }
}
else {
    if ($isInteractive) { Write-Warning "bat not found. Install it with: winget install -e --id sharkdp.bat" }
}

# Git Shortcuts
function gs { git status }

function ga { git add .; if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed (exit $LASTEXITCODE)" } }

# Remove built-in gc alias (Get-Content) so our function is reachable
if (Get-Command Remove-Alias -ErrorAction SilentlyContinue) {
    Remove-Alias gc -Force -ErrorAction SilentlyContinue
}
else {
    Remove-Item Alias:\gc -Force -ErrorAction SilentlyContinue
}
function gc { if (-not $args) { Write-Error "Usage: gc <message>"; return }; git commit -m "$args"; if ($LASTEXITCODE -ne 0) { Write-Warning "git commit failed (exit $LASTEXITCODE)" } }

function gpush { git push }

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

function gcl { git clone @args }

# Add all + commit
function gcom {
    if (-not $args) { Write-Error "Usage: gcom <message>"; return }
    git add .
    if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed. Commit skipped."; return }
    git commit -m "$args"
}
# Add all + commit + push
function lazyg {
    if (-not $args) { Write-Error "Usage: lazyg <message>"; return }
    git add .
    if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed. Commit skipped."; return }
    git commit -m "$args"
    if ($LASTEXITCODE -eq 0) {
        git push
    }
    else {
        Write-Warning "Commit failed. Push skipped."
    }
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
        netstat -ano | Select-String 'LISTENING'
    }
}

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

function localip {
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize
}

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
    if (-not (Test-Path $File)) { Write-Error "File not found: $File"; return }
    (Get-FileHash -Path $File -Algorithm $Algorithm).Hash
}

function checksum {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$Expected
    )
    if (-not (Test-Path $File)) { Write-Error "File not found: $File"; return }
    $algo = switch ($Expected.Length) {
        32 { 'MD5' }
        40 { 'SHA1' }
        64 { 'SHA256' }
        96 { 'SHA384' }
        128 { 'SHA512' }
        default { 'SHA256' }
    }
    $actual = (Get-FileHash -Path $File -Algorithm $algo).Hash
    if ($actual -eq $Expected.ToUpper()) {
        Write-Host "MATCH ($algo)" -ForegroundColor Green
    }
    else {
        Write-Host "MISMATCH ($algo)" -ForegroundColor Red
        Write-Host "Expected: $Expected"
        Write-Host "Actual:   $actual"
    }
}

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

function b64 {
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

function b64d {
    param([Parameter(Mandatory)][string]$Text)
    try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text)) }
    catch { Write-Error "Invalid Base64 input: $_" }
}

# Docker Shortcuts (conditional)
if (Get-Command docker -ErrorAction SilentlyContinue) {
    function dps { docker ps @args }
    function dpa { docker ps -a @args }
    function dimg { docker images @args }
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
    do {
        if ($Live) { Clear-Host }
        try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
        catch { Write-Error "Failed to query system info: $_"; return }
        $totalMem = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        $usedMem = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 1)
        $memPct = [math]::Round($usedMem / $totalMem * 100)
        $cpuLoad = try { [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average) } catch { 0 }
        $procCount = @(Get-Process).Count
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $up = (Get-Uptime)
        }
        else {
            $boot = $os.LastBootUpTime
            $up = (Get-Date) - $boot
        }
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
        @{L = 'Threads'; E = { $_.Threads.Count }; A = 'Right' } -AutoSize
        if ($Live) { Start-Sleep -Seconds 2 }
    } while ($Live)
}

function reload { . $PROFILE }

function Clear-ProfileCache {
    $cacheDir = Join-Path $env:LOCALAPPDATA "PowerShellProfile"
    if (-not (Test-Path $cacheDir)) { Write-Host "No cache directory found." -ForegroundColor Yellow; return }
    $items = Get-ChildItem $cacheDir -Exclude "user-settings.json" -ErrorAction SilentlyContinue
    if (-not $items) { Write-Host "Cache is already clean." -ForegroundColor Green; return }
    foreach ($item in $items) {
        Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed $($item.Name)" -ForegroundColor DarkGray
    }
    Write-Host "Profile cache cleared. Restart your terminal to regenerate." -ForegroundColor Green
}

function path { $env:PATH -split ';' | Where-Object { $_ } }

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
    catch { $null = $_ }

    # Fallback: Open-Meteo (free, no API key)
    try {
        $loc = if ($City) {
            $geo = Invoke-RestMethod "https://geocoding-api.open-meteo.com/v1/search?name=$encoded&count=1" -TimeoutSec 5
            if (-not $geo -or -not $geo.results) { Write-Error "City '$City' not found."; return }
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
        $wx = Invoke-RestMethod "https://api.open-meteo.com/v1/forecast?latitude=$($loc.latitude)&longitude=$($loc.longitude)&current=temperature_2m,weather_code" -TimeoutSec 5
        if (-not $wx -or -not $wx.current) { Write-Error "Weather API returned no data."; return }
        $temp = $wx.current.temperature_2m
        $unit = $wx.current_units.temperature_2m
        Write-Host "$($loc.name): ${temp}${unit}" -ForegroundColor Cyan
    }
    catch { Write-Error "Could not fetch weather: $_" }
}

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

function hosts {
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $editor = if ($env:EDITOR) { $env:EDITOR } elseif (Get-Command code -ErrorAction SilentlyContinue) { 'code' } else { 'notepad' }
    Start-Process $editor $hostsPath -Verb RunAs
}

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
    catch { Write-Error "Speed test failed: $_" }
}

function sizeof {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { Write-Error "Path not found: $Path"; return }
    $item = Get-Item $Path
    if ($item.PSIsContainer) {
        $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
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

function eventlog {
    param([ValidateRange(1, 10000)][int]$Count = 20)
    Get-WinEvent -LogName System, Application -MaxEvents $Count -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated -Descending |
    Select-Object -First $Count TimeCreated, LogName, LevelDisplayName, Id, Message |
    Format-Table -AutoSize -Wrap
}

# SSH & Remote
if (Get-Command ssh -ErrorAction SilentlyContinue) {
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

    function keygen {
        param([string]$Name = 'id_ed25519')
        $keyPath = Join-Path "$env:USERPROFILE\.ssh" $Name
        ssh-keygen -t ed25519 -f $keyPath
    }
}

function rdp {
    param([Parameter(Mandatory)][string]$Computer)
    mstsc /v:$Computer
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
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            Write-Host "$status $($_.Exception.Response.StatusCode)" -ForegroundColor Red
            # PS7 uses HttpResponseMessage (no GetResponseStream); PS5 uses HttpWebResponse
            if ($_.ErrorDetails.Message) {
                $_.ErrorDetails.Message
            }
            elseif ($_.Exception.Response | Get-Member -Name GetResponseStream -ErrorAction SilentlyContinue) {
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $reader.ReadToEnd()
                    $reader.Dispose()
                }
                catch { Write-Error "HTTP error (could not read response body)" }
            }
        }
        else { Write-Error $_ }
    }
}

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
            if (-not (Test-Path $File)) { Write-Error "File not found: $File"; return }
            Get-Content $File -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        else { Write-Error 'Usage: prettyjson <file> or <pipeline> | prettyjson' }
    }
    catch { Write-Error "Invalid JSON: $_" }
}

# Clipboard Utilities
function cpy { if (-not $args) { Write-Error "Usage: cpy <text>"; return }; Set-Clipboard ($args -join ' ') }
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
    # Guard against hosts without VT support (e.g. AI/Codex terminals, redirected output)
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
        try {
            $clipboardText = Get-Clipboard -Raw
            if ([string]::IsNullOrWhiteSpace($clipboardText)) {
                [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
                return
            }
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert($clipboardText)
        }
        catch {
            [Microsoft.PowerShell.PSConsoleReadLine]::Ding()
        }
    }
    Set-PSReadLineKeyHandler -Chord 'Alt+v' -BriefDescription SmartPaste -Description 'Paste clipboard as one block into prompt' -ScriptBlock $smartPasteHandler

    # fzf integration via PSFzf (fuzzy history search on Ctrl+R, file finder on Ctrl+T)
    if (Get-Command fzf -ErrorAction SilentlyContinue) {
        try {
            Import-Module PSFzf -ErrorAction Stop
            Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
        }
        catch {
            Write-Verbose "PSFzf module not available: $_"
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

# Oh My Posh initialization (interactive only, cached for fast startup)
if ($isInteractive) {
    if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
        # Read theme name + URL from cached config
        $profileConfigPath = Join-Path $cacheDir "theme.json"
        $themeName = $null
        $themeUrl = $null
        if (Test-Path $profileConfigPath) {
            try {
                $cfg = Get-Content $profileConfigPath -Raw | ConvertFrom-Json
                if ($cfg.theme.name) { $themeName = $cfg.theme.name }
                if ($cfg.theme.url) { $themeUrl = $cfg.theme.url }
            }
            catch { Write-Verbose "Failed to parse theme.json: $_" }
        }
        # User-settings theme override (startup-time, not just Update-Profile)
        $userSettingsStartup = Join-Path $cacheDir "user-settings.json"
        if (Test-Path $userSettingsStartup) {
            try {
                $userCfg = Get-Content $userSettingsStartup -Raw | ConvertFrom-Json
                if ($userCfg.theme.name) { $themeName = $userCfg.theme.name }
                if ($userCfg.theme.url) { $themeUrl = $userCfg.theme.url }
            }
            catch { Write-Verbose "Failed to parse user-settings.json: $_" }
        }
        if (-not $themeName) {
            Write-Verbose "No theme.json found in cache. Run Update-Profile or setup.ps1 to configure the OMP theme."
        }
        $localThemePath = if ($themeName) { Join-Path $cacheDir "$themeName.omp.json" } else { $null }
        if ($localThemePath -and -not (Test-Path $localThemePath)) {
            # Try migrating from old location (Documents\PowerShell), fall back to download
            $oldThemePath = Join-Path (Split-Path $PROFILE) "$themeName.omp.json"
            if (Test-Path $oldThemePath) {
                try { Move-Item $oldThemePath $localThemePath -Force -ErrorAction Stop }
                catch { Write-Warning "Could not migrate theme from Documents: $_" }
            }
            if (-not (Test-Path $localThemePath) -and $themeUrl) {
                try {
                    Invoke-RestMethod -Uri $themeUrl -OutFile $localThemePath -TimeoutSec 10
                    $themeSize = (Get-Item $localThemePath).Length
                    if ($themeSize -eq 0) { throw "Downloaded theme file is empty" }
                    $null = Get-Content $localThemePath -Raw | ConvertFrom-Json
                    Write-Host "Downloaded missing Oh My Posh theme to $localThemePath"
                }
                catch {
                    Write-Warning "Failed to download/validate theme file: $_"
                    Remove-Item $localThemePath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        if ($localThemePath -and (Test-Path $localThemePath)) {
            # Cache the OMP init script so we don't shell out every startup
            # Header tracks both OMP version AND theme path so a theme switch invalidates the cache
            $ompCachePath = Join-Path $cacheDir "omp-init.ps1"
            $ompVersion = try { ((oh-my-posh version) | Out-String).Trim() } catch { 'unknown' }
            $ompCacheHeader = '# OMP_CACHE: {0} | {1}' -f $ompVersion, $localThemePath
            $cacheValid = $false
            if (Test-Path $ompCachePath) {
                $fileSize = (Get-Item $ompCachePath).Length
                if ($fileSize -gt 0) {
                    $cacheContent = Get-Content $ompCachePath -First 1
                    if ($cacheContent -eq $ompCacheHeader) { $cacheValid = $true }
                }
                if (-not $cacheValid) { Remove-Item $ompCachePath -Force -ErrorAction SilentlyContinue }
            }
            if (-not $cacheValid) {
                $initScript = oh-my-posh init pwsh --config $localThemePath
                if ($initScript) {
                    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                    [System.IO.File]::WriteAllText($ompCachePath, ($ompCacheHeader + "`n" + ($initScript -join "`n")), $utf8NoBom)
                }
                else {
                    Write-Warning "oh-my-posh init produced no output. Cache not written."
                }
            }
            try {
                . $ompCachePath
            }
            catch {
                Remove-Item $ompCachePath -Force -ErrorAction SilentlyContinue
                try {
                    $initScript = oh-my-posh init pwsh --config $localThemePath
                    if ($initScript) {
                        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                        [System.IO.File]::WriteAllText($ompCachePath, ($ompCacheHeader + "`n" + ($initScript -join "`n")), $utf8NoBom)
                        . $ompCachePath
                    }
                    else {
                        Write-Warning "oh-my-posh init produced no output."
                    }
                }
                catch {
                    Write-Warning "Failed to initialize oh-my-posh: $_"
                }
            }
        }
    }
    else {
        Write-Warning "oh-my-posh not found. Install it with: winget install JanDeDobbeleer.OhMyPosh"
    }
}

# zoxide initialization (interactive only, cached for fast startup)
if ($isInteractive) {
    if (Get-Command zoxide -ErrorAction SilentlyContinue) {
        $zoxideCachePath = Join-Path $cacheDir "zoxide-init.ps1"
        $zoxideVersion = try { ((zoxide --version 2>$null) | Out-String).Trim() } catch { 'unknown' }
        $cacheValid = $false
        if (Test-Path $zoxideCachePath) {
            $fileSize = (Get-Item $zoxideCachePath).Length
            if ($fileSize -gt 0) {
                $cacheContent = Get-Content $zoxideCachePath -First 1
                if ($cacheContent -eq "# ZOXIDE_CACHE_VERSION: $zoxideVersion") { $cacheValid = $true }
            }
            if (-not $cacheValid) { Remove-Item $zoxideCachePath -Force -ErrorAction SilentlyContinue }
        }
        if (-not $cacheValid) {
            $initScript = (zoxide init --cmd z powershell | Out-String)
            if ($initScript) {
                $zoxideHeader = "# ZOXIDE_CACHE_VERSION: $zoxideVersion"
                $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($zoxideCachePath, ($zoxideHeader + "`n" + $initScript), $utf8NoBom)
            }
            else {
                Write-Warning "zoxide init produced no output. Cache not written."
            }
        }
        try {
            . $zoxideCachePath
        }
        catch {
            Remove-Item $zoxideCachePath -Force -ErrorAction SilentlyContinue
            try {
                $initScript = (zoxide init --cmd z powershell | Out-String)
                if ($initScript) {
                    $zoxideHeader = "# ZOXIDE_CACHE_VERSION: $zoxideVersion"
                    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                    [System.IO.File]::WriteAllText($zoxideCachePath, ($zoxideHeader + "`n" + $initScript), $utf8NoBom)
                    . $zoxideCachePath
                }
                else {
                    Write-Warning "zoxide init produced no output."
                }
            }
            catch {
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
${g}Edit-Profile${r} / ${g}ep${r} - Open profile in editor.
${g}Update-Profile${r} - Sync profile, theme, caches, and WT settings. Use -Force to re-apply.
${g}Update-PowerShell${r} - Check for new PowerShell releases.
${g}Update-Tools${r} - Update Oh My Posh, eza, zoxide, fzf, bat, and ripgrep.
${g}Show-Help${r} - Show this help message.
${g}reload${r} - Reload the PowerShell profile.

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
${g}trash${r} <path> - Move to Recycle Bin.  ${g}unzip${r} <file> - Extract zip.
${g}extract${r} <file> - Universal extractor (.zip, .tar, .gz, .7z, .rar).
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
${g}nslook${r} <domain> [type] - DNS lookup (A, MX, TXT, etc.).
${g}svc${r} [name] [-Count n] [-Live] - htop-like process viewer.
${g}eventlog${r} [n] - Last n event log entries (default 20).
${g}path${r} - Display PATH entries one per line.
${g}weather${r} [city] - Quick weather lookup.
${g}speedtest${r} - Download speed test.
${g}wifipass${r} [ssid] - Show saved WiFi passwords.
${g}hosts${r} - Open hosts file in elevated editor.
${g}Clear-Cache${r} [-IncludeSystemCaches] - Clear user/system caches.
${g}Clear-ProfileCache${r} - Reset all profile caches (OMP, zoxide, configs).
${g}winutil${r} - Launch Chris Titus WinUtil.
${g}harden${r} - Open Harden System Security (MS Store).

${c}Security & Crypto${r}
${g}hash${r} <file> [algo] - File hash (default SHA256).
${g}checksum${r} <file> <expected> - Verify file hash.
${g}genpass${r} [length] - Random password (default 20), copies to clipboard.
${g}b64${r} / ${g}b64d${r} <text> - Base64 encode / decode.

${c}Developer${r}
${g}killport${r} <port> - Kill process on a TCP port.
${g}http${r} <url> [-Method POST] [-Body '...'] - HTTP requests, auto-formats JSON.
${g}prettyjson${r} <file> - Pretty-print JSON (or pipe: ${g}cat data.json | prettyjson${r}).
${g}hb${r} <file> - Upload to hastebin, copy URL.

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
