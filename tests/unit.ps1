# Hermetic regression tests for the profile and setup.ps1. Every case runs in a disposable sandbox (LOCALAPPDATA, TEMP and
# $PROFILE redirected), downloads are stubbed, and commands that would change the machine are blocked. No network access.
#   pwsh -NoProfile -File tests/unit.ps1
#   powershell -NoProfile -File tests/unit.ps1
param(
    # CI runners are elevated disposable VMs; elsewhere run the suite from a normal shell.
    [switch]$AllowElevated,
    # Run only the cases whose name matches this pattern.
    [string]$Filter = '.'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Sandbox.ps1')
Assert-PspTestSafety -AllowElevated:$AllowElevated -ScriptName 'tests/unit.ps1'

$repoRoot = Split-Path -Parent $PSScriptRoot
$profilePath = Join-Path $repoRoot 'Microsoft.PowerShell_profile.ps1'
$setupPath = Join-Path $repoRoot 'setup.ps1'
$utf8 = [System.Text.UTF8Encoding]::new($false)
$script:Passed = 0
$script:Failed = 0
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

# Run one case in a fresh sandbox; the profile functions loaded below pick up the redirected locations at call time.
function Test-Case {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    if ($Name -notmatch $Filter) { return }
    $script:Sandbox = New-PspSandbox -Name 'unit'
    Enter-PspSandbox -Sandbox $script:Sandbox
    $savedPwd = Get-Location
    try {
        $null = & $Body
        Write-Host "  PASS  $Name" -ForegroundColor Green
        $script:Passed++
    }
    catch {
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host ("        {0} (line {1})" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Yellow
        $script:Failed++
    }
    finally {
        Set-Location $savedPwd
        foreach ($stub in 'Invoke-RestMethod', 'Invoke-WebRequest') { Remove-Item -Path "function:global:$stub" -ErrorAction SilentlyContinue }
        Exit-PspSandbox -Sandbox $script:Sandbox
    }
}

# Serve repository files for raw.githubusercontent.com URLs (in their committed LF form), a fixed commit for the GitHub API,
# and $global:PspStubSums for release SHA256SUMS.txt requests; everything else fails as if offline.
function Install-DownloadStub {
    $global:PspStubRepo = $repoRoot
    Set-Item -Path 'function:global:Invoke-RestMethod' -Value {
        param([string]$Uri, [string]$OutFile, $Headers, [int]$TimeoutSec, [switch]$UseBasicParsing, $ErrorAction, $Method)
        if ($Uri -match '^https://api\.github\.com/repos/26zl/PowerShellPerfect/commits/') { return ('a' * 40) }
        if ($Uri -match '^https://raw\.githubusercontent\.com/26zl/PowerShellPerfect/[^/]+/(.+)$') {
            $text = [System.IO.File]::ReadAllText((Join-Path $global:PspStubRepo $Matches[1])) -replace "`r`n", "`n"
            [System.IO.File]::WriteAllText($OutFile, $text, [System.Text.UTF8Encoding]::new($false))
            return
        }
        if ($Uri -match '/releases/download/v9\.9\.9/SHA256SUMS\.txt$' -and $global:PspStubSums) {
            [System.IO.File]::WriteAllText($OutFile, $global:PspStubSums, [System.Text.UTF8Encoding]::new($false))
            return
        }
        if ($global:PspStubTheme -and $Uri -like 'https://raw.githubusercontent.com/JanDeDobbeleer/*') {
            [System.IO.File]::WriteAllText($OutFile, $global:PspStubTheme, [System.Text.UTF8Encoding]::new($false))
            return
        }
        throw "offline (test stub): $Uri"
    }
    Set-Item -Path 'function:global:Invoke-WebRequest' -Value { [PSCustomObject]@{ StatusCode = 200 } }
}

# Return the SHA-256 of a repository file as served by raw.githubusercontent.com (LF line endings).
function Get-CommittedSha256 {
    param([Parameter(Mandatory)][string]$RelativePath)
    $text = [System.IO.File]::ReadAllText((Join-Path $repoRoot $RelativePath)) -replace "`r`n", "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '') }
    finally { $sha.Dispose() }
}

# Write a Windows Terminal settings.json into the sandbox and return its path.
function New-WtSettings {
    param([string]$Json = '{ "profiles": { "defaults": { "opacity": 95 }, "list": [] }, "schemes": [], "actions": [] }', [string]$Variant = 'Microsoft.WindowsTerminal_8wekyb3d8bbwe')
    $dir = Join-Path $env:LOCALAPPDATA "Packages\$Variant\LocalState"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $path = Join-Path $dir 'settings.json'
    [System.IO.File]::WriteAllText($path, $Json, [System.Text.UTF8Encoding]::new($false))
    $path
}

Write-Host ''
Write-Host ("== tests/unit.ps1 on PowerShell {0} ==" -f $PSVersionTable.PSVersion) -ForegroundColor Cyan

# Load the profile once, inside a sandbox, then replace the functions that reach outside it.
$loadSandbox = New-PspSandbox -Name 'load'
Enter-PspSandbox -Sandbox $loadSandbox
$WarningPreference = 'SilentlyContinue'
. $profilePath
. $PspPostLoadStubs
$WarningPreference = 'Continue'
Exit-PspSandbox -Sandbox $loadSandbox

# Setup helpers: setup.ps1's own functions and curated data (shared helpers already came from the profile).
foreach ($definition in (Get-PspFunctionSource -Path $setupPath -Name @(
            'Save-WizardChoices', 'Resolve-WizardState', 'Set-PreferredEditorInProfiles', 'Install-OhMyPoshTheme', 'Get-OmpThemeUrl', 'Remove-SafeTempDirectory',
            'Start-InstallWizard', 'Select-WizardItem', 'Read-WizardYesNo', 'Select-PreferredEditor', 'Get-OmpThemeList', 'Test-TelemetryOptOutSet'))) {
    . ([scriptblock]::Create($definition))
}
$script:IsElevated = $false
foreach ($variable in '$script:CuratedSchemes', '$script:CuratedFonts', '$EditorCandidates', '$script:OmpThemesRef', '$script:PinnedOmpThemes') {
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable $variable)))
}

Write-Host '-- JSON handling --' -ForegroundColor Magenta

Test-Case 'ConvertFrom-JsonC removes comments and trailing commas but never touches strings (F-18)' {
    $q = [char]34
    $text = "{`n  // line comment`n  ${q}url${q}: ${q}https://example.com/a//b${q}, /* block */`n  ${q}quote${q}: ${q}say \${q}hi\${q} // not a comment${q},`n  ${q}list${q}: [1, 2, 3,],`n  ${q}nested${q}: { ${q}k${q}: ${q}v${q}, },`n}"
    $o = ConvertFrom-JsonC -Text $text
    Assert-True ($o.url -eq 'https://example.com/a//b') 'a // inside a string was treated as a comment'
    Assert-True ($o.quote -eq 'say "hi" // not a comment') 'an escaped quote ended the string early'
    Assert-True (@($o.list).Count -eq 3) 'trailing comma in an array'
    Assert-True ($o.nested.k -eq 'v') 'trailing comma in an object'
}

Test-Case 'Read-JsonFile reads UTF-8 with and without BOM on both editions (F-19)' {
    $path = Join-Path $script:Sandbox.Work 'bom.json'
    $value = 'caf' + [char]0xE9
    [System.IO.File]::WriteAllText($path, ('{ "name": "' + $value + '" }'), [System.Text.UTF8Encoding]::new($true))
    Assert-True ((Read-JsonFile $path).name -eq $value) 'BOM file decoded wrongly'
    [System.IO.File]::WriteAllText($path, ('{ "name": "' + $value + '" }'), $utf8)
    Assert-True ((Read-JsonFile $path).name -eq $value) 'BOM-less UTF-8 decoded wrongly'
}

Test-Case 'Merge-PspUserSettings appends user keybindings to the shipped ones as a flat list' {
    $term = Read-JsonFile (Join-Path $repoRoot 'terminal-config.json')
    $theme = Read-JsonFile (Join-Path $repoRoot 'theme.json')
    $shipped = @($term.keybindings).Count
    $user = ConvertFrom-JsonC -Text '{ "keybindings": [ { "keys": "ctrl+shift+t", "command": { "action": "newTab" } } ], "theme": { "name": "x", "url": "https://raw.githubusercontent.com/a/b/c.omp.json" } }'
    $result = Merge-PspUserSettings -UserSettings $user -ThemeConfig $theme -TerminalConfig $term
    $keys = @($term.keybindings | ForEach-Object { Get-PspProp $_ 'keys' })
    Assert-True ($result.Keybindings -and @($term.keybindings).Count -eq $shipped + 1) 'keybindings not merged into one flat list'
    Assert-True ($keys -contains 'ctrl+a' -and $keys -contains 'ctrl+shift+t') "unexpected keys: $($keys -join ', ')"
    Assert-True (-not (Test-PspProp $theme.theme 'sha256')) 'pinned hash kept for a user-chosen theme URL'
}

Write-Host '-- Windows Terminal changes (F-01, F-05) --' -ForegroundColor Magenta

Test-Case 'Update/Undo keep later user edits and revert only what the profile changed (F-01)' {
    $theme = Read-JsonFile (Join-Path $repoRoot 'theme.json')
    $term = Read-JsonFile (Join-Path $repoRoot 'terminal-config.json')
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $original = @'
{
    // user comment
    "theme": "dark",
    "profiles": {
        "defaults": { "opacity": 90, "font": { "face": "Consolas", "weight": "bold" } },
        "list": [ { "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}", "name": "PowerShell", "source": "Windows.Terminal.PowerShellCore" } ]
    },
    "schemes": [ { "name": "Campbell", "background": "#0C0C0C" } ],
    "actions": [ { "command": "unfocusPane", "id": "User.ctrlaOld" } ],
    "keybindings": [ { "id": "User.ctrlaOld", "keys": "ctrl+a" } ],
}
'@
    $path = New-WtSettings -Json $original
    $origParsed = ConvertFrom-JsonC -Text $original
    foreach ($run in 1, 2) {
        Assert-True ((Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults $term.defaults -WindowsTerminal $theme.windowsTerminal -Keybindings $term.keybindings -NoLogo -Confirm:$false) -eq $true) "apply run $run"
    }
    $applied = Read-JsonFile $path
    Assert-True ($applied.profiles.defaults.colorScheme -eq $theme.windowsTerminal.colorScheme) 'colorScheme not applied'
    Assert-True ($applied.profiles.defaults.font.weight -eq 'bold') 'unmanaged font key lost'
    Assert-True (@($applied.schemes | Where-Object name -eq $theme.windowsTerminal.scheme.name).Count -eq 1) 'scheme not upserted exactly once'
    Assert-True (Test-Path -LiteralPath "$path.psp-original") 'no durable pre-install copy'
    # The user changes something after install.
    $applied.profiles.defaults.opacity = 42
    $applied.profiles.list = @($applied.profiles.list) + ([PSCustomObject]@{ name = 'User added'; commandline = 'wsl.exe' })
    [System.IO.File]::WriteAllText($path, ($applied | ConvertTo-Json -Depth 50), $utf8)
    $result = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    $after = Read-JsonFile $path
    Assert-True ($result.Reverted -gt 0 -and $result.Kept -ge 1) "unexpected revert counts $($result.Reverted)/$($result.Kept)"
    Assert-True ($after.profiles.defaults.opacity -eq 42) 'user edit made after install was lost'
    Assert-True (@($after.profiles.list | Where-Object name -eq 'User added').Count -eq 1) 'user-added profile was lost'
    Assert-True (-not (Test-PspProp $after.profiles.defaults 'colorScheme')) 'colorScheme not removed'
    Assert-True ((ConvertTo-PspCanonicalJson $after.profiles.defaults.font) -eq (ConvertTo-PspCanonicalJson $origParsed.profiles.defaults.font)) 'font not restored'
    Assert-True ((ConvertTo-PspCanonicalJson @($after.keybindings)) -eq (ConvertTo-PspCanonicalJson @($origParsed.keybindings))) 'keybindings not restored'
    Assert-True ($after.theme -eq 'dark') 'theme not restored'
    Assert-True (-not ([string]@($after.profiles.list)[0].commandline -match '-NoLogo')) '-NoLogo not removed'
}

Test-Case 'Undo leaves no empty arrays the profile created in a file that had none' {
    $theme = Read-JsonFile (Join-Path $repoRoot 'theme.json')
    $term = Read-JsonFile (Join-Path $repoRoot 'terminal-config.json')
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $original = '{ "profiles": { "defaults": { "opacity": 80 } } }'
    $path = New-WtSettings -Json $original
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults $term.defaults -WindowsTerminal $theme.windowsTerminal -Keybindings $term.keybindings -Confirm:$false
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    $after = Read-JsonFile $path
    Assert-True ((ConvertTo-PspCanonicalJson $after) -eq (ConvertTo-PspCanonicalJson (ConvertFrom-JsonC -Text $original))) "not restored exactly: $(ConvertTo-PspCanonicalJson $after)"
}

Test-Case 'A single-element array value is recorded as an array and reverted' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": { "defaults": {}, "list": [] } }'
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults ([PSCustomObject]@{ bellStyle = [object[]]@('window') }) -Confirm:$false
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    Assert-True (-not (Test-PspProp (Read-JsonFile $path).profiles.defaults 'bellStyle')) 'a ["window"] value was recorded as "window" and never reverted'
}

Test-Case 'Values an earlier profile version wrote are reverted to the pre-install copy' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    # An earlier version wrote opacity and font without a change record; the pre-install file is kept as .psp-original.
    $path = New-WtSettings -Json '{ "profiles": { "defaults": { "opacity": 75, "font": { "face": "CaskaydiaCove NF" } }, "list": [] } }'
    [System.IO.File]::WriteAllText("$path.psp-original", '{ "profiles": { "defaults": { "opacity": 95 }, "list": [] } }', $utf8)
    $defaults = [PSCustomObject]@{ opacity = 75; font = [PSCustomObject]@{ face = 'CaskaydiaCove NF' } }
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults $defaults -Confirm:$false
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    $after = (Read-JsonFile $path).profiles.defaults
    Assert-True ($after.opacity -eq 95 -and -not (Test-PspProp $after 'font')) "pre-install values not restored: $(ConvertTo-PspCanonicalJson $after)"
}

Test-Case '-NoLogo is recorded correctly for a bare-array profiles list' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": [ { "guid": "{a1}", "name": "PowerShell", "commandline": "pwsh.exe" } ] }'
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -NoLogo -Confirm:$false
    Assert-True (@((Read-JsonFile $path).profiles.list)[0].commandline -eq 'pwsh.exe -NoLogo') '-NoLogo not added'
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    Assert-True (@((Read-JsonFile $path).profiles.list)[0].commandline -eq 'pwsh.exe') 'command line not restored (dropped instead)'
}

Test-Case 'A -NoLogo an earlier profile version added is removed on uninstall' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": { "list": [ { "guid": "{b2}", "name": "PowerShell", "commandline": "pwsh.exe -NoLogo" } ] } }'
    [System.IO.File]::WriteAllText("$path.psp-original", '{ "profiles": { "list": [ { "guid": "{b2}", "name": "PowerShell", "commandline": "pwsh.exe" } ] } }', $utf8)
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -NoLogo -Confirm:$false
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    Assert-True (@((Read-JsonFile $path).profiles.list)[0].commandline -eq 'pwsh.exe') 'the earlier -NoLogo was left behind'
}

Test-Case 'Undo keeps a profile action that the user bound to more keys' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": { "defaults": {}, "list": [] }, "actions": [], "keybindings": [] }'
    $kb = @([PSCustomObject]@{ keys = 'ctrl+shift+f'; command = [PSCustomObject]@{ action = 'find' } })
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Keybindings $kb -Confirm:$false
    $wt = Read-JsonFile $path
    $id = [string]@($wt.actions)[0].id
    $wt.keybindings = @($wt.keybindings) + ([PSCustomObject]@{ id = $id; keys = 'alt+f' })
    [System.IO.File]::WriteAllText($path, ($wt | ConvertTo-Json -Depth 20), $utf8)
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Confirm:$false
    $after = Read-JsonFile $path
    Assert-True (@($after.actions | Where-Object { $_.id -eq $id }).Count -eq 1) 'the action was removed while alt+f still points at it'
}

Test-Case 'Undo-WindowsTerminalSettingsFile is a high-impact command' {
    $binding = (Get-Command Undo-WindowsTerminalSettingsFile).ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
    Assert-True ($binding.ConfirmImpact -eq 'High') "ConfirmImpact is $($binding.ConfirmImpact)"
}

Test-Case 'Uninstall-Profile reverts every Windows Terminal variant (F-01)' {
    $stable = New-WtSettings
    $preview = New-WtSettings -Variant 'Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe'
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $defaults = [PSCustomObject]@{ opacity = 75; font = [PSCustomObject]@{ face = 'CaskaydiaCove NF' } }
    foreach ($p in $stable, $preview) { $null = Update-WindowsTerminalSettingsFile -Path $p -ManifestPath $manifest -Defaults $defaults -Confirm:$false }
    Uninstall-Profile -Confirm:$false 6>$null | Out-Null
    foreach ($p in $stable, $preview) {
        $wt = Read-JsonFile $p
        Assert-True ($wt.profiles.defaults.opacity -eq 95) "opacity not restored in $p"
        Assert-True (-not (Test-PspProp $wt.profiles.defaults 'font')) "font left behind in $p"
        # The pre-install copy stays until -RemoveUserData; the rotating backups go.
        $left = @(Get-WtProfileBackups -Path $p)
        Assert-True ($left.Count -eq 1 -and $left[0].Name -like '*.psp-original') "unexpected backups next to ${p}: $(@($left | ForEach-Object { $_.Name }) -join ', ')"
    }
}

Test-Case 'Uninstall-Profile -RemoveUserData also removes the pre-install copy' {
    $path = New-WtSettings
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults ([PSCustomObject]@{ opacity = 75 }) -Confirm:$false
    Uninstall-Profile -RemoveUserData -Confirm:$false 6>$null | Out-Null
    Assert-True ((Read-JsonFile $path).profiles.defaults.opacity -eq 95) 'not reverted'
    Assert-True (@(Get-WtProfileBackups -Path $path).Count -eq 0) 'backups left with -RemoveUserData'
}

Test-Case 'Uninstall-Profile -HardResetWindowsTerminal drops the change record of the deleted file' {
    $path = New-WtSettings
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults ([PSCustomObject]@{ opacity = 75 }) -Confirm:$false
    Uninstall-Profile -HardResetWindowsTerminal -Confirm:$false 6>$null | Out-Null
    Assert-True (-not (Test-Path -LiteralPath $path)) 'settings.json not deleted'
    Assert-True (-not (Get-PspProp (Read-WtChangeManifest -ManifestPath $manifest).files $path.ToLowerInvariant())) 'the record of the deleted file was kept'
}

Test-Case 'An unreadable user-settings.json leaves settings.json alone in Uninstall-Profile' {
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path (Get-PspCacheDir) 'user-settings.json'), '{ "windowsTerminal": ', $utf8)
    $path = New-WtSettings -Json '{"profiles":{"defaults":{"opacity":75}}}'
    [System.IO.File]::WriteAllText("$path.20240101-000000.bak", '{"stale":true}', $utf8)
    $before = [System.IO.File]::ReadAllText($path)
    $out = Uninstall-Profile -Confirm:$false *>&1 | Out-String
    Assert-True ([System.IO.File]::ReadAllText($path) -eq $before) 'settings.json was changed'
    Assert-True ($out -match 'could not be read') 'no warning about the unreadable file'
}

Test-Case 'Uninstall-Profile without a change record restores the oldest backup and keeps the current file (F-01)' {
    $path = New-WtSettings -Json '{"profiles":{"defaults":{"opacity":75}}}'
    [System.IO.File]::WriteAllText("$path.20240101-000000.bak", '{"profiles":{"defaults":{"opacity":88}}}', $utf8)
    (Get-Item -LiteralPath "$path.20240101-000000.bak").LastWriteTime = (Get-Date).AddDays(-10)
    [System.IO.File]::WriteAllText("$path.20240601-000000.bak", '{"profiles":{"defaults":{"opacity":60}}}', $utf8)
    Uninstall-Profile -Confirm:$false 6>$null | Out-Null
    Assert-True ((Read-JsonFile $path).profiles.defaults.opacity -eq 88) 'did not restore the oldest (pre-install) backup'
    Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $path) -Filter 'settings.json.pre-uninstall-*.json').Count -eq 1) 'current settings were not kept'
}

Test-Case 'windowsTerminal.manage = false leaves settings.json alone in uninstall and Set-TerminalBackground (F-05)' {
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path (Get-PspCacheDir) 'user-settings.json'), '{ "windowsTerminal": { "manage": false } }', $utf8)
    $path = New-WtSettings -Json '{"profiles":{"defaults":{"opacity":75}}}'
    [System.IO.File]::WriteAllText("$path.20240101-000000.bak", '{"stale":true}', $utf8)
    $before = [System.IO.File]::ReadAllText($path)
    $img = Join-Path $script:Sandbox.Work 'bg.png'
    [System.IO.File]::WriteAllBytes($img, [byte[]](0x89, 0x50, 0x4E, 0x47))
    Set-TerminalBackground -Path $img -Confirm:$false 6>$null
    Uninstall-Profile -Confirm:$false 6>$null | Out-Null
    Uninstall-Profile -HardResetWindowsTerminal -Confirm:$false 6>$null | Out-Null
    Assert-True ((Test-Path -LiteralPath $path) -and [System.IO.File]::ReadAllText($path) -eq $before) 'settings.json was changed or deleted'
}

Test-Case 'Set-TerminalBackground goes through the change record and -Clear reverts cleanly' {
    $path = New-WtSettings -Json '{ "profiles": { "defaults": { "backgroundImageOpacity": 0.8 }, "list": [] } }'
    $img = Join-Path $script:Sandbox.Work 'bg.png'
    [System.IO.File]::WriteAllBytes($img, [byte[]](0x89, 0x50, 0x4E, 0x47))
    Set-TerminalBackground -Path $img -Alignment left -Confirm:$false 6>$null
    $wt = Read-JsonFile $path
    Assert-True ($wt.profiles.defaults.backgroundImage -eq $img -and $wt.profiles.defaults.backgroundImageAlignment -eq 'left') 'background not applied'
    Set-TerminalBackground -Clear -Confirm:$false 6>$null
    $null = Undo-WindowsTerminalSettingsFile -Path $path -ManifestPath (Join-Path (Get-PspCacheDir) 'wt-changes.json') -Confirm:$false
    $wt = Read-JsonFile $path
    Assert-True ($wt.profiles.defaults.backgroundImageOpacity -eq 0.8 -and -not (Test-PspProp $wt.profiles.defaults 'backgroundImage')) 'original values not restored'
}

Write-Host '-- Trusted .psprc.ps1 (F-02) --' -ForegroundColor Magenta

Test-Case 'A trusted .psprc.ps1 runs only while its content matches the approved hash' {
    $repo = Join-Path $script:Sandbox.Work 'repo'
    New-Item -ItemType Directory -Path $repo -Force | Out-Null
    $rc = Join-Path $repo '.psprc.ps1'
    [System.IO.File]::WriteAllText($rc, '$env:PSP_RC_RAN = "v1"', $utf8)
    $script:PSP.Features.perDirProfiles = $true
    $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear()
    $env:PSP_RC_RAN = $null
    Add-TrustedDirectory -Path $repo -Confirm:$false 6>$null | Out-Null
    $saved = Read-JsonFile (Join-Path (Get-PspCacheDir) 'user-settings.json')
    Assert-True ((Get-PspProp $saved.trustedRcHashes $repo) -eq (Get-PspRcHash -Directory $repo)) 'approved hash not persisted'
    Push-Location $repo
    try {
        $script:PSP.LastPwd = $null; Invoke-PromptStage 6>$null
        Assert-True ($env:PSP_RC_RAN -eq 'v1') 'approved file did not run'
        # A git pull changes the file.
        [System.IO.File]::WriteAllText($rc, '$env:PSP_RC_RAN = "v2"', $utf8)
        $env:PSP_RC_RAN = $null
        $script:PSP.LastPwd = $null
        $warnings = @(Invoke-PromptStage 6>$null 3>&1)
        Assert-True ($null -eq $env:PSP_RC_RAN) 'changed file ran without approval'
        Assert-True ((@($warnings) -join ' ') -match 'changed since it was approved') 'no warning for the changed file'
        Add-TrustedDirectory -Path $repo -Confirm:$false 6>$null | Out-Null
        $env:PSP_RC_RAN = $null
        $script:PSP.LastPwd = $null; Invoke-PromptStage 6>$null
        Assert-True ($env:PSP_RC_RAN -eq 'v2') 're-approved file did not run'
    }
    finally { Pop-Location; $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear(); $env:PSP_RC_RAN = $null }
}

Test-Case 'A trusted directory from an older version (no hash) does not run its .psprc.ps1' {
    $dir = Join-Path $script:Sandbox.Work 'legacy'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dir '.psprc.ps1'), '$env:PSP_LEGACY_RAN = "yes"', $utf8)
    $script:PSP.Features.perDirProfiles = $true
    $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear()
    [void]$script:PSP.TrustedDirs.Add($dir)
    $env:PSP_LEGACY_RAN = $null
    Push-Location $dir
    try { $script:PSP.LastPwd = $null; Invoke-PromptStage 6>$null 3>$null }
    finally { Pop-Location; $script:PSP.TrustedDirs.Clear() }
    Assert-True ($null -eq $env:PSP_LEGACY_RAN) 'legacy trust entry ran unapproved code'
}

Test-Case 'Trust changes never overwrite an unparseable user-settings.json and roll back in memory' {
    $repo = Join-Path $script:Sandbox.Work 'repo2'
    New-Item -ItemType Directory -Path $repo -Force | Out-Null
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $settings = Join-Path (Get-PspCacheDir) 'user-settings.json'
    [System.IO.File]::WriteAllText($settings, '{ "trustedDirs": [ ', $utf8)
    $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear()
    Add-TrustedDirectory -Path $repo -Confirm:$false -ErrorAction SilentlyContinue 6>$null 3>$null | Out-Null
    Assert-True ([System.IO.File]::ReadAllText($settings) -eq '{ "trustedDirs": [ ') 'corrupt settings were overwritten'
    Assert-True ($script:PSP.TrustedDirs.Count -eq 0 -and $script:PSP.TrustedRcHashes.Count -eq 0) 'in-memory trust not rolled back'
}

Test-Case 'Trust changes keep entries another session saved since this one loaded' {
    $a = Join-Path $script:Sandbox.Work 'trust-a'
    $b = Join-Path $script:Sandbox.Work 'trust-b'
    foreach ($d in $a, $b) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $settings = Join-Path (Get-PspCacheDir) 'user-settings.json'
    $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear()
    try {
        # Another session trusted $a after this one loaded.
        [System.IO.File]::WriteAllText($settings, (@{ trustedDirs = @($a); trustedRcHashes = @{ $a = '' } } | ConvertTo-Json), $utf8)
        Add-TrustedDirectory -Path $b -Confirm:$false 6>$null | Out-Null
        $saved = @((Read-JsonFile $settings).trustedDirs)
        Assert-True ($saved -contains $a -and $saved -contains $b) "entries lost: $($saved -join ', ')"
        Assert-True ($script:PSP.TrustedDirs -contains $a) 'this session did not pick up the other entry'
        Remove-TrustedDirectory -Path $b -Confirm:$false 6>$null | Out-Null
        $saved = @((Read-JsonFile $settings).trustedDirs)
        Assert-True ($saved -contains $a -and $saved -notcontains $b) "untrust result: $($saved -join ', ')"
    }
    finally { $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear() }
}

Test-Case 'An approved .psprc.ps1 runs the text that was checked and sees its folder as $PSScriptRoot' {
    $repo = Join-Path $script:Sandbox.Work 'rcroot'
    New-Item -ItemType Directory -Path $repo -Force | Out-Null
    $rc = Join-Path $repo '.psprc.ps1'
    $approved = 'param()' + "`r`n" + '$env:PSP_RC_RAN = "approved|$PSScriptRoot"'
    [System.IO.File]::WriteAllText($rc, $approved, $utf8)
    $script:PSP.Features.perDirProfiles = $true
    $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear()
    $env:PSP_RC_RAN = $null
    try {
        Add-TrustedDirectory -Path $repo -Confirm:$false 6>$null | Out-Null
        $approvedContent = Get-PspRcContent -Directory $repo
        # The file is swapped between the check and the run: only the checked text may run.
        [System.IO.File]::WriteAllText($rc, '$env:PSP_RC_RAN = "swapped"', $utf8)
        function Get-PspRcContent { param([string]$Directory) $approvedContent }
        Push-Location $repo
        try { $script:PSP.LastPwd = $null; Invoke-PromptStage 6>$null 3>$null }
        finally { Pop-Location }
        Assert-True ($env:PSP_RC_RAN -eq "approved|$repo") "ran: '$env:PSP_RC_RAN'"
    }
    finally { $script:PSP.TrustedDirs.Clear(); $script:PSP.TrustedRcHashes.Clear(); $env:PSP_RC_RAN = $null }
}

Write-Host '-- Update-Profile and setup.ps1 verification (F-03, F-08) --' -ForegroundColor Magenta

Test-Case 'Update-Profile stops without a hash and on a wrong hash, writing nothing' {
    Install-DownloadStub
    $err = $null
    Update-Profile -Ref main -ErrorAction SilentlyContinue -ErrorVariable err 6>$null | Out-Null
    Assert-True ((@($err) -join ' ') -match 'Hash input required') 'missing hash was not rejected'
    $err = $null
    Update-Profile -Ref main -ExpectedSha256 ('0' * 64) -ErrorAction SilentlyContinue -ErrorVariable err 6>$null | Out-Null
    Assert-True ((@($err) -join ' ') -match 'mismatch') 'wrong hash was not rejected'
    Assert-True (-not (Test-Path -LiteralPath $PROFILE)) 'profile written despite failed verification'
    Assert-True (@(Get-ChildItem -LiteralPath $env:TEMP -Filter 'psp-*' -Force).Count -eq 0) 'temp files left behind'
}

Test-Case 'Update-Profile -Ref vX.Y.Z checks the release SHA256SUMS.txt and installs no tools by default' {
    Install-DownloadStub
    $global:PspStubSums = (@('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    $err = $null
    $script:Installs = @()
    function winget { $script:Installs += "winget $args"; $global:LASTEXITCODE = 0 }
    function Install-Module { $script:Installs += "Install-Module $args" }
    $out = Update-Profile -Ref v9.9.9 -ErrorAction SilentlyContinue -ErrorVariable err *>&1 | Out-String
    # -ErrorVariable also collects errors that nested calls silenced; only the update's own failure counts.
    $failure = @($err | Where-Object { "$_" -match 'Unable to check for' })
    Assert-True ($failure.Count -eq 0) "update failed: $($failure -join ' ')"
    Assert-True ($out -match 'match the SHA256SUMS.txt of release v9.9.9') 'release verification not reported'
    Assert-True (Test-Path -LiteralPath $PROFILE) 'profile not installed'
    Assert-True ($script:Installs.Count -eq 0 -and @(Get-PspSandboxWingetCalls -Sandbox $script:Sandbox).Count -eq 0) "Update-Profile installed software without -InstallMissingTools: $($script:Installs -join ' | ')"
    $state = Read-JsonFile (Join-Path (Get-PspCacheDir) 'installed.json')
    Assert-True ($state.ref -eq 'v9.9.9' -and $state.commit -eq ('a' * 40)) 'install state not recorded'
    # A tampered file is rejected.
    $global:PspStubSums = $global:PspStubSums -replace '^[0-9a-f]{64}', ('f' * 64)
    Remove-Item -LiteralPath $PROFILE -Force
    $err = $null
    Update-Profile -Ref v9.9.9 -Force -ErrorAction SilentlyContinue -ErrorVariable err 6>$null | Out-Null
    Assert-True ((@($err) -join ' ') -match 'does not match the SHA256SUMS.txt') 'tampered release file accepted'
    Assert-True (-not (Test-Path -LiteralPath $PROFILE)) 'tampered profile installed'
    $global:PspStubSums = $null
}

Test-Case 'setup.ps1 verifies the bundle before any change (missing, wrong, pinned and release hashes)' {
    Install-DownloadStub
    $out = & $setupPath -Ref main -CiMode -SkipWizard *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 1 -and $out -match 'Hash input required') 'missing hash accepted'
    Assert-True (-not (Test-Path -LiteralPath (Get-PspCacheDir)) -and -not (Test-Path -LiteralPath $PROFILE)) 'changes made before verification'
    $combined = [regex]::Match($out, 'combined:\s+([0-9A-F]{64})').Groups[1].Value
    $out = & $setupPath -Ref main -CiMode -SkipWizard -ExpectedSha256 ('0' * 64) *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 1 -and $out -match 'mismatch' -and -not (Test-Path -LiteralPath $PROFILE)) 'wrong hash accepted'
    $out = & $setupPath -Ref main -CiMode -SkipWizard -ExpectedSha256 $combined *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $PROFILE)) "pinned install failed: $out"
    Assert-True (@(Get-ChildItem -LiteralPath $env:TEMP -Filter 'psp-*' -Force).Count -eq 0) 'temp files left behind'
}

Test-Case 'Update-Profile -InstallMissingTools installs missing tools even when the profile is up to date' {
    Install-DownloadStub
    $global:PspStubSums = (@('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    try {
        $err = $null
        Update-Profile -Ref main -InstallMissingTools -ErrorAction SilentlyContinue -ErrorVariable err 6>$null | Out-Null
        Assert-True ((@($err) -join ' ') -match "ExpectedSha256 '[0-9A-F]{64}' -InstallMissingTools") 'the re-run hint drops -InstallMissingTools'
        Update-Profile -Ref v9.9.9 -ErrorAction SilentlyContinue *>&1 | Out-Null
        Assert-True (Test-Path -LiteralPath $PROFILE) 'first update did not install the profile'
        $script:WingetCalls = @()
        function winget { $script:WingetCalls += ($args -join ' '); $global:LASTEXITCODE = 0 }
        function Get-ProfileToolExecutablePath { param($Tool) $null }
        $out = Update-Profile -Ref v9.9.9 -InstallMissingTools -ErrorAction SilentlyContinue *>&1 | Out-String
        $installs = @($script:WingetCalls | Where-Object { $_ -match '^install -e --id ' })
        Assert-True ($installs.Count -eq @($script:ProfileTools).Count) "missing tools not installed on an up-to-date profile: $($script:WingetCalls -join ' | ') $out"
    }
    finally { $global:PspStubSums = $null }
}

Test-Case 'An unreadable user-settings.json leaves settings.json alone in Update-Profile' {
    Install-DownloadStub
    $global:PspStubSums = (@('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    try {
        New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path (Get-PspCacheDir) 'user-settings.json'), '{ "windowsTerminal": ', $utf8)
        $path = New-WtSettings
        $before = [System.IO.File]::ReadAllText($path)
        Update-Profile -Ref v9.9.9 -ErrorAction SilentlyContinue *>&1 | Out-Null
        Assert-True (Test-Path -LiteralPath $PROFILE) 'profile not installed'
        Assert-True ([System.IO.File]::ReadAllText($path) -eq $before) 'settings.json was changed'
    }
    finally { $global:PspStubSums = $null }
}

Test-Case 'winutil runs a pinned or forced download only from an elevated shell' {
    $script:Downloads = 0
    function Invoke-WebRequest { $script:Downloads++; [PSCustomObject]@{ RawContentStream = [System.IO.MemoryStream]::new([byte[]](0x23)) } }
    $saved = $script:PSP.IsAdmin
    $script:PSP.IsAdmin = $false
    try {
        foreach ($call in @(@{ Force = $true }, @{ ExpectedSha256 = ('0' * 64) })) {
            $err = $null
            winutil @call -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err 6>$null
            Assert-True ((@($err) -join ' ') -match 'elevated shell' -and $script:Downloads -eq 0) "winutil -$(@($call.Keys)[0]) went ahead unelevated"
        }
    }
    finally { $script:PSP.IsAdmin = $saved }
}

Test-Case 'Invoke-ProfileWizard checks setup.ps1 of a release and passes the tag on' {
    Install-DownloadStub
    $global:PspStubSums = (@('setup.ps1', 'Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    $script:ShellArgs = $null
    function Get-PspShellPath { 'Invoke-PspTestShell' }
    function Invoke-PspTestShell { $script:ShellArgs = @($args); $global:LASTEXITCODE = 0 }
    try {
        Invoke-ProfileWizard -Ref v9.9.9 -Confirm:$false 6>$null
        $i = [array]::IndexOf([object[]]$script:ShellArgs, '-Ref')
        Assert-True ($i -ge 0 -and $script:ShellArgs[$i + 1] -eq 'v9.9.9') "setup.ps1 not started with the release tag: $($script:ShellArgs -join ' ')"
        $global:PspStubSums = $global:PspStubSums -replace '(?m)^[0-9a-f]{64}(?=  setup\.ps1$)', ('f' * 64)
        $script:ShellArgs = $null
        $err = $null
        Invoke-ProfileWizard -Ref v9.9.9 -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err 6>$null
        Assert-True ($null -eq $script:ShellArgs -and (@($err) -join ' ') -match 'does not match the SHA256SUMS.txt') 'a setup.ps1 that differs from the release was run'
    }
    finally { $global:PspStubSums = $null }
}

Test-Case 'setup.ps1 -Ref vX.Y.Z verifies the bundle against the release SHA256SUMS.txt' {
    Install-DownloadStub
    $global:PspStubSums = (@('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    try {
        $out = & $setupPath -Ref v9.9.9 -CiMode -SkipWizard *>&1 | Out-String
        Assert-True ($LASTEXITCODE -eq 0 -and $out -match 'matches the SHA256SUMS.txt of release v9.9.9' -and (Test-Path -LiteralPath $PROFILE)) "release install failed: $out"
        Remove-Item -LiteralPath $PROFILE -Force
        $global:PspStubSums = $global:PspStubSums -replace '(?m)^[0-9a-f]{64}(?=  theme\.json$)', ('f' * 64)
        $out = & $setupPath -Ref v9.9.9 -CiMode -SkipWizard *>&1 | Out-String
        Assert-True ($LASTEXITCODE -eq 1 -and $out -match 'does not match the SHA256SUMS.txt' -and -not (Test-Path -LiteralPath $PROFILE)) 'a bundle that differs from the release was installed'
    }
    finally { $global:PspStubSums = $null }
}

Test-Case 'setup.ps1 run as a script block leaves no variables in the caller''s session' {
    $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
    $code = @(
        "`$global:PROFILE = $(& $q $PROFILE)"
        "& ([scriptblock]::Create([System.IO.File]::ReadAllText($(& $q $setupPath)))) -LocalRepo $(& $q $repoRoot) -CiMode -SkipWizard -WhatIf *> `$null"
        "`$left = @('Bundle', 'WorkDir', 'CanPrompt', 'SharedFunctionNames', 'CuratedFonts', 'IsCiHost') | Where-Object { Get-Variable -Name `$_ -Scope Global -ErrorAction Ignore }"
        "'LEFT=' + (`$left -join ',') + ';EXIT=' + `$LASTEXITCODE"
    ) -join "`n"
    $exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh' } else { 'powershell' }
    $out = & $exe -NoProfile -NonInteractive -Command $code 2>&1 | Out-String
    Assert-True ($out -match 'LEFT=;EXIT=0') "unexpected: $out"
}

Test-Case 'setup.ps1 saves the user''s own profile as profile.original.ps1, never an installed copy' {
    Install-DownloadStub
    $d = $script:Sandbox.Ps7Dir
    # An installed copy of this profile is current; the user's own profile only survives as an old backup.
    [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), [System.IO.File]::ReadAllText($profilePath), $utf8)
    $own = Join-Path $d 'oldprofile.20240101-000000.ps1'
    [System.IO.File]::WriteAllText($own, '# my own profile', $utf8)
    (Get-Item -LiteralPath $own).LastWriteTime = (Get-Date).AddDays(-30)
    $out = & $setupPath -LocalRepo $repoRoot -CiMode -SkipWizard *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 0) "setup failed: $out"
    Assert-True ([System.IO.File]::ReadAllText((Join-Path $d 'profile.original.ps1')).Trim() -eq '# my own profile') 'profile.original.ps1 is not the user''s own profile'
}

Test-Case 'setup.ps1 loads every profile helper its shared functions call' {
    $tokens = $null; $parseErrors = $null
    $profileAst = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $setupAst = [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$tokens, [ref]$parseErrors)
    $profileFns = @{}
    foreach ($s in $profileAst.EndBlock.Statements) { if ($s -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $profileFns[$s.Name] = $s } }
    $available = @{}
    foreach ($f in $setupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $available[$f.Name] = $true }
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable '$script:SharedFunctionNames')))
    $shared = @($script:SharedFunctionNames)
    foreach ($n in $shared) { $available[$n] = $true }
    $missing = @()
    foreach ($n in $shared) {
        Assert-True ($profileFns.ContainsKey($n)) "the profile does not define $n"
        foreach ($c in $profileFns[$n].FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $called = $c.GetCommandName()
            if ($called -and $profileFns.ContainsKey($called) -and -not $available[$called]) { $missing += "$called (called by $n)" }
        }
    }
    Assert-True ($missing.Count -eq 0) "add to `$script:SharedFunctionNames in setup.ps1: $($missing | Sort-Object -Unique)"
}

Test-Case 'setup.ps1 -LocalRepo -CiMode installs into the sandbox; -WhatIf changes nothing (F-14)' {
    # Downloads (the Oh My Posh theme) fail as if offline.
    Install-DownloadStub
    $wt = New-WtSettings
    $out = & $setupPath -LocalRepo $repoRoot -CiMode -SkipWizard -WhatIf *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath $PROFILE) -and -not (Test-Path -LiteralPath (Get-PspCacheDir))) "-WhatIf changed something: $out"
    $out = & $setupPath -LocalRepo $repoRoot -CiMode -SkipWizard *>&1 | Out-String
    Assert-True ($LASTEXITCODE -eq 0) "setup failed: $out"
    foreach ($f in 'theme.json', 'terminal-config.json', 'user-settings.json', 'installed.json', 'wt-changes.json') {
        Assert-True (Test-Path -LiteralPath (Join-Path (Get-PspCacheDir) $f)) "cache is missing $f"
    }
    Assert-True ((Read-JsonFile $wt).profiles.defaults.font.face -eq 'CaskaydiaCove NF') 'terminal defaults not applied'
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path (Get-PspCacheDir) 'logs') -Filter 'setup-*.log').Count -eq 1) 'no setup log'
    Assert-True ($out -notmatch 'Terminal-Icons') 'Terminal-Icons touched in CI mode (F-07)'
}

Write-Host '-- Wizard input (F-06, F-21) --' -ForegroundColor Magenta

Test-Case 'Save-WizardChoices refuses an unparseable file and keeps hand-edited JSONC keys' {
    $path = Join-Path $script:Sandbox.Work 'user-settings.json'
    [System.IO.File]::WriteAllText($path, '{ "trustedDirs": [ ', $utf8)
    $threw = $false
    try { Save-WizardChoices -Choices @{ Features = [ordered]@{ psfzf = $false } } -UserSettingsPath $path -Confirm:$false } catch { $threw = $true }
    Assert-True ($threw -and [System.IO.File]::ReadAllText($path) -eq '{ "trustedDirs": [ ') 'unparseable settings were overwritten'
    $jsonc = "{`n  // mine`n  `"trustedDirs`": [`"C:\\work`"],`n  `"commandOverrides`": { `"gs`": `"git status`" },`n}"
    [System.IO.File]::WriteAllText($path, $jsonc, $utf8)
    Save-WizardChoices -Choices @{ Features = [ordered]@{ psfzf = $false }; Terminal = [ordered]@{ opacity = 90; fontSize = 12 } } -UserSettingsPath $path -Confirm:$false
    $s = Read-JsonFile $path
    Assert-True (@($s.trustedDirs) -contains 'C:\work' -and $s.commandOverrides.gs -eq 'git status') 'existing keys lost'
    Assert-True ($s.features.psfzf -eq $false -and $s.defaults.opacity -eq 90 -and $s.defaults.font.size -eq 12) 'choices not saved'
    Assert-True ([System.IO.File]::ReadAllText("$path.bak") -eq $jsonc) 'no backup of the previous file'
}

Test-Case 'Resumed wizard state is rebuilt from the curated lists (tampered values dropped)' {
    $saved = [PSCustomObject]@{
        Theme          = [PSCustomObject]@{ Name = 'pure'; Url = 'http://evil.example/x.omp.json' }
        Scheme         = [PSCustomObject]@{ name = 'Dracula'; background = '#ff0000' }
        Font           = [PSCustomObject]@{ Name = 'CascadiaCode'; Asset = '../../evil'; Sha256 = ('0' * 64) }
        Editor         = "code'; Remove-Item C:\ -Recurse; '"
        TabBar         = 'red'
        AppTheme       = 'light'
        Terminal       = [PSCustomObject]@{ opacity = 500; fontSize = 12; cursorShape = 'bar; rm' }
        Features       = [PSCustomObject]@{ psfzf = $false; evil = $true }
        CompletedSteps = @('Theme', 'Bogus')
    }
    $v = Resolve-WizardState -Saved $saved
    Assert-True ($null -eq $v.Theme) 'untrusted theme URL kept'
    Assert-True ($v.Scheme.background -eq '#282a36') 'scheme not replaced by the curated definition'
    Assert-True ($v.Font.Asset -eq 'CascadiaCode' -and $v.Font.Sha256 -ne ('0' * 64)) 'font asset or hash taken from the state file'
    Assert-True ($null -eq $v.Editor -and $null -eq $v.TabBar -and $v.AppTheme -eq 'light') 'editor/tab bar validation'
    Assert-True ($v.Terminal.Count -eq 1 -and $v.Terminal['fontSize'] -eq 12) 'terminal values not range-checked'
    Assert-True ($v.Features.Count -eq 1 -and $v.Features['psfzf'] -eq $false) 'unknown feature kept'
    Assert-True (@($v.CompletedSteps).Count -eq 1) 'unknown step kept'
}

# Answer the wizard's Read-Host prompts from a queue; '<STOP>' simulates an interrupted run (Ctrl+C).
function New-WizardAnswers {
    param([string[]]$Answers)
    $script:WizardAnswers = [System.Collections.Generic.Queue[string]]::new()
    foreach ($a in $Answers) { $script:WizardAnswers.Enqueue($a) }
}

Test-Case 'Wizard quick start saves the pinned preset' {
    function Read-Host { param($Prompt, [switch]$AsSecureString) if ($script:WizardAnswers.Count -eq 0) { throw "unexpected prompt: $Prompt" }; $script:WizardAnswers.Dequeue() }
    function Test-TelemetryOptOutSet { $false }
    New-WizardAnswers @('y', '')
    $state = Join-Path (Get-PspCacheDir) 'wizard-state.json'
    $choices = Start-InstallWizard -StatePath $state 6>$null
    Assert-True ($choices.Theme.Name -eq 'atomic' -and $choices.Theme.Sha256 -eq $script:PinnedOmpThemes['atomic']) 'preset theme not pinned'
    Assert-True ($choices.Theme.Url -match '/v31\.8\.0/themes/atomic\.omp\.json$') 'preset theme URL not pinned'
    Assert-True ($choices.Scheme.name -eq 'Tokyo Night' -and $choices.Font.Asset -eq 'CascadiaCode') 'preset scheme or font missing'
    Assert-True ($script:WizardAnswers.Count -eq 0) 'wizard asked fewer questions than expected'
    $settings = Join-Path (Get-PspCacheDir) 'user-settings.json'
    Save-WizardChoices -Choices $choices -UserSettingsPath $settings -Confirm:$false
    $saved = Read-JsonFile $settings
    Assert-True ($saved.theme.name -eq 'atomic' -and $saved.theme.sha256 -eq $script:PinnedOmpThemes['atomic'] -and $saved.defaults.font.face -eq 'CaskaydiaCove NF') 'preset not saved'
}

Test-Case 'An interrupted wizard resumes from its saved state' {
    function Read-Host { param($Prompt, [switch]$AsSecureString) if ($script:WizardAnswers.Count -eq 0) { throw "unexpected prompt: $Prompt" }; $a = $script:WizardAnswers.Dequeue(); if ($a -eq '<STOP>') { throw 'interrupted' }; $a }
    function Test-TelemetryOptOutSet { $false }
    function Get-OmpThemeList { @(@{ Name = 'atomic'; Desc = ''; Url = (Get-OmpThemeUrl -Name 'atomic'); Sha256 = $script:PinnedOmpThemes['atomic'] }, @{ Name = 'pure'; Desc = ''; Url = (Get-OmpThemeUrl -Name 'pure'); Sha256 = $script:PinnedOmpThemes['pure'] }) }
    $state = Join-Path (Get-PspCacheDir) 'wizard-state.json'
    # No quick start; theme, scheme, font, tab bar (default), dark chrome; stop at the first terminal question.
    New-WizardAnswers @('n', 'atomic', 'Nord', 'Hack', '', 'n', '<STOP>')
    $threw = $false
    try { $null = Start-InstallWizard -StatePath $state 6>$null } catch { $threw = $_.Exception.Message -eq 'interrupted' }
    Assert-True $threw 'interruption not raised'
    Assert-True (Test-Path -LiteralPath $state) 'no state saved'
    # Resume; then terminal (opacity 90, no acrylic, size 12, defaults), PSReadLine, no background, default editor, no telemetry, 5 features, apply.
    New-WizardAnswers @('y', '90', 'n', '12', '', '', '', '', '', 'n', '', 'n', '', '', '', '', '', '')
    $choices = Start-InstallWizard -StatePath $state 6>$null
    Assert-True ($choices.Theme.Name -eq 'atomic' -and $choices.Scheme.name -eq 'Nord' -and $choices.Font.Asset -eq 'Hack') 'choices made before the interruption were lost'
    Assert-True ($choices.Terminal['opacity'] -eq 90 -and $choices.Terminal['fontSize'] -eq 12) 'choices after resume missing'
    Assert-True ($choices.TelemetryOptOut -eq $false -and $choices.Features['psfzf'] -eq $true) 'telemetry or feature answers wrong'
    Assert-True ($script:WizardAnswers.Count -eq 0) 'wizard asked fewer questions than expected'
}
Test-Case 'Wizard quick start picks an installed editor instead of installing one' {
    function Read-Host { param($Prompt, [switch]$AsSecureString) if ($script:WizardAnswers.Count -eq 0) { throw "unexpected prompt: $Prompt" }; $script:WizardAnswers.Dequeue() }
    function Test-TelemetryOptOutSet { $false }
    # Only vim is installed.
    function Get-Command { param([string]$Name, $ErrorAction) if ($Name -eq 'vim') { [PSCustomObject]@{ Name = 'vim' } } }
    New-WizardAnswers @('y', '')
    $choices = Start-InstallWizard -StatePath (Join-Path (Get-PspCacheDir) 'wizard-state.json') 6>$null
    Assert-True ($choices.Editor -eq 'vim') "preset editor is '$($choices.Editor)'"
}

Test-Case 'Wizard name matching treats wildcard characters literally' {
    function Read-Host { param($Prompt, [switch]$AsSecureString) if ($script:WizardAnswers.Count -eq 0) { throw "unexpected prompt: $Prompt" }; $script:WizardAnswers.Dequeue() }
    New-WizardAnswers @('[', '2')
    $item = Select-WizardItem -Title 'pick' -Items @(@{ Name = 'alpha'; Desc = '' }, @{ Name = 'beta'; Desc = '' }) 6>$null
    Assert-True ($item.Name -eq 'beta') 'a reply with [ broke the selection'
}

Test-Case 'Set-PreferredEditorInProfiles quotes the name, backs up, and leaves an unchanged file alone' {
    $dir = $script:Sandbox.Ps7Dir
    $userProfile = Join-Path $dir 'profile_user.ps1'
    [System.IO.File]::WriteAllText($userProfile, "# mine`r`n`$script:EditorPriority = @('vim', 'notepad')`r`n# end`r`n", $utf8)
    Set-PreferredEditorInProfiles -EditorName "o'brien" -CommentLabel 't' -ProfileDirs @($dir) -Confirm:$false
    $text = [System.IO.File]::ReadAllText($userProfile)
    $tokens = $null; $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0 -and $text -match "@\('o''brien', 'notepad'\)") 'editor name not quoted safely'
    Assert-True ($text -match "# end`r`n" -and $text -notmatch "notepad'\)`n") 'line endings damaged'
    Assert-True (Test-Path -LiteralPath "$userProfile.bak") 'no backup'
    $stamp = (Get-Item -LiteralPath $userProfile).LastWriteTimeUtc
    Start-Sleep -Milliseconds 50
    Set-PreferredEditorInProfiles -EditorName "o'brien" -CommentLabel 't' -ProfileDirs @($dir) -Confirm:$false
    Assert-True ((Get-Item -LiteralPath $userProfile).LastWriteTimeUtc -eq $stamp) 'unchanged file was rewritten'
}

Test-Case 'Install-OhMyPoshTheme rejects a theme whose hash differs and invalid names (F-11)' {
    Install-DownloadStub
    $global:PspStubTheme = '{ "blocks": [] }'
    $url = Get-OmpThemeUrl -Name 'pure'
    Assert-True (-not (Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url -Sha256 ('0' * 64) 6>$null)) 'mismatching theme accepted'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path (Get-PspCacheDir) 'pure.omp.json'))) 'mismatching theme written'
    $good = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($utf8.GetBytes($global:PspStubTheme))) -Algorithm SHA256).Hash
    Assert-True (Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url -Sha256 $good 6>$null) 'matching theme rejected'
    Assert-True (-not (Install-OhMyPoshTheme -ThemeName '..\evil' -ThemeUrl $url 6>$null)) 'path-like theme name accepted'
    $global:PspStubTheme = $null
}

Write-Host '-- Cache, uninstall leftovers and state (F-16, F-17) --' -ForegroundColor Magenta

Test-Case 'Clear-ProfileCache keeps settings and state files' {
    $cache = Get-PspCacheDir
    New-Item -ItemType Directory -Path (Join-Path $cache 'plugins') -Force | Out-Null
    foreach ($f in 'user-settings.json', 'telemetry.owned', 'wt-changes.json', 'installed.json', 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'bg-1a2b3c.png') {
        [System.IO.File]::WriteAllText((Join-Path $cache $f), '{}', $utf8)
    }
    Clear-ProfileCache -Confirm:$false 6>$null
    foreach ($f in 'user-settings.json', 'telemetry.owned', 'wt-changes.json', 'installed.json', 'plugins', 'bg-1a2b3c.png') { Assert-True (Test-Path -LiteralPath (Join-Path $cache $f)) "$f was removed" }
    foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json') { Assert-True (-not (Test-Path -LiteralPath (Join-Path $cache $f))) "$f was kept" }
}

Test-Case 'Uninstall-Profile -RemoveUserData removes profile backups; a plain uninstall lists them' {
    foreach ($d in $script:Sandbox.Ps7Dir, $script:Sandbox.Ps5Dir) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        foreach ($f in 'Microsoft.PowerShell_profile.ps1', 'oldprofile.20240101-000000.ps1', 'profile_user.ps1') { [System.IO.File]::WriteAllText((Join-Path $d $f), '# x', $utf8) }
    }
    $out = Uninstall-Profile -Confirm:$false 6>&1 | Out-String
    Assert-True ($out -match 'oldprofile') 'kept profile backups are not reported'
    Assert-True (Test-Path -LiteralPath (Join-Path $script:Sandbox.Ps7Dir 'oldprofile.20240101-000000.ps1')) 'backup removed without -RemoveUserData'
    Uninstall-Profile -RemoveUserData -Confirm:$false 6>$null | Out-Null
    foreach ($d in $script:Sandbox.Ps7Dir, $script:Sandbox.Ps5Dir) {
        Assert-True (@(Get-ChildItem -LiteralPath $d -Filter 'oldprofile*.ps1' -ErrorAction SilentlyContinue).Count -eq 0) "backups left in $d"
    }
}

Test-Case 'Uninstall-Profile never restores a profile.original.ps1 that is a copy of this profile' {
    $d = $script:Sandbox.Ps7Dir
    $installed = '### PowerShell Profile (26zl)' + "`r`n# installed copy"
    foreach ($f in 'Microsoft.PowerShell_profile.ps1', 'profile.original.ps1') { [System.IO.File]::WriteAllText((Join-Path $d $f), $installed, $utf8) }
    $own = Join-Path $d 'oldprofile.20240101-000000.ps1'
    [System.IO.File]::WriteAllText($own, '# my own profile', $utf8)
    Uninstall-Profile -Confirm:$false 6>$null 3>$null | Out-Null
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $d 'Microsoft.PowerShell_profile.ps1'))) 'this profile was left installed'
    Assert-True (Test-Path -LiteralPath $own) 'the backup of the user''s own profile was deleted'
}

Test-Case 'Set-PspInstallState drops a value that is passed empty' {
    $cache = Get-PspCacheDir
    Set-PspInstallState -CacheDir $cache -Version '1.0.0' -Commit ('b' * 40) -Source 'remote'
    Set-PspInstallState -CacheDir $cache -Version '1.0.1' -Commit '' -Source 'local'
    $state = Read-JsonFile (Join-Path $cache 'installed.json')
    Assert-True ($state.version -eq '1.0.1' -and $state.source -eq 'local' -and -not (Test-PspProp $state 'commit')) "stale value kept: $($state | ConvertTo-Json -Compress)"
}

Test-Case 'Write-Utf8FileAtomic writes completely when the caller runs with -WhatIf' {
    $path = Join-Path $script:Sandbox.Work 'atomic.txt'
    [System.IO.File]::WriteAllText($path, 'old', $utf8)
    & { $WhatIfPreference = $true; Write-Utf8FileAtomic -Path $path -Content 'new' -BackupPath "$path.bak" }
    Assert-True ([System.IO.File]::ReadAllText($path) -eq 'new') 'file not written'
    Assert-True (@(Get-ChildItem -LiteralPath $script:Sandbox.Work -Filter '.psp-tmp-*' -Force).Count -eq 0) 'temporary file left behind'
}

Test-Case 'Uninstall-Profile -RemoveFonts uses the font named in the cached terminal-config.json' {
    $fonts = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'
    New-Item -ItemType Directory -Path $fonts -Force | Out-Null
    $font = Join-Path $fonts 'JetBrainsMonoNerdFont-Regular.ttf'
    [System.IO.File]::WriteAllText($font, 'x', $utf8)
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path (Get-PspCacheDir) 'terminal-config.json'), '{ "fontInstall": { "displayName": "JetBrainsMono NF" } }', $utf8)
    $script:PSP.TestFontScopes = @(@{ Name = 'per-user'; Dir = $fonts; Reg = 'HKCU:\SOFTWARE\PowerShellPerfectTest\Fonts-NotPresent'; NeedsAdmin = $false })
    Uninstall-Profile -RemoveFonts -Confirm:$false 6>$null 3>$null | Out-Null
    Assert-True (-not (Test-Path -LiteralPath $font)) 'the font named in terminal-config.json was not removed'
}

Test-Case 'Uninstall-Profile -All stays inside the sandbox font folder' {
    $fonts = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'
    New-Item -ItemType Directory -Path $fonts -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $fonts 'CaskaydiaCoveNerdFont-Regular.ttf'), 'x', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $fonts 'CascadiaCode.ttf'), 'x', $utf8)
    $script:PSP.TestFontScopes = @(@{ Name = 'per-user'; Dir = $fonts; Reg = 'HKCU:\SOFTWARE\PowerShellPerfectTest\Fonts-NotPresent'; NeedsAdmin = $false })
    Uninstall-Profile -All -Confirm:$false 6>$null 3>$null | Out-Null
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $fonts 'CaskaydiaCoveNerdFont-Regular.ttf'))) 'Nerd Font file not removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $fonts 'CascadiaCode.ttf')) 'unrelated font removed'
}

Write-Host '-- Command guards and data handling (F-10, F-19, F-22, F-23, F-24, F-25) --' -ForegroundColor Magenta

Test-Case 'killport refuses protected system processes' {
    $script:Stopped = @()
    function Get-NetTCPConnection { param([int]$LocalPort, $ErrorAction) [PSCustomObject]@{ OwningProcess = 4242 } }
    function Get-Process { param([int]$Id, $ErrorAction) [PSCustomObject]@{ Id = 4242; ProcessName = 'svchost' } }
    function Stop-Process { param([int]$Id, [switch]$Force, $ErrorAction) $script:Stopped += $Id }
    killport 135 -Confirm:$false 6>$null 3>$null
    Assert-True ($script:Stopped.Count -eq 0) 'protected process was stopped'
}

Test-Case 'pkill refuses match-everything patterns' {
    $err = $null
    pkill '*' -ErrorAction SilentlyContinue -ErrorVariable err
    Assert-True ((@($err) -join ' ') -match 'refusing') 'match-all pattern accepted'
}

Test-Case 'Clear-Cache refuses a TEMP that is not a temp folder' {
    $docs = Join-Path $script:Sandbox.Root 'Documents'
    $keep = Join-Path $docs 'keep.txt'
    [System.IO.File]::WriteAllText($keep, 'x', $utf8)
    $env:TEMP = $docs; $env:TMP = $docs
    Clear-Cache -Confirm:$false 6>$null 3>$null
    Assert-True (Test-Path -LiteralPath $keep) 'non-temp folder was emptied'
    $env:TEMP = $script:Sandbox.Temp; $env:TMP = $script:Sandbox.Temp
    $junk = Join-Path $script:Sandbox.Temp 'junk.tmp'
    [System.IO.File]::WriteAllText($junk, 'x', $utf8)
    Clear-Cache -Confirm:$false 6>$null 3>$null
    Assert-True (-not (Test-Path -LiteralPath $junk)) 'temp folder not cleared'
}

Test-Case 'Clear-Cache accepts a Remote Desktop temp folder and keeps going past a file in use' {
    $rdp = Join-Path $script:Sandbox.Temp '2'
    $sub = Join-Path $rdp 'sub'
    New-Item -ItemType Directory -Path $sub -Force | Out-Null
    $locked = Join-Path $sub 'a-locked.txt'
    $other = Join-Path $sub 'b-other.txt'
    foreach ($f in $locked, $other) { [System.IO.File]::WriteAllText($f, 'x', $utf8) }
    $env:TEMP = $rdp; $env:TMP = $rdp
    $stream = [System.IO.File]::Open($locked, 'Open', 'Read', 'None')
    try { Clear-Cache -Confirm:$false 6>$null 3>$null }
    finally { $stream.Dispose(); $env:TEMP = $script:Sandbox.Temp; $env:TMP = $script:Sandbox.Temp }
    Assert-True (-not (Test-Path -LiteralPath $other)) 'files next to a file in use were not removed'
}

Test-Case 'trash refuses when Windows would delete permanently instead of recycling' {
    $file = Join-Path $script:Sandbox.Work 'keep.txt'
    [System.IO.File]::WriteAllText($file, 'x', $utf8)
    function Test-PspRecycleBinSession { $false }
    $err = $null
    # -WhatIf keeps the file safe even if the guard regresses.
    trash $file -WhatIf -ErrorAction SilentlyContinue -ErrorVariable err 6>$null 3>$null
    Assert-True ((@($err) -join ' ') -match 'interactive desktop session') 'no refusal outside an interactive session'
    Assert-True (Test-Path -LiteralPath $file) 'file removed'
}

Test-Case 'extract accepts an archive on a PowerShell drive' {
    $src = Join-Path $script:Sandbox.Work 'p.txt'
    [System.IO.File]::WriteAllText($src, 'zip', $utf8)
    Compress-Archive -LiteralPath $src -DestinationPath (Join-Path $script:Sandbox.Work 'p.zip')
    $dest = Join-Path $script:Sandbox.Work 'pdest'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    New-PSDrive -Name PspUnit -PSProvider FileSystem -Root $script:Sandbox.Work | Out-Null
    Push-Location $dest
    try {
        extract 'PspUnit:\p.zip' 6>$null
        Assert-True (Test-Path -LiteralPath (Join-Path $dest 'p.txt')) 'archive on a PSDrive not extracted'
    }
    finally { Pop-Location; Remove-PSDrive -Name PspUnit -ErrorAction SilentlyContinue }
}

Test-Case 'No variable name in the profile ends in ? (a "$Target?" string names the variable Target?)' {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $bad = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath.Length -gt 1 -and $n.VariablePath.UserPath.EndsWith('?') }, $true))
    Assert-True ($bad.Count -eq 0) "line(s) $(@($bad | ForEach-Object { $_.Extent.StartLineNumber }) -join ', ')"
}

Test-Case 'The Oh My Posh prompt falls back without running the prompt hooks twice' {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $assign = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$Function:prompt' -and $n.Right.Extent.Text -match 'Get-OhMyPoshPromptText' }, $true) | Select-Object -First 1
    $ompPrompt = & ([scriptblock]::Create($assign.Right.Extent.Text))
    $script:StageRuns = 0
    function Invoke-PromptStage { $script:StageRuns++ }
    function Get-OhMyPoshPromptText { $null }
    $text = & $ompPrompt
    Assert-True ($script:StageRuns -eq 1) "prompt hooks ran $($script:StageRuns) times"
    Assert-True ([string]$text -match '\] [\$#] $') "fallback prompt was '$text'"
}

Test-Case 'An Oh My Posh render that times out is stopped with its child processes' {
    $saved = $script:PSP.PromptTimeoutMs
    # Long enough for the child PowerShell to start ping, which then outlives it unless the whole tree is stopped.
    $script:PSP.PromptTimeoutMs = 4000
    $marker = '-n 41 -w 997 127.0.0.1'
    try {
        $shell = (Get-Process -Id $PID).Path
        $result = Invoke-OhMyPoshCommand -ExecutablePath $shell -Arguments @('-NoProfile', '-NonInteractive', '-Command', "ping.exe $marker")
        Assert-True ($null -eq $result) 'a timed-out render returned output'
        Start-Sleep -Milliseconds 500
        $left = @(Get-CimInstance Win32_Process -Filter "Name = 'PING.EXE'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*$marker*" })
        foreach ($p in $left) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Assert-True ($left.Count -eq 0) 'the child process of a timed-out render kept running'
    }
    finally { $script:PSP.PromptTimeoutMs = $saved }
}

Test-Case 'sed keeps the file encoding and writes a .bak (F-19)' {
    $ansi = Join-Path $script:Sandbox.Work 'ansi.txt'
    $code = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
    $enc = [System.Text.Encoding]::GetEncoding($code)
    $word = 'caf' + [char]0xE9
    if ($enc.GetString($enc.GetBytes($word)) -eq $word) {
        [System.IO.File]::WriteAllBytes($ansi, $enc.GetBytes("$word old"))
        sed $ansi 'old' 'new'
        Assert-True ($enc.GetString([System.IO.File]::ReadAllBytes($ansi)) -eq "$word new") 'ANSI text damaged'
    }
    $utf16 = Join-Path $script:Sandbox.Work 'utf16.txt'
    [System.IO.File]::WriteAllText($utf16, "$word old", [System.Text.UnicodeEncoding]::new($false, $true))
    sed $utf16 'old' 'new'
    $bytes = [System.IO.File]::ReadAllBytes($utf16)
    Assert-True ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) -eq "$word new") 'UTF-16 file converted'
    Assert-True (Test-Path -LiteralPath "$utf16.bak") 'no .bak written'
}

Test-Case 'env masks secret-looking values unless -ShowValues (F-23)' {
    $fake = 'gh' + 'p_' + ('A' * 36)
    $env:PSP_UNIT_TOKEN = $fake
    try {
        $masked = env 'PSP_UNIT_TOKEN' | Out-String
        $shown = env 'PSP_UNIT_TOKEN' -ShowValues | Out-String
        Assert-True ($masked -notmatch [regex]::Escape($fake) -and $masked -match '\*{8}') 'value not masked'
        Assert-True ($shown -match [regex]::Escape($fake)) '-ShowValues did not reveal the value'
    }
    finally { Remove-Item env:PSP_UNIT_TOKEN -ErrorAction SilentlyContinue }
    foreach ($name in 'DB_PASS', 'MYSQL_PWD', 'AZURE_STORAGE_ACCOUNT_KEY', 'SQL_CONNECTION_STRING', 'GPG_PASSPHRASE') {
        Assert-True (Test-PspSensitiveVariable -Name $name -Value 'x') "$name not treated as secret"
    }
    $key = 'A' * 40
    foreach ($value in "Server=db;User Id=app;Password=$key", "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=$key", "https://a.blob.core.windows.net/c?sv=2022&sig=$key") {
        Assert-True (Test-PspSensitiveVariable -Name 'PSP_UNIT_VALUE' -Value $value) "value not treated as secret: $($value.Substring(0, 12))..."
    }
    foreach ($name in 'PATH', 'PASSAGE_DIR', 'COMPASS_HOME') { Assert-True (-not (Test-PspSensitiveVariable -Name $name -Value 'C:\x')) "$name masked" }
}

Test-Case 'Format-PspTlsErrors names host and chain problems (F-22)' {
    $both = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch -bor [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
    $text = Format-PspTlsErrors -Errors $both -Domain 'example.com'
    Assert-True ($text -match 'name does not match example.com' -and $text -match 'chain not trusted') "unexpected: $text"
    Assert-True ((Format-PspTlsErrors -Errors ([System.Net.Security.SslPolicyErrors]::None) -Domain 'x') -eq '') 'clean certificate reported problems'
}

Test-Case 'extract refuses to overwrite existing files without -Force (F-24)' {
    $src = Join-Path $script:Sandbox.Work 'a.txt'
    [System.IO.File]::WriteAllText($src, 'from-zip', $utf8)
    $zip = Join-Path $script:Sandbox.Work 'a.zip'
    Compress-Archive -LiteralPath $src -DestinationPath $zip
    $dest = Join-Path $script:Sandbox.Work 'dest'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dest 'a.txt'), 'mine', $utf8)
    Push-Location $dest
    try {
        $err = $null
        extract $zip -ErrorAction SilentlyContinue -ErrorVariable err 6>$null
        Assert-True ((@($err) -join ' ') -match 'already exist' -and [System.IO.File]::ReadAllText((Join-Path $dest 'a.txt')) -eq 'mine') 'existing file overwritten'
        extract $zip -Force 6>$null
        Assert-True ([System.IO.File]::ReadAllText((Join-Path $dest 'a.txt')) -eq 'from-zip') '-Force did not overwrite'
    }
    finally { Pop-Location }
}

Test-Case 'Copy-SshKey remote script appends safely and skips a key that is present (F-24)' {
    $sh = @((Join-Path $env:ProgramFiles 'Git\bin\sh.exe'), (Join-Path $env:ProgramFiles 'Git\usr\bin\sh.exe')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $sh) { Write-Host '        (Git sh.exe not found; skipped)' -ForegroundColor DarkGray; return }
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Copy-SshKey' }, $true) | Select-Object -First 1
    $assign = $fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$remoteScript' }, $true) | Select-Object -First 1
    $remoteScript = $assign.Right.Expression.Value
    $sshHome = Join-Path $script:Sandbox.Work 'home'
    New-Item -ItemType Directory -Path (Join-Path $sshHome '.ssh') -Force | Out-Null
    $auth = Join-Path $sshHome '.ssh\authorized_keys'
    [System.IO.File]::WriteAllText($auth, 'ssh-ed25519 AAAAexisting old@host', $utf8)
    $savedHome = $env:HOME
    $env:HOME = $sshHome
    try {
        $null = 'ssh-ed25519 AAAAnewkey me@pc' | & $sh -c $remoteScript
        $lines = @([System.IO.File]::ReadAllLines($auth) | Where-Object { $_ })
        Assert-True ($lines.Count -eq 2 -and $lines[0] -eq 'ssh-ed25519 AAAAexisting old@host' -and $lines[1] -eq 'ssh-ed25519 AAAAnewkey me@pc') "unexpected authorized_keys: $($lines -join ' | ')"
        $again = @('ssh-ed25519 AAAAnewkey me@pc' | & $sh -c $remoteScript)
        Assert-True ($again -contains 'PSP_KEY_ALREADY_PRESENT') 'present key not detected'
        Assert-True (@([System.IO.File]::ReadAllLines($auth) | Where-Object { $_ }).Count -eq 2) 'key appended twice'
    }
    finally { $env:HOME = $savedHome }
}

Test-Case 'NO_COLOR drops colors from Write-PspHost and Show-Help (F-25)' {
    $script:HostCalls = @()
    function Write-Host { param([object]$Object, [System.ConsoleColor]$ForegroundColor, [switch]$NoNewline, $BackgroundColor, $Separator) $script:HostCalls += , @($PSBoundParameters.Keys) }
    $env:NO_COLOR = '1'
    Write-PspHost 'x' -ForegroundColor Red
    Assert-True (-not ($script:HostCalls[0] -contains 'ForegroundColor')) 'color passed despite NO_COLOR'
    $env:NO_COLOR = $null
    Write-PspHost 'x' -ForegroundColor Red
    Assert-True ($script:HostCalls[1] -contains 'ForegroundColor') 'color dropped without NO_COLOR'
    Remove-Item function:Write-Host
    $env:NO_COLOR = '1'
    $help = Show-Help 6>&1 | Out-String
    Assert-True ($help -notmatch [char]27 -and $help -match 'version \d+\.\d+\.\d+') 'Show-Help printed escape codes or no version'
}

$script:Stopwatch.Stop()
Write-Host ''
$color = if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
Write-Host ("  {0} passed, {1} failed in {2:N1}s" -f $script:Passed, $script:Failed, $script:Stopwatch.Elapsed.TotalSeconds) -ForegroundColor $color
exit ([int]($script:Failed -gt 0))
