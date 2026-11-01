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
            'Start-InstallWizard', 'Select-WizardItem', 'Read-WizardYesNo', 'Select-PreferredEditor', 'Get-OmpThemeList', 'Test-TelemetryOptOutSet',
            'Install-NerdFonts'))) {
    . ([scriptblock]::Create($definition))
}
$script:IsElevated = $false
foreach ($variable in '$script:CuratedSchemes', '$script:CuratedFonts', '$EditorCandidates', '$script:OmpThemesRef', '$script:PinnedOmpThemes') {
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable $variable)))
}

Write-Host '-- JSON handling --' -ForegroundColor Magenta

Test-Case 'ConvertFrom-JsonC removes comments and trailing commas but never touches strings' {
    $q = [char]34
    $text = "{`n  // line comment`n  ${q}url${q}: ${q}https://example.com/a//b${q}, /* block */`n  ${q}quote${q}: ${q}say \${q}hi\${q} // not a comment${q},`n  ${q}list${q}: [1, 2, 3,],`n  ${q}nested${q}: { ${q}k${q}: ${q}v${q}, },`n}"
    $o = ConvertFrom-JsonC -Text $text
    Assert-True ($o.url -eq 'https://example.com/a//b') 'a // inside a string was treated as a comment'
    Assert-True ($o.quote -eq 'say "hi" // not a comment') 'an escaped quote ended the string early'
    Assert-True (@($o.list).Count -eq 3) 'trailing comma in an array'
    Assert-True ($o.nested.k -eq 'v') 'trailing comma in an object'
}

Test-Case 'ConvertFrom-JsonC returns the same result for plain JSON and for JSONC with comments and trailing commas' {
    $plain = '{ "theme": { "name": "pure", "url": "https://raw.githubusercontent.com/a//b.omp.json" }, "list": [1, 2], "one": [{ "k": "v" }] }'
    $jsonc = "{`n  // comment`n  `"theme`": { `"name`": `"pure`", /* inline */ `"url`": `"https://raw.githubusercontent.com/a//b.omp.json`", },`n  `"list`": [1, 2,],`n  `"one`": [{ `"k`": `"v`" }],`n}"
    $a = ConvertFrom-JsonC -Text $plain
    $b = ConvertFrom-JsonC -Text $jsonc
    Assert-True ((ConvertTo-PspCanonicalJson $a) -eq (ConvertTo-PspCanonicalJson $b)) "plain: $(ConvertTo-PspCanonicalJson $a) jsonc: $(ConvertTo-PspCanonicalJson $b)"
    Assert-True ($null -eq (ConvertFrom-JsonC -Text '// only a comment')) 'a comment-only text did not parse as empty'
}

Test-Case 'Read-JsonFile reads UTF-8 with and without BOM on both editions' {
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
    Assert-True ($keys -contains 'ctrl+shift+t') "unexpected keys: $($keys -join ', ')"
    # Ctrl+A belongs to the shell (beginning of line in bash, tmux prefix), so the shipped config does not bind it.
    Assert-True ($keys -notcontains 'ctrl+a') 'terminal-config.json binds ctrl+a in Windows Terminal again'
    Assert-True (-not (Test-PspProp $theme.theme 'sha256')) 'pinned hash kept for a user-chosen theme URL'
}

Write-Host '-- Windows Terminal changes --' -ForegroundColor Magenta

Test-Case 'Update/Undo keep later user edits and revert only what the profile changed' {
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

Test-Case 'Uninstall-Profile reverts every Windows Terminal variant' {
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

Test-Case 'Uninstall-Profile without a change record restores the oldest backup and keeps the current file' {
    $path = New-WtSettings -Json '{"profiles":{"defaults":{"opacity":75}}}'
    [System.IO.File]::WriteAllText("$path.20240101-000000.bak", '{"profiles":{"defaults":{"opacity":88}}}', $utf8)
    (Get-Item -LiteralPath "$path.20240101-000000.bak").LastWriteTime = (Get-Date).AddDays(-10)
    [System.IO.File]::WriteAllText("$path.20240601-000000.bak", '{"profiles":{"defaults":{"opacity":60}}}', $utf8)
    Uninstall-Profile -Confirm:$false 6>$null | Out-Null
    Assert-True ((Read-JsonFile $path).profiles.defaults.opacity -eq 88) 'did not restore the oldest (pre-install) backup'
    Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $path) -Filter 'settings.json.pre-uninstall-*.json').Count -eq 1) 'current settings were not kept'
}

Test-Case 'windowsTerminal.manage = false leaves settings.json alone in uninstall and Set-TerminalBackground' {
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

Write-Host '-- Trusted .psprc.ps1 --' -ForegroundColor Magenta

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

Write-Host '-- Update-Profile and setup.ps1 verification --' -ForegroundColor Magenta

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
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable '$script:OptionalSharedFunctionNames')))
    # Optional helpers are loaded whenever the profile defines them, which the current one does.
    $shared = @($script:SharedFunctionNames) + @($script:OptionalSharedFunctionNames)
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

Test-Case 'setup.ps1 -LocalRepo -CiMode installs into the sandbox; -WhatIf changes nothing' {
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
    Assert-True ($out -notmatch 'Terminal-Icons') 'Terminal-Icons touched in CI mode'
}

Write-Host '-- Wizard input --' -ForegroundColor Magenta

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
    # 'Theme' lost its answer, so it is asked again; 'Bogus' is not a step.
    Assert-True (@($v.CompletedSteps).Count -eq 0) "a step without a valid answer, or an unknown step, was kept: $($v.CompletedSteps -join ', ')"
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

Test-Case 'Install-OhMyPoshTheme rejects a theme whose hash differs and invalid names' {
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

Write-Host '-- Cache, uninstall leftovers and state --' -ForegroundColor Magenta

Test-Case 'Clear-ProfileCache keeps settings, state and theme files' {
    $cache = Get-PspCacheDir
    New-Item -ItemType Directory -Path (Join-Path $cache 'plugins') -Force | Out-Null
    $files = 'user-settings.json', 'telemetry.owned', 'wt-changes.json', 'installed.json', 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'pure.omp.json', 'omp-theme-fast.json', 'omp-secondary-prompt.txt', 'bg-1a2b3c.png'
    foreach ($f in $files) { [System.IO.File]::WriteAllText((Join-Path $cache $f), '{}', $utf8) }
    Clear-ProfileCache -Confirm:$false 6>$null
    # Only Update-Profile or setup.ps1 can restore theme.json, terminal-config.json and the theme, so they are not caches.
    foreach ($f in 'user-settings.json', 'telemetry.owned', 'wt-changes.json', 'installed.json', 'plugins', 'bg-1a2b3c.png', 'theme.json', 'terminal-config.json', 'pure.omp.json') { Assert-True (Test-Path -LiteralPath (Join-Path $cache $f)) "$f was removed" }
    foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'omp-theme-fast.json', 'omp-secondary-prompt.txt') { Assert-True (-not (Test-Path -LiteralPath (Join-Path $cache $f))) "$f was kept" }
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

Write-Host '-- Command guards and data handling --' -ForegroundColor Magenta

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

Test-Case 'No line comment sits right under a help block, where Get-Help would add it to the synopsis' {
    $text = [System.IO.File]::ReadAllText($profilePath)
    $hits = @([regex]::Matches($text, '(?m)^[ \t]*#>[ \t]*\r?\n[ \t]*#(?!>)') | ForEach-Object { $text.Substring(0, $_.Index).Split("`n").Count + 1 })
    Assert-True ($hits.Count -eq 0) "line(s) $($hits -join ', ')"
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
    # The child writes this file right before it starts ping, so a child too slow to reach ping fails the test instead of passing it.
    $started = Join-Path $script:Sandbox.Work 'ping-started.txt'
    try {
        $shell = (Get-Process -Id $PID).Path
        $result = Invoke-OhMyPoshCommand -ExecutablePath $shell -Arguments @('-NoProfile', '-NonInteractive', '-Command', "[System.IO.File]::WriteAllText('$started', 'x'); ping.exe $marker")
        Assert-True ([System.IO.File]::Exists($started)) 'the child never reached ping before the timeout, so the tree kill was not exercised'
        Assert-True ($null -eq $result) 'a timed-out render returned output'
        Start-Sleep -Milliseconds 500
        $left = @(Get-CimInstance Win32_Process -Filter "Name = 'PING.EXE'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*$marker*" })
        foreach ($p in $left) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Assert-True ($left.Count -eq 0) 'the child process of a timed-out render kept running'
    }
    finally { $script:PSP.PromptTimeoutMs = $saved }
}

Test-Case 'sed keeps the file encoding and writes a .bak' {
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

Test-Case 'env masks secret-looking values unless -ShowValues' {
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

Test-Case 'Format-PspTlsErrors names host and chain problems' {
    $both = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch -bor [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
    $text = Format-PspTlsErrors -Errors $both -Domain 'example.com'
    Assert-True ($text -match 'name does not match example.com' -and $text -match 'chain not trusted') "unexpected: $text"
    Assert-True ((Format-PspTlsErrors -Errors ([System.Net.Security.SslPolicyErrors]::None) -Domain 'x') -eq '') 'clean certificate reported problems'
}

Test-Case 'extract refuses to overwrite existing files without -Force' {
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

Test-Case 'Copy-SshKey remote script appends safely and skips a key that is present' {
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

Test-Case 'NO_COLOR drops colors from Write-PspHost and Show-Help' {
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

Write-Host '-- Startup path, Windows Terminal and command fixes (2026-11) --' -ForegroundColor Magenta

Test-Case 'Find-ProfileExecutable finds a tool on PATH without Get-Command and returns $null for a missing one' {
    $bin = Join-Path $script:Sandbox.Work 'bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $bin 'psp-probe-tool.exe'), '', $utf8)
    $env:PATH = $bin + [System.IO.Path]::PathSeparator + $env:PATH
    Assert-True ((Find-ProfileExecutable -Name 'psp-probe-tool') -eq (Join-Path $bin 'psp-probe-tool.exe')) 'tool on PATH not found'
    Assert-True ($null -eq (Find-ProfileExecutable -Name 'psp-no-such-tool')) 'a missing tool was reported'
}

Test-Case 'ConvertTo-ProfileFastOmpTheme drops the upstream and stash lookups from git segments only' {
    $theme = '{ "blocks": [ { "segments": [ { "type": "git", "properties": { "fetch_upstream_icon": true, "fetch_stash_count": true }, "template": "{{ .UpstreamIcon }}{{ .HEAD }}{{ if gt .StashCount 0 }} S{{ .StashCount }}{{ end }}" }, { "type": "path", "template": "{{ .Path }} {{ .StashCount }}" } ] } ] }'
    $fast = ConvertFrom-Json (ConvertTo-ProfileFastOmpTheme -Json $theme)
    $git = $fast.blocks[0].segments[0]
    Assert-True ($git.properties.fetch_upstream_icon -eq $false) 'upstream icon still fetched'
    Assert-True ($git.template -notmatch 'Upstream|StashCount' -and $git.template -match '\.HEAD') "git template not tuned: $($git.template)"
    Assert-True ($fast.blocks[0].segments[1].template -match 'StashCount') 'a non-git segment was changed'
    Assert-True ($null -eq (ConvertTo-ProfileFastOmpTheme -Json '{ "blocks": [ { "segments": [ { "type": "path", "template": "{{ .Path }}" } ] } ] }')) 'an unchanged theme was rewritten'
}

Test-Case 'Get-PspOmpThemeRisk finds command segments, command-running template functions and extends anywhere' {
    $risky = [ordered]@{
        'command segment'                = '{ "blocks": [ { "segments": [ { "type": "path" }, { "type": "command", "properties": { "command": "whoami" } } ] } ] }'
        'template function cmd'          = '{ "console_title_template": "{{ cmd \"calc\" }}" }'
        'template function readFile'     = '{ "transient_prompt": { "template": "{{ readFile \"C:/secret.txt\" }}" } }'
        'template function getHostByName' = '{ "blocks": [ { "segments": [ { "type": "text", "template": "{{ getHostByName (printf \"%s.example\" .UserName) }}" } ] } ] }'
        'extends another config'         = '{ "version": 3, "extends": "./base.omp.json" }'
    }
    foreach ($reason in $risky.Keys) {
        $found = Get-PspOmpThemeRisk -Theme (ConvertFrom-JsonC -Text $risky[$reason])
        Assert-True (@($found) -contains $reason) "not found: $reason (got $($found -join ', '))"
    }
    $safe = ConvertFrom-JsonC -Text '{ "blocks": [ { "segments": [ { "type": "git", "template": "{{ .HEAD }} {{ .Env.USERNAME }}" } ] } ], "tooltips": [] }'
    Assert-True ((Get-PspOmpThemeRisk -Theme $safe).Count -eq 0) 'a theme with only fields such as .Env was flagged'
    Assert-True ((Get-PspOmpThemeRisk -Theme $null).Count -eq 0) 'a missing theme was flagged'
}

Test-Case 'Install-OhMyPoshTheme refuses a theme that can run commands unless allowed' {
    Install-DownloadStub
    $global:PspStubTheme = '{ "blocks": [ { "segments": [ { "type": "command", "properties": { "command": "calc.exe" } } ] } ] }'
    try {
        $url = Get-OmpThemeUrl -Name 'pure'
        # The width keeps Windows PowerShell from wrapping the message at the console width.
        $out = Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url 6>&1 | Out-String -Width 4096
        Assert-True (-not (Test-Path -LiteralPath (Join-Path (Get-PspCacheDir) 'pure.omp.json'))) 'a theme with a command segment was installed'
        Assert-True ($out -match 'allowCommands') "the refusal does not name the opt-in: $out"
        Assert-True (Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url -AllowCommands 6>$null) 'an allowed theme was refused'
        # An existing file with a command segment is not kept as valid without the opt-in.
        Assert-True (-not (Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url 6>$null)) 'the existing theme with a command segment was accepted'
        # A template that runs a program is refused as well.
        Remove-Item -LiteralPath (Join-Path (Get-PspCacheDir) 'pure.omp.json') -Force
        $global:PspStubTheme = '{ "blocks": [ { "segments": [ { "type": "text", "template": "{{ cmd \"calc.exe\" }}" } ] } ] }'
        Assert-True (-not (Install-OhMyPoshTheme -ThemeName 'pure' -ThemeUrl $url 6>$null)) 'a theme whose template runs cmd was installed'
    }
    finally { $global:PspStubTheme = $null }
}

Test-Case 'Get-PspExecutableVersion reads the version resource or asks the program; Test-PspOmpVersionSafe compares with the minimum' {
    $cmdVersion = Get-PspExecutableVersion -Path (Join-Path ([Environment]::SystemDirectory) 'cmd.exe')
    Assert-True ($cmdVersion -is [version] -and $cmdVersion.Major -ge 6) "cmd.exe version: $cmdVersion"
    $fake = Join-Path $script:Sandbox.Work 'omp.cmd'
    [System.IO.File]::WriteAllText($fake, "@echo oh-my-posh v29.0.4`r`n", $utf8)
    Assert-True ($null -eq (Get-PspExecutableVersion -Path $fake)) 'a file without a version resource returned a version'
    Assert-True ((Get-PspExecutableVersion -Path $fake -VersionArgument 'version') -eq [version]'29.0.4') 'the version the program printed was not read'
    Assert-True ([version](Get-PspComponentPins).OhMyPoshMinimum -le [version](Get-PspComponentPins).OhMyPosh) 'the pinned portable build is older than the minimum'
    function Get-PspExecutableVersion { param($Path, $VersionArgument) $null = $Path, $VersionArgument; $script:StubVersion }
    $script:StubVersion = [version]'29.35.0'
    Assert-True (-not (Test-PspOmpVersionSafe -Path 'x')) '29.35.0 was accepted'
    $script:StubVersion = [version]'29.35.1'
    Assert-True (Test-PspOmpVersionSafe -Path 'x') '29.35.1 was refused'
    $script:StubVersion = $null
    Assert-True (Test-PspOmpVersionSafe -Path 'x') 'a build whose version cannot be read was refused'
}

Test-Case 'Oh My Posh older than the minimum never renders: the managed portable build takes over, or the plain prompt stays' {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $block = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$script:PSP.IsInteractive' -and $n.Clauses[0].Item2.Extent.Text -match '_pspOmpExecutablePath = Get-OhMyPoshExecutablePath' }, $true) | Select-Object -First 1
    Assert-True ($null -ne $block) 'the Oh My Posh init block was not found'
    $init = [scriptblock]::Create($block.Extent.Text)
    $cacheDir = Get-PspCacheDir
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $cacheDir 'unit.omp.json'), '{ "blocks": [ { "type": "prompt", "segments": [ { "type": "path", "template": "{{ .Path }}" } ] } ] }', $utf8)
    $oldExe = Join-Path $script:Sandbox.Work 'old\oh-my-posh.exe'
    $portableExe = Get-OhMyPoshPortablePath
    foreach ($p in $oldExe, $portableExe) {
        New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
        [System.IO.File]::WriteAllText($p, 'stub', $utf8)
    }
    $_pspThemeConfig = [pscustomobject]@{ theme = [pscustomobject]@{ name = 'unit' } }
    $_pspRlUser = $null
    $script:VersionChecks = [System.Collections.Generic.List[string]]::new()
    function Get-OhMyPoshExecutablePath { $oldExe }
    function Test-PspOmpVersionSafe { param($Path) $script:VersionChecks.Add($Path); $Path -ne $oldExe }
    function Get-OhMyPoshPromptText { param([string]$Type, $ExecutablePath, $ConfigPath, [switch]$Prefetch) $null = $ExecutablePath, $ConfigPath, $Prefetch; if ($Type -eq 'secondary') { '>> ' } }
    function Set-PSReadLineOption { }
    $envNames = 'VIRTUAL_ENV_DISABLE_PROMPT', 'PYENV_VIRTUALENV_DISABLE_PROMPT', 'POWERLINE_COMMAND', 'POSH_SHELL', 'POSH_SHELL_VERSION', 'CONDA_PROMPT_MODIFIER'
    $savedEnv = @{}
    foreach ($n in $envNames) { $savedEnv[$n] = [Environment]::GetEnvironmentVariable($n) }
    $savedInteractive = $script:PSP.IsInteractive
    $script:PSP.IsInteractive = $true
    $script:OhMyPoshExecutablePath = $null
    try {
        $warnings = @(& $init 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        Assert-True ($script:OhMyPoshExecutablePath -eq $portableExe) "rendered with '$($script:OhMyPoshExecutablePath)'"
        Assert-True ($warnings.Count -eq 0) "warnings: $($warnings -join '; ')"
        $cache = [System.IO.File]::ReadAllText((Join-Path $cacheDir 'omp-secondary-prompt.txt'))
        Assert-True ($cache.Contains('|' + $portableExe + '|') -and $cache.Contains('|ompMinimum=')) 'the cache key does not name the portable build and the minimum'

        # The next start checks the old binary once and then finds the cache written for the portable build.
        $script:VersionChecks.Clear()
        $script:OhMyPoshExecutablePath = $null
        $null = & $init 3>&1
        Assert-True ($script:OhMyPoshExecutablePath -eq $portableExe -and $script:VersionChecks.Count -eq 2) "version checks: $($script:VersionChecks -join ', ')"

        # Without a safe portable build the old binary is not used and only the version warning is shown.
        Remove-Item -LiteralPath $portableExe -Force
        Remove-Item -LiteralPath (Join-Path $cacheDir 'omp-secondary-prompt.txt') -Force
        $script:OhMyPoshExecutablePath = $null
        $warnings = @(& $init 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        Assert-True ($null -eq $script:OhMyPoshExecutablePath) 'a build older than the minimum rendered the prompt'
        Assert-True ($warnings.Count -eq 1 -and [string]$warnings[0] -match 'CVE-2026-73505') "warnings: $($warnings -join '; ')"
    }
    finally {
        $script:PSP.IsInteractive = $savedInteractive
        $script:OhMyPoshExecutablePath = $null
        $script:OhMyPoshConfigPath = $null
        $script:OhMyPoshPromptPrefetch = $null
        foreach ($n in $envNames) { [Environment]::SetEnvironmentVariable($n, $savedEnv[$n]) }
    }
}

Test-Case 'Install-OhMyPoshPortable keeps a newer managed build and never installs a download whose hash differs' {
    $target = Get-OhMyPoshPortablePath
    New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
    [System.IO.File]::WriteAllText($target, 'installed', $utf8)
    [System.IO.File]::WriteAllText((Join-Path (Split-Path $target) 'psp-managed.txt'), "v99.0.0`n", $utf8)
    $script:DownloadCalls = 0
    function Invoke-DownloadWithRetry { param($Uri, $OutFile, $TimeoutSec) $null = $Uri, $TimeoutSec; $script:DownloadCalls++; [System.IO.File]::WriteAllText($OutFile, 'not the pinned build', [System.Text.UTF8Encoding]::new($false)) }
    function Get-PspExecutableVersion { param($Path, $VersionArgument) $null = $Path, $VersionArgument; $script:StubVersion }
    $script:StubVersion = [version]'99.0.0'
    $result = Install-OhMyPoshPortable -Confirm:$false 6>$null
    Assert-True ($result -eq $target -and $script:DownloadCalls -eq 0) 'a managed build newer than the pin was replaced'
    $script:StubVersion = [version]'30.0.0'
    $result = Install-OhMyPoshPortable -Confirm:$false 3>$null 6>$null
    Assert-True ($null -eq $result -and $script:DownloadCalls -eq 1) "a download whose hash differs was accepted: $result"
    Assert-True ([System.IO.File]::ReadAllText($target) -eq 'installed') 'the installed build was replaced by a download whose hash differs'
}

Test-Case 'Retired keybindings are reverted, recorded or tagged by an earlier version; user bindings stay' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": { "defaults": {}, "list": [] }, "actions": [ { "command": "unfocusPane", "id": "User.mine" } ], "keybindings": [ { "id": "User.mine", "keys": "ctrl+a" } ] }'
    $ctrlA = @([PSCustomObject]@{ keys = 'ctrl+a'; command = 'selectAll' })
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Keybindings $ctrlA -Confirm:$false
    Assert-True (@((Read-JsonFile $path).keybindings | Where-Object { $_.id -eq 'User.profile.ctrla' }).Count -eq 1) 'binding not applied'
    # A run without -Keybindings (Set-TerminalBackground) keeps it.
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Defaults ([PSCustomObject]@{ opacity = 80 }) -Confirm:$false
    Assert-True (@((Read-JsonFile $path).keybindings | Where-Object { $_.id -eq 'User.profile.ctrla' }).Count -eq 1) 'binding removed by a run that did not sync keybindings'
    # The configuration no longer lists ctrl+a: the user's own binding comes back and the record is dropped.
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Keybindings @() -Confirm:$false
    $wt = Read-JsonFile $path
    Assert-True (@($wt.keybindings | Where-Object { $_.keys -eq 'ctrl+a' -and $_.id -eq 'User.mine' }).Count -eq 1) "the user's ctrl+a binding was not restored: $(ConvertTo-PspCanonicalJson $wt.keybindings)"
    Assert-True (@($wt.actions | Where-Object { $_.id -eq 'User.profile.ctrla' }).Count -eq 0) 'the retired action was left behind'
    $entry = Get-PspProp (Read-JsonFile $manifest).files $path.ToLowerInvariant()
    Assert-True (-not (Test-PspProp $entry.bindings 'ctrl+a')) 'the retired binding is still recorded'
    # A binding tagged by a version without a change record is removed too; the pre-install copy had none.
    $legacy = New-WtSettings -Json '{ "profiles": { "defaults": {}, "list": [] }, "actions": [ { "command": "selectAll", "id": "User.profile.ctrla" }, { "command": "find", "id": "User.find" } ], "keybindings": [ { "id": "User.profile.ctrla", "keys": "ctrl+a" }, { "id": "User.find", "keys": "ctrl+f" } ] }' -Variant 'Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe'
    [System.IO.File]::WriteAllText("$legacy.psp-original", '{ "profiles": { "defaults": {}, "list": [] }, "actions": [ { "command": "find", "id": "User.find" } ], "keybindings": [ { "id": "User.find", "keys": "ctrl+f" } ] }', $utf8)
    $null = Update-WindowsTerminalSettingsFile -Path $legacy -ManifestPath $manifest -Keybindings @() -Confirm:$false
    $wt = Read-JsonFile $legacy
    Assert-True (@($wt.keybindings | Where-Object { $_.keys -eq 'ctrl+a' }).Count -eq 0 -and @($wt.actions | Where-Object { $_.id -eq 'User.profile.ctrla' }).Count -eq 0) 'the legacy ctrl+a binding was left behind'
    Assert-True (@($wt.keybindings | Where-Object { $_.keys -eq 'ctrl+f' }).Count -eq 1) 'an unrelated user binding was removed'
}

Test-Case '-NoLogo goes right after the executable and only into PowerShell command lines' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $q = [char]34
    $list = @(
        @{ guid = '{p1}'; name = 'Quoted'; commandline = "${q}C:\Program Files\PowerShell\7\pwsh.exe${q} -NoExit" }
        @{ guid = '{p2}'; name = 'Via cmd'; commandline = 'cmd.exe /k pwsh' }
        @{ guid = '{p3}'; name = 'Abbreviated'; commandline = 'pwsh.exe -nol' }
        @{ guid = '{p4}'; name = 'PowerShell 7 Preview'; source = 'Windows.Terminal.PowerShellCore' }
        @{ guid = '{p5}'; name = 'PowerShell'; source = 'Windows.Terminal.PowerShellCore' }
        @{ guid = '{p6}'; name = 'Windows PowerShell'; commandline = '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe' }
    )
    $path = New-WtSettings -Json (ConvertTo-Json -InputObject ([PSCustomObject]@{ profiles = [PSCustomObject]@{ defaults = [PSCustomObject]@{}; list = $list } }) -Depth 5)
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -NoLogo -Confirm:$false
    $byName = @{}
    foreach ($p in @((Read-JsonFile $path).profiles.list)) { $byName[$p.name] = [string](Get-PspProp $p 'commandline') }
    Assert-True ($byName['Quoted'] -eq "${q}C:\Program Files\PowerShell\7\pwsh.exe${q} -NoLogo -NoExit") "quoted path: $($byName['Quoted'])"
    Assert-True ($byName['Via cmd'] -eq 'cmd.exe /k pwsh') "another program's command line was changed: $($byName['Via cmd'])"
    Assert-True ($byName['Abbreviated'] -eq 'pwsh.exe -nol') "an abbreviated -NoLogo got a second one: $($byName['Abbreviated'])"
    Assert-True (-not $byName['PowerShell 7 Preview']) "the Preview profile was pointed at pwsh.exe: $($byName['PowerShell 7 Preview'])"
    Assert-True ($byName['PowerShell'] -eq 'pwsh.exe -NoLogo') "the generated PowerShell profile: $($byName['PowerShell'])"
    Assert-True ($byName['Windows PowerShell'] -eq '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo') "Windows PowerShell: $($byName['Windows PowerShell'])"
}

Test-Case 'admin passes every argument to the elevated shell as a quoted literal' {
    $global:PspStartedArgs = $null
    Set-Item -Path 'function:global:Start-Process' -Value { param($FilePath, $Verb, $ArgumentList) $global:PspStartedArgs = @($ArgumentList) -join ' ' }
    admin Write-Output 'a;calc' '-Name:' "it's" -Flag
    $encoded = [regex]::Match([string]$global:PspStartedArgs, '-EncodedCommand\s+"?([A-Za-z0-9+/=]+)').Groups[1].Value
    $command = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    Assert-True ($command -eq "& 'Write-Output' 'a;calc' -Name: 'it''s' -Flag") "unexpected elevated command: $command"
    $global:PspStartedArgs = $null
}

Test-Case 'hb -Force -WhatIf uploads nothing' {
    $file = Join-Path $script:Sandbox.Work 'paste.txt'
    [System.IO.File]::WriteAllText($file, 'secret-ish', $utf8)
    $script:Uploads = 0
    function Invoke-RestMethod { $script:Uploads++ }
    hb $file -Force -WhatIf 6>$null 3>$null
    Assert-True ($script:Uploads -eq 0) 'hb uploaded under -WhatIf'
}

Test-Case 'sed leaves a file without the text untouched and works on PowerShell drives' {
    $file = Join-Path $script:Sandbox.Work 'conf.ini'
    [System.IO.File]::WriteAllText($file, "a=1`r`n", $utf8)
    $stamp = (Get-Item -LiteralPath $file).LastWriteTimeUtc
    Start-Sleep -Milliseconds 30
    sed $file 'missing' 'x' 6>$null
    Assert-True ((Get-Item -LiteralPath $file).LastWriteTimeUtc -eq $stamp -and -not (Test-Path -LiteralPath "$file.bak")) 'a file without the text was rewritten or backed up'
    $null = New-PSDrive -Name PspSed -PSProvider FileSystem -Root $script:Sandbox.Work -Scope Global
    try {
        sed 'PspSed:\conf.ini' 'a=1' 'a=2' 6>$null
        Assert-True ([System.IO.File]::ReadAllText($file) -eq "a=2`r`n" -and (Test-Path -LiteralPath "$file.bak")) 'sed on a PowerShell drive path failed'
    }
    finally { Remove-PSDrive -Name PspSed -Scope Global -ErrorAction SilentlyContinue }
    $ErrorActionPreference = 'Continue'
    $out = sed $script:Sandbox.Work 'a' 'b' 2>&1 | Out-String
    Assert-True ($out -match 'File not found') 'a folder was accepted as a file'
}

Test-Case 'envload skips variables that change how programs run unless -AllowSensitive' {
    $envFile = Join-Path $script:Sandbox.Work '.env'
    [System.IO.File]::WriteAllText($envFile, "PSP_ENV_OK=1`nGIT_SSH_COMMAND=calc.exe`nNODE_OPTIONS=--require ./x.js`nPATH=C:\evil`n", $utf8)
    $savedPath = $env:PATH
    try {
        $warn = envload $envFile 3>&1 6>$null | Out-String
        Assert-True ($env:PSP_ENV_OK -eq '1') 'a plain variable was not loaded'
        Assert-True (-not $env:GIT_SSH_COMMAND -and -not $env:NODE_OPTIONS -and $env:PATH -eq $savedPath) 'a sensitive variable was loaded without -AllowSensitive'
        Assert-True ($warn -match 'GIT_SSH_COMMAND' -and $warn -match 'AllowSensitive') "the skipped names are not reported: $warn"
        envload $envFile -AllowSensitive 3>$null 6>$null
        Assert-True ($env:GIT_SSH_COMMAND -eq 'calc.exe') '-AllowSensitive did not load the variable'
    }
    finally {
        $env:PATH = $savedPath
        foreach ($n in 'PSP_ENV_OK', 'GIT_SSH_COMMAND', 'NODE_OPTIONS') { Remove-Item -LiteralPath "env:$n" -ErrorAction SilentlyContinue }
    }
}

Test-Case 'prettyjson accepts pipeline input and keeps a top-level array an array' {
    $out = '[1, 2]' | prettyjson | Out-String
    Assert-True ($out -notmatch '"value"' -and $out -notmatch '"Count"') "array re-indented as an object: $out"
    $multi = @('{', '  "a": [1,', '2]', '}') | prettyjson | Out-String
    Assert-True ((ConvertFrom-Json $multi).a.Count -eq 2) "multi-line pipeline input failed: $multi"
}

Test-Case 'bak copies a folder next to itself with its contents, also with a trailing separator' {
    $dir = Join-Path $script:Sandbox.Work 'site'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dir 'index.html'), 'hi', $utf8)
    bak ($dir + '\') 6>$null
    $copy = @(Get-ChildItem -LiteralPath $script:Sandbox.Work -Directory -Filter 'site.*.bak')
    Assert-True ($copy.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $copy[0].FullName 'index.html'))) 'folder backup missing or empty'
    Assert-True (@(Get-ChildItem -LiteralPath $dir -Force).Count -eq 1) 'the backup landed inside the folder'
}

Test-Case 'killport, Stop-StuckProcess and Remove-LockedItem never stop this session or system processes' {
    $script:Stopped = @()
    function Get-NetTCPConnection { [PSCustomObject]@{ OwningProcess = $PID; LocalPort = 5000 } }
    function Stop-Process { param($Id) $script:Stopped += $Id }
    killport 5000 -Confirm:$false 3>$null 6>$null
    Stop-StuckProcess -Id $PID -Confirm:$false 3>$null 6>$null
    Assert-True ($script:Stopped.Count -eq 0) "this session was stopped: $($script:Stopped -join ',')"
    $file = Join-Path $script:Sandbox.Work 'locked.bin'
    [System.IO.File]::WriteAllText($file, 'x', $utf8)
    function Remove-Item { throw 'locked' }
    function Find-FileLocker { [PSCustomObject]@{ PID = 4; Name = 'System'; WindowTitle = '' } }
    function Stop-StuckProcess { $script:Stopped += 'stuck' }
    Remove-LockedItem $file -KillSystem -Confirm:$false -ErrorAction SilentlyContinue 3>$null 6>$null
    Assert-True ($script:Stopped.Count -eq 0) 'Remove-LockedItem -KillSystem stopped a system process'
}

Test-Case 'mtr counts a PowerShell 7 TimedOut reply as loss, and firewall and DNS failures are reported as errors' {
    function Test-NetConnection { [PSCustomObject]@{ TraceRoute = @('10.0.0.1') } }
    function Test-Connection { [PSCustomObject]@{ Status = 'TimedOut'; Latency = 0 } }
    $out = mtr example.invalid -Count 2 6>&1 | Out-String
    Assert-True ($out -match '10\.0\.0\.1\s+100%') "a timed-out hop was not counted as loss: $out"
    $saved = $script:PSP.IsAdmin
    $script:PSP.IsAdmin = $true
    try {
        function New-NetFirewallRule { throw 'access denied' }
        $err = $null
        fwallow -Name 'PSP test' -Port 1 -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err 6>$null
        Assert-True ((@($err) -join ' ') -match 'Could not add firewall rule') 'a failed firewall rule was not reported'
    }
    finally { $script:PSP.IsAdmin = $saved }
    function Clear-DnsClientCache { throw 'access denied' }
    $ErrorActionPreference = 'Continue'
    $out = flushdns 2>&1 6>$null | Out-String
    Assert-True ($out -match 'Could not flush') "a failed DNS flush was reported as success: $out"
}

Test-Case 'ConvertTo-NativeArgumentLine keeps an empty argument' {
    Assert-True ((ConvertTo-NativeArgumentLine @('a', '', 'b c')) -eq 'a "" "b c"') "unexpected: $(ConvertTo-NativeArgumentLine @('a', '', 'b c'))"
}

Test-Case 'reload warns unless dot-sourced, and runs the profile either way' {
    New-Item -ItemType Directory -Path (Split-Path $PROFILE) -Force | Out-Null
    [System.IO.File]::WriteAllText($PROFILE, '$global:PspReloadRuns++', $utf8)
    $global:PspReloadRuns = 0
    $warn = reload 3>&1 | Out-String
    Assert-True ($global:PspReloadRuns -eq 1 -and $warn -match '\. reload') "reload did not warn or did not run the profile: $warn"
    $warn = . reload 3>&1 | Out-String
    Assert-True ($global:PspReloadRuns -eq 2 -and [string]::IsNullOrWhiteSpace($warn)) "a dot-sourced reload warned or did not run: $warn"
    Remove-Variable -Name PspReloadRuns -Scope Global -ErrorAction SilentlyContinue
}

Test-Case 'Update-Profile saves profile.original.ps1 before rotation, which keeps only timestamped copies' {
    Install-DownloadStub
    $global:PspStubSums = (@('Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json') | ForEach-Object { '{0}  {1}' -f (Get-CommittedSha256 $_).ToLowerInvariant(), $_ }) -join "`n"
    try {
        $d = $script:Sandbox.Ps7Dir
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), "### PowerShell Profile (26zl)`r`n# older installed copy", $utf8)
        [System.IO.File]::WriteAllText((Join-Path $d 'oldprofile.20240101-000000.ps1'), '# my own profile', $utf8)
        (Get-Item -LiteralPath (Join-Path $d 'oldprofile.20240101-000000.ps1')).LastWriteTime = (Get-Date).AddDays(-30)
        foreach ($i in 1..6) { [System.IO.File]::WriteAllText((Join-Path $d ('oldprofile.2025010{0}-000000.ps1' -f $i)), "### PowerShell Profile (26zl)`r`n# copy $i", $utf8) }
        [System.IO.File]::WriteAllText((Join-Path $d 'oldprofile.keep.ps1'), '# not a timestamped backup', $utf8)
        Update-Profile -Ref v9.9.9 -ErrorAction SilentlyContinue *>&1 | Out-Null
        Assert-True ([System.IO.File]::ReadAllText((Join-Path $d 'profile.original.ps1')).Trim() -eq '# my own profile') 'profile.original.ps1 is not the user''s own profile'
        $stamped = @(Get-ChildItem -LiteralPath $d -Filter 'oldprofile.*.ps1' | Where-Object { $_.Name -match '^oldprofile\.\d{8}-\d{6}\.ps1$' })
        Assert-True ($stamped.Count -eq 5) "expected 5 timestamped backups, found $($stamped.Count)"
        Assert-True (Test-Path -LiteralPath (Join-Path $d 'oldprofile.keep.ps1')) 'a backup without a timestamp was rotated away'
    }
    finally { $global:PspStubSums = $null }
}

Test-Case 'setup.ps1 stops with exit code 2 and installs nothing when the wizard summary is declined' {
    # setup.ps1 runs in its own script scope, so the answers live in a global queue.
    $global:PspWizardQueue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($a in 'y', 'n') { $global:PspWizardQueue.Enqueue($a) }
    function Read-Host { param($Prompt, [switch]$AsSecureString) if ($global:PspWizardQueue.Count -eq 0) { throw "unexpected prompt: $Prompt" }; $global:PspWizardQueue.Dequeue() }
    try { $out = & $setupPath -LocalRepo $repoRoot -CiMode -Wizard *>&1 | Out-String }
    finally { Remove-Variable -Name PspWizardQueue -Scope Global -ErrorAction SilentlyContinue }
    Assert-True ($LASTEXITCODE -eq 2) "exit code $LASTEXITCODE`: $out"
    Assert-True ($out -match 'nothing was installed') 'the cancellation is not reported'
    Assert-True (-not (Test-Path -LiteralPath $PROFILE)) 'the profile was installed after the summary was declined'
}

Test-Case 'Runs of a script or command count as non-interactive unless -NoExit comes first' {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    $loop = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and $n.Extent.Text -match '_pspScriptRun = \$true' }, $true) | Select-Object -First 1
    Assert-True ($null -ne $loop) 'the command-line scan was not found'
    $scan = [scriptblock]::Create('param($a) $_pspArgs = $a; $_pspScriptRun = $false; ' + $loop.Extent.Text + '; $_pspScriptRun')
    $cases = @(
        @{ Args = @('pwsh.exe'); Expected = $false }
        @{ Args = @('pwsh.exe', '-NoLogo', '-WorkingDirectory', 'C:\work'); Expected = $false }
        @{ Args = @('pwsh.exe', '-ex', 'Bypass'); Expected = $false }
        @{ Args = @('pwsh.exe', '-File', 'x.ps1'); Expected = $true }
        @{ Args = @('pwsh.exe', '-c', 'Get-Date'); Expected = $true }
        @{ Args = @('pwsh.exe', '/Command', 'Get-Date'); Expected = $true }
        @{ Args = @('powershell.exe', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', 'ZQBjAGgAbwA='); Expected = $true }
        @{ Args = @('pwsh.exe', '-NoExit', '-Command', 'Get-Date'); Expected = $false }
        @{ Args = @('pwsh.exe', '-noe', '-c', 'Get-Date'); Expected = $false }
        @{ Args = @('pwsh.exe', '-Command', 'Get-Date', '-NoExit'); Expected = $true }
        @{ Args = @('pwsh.exe', '-NoLogo'); Expected = $false }
        @{ Args = @('pwsh.exe', '-e', 'ZQBjAGgAbwA='); Expected = $true }
    )
    foreach ($case in $cases) {
        $result = & $scan $case.Args
        Assert-True ($result -eq $case.Expected) ("{0}: expected {1}, got {2}" -f ($case.Args -join ' '), $case.Expected, $result)
    }
}

Test-Case 'The startup garbage collection pause is skipped when not interactive and ends once, at the first prompt' {
    # This test session is not interactive, so loading the profile reserved nothing.
    Assert-True (-not $script:PspNoGcRegion -and [System.Runtime.GCSettings]::LatencyMode -ne [System.Runtime.GCLatencyMode]::NoGCRegion) 'a non-interactive load held garbage collection off'
    $before = [System.Runtime.GCSettings]::LatencyMode
    $script:PspNoGcRegion = [System.GC]::TryStartNoGCRegion(16MB)
    try {
        Assert-True ($script:PspNoGcRegion -and [System.Runtime.GCSettings]::LatencyMode -eq [System.Runtime.GCLatencyMode]::NoGCRegion) 'the test could not start a no-GC region'
        $null = Get-PspPlainPrompt
        Exit-PspNoGcRegion
        Assert-True ([System.Runtime.GCSettings]::LatencyMode -eq $before -and -not $script:PspNoGcRegion) "the region did not end: $([System.Runtime.GCSettings]::LatencyMode)"
        Exit-PspNoGcRegion
        Assert-True ([System.Runtime.GCSettings]::LatencyMode -eq $before) 'a second call changed the latency mode'
    }
    finally {
        if ([System.Runtime.GCSettings]::LatencyMode -eq [System.Runtime.GCLatencyMode]::NoGCRegion) { [System.GC]::EndNoGCRegion() }
        $script:PspNoGcRegion = $false
    }
}

Test-Case 'The history filter is hooked into PSReadLine and keeps ordinary lines' {
    Import-Module PSReadLine -ErrorAction Stop
    $saved = (Get-PSReadLineOption).AddToHistoryHandler
    try {
        Register-ProfileHistoryHandler
        $handler = (Get-PSReadLineOption).AddToHistoryHandler
        Assert-True ($null -ne $handler) 'no history handler is registered'
        Assert-True ($handler.Invoke('pwnd hunter2') -eq $false) 'a pwnd password reached history'
        Assert-True ($handler.Invoke('$s = ConvertTo-SecureString ''x'' -AsPlainText -Force') -eq $false) 'an -AsPlainText line reached history'
        # PSReadLine 2.2+ answers with its own filter's verdict; 2.0 (Windows PowerShell's built-in copy) has none.
        $kept = [string]$handler.Invoke('Get-ChildItem')
        Assert-True ($kept -in 'True', 'MemoryAndFile') "an ordinary line was not kept: $kept"
    }
    finally { if ($null -ne $saved) { Set-PSReadLineOption -AddToHistoryHandler $saved } }
}

Test-Case 'Keybinding ids keep punctuation keys apart, and a binding dropped from the configuration is reported as pending' {
    $manifest = Join-Path (Get-PspCacheDir) 'wt-changes.json'
    New-Item -ItemType Directory -Path (Get-PspCacheDir) -Force | Out-Null
    $path = New-WtSettings -Json '{ "profiles": { "defaults": {}, "list": [] }, "actions": [], "keybindings": [] }'
    $bindings = @(
        [PSCustomObject]@{ keys = 'ctrl+='; command = [PSCustomObject]@{ action = 'adjustFontSize'; delta = 1 } }
        [PSCustomObject]@{ keys = 'ctrl+-'; command = [PSCustomObject]@{ action = 'adjustFontSize'; delta = -1 } }
        [PSCustomObject]@{ keys = 'ctrl+a'; command = 'selectAll' }
    )
    $null = Update-WindowsTerminalSettingsFile -Path $path -ManifestPath $manifest -Keybindings $bindings -Confirm:$false
    $wt = Read-JsonFile $path
    $ids = @($wt.keybindings | ForEach-Object { $_.id })
    Assert-True ($ids.Count -eq 3 -and @($ids | Select-Object -Unique).Count -eq 3) "ids collide: $($ids -join ', ')"
    Assert-True ($ids -contains 'User.profile.ctrla') 'a binding of letters only changed its id'
    $plusId = ($wt.keybindings | Where-Object { $_.keys -eq 'ctrl+=' }).id
    Assert-True ((@($wt.actions | Where-Object { $_.id -eq $plusId })[0]).command.delta -eq 1) 'ctrl+= runs the command of another binding'
    Assert-True (-not (Test-WtRetiredKeybindingPending -Keybindings $bindings -ManifestPath $manifest)) 'a configured binding counts as retired'
    Assert-True (Test-WtRetiredKeybindingPending -Keybindings @($bindings[0], $bindings[1]) -ManifestPath $manifest) 'a binding dropped from the configuration is not reported'
}

Test-Case 'Update-SessionPathFromRegistry keeps the session entries and adds each missing registry entry once' {
    # The sandbox stubs this function out, so the real one is loaded here.
    . ([scriptblock]::Create((Get-PspFunctionSource -Path $profilePath -Name 'Update-SessionPathFromRegistry')))
    $saved = $env:PATH
    try {
        $machine = @(([string][Environment]::GetEnvironmentVariable('PATH', 'Machine')) -split ';' | Where-Object { $_ })
        $env:PATH = 'C:\psp-session-only;' + $(if ($machine.Count) { $machine[0] } else { '' })
        Update-SessionPathFromRegistry
        $entries = @($env:PATH -split ';' | Where-Object { $_ })
        Assert-True ($entries[0] -eq 'C:\psp-session-only') 'a session-only entry was dropped or moved'
        foreach ($m in $machine) {
            Assert-True (@($entries | Where-Object { $_.TrimEnd('\') -eq $m.TrimEnd('\') }).Count -eq 1) "registry entry missing or repeated: $m"
        }
    }
    finally { $env:PATH = $saved }
}

Test-Case 'lint always passes its own settings, so the analyzed folder cannot load custom rules' {
    $script:LintArgs = $null
    function Get-Module { param([switch]$ListAvailable, $Name) $null = $ListAvailable, $Name; [PSCustomObject]@{ Name = 'PSScriptAnalyzer' } }
    function Import-Module { }
    function Invoke-ScriptAnalyzer { param($Path, [switch]$Recurse, $Settings, [switch]$Fix) $null = $Path, $Recurse, $Fix; $script:LintArgs = @{ Settings = $Settings }; @() }
    lint $script:Sandbox.Work 6>$null | Out-Null
    Assert-True ($null -ne $script:LintArgs -and $script:LintArgs.Settings -is [hashtable]) 'lint ran without -Settings'
    lint $script:Sandbox.Work -Mode CI 6>$null | Out-Null
    Assert-True (@($script:LintArgs.Settings.ExcludeRules) -contains 'PSAvoidUsingWriteHost') 'the CI mode did not pass its rule list'
}

Test-Case 'Quoted literals for the elevated shell also double typographic single quotes' {
    $global:PspStartedArgs = $null
    Set-Item -Path 'function:global:Start-Process' -Value { param($FilePath, $Verb, $ArgumentList) $global:PspStartedArgs = @($ArgumentList) -join ' ' }
    $value = 'a' + [char]0x2019 + '; calc'
    admin Write-Output $value
    $encoded = [regex]::Match([string]$global:PspStartedArgs, '-EncodedCommand\s+"?([A-Za-z0-9+/=]+)').Groups[1].Value
    $command = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    $global:PspStartedArgs = $null
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($command, [ref]$tokens, [ref]$parseErrors)
    $statements = @($ast.EndBlock.Statements)
    Assert-True ($statements.Count -eq 1 -and @($parseErrors).Count -eq 0) "the argument ended the quoted string early: $command"
    $elements = @($statements[0].PipelineElements[0].CommandElements)
    Assert-True ($elements.Count -eq 2 -and $elements[1].Value -eq $value) "the argument arrived changed: $command"
}

Test-Case 'envload also skips build, cloud and tool settings that can run programs' {
    $envFile = Join-Path $script:Sandbox.Work '.env'
    $names = 'KUBECONFIG', 'JAVA_OPTS', 'RUSTC_WRAPPER', 'AWS_CONFIG_FILE', 'GOOGLE_APPLICATION_CREDENTIALS', 'CC', 'LESSOPEN', 'CARGO_HOME', 'DOCKER_HOST'
    [System.IO.File]::WriteAllText($envFile, ((@($names | ForEach-Object { "$_=x" }) + 'PSP_ENV_PLAIN=1') -join "`n"), $utf8)
    $saved = @{}
    foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
    try {
        envload $envFile 3>$null 6>$null
        Assert-True ($env:PSP_ENV_PLAIN -eq '1') 'a plain variable was not loaded'
        foreach ($n in $names) { Assert-True ([Environment]::GetEnvironmentVariable($n) -eq $saved[$n]) "$n was loaded without -AllowSensitive" }
    }
    finally {
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        Remove-Item -LiteralPath 'env:PSP_ENV_PLAIN' -ErrorAction SilentlyContinue
    }
}

Test-Case 'The history filter drops newer token shapes and keeps ordinary lines' {
    # The token shapes are assembled here so the repository secret scan does not match the test itself.
    $lines = @(
        ('$k = ''' + 'sk-' + 'proj-' + ('a' * 24) + '''')
        ('git push https://oauth2:' + 'glpat-' + ('b' * 20) + '@gitlab.example')
        ('az storage blob list --connection-string ''' + 'AccountKey=' + ('c' * 12) + '''')
        ('curl ''https://acct.blob.core.windows.net/c/f?sv=2024&' + 'sig=' + ('d' * 24) + '''')
        ('$env:DB_' + 'PASS = ''x''')
    )
    foreach ($line in $lines) { Assert-True (-not (Test-ProfileHistorySafeLine -Line $line)) "kept in history: $line" }
    Assert-True (Test-ProfileHistorySafeLine -Line 'Get-ChildItem -Path C:\work') 'an ordinary line was dropped'
}

Test-Case 'Uninstall-Profile restores the original once and then leaves a profile that is not this one alone' {
    $d = $script:Sandbox.Ps7Dir
    $main = Join-Path $d 'Microsoft.PowerShell_profile.ps1'
    [System.IO.File]::WriteAllText($main, '### PowerShell Profile (26zl)' + "`r`n# installed copy", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $d 'profile.original.ps1'), '# my own profile', $utf8)
    Uninstall-Profile -Confirm:$false 6>$null 3>$null | Out-Null
    Assert-True ([System.IO.File]::ReadAllText($main) -eq '# my own profile') 'the original profile was not restored'
    [System.IO.File]::WriteAllText($main, '# my own profile, edited', $utf8)
    Uninstall-Profile -Confirm:$false 6>$null 3>$null | Out-Null
    Assert-True ([System.IO.File]::ReadAllText($main) -eq '# my own profile, edited') 'a second uninstall replaced a profile that is not this one'
}

Test-Case 'genpass copies through the clipboard that skips history and writes nothing to the success stream' {
    $script:Copied = $null
    function Set-PspSensitiveClipboard { param($Text) $script:Copied = $Text }
    $out = genpass -Length 24 6>$null
    Assert-True ($null -eq $out) 'genpass wrote the password to the success stream'
    Assert-True (([string]$script:Copied).Length -eq 24) "copied: $([string]$script:Copied)"
}

Test-Case 'Install-OhMyPoshPortable installs only a build signed by the Oh My Posh author' {
    $target = Get-OhMyPoshPortablePath
    function Invoke-DownloadWithRetry { param($Uri, $OutFile, $TimeoutSec) $null = $Uri, $TimeoutSec; [System.IO.File]::WriteAllText($OutFile, 'downloaded build', [System.Text.UTF8Encoding]::new($false)) }
    # The hash check passes, so only the signature decides.
    function Get-FileHash { param($LiteralPath, $Algorithm) $null = $Algorithm; [PSCustomObject]@{ Hash = [string](Get-PspComponentPins).OhMyPoshSha256[[System.IO.Path]::GetFileName($LiteralPath)] } }
    $script:Signature = [PSCustomObject]@{ Status = 'Valid'; SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Someone Else' } }
    function Get-AuthenticodeSignature { param($LiteralPath) $null = $LiteralPath; $script:Signature }
    Assert-True ($null -eq (Install-OhMyPoshPortable -Force -Confirm:$false 3>$null 6>$null) -and -not [System.IO.File]::Exists($target)) 'a build signed by someone else was installed'
    $script:Signature = [PSCustomObject]@{ Status = 'NotSigned'; SignerCertificate = $null }
    Assert-True ($null -eq (Install-OhMyPoshPortable -Force -Confirm:$false 3>$null 6>$null) -and -not [System.IO.File]::Exists($target)) 'an unsigned build was installed'
    $script:Signature = [PSCustomObject]@{ Status = 'Valid'; SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Jan Joris De Dobbeleer, O=Jan Joris De Dobbeleer' } }
    Assert-True ((Install-OhMyPoshPortable -Force -Confirm:$false 6>$null) -eq $target -and [System.IO.File]::ReadAllText($target) -eq 'downloaded build') 'a correctly signed build was not installed'
    Assert-True ([System.IO.File]::Exists((Join-Path (Split-Path $target) 'psp-managed.txt'))) 'the managed marker was not written'
}

Test-Case 'Versions named in README.md and SECURITY.md match the pins' {
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable '$script:NerdFontVersion')))
    $pins = Get-PspComponentPins
    $docs = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'README.md')) + [System.IO.File]::ReadAllText((Join-Path $repoRoot 'SECURITY.md'))
    $expected = @(('v' + $pins.OhMyPosh), $script:OmpThemesRef, ('v' + $script:NerdFontVersion), $pins.OhMyPoshMinimum)
    foreach ($version in $expected) { Assert-True ($docs.Contains($version)) "the docs do not name $version" }
    # Every release-shaped Oh My Posh or Nerd Fonts version in the docs is one of the pinned ones.
    $named = @([regex]::Matches($docs, '(?<![\d.])v?\d+\.\d+\.\d+(?![\d.])') | ForEach-Object { $_.Value.TrimStart('v') } | Where-Object { $_ -match '^(29|3[0-9])\.' -or $_ -match '^3\.\d+\.\d+$' } | Select-Object -Unique)
    $allowed = @($expected | ForEach-Object { $_.TrimStart('v') }) + '1.0.0'
    $stale = @($named | Where-Object { $allowed -notcontains $_ })
    Assert-True ($stale.Count -eq 0) "versions in the docs that match no pin: $($stale -join ', ')"
}

Test-Case 'Install-NerdFonts never extracts an archive whose hash differs' {
    $script:Extracted = $false
    function Invoke-DownloadWithRetry { param($Uri, $OutFile, $TimeoutSec, $MaxAttempts) $null = $Uri, $TimeoutSec, $MaxAttempts; [System.IO.File]::WriteAllText($OutFile, 'not the pinned archive', [System.Text.UTF8Encoding]::new($false)) }
    function Expand-Archive { $script:Extracted = $true }
    $ok = Install-NerdFonts -FontName 'PspTestFont' -FontDisplayName 'PspTestFont NF' -Version '3.4.0' -Sha256 ('A' * 64) -Confirm:$false 6>$null
    Assert-True (-not $ok -and -not $script:Extracted) 'an archive whose hash differs was installed'
}

Test-Case 'setup.ps1 checks local release files against the SHA256SUMS.txt next to them' {
    $dir = Join-Path $script:Sandbox.Work 'release'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $bundle = 'Microsoft.PowerShell_profile.ps1', 'theme.json', 'terminal-config.json'
    foreach ($f in @('setup.ps1') + $bundle) { Copy-Item -LiteralPath (Join-Path $repoRoot $f) -Destination $dir }
    $sums = @(foreach ($f in $bundle) { '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $dir $f) -Algorithm SHA256).Hash.ToLowerInvariant(), $f })
    [System.IO.File]::WriteAllText((Join-Path $dir 'SHA256SUMS.txt'), ($sums -join "`n"), $utf8)
    $out = & (Join-Path $dir 'setup.ps1') -LocalRepo $dir -CiMode -SkipWizard -WhatIf *>&1 | Out-String -Width 4096
    Assert-True ($out -match 'matches the SHA256SUMS.txt in') "matching files were not reported as verified: $out"
    # One wrong line stops setup before anything is installed.
    $sums[0] = ('0' * 64) + '  Microsoft.PowerShell_profile.ps1'
    [System.IO.File]::WriteAllText((Join-Path $dir 'SHA256SUMS.txt'), ($sums -join "`n"), $utf8)
    $out = & (Join-Path $dir 'setup.ps1') -LocalRepo $dir -CiMode -SkipWizard *>&1 | Out-String -Width 4096
    Assert-True ($LASTEXITCODE -ne 0 -and $out -match 'does not match the SHA256SUMS.txt') "a file that differs from SHA256SUMS.txt was accepted: $out"
    Assert-True (-not (Test-Path -LiteralPath $PROFILE)) 'the profile was installed from files that failed the check'
}

$script:Stopwatch.Stop()
Write-Host ''
$color = if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
Write-Host ("  {0} passed, {1} failed in {2:N1}s" -f $script:Passed, $script:Failed, $script:Stopwatch.Elapsed.TotalSeconds) -ForegroundColor $color
exit ([int]($script:Failed -gt 0))
