# Shared helpers for the test scripts: disposable sandboxes that redirect every location the profile and setup.ps1
# write to, fail-closed stubs for commands that would change the machine, and a guard against elevated runs.
# Dot-source this file: . (Join-Path $PSScriptRoot 'lib\Sandbox.ps1')

# Return $true when the current process runs elevated.
function Test-PspTestElevated {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { $false }
}

# Stop unless the run is unelevated or the caller opted in; machine-wide scopes (fonts, HKLM, firewall) are writable only when elevated.
function Assert-PspTestSafety {
    param([switch]$AllowElevated, [string]$ScriptName = 'This test script')
    if ((Test-PspTestElevated) -and -not $AllowElevated) {
        throw "$ScriptName refuses to run in an elevated shell: a test mistake could then change machine-wide fonts, registry or firewall settings. Run it from a normal shell, or pass -AllowElevated inside a disposable VM."
    }
}

# Create a disposable sandbox folder tree and return its paths.
function New-PspSandbox {
    param([string]$Name = 'sandbox', [string]$Root = [System.IO.Path]::GetTempPath())
    $base = Join-Path $Root ('psp-test-{0}-{1}' -f $Name, [System.IO.Path]::GetRandomFileName())
    $sandbox = [PSCustomObject]@{
        Root   = $base
        Local  = Join-Path $base 'Local'
        Temp   = Join-Path $base 'Temp'
        Docs   = Join-Path $base 'Documents'
        Ps7Dir = Join-Path $base 'Documents\PowerShell'
        Ps5Dir = Join-Path $base 'Documents\WindowsPowerShell'
        Cache  = Join-Path $base 'Local\PowerShellProfile'
        WtDir  = Join-Path $base 'Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
        Fonts  = Join-Path $base 'Fonts'
        Work   = Join-Path $base 'Work'
        Bin    = Join-Path $base 'bin'
    }
    foreach ($dir in $sandbox.Local, $sandbox.Temp, $sandbox.Ps7Dir, $sandbox.Work, $sandbox.Bin) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Code that looks winget up as an application (Get-Command -CommandType Application) finds this instead of the real one;
    # every call is logged to winget-calls.log next to it and fails.
    $wingetStub = "@echo off`r`necho %*>>""%~dp0winget-calls.log""`r`necho Blocked by the test sandbox: winget %* 1>&2`r`nexit /b 1`r`n"
    [System.IO.File]::WriteAllText((Join-Path $sandbox.Bin 'winget.cmd'), $wingetStub, [System.Text.Encoding]::ASCII)
    $sandbox
}

# Return the winget command lines that reached the sandbox's winget.cmd.
function Get-PspSandboxWingetCalls {
    param([Parameter(Mandatory)][object]$Sandbox)
    $log = Join-Path $Sandbox.Bin 'winget-calls.log'
    if (Test-Path -LiteralPath $log) { @(Get-Content -LiteralPath $log) } else { @() }
}

# Point LOCALAPPDATA, TEMP/TMP and $PROFILE into a sandbox and install the fail-closed stubs; call before loading the profile.
function Enter-PspSandbox {
    param([Parameter(Mandatory)][object]$Sandbox)
    if (-not (Get-Variable -Name PspSandboxSaved -Scope Global -ErrorAction Ignore)) {
        $global:PspSandboxSaved = @{
            LOCALAPPDATA = $env:LOCALAPPDATA; TEMP = $env:TEMP; TMP = $env:TMP; CI = $env:CI; NO_COLOR = $env:NO_COLOR; PROFILE = $global:PROFILE; PATH = $env:PATH
        }
    }
    $env:PATH = $Sandbox.Bin + ';' + $global:PspSandboxSaved.PATH
    $env:LOCALAPPDATA = $Sandbox.Local
    $env:TEMP = $Sandbox.Temp
    $env:TMP = $Sandbox.Temp
    $env:CI = 'true'
    $global:PROFILE = Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1'
    Install-PspTestStubs
}

# Restore the environment saved by the first Enter-PspSandbox and remove the stubs.
function Exit-PspSandbox {
    param([object]$Sandbox, [switch]$Keep)
    $saved = Get-Variable -Name PspSandboxSaved -Scope Global -ValueOnly -ErrorAction Ignore
    if ($saved) {
        foreach ($name in 'LOCALAPPDATA', 'TEMP', 'TMP', 'CI', 'NO_COLOR', 'PATH') { Set-Item -Path "env:$name" -Value $saved[$name] -ErrorAction SilentlyContinue }
        $global:PROFILE = $saved.PROFILE
        Remove-Variable -Name PspSandboxSaved -Scope Global -ErrorAction SilentlyContinue
    }
    Remove-PspTestStubs
    if ($Sandbox -and -not $Keep -and (Test-Path -LiteralPath $Sandbox.Root)) {
        Remove-Item -LiteralPath $Sandbox.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$script:PspTestStubNames = @(
    'winget', 'Install-Module', 'Uninstall-Module', 'Install-PSResource', 'Uninstall-PSResource', 'Update-Module',
    'Set-ExecutionPolicy', 'Start-Process', 'Remove-ItemProperty', 'Set-ItemProperty', 'New-ItemProperty',
    'New-NetFirewallRule', 'Remove-NetFirewallRule', 'Stop-Computer', 'Restart-Computer', 'Start-MpScan'
)

# Define global functions that shadow commands which would change the machine; each one throws so a test cannot reach the real command.
function Install-PspTestStubs {
    foreach ($name in $script:PspTestStubNames) {
        $body = [scriptblock]::Create("throw ""Blocked by the test sandbox: $name `$args""")
        Set-Item -Path "function:global:$name" -Value $body
    }
    # Registry writes are allowed only below the test key.
    Set-Item -Path 'function:global:Remove-ItemProperty' -Value {
        param([string]$Path, [string]$Name, [switch]$Force, $ErrorAction)
        if ($Path -notlike 'HKCU:\SOFTWARE\PowerShellPerfectTest*') { throw "Blocked by the test sandbox: Remove-ItemProperty $Path" }
        Microsoft.PowerShell.Management\Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

# Remove the stubs installed by Install-PspTestStubs.
function Remove-PspTestStubs {
    foreach ($name in $script:PspTestStubNames) { Remove-Item -Path "function:global:$name" -ErrorAction SilentlyContinue }
}

# Dot-source right after loading the profile: replaces profile functions that reach outside the sandbox.
$script:PspPostLoadStubs = {
    # oh-my-posh keeps its own cache outside LOCALAPPDATA\PowerShellProfile.
    function Clear-OhMyPoshCaches { param([switch]$Quiet) }
    # Reloading PATH from the registry would drop the sandbox's winget.cmd from the front of PATH.
    function Update-SessionPathFromRegistry { }
    # Font removal stays inside the sandbox.
    if ($script:PSP) {
        $script:PSP.TestFontScopes = @(
            @{ Name = 'per-user'; Dir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'); Reg = 'HKCU:\SOFTWARE\PowerShellPerfectTest\Fonts-NotPresent'; NeedsAdmin = $false }
        )
    }
}

# Return the source text of the named top-level functions of a script, for loading helpers without running the script.
function Get-PspFunctionSource {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Name)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "$Path has $($parseErrors.Count) parse error(s)" }
    $defined = @{}
    foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $defined[$statement.Name] = $statement.Extent.Text }
    }
    foreach ($n in $Name) {
        if (-not $defined.ContainsKey($n)) { throw "$Path does not define $n" }
        $defined[$n]
    }
}

# Return the source text of a top-level variable assignment of a script (for example $script:CuratedFonts).
function Get-PspAssignmentSource {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Variable)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    $hit = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq $Variable } | Select-Object -First 1
    if (-not $hit) { throw "$Path does not assign $Variable" }
    $hit.Extent.Text
}
