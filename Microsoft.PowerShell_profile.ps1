### PowerShell Profile (26zl)
### https://github.com/26zl/PowerShellPerfect

$_pspStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Normalize known agent/AI env vars to AI_AGENT.
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) {
    $env:AI_AGENT = '1'
}

# Detect non-interactive environments that should skip network calls and UI setup.
$isInteractive = [Environment]::UserInteractive -and
-not [bool]$env:CI -and
-not [bool]$env:AI_AGENT -and
-not ($host.Name -eq 'Default Host') -and
-not $(try { [Console]::IsOutputRedirected } catch { $false }) -and
-not ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '(?i)^-NonI' })

# Enforce TLS 1.2 for network commands on Windows PowerShell 5.1.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }
}

# Return the profile cache directory, resolved from LOCALAPPDATA at call time so redirected environments are honored.
function Get-PspCacheDir {
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [System.IO.Path]::GetTempPath() }
    Join-Path $base 'PowerShellProfile'
}

# Kept for scripts that read it; profile functions call Get-PspCacheDir instead.
$cacheDir = Get-PspCacheDir
if (-not (Test-Path -LiteralPath $cacheDir)) {
    # Cache creation is best-effort.
    try { New-Item -ItemType Directory -Path $cacheDir -Force -ErrorAction Stop | Out-Null }
    catch { Write-Warning "Could not create cache dir '$cacheDir': $($_.Exception.Message)" }
}

# Detect administrator status safely across PowerShell editions and platforms.
$_pspIsWindowsOS = (-not (Test-Path Variable:\IsWindows)) -or $IsWindows
if ($_pspIsWindowsOS) {
    try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { $isAdmin = $false }
}
else { $isAdmin = $false }

# Protect core Windows processes from profile process-killing commands.
$script:ProtectedProcessNames = @('System', 'Idle', 'Registry', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'smss', 'svchost', 'dwm')

# Define tool installation, upgrade, cache, and version metadata.
$script:ProfileTools = @(
    @{ Name = "Oh My Posh"; Id = "JanDeDobbeleer.OhMyPosh"; Cmd = "oh-my-posh"; Cache = $null; VerCmd = "version"; UpgradeStrategy = "preserve-direct" }
    @{ Name = "eza"; Id = "eza-community.eza"; Cmd = "eza"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "zoxide"; Id = "ajeetdsouza.zoxide"; Cmd = "zoxide"; Cache = "zoxide-init.ps1"; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "fzf"; Id = "junegunn.fzf"; Cmd = "fzf"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "bat"; Id = "sharkdp.bat"; Cmd = "bat"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
    @{ Name = "ripgrep"; Id = "BurntSushi.ripgrep.MSVC"; Cmd = "rg"; Cache = $null; VerCmd = "--version"; UpgradeStrategy = "winget" }
)

# Expose hooks, feature toggles, command metadata, and shared state through $PSP.
$script:PSP = @{
    # Semantic version of the profile; release tags (vX.Y.Z) must match it.
    Version      = '1.0.0'
    RepoOwner    = '26zl'
    RepoName     = 'PowerShellPerfect'
    IsInteractive = $isInteractive
    IsAdmin      = $isAdmin
    AdminSuffix  = $(if ($isAdmin) { ' [ADMIN]' } else { '' })
    # Milliseconds to wait for oh-my-posh before falling back to the plain prompt.
    PromptTimeoutMs = 5000
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
        # transientPrompt collapses the previous prompt on Enter (p10k-style); no-op without a console host + PSReadLine.
        transientPrompt  = $false
        # Require explicit opt-in before compiling commandOverrides strings as scriptblocks.
        commandOverrides = $false
        # Keep the weekly GitHub update check disabled by default.
        updateCheck      = $false
    }
    # Return the collapsed prompt text used by the customizable transient prompt.
    TransientPrompt = { "$ " }
    TrustedDirs  = [System.Collections.Generic.List[string]]::new()
    # SHA-256 of the .psprc.ps1 approved for each trusted directory ('' when none existed at approval).
    TrustedRcHashes = @{}
    LastPwd      = $null
    # Store the most recent directories added by Invoke-PromptStage.
    PwdHistory   = [System.Collections.Generic.List[string]]::new()
    PwdHistoryMax = 20
    # Prevent cdb navigation from re-adding the consumed directory to PwdHistory.
    SuppressPwdHistoryPush = $false
    # Store the tab title without context indicators for the PrePrompt hook.
    BaseTitle    = $null
}

# Run registered hook actions while isolating errors.
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
    <#
    .SYNOPSIS
    Hook lifecycle events.
    .EXAMPLE
    Register-ProfileHook -EventName OnCd -Action { Write-Host $PWD }
    Run code after every directory change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OnProfileLoad', 'PrePrompt', 'OnCd')][string]$EventName,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $script:PSP.Hooks[$EventName].Add($Action)
}

# Add a custom help section from a plugin or profile_user.ps1.
function Register-HelpSection {
    <#
    .SYNOPSIS
    Add section to Show-Help.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Lines
    )
    $script:PSP.HelpSections.Add([PSCustomObject]@{ Title = $Title; Lines = $Lines })
}

# Add a command to the discovery registry consumed by Get-ProfileCommand.
function Register-ProfileCommand {
    <#
    .SYNOPSIS
    Register a command for discovery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [string]$Synopsis = ''
    )
    $script:PSP.Commands.Add([PSCustomObject]@{ Name = $Name; Category = $Category; Synopsis = $Synopsis })
}

# Run a scriptblock in a job and return $null on timeout or failure.
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

# Quote arguments for a single native command line using the CommandLineToArgvW rules (quotes and trailing backslashes).
function ConvertTo-NativeArgumentLine {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList)
    ($ArgumentList | ForEach-Object {
        if ($_ -eq '') { '""' }
        elseif ($_ -notmatch '[\s"]') { $_ }
        else {
            $s = $_ -replace '(\\*)"', '$1$1\"'
            $s = $s -replace '(\\+)$', '$1$1'
            '"' + $s + '"'
        }
    }) -join ' '
}

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

# Read text as UTF-8 with BOM detection across PowerShell editions; relative paths resolve against the current location.
function Get-Utf8FileText {
    param([Parameter(Mandatory)][string]$Path)
    [System.IO.File]::ReadAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}

# Write UTF-8 without BOM through a sibling temp file before replacing the target; a symlink is written in place so the link survives.
function Write-Utf8FileAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        # Copy the current file here first; the write is abandoned if the copy fails.
        [string]$BackupPath
    )
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $existing = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    # Callers gate the write with ShouldProcess; the steps below must not prompt again or honor -WhatIf on their own.
    if ($BackupPath -and $existing) { Copy-Item -LiteralPath $Path -Destination $BackupPath -Force -ErrorAction Stop -Confirm:$false -WhatIf:$false }
    if ($existing -and $existing.LinkType) {
        [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
        return
    }
    $dir = Split-Path -Parent $Path
    if (-not $dir) { $dir = '.' }
    $tmp = Join-Path $dir ('.psp-tmp-' + [System.IO.Path]::GetRandomFileName())
    try {
        [System.IO.File]::WriteAllText($tmp, $Content, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop -Confirm:$false -WhatIf:$false
    }
    catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false }
        throw
    }
}

# Parse JSON that may contain // or /* */ comments and trailing commas (Windows Terminal JSONC); string contents are never altered.
function ConvertFrom-JsonC {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $keepStrings = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        if ($m.Value[0] -eq [char]34) { $m.Value } elseif ($m.Value.StartsWith('/*')) { ' ' } else { '' }
    }
    $noComments = [regex]::Replace($Text, '"(?:[^"\\]|\\.)*"|//[^\r\n]*|/\*[\s\S]*?\*/', $keepStrings)
    $clean = [regex]::Replace($noComments, '"(?:[^"\\]|\\.)*"|,(?=\s*[}\]])', $keepStrings)
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    $parsed = $clean | ConvertFrom-Json -ErrorAction Stop
    if ($parsed -is [System.Collections.IList]) { return , $parsed }
    return $parsed
}

# Read a UTF-8 (BOM-aware) JSON or JSONC file; returns $null for a missing or empty file and throws on invalid content.
function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $raw = Get-Utf8FileText $Path
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $parsed = ConvertFrom-JsonC -Text $raw
    if ($parsed -is [System.Collections.IList]) { return , $parsed }
    return $parsed
}

# Return a property of an object or dictionary, keeping list values intact ($null when absent).
function Get-PspProp {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $value = $null
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { $value = $Object[$Name] }
    }
    else {
        $p = $Object.PSObject.Properties[$Name]
        if ($p) { $value = $p.Value }
    }
    if ($value -is [System.Collections.IList]) { return , $value }
    return $value
}

# Return a property that holds a list as an object[] without null entries (empty when absent).
function Get-PspArray {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    $value = Get-PspProp $Object $Name
    return , [object[]]@($value | Where-Object { $null -ne $_ })
}

# Return a nested property addressed by a dotted path such as 'profiles.defaults' ($null when any part is missing).
function Get-PspPath {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Path)
    $node = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $node) { return $null }
        $node = Get-PspProp $node $part
    }
    if ($node -is [System.Collections.IList]) { return , $node }
    return $node
}

# Return $true when an object or dictionary has the named property.
function Test-PspProp {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    [bool]$Object.PSObject.Properties[$Name]
}

# Set or add a property on a PSCustomObject or dictionary.
function Set-PspProp {
    param([Parameter(Mandatory)][object]$Object, [Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Value)
    if ($Object -is [System.Collections.IDictionary]) { $Object[$Name] = $Value; return }
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

# Remove a property from a PSCustomObject or dictionary if present.
function Remove-PspProp {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return }
    if ($Object -is [System.Collections.IDictionary]) { $Object.Remove($Name); return }
    if ($Object.PSObject.Properties[$Name]) { $Object.PSObject.Properties.Remove($Name) }
}

# Return a deep copy of parsed JSON data.
function Copy-PspObject {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $copy = ConvertTo-Json -InputObject $Value -Depth 50 -Compress | ConvertFrom-Json
    if ($copy -is [System.Collections.IList]) { return , $copy }
    return $copy
}

# Serialize parsed JSON data with object keys sorted recursively, so equal settings compare equal across editions.
function ConvertTo-PspCanonicalJson {
    param([AllowNull()][object]$Value)
    function ConvertTo-PspSortedNode {
        param([AllowNull()][object]$Node)
        if ($null -eq $Node) { return $null }
        if ($Node -is [string]) { return $Node }
        if ($Node -is [System.Collections.IDictionary]) {
            $sorted = [ordered]@{}
            foreach ($k in ($Node.Keys | Sort-Object)) { $sorted[[string]$k] = ConvertTo-PspSortedNode $Node[$k] }
            return $sorted
        }
        if ($Node -is [System.Management.Automation.PSCustomObject]) {
            $sorted = [ordered]@{}
            foreach ($p in ($Node.PSObject.Properties | Sort-Object Name)) { $sorted[$p.Name] = ConvertTo-PspSortedNode $p.Value }
            return $sorted
        }
        if ($Node -is [System.Collections.IEnumerable]) {
            return , @(foreach ($item in $Node) { ConvertTo-PspSortedNode $item })
        }
        return $Node
    }
    ConvertTo-Json -InputObject (ConvertTo-PspSortedNode $Value) -Depth 50 -Compress
}

# Return $true when two parsed JSON values are equal regardless of key order.
function Test-PspJsonEqual {
    param([AllowNull()][object]$Left, [AllowNull()][object]$Right)
    (ConvertTo-PspCanonicalJson $Left) -ceq (ConvertTo-PspCanonicalJson $Right)
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

# Return the raw.githubusercontent.com URL of a repository file at a branch, tag or commit.
function Get-PspRawUrl {
    param([Parameter(Mandatory)][string]$Ref, [Parameter(Mandatory)][string]$Path)
    'https://raw.githubusercontent.com/{0}/{1}/{2}/{3}' -f $script:PSP.RepoOwner, $script:PSP.RepoName, $Ref, $Path
}

# Return the upstream main SHA from GitHub or $null on failure.
function Get-LatestMainCommitSha {
    Resolve-PspCommitSha -Owner $script:PSP.RepoOwner -Repo $script:PSP.RepoName -Ref 'main' -TimeoutSec 3
}

# Return the pinned versions of third-party components the profile and setup.ps1 install at runtime.
function Get-PspComponentPins {
    @{
        PSFzf      = '2.7.12'
        HttpServer = '14.1.1'
    }
}

# Read the install record written by setup.ps1 and Update-Profile (version, source ref, commit, bundle hash).
function Get-PspInstallState {
    param([string]$CacheDir = (Get-PspCacheDir))
    try { Read-JsonFile (Join-Path $CacheDir 'installed.json') } catch { $null }
}

# Return $true when a file is a copy of this profile (its header line), so it is never kept or restored as the user's own profile.
function Test-PspProfileFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try { $head = @(Get-Content -LiteralPath $Path -TotalCount 3 -ErrorAction Stop) } catch { return $false }
    [bool]@($head | Where-Object { $_ -match '^### PowerShell Profile \(26zl\)' }).Count
}

# Return the file that holds the user's own profile from before the first install: the current profile unless it is a
# copy of this one, otherwise the oldest oldprofile*.ps1 backup that is not ($null when there is none).
function Get-PspOriginalProfileSource {
    param([Parameter(Mandatory)][string]$Directory)
    $current = Join-Path $Directory 'Microsoft.PowerShell_profile.ps1'
    if ((Test-Path -LiteralPath $current -PathType Leaf) -and -not (Test-PspProfileFile -Path $current)) { return $current }
    $backup = Get-ChildItem -LiteralPath $Directory -Filter 'oldprofile*.ps1' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime | Where-Object { -not (Test-PspProfileFile -Path $_.FullName) } | Select-Object -First 1
    if ($backup) { return $backup.FullName }
    return $null
}

# Write the install record; unknown values are kept from the previous record.
function Set-PspInstallState {
    param(
        [Parameter(Mandatory)][string]$CacheDir,
        [string]$Version,
        [string]$Ref,
        [string]$Commit,
        [string]$BundleSha256,
        [string]$Source
    )
    $state = Get-PspInstallState -CacheDir $CacheDir
    if ($null -eq $state) { $state = [PSCustomObject]@{} }
    $values = [ordered]@{ version = @('Version', $Version); ref = @('Ref', $Ref); commit = @('Commit', $Commit); bundleSha256 = @('BundleSha256', $BundleSha256); source = @('Source', $Source) }
    foreach ($key in @($values.Keys)) {
        if ($values[$key][1]) { Set-PspProp $state $key $values[$key][1] }
        # Passed but empty (for example a commit the GitHub API could not resolve): drop the previous value.
        elseif ($PSBoundParameters.ContainsKey($values[$key][0])) { Remove-PspProp $state $key }
    }
    Set-PspProp $state 'updatedAt' (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
    if (-not (Test-Path -LiteralPath $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
    Write-Utf8FileAtomic -Path (Join-Path $CacheDir 'installed.json') -Content ($state | ConvertTo-Json -Depth 5)
}

# Get the full path to an external command
function Get-ExternalCommandPath {
    param(
        [Parameter(Mandatory)]
        [string]$CommandName
    )

    $cmd = Get-Command $CommandName -ErrorAction Ignore
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

function Update-SessionPathFromRegistry {
    $machinePath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
    $env:PATH = (@($machinePath, $userPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';'
}

# Manage restorable tab titles for long-running commands.
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

# Return the first Windows Terminal settings file found across supported install variants (or $null).
function Get-WindowsTerminalSettingsPath {
    @(Get-WindowsTerminalSettingsPaths)[0]
}

# Return all Windows Terminal settings files found across supported install variants.
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

# Load the manifest that records each Windows Terminal change the profile made (empty when missing or unreadable).
function Read-WtChangeManifest {
    param([Parameter(Mandatory)][string]$ManifestPath)
    $manifest = $null
    try { $manifest = Read-JsonFile $ManifestPath }
    catch { Write-Warning "Ignoring unreadable ${ManifestPath}: $($_.Exception.Message)" }
    if ($null -eq $manifest) { $manifest = [PSCustomObject]@{ version = 1; files = [PSCustomObject]@{} } }
    if (-not (Get-PspProp $manifest 'files')) { Set-PspProp $manifest 'files' ([PSCustomObject]@{}) }
    return $manifest
}

# Save the change manifest, deleting it once no settings file has recorded changes.
function Save-WtChangeManifest {
    param([Parameter(Mandatory)][string]$ManifestPath, [Parameter(Mandatory)][object]$Manifest)
    if (@($Manifest.files.PSObject.Properties).Count -eq 0) {
        Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue -Confirm:$false -WhatIf:$false
        return
    }
    $dir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -Confirm:$false -WhatIf:$false | Out-Null }
    Write-Utf8FileAtomic -Path $ManifestPath -Content ($Manifest | ConvertTo-Json -Depth 100)
}

# Record the pre-install value of a setting once and the value the profile applies each time.
function Add-WtChangeRecord {
    param(
        [Parameter(Mandatory)][object]$Section,
        [Parameter(Mandatory)][string]$Name,
        [bool]$Existed,
        [AllowNull()][object]$Original,
        [AllowNull()][object]$Applied,
        [switch]$AppliedRemoved
    )
    $record = Get-PspProp $Section $Name
    if (-not $record) {
        $record = [PSCustomObject]@{ existed = $Existed; original = $Original; applied = $null; removed = $false }
        Set-PspProp $Section $Name $record
    }
    $record.applied = $Applied
    $record.removed = [bool]$AppliedRemoved
}

# Set or remove one settings property and record it; object values (font) are merged so unmanaged keys survive.
function Set-WtRecordedValue {
    param(
        [Parameter(Mandatory)][object]$Container,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][object]$Section,
        [AllowNull()][object]$Baseline,
        # Pre-install copy; used when the file already holds the value being written (an earlier profile version wrote it).
        [AllowNull()][object]$LegacyBaseline,
        [switch]$Remove
    )
    $current = Get-PspProp $Container $Name
    if (-not $Remove -and $Value -is [System.Management.Automation.PSCustomObject] -and $current -is [System.Management.Automation.PSCustomObject]) {
        $merged = Copy-PspObject $current
        foreach ($p in $Value.PSObject.Properties) { Set-PspProp $merged $p.Name $p.Value }
        $Value = $merged
    }
    $reference = $Baseline
    if (-not $Remove -and $null -ne $LegacyBaseline -and (Test-PspProp $Container $Name) -and (Test-PspJsonEqual $current $Value)) { $reference = $LegacyBaseline }
    $baseHas = Test-PspProp $reference $Name
    # Assigned in branches: an if expression would unroll array values such as ["window"].
    $original = $null
    if ($baseHas) { $original = Get-PspProp $reference $Name }
    $applied = $null
    if (-not $Remove) { $applied = $Value }
    Add-WtChangeRecord -Section $Section -Name $Name -Existed $baseHas -Original $original -Applied $applied -AppliedRemoved:$Remove
    if ($Remove) { Remove-PspProp $Container $Name } else { Set-PspProp $Container $Name $Value }
}

# Upsert a named entry (color scheme or theme) in a settings array and record it.
function Set-WtRecordedArrayItem {
    param(
        [Parameter(Mandatory)][object]$Root,
        [Parameter(Mandatory)][string]$ArrayName,
        [Parameter(Mandatory)][object]$Item,
        [Parameter(Mandatory)][object]$Section,
        [AllowNull()][object]$Baseline,
        [AllowNull()][object]$LegacyBaseline
    )
    $name = [string](Get-PspProp $Item 'name')
    if (-not $name) { return }
    $items = Get-PspArray $Root $ArrayName
    $currentItem = $items | Where-Object { (Get-PspProp $_ 'name') -eq $name } | Select-Object -First 1
    $reference = if ($null -ne $LegacyBaseline -and $null -ne $currentItem -and (Test-PspJsonEqual $currentItem $Item)) { $LegacyBaseline } else { $Baseline }
    $baseItem = (Get-PspArray $reference $ArrayName) | Where-Object { (Get-PspProp $_ 'name') -eq $name } | Select-Object -First 1
    Add-WtChangeRecord -Section $Section -Name $name -Existed ($null -ne $baseItem) -Original $baseItem -Applied $Item
    Set-PspProp $Root $ArrayName ([object[]](@($items | Where-Object { (Get-PspProp $_ 'name') -ne $name }) + $Item))
}

# Bind keys to a command (new id-based or old inline actions format) and record what the binding replaced.
function Set-WtRecordedKeybinding {
    param(
        [Parameter(Mandatory)][object]$Root,
        [Parameter(Mandatory)][object]$Binding,
        [Parameter(Mandatory)][object]$Section,
        [AllowNull()][object]$Baseline,
        [AllowNull()][object]$LegacyBaseline
    )
    $keys = [string](Get-PspProp $Binding 'keys')
    if ([string]::IsNullOrWhiteSpace($keys)) { return }
    $command = Get-PspProp $Binding 'command'
    $id = 'User.profile.' + ($keys -replace '[^a-zA-Z0-9]', '')
    $newFormat = Test-PspProp $Root 'keybindings'
    $record = Get-PspProp $Section $keys
    if (-not $record) {
        # Remember what the pre-install file bound to these keys so uninstall can put it back.
        $source = if ($null -ne $Baseline) { $Baseline } else { $Root }
        # The binding is already there when an earlier profile version set it; the pre-install copy shows what it replaced.
        $alreadyBound = @((Get-PspArray $Root 'actions') | Where-Object { (Get-PspProp $_ 'id') -eq $id -or ((Get-PspProp $_ 'keys') -eq $keys -and (Test-PspJsonEqual (Get-PspProp $_ 'command') $command)) }).Count -gt 0
        if ($alreadyBound -and $null -ne $LegacyBaseline) { $source = $LegacyBaseline }
        $removedBindings = @((Get-PspArray $source 'keybindings') | Where-Object { (Get-PspProp $_ 'keys') -eq $keys })
        if (Test-PspProp $source 'keybindings') {
            $boundIds = @($removedBindings | ForEach-Object { Get-PspProp $_ 'id' })
            $removedActions = @((Get-PspArray $source 'actions') | Where-Object { $boundIds -contains (Get-PspProp $_ 'id') })
        }
        else {
            $removedActions = @((Get-PspArray $source 'actions') | Where-Object { (Get-PspProp $_ 'keys') -eq $keys })
        }
        $record = [PSCustomObject]@{ format = 'old'; id = $id; appliedAction = $null; appliedBinding = $null; removedActions = [object[]]$removedActions; removedBindings = [object[]]$removedBindings }
        Set-PspProp $Section $keys $record
    }
    $actions = Get-PspArray $Root 'actions'
    if ($newFormat) {
        $existingIds = @((Get-PspArray $Root 'keybindings') | Where-Object { (Get-PspProp $_ 'keys') -eq $keys } | ForEach-Object { Get-PspProp $_ 'id' })
        $actions = @($actions | Where-Object { ($existingIds -notcontains (Get-PspProp $_ 'id')) -and (Get-PspProp $_ 'id') -ne $id })
        $bindings = @((Get-PspArray $Root 'keybindings') | Where-Object { (Get-PspProp $_ 'keys') -ne $keys })
        $action = [PSCustomObject]@{ command = $command; id = $id }
        $bindingEntry = [PSCustomObject]@{ id = $id; keys = $keys }
        Set-PspProp $Root 'actions' ([object[]]($actions + $action))
        Set-PspProp $Root 'keybindings' ([object[]]($bindings + $bindingEntry))
        $record.format = 'new'; $record.appliedAction = $action; $record.appliedBinding = $bindingEntry
    }
    else {
        $actions = @($actions | Where-Object { (Get-PspProp $_ 'keys') -ne $keys })
        $action = [PSCustomObject]@{ keys = $keys; command = $command }
        Set-PspProp $Root 'actions' ([object[]]($actions + $action))
        $record.format = 'old'; $record.appliedAction = $action; $record.appliedBinding = $null
    }
}

# Return the profiles list of a settings object, including pre-2020 files that keep profiles as a bare list.
function Get-WtProfileList {
    param([AllowNull()][object]$Settings)
    $profilesNode = Get-PspProp $Settings 'profiles'
    if ($profilesNode -is [System.Collections.IList]) { return , [object[]]@($profilesNode | Where-Object { $null -ne $_ }) }
    return , (Get-PspArray $profilesNode 'list')
}

# Launch PowerShell profiles in profiles.list with -NoLogo and record each changed command line.
function Set-WtRecordedNoLogo {
    param([Parameter(Mandatory)][object]$Root, [Parameter(Mandatory)][object]$Section, [AllowNull()][object]$Baseline, [AllowNull()][object]$LegacyBaseline)
    $baseList = Get-WtProfileList $Baseline
    $legacyList = Get-WtProfileList $LegacyBaseline
    foreach ($prof in (Get-WtProfileList $Root)) {
        $cmd = [string](Get-PspProp $prof 'commandline')
        $src = [string](Get-PspProp $prof 'source')
        $profName = [string](Get-PspProp $prof 'name')
        $isPwsh = $cmd -match 'pwsh' -or $src -match 'Windows\.Terminal\.PowerShellCore'
        $isPS5 = $cmd -match 'powershell\.exe' -or $profName -match 'Windows PowerShell'
        if (-not ($isPwsh -or $isPS5)) { continue }
        $guid = [string](Get-PspProp $prof 'guid')
        $recordKey = if ($guid) { "guid:$guid" } else { "name:$profName" }
        $matchProfile = { param($candidate) if ($guid) { (Get-PspProp $candidate 'guid') -eq $guid } else { (Get-PspProp $candidate 'name') -eq $profName } }
        $baseProf = $baseList | Where-Object { & $matchProfile $_ } | Select-Object -First 1
        if ($null -ne $baseProf) {
            $baseHas = Test-PspProp $baseProf 'commandline'
            $baseCmd = if ($baseHas) { [string](Get-PspProp $baseProf 'commandline') } else { $null }
        }
        else {
            # A profile the baseline does not know (added since) keeps its current command line as the original.
            $baseHas = [bool]$cmd
            $baseCmd = if ($cmd) { $cmd } else { $null }
        }
        $newCmd = $null
        if ($cmd -and $cmd -notmatch '-NoLogo' -and $cmd -notmatch '(?i)-(Command|File|EncodedCommand)') { $newCmd = "$cmd -NoLogo" }
        elseif (-not $cmd -and $src) { $newCmd = $(if ($isPwsh) { 'pwsh.exe -NoLogo' } else { 'powershell.exe -NoLogo' }) }
        elseif ($cmd -match '-NoLogo' -and -not (Get-PspProp $Section $recordKey)) {
            # Adopt a -NoLogo an earlier profile version added (the pre-install copy has the profile without it) so uninstall can remove it.
            $legacyProf = $legacyList | Where-Object { & $matchProfile $_ } | Select-Object -First 1
            if ($null -ne $legacyProf) {
                $legacyHas = Test-PspProp $legacyProf 'commandline'
                $legacyCmd = if ($legacyHas) { [string](Get-PspProp $legacyProf 'commandline') } else { $null }
                if ($legacyCmd -ne $cmd) { Add-WtChangeRecord -Section $Section -Name $recordKey -Existed $legacyHas -Original $legacyCmd -Applied $cmd }
            }
            elseif ($null -ne $baseProf -and $cmd -ne $baseCmd) {
                Add-WtChangeRecord -Section $Section -Name $recordKey -Existed $baseHas -Original $baseCmd -Applied $cmd
            }
            continue
        }
        if (-not $newCmd) { continue }
        Add-WtChangeRecord -Section $Section -Name $recordKey -Existed $baseHas -Original $baseCmd -Applied $newCmd
        Set-PspProp $prof 'commandline' $newCmd
    }
}

# Apply profile-managed settings to one Windows Terminal settings.json and record every change in the manifest.
function Update-WindowsTerminalSettingsFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ManifestPath,
        # profiles.defaults values to set (object values are merged key by key).
        [AllowNull()][object]$Defaults,
        # profiles.defaults keys to remove.
        [string[]]$RemoveDefaults = @(),
        # theme.json windowsTerminal section: colorScheme, cursorColor, scheme, theme, themeDefinition.
        [AllowNull()][object]$WindowsTerminal,
        # Keybindings as objects with keys and command.
        [AllowNull()][object[]]$Keybindings,
        # Append -NoLogo to PowerShell profiles in profiles.list.
        [switch]$NoLogo,
        [int]$KeepBackups = 5
    )
    $raw = Get-Utf8FileText $Path
    $wt = if ([string]::IsNullOrWhiteSpace($raw)) { $null } else { ConvertFrom-JsonC -Text $raw }
    if ($null -eq $wt) { $wt = [PSCustomObject]@{} }
    $dir = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    $timestamped = @(Get-ChildItem -LiteralPath $dir -Filter "$leaf.*.bak" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.\d{8}-\d{6}\.bak$' } | Sort-Object LastWriteTime)
    $manifest = Read-WtChangeManifest -ManifestPath $ManifestPath
    $key = $Path.ToLowerInvariant()
    $entry = Get-PspProp $manifest.files $key
    # Values first seen in this run are recorded against the file as it was before this write. A value the file
    # already holds was probably written by an earlier profile version, so it is recorded against the pre-install copy
    # (settings.json.psp-original, or the oldest timestamped backup left by versions without a change record).
    $baseline = Copy-PspObject $wt
    $originalCopy = "$Path.psp-original"
    $legacyBaseline = $null
    $legacySource = if (Test-Path -LiteralPath $originalCopy) { $originalCopy } elseif ($timestamped.Count -gt 0) { $timestamped[0].FullName } else { $null }
    if ($legacySource) {
        try { $legacyBaseline = ConvertFrom-JsonC -Text (Get-Utf8FileText $legacySource) }
        catch { $null = $_ }
    }
    if (-not $entry) {
        $entry = [PSCustomObject]@{
            defaults = [PSCustomObject]@{}; root = [PSCustomObject]@{}; schemes = [PSCustomObject]@{}
            themes = [PSCustomObject]@{}; bindings = [PSCustomObject]@{}; commandlines = [PSCustomObject]@{}
        }
        Set-PspProp $manifest.files $key $entry
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Update Windows Terminal settings')) { return $false }

    # Keep one durable copy of the file as it was before the profile first changed it.
    if (-not (Test-Path -LiteralPath $originalCopy)) {
        $source = if ($timestamped.Count -gt 0) { $timestamped[0].FullName } else { $Path }
        Copy-Item -LiteralPath $source -Destination $originalCopy -ErrorAction Stop -Confirm:$false
    }
    # Rotating backup; a failed backup aborts the write.
    Copy-Item -LiteralPath $Path -Destination ('{0}.{1}.bak' -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force -ErrorAction Stop -Confirm:$false
    Get-ChildItem -LiteralPath $dir -Filter "$leaf.*.bak" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.\d{8}-\d{6}\.bak$' } | Sort-Object LastWriteTime -Descending |
        Select-Object -Skip $KeepBackups | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue -Confirm:$false }

    $profilesNode = Get-PspProp $wt 'profiles'
    if ($profilesNode -is [array]) {
        # Pre-2020 files keep profiles as a bare list; Windows Terminal accepts the object form.
        $profilesNode = [PSCustomObject]@{ defaults = [PSCustomObject]@{}; list = [object[]]$profilesNode }
        Set-PspProp $wt 'profiles' $profilesNode
    }
    elseif ($null -eq $profilesNode) {
        $profilesNode = [PSCustomObject]@{}
        Set-PspProp $wt 'profiles' $profilesNode
    }
    $defaultsNode = Get-PspProp $profilesNode 'defaults'
    if ($null -eq $defaultsNode) {
        $defaultsNode = [PSCustomObject]@{}
        Set-PspProp $profilesNode 'defaults' $defaultsNode
    }
    $baseDefaults = Get-PspPath $baseline 'profiles.defaults'
    $legacyDefaults = $null
    if ($null -ne $legacyBaseline) {
        $legacyDefaults = Get-PspPath $legacyBaseline 'profiles.defaults'
        # A pre-install file without defaults still counts: the profile added every default it holds.
        if ($null -eq $legacyDefaults) { $legacyDefaults = [PSCustomObject]@{} }
    }
    # Arrays the profile adds to a file that had none are removed again on uninstall once they are empty.
    $created = [System.Collections.Generic.List[string]]::new()
    foreach ($name in (Get-PspArray $entry 'createdArrays')) { $created.Add([string]$name) }
    $wantsArray = @{
        schemes = [bool]($WindowsTerminal -and (Get-PspProp $WindowsTerminal 'scheme'))
        themes  = [bool]($WindowsTerminal -and (Get-PspProp $WindowsTerminal 'themeDefinition'))
        actions = [bool]@($Keybindings | Where-Object { $null -ne $_ }).Count
    }
    foreach ($name in $wantsArray.Keys) {
        if ($wantsArray[$name] -and -not (Test-PspProp $wt $name) -and -not $created.Contains($name)) { $created.Add($name) }
    }
    if ($created.Count -gt 0) { Set-PspProp $entry 'createdArrays' ([object[]]$created.ToArray()) }
    if ($null -ne $Defaults) {
        foreach ($p in $Defaults.PSObject.Properties) {
            Set-WtRecordedValue -Container $defaultsNode -Name $p.Name -Value $p.Value -Section $entry.defaults -Baseline $baseDefaults -LegacyBaseline $legacyDefaults
        }
    }
    foreach ($name in $RemoveDefaults) {
        if (Test-PspProp $defaultsNode $name) {
            Set-WtRecordedValue -Container $defaultsNode -Name $name -Value $null -Section $entry.defaults -Baseline $baseDefaults -Remove
        }
    }
    if ($null -ne $WindowsTerminal) {
        foreach ($name in 'colorScheme', 'cursorColor') {
            $value = Get-PspProp $WindowsTerminal $name
            if ($value) { Set-WtRecordedValue -Container $defaultsNode -Name $name -Value $value -Section $entry.defaults -Baseline $baseDefaults -LegacyBaseline $legacyDefaults }
        }
        $scheme = Get-PspProp $WindowsTerminal 'scheme'
        if ($scheme) {
            $schemeObj = Copy-PspObject ([PSCustomObject]$scheme)
            if (-not (Get-PspProp $schemeObj 'name') -and (Get-PspProp $WindowsTerminal 'colorScheme')) { Set-PspProp $schemeObj 'name' $WindowsTerminal.colorScheme }
            Set-WtRecordedArrayItem -Root $wt -ArrayName 'schemes' -Item $schemeObj -Section $entry.schemes -Baseline $baseline -LegacyBaseline $legacyBaseline
        }
        $themeDef = Get-PspProp $WindowsTerminal 'themeDefinition'
        if ($themeDef) {
            Set-WtRecordedArrayItem -Root $wt -ArrayName 'themes' -Item (Copy-PspObject ([PSCustomObject]$themeDef)) -Section $entry.themes -Baseline $baseline -LegacyBaseline $legacyBaseline
        }
        $themeName = Get-PspProp $WindowsTerminal 'theme'
        if ($themeName) { Set-WtRecordedValue -Container $wt -Name 'theme' -Value $themeName -Section $entry.root -Baseline $baseline -LegacyBaseline $legacyBaseline }
    }
    foreach ($kb in @($Keybindings | Where-Object { $null -ne $_ })) {
        Set-WtRecordedKeybinding -Root $wt -Binding $kb -Section $entry.bindings -Baseline $baseline -LegacyBaseline $legacyBaseline
    }
    if ($NoLogo) { Set-WtRecordedNoLogo -Root $wt -Section $entry.commandlines -Baseline $baseline -LegacyBaseline $legacyBaseline }

    # Deeply nested Windows Terminal action objects need the full depth.
    Write-Utf8FileAtomic -Path $Path -Content ($wt | ConvertTo-Json -Depth 100)
    Save-WtChangeManifest -ManifestPath $ManifestPath -Manifest $manifest
    return $true
}

# Return the name/record pairs stored in one section of a manifest entry.
function Get-WtChangeRecords {
    param([AllowNull()][object]$Entry, [Parameter(Mandatory)][string]$Section)
    $node = Get-PspProp $Entry $Section
    if ($null -eq $node) { return }
    foreach ($p in $node.PSObject.Properties) { $p }
}

# Restore one recorded value when the user has not changed it since the profile wrote it.
function Restore-WtRecordedValue {
    param([AllowNull()][object]$Container, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][object]$Record)
    if ($null -eq $Container) { return $false }
    $has = Test-PspProp $Container $Name
    $untouched = if ($Record.removed) { -not $has } else { $has -and (Test-PspJsonEqual (Get-PspProp $Container $Name) $Record.applied) }
    if (-not $untouched) { return $false }
    if ($Record.existed) { Set-PspProp $Container $Name $Record.original } else { Remove-PspProp $Container $Name }
    return $true
}

# Restore a recorded scheme or theme entry when it still matches what the profile wrote.
function Restore-WtRecordedArrayItem {
    param([Parameter(Mandatory)][object]$Root, [Parameter(Mandatory)][string]$ArrayName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][object]$Record)
    $items = Get-PspArray $Root $ArrayName
    $current = $items | Where-Object { (Get-PspProp $_ 'name') -eq $Name } | Select-Object -First 1
    if ($null -eq $current -or -not (Test-PspJsonEqual $current $Record.applied)) { return $false }
    $rest = @($items | Where-Object { (Get-PspProp $_ 'name') -ne $Name })
    if ($Record.existed -and $null -ne $Record.original) { $rest += $Record.original }
    Set-PspProp $Root $ArrayName ([object[]]$rest)
    return $true
}

# Remove a recorded keybinding and put back what it replaced, unless the user changed it.
function Restore-WtRecordedKeybinding {
    param([Parameter(Mandatory)][object]$Root, [Parameter(Mandatory)][object]$Record)
    $actions = Get-PspArray $Root 'actions'
    if (-not ($actions | Where-Object { Test-PspJsonEqual $_ $Record.appliedAction })) { return $false }
    if ($Record.format -eq 'new' -and (Test-PspProp $Root 'keybindings')) {
        $bindings = @((Get-PspArray $Root 'keybindings') | Where-Object { -not (Test-PspJsonEqual $_ $Record.appliedBinding) })
        # Keys the user has since bound to this action keep it.
        $actionId = [string](Get-PspProp $Record.appliedAction 'id')
        if ($actionId -and ($bindings | Where-Object { (Get-PspProp $_ 'id') -eq $actionId })) { return $false }
    }
    $actions = @($actions | Where-Object { -not (Test-PspJsonEqual $_ $Record.appliedAction) })
    if ($Record.format -eq 'new' -and (Test-PspProp $Root 'keybindings')) {
        foreach ($b in (Get-PspArray $Record 'removedBindings')) {
            if (-not ($bindings | Where-Object { (Get-PspProp $_ 'keys') -eq (Get-PspProp $b 'keys') })) { $bindings += $b }
        }
        Set-PspProp $Root 'keybindings' ([object[]]$bindings)
    }
    foreach ($a in (Get-PspArray $Record 'removedActions')) {
        if (-not ($actions | Where-Object { Test-PspJsonEqual $_ $a })) { $actions += $a }
    }
    Set-PspProp $Root 'actions' ([object[]]$actions)
    return $true
}

# Revert the recorded changes in one settings.json, keeping every value the user changed after the profile wrote it.
function Undo-WindowsTerminalSettingsFile {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ManifestPath)
    $manifest = Read-WtChangeManifest -ManifestPath $ManifestPath
    $key = $Path.ToLowerInvariant()
    $entry = Get-PspProp $manifest.files $key
    if (-not $entry) { return $null }
    $wt = ConvertFrom-JsonC -Text (Get-Utf8FileText $Path)
    if ($null -eq $wt) { $wt = [PSCustomObject]@{} }
    $reverted = 0
    $kept = 0
    $defaultsNode = Get-PspPath $wt 'profiles.defaults'
    foreach ($p in @(Get-WtChangeRecords $entry 'defaults')) {
        if (Restore-WtRecordedValue -Container $defaultsNode -Name $p.Name -Record $p.Value) { $reverted++ } else { $kept++ }
    }
    foreach ($p in @(Get-WtChangeRecords $entry 'root')) {
        if (Restore-WtRecordedValue -Container $wt -Name $p.Name -Record $p.Value) { $reverted++ } else { $kept++ }
    }
    foreach ($arrayName in 'schemes', 'themes') {
        foreach ($p in @(Get-WtChangeRecords $entry $arrayName)) {
            if (Restore-WtRecordedArrayItem -Root $wt -ArrayName $arrayName -Name $p.Name -Record $p.Value) { $reverted++ } else { $kept++ }
        }
    }
    foreach ($p in @(Get-WtChangeRecords $entry 'bindings')) {
        if (Restore-WtRecordedKeybinding -Root $wt -Record $p.Value) { $reverted++ } else { $kept++ }
    }
    $list = Get-PspArray (Get-PspProp $wt 'profiles') 'list'
    foreach ($p in @(Get-WtChangeRecords $entry 'commandlines')) {
        $recordKey = $p.Name
        $prof = $list | Where-Object {
            if ($recordKey -like 'guid:*') { ('guid:' + (Get-PspProp $_ 'guid')) -eq $recordKey } else { ('name:' + (Get-PspProp $_ 'name')) -eq $recordKey }
        } | Select-Object -First 1
        if ($prof -and (Restore-WtRecordedValue -Container $prof -Name 'commandline' -Record $p.Value)) { $reverted++ } else { $kept++ }
    }
    foreach ($arrayName in (Get-PspArray $entry 'createdArrays')) {
        if ((Test-PspProp $wt $arrayName) -and (Get-PspArray $wt $arrayName).Count -eq 0) { Remove-PspProp $wt $arrayName }
    }
    if (-not $PSCmdlet.ShouldProcess($Path, "Revert $reverted Windows Terminal change(s) made by this profile")) { return $null }
    Write-Utf8FileAtomic -Path $Path -Content ($wt | ConvertTo-Json -Depth 100)
    Remove-PspProp $manifest.files $key
    Save-WtChangeManifest -ManifestPath $ManifestPath -Manifest $manifest
    return [PSCustomObject]@{ Reverted = $reverted; Kept = $kept }
}

# Return the timestamped settings.json backups and the durable pre-install copy the profile created next to a settings file.
function Get-WtProfileBackups {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -eq "$leaf.psp-original" -or ($_.Name.StartsWith("$leaf.") -and $_.Name -match '\.\d{8}-\d{6}\.bak$')
        })
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
            $env:PATH = (@($candidateDir, $env:PATH) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';'
        }

        return $candidatePath
    }

    # Last resort: the WindowsApps app-execution alias. MSIX/Store installs of oh-my-posh
    # expose the CLI only through this shim - it is a 0-byte reparse point, so it is
    # preferred last, but it launches normally and is the only entry point available.
    if ($resolvedPath) { return $resolvedPath }

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

# Invoke oh-my-posh with explicit arguments and UTF-8 streams.
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
        # A hung segment must not hang the prompt; callers fall back to the plain prompt on $null.
        $timeoutMs = if ($script:PSP -and $script:PSP.PromptTimeoutMs) { [int]$script:PSP.PromptTimeoutMs } else { 5000 }
        if (-not $process.WaitForExit($timeoutMs)) {
            # Stop the whole tree: segments such as git run as child processes.
            try {
                if ($PSVersionTable.PSVersion.Major -ge 7) { $process.Kill($true) }
                else { $null = & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /T /F /PID $process.Id 2>&1 }
            }
            catch { $null = $_ }
            return $null
        }
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

# Gather context for oh-my-posh prompt rendering.
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

# Get prompt text from oh-my-posh with explicit arguments and context.
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

# Clear current and legacy oh-my-posh caches.
function Clear-OhMyPoshCaches {
    param(
        [switch]$Quiet
    )

    # Derive the Documents root from $PROFILE like the installer does, so redirected sessions stay inside their sandbox.
    $docRoot = Split-Path (Split-Path $PROFILE)
    $legacyCachePaths = @(
        (Join-Path (Get-PspCacheDir) 'omp-init.ps1')
        (Join-Path $docRoot 'PowerShell\omp-init.ps1')
        (Join-Path $docRoot 'WindowsPowerShell\omp-init.ps1')
    ) | Select-Object -Unique

    foreach ($legacyPath in $legacyCachePaths) {
        if (-not (Test-Path -LiteralPath $legacyPath)) { continue }
        try {
            $firstLine = Get-Content -LiteralPath $legacyPath -TotalCount 1 -ErrorAction Stop
            if ($firstLine -match '^# OMP_CACHE') {
                Remove-Item -LiteralPath $legacyPath -Force -ErrorAction SilentlyContinue
                if (-not $Quiet) {
                    Write-PspHost "  Removed legacy OMP init cache: $legacyPath" -ForegroundColor DarkGray
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

# Return the starter user-settings.json written by setup.ps1 and Update-Profile when none exists.
function Get-PspUserSettingsTemplate {
    @'
{
    "_comment": "User overrides for terminal, theme, and profile behavior. Only add keys you want to override.",
    "_examples": {
        "theme": { "name": "catppuccin", "url": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/v31.8.0/themes/catppuccin.omp.json" },
        "windowsTerminal": { "manage": true, "colorScheme": "One Half Dark", "cursorColor": "#ffffff" },
        "_manage_note": "set windowsTerminal.manage to false when another tool (for example a dotfiles repo) owns Windows Terminal settings.json; the profile then leaves that file alone",
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
}

# Apply user-settings.json overrides to the downloaded theme and terminal configuration; returns what the overrides contained.
function Merge-PspUserSettings {
    param(
        [AllowNull()][object]$UserSettings,
        [AllowNull()][object]$ThemeConfig,
        [AllowNull()][object]$TerminalConfig
    )
    $result = [PSCustomObject]@{ Theme = $false; WindowsTerminal = $false; Defaults = $false; Keybindings = $false; Managed = $true }
    if ($null -eq $UserSettings) { return $result }
    $userTheme = Get-PspProp $UserSettings 'theme'
    $userWt = Get-PspProp $UserSettings 'windowsTerminal'
    $userDefaults = Get-PspProp $UserSettings 'defaults'
    $userKeys = Get-PspProp $UserSettings 'keybindings'
    $result.Theme = $null -ne $userTheme
    $result.WindowsTerminal = $null -ne $userWt
    $result.Defaults = $null -ne $userDefaults
    $result.Keybindings = $null -ne $userKeys
    # windowsTerminal.manage = false hands settings.json to another tool, such as a dotfiles repo.
    if ($userWt -and (Test-PspProp $userWt 'manage') -and $userWt.manage -eq $false) { $result.Managed = $false }
    if ($ThemeConfig -and $userTheme) {
        if (-not (Get-PspProp $ThemeConfig 'theme')) { Set-PspProp $ThemeConfig 'theme' ([PSCustomObject]@{}) }
        Merge-JsonObject $ThemeConfig.theme $userTheme
        # A user-chosen theme URL comes without the pinned hash of the default theme.
        if ((Test-PspProp $userTheme 'url') -and -not (Test-PspProp $userTheme 'sha256')) { Remove-PspProp $ThemeConfig.theme 'sha256' }
    }
    if ($ThemeConfig -and $userWt) {
        if (-not (Get-PspProp $ThemeConfig 'windowsTerminal')) { Set-PspProp $ThemeConfig 'windowsTerminal' ([PSCustomObject]@{}) }
        Merge-JsonObject $ThemeConfig.windowsTerminal $userWt
    }
    if ($TerminalConfig -and $userDefaults) {
        if (-not (Get-PspProp $TerminalConfig 'defaults')) { Set-PspProp $TerminalConfig 'defaults' ([PSCustomObject]@{}) }
        Merge-JsonObject $TerminalConfig.defaults $userDefaults
    }
    if ($TerminalConfig -and $userKeys) {
        Set-PspProp $TerminalConfig 'keybindings' ([object[]]((Get-PspArray $TerminalConfig 'keybindings') + @($userKeys)))
    }
    return $result
}

# Return $true when a URL is an HTTPS raw.githubusercontent.com address (the only host themes are fetched from).
function Test-PspTrustedThemeUrl {
    param([AllowNull()][string]$Url)
    try { $uri = [Uri]$Url } catch { return $false }
    $uri.Scheme -eq 'https' -and $uri.Host -in @('raw.githubusercontent.com', 'githubusercontent.com')
}

# Download profile, theme.json and terminal-config.json from a branch, tag or commit and apply them after hash verification.
function Update-Profile {
    <#
    .SYNOPSIS
    Sync profile, theme, caches, WT settings from a branch, tag or commit.
    .EXAMPLE
    Update-Profile -Ref v1.1.0
    Install release v1.1.0; the downloads are checked against its SHA256SUMS.txt.
    .EXAMPLE
    Update-Profile
    Show the hashes of the latest main without installing anything.
    .EXAMPLE
    Update-Profile -InstallMissingTools
    Also install managed tools that are missing (winget accepts the source and package agreements).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [switch]$SkipHashCheck,
        # Branch, tag (vX.Y.Z) or commit; resolved to a commit so the printed hash can be reproduced.
        [ValidatePattern('^(?!.*\.\.)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')]
        [string]$Ref = 'main',
        # Also install missing managed tools with winget (accepting the winget source and package agreements) and the pinned PSFzf module.
        [switch]$InstallMissingTools,
        [switch]$Force
    )

    $cacheDir = Get-PspCacheDir
    # Use randomized temporary names to avoid concurrent file collisions.
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
    $overrides = [PSCustomObject]@{ Theme = $false; WindowsTerminal = $false; Defaults = $false; Keybindings = $false; Managed = $true }
    $combinedHash = $null

    # Gate downloads behind ShouldProcess so -WhatIf remains offline.
    if (-not $PSCmdlet.ShouldProcess("$($script:PSP.RepoOwner)/$($script:PSP.RepoName)@$Ref", 'Download profile/theme/terminal-config and apply updates')) { return }

    # Resolve the ref once so every file comes from the same commit; fall back to the ref itself when the GitHub API is unreachable.
    $commit = Resolve-PspCommitSha -Owner $script:PSP.RepoOwner -Repo $script:PSP.RepoName -Ref $Ref
    $sourceRef = if ($commit) { $commit } else { $Ref }

    try {
        # Phase 1: Download profile and config
        Invoke-DownloadWithRetry -Uri (Get-PspRawUrl -Ref $sourceRef -Path 'Microsoft.PowerShell_profile.ps1') -OutFile $tempProfile

        $configDownloaded = $false
        try {
            Invoke-DownloadWithRetry -Uri (Get-PspRawUrl -Ref $sourceRef -Path 'theme.json') -OutFile $tempConfig
            $configDownloaded = $true
        }
        catch {
            Write-Warning "Could not download theme.json (non-fatal): $_"
            $phaseErrors += "theme.json download: $_"
        }

        $terminalConfigDownloaded = $false
        try {
            Invoke-DownloadWithRetry -Uri (Get-PspRawUrl -Ref $sourceRef -Path 'terminal-config.json') -OutFile $tempTerminalConfig
            $terminalConfigDownloaded = $true
        }
        catch {
            Write-Warning "Could not download terminal-config.json (non-fatal): $_"
            $phaseErrors += "terminal-config.json download: $_"
        }

        # Phase 2: Verify profile hashes in both PowerShell edition directories.
        $newHash = (Get-FileHash -LiteralPath $tempProfile -Algorithm SHA256).Hash
        $_docsRoot = Split-Path (Split-Path $PROFILE)
        $_editionDirs = @(
            (Join-Path $_docsRoot 'PowerShell')
            (Join-Path $_docsRoot 'WindowsPowerShell')
        )
        $_installedProfiles = foreach ($_ed in $_editionDirs) {
            $_p = Join-Path $_ed 'Microsoft.PowerShell_profile.ps1'
            if (Test-Path -LiteralPath $_p) { $_p }
        }
        $profileChanged = $false
        if (-not $_installedProfiles) {
            # Fresh install scenario - always copy
            $profileChanged = $true
        }
        else {
            foreach ($_ip in $_installedProfiles) {
                if ((Get-FileHash -LiteralPath $_ip -Algorithm SHA256).Hash -ne $newHash) {
                    $profileChanged = $true
                    break
                }
            }
        }

        # Check if config actually changed
        $configChanged = $false
        $newConfigHash = $null
        $cachedConfig = Join-Path $cacheDir "theme.json"
        if ($configDownloaded) {
            $newConfigHash = (Get-FileHash -LiteralPath $tempConfig -Algorithm SHA256).Hash
            $oldConfigHash = if (Test-Path -LiteralPath $cachedConfig) { (Get-FileHash -LiteralPath $cachedConfig -Algorithm SHA256).Hash } else { "" }
            $configChanged = $newConfigHash -ne $oldConfigHash
        }

        # Check if terminal config actually changed
        $terminalConfigChanged = $false
        $newTerminalConfigHash = $null
        $cachedTerminalConfig = Join-Path $cacheDir "terminal-config.json"
        if ($terminalConfigDownloaded) {
            $newTerminalConfigHash = (Get-FileHash -LiteralPath $tempTerminalConfig -Algorithm SHA256).Hash
            $oldTerminalConfigHash = if (Test-Path -LiteralPath $cachedTerminalConfig) { (Get-FileHash -LiteralPath $cachedTerminalConfig -Algorithm SHA256).Hash } else { "" }
            $terminalConfigChanged = $newTerminalConfigHash -ne $oldTerminalConfigHash
        }

        if (Test-Path -LiteralPath $userSettingsPath) {
            try {
                $userSettingsHash = (Get-FileHash -LiteralPath $userSettingsPath -Algorithm SHA256).Hash
                $appliedUserSettingsHash = if (Test-Path -LiteralPath $userSettingsStatePath) {
                    (Get-Utf8FileText $userSettingsStatePath).Trim()
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

        if (-not $profileChanged -and -not $configChanged -and -not $terminalConfigChanged -and -not $userSettingsChanged -and -not $Force -and -not $InstallMissingTools) {
            Write-PspHost "Profile is up to date." -ForegroundColor Green
            return
        }

        # Combined hash verification - covers profile + config files (skipped when nothing changed upstream)
        if (-not $SkipHashCheck -and ($profileChanged -or $configChanged -or $terminalConfigChanged)) {
            $configLabel = if ($configDownloaded) { $newConfigHash } else { "NONE" }
            $terminalLabel = if ($terminalConfigDownloaded) { $newTerminalConfigHash } else { "NONE" }
            $combinedHash = Get-CombinedSha256 -Parts @("profile:$newHash", "theme:$configLabel", "terminal:$terminalLabel")

            # A release tag is checked against the SHA256SUMS.txt published with that release.
            $releaseSums = $null
            if (-not $ExpectedSha256) { $releaseSums = Get-PspReleaseChecksums -Owner $script:PSP.RepoOwner -Repo $script:PSP.RepoName -Tag $Ref }
            if ($releaseSums) {
                $releaseChecks = @(
                    @('Microsoft.PowerShell_profile.ps1', $newHash, $true),
                    @('theme.json', $newConfigHash, $configDownloaded),
                    @('terminal-config.json', $newTerminalConfigHash, $terminalConfigDownloaded)
                )
                foreach ($check in $releaseChecks) {
                    if (-not $check[2]) { throw "$($check[0]) could not be downloaded, so release $Ref cannot be verified." }
                    if ($releaseSums[$check[0]] -ne $check[1]) { throw "$($check[0]) does not match the SHA256SUMS.txt of release $Ref." }
                }
                Write-PspHost "Downloaded files match the SHA256SUMS.txt of release $Ref." -ForegroundColor Green
            }
            elseif (-not $ExpectedSha256) {
                Write-PspHost "Downloaded file hashes (computed over what was just fetched from $sourceRef):" -ForegroundColor Yellow
                Write-PspHost "  profile.ps1:       $newHash" -ForegroundColor Yellow
                Write-PspHost ("  theme.json:        {0}" -f $(if ($configDownloaded) { $newConfigHash } else { '(not downloaded)' })) -ForegroundColor Yellow
                Write-PspHost ("  terminal-config:   {0}" -f $(if ($terminalConfigDownloaded) { $newTerminalConfigHash } else { '(not downloaded)' })) -ForegroundColor Yellow
                Write-PspHost "  combined:          $combinedHash" -ForegroundColor Yellow
                Write-PspHost "Release tags (Update-Profile -Ref vX.Y.Z) are verified automatically against the release's SHA256SUMS.txt." -ForegroundColor DarkYellow
                Write-PspHost "For a branch or commit, check the commit out-of-band first: https://github.com/$($script:PSP.RepoOwner)/$($script:PSP.RepoName)/commit/$sourceRef" -ForegroundColor DarkYellow
                $rerunTools = if ($InstallMissingTools) { ' -InstallMissingTools' } else { '' }
                throw "Hash input required. Re-run with: Update-Profile -Ref $sourceRef -ExpectedSha256 '$combinedHash'$rerunTools (or -SkipHashCheck)."
            }
            elseif ($combinedHash -ne $ExpectedSha256.ToUpperInvariant()) {
                throw "Combined hash mismatch. Expected $($ExpectedSha256.ToUpperInvariant()), got $combinedHash."
            }
        }

        # Phase 3: Copy changed profiles to existing edition directories and create only the current edition directory.
        if ($profileChanged) {
            if ($PSCmdlet.ShouldProcess($PROFILE, "Replace profile with downloaded version (hash: $newHash)")) {
                $docsRoot = Split-Path (Split-Path $PROFILE)
                $profileDirs = @(
                    Join-Path $docsRoot "PowerShell"
                    Join-Path $docsRoot "WindowsPowerShell"
                )
                $currentEditionDir = Split-Path $PROFILE
                if (-not (Test-Path -LiteralPath $currentEditionDir)) {
                    try {
                        New-Item -ItemType Directory -Path $currentEditionDir -Force | Out-Null
                        Write-PspHost "Created profile directory: $currentEditionDir" -ForegroundColor DarkGray
                    }
                    catch {
                        Write-Warning "Failed to create profile directory $currentEditionDir`: $_"
                    }
                }
                $copySuccess = 0
                $copyFailed = @()
                foreach ($dir in $profileDirs) {
                    $target = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
                    if (Test-Path -LiteralPath $dir) {
                        # Back up the current profile before overwriting it, keeping the latest five
                        # (profile.original.ps1 is never matched, so the first-install copy survives).
                        if (Test-Path -LiteralPath $target -PathType Leaf) {
                            try {
                                $backupStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                                Copy-Item -LiteralPath $target -Destination (Join-Path $dir "oldprofile.$backupStamp.ps1") -Force -ErrorAction Stop
                                Get-ChildItem -LiteralPath $dir -Filter 'oldprofile*.ps1' -ErrorAction SilentlyContinue |
                                    Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
                                    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
                            }
                            catch { Write-Warning "Could not back up $target before update: $_" }
                        }
                        try {
                            Copy-Item -LiteralPath $tempProfile -Destination $target -Force -ErrorAction Stop
                            $copySuccess++
                        }
                        catch {
                            $copyFailed += $target
                            Write-Warning "Failed to copy profile to ${target}: $_"
                        }
                    }
                }
                if ($copySuccess -gt 0 -and $copyFailed.Count -eq 0) {
                    Write-PspHost "Profile updated ($copySuccess locations)." -ForegroundColor Green
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
            Write-PspHost "Profile .ps1 unchanged, applying config updates..." -ForegroundColor Cyan
        }

        # Load config for remaining phases.
        $config = $null
        if ($configDownloaded) {
            try { $config = Read-JsonFile $tempConfig }
            catch { Write-Verbose "Failed to parse downloaded config: $_" }
        }
        elseif (Test-Path -LiteralPath $cachedConfig) {
            try { $config = Read-JsonFile $cachedConfig }
            catch {
                Write-Warning "Corrupt cached config removed: $cachedConfig"
                Remove-Item -LiteralPath $cachedConfig -Force -ErrorAction SilentlyContinue
            }
        }

        # Load terminal config for the Windows Terminal phase.
        $terminalConfig = $null
        if ($terminalConfigDownloaded) {
            try { $terminalConfig = Read-JsonFile $tempTerminalConfig }
            catch { Write-Verbose "Failed to parse downloaded terminal config: $_" }
        }
        elseif (Test-Path -LiteralPath $cachedTerminalConfig) {
            try { $terminalConfig = Read-JsonFile $cachedTerminalConfig }
            catch {
                Write-Warning "Corrupt cached terminal config removed: $cachedTerminalConfig"
                Remove-Item -LiteralPath $cachedTerminalConfig -Force -ErrorAction SilentlyContinue
            }
        }

        # Apply user-settings.json overrides (never downloaded, never overwritten)
        if (Test-Path -LiteralPath $userSettingsPath) {
            try {
                $userSettings = Read-JsonFile $userSettingsPath
                $userSettingsParsed = $true
                $overrides = Merge-PspUserSettings -UserSettings $userSettings -ThemeConfig $config -TerminalConfig $terminalConfig
                Write-PspHost "User overrides applied from user-settings.json" -ForegroundColor DarkGray
            }
            catch {
                # Without the file it is unknown whether another tool owns Windows Terminal's settings.json, so leave it alone.
                $overrides.Managed = $false
                Write-Warning "Failed to parse user-settings.json: $_. Windows Terminal settings are left alone until it parses."
            }
        }
        else {
            # Create the same starter user-settings template used by setup.ps1.
            if ($PSCmdlet.ShouldProcess($userSettingsPath, "Create user-settings.json template")) {
                if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
                Write-Utf8FileAtomic -Path $userSettingsPath -Content (Get-PspUserSettingsTemplate)
                Write-PspHost "Created user-settings.json template in $cacheDir" -ForegroundColor Green
            }
        }

        # Phase 4: OMP theme sync + orphan cleanup
        if ($config -and $config.theme -and $config.theme.name -and [string]$config.theme.name -notmatch '^[A-Za-z0-9._-]+$') {
            Write-Warning "Ignoring OMP theme with an invalid name: $($config.theme.name)"
            $phaseErrors += "OMP theme name invalid: $($config.theme.name)"
        }
        elseif ($config -and $config.theme -and $config.theme.name) {
            $themeName = [string]$config.theme.name
            $themeUrl = [string](Get-PspProp $config.theme 'url')
            $themeSha256 = [string](Get-PspProp $config.theme 'sha256')
            $localThemePath = Join-Path $cacheDir "$themeName.omp.json"
            $currentThemeReady = $false
            if (Test-Path -LiteralPath $localThemePath) {
                try {
                    if ($null -eq (Read-JsonFile $localThemePath)) { throw 'Theme file is empty' }
                    $currentThemeReady = -not $themeSha256 -or ((Get-FileHash -LiteralPath $localThemePath -Algorithm SHA256).Hash -eq $themeSha256.ToUpperInvariant())
                }
                catch {
                    Write-Warning "Existing OMP theme '$themeName' is invalid at '$localThemePath': $_"
                }
            }

            $themeOverrideChanged = $userSettingsChanged -and $overrides.Theme
            $shouldDownloadTheme = $Force -or (-not $currentThemeReady) -or $configChanged -or $themeOverrideChanged
            $themeUrlTrusted = $false
            if ($themeUrl) {
                $themeUrlTrusted = Test-PspTrustedThemeUrl $themeUrl
                if (-not $themeUrlTrusted) { Write-Warning "Skipping OMP theme download from untrusted URL: $themeUrl" }
            }
            if ($shouldDownloadTheme -and $themeUrl -and $themeUrlTrusted) {
                if ($PSCmdlet.ShouldProcess($localThemePath, "Download OMP theme '$themeName'")) {
                    $tempThemePath = Join-Path $cacheDir ("{0}.{1}.download" -f $themeName, [System.IO.Path]::GetRandomFileName())
                    try {
                        Invoke-DownloadWithRetry -Uri $themeUrl -OutFile $tempThemePath
                        if ($null -eq (Read-JsonFile $tempThemePath)) { throw 'Downloaded theme file is empty' }
                        if ($themeSha256) {
                            $actualThemeHash = (Get-FileHash -LiteralPath $tempThemePath -Algorithm SHA256).Hash
                            if ($actualThemeHash -ne $themeSha256.ToUpperInvariant()) { throw "Theme hash mismatch (expected $themeSha256, got $actualThemeHash)" }
                        }
                        Move-Item -LiteralPath $tempThemePath -Destination $localThemePath -Force
                        Write-PspHost "OMP theme '$themeName' updated." -ForegroundColor Green
                        $currentThemeReady = $true
                    }
                    catch {
                        Write-Warning "Failed to download/validate OMP theme: $_"
                        $phaseErrors += "OMP theme download: $_"
                    }
                    finally {
                        Remove-Item -LiteralPath $tempThemePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            elseif ($shouldDownloadTheme -and -not $themeUrl -and -not $currentThemeReady) {
                Write-Warning "OMP theme '$themeName' is missing locally and no download URL is configured."
                $phaseErrors += "OMP theme missing URL: $themeName"
            }

            if ($currentThemeReady) {
                $ompFiles = Get-ChildItem -LiteralPath $cacheDir -Filter "*.omp.json" -ErrorAction SilentlyContinue
                foreach ($file in $ompFiles) {
                    if ($file.Name -ne "$themeName.omp.json") {
                        if ($PSCmdlet.ShouldProcess($file.FullName, "Remove orphaned OMP theme")) {
                            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                            Write-PspHost "Removed orphaned theme: $($file.Name)" -ForegroundColor DarkGray
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
                    if (Test-Path -LiteralPath $cachePath) {
                        if ($PSCmdlet.ShouldProcess($cachePath, "Invalidate $($tool.Name) init cache")) {
                            Remove-Item -LiteralPath $cachePath -Force -ErrorAction SilentlyContinue
                            Write-PspHost "$($tool.Name) init cache cleared." -ForegroundColor DarkGray
                        }
                    }
                }
            }
        }

        # Phase 6: Synchronize every installed Windows Terminal variant through the change-recording writer.
        $terminalOverridesChanged = $userSettingsChanged -and ($overrides.WindowsTerminal -or $overrides.Defaults -or $overrides.Keybindings)
        if (-not $overrides.Managed) {
            Write-PspHost "Windows Terminal settings left alone (windowsTerminal.manage = false, or user-settings.json could not be parsed)." -ForegroundColor DarkGray
        }
        elseif (($Force -or $profileChanged -or $configChanged -or $terminalConfigChanged -or $terminalOverridesChanged) -and (($config -and $config.windowsTerminal) -or $terminalConfig)) {
            $manifestPath = Join-Path $cacheDir 'wt-changes.json'
            foreach ($wtSettingsPath in @(Get-WindowsTerminalSettingsPaths)) {
                try {
                    $wtArgs = @{
                        Path            = $wtSettingsPath
                        ManifestPath    = $manifestPath
                        Defaults        = Get-PspProp $terminalConfig 'defaults'
                        WindowsTerminal = Get-PspProp $config 'windowsTerminal'
                        Keybindings     = Get-PspArray $terminalConfig 'keybindings'
                        NoLogo          = $true
                    }
                    if (Update-WindowsTerminalSettingsFile @wtArgs) {
                        Write-PspHost "Windows Terminal settings updated: $wtSettingsPath" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Failed to update Windows Terminal settings ($wtSettingsPath): $_"
                    $phaseErrors += "Windows Terminal sync: $_"
                }
            }
        }

        # Phase 7: Managed tools are reported, and installed only on request.
        $missing = @($script:ProfileTools | Where-Object { -not (Get-ProfileToolExecutablePath -Tool $_) })
        $psfzfMissing = -not (Get-Module -ListAvailable -Name PSFzf)
        if (($missing.Count -gt 0 -or $psfzfMissing) -and -not $InstallMissingTools) {
            $names = @($missing | ForEach-Object { $_.Name }) + @(if ($psfzfMissing) { 'PSFzf (module)' })
            Write-PspHost ("Not installed: {0}. Run 'Update-Profile -InstallMissingTools' to install them (winget accepts the source and package agreements for you)." -f ($names -join ', ')) -ForegroundColor DarkYellow
        }
        elseif ($InstallMissingTools -and (Get-Command winget -ErrorAction Ignore)) {
            $installedTools = @()
            foreach ($tool in $missing) {
                if ($PSCmdlet.ShouldProcess($tool.Name, "Install via winget (accepts the winget source and package agreements)")) {
                    Write-PspHost "  Installing $($tool.Name)..." -ForegroundColor Yellow
                    winget install -e --id $tool.Id --accept-source-agreements --accept-package-agreements
                    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335185 -or $LASTEXITCODE -eq -1978335189) {
                        Write-PspHost "  $($tool.Name) installed." -ForegroundColor Green
                        $installedTools += $tool
                    }
                    else {
                        Write-Warning "  $($tool.Name) install may have failed (exit code: $LASTEXITCODE)"
                    }
                }
            }
            # Refresh PATH so newly installed tools are found
            if ($installedTools.Count -gt 0) {
                Update-SessionPathFromRegistry
            }
            if ((Get-Command fzf -ErrorAction Ignore) -and $psfzfMissing) {
                $psfzfVersion = (Get-PspComponentPins).PSFzf
                if ($PSCmdlet.ShouldProcess("PSFzf $psfzfVersion", 'Install PowerShell module from the PowerShell Gallery')) {
                    try {
                        Install-Module -Name PSFzf -RequiredVersion $psfzfVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-PspHost "  PSFzf $psfzfVersion installed." -ForegroundColor Green
                    }
                    catch { Write-Warning "  Failed to install PSFzf: $_" }
                }
            }
            # Invalidate init caches only for tools that were actually installed
            foreach ($tool in $installedTools) {
                if ($tool.Cache) {
                    Remove-Item -LiteralPath (Join-Path $cacheDir $tool.Cache) -ErrorAction SilentlyContinue
                }
            }
        }
        elseif ($InstallMissingTools) {
            Write-Warning "winget not found; cannot install missing tools."
        }

        # Save configs to cache.
        if ($configChanged) {
            if ($PSCmdlet.ShouldProcess($cachedConfig, "Save theme.json to cache")) {
                Copy-Item -LiteralPath $tempConfig -Destination $cachedConfig -Force
            }
        }
        if ($terminalConfigChanged) {
            if ($PSCmdlet.ShouldProcess($cachedTerminalConfig, "Save terminal-config.json to cache")) {
                Copy-Item -LiteralPath $tempTerminalConfig -Destination $cachedTerminalConfig -Force
            }
        }
        if (Test-Path -LiteralPath $userSettingsPath) {
            if ($userSettingsParsed -and $userSettingsHash -and $phaseErrors.Count -eq 0) {
                if ($PSCmdlet.ShouldProcess($userSettingsStatePath, 'Save applied user-settings fingerprint')) {
                    Write-Utf8FileAtomic -Path $userSettingsStatePath -Content $userSettingsHash
                }
            }
        }
        elseif (Test-Path -LiteralPath $userSettingsStatePath) {
            if ($PSCmdlet.ShouldProcess($userSettingsStatePath, 'Remove stale user-settings fingerprint')) {
                Remove-Item -LiteralPath $userSettingsStatePath -Force -ErrorAction SilentlyContinue
            }
        }

        # Error summary
        if ($phaseErrors.Count -gt 0) {
            Write-PspHost ""
            Write-PspHost "Update completed with $($phaseErrors.Count) issue(s):" -ForegroundColor Yellow
            foreach ($err in $phaseErrors) {
                Write-PspHost "  - $err" -ForegroundColor Yellow
            }
        }

        # Record exactly what was applied: the update-check baseline and psp-doctor read it.
        if ($profileActuallyUpdated -and -not $WhatIfPreference) {
            $newVersion = [regex]::Match((Get-Utf8FileText $tempProfile), "(?m)^\s*Version\s*=\s*'([^']+)'").Groups[1].Value
            try {
                Set-PspInstallState -CacheDir $cacheDir -Version $newVersion -Ref $Ref -Commit $commit -BundleSha256 $combinedHash -Source 'remote'
                if ($commit) { Write-Utf8FileAtomic -Path (Join-Path $cacheDir 'applied-commit.sha') -Content $commit }
            }
            catch { Write-Verbose "Could not record install state: $_" }
        }

        # Restart when any profile or configuration content loaded by the session changed.
        $anyRuntimeChange = $profileActuallyUpdated -or $configChanged -or $terminalConfigChanged -or $userSettingsChanged
        if ($anyRuntimeChange) {
            $reason = if ($profileActuallyUpdated) { 'Profile updated' }
                      elseif ($configChanged) { 'Theme config updated' }
                      elseif ($terminalConfigChanged) { 'Terminal config updated' }
                      else { 'User settings updated' }
            # Clean up temp files here too: Restart-TerminalToApply calls exit, which can bypass the finally block.
            Remove-Item -LiteralPath $tempProfile, $tempConfig, $tempTerminalConfig -ErrorAction SilentlyContinue
            Restart-TerminalToApply -Message "$reason. Restarting terminal..."
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Unable to check for `$profile updates: $_"
    }
    finally {
        Remove-Item -LiteralPath $tempProfile -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempConfig -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempTerminalConfig -ErrorAction SilentlyContinue
    }
}

# Check for new PowerShell (Core) releases and update via winget
function Update-PowerShell {
    <#
    .SYNOPSIS
    Check for new PowerShell releases.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-PspHost "Windows PowerShell 5.1 is updated via Windows Update, not winget." -ForegroundColor Yellow
        Write-PspHost "This command checks for PowerShell 7+ (Core) updates only." -ForegroundColor Yellow
        return
    }
    try {
        Write-PspHost "Checking for PowerShell updates..." -ForegroundColor Cyan
        $currentVersion = $PSVersionTable.PSVersion
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $headers = @{}
        if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl -TimeoutSec 10 -Headers $headers -UseBasicParsing
        if (-not $latestReleaseInfo.tag_name) { Write-Error "Invalid GitHub API response (missing tag_name)."; return }
        $latestVersionStr = $latestReleaseInfo.tag_name.Trim('v') -replace '-.*$', ''
        $latestVersion = [version]$latestVersionStr
        if ($currentVersion -lt $latestVersion) {
            if ($PSCmdlet.ShouldProcess("PowerShell (Core) $currentVersion -> $latestVersion", 'winget upgrade')) {
                Write-PspHost "Updating PowerShell ($currentVersion -> $latestVersion)..." -ForegroundColor Yellow
                Start-Process -FilePath (Get-PspShellPath) -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -NoNewWindow
                Write-PspHost "PowerShell update started. Please restart your shell when complete." -ForegroundColor Magenta
            }
        }
        else {
            Write-PspHost "Your PowerShell is up to date." -ForegroundColor Green
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
    <#
    .SYNOPSIS
    Upgrade winget-managed tools.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Get-Command winget -ErrorAction Ignore)) {
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
        Write-PspHost "No profile tools detected. Run Update-Profile to install them." -ForegroundColor Yellow
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
                Write-PspHost "Skipping $($tool.Name) update to preserve direct/MSI install at $($ompInstall.Path)." -ForegroundColor DarkGray
                $preserved++
                continue
            }
        }

        if (-not $PSCmdlet.ShouldProcess($tool.Name, 'winget upgrade')) { continue }
        # Capture pre-upgrade version
        $oldVer = Get-ProfileToolVersionText -Tool $tool -ExecutablePath $toolPath
        Write-PspHost "Updating $($tool.Name)..." -ForegroundColor Cyan
        winget upgrade --id $tool.Id --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            # Refresh PATH after install.
            Update-SessionPathFromRegistry
            $newToolPath = Get-ProfileToolExecutablePath -Tool $tool
            $newVer = if ($newToolPath) { Get-ProfileToolVersionText -Tool $tool -ExecutablePath $newToolPath } else { $null }
            if ($newVer -and $oldVer -and $newVer -ne $oldVer) {
                Write-PspHost "  $($tool.Name): $oldVer -> $newVer" -ForegroundColor Green
                if ($tool.Cache) {
                    Remove-Item -LiteralPath (Join-Path (Get-PspCacheDir) $tool.Cache) -ErrorAction SilentlyContinue
                }
                $upgraded++
            }
            else {
                Write-PspHost "  $($tool.Name): already up to date ($oldVer)" -ForegroundColor DarkGray
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
            Write-PspHost "All winget-managed tools are up to date. $preserved tool(s) were preserved." -ForegroundColor Green
        }
        else {
            Write-PspHost "All tools are up to date." -ForegroundColor Green
        }
    }
}

# Return the executable of the running PowerShell by absolute path; Store installs, which cannot be started by path, use their app alias.
function Get-PspShellPath {
    $exe = (Get-Process -Id $PID).Path
    if ($exe -and $exe -notmatch '\\WindowsApps\\') { return $exe }
    if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
}

# Restart interactively in Windows Terminal when available and fall back to pwsh or powershell.
function Restart-TerminalToApply {
    param([string]$Message = "Update applied. Restarting terminal...")
    if (-not $script:PSP.IsInteractive) { return }
    if ($WhatIfPreference) { return }
    $dir = (Get-Location).Path
    if (-not $dir -or -not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) {
        $dir = [Environment]::GetFolderPath('UserProfile')
    }
    $shellExe = Get-PspShellPath
    Write-PspHost $Message -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-PspHost "Press Enter to restart (or close this window to cancel)..." -ForegroundColor Yellow
    try { $null = Read-Host } catch { $null = $_ }
    $wt = Get-Command wt.exe -CommandType Application -ErrorAction Ignore | Select-Object -First 1
    if ($wt) {
        Start-Process -FilePath $wt.Source -ArgumentList (ConvertTo-NativeArgumentLine @('-w', '0', '-d', $dir, $shellExe, '-NoExit'))
    }
    else {
        Start-Process -FilePath $shellExe -ArgumentList "-NoExit" -WorkingDirectory $dir
    }
    exit
}

# Clear the user temp folder and the legacy WinINet (Internet Explorer) cache; -IncludeSystemCaches adds Windows\Temp and Windows\Prefetch.
function Clear-Cache {
    <#
    .SYNOPSIS
    Clear user/system temp caches.
    .EXAMPLE
    Clear-Cache -WhatIf
    Show which folders would be emptied.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$IncludeSystemCaches
    )

    # Folders a misconfigured TEMP could point at; deleting their contents would be catastrophic.
    $neverClear = @(
        [Environment]::GetFolderPath('UserProfile'), [Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('Desktop'),
        $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA, $env:APPDATA
    ) | Where-Object { $_ } | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }

    $bases = @()
    $userTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
    $isDriveRoot = $userTemp -eq ([System.IO.Path]::GetPathRoot($userTemp)).TrimEnd('\')
    # A temp folder is named Temp or Tmp; Remote Desktop sessions use a numbered folder inside it (Temp\2).
    $tempLeaf = Split-Path -Leaf $userTemp
    $looksLikeTemp = $tempLeaf -match '^(?i)te?mp$' -or ($tempLeaf -match '^\d+$' -and (Split-Path -Leaf (Split-Path -Parent $userTemp)) -match '^(?i)te?mp$')
    if ($isDriveRoot -or $neverClear -contains $userTemp -or -not $looksLikeTemp) {
        Write-Warning "Skipping the user temp folder: '$userTemp' does not look like a temp folder (check `$env:TEMP and `$env:TMP)."
    }
    else { $bases += @{ Name = 'User Temp'; Base = $userTemp; Recurse = $true } }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $bases += @{ Name = 'Legacy Internet Explorer (WinINet) cache'; Base = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache'); Recurse = $true } }
    if ($IncludeSystemCaches -and -not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $bases += @{ Name = 'Windows Temp (all users, needs admin)'; Base = (Join-Path $env:SystemRoot 'Temp'); Recurse = $true }
        $bases += @{ Name = 'Windows Prefetch (all users, needs admin)'; Base = (Join-Path $env:SystemRoot 'Prefetch'); Recurse = $false }
    }

    foreach ($target in $bases) {
        if (-not (Test-Path -LiteralPath $target.Base -PathType Container)) { continue }
        if (-not $PSCmdlet.ShouldProcess($target.Base, "Delete the contents of $($target.Name)")) { continue }
        $removed = 0
        $skipped = 0
        foreach ($child in @(Get-ChildItem -LiteralPath $target.Base -Force -ErrorAction SilentlyContinue)) {
            if (-not $target.Recurse -and $child.PSIsContainer) { continue }
            # Keep going past files in use; whatever is still there afterwards counts as skipped.
            Remove-Item -LiteralPath $child.FullName -Recurse:$target.Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $child.FullName) { $skipped++ } else { $removed++ }
        }
        Write-PspHost ("Cleared {0}: {1} item(s) removed, {2} in use or protected." -f $target.Name, $removed, $skipped) -ForegroundColor Green
    }
}

# Show the last command's execution time from bounded PowerShell history.
function duration {
    <#
    .SYNOPSIS
    Show elapsed time of the last command.
    #>
    $last = Get-History -Count 1 -ErrorAction SilentlyContinue
    if (-not $last) {
        Write-PspHost 'No history yet.' -ForegroundColor Yellow
        return
    }
    $span = $last.EndExecutionTime - $last.StartExecutionTime
    $cmd = $last.CommandLine
    if ($cmd.Length -gt 60) { $cmd = $cmd.Substring(0, 57) + '...' }
    $secs = [math]::Round($span.TotalSeconds, 3)
    Write-PspHost ("  {0}" -f $cmd) -ForegroundColor DarkGray
    Write-PspHost ("  {0}s  ({1:hh\:mm\:ss\.fff})" -f $secs, $span) -ForegroundColor Cyan
}

# Move back through the bounded directory history without re-adding consumed entries.
function cdb {
    <#
    .SYNOPSIS
    Cd back N entries in history (default 1).
    #>
    [CmdletBinding()]
    param([int]$N = 1)
    if (-not $script:PSP -or -not $script:PSP.PwdHistory -or $script:PSP.PwdHistory.Count -eq 0) {
        Write-PspHost 'No directory history yet.' -ForegroundColor Yellow
        return
    }
    if ($N -lt 1 -or $N -gt $script:PSP.PwdHistory.Count) {
        Write-PspHost ("History has {0} entries; N must be 1..{0}." -f $script:PSP.PwdHistory.Count) -ForegroundColor Yellow
        return
    }
    $target = $script:PSP.PwdHistory[$N - 1]
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Warning "Directory no longer exists: $target (marked with '!' in cdh). Run 'cdh' to see the stack."
        return
    }
    # Pop the consumed entries (0..N-1).
    for ($i = 0; $i -lt $N; $i++) { $script:PSP.PwdHistory.RemoveAt(0) }
    # Suppress auto-push on the Set-Location that follows - we already cleaned up the stack.
    $script:PSP.SuppressPwdHistoryPush = $true
    Set-Location -LiteralPath $target
}

# List directory history entries addressable through cdb.
function cdh {
    <#
    .SYNOPSIS
    List the cd history stack.
    #>
    if (-not $script:PSP -or -not $script:PSP.PwdHistory -or $script:PSP.PwdHistory.Count -eq 0) {
        Write-PspHost 'No directory history yet.' -ForegroundColor Yellow
        return
    }
    $i = 1
    foreach ($d in $script:PSP.PwdHistory) {
        $exists = Test-Path -LiteralPath $d
        $color = if ($exists) { 'White' } else { 'DarkGray' }
        $mark = if ($exists) { ' ' } else { '!' }
        Write-PspHost ("  [{0}]{1} {2}" -f $i, $mark, $d) -ForegroundColor $color
        $i++
    }
}

# Return a directory's .psprc.ps1 as its SHA-256 and text, read once so the hash describes exactly what runs ($null when it has none).
function Get-PspRcContent {
    param([Parameter(Mandatory)][string]$Directory)
    $rc = Join-Path $Directory '.psprc.ps1'
    if (-not (Test-Path -LiteralPath $rc -PathType Leaf)) { return $null }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $rc).ProviderPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
    finally { $sha.Dispose() }
    $text = ''
    if ($bytes.Length -gt 0) {
        $encoding = Get-PspTextEncoding -Bytes $bytes
        $skip = $encoding.GetPreamble().Length
        $text = $encoding.GetString($bytes, $skip, $bytes.Length - $skip)
    }
    [PSCustomObject]@{ Hash = $hash; Text = $text }
}

# Return the SHA-256 of a directory's .psprc.ps1, or '' when it has none.
function Get-PspRcHash {
    param([Parameter(Mandatory)][string]$Directory)
    $content = Get-PspRcContent -Directory $Directory
    if ($content) { $content.Hash } else { '' }
}

# Return a script block for approved .psprc.ps1 text that sees $PSScriptRoot and $PSCommandPath as a dot-sourced file would.
function New-PspRcScriptBlock {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Path)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "$Path does not parse: $($parseErrors[0].Message)" }
    # The engine clears both variables for in-memory code, so set them after any param block or using statements (which
    # must come first), on the same line so error line numbers still match the file.
    $offset = 0
    if ($ast.ParamBlock) { $offset = $ast.ParamBlock.Extent.EndOffset }
    foreach ($statement in $ast.UsingStatements) { $offset = [Math]::Max($offset, $statement.Extent.EndOffset) }
    $prelude = "`$PSScriptRoot = '{0}'; `$PSCommandPath = '{1}'; " -f ((Split-Path -Parent $Path) -replace "'", "''"), ($Path -replace "'", "''")
    if ($offset -gt 0) { $prelude = "; $prelude" }
    [scriptblock]::Create($Text.Insert($offset, $prelude))
}

# Run shared prompt hooks and trusted per-directory profiles for both prompt implementations.
function Invoke-PromptStage {
    if (-not $script:PSP) { return }
    Invoke-ProfileHook -EventName 'PrePrompt'
    try {
        $current = $PWD.ProviderPath
        if (-not $current) { return }
        if ($current -eq $script:PSP.LastPwd) { return }
        # Push the previous directory unless cdb is consuming the history stack.
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
        if (-not (Test-Path -LiteralPath $rc -PathType Leaf)) { return }
        $trusted = $script:PSP.TrustedDirs | Where-Object { $_ -ieq $current } | Select-Object -First 1
        if (-not $trusted) {
            Write-PspHost ".psprc.ps1 found in this directory. Review it, then run Add-TrustedDirectory to auto-load it." -ForegroundColor Yellow
            return
        }
        # Trust covers the file content that was approved (like direnv): any later change, for example from git pull, needs a new approval.
        $approved = [string]$script:PSP.TrustedRcHashes[$trusted]
        $rcContent = Get-PspRcContent -Directory $current
        if (-not $approved -or -not $rcContent -or $approved -ne $rcContent.Hash) {
            Write-Warning ".psprc.ps1 in $current was not run: it changed since it was approved, or was never approved. Review it, then run Add-TrustedDirectory to approve this version."
            return
        }
        # Run the text that was hashed, so the file cannot change between the check and the run.
        try { . (New-PspRcScriptBlock -Text $rcContent.Text -Path $rc) }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning ".psprc.ps1 failed: $($_.Exception.Message)"
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "prompt stage: $($_.Exception.Message)"
    }
}

# Return the plain prompt text, also used when oh-my-posh fails or times out.
function Get-PspPlainPrompt {
    if ($script:PSP.IsAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}

function prompt {
    Invoke-PromptStage
    Get-PspPlainPrompt
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}{1}" -f $PSVersionTable.PSVersion.ToString(), $script:PSP.AdminSuffix

# Resolve the editor lazily from the customizable $script:EditorPriority list.
if ($null -eq $script:EditorPriority) {
    $script:EditorPriority = @('code', 'notepad')
}
$script:ResolvedEditor = $null
# Store default arguments parsed from the resolved editor command.
$script:ResolvedEditorArgs = @()

# Resolve preferred editor from EditorPriority or env EDITOR (used by edit/Edit-Profile)
function Resolve-PreferredEditor {
    if ($script:ResolvedEditor -and (Get-Command $script:ResolvedEditor -CommandType Application -ErrorAction Ignore)) {
        return $script:ResolvedEditor
    }

    $candidates = @()
    if ($env:EDITOR) { $candidates += $env:EDITOR }
    $candidates += @($script:EditorPriority)

    foreach ($candidate in ($candidates | Where-Object { $_ })) {
        # Split editor flags from the executable when the full candidate is not a command.
        $exe = $candidate
        $extraArgs = @()
        if (-not (Get-Command $candidate -CommandType Application -ErrorAction Ignore) -and $candidate -match '\s') {
            $tok = $candidate -split '\s+'
            $exe = $tok[0]
            $extraArgs = @($tok | Select-Object -Skip 1)
        }
        if (Get-Command $exe -CommandType Application -ErrorAction Ignore) {
            $script:ResolvedEditor = $exe
            $script:ResolvedEditorArgs = $extraArgs
            return $script:ResolvedEditor
        }
    }

    $script:ResolvedEditor = 'notepad'
    $script:ResolvedEditorArgs = @()
    return $script:ResolvedEditor
}

# Open files with preferred editor (alias: edit)
function edit {
    <#
    .SYNOPSIS
    Open file in preferred editor.
    #>
    $editor = Resolve-PreferredEditor
    & $editor @script:ResolvedEditorArgs @args
}

# Quick Access to Editing the Profile
function Edit-Profile {
    <#
    .SYNOPSIS
    Open profile in preferred editor.
    #>
    edit $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Create file or update its timestamp
function touch {
    <#
    .SYNOPSIS
    Create file or update timestamp.
    #>
    param([Parameter(ValueFromRemainingArguments)][string[]]$Files)
    if (-not $Files) { Write-Error "Usage: touch <file> [file2 ...]"; return }
    foreach ($file in $Files) {
        if (Test-Path -LiteralPath $file) {
            (Get-Item -LiteralPath $file).LastWriteTime = Get-Date
        }
        else {
            New-Item -ItemType File -Path $file -Force | Out-Null
        }
    }
}
# Recursive file search by name
function ff($name) {
    <#
    .SYNOPSIS
    Find files recursively.
    #>
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

# Network Utilities
function pubip {
    <#
    .SYNOPSIS
    Public IP.
    #>
    try {
        (Invoke-WebRequest https://ifconfig.me/ip -TimeoutSec 10 -UseBasicParsing).Content
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to retrieve public IP: $_"
    }
}

# Download WinUtil from https://christitus.com/win into memory; it runs only with a hash pin or -Force, after confirmation.
function winutil {
    <#
    .SYNOPSIS
    Fetch Chris Titus WinUtil (safe-by-default; -ExpectedSha256/-Force to run).
    .EXAMPLE
    winutil
    Download WinUtil and print its SHA-256 without running it.
    .EXAMPLE
    winutil -ExpectedSha256 <hash>
    Run it only if it still has that hash.
    #>
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
    if (($ExpectedSha256 -or $Force) -and -not $script:PSP.IsAdmin) {
        # Run unelevated, WinUtil relaunches itself as administrator from its latest release, which the hash check never saw.
        Write-Error 'Run winutil from an elevated shell (open one with: admin). Unelevated, WinUtil relaunches itself as administrator from its latest, unchecked release.'
        return
    }
    try {
        # The bytes stay in memory between hashing and execution, so nothing on disk can be swapped in after the check.
        $response = Invoke-WebRequest -Uri 'https://christitus.com/win' -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
        $bytes = $response.RawContentStream.ToArray()
        if ($bytes.Length -eq 0) { throw 'Downloaded WinUtil script is empty.' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
        finally { $sha.Dispose() }
        Write-PspHost "Source: https://christitus.com/win"
        Write-PspHost "SHA256: $actualHash" -ForegroundColor Cyan
        $downloadLabel = "WinUtil script from https://christitus.com/win (SHA256: $actualHash)"
        $offset = if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { 3 } else { 0 }
        $code = [System.Text.Encoding]::UTF8.GetString($bytes, $offset, $bytes.Length - $offset)
        if ($ExpectedSha256) {
            if ($actualHash -ine $ExpectedSha256.Trim()) {
                Write-Error "SHA256 mismatch. Expected: $ExpectedSha256. Actual: $actualHash. Aborting."
                return
            }
            if (-not $PSCmdlet.ShouldProcess($downloadLabel, 'Execute downloaded WinUtil script (hash matched)')) {
                return
            }
            Write-PspHost "SHA256 matched expected value. Executing..." -ForegroundColor Green
            & ([scriptblock]::Create($code))
            return
        }
        if ($Force) {
            Write-Warning 'Executing an external script without hash pinning. Review the source and SHA256 first.'
            if (-not $PSCmdlet.ShouldProcess($downloadLabel, 'Execute downloaded WinUtil script without hash verification')) {
                return
            }
            Write-PspHost "Executing with -Force (no hash verification)..." -ForegroundColor Yellow
            & ([scriptblock]::Create($code))
            return
        }
        Write-PspHost ''
        Write-PspHost "NOT executing by default. Re-run with one of:" -ForegroundColor Yellow
        Write-PspHost "  winutil -ExpectedSha256 '$actualHash'   (pin this version)"
        Write-PspHost "  winutil -Force                          (trust without hash check)"
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to fetch WinUtil: $($_.Exception.Message)"
    }
}

# Launch Harden Windows Security with explicit ShouldProcess confirmation.
function harden {
    <#
    .SYNOPSIS
    Open Harden Windows Security (prompts before launch).
    #>
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

# Open an elevated Windows Terminal, pwsh, or powershell session (executables resolved to absolute paths before elevating).
function admin {
    <#
    .SYNOPSIS
    Open elevated terminal.
    #>
    $shell = Get-PspShellPath
    $wt = Get-Command wt.exe -CommandType Application -ErrorAction Ignore | Select-Object -First 1
    if ($args.Count -gt 0) {
        $escaped = $args | ForEach-Object { if ($_ -match '\s') { "'$($_ -replace "'","''")'" } else { $_ } }
        $command = $escaped -join ' '
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        if ($wt) {
            Start-Process -FilePath $wt.Source -Verb runAs -ArgumentList (ConvertTo-NativeArgumentLine @($shell, '-NoExit', '-EncodedCommand', $encoded))
        }
        else {
            Start-Process -FilePath $shell -Verb runAs -ArgumentList @('-NoExit', '-EncodedCommand', $encoded)
        }
    }
    elseif ($wt) {
        Start-Process -FilePath $wt.Source -Verb runAs
    }
    else {
        Start-Process -FilePath $shell -Verb runAs
    }
}

Set-Alias -Name su -Value admin
# Return system uptime through WMI on PS5 or Get-Uptime on PS7.
function Get-SystemBootTime {
    <#
    .SYNOPSIS
    Return system uptime through WMI on PS5 or Get-Uptime on PS7.
    #>
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
    <#
    .SYNOPSIS
    System uptime.
    #>
    try {
        $bootTime = Get-SystemBootTime
        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Write-PspHost "System started on: $formattedBootTime" -ForegroundColor DarkGray

        $uptime = (Get-Date) - $bootTime
        Write-PspHost ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Blue
    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}
# Universal archive extractor (.zip, .tar, .gz, .7z, .rar); refuses to overwrite existing files unless -Force.
function extract {
    <#
    .SYNOPSIS
    Universal archive extractor.
    .EXAMPLE
    extract .\archive.zip
    Extract into the current directory; stops if a file would be overwritten.
    .EXAMPLE
    extract .\archive.zip -Force
    Extract and overwrite existing files.
    #>
    param([Parameter(Mandatory)][string]$File, [switch]$Force)
    $resolved = Resolve-Path -LiteralPath $File -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $File"; return }
    $path = $resolved.ProviderPath
    $destination = (Get-Location).ProviderPath
    $ext = [System.IO.Path]::GetExtension($path).ToLower()
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($path)
    if ([string]::Equals('.tar', [System.IO.Path]::GetExtension($baseName), [StringComparison]::OrdinalIgnoreCase)) { $ext = '.tar' + $ext }
    # List what the archive would write and stop before touching anything that already exists.
    $entries = @()
    if ($ext -eq '.zip') {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($path)
        try { $entries = @($zip.Entries | ForEach-Object { $_.FullName }) } finally { $zip.Dispose() }
    }
    elseif ($ext -in '.tar', '.tar.gz', '.tgz', '.tar.bz2') { $entries = @(tar -tf "$path" 2>$null) }
    elseif ($ext -eq '.gz') { $entries = @($baseName) }
    $conflicts = @($entries | Where-Object { $_ -and -not $_.EndsWith('/') } |
        ForEach-Object { Join-Path $destination ($_ -replace '/', '\') } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($conflicts.Count -gt 0 -and -not $Force) {
        Write-Error ("{0} file(s) already exist, for example '{1}'. Nothing was extracted; re-run with -Force to overwrite." -f $conflicts.Count, $conflicts[0])
        return
    }
    Write-PspHost "Extracting $path ..." -ForegroundColor Cyan
    switch ($ext) {
        '.zip' { Expand-Archive -LiteralPath $path -DestinationPath $destination -Force }
        '.tar' { tar -xf "$path" -C "$destination"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.gz' { tar -xzf "$path" -C "$destination"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tgz' { tar -xzf "$path" -C "$destination"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.tar.bz2' { tar -xjf "$path" -C "$destination"; if ($LASTEXITCODE -ne 0) { Write-Error "tar extraction failed (exit $LASTEXITCODE)" } }
        '.gz' {
            $outFile = Join-Path $destination $baseName
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
            Write-PspHost "Extracted to $outFile" -ForegroundColor Green
        }
        { $_ -in '.7z', '.rar' } {
            if (-not (Get-Command 7z -ErrorAction Ignore)) { Write-Error "7z not found. Install with: winget install 7zip.7zip"; return }
            # 7-Zip asks before overwriting by default; -Force overwrites without asking.
            if ($Force) { 7z x "$path" -o"$destination" -aoa } else { 7z x "$path" -o"$destination" }
        }
        default { Write-Error "Unsupported format: $ext" }
    }
}

# Upload an entire file to a public paste after confirmation.
function hb {
    <#
    .SYNOPSIS
    Upload to hastebin.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Position = 0)][string]$Path, [switch]$Force)

    if (-not $Path) { Write-Error "No file path specified."; return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Write-Error "File path does not exist."; return }
    $Content = Get-Utf8FileText $Path

    $uri = "https://bin.christitus.com/documents"
    $sizeKb = [math]::Round((Get-Item -LiteralPath $Path).Length / 1KB, 1)
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($uri, "Publish '$Path' (${sizeKb} KB) to a PUBLIC paste")) { return }
    if ($Force) { Write-Warning "Uploading '$Path' (${sizeKb} KB) to a PUBLIC paste: $uri" }
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
    <#
    .SYNOPSIS
    Search for pattern in files.
    #>
    param([string]$regex, [string]$dir)
    if (-not $regex) { Write-Error "Usage: grep <regex> [dir] or <pipeline> | grep <regex>"; return }
    $hasInput = $MyInvocation.ExpectingInput
    if (Get-Command rg -CommandType Application -ErrorAction Ignore) {
        # -e keeps a pattern that starts with '-' from being read as an option.
        if ($dir) { rg -e $regex -- $dir }
        elseif ($hasInput) { $input | rg -e $regex }
        else { rg -e $regex -- . }
    }
    else {
        if ($dir) { Get-ChildItem -LiteralPath $dir -Recurse -File | Select-String -Pattern $regex }
        elseif ($hasInput) { $input | Select-String -Pattern $regex }
        else { Get-ChildItem -LiteralPath . -Recurse -File | Select-String -Pattern $regex }
    }
}

# Disk volume info
function df {
    <#
    .SYNOPSIS
    Disk volumes.
    #>
    get-volume
}

# Detect a text file's encoding: byte order mark first, then strict UTF-8, otherwise the system ANSI code page.
function Get-PspTextEncoding {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [System.Text.UTF8Encoding]::new($true) }
    if ($Bytes.Length -ge 4 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0) { return [System.Text.UTF32Encoding]::new($false, $true) }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [System.Text.UnicodeEncoding]::new($false, $true) }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { return [System.Text.UnicodeEncoding]::new($true, $true) }
    try {
        $null = [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        return [System.Text.UTF8Encoding]::new($false)
    }
    catch { return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage) }
}

# Find and replace literal text in a file, keeping its encoding and byte order mark, with a .bak copy of the original.
function sed($file, $find, $replace) {
    <#
    .SYNOPSIS
    Find and replace in file.
    .EXAMPLE
    sed .\config.ini "old" "new"
    Replace every "old" with "new", keeping the encoding; the original is saved as config.ini.bak.
    #>
    if (-not $file -or -not (Test-Path -LiteralPath $file)) {
        Write-Error "File not found: $file"
        return
    }
    if ($null -eq $find -or $find -eq '') { Write-Error "Usage: sed <file> <find> <replace>"; return }
    if ($null -eq $replace) { $replace = '' }
    $resolved = (Resolve-Path -LiteralPath $file).Path
    $bytes = [System.IO.File]::ReadAllBytes($resolved)
    if ($bytes.Length -eq 0) { Write-Warning "File is empty: $file"; return }
    $encoding = Get-PspTextEncoding -Bytes $bytes
    $bomLength = $encoding.GetPreamble().Length
    $content = $encoding.GetString($bytes, $bomLength, $bytes.Length - $bomLength)
    # Keep a single .bak of the pre-edit content, like sed -i.bak; no backup means no edit.
    Copy-Item -LiteralPath $resolved -Destination "$resolved.bak" -Force -ErrorAction Stop
    [System.IO.File]::WriteAllText($resolved, $content.replace("$find", $replace), $encoding)
}

# Show the full path of a command
function which($name) {
    <#
    .SYNOPSIS
    Show command path.
    #>
    if (-not $name) { Write-Error "Usage: which <name>"; return }
    $cmd = Get-Command $name -ErrorAction Ignore
    if ($cmd) { $cmd | Select-Object -ExpandProperty Definition; return }
    # Fall back to checking the current directory (like bash which for ./files)
    $local = Join-Path (Get-Location).ProviderPath $name
    if (Test-Path -LiteralPath $local) { (Resolve-Path -LiteralPath $local).Path; return }
    Write-Error "which: $name not found"
}

# Identify file type via magic bytes (like Linux file command)
function file {
    <#
    .SYNOPSIS
    Identify file type via magic bytes.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "file: cannot open '$Path' (No such file or directory)"; return }
    $fullPath = $resolved.Path
    $item = Get-Item -LiteralPath $fullPath
    if ($item.PSIsContainer) { Write-PspHost "$($fullPath): directory"; return }
    $size = $item.Length
    if ($size -eq 0) { Write-PspHost "$($fullPath): empty"; return }

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

    Write-PspHost "$($fullPath): $result ($([Math]::Round($size / 1KB, 1)) KB)"
}

# Set an environment variable in the current session
function export($name, $value) {
    <#
    .SYNOPSIS
    Set environment variable.
    #>
    if (-not $name) { Write-Error "Usage: export <name> <value>"; return }
    if ($null -eq $value) { Write-Error "Usage: export <name> <value>"; return }
    Set-Item -LiteralPath "env:$name" -Value $value -Force
}

# Kill processes by name; a wildcard pattern lists what it matches and asks first unless -Force.
function pkill {
    <#
    .SYNOPSIS
    Kill processes by name.
    .EXAMPLE
    pkill notepad
    Stop every notepad process.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Position = 0)][string]$Name, [switch]$Force)
    if (-not $Name) { Write-Error "Usage: pkill <name>"; return }
    # Reject bare wildcards that could match every process.
    if ($Name -match '^[\*\?\.\s]+$') { Write-Error "pkill: refusing to match every process. Pass a specific name."; return }
    $procs = @(Get-Process -Name $Name -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID -and $script:ProtectedProcessNames -notcontains $_.ProcessName })
    if (-not $procs) { Write-Warning "pkill: no killable process matching '$Name'."; return }
    if ($Name -match '[\*\?\[]' -and -not $Force -and -not $WhatIfPreference) {
        $names = ($procs | Select-Object -ExpandProperty ProcessName -Unique | Sort-Object) -join ', '
        $go = $false
        try { $go = $PSCmdlet.ShouldContinue("Stop $($procs.Count) process(es) matching '$Name': $names", 'pkill') }
        catch { Write-Warning "pkill: cannot ask for confirmation in this session; re-run with -Force to stop: $names" }
        if (-not $go) { return }
    }
    foreach ($p in $procs) {
        if ($PSCmdlet.ShouldProcess("$($p.ProcessName) (PID $($p.Id))", 'Stop process')) { $p | Stop-Process -ErrorAction SilentlyContinue }
    }
}

# List processes by name
function pgrep($name) {
    <#
    .SYNOPSIS
    List processes by name.
    #>
    if (-not $name) { Write-Error "Usage: pgrep <name>"; return }
    Get-Process $name -ErrorAction SilentlyContinue
}

# Display first n lines of a file (default 10)
function head {
    <#
    .SYNOPSIS
    First n lines.
    #>
    param($Path, $n = 10)
    if (-not $Path) { Write-Error "Usage: head <path> [n]"; return }
    Get-Content -LiteralPath $Path -Head $n
}

# Display last n lines of a file (default 10, -f to follow)
function tail {
    <#
    .SYNOPSIS
    Last n lines.
    #>
    param($Path, $n = 10, [switch]$f = $false)
    if (-not $Path) { Write-Error "Usage: tail <path> [n] [-f]"; return }
    Get-Content -LiteralPath $Path -Tail $n -Wait:$f
}

Set-Alias -Name nf -Value touch

# Directory Management
function mkcd {
    <#
    .SYNOPSIS
    Create dir and cd into it.
    #>
    param($dir) if (-not $dir) { Write-Error "Usage: mkcd <dir>"; return }; $made = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop; Set-Location -LiteralPath $made.FullName
}

# Move a file or folder to the Recycle Bin and report what actually happened.
function trash {
    <#
    .SYNOPSIS
    Move to Recycle Bin.
    .EXAMPLE
    trash .\old.txt
    Move a file to the Recycle Bin.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Position = 0)][string]$Path)
    if (-not $Path) { Write-Error "Usage: trash <path>"; return }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Error "Item '$Path' does not exist."; return }
    $item = Get-Item -LiteralPath $Path -Force
    $full = $item.FullName
    if ($item.PSIsContainer -and -not $item.Parent) { Write-Error "Cannot move a drive root to the Recycle Bin."; return }
    # Network and removable drives have no Recycle Bin; Windows then asks before deleting permanently.
    $recyclable = -not $full.StartsWith('\\')
    if ($recyclable) {
        try { $recyclable = ([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($full))).DriveType -eq [System.IO.DriveType]::Fixed }
        catch { $recyclable = $false }
    }
    if (-not $recyclable) { Write-Warning "'$full' is on a drive without a Recycle Bin; Windows will ask before deleting it permanently." }
    if (-not (Test-PspRecycleBinSession)) {
        Write-Error "trash needs an interactive desktop session: in this session (SSH, WinRM or a service) Windows would delete '$full' permanently instead of recycling it. Use Remove-Item to delete it."
        return
    }
    if (-not $PSCmdlet.ShouldProcess($full, 'Move to the Recycle Bin')) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic
    $ui = [Microsoft.VisualBasic.FileIO.UIOption]::AllDialogs
    $recycle = [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin
    $onCancel = [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException
    try {
        if ($item.PSIsContainer) { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($full, $ui, $recycle, $onCancel) }
        else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($full, $ui, $recycle, $onCancel) }
    }
    catch [System.OperationCanceledException] {
        Write-Warning "Cancelled; '$full' was not moved."
        return
    }
    if (Test-Path -LiteralPath $full) { Write-Warning "'$full' is still there; it was not moved to the Recycle Bin."; return }
    $where = if ($recyclable) { 'moved to the Recycle Bin' } else { 'deleted (this drive has no Recycle Bin)' }
    Write-PspHost "Item '$full' has been $where."
}

# Return $true when the Recycle Bin can be used: Windows recycles only in an interactive desktop session and deletes permanently otherwise.
function Test-PspRecycleBinSession { [Environment]::UserInteractive }

### Quality of Life Aliases

# Navigation Shortcuts
function docs {
    <#
    .SYNOPSIS
    Jump to Documents.
    #>
    $docs = [Environment]::GetFolderPath("MyDocuments")
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $HOME + "\Documents" }
    Set-Location -Path $docs
}

# Change directory to Desktop
function dtop {
    <#
    .SYNOPSIS
    Jump to Desktop.
    #>
    $dtop = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrWhiteSpace($dtop)) { $dtop = $HOME + "\Desktop" }
    Set-Location -Path $dtop
}

# Enhanced Listing (eza - modern ls replacement with icons and git status)
if (Get-Command eza -CommandType Application -ErrorAction Ignore) {
    # la/ll/lt expose eza under distinct names; the built-in ls alias (Get-ChildItem) is left intact
    # so scripts run later in this session keep the standard listing. Pass the icon setting as
    # --icons=WHEN: eza takes an optional value there, so a bare --icons swallows a following path.
    function la {
        <#
        .SYNOPSIS
        Eza listing with hidden.
        #>
        eza -a --icons=auto @args
    }
    function ll {
        <#
        .SYNOPSIS
        Eza long + git listing.
        #>
        eza -la --icons=auto --git @args
    }
    function lt {
        <#
        .SYNOPSIS
        Eza tree listing.
        #>
        eza --tree --icons=auto --level=2 @args
    }
}
else {
    if ($script:PSP.IsInteractive) { Write-Warning "eza not found. Install it with: winget install -e --id eza-community.eza" }
    # Fallback listing when eza not installed
    function la {
        <#
        .SYNOPSIS
        Eza listing with hidden.
        #>
        Get-ChildItem -Force | Format-Table -AutoSize
    }
    function ll {
        <#
        .SYNOPSIS
        Eza long + git listing.
        #>
        Get-ChildItem -Force | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
    }
    function lt {
        <#
        .SYNOPSIS
        Eza tree listing.
        #>
        Get-ChildItem -Recurse -Depth 2 | Format-Table -AutoSize
    }
}

# Syntax-highlighted file viewer (bat - modern cat replacement)
if (-not $env:BAT_THEME) { $env:BAT_THEME = "TwoDark" }
if (Get-Command bat -CommandType Application -ErrorAction Ignore) {
    # bcat exposes bat under a distinct name; the built-in cat alias (Get-Content) is left intact so
    # scripts run later in this session keep reading raw file contents.
    function bcat {
        <#
        .SYNOPSIS
        Syntax-highlighted viewer (bat).
        #>
        bat --paging=never @args
    }
}
else {
    if ($script:PSP.IsInteractive) { Write-Warning "bat not found. Install it with: winget install -e --id sharkdp.bat" }
}

# Git Shortcuts
function gs {
    <#
    .SYNOPSIS
    Git status.
    #>
    git status
}

# Git add all
function ga {
    <#
    .SYNOPSIS
    Git add .
    #>
    git add .; if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed (exit $LASTEXITCODE)" }
}

# Git commit with message. Named gcmsg, not gc, so the built-in gc alias (Get-Content) stays intact
# for scripts run later in this session.
function gcmsg {
    <#
    .SYNOPSIS
    Git commit -m.
    #>
    if (-not $args) { Write-Error "Usage: gcmsg <message> [git-flags]"; return }
    $msg = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    git commit -m $msg @rest
    if ($LASTEXITCODE -ne 0) { Write-Warning "git commit failed (exit $LASTEXITCODE)" }
}

# Git push (gp is a built-in alias, so this is named gpush)
function gpush {
    <#
    .SYNOPSIS
    Git push.
    #>
    git push
}

# Git pull (gl is a built-in alias, so this is named gpull)
function gpull {
    <#
    .SYNOPSIS
    Git pull.
    #>
    git pull
}

# Jump to github directory via zoxide
function g {
    <#
    .SYNOPSIS
    Zoxide jump to github dir.
    #>
    if (Get-Command __zoxide_z -ErrorAction Ignore) {
        __zoxide_z github
    }
    else {
        Write-Warning "zoxide is not initialized. Install zoxide and restart your shell."
    }
}

# Git clone shortcut
function gcl {
    <#
    .SYNOPSIS
    Git clone.
    #>
    git clone @args
}

# Add all + commit
function gcom {
    <#
    .SYNOPSIS
    Add + commit.
    #>
    if (-not $args) { Write-Error "Usage: gcom <message> [git-flags]"; return }
    git add .
    if ($LASTEXITCODE -ne 0) { Write-Warning "git add failed. Commit skipped."; return }
    $msg = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    git commit -m $msg @rest
}
# Add all + commit + push
function lazyg {
    <#
    .SYNOPSIS
    Add + commit + push.
    #>
    if (-not $args) { Write-Error "Usage: lazyg <message>"; return }
    gcom @args
    if ($LASTEXITCODE -eq 0) { git push }
    else { Write-Warning "Commit failed. Push skipped." }
}

# Quick Access to System Information
function sysinfo {
    <#
    .SYNOPSIS
    Detailed system info.
    #>
    Get-ComputerInfo
}

# Networking Utilities
function flushdns {
    <#
    .SYNOPSIS
    Clear DNS cache.
    #>
    Clear-DnsClientCache
    Write-PspHost "DNS has been flushed"
}

# Network Diagnostics
function ports {
    <#
    .SYNOPSIS
    Listening TCP ports.
    #>
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
        # A listening TCP socket has no remote end (0.0.0.0:0 or [::]:0); matching that avoids the localized state column.
        netstat -ano -p TCP | Select-String -Pattern '\s(0\.0\.0\.0:0|\[::\]:0)\s'
        netstat -ano -p TCPv6 | Select-String -Pattern '\s(0\.0\.0\.0:0|\[::\]:0)\s'
    }
}

# Check if a specific port is open on a host (defaults to localhost)
function checkport {
    <#
    .SYNOPSIS
    Test TCP connectivity.
    #>
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][int]$Port
    )
    $result = Test-NetConnection -ComputerName $Hostname -Port $Port -WarningAction SilentlyContinue
    if ($result -and $result.TcpTestSucceeded) {
        Write-PspHost "$Hostname`:$Port is OPEN" -ForegroundColor Green
    }
    else {
        Write-PspHost "$Hostname`:$Port is CLOSED/FILTERED" -ForegroundColor Red
    }
}

# List local IPv4 addresses (excluding loopback and APIPA)
function localip {
    <#
    .SYNOPSIS
    Local IPv4 addresses.
    #>
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize
}

# DNS Lookup (defaults to A record, specify type with -Type)
function nslook {
    <#
    .SYNOPSIS
    DNS lookup.
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        [ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'ANY')][string]$Type = 'A'
    )
    Resolve-DnsName -Name $Domain -Type $Type | Format-Table -AutoSize
}

# Security & Crypto
function hash {
    <#
    .SYNOPSIS
    File hash (default SHA256).
    #>
    param(
        [Parameter(Mandatory)][string]$File,
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')][string]$Algorithm = 'SHA256'
    )
    if (-not (Test-Path -LiteralPath $File)) { Write-Error "File not found: $File"; return }
    (Get-FileHash -LiteralPath $File -Algorithm $Algorithm).Hash
}

# Verify file integrity by comparing computed hash to expected value (auto-detects algorithm by length)
function checksum {
    <#
    .SYNOPSIS
    Verify file hash.
    #>
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
        Write-PspHost "MATCH ($algo)" -ForegroundColor Green
    }
    else {
        Write-PspHost "MISMATCH ($algo)" -ForegroundColor Red
        Write-PspHost "Expected: $Expected"
        Write-PspHost "Actual:   $actual"
    }
}

# Generate a random password of specified length (default 20) and copy to clipboard
function genpass {
    <#
    .SYNOPSIS
    Random password (clipboard).
    #>
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
    # Use the host as a fallback when the clipboard is unavailable without writing the password to the success stream.
    try {
        Set-Clipboard $password -ErrorAction Stop
        Write-PspHost "Password copied to clipboard." -ForegroundColor Green
    }
    catch {
        Write-Warning "Clipboard unavailable ($($_.Exception.Message)); showing the password once below:"
        Write-PspHost $password -ForegroundColor Yellow
    }
    # Keep the plaintext out of the success stream and terminal scrollback.
    return
}

# Base64 encode/decode
function b64 {
    <#
    .SYNOPSIS
    Base64 encode.
    #>
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

# Base64 decode with error handling
function b64d {
    <#
    .SYNOPSIS
    Base64 decode.
    #>
    param([Parameter(Mandatory)][string]$Text)
    try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Text)) }
    catch { Write-Error "Invalid Base64 input: $_" }
}

# VirusTotal file scanner (PS5-compatible, no dependencies)
function vtscan {
    <#
    .SYNOPSIS
    VirusTotal hash lookup (-Upload submits).
    .EXAMPLE
    vtscan .\setup.exe
    Look up the file's hash on VirusTotal.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [switch]$Upload
    )
    $apiKey = if ($env:VTCLI_APIKEY) { $env:VTCLI_APIKEY } elseif ($env:VT_API_KEY) { $env:VT_API_KEY } else { $null }
    if (-not $apiKey) {
        Write-PspHost 'Set $env:VTCLI_APIKEY first (free key at https://www.virustotal.com/gui/my-apikey)' -ForegroundColor Red
        Write-PspHost 'Or run: vt init' -ForegroundColor Yellow
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
    Write-PspHost "`nFile:       $($file.Name) ($sizeLabel)" -ForegroundColor Cyan
    Write-PspHost "SHA256:     $sha" -ForegroundColor Cyan

    # Lookup by hash first
    $found = $false
    try {
        $report = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha" -Headers $headers -ErrorAction Stop -UseBasicParsing -TimeoutSec 30
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
        Write-PspHost "Detections: $mal/$total" -ForegroundColor $color
        $vtLink = "https://www.virustotal.com/gui/file/$sha/detection"
        Write-PspHost "Link:       $vtLink" -ForegroundColor Cyan
        Start-Process $vtLink
        $results = $report.data.attributes.last_analysis_results
        $detections = if ($results) {
            $results.PSObject.Properties |
            Where-Object { $_.Value.category -eq 'malicious' } |
            Sort-Object { $_.Value.engine_name }
        }
        if ($detections) {
            Write-PspHost ''
            foreach ($d in $detections) {
                $engine = $d.Value.engine_name.PadRight(20)
                Write-PspHost "  $engine $($d.Value.result)" -ForegroundColor Red
            }
        }
        return
    }

    # File not known - upload
    if (-not $Upload) {
        Write-PspHost 'Hash not found. Not uploading by default.' -ForegroundColor Yellow
        Write-PspHost 'Re-run with: vtscan -Upload <file>  (submits the file to VirusTotal)' -ForegroundColor Yellow
        return
    }
    if (-not $PSCmdlet.ShouldProcess($resolved.Path, 'Upload file to VirusTotal (submitted files are shared with the VirusTotal community and its partners)')) {
        return
    }
    Write-PspHost 'Hash not found, uploading...' -ForegroundColor Yellow
    $uploadUrl = 'https://www.virustotal.com/api/v3/files'
    if ($file.Length -gt 10MB) {
        try {
            $uploadUrl = (Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/files/upload_url' -Headers $headers -ErrorAction Stop -UseBasicParsing -TimeoutSec 30).data
            if (-not $uploadUrl) { Write-Error "VirusTotal did not return an upload URL."; return }
            Write-PspHost 'Using large-file upload endpoint.' -ForegroundColor DarkGray
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
    # Cast the multipart payload to byte[] so Invoke-WebRequest sends raw bytes.
    $bodyBytes = [byte[]]($enc.GetBytes($header) + $fileBytes + $enc.GetBytes($footer))
    try {
        $resp = Invoke-WebRequest -Uri $uploadUrl `
            -Method Post -Headers $headers `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $bodyBytes -UseBasicParsing -ErrorAction Stop -TimeoutSec 120
        $parsed = $resp.Content | ConvertFrom-Json
        if (-not $parsed -or -not $parsed.data -or -not $parsed.data.links) {
            Write-Error "Unexpected VirusTotal upload response."
            return
        }
        $link = $parsed.data.links.self
        Write-PspHost "Uploaded. Analysis: $link" -ForegroundColor Green
        $vtLink = "https://www.virustotal.com/gui/file/$sha/detection"
        Write-PspHost "Link:       $vtLink" -ForegroundColor Cyan
        Start-Process $vtLink
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Upload failed: $_"
    }
}

if (-not (Get-Command vt.exe -CommandType Application -ErrorAction Ignore)) {
    # Fallback when vt-cli not installed: show install instructions
    function vt {
        <#
        .SYNOPSIS
        VirusTotal CLI (vt-cli).
        #>
        Write-PspHost 'vt-cli is not installed. Install with:' -ForegroundColor Red
        Write-PspHost '  winget install VirusTotal.vt-cli' -ForegroundColor Yellow
        Write-PspHost 'Then run: vt init' -ForegroundColor Yellow
    }
}

# Docker Shortcuts (conditional)
if (Get-Command docker -CommandType Application -ErrorAction Ignore) {
    # dps/dpa/dimg: list containers and images
    function dps {
        <#
        .SYNOPSIS
        List running containers.
        #>
        docker ps @args
    }
    function dpa {
        <#
        .SYNOPSIS
        List all containers.
        #>
        docker ps -a @args
    }
    function dimg {
        <#
        .SYNOPSIS
        List images.
        #>
        docker images @args
    }
    # dlogs: follow container logs; dex: exec into container
    function dlogs {
        <#
        .SYNOPSIS
        Follow container logs.
        #>
        param([Parameter(Mandatory)][string]$Container)
        $old = Push-TabTitle "logs: $Container"
        try { docker logs -f $Container }
        finally { Pop-TabTitle $old }
    }
    function dex {
        <#
        .SYNOPSIS
        Exec into container.
        #>
        param(
            [Parameter(Mandatory)][string]$Container,
            [string]$Shell = 'bash'
        )
        $old = Push-TabTitle "docker: $Container"
        try { docker exec -it $Container $Shell }
        finally { Pop-TabTitle $old }
    }
    # dstop: stop all running containers; dprune: system prune. Both confirm first (-Confirm:$false skips).
    function dstop {
        <#
        .SYNOPSIS
        Stop all running containers.
        #>
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
        param()
        $running = @(docker ps -q)
        if (-not $running) { Write-PspHost "No running containers."; return }
        if ($PSCmdlet.ShouldProcess("$($running.Count) running container(s)", 'docker stop')) { docker stop $running }
    }
    function dprune {
        <#
        .SYNOPSIS
        Docker system prune.
        #>
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
        param()
        if ($PSCmdlet.ShouldProcess('stopped containers, unused networks, dangling images and build cache', 'docker system prune')) { docker system prune -f }
    }
}

# Define the WSL wrapper and helpers only when wsl.exe is available.
if (Get-Command wsl.exe -CommandType Application -ErrorAction Ignore) {
    # Show the WSL distro in the tab title and invoke wsl.exe without recursion.
    function wsl {
        <#
        .SYNOPSIS
        Wraps wsl.exe; shows distro in tab title.
        #>
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

    # List installed WSL distros. Columns are parsed by position and the running set comes from
    # 'wsl --list --running --quiet', so localized state words on non-English Windows do not matter.
    function Get-WslDistro {
        <#
        .SYNOPSIS
        List installed distros with state + version.
        #>
        [CmdletBinding()]
        param()
        $running = @(& wsl.exe --list --running --quiet 2>$null | ForEach-Object { ([string]$_ -replace "`0", '').Trim() } | Where-Object { $_ })
        $results = @()
        foreach ($line in @(& wsl.exe -l -v 2>&1)) {
            $clean = ([string]$line) -replace "`0", ''
            if ($clean -match '^\s*(\*?)\s*([A-Za-z0-9._-]+)\s+\S.*?\s+(\d+)\s*$') {
                $name = $matches[2]
                $results += [PSCustomObject]@{
                    Default = ($matches[1] -eq '*')
                    Name    = $name
                    State   = $(if ($running -contains $name) { 'Running' } else { 'Stopped' })
                    Version = [int]$matches[3]
                }
            }
        }
        $results
    }

    # Open a WSL shell in the current Windows directory.
    function Enter-WslHere {
        <#
        .SYNOPSIS
        Open WSL in current Windows directory (alias: wsl-here).
        #>
        [CmdletBinding()]
        param([string]$Distro)
        $wslArgs = @('--cd', (Get-Location).ProviderPath)
        if ($Distro) { $wslArgs = @('-d', $Distro) + $wslArgs }
        wsl @wslArgs
    }
    Set-Alias -Name wsl-here -Value Enter-WslHere

    # Normalize separators and terminate options before converting a Windows path with wslpath.
    function ConvertTo-WslPath {
        <#
        .SYNOPSIS
        Windows -> WSL path (wslpath -a).
        #>
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

    # Normalize separators and terminate options before converting a WSL path with wslpath.
    function ConvertTo-WindowsPath {
        <#
        .SYNOPSIS
        WSL -> Windows path (wslpath -w).
        #>
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

    # Shut down all WSL distros or terminate one named distro.
    function Stop-Wsl {
        <#
        .SYNOPSIS
        Shutdown all distros or terminate one.
        #>
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param([string]$Distro)
        if ($Distro) {
            if ($PSCmdlet.ShouldProcess($Distro, 'wsl --terminate')) {
                & wsl.exe --terminate $Distro
                Write-PspHost "Terminated: $Distro" -ForegroundColor Green
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess('all WSL distros', 'wsl --shutdown')) {
                & wsl.exe --shutdown
                Write-PspHost "All WSL distros stopped." -ForegroundColor Green
            }
        }
    }

    # Return the first IPv4 address reported by a WSL distro.
    function Get-WslIp {
        <#
        .SYNOPSIS
        Get IPv4 of a running distro.
        #>
        [CmdletBinding()]
        param([string]$Distro)
        $wslArgs = @()
        if ($Distro) { $wslArgs += '-d', $Distro }
        $wslArgs += 'hostname', '-I'
        $out = (& wsl.exe @wslArgs 2>$null | Out-String).Trim()
        if (-not $out) { Write-Warning 'No IP returned; is the distro running?'; return }
        ($out -split '\s+')[0]
    }

    # Return FileInfo objects from a running distro through its \\wsl$ UNC path.
    function Get-WslFile {
        <#
        .SYNOPSIS
        List files inside a distro via UNC; pipe-friendly.
        #>
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

    # Return a reachable WSL UNC path or $null on failure.
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

    # Render a bounded WSL directory tree with eza or Get-ChildItem.
    function Show-WslTree {
        <#
        .SYNOPSIS
        Tree view of a distro path (alias: wsl-tree).
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0)][string]$Distro,
            [Parameter(Position = 1)][string]$Path = '/',
            [ValidateRange(1, 10)][int]$Depth = 2,
            [switch]$All
        )
        $unc = Resolve-WslUncPath -Distro $Distro -Path $Path
        if (-not $unc) { return }
        if (Get-Command eza -CommandType Application -ErrorAction Ignore) {
            $ezaArgs = @('--tree', "--level=$Depth", '--icons=auto', '--git-ignore')
            if ($All) { $ezaArgs += '-a' }
            & eza @ezaArgs $unc
        }
        else {
            # Render the fallback PowerShell tree using directory-relative depth.
            Get-ChildItem -LiteralPath $unc -Recurse -Depth ($Depth - 1) -Force:$All |
            Select-Object Mode, Length, LastWriteTime, FullName
        }
    }
    Set-Alias -Name wsl-tree -Value Show-WslTree

    # Open a WSL distro path in Windows Explorer.
    function Open-WslExplorer {
        <#
        .SYNOPSIS
        Open distro in Windows Explorer (alias: wsl-explorer).
        #>
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
    <#
    .SYNOPSIS
    Htop-like process viewer.
    #>
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
        Write-PspHost ''
        Write-PspHost ('  CPU: {0}%  |  Mem: {1}/{2} GB ({3}%)  |  Procs: {4}  |  Up: {5}' -f $cpuLoad, $usedMem, $totalMem, $memPct, $procCount, $upStr) -ForegroundColor Cyan
        Write-PspHost ('  ' + ('-' * 70)) -ForegroundColor DarkGray
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
function reload {
    <#
    .SYNOPSIS
    Reload the profile in-place.
    #>
    . $PROFILE
}

# Diagnose version, tools, caches, fonts, PATH, modules, plugins and trust with OK, WARN, or FAIL results.
function Test-ProfileHealth {
    <#
    .SYNOPSIS
    Diagnose install: tools, caches, fonts, PATH, modules.
    .EXAMPLE
    Test-ProfileHealth
    Print the health report.
    .EXAMPLE
    Test-ProfileHealth -PassThru | Where-Object Status -ne 'OK'
    Return the rows that need attention.
    #>
    [CmdletBinding()]
    param(
        # Emit the result objects for scripting; the rendered report prints either way.
        [switch]$PassThru
    )

    $cacheDir = Get-PspCacheDir
    $results = @()

    # Version and install source
    $results += [pscustomobject]@{ Category = 'Profile'; Check = 'version'; Status = 'OK'; Detail = "v$($script:PSP.Version)" }
    $state = Get-PspInstallState -CacheDir $cacheDir
    if ($state) {
        $source = @(
            if (Get-PspProp $state 'source') { [string]$state.source }
            if (Get-PspProp $state 'ref') { "ref $($state.ref)" }
            if (Get-PspProp $state 'commit') { "commit $(([string]$state.commit).Substring(0, [Math]::Min(12, ([string]$state.commit).Length)))" }
            if (Get-PspProp $state 'updatedAt') { "at $($state.updatedAt)" }
        ) -join ', '
        $results += [pscustomobject]@{ Category = 'Profile'; Check = 'installed from'; Status = 'OK'; Detail = $source }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Profile'; Check = 'installed from'; Status = 'WARN'; Detail = 'no install record (installed by an older version or setprofile.ps1)' }
    }

    # Managed tools
    foreach ($tool in $script:ProfileTools) {
        $path = Get-ProfileToolExecutablePath -Tool $tool
        if ($path) {
            $results += [pscustomobject]@{ Category = 'Tools'; Check = $tool.Name; Status = 'OK'; Detail = $path }
        }
        else {
            $results += [pscustomobject]@{ Category = 'Tools'; Check = $tool.Name; Status = 'FAIL'; Detail = 'not installed (Update-Profile -InstallMissingTools or setup.ps1)' }
        }
    }

    # Disk caches (OMP has no init-file cache; it renders via the binary each prompt)
    foreach ($c in @('zoxide-init.ps1', 'theme.json', 'terminal-config.json')) {
        $p = Join-Path $cacheDir $c
        if (-not (Test-Path -LiteralPath $p)) {
            $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'WARN'; Detail = 'missing (will regenerate on next load)' }
            continue
        }
        $size = (Get-Item -LiteralPath $p).Length
        if ($size -eq 0) {
            $results += [pscustomobject]@{ Category = 'Caches'; Check = $c; Status = 'FAIL'; Detail = 'empty file (corrupt)' }
            continue
        }
        if ($c -like '*.json') {
            try {
                $null = Read-JsonFile $p
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
    $usCfg = $null
    if (Test-Path -LiteralPath $us) {
        try {
            $usCfg = Read-JsonFile $us
            $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'OK'; Detail = 'parses' }
        }
        catch {
            $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'FAIL'; Detail = $_.Exception.Message }
        }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Config'; Check = 'user-settings.json'; Status = 'WARN'; Detail = 'missing (no overrides applied)' }
    }

    # Windows Terminal settings.json ownership: a symlink or windowsTerminal.manage = false means another tool owns it.
    $wtManagedHere = -not ($usCfg -and $usCfg.windowsTerminal -and (Test-PspProp $usCfg.windowsTerminal 'manage') -and $usCfg.windowsTerminal.manage -eq $false)
    $manifest = Read-WtChangeManifest -ManifestPath (Join-Path $cacheDir 'wt-changes.json')
    foreach ($wtPath in @(Get-WindowsTerminalSettingsPaths)) {
        $wtItem = Get-Item -LiteralPath $wtPath -Force -ErrorAction SilentlyContinue
        if (-not $wtItem) { continue }
        $wtVariant = if ($wtPath -match 'WindowsTerminalPreview') { 'Preview' } elseif ($wtPath -match 'WindowsTerminalCanary') { 'Canary' } elseif ($wtPath -match 'Packages') { 'Stable' } else { 'Unpackaged' }
        $tracked = if (Get-PspProp $manifest.files $wtPath.ToLowerInvariant()) { 'changes recorded for uninstall' } else { 'no recorded changes' }
        if ($wtItem.LinkType) {
            $wtTarget = [string](@($wtItem.Target)[0])
            if ($wtManagedHere) {
                $results += [pscustomobject]@{ Category = 'Terminal'; Check = "settings.json ($wtVariant)"; Status = 'WARN'; Detail = "symlink to $wtTarget; set windowsTerminal.manage = false in user-settings.json if that tool owns it" }
            }
            else {
                $results += [pscustomobject]@{ Category = 'Terminal'; Check = "settings.json ($wtVariant)"; Status = 'OK'; Detail = "symlink to $wtTarget, managed elsewhere" }
            }
        }
        elseif ($wtManagedHere) {
            $results += [pscustomobject]@{ Category = 'Terminal'; Check = "settings.json ($wtVariant)"; Status = 'OK'; Detail = "managed by this profile, $tracked" }
        }
        else {
            $results += [pscustomobject]@{ Category = 'Terminal'; Check = "settings.json ($wtVariant)"; Status = 'OK'; Detail = 'not managed (windowsTerminal.manage = false)' }
        }
    }

    # Check the font this install actually uses: a wizard choice in user-settings.json
    # overrides the shipped terminal-config.json default.
    $fontName = $null
    if ($usCfg -and $usCfg.defaults -and $usCfg.defaults.font -and $usCfg.defaults.font.face) {
        $fontName = [string]$usCfg.defaults.font.face
    }
    if (-not $fontName) {
        try {
            $tc = Read-JsonFile (Join-Path $cacheDir 'terminal-config.json')
            if ($tc -and $tc.fontInstall) { $fontName = [string]$tc.fontInstall.displayName }
        }
        catch { $null = $_ }
    }
    if ($fontName) {
        # Report unavailable System.Drawing as WARN on non-Windows platforms.
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
            # GDI+ caches the family list per process, so a font installed after this session
            # started reads as missing; the font registry is the authoritative fallback.
            if (-not $installed) {
                foreach ($hive in @('HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts')) {
                    try {
                        $fontKey = Get-ItemProperty -Path $hive -ErrorAction Stop
                        if (@($fontKey.PSObject.Properties.Name | Where-Object { $_ -like "$fontName*" }).Count -gt 0) {
                            $installed = $true
                            break
                        }
                    }
                    catch { $null = $_ }
                }
            }
            if ($installed) {
                $results += [pscustomobject]@{ Category = 'Fonts'; Check = $fontName; Status = 'OK'; Detail = 'installed' }
            }
            else {
                $results += [pscustomobject]@{ Category = 'Fonts'; Check = $fontName; Status = 'FAIL'; Detail = 'not installed (run setup.ps1 -Wizard or setup.ps1)' }
            }
        }
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
    if (Test-Path -LiteralPath $pluginDir) {
        $plugins = @(Get-ChildItem -LiteralPath $pluginDir -Filter *.ps1 -ErrorAction SilentlyContinue)
        $results += [pscustomobject]@{ Category = 'Plugins'; Check = 'user plugins'; Status = 'OK'; Detail = "$($plugins.Count) file(s) in $pluginDir" }
    }

    # Extensibility state: a trusted directory whose .psprc.ps1 no longer matches its approval will not run.
    $trustedCount = if ($script:PSP.TrustedDirs) { $script:PSP.TrustedDirs.Count } else { 0 }
    $stale = @($script:PSP.TrustedDirs | Where-Object {
            (Test-Path -LiteralPath (Join-Path $_ '.psprc.ps1')) -and ([string]$script:PSP.TrustedRcHashes[$_]) -ne (Get-PspRcHash -Directory $_)
        })
    if ($stale.Count -gt 0) {
        $results += [pscustomobject]@{ Category = 'Extension'; Check = 'trusted directories'; Status = 'WARN'; Detail = "$trustedCount entries; .psprc.ps1 needs re-approval in: $($stale -join ', ')" }
    }
    else {
        $results += [pscustomobject]@{ Category = 'Extension'; Check = 'trusted directories'; Status = 'OK'; Detail = "$trustedCount entries" }
    }

    # Format + render
    $okCount = @($results | Where-Object Status -eq 'OK').Count
    $warnCount = @($results | Where-Object Status -eq 'WARN').Count
    $failCount = @($results | Where-Object Status -eq 'FAIL').Count

    Write-PspHost ''
    Write-PspHost 'Profile Health Check' -ForegroundColor Cyan
    Write-PspHost '===================='
    $fmt = '{0,-10} {1,-30} {2,-5} {3}'
    Write-PspHost ($fmt -f 'Category', 'Check', 'Stat', 'Detail') -ForegroundColor DarkGray
    foreach ($r in $results) {
        $color = switch ($r.Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'White' } }
        $detail = if ($r.Detail.Length -gt 80) { $r.Detail.Substring(0, 77) + '...' } else { $r.Detail }
        Write-PspHost ($fmt -f $r.Category, $r.Check, $r.Status, $detail) -ForegroundColor $color
    }
    Write-PspHost ''
    $summaryColor = if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
    Write-PspHost ("Summary: {0} OK, {1} WARN, {2} FAIL" -f $okCount, $warnCount, $failCount) -ForegroundColor $summaryColor

    # Emit objects only on request: a bare call would otherwise render the table a second
    # time through the default formatter. Scripts use -PassThru to query the rows.
    if ($PassThru) { $results }
}
Set-Alias -Name psp-doctor -Value Test-ProfileHealth -Scope Script

# Clear regenerable profile and Oh My Posh caches before a terminal restart; settings, plugins and install state are kept.
function Clear-ProfileCache {
    <#
    .SYNOPSIS
    Reset caches except user settings.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $cacheDir = Get-PspCacheDir
    if (-not (Test-Path -LiteralPath $cacheDir)) {
        if ($PSCmdlet.ShouldProcess('Oh My Posh caches', 'Clear')) { Clear-OhMyPoshCaches -Quiet }
        Write-PspHost "No cache directory found." -ForegroundColor Yellow
        return
    }
    # State files are not caches: uninstall needs the telemetry marker and the Windows Terminal change record.
    $preservedNames = @('user-settings.json', 'user-settings.json.bak', 'plugins', 'telemetry.owned', 'wt-changes.json', 'installed.json', 'applied-commit.sha', 'logs')
    # bg-*.png are resized background images that Windows Terminal points at.
    $items = @(Get-ChildItem -LiteralPath $cacheDir -Force -ErrorAction SilentlyContinue | Where-Object { $preservedNames -notcontains $_.Name -and $_.Name -notlike 'bg-*.png' })
    if ($items.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess('Oh My Posh caches', 'Clear')) { Clear-OhMyPoshCaches -Quiet }
        Write-PspHost "Cache is already clean." -ForegroundColor Green
        return
    }
    foreach ($item in $items) {
        if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove cache item')) {
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-PspHost "  Removed $($item.Name)" -ForegroundColor DarkGray
        }
    }
    if ($PSCmdlet.ShouldProcess('Oh My Posh caches', 'Clear')) { Clear-OhMyPoshCaches -Quiet }
    Restart-TerminalToApply -Message "Profile cache cleared. Restarting terminal..."
}

# Download setup.ps1 from a branch, tag or commit and run its wizard in this session, pinned by hash unless -SkipHashCheck.
function Invoke-ProfileWizard {
    <#
    .SYNOPSIS
    Re-run install wizard (alias: Reconfigure-Profile).
    .EXAMPLE
    Invoke-ProfileWizard -Ref v1.0.0
    Run the wizard from setup.ps1 of release v1.0.0, checked against the release's SHA256SUMS.txt.
    .EXAMPLE
    Invoke-ProfileWizard -Ref <commit> -ExpectedSha256 <hash>
    Run the wizard from a commit's setup.ps1 pinned to the hash an earlier run printed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$Resume,
        # Accepted for compatibility: setup.ps1 no longer needs elevation, so the wizard always runs in this session.
        [switch]$NoElevate,
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$BundleExpectedSha256,
        # Branch, tag (vX.Y.Z) or commit; setup.ps1 and its install bundle both come from the same resolved commit.
        [ValidatePattern('^(?!.*\.\.)(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')]
        [string]$Ref = 'main',
        [switch]$SkipHashCheck
    )

    if ($BundleExpectedSha256 -and $SkipHashCheck) {
        Write-Error 'Use either -BundleExpectedSha256 or -SkipHashCheck, not both.'
        return
    }
    if (-not $PSCmdlet.ShouldProcess("setup.ps1 from $($script:PSP.RepoOwner)/$($script:PSP.RepoName)@$Ref", 'Download and run the setup wizard')) { return }

    $commit = Resolve-PspCommitSha -Owner $script:PSP.RepoOwner -Repo $script:PSP.RepoName -Ref $Ref
    $sourceRef = if ($commit) { $commit } else { $Ref }
    $setupUrl = Get-PspRawUrl -Ref $sourceRef -Path 'setup.ps1'
    # A private folder: setup.ps1 treats a folder that also holds the profile files as a local clone.
    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('psp-reconfigure-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    $setupLocal = Join-Path $workDir 'setup.ps1'

    try {
        Write-PspHost "Downloading setup.ps1 from $setupUrl" -ForegroundColor Cyan
        try { Invoke-DownloadWithRetry -Uri $setupUrl -OutFile $setupLocal }
        catch {
            Write-Warning "Download failed: $($_.Exception.Message)"
            return
        }

        $actualHash = (Get-FileHash -LiteralPath $setupLocal -Algorithm SHA256).Hash
        $releaseSums = $null
        if (-not $ExpectedSha256 -and -not $SkipHashCheck) { $releaseSums = Get-PspReleaseChecksums -Owner $script:PSP.RepoOwner -Repo $script:PSP.RepoName -Tag $Ref }
        if ($releaseSums) {
            if ($releaseSums['setup.ps1'] -ne $actualHash) {
                Write-Error "setup.ps1 does not match the SHA256SUMS.txt of release $Ref. Aborting."
                return
            }
            Write-PspHost "  setup.ps1 matches the SHA256SUMS.txt of release $Ref." -ForegroundColor Green
        }
        elseif ($ExpectedSha256) {
            if ($actualHash -ine $ExpectedSha256.Trim()) {
                Write-Error "SHA256 mismatch. Expected: $ExpectedSha256. Actual: $actualHash. Aborting."
                return
            }
            Write-PspHost "  Hash verified: $actualHash" -ForegroundColor Green
        }
        elseif (-not $SkipHashCheck) {
            Write-PspHost "  Downloaded setup.ps1 SHA256: $actualHash (commit $sourceRef)" -ForegroundColor Yellow
            Write-PspHost "  Release tags (-Ref vX.Y.Z) are checked against the release's SHA256SUMS.txt automatically; check a branch or commit out-of-band." -ForegroundColor DarkYellow
            Write-PspHost "  Pin it:  Invoke-ProfileWizard -Ref $sourceRef -ExpectedSha256 '$actualHash'" -ForegroundColor Yellow
            Write-PspHost "  Then pin the setup bundle with -BundleExpectedSha256 when prompted." -ForegroundColor Yellow
            Write-PspHost "  Or skip: Invoke-ProfileWizard -SkipHashCheck" -ForegroundColor Yellow
            throw "Hash input required. Re-run with -ExpectedSha256 or -SkipHashCheck."
        }

        # A release tag is passed on as is, so setup.ps1 checks the bundle against that release's SHA256SUMS.txt.
        $setupRef = if ($Ref -match '^v\d+\.\d+\.\d+$') { $Ref } else { $sourceRef }
        $shellArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $setupLocal, '-Wizard', '-Ref', $setupRef)
        if ($Resume) { $shellArgs += '-Resume' }
        if ($SkipHashCheck) {
            $shellArgs += '-SkipHashCheck'
        }
        elseif ($BundleExpectedSha256) {
            $shellArgs += @('-ExpectedSha256', $BundleExpectedSha256)
        }
        elseif ($setupRef -notmatch '^v\d+\.\d+\.\d+$') {
            Write-PspHost "  setup.ps1 will stop before making changes and print the install-bundle hash." -ForegroundColor Yellow
            Write-PspHost "  Re-run with -BundleExpectedSha256 '<hash>' or -SkipHashCheck to apply the wizard." -ForegroundColor Yellow
        }

        & (Get-PspShellPath) @shellArgs
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            Write-PspHost "Wizard complete. Reload your shell (run 'reload') to apply changes." -ForegroundColor Green
        }
        else {
            Write-Warning "Wizard exited with code $exitCode. Review the output above."
        }
    }
    finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Set-Alias -Name Reconfigure-Profile -Value Invoke-ProfileWizard -Scope Script

# Uninstall profile components with granular options; Windows Terminal changes are reverted change by change.
function Uninstall-Profile {
    <#
    .SYNOPSIS
    Remove profile, caches, WT changes.
    .EXAMPLE
    Uninstall-Profile -WhatIf
    List everything a plain uninstall would remove or revert.
    .EXAMPLE
    Uninstall-Profile -All
    Also remove tools, fonts and user data.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$RemoveTools,
        [switch]$RemoveUserData,
        [switch]$RemoveFonts,
        [switch]$All,
        [switch]$HardResetWindowsTerminal,
        [switch]$Force
    )

    if ($All) { $RemoveTools = $true; $RemoveUserData = $true; $RemoveFonts = $true }
    $preserved = @()
    $cacheDir = Get-PspCacheDir

    # Read state first: the cache clean-up below removes the files it lives in.
    $telemetryMarker = Join-Path $cacheDir 'telemetry.owned'
    $telemetryOwned = Test-Path -LiteralPath $telemetryMarker
    $telemetryScope = 'Machine'
    if ($telemetryOwned -and (Get-Utf8FileText $telemetryMarker) -match '(?im)^scope:\s*User\b') { $telemetryScope = 'User' }
    $manifestPath = Join-Path $cacheDir 'wt-changes.json'
    $userSettings = $null
    $userSettingsUnreadable = $false
    try { $userSettings = Read-JsonFile (Join-Path $cacheDir 'user-settings.json') } catch { $userSettingsUnreadable = $true }
    $terminalConfigAtStart = $null
    try { $terminalConfigAtStart = Read-JsonFile (Join-Path $cacheDir 'terminal-config.json') } catch { $null = $_ }
    $userWt = Get-PspProp $userSettings 'windowsTerminal'
    $wtManaged = -not $userSettingsUnreadable -and -not ($userWt -and (Test-PspProp $userWt 'manage') -and $userWt.manage -eq $false)

    # Phase 1: Windows Terminal settings, in every installed variant.
    if ($userSettingsUnreadable) {
        Write-Warning '  user-settings.json could not be read, so it is unknown whether another tool owns Windows Terminal settings; they are left alone. Fix the file and run Uninstall-Profile again.'
        $preserved += 'Windows Terminal changes (user-settings.json could not be read)'
    }
    elseif (-not $wtManaged) {
        Write-PspHost '  Windows Terminal settings left alone (windowsTerminal.manage = false in user-settings.json).' -ForegroundColor DarkGray
    }
    else {
        foreach ($wtSettingsPath in @(Get-WindowsTerminalSettingsPaths)) {
            $wtItem = Get-Item -LiteralPath $wtSettingsPath -Force -ErrorAction SilentlyContinue
            if ($wtItem -and $wtItem.LinkType) {
                Write-PspHost "  $wtSettingsPath is a symlink managed elsewhere; Windows Terminal settings left in place." -ForegroundColor DarkGray
                continue
            }
            $profileBackups = Get-WtProfileBackups -Path $wtSettingsPath
            if ($HardResetWindowsTerminal) {
                if ($PSCmdlet.ShouldProcess($wtSettingsPath, 'Delete WT settings for hard reset')) {
                    Remove-Item -LiteralPath $wtSettingsPath -Force -ErrorAction SilentlyContinue
                    Write-PspHost "  Deleted $wtSettingsPath (Windows Terminal recreates defaults on next launch)." -ForegroundColor Green
                    # The recorded changes belonged to the deleted file.
                    $hardManifest = Read-WtChangeManifest -ManifestPath $manifestPath
                    if (Get-PspProp $hardManifest.files $wtSettingsPath.ToLowerInvariant()) {
                        Remove-PspProp $hardManifest.files $wtSettingsPath.ToLowerInvariant()
                        Save-WtChangeManifest -ManifestPath $manifestPath -Manifest $hardManifest
                    }
                    if ($RemoveUserData) {
                        foreach ($bak in $profileBackups) {
                            if ($PSCmdlet.ShouldProcess($bak.FullName, 'Remove WT backup made by this profile')) {
                                Remove-Item -LiteralPath $bak.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    elseif ($profileBackups.Count -gt 0) {
                        $preserved += "Windows Terminal backups next to $wtSettingsPath, including the pre-install copy (use -RemoveUserData to remove)"
                    }
                }
                continue
            }
            $restored = $false
            $hasRecord = [bool](Get-PspProp (Read-WtChangeManifest -ManifestPath $manifestPath).files $wtSettingsPath.ToLowerInvariant())
            if ($hasRecord) {
                try {
                    $undo = Undo-WindowsTerminalSettingsFile -Path $wtSettingsPath -ManifestPath $manifestPath
                    if ($undo) {
                        $restored = $true
                        $keptNote = if ($undo.Kept -gt 0) { "; kept $($undo.Kept) setting(s) changed since the profile wrote them" } else { '' }
                        Write-PspHost "  Reverted $($undo.Reverted) Windows Terminal change(s) in $wtSettingsPath$keptNote." -ForegroundColor Green
                    }
                }
                catch { Write-Warning "  Could not revert recorded changes in ${wtSettingsPath}: $($_.Exception.Message)" }
            }
            else {
                # Installed by a version without the change record: restore the oldest copy and keep the current file.
                $source = @($profileBackups | Where-Object { $_.Name -like '*.psp-original' }) + @($profileBackups | Where-Object { $_.Name -like '*.bak' } | Sort-Object LastWriteTime) | Select-Object -First 1
                if ($source -and $PSCmdlet.ShouldProcess($wtSettingsPath, "Restore Windows Terminal settings from $($source.Name)")) {
                    $safety = '{0}.pre-uninstall-{1}.json' -f $wtSettingsPath, (Get-Date -Format 'yyyyMMdd-HHmmss')
                    try {
                        Copy-Item -LiteralPath $wtSettingsPath -Destination $safety -Force -ErrorAction Stop
                        Copy-Item -LiteralPath $source.FullName -Destination $wtSettingsPath -Force -ErrorAction Stop
                        $restored = $true
                        Write-PspHost "  Restored $wtSettingsPath from $($source.Name)." -ForegroundColor Green
                        $preserved += "Windows Terminal settings as they were just before uninstall: $safety"
                    }
                    catch { Write-Warning "  Could not restore ${wtSettingsPath}: $($_.Exception.Message)" }
                }
            }
            # Backups go only after a successful restore, so a failed or declined restore loses nothing; the pre-install copy
            # stays unless user data is removed too.
            if ($restored) {
                foreach ($bak in $profileBackups) {
                    if ($bak.Name -like '*.psp-original' -and -not $RemoveUserData) {
                        $preserved += "Windows Terminal settings from before the first install: $($bak.FullName) (-RemoveUserData removes it)"
                        continue
                    }
                    if ($PSCmdlet.ShouldProcess($bak.FullName, 'Remove WT backup made by this profile')) {
                        Remove-Item -LiteralPath $bak.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            elseif ($profileBackups.Count -gt 0) {
                $preserved += "Windows Terminal backups next to $wtSettingsPath (not restored)"
            }
        }
    }
    if (@((Read-WtChangeManifest -ManifestPath $manifestPath).files.PSObject.Properties).Count -gt 0) {
        $preserved += "Windows Terminal change record for settings that were not reverted: $manifestPath"
    }

    # Phase 2: Telemetry opt-out, removed only when setup set it (ownership marker) and at the scope it used.
    $telemetrySet = [bool][System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', $telemetryScope)
    if ($telemetryOwned -and $telemetrySet) {
        if ($telemetryScope -eq 'Machine' -and -not $script:PSP.IsAdmin) {
            Write-Warning '  POWERSHELL_TELEMETRY_OPTOUT was set machine-wide by setup; re-run Uninstall-Profile in an elevated shell to remove it.'
            $preserved += 'POWERSHELL_TELEMETRY_OPTOUT (machine-wide; re-run Uninstall-Profile elevated to remove it)'
        }
        elseif ($PSCmdlet.ShouldProcess("POWERSHELL_TELEMETRY_OPTOUT ($telemetryScope)", 'Remove environment variable')) {
            [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', $null, $telemetryScope)
            Remove-Item -LiteralPath $telemetryMarker -Force -ErrorAction SilentlyContinue
            Write-PspHost "  Removed POWERSHELL_TELEMETRY_OPTOUT ($telemetryScope)." -ForegroundColor Green
        }
    }
    elseif ($telemetryOwned) {
        # Variable already gone; drop the stale marker so repeat uninstalls stay idempotent.
        if ($PSCmdlet.ShouldProcess($telemetryMarker, 'Remove stale telemetry marker')) { Remove-Item -LiteralPath $telemetryMarker -Force -ErrorAction SilentlyContinue }
    }
    elseif ([System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine') -or [System.Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'User')) {
        Write-PspHost '  Leaving POWERSHELL_TELEMETRY_OPTOUT alone (not set by this profile).' -ForegroundColor DarkGray
    }

    # Phase 3: Cache cleanup. User data stays unless requested; state that is still needed stays too.
    if (Test-Path -LiteralPath $cacheDir) {
        $excludes = @()
        if (-not $RemoveUserData) { $excludes += 'user-settings.json', 'user-settings.json.bak', 'plugins' }
        if (Test-Path -LiteralPath $telemetryMarker) { $excludes += 'telemetry.owned' }
        if (Test-Path -LiteralPath $manifestPath) { $excludes += 'wt-changes.json' }
        $cacheItems = Get-ChildItem -LiteralPath $cacheDir -Force -ErrorAction SilentlyContinue |
            Where-Object { $excludes -notcontains $_.Name }
        foreach ($item in $cacheItems) {
            $itemLabel = if ($item.PSIsContainer) { 'Remove cache directory' } else { 'Remove cache file' }
            if ($PSCmdlet.ShouldProcess($item.FullName, $itemLabel)) {
                Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
                Write-PspHost "  Removed $($item.Name)" -ForegroundColor DarkGray
            }
        }
        if (-not $RemoveUserData) {
            $preserved += 'user-settings.json (use -RemoveUserData to remove)'
            if (Test-Path -LiteralPath (Join-Path $cacheDir 'plugins')) { $preserved += 'plugins/ (use -RemoveUserData to remove)' }
        }
        # Remove empty cache dir
        $remaining = Get-ChildItem -LiteralPath $cacheDir -Force -ErrorAction SilentlyContinue
        if (-not $remaining) {
            if ($PSCmdlet.ShouldProcess($cacheDir, 'Remove empty cache directory')) {
                Remove-Item -LiteralPath $cacheDir -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Phase 3b: Temporary profile artifacts
    $tempArtifactPatterns = @(
        'psp-wizard-state.json'
        'psp-profile-*.ps1'
        'psp-theme-*.json'
        'psp-terminal-*.json'
        'psp-setup-*'
        'psp-reconfigure-*'
    )
    foreach ($pattern in $tempArtifactPatterns) {
        $orphans = Get-ChildItem -LiteralPath $env:TEMP -Filter $pattern -Force -ErrorAction SilentlyContinue
        foreach ($orphan in $orphans) {
            if ($PSCmdlet.ShouldProcess($orphan.FullName, 'Remove leftover temp item')) {
                Remove-Item -LiteralPath $orphan.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-PspHost "  Removed $($orphan.Name)" -ForegroundColor DarkGray
            }
        }
    }

    # Gated so -WhatIf stays read-only; the OMP cache clear deletes files of its own.
    if ($PSCmdlet.ShouldProcess('Oh My Posh caches', 'Clear')) { Clear-OhMyPoshCaches -Quiet }

    # Phase 4: PSFzf module - opt-in with -RemoveTools, since it is one of the managed tools.
    $isCiOrAgent = (($env:CI -or $env:AI_AGENT) -and -not $Force)
    $psfzfPresent = [bool](Get-Module -ListAvailable -Name PSFzf)
    if ($psfzfPresent -and -not $RemoveTools) {
        $preserved += 'PSFzf module (use -RemoveTools to remove)'
    }
    elseif ($psfzfPresent) {
        if ($isCiOrAgent) {
            Write-Warning '  Skipping PSFzf module uninstall under CI/agent environment ($env:CI/$env:AI_AGENT set). Re-run with -Force to uninstall it anyway.'
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
                Write-PspHost '  Uninstalled PSFzf module.' -ForegroundColor Green
                $uninstalled = $true
            }
            catch {
                Write-Warning "  Failed to uninstall PSFzf in current session: $_"
            }

            if (-not $uninstalled) {
                # Retry uninstall from a background shell to release the module.
                try {
                    Start-Process -FilePath (Get-PspShellPath) -ArgumentList @(
                        '-NoProfile'
                        '-NonInteractive'
                        '-Command'
                        "try { Uninstall-Module -Name PSFzf -AllVersions -Force -ErrorAction SilentlyContinue } catch { `$null = `$_ }"
                    ) -WindowStyle Hidden | Out-Null
                    Write-PspHost '  Scheduled PSFzf uninstall in background session.' -ForegroundColor Yellow
                }
                catch {
                    Write-Warning "  Failed to schedule PSFzf uninstall in background session: $_"
                }
            }
        }
    }

    # Phase 5: Managed tools (winget by default, direct/MSI aware for Oh My Posh)
    if ($RemoveTools) {
        if ($isCiOrAgent) {
            Write-Warning '  Skipping managed tool uninstall under CI/agent environment ($env:CI/$env:AI_AGENT set). Re-run with -Force to uninstall them anyway.'
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
                        Write-PspHost "  Preserving $($tool.Name) ($toolLocation)." -ForegroundColor DarkGray
                    }
                    continue
                }

                if ($removalMode -eq 'winget') {
                    if ($PSCmdlet.ShouldProcess($tool.Name, 'Uninstall via winget')) {
                        try {
                            $wingetOutput = @(& $wingetPath uninstall -e --id $tool.Id --silent 2>&1)
                            if ($LASTEXITCODE -eq 0) {
                                Write-PspHost "  Uninstalled $($tool.Name)" -ForegroundColor Green
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
                    if ($PSCmdlet.ShouldProcess($tool.Name, 'Uninstall via MSI')) {
                        try {
                            $msiProc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/x', $ompMsiProductCode, '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
                            if ($msiProc.ExitCode -in @(0, 1605, 3010)) {
                                Write-PspHost "  Uninstalled $($tool.Name)" -ForegroundColor Green
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
    else { $preserved += 'Managed tools (use -RemoveTools to uninstall)' }

    # Phase 6: Nerd Fonts (opt-in). Shell font installs land per-user on Windows 10/11 unless
    # elevated, so both scopes are swept; only the machine-wide one needs admin.
    if ($RemoveFonts) {
        # Derive the uninstall font filter from what setup actually installed: a wizard font choice
        # in user-settings.json wins over terminal-config.json, which wins over the install default.
        $fontDisplayName = 'CaskaydiaCove NF'
        try {
            # Read before the cache cleanup removed it.
            $tc = $terminalConfigAtStart
            if ($tc -and $tc.fontInstall -and $tc.fontInstall.displayName) { $fontDisplayName = [string]$tc.fontInstall.displayName }
        }
        catch { $null = $_ }
        if ($userSettings -and $userSettings.defaults -and $userSettings.defaults.font -and $userSettings.defaults.font.face) {
            $fontDisplayName = [string]$userSettings.defaults.font.face
        }
        $tokens = @($fontDisplayName -split '\s+' | Where-Object { $_ })
        # Registry entries keep the display form ("CaskaydiaCove NF Bold (TrueType)")...
        $regNamePattern = ($tokens | ForEach-Object { [regex]::Escape($_) }) -join '.*'
        # ...but on disk the same family is written "CaskaydiaCoveNerdFont-Bold.ttf", so the
        # abbreviated "NF" never matches a filename. Match family prefix + the NerdFont marker,
        # which also keeps this away from Microsoft's own Cascadia Code files.
        $fileNamePattern = '^' + [regex]::Escape($tokens[0]) + '.*NerdFont'
        $fontExtensions = @('.ttf', '.otf')

        $isElevated = $script:PSP.IsAdmin
        # Tests point this at sandbox folders; nothing outside tests sets it.
        $fontScopes = if ($script:PSP.ContainsKey('TestFontScopes') -and $script:PSP.TestFontScopes) { @($script:PSP.TestFontScopes) } else {
            @(
                @{ Name = 'per-user'; Dir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'); Reg = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'; NeedsAdmin = $false }
                @{ Name = 'machine-wide'; Dir = (Join-Path $env:SystemRoot 'Fonts'); Reg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'; NeedsAdmin = $true }
            )
        }

        $fontMatches = 0
        $removedFontCount = 0
        $skippedMachineScope = $false
        # Under -WhatIf nothing is actually deleted, so the orphan sweep would re-list every file
        # the registry pass already claimed. Track them to keep the plan honest.
        $handledFontFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($scope in $fontScopes) {
            if ($scope.NeedsAdmin -and -not $isElevated) {
                # Only nag about elevation when that scope actually holds matching fonts.
                $blocked = @(Get-ChildItem -LiteralPath $scope.Dir -ErrorAction SilentlyContinue |
                    Where-Object { $fontExtensions -contains $_.Extension -and $_.Name -match $fileNamePattern })
                if ($blocked) { $skippedMachineScope = $true }
                continue
            }

            # Registry first - each entry points at the file that belongs to it.
            $scopeDirFull = $null
            try { $scopeDirFull = [System.IO.Path]::GetFullPath($scope.Dir).TrimEnd('\') } catch { $null = $_ }
            $regEntries = Get-ItemProperty -Path $scope.Reg -ErrorAction SilentlyContinue
            if ($regEntries) {
                foreach ($prop in @($regEntries.PSObject.Properties | Where-Object { $_.Name -match $regNamePattern })) {
                    $fontFile = [string]$prop.Value
                    # An entry without a file, or one pointing outside this scope's store, is left alone.
                    if (-not $fontFile) { continue }
                    # Machine entries often store a bare filename; per-user ones store a full path.
                    if (-not [System.IO.Path]::IsPathRooted($fontFile)) { $fontFile = Join-Path $scope.Dir $fontFile }
                    $inScope = $false
                    if ($scopeDirFull) {
                        try {
                            $inScope = [System.IO.Path]::GetFullPath($fontFile).StartsWith(
                                $scopeDirFull + [System.IO.Path]::DirectorySeparatorChar,
                                [System.StringComparison]::OrdinalIgnoreCase)
                        }
                        catch { $inScope = $false }
                    }
                    if (-not $inScope) { continue }
                    if ((Test-Path -LiteralPath $fontFile) -and $handledFontFiles.Add($fontFile)) {
                        $fontMatches++
                        if ($PSCmdlet.ShouldProcess($fontFile, 'Remove font file')) {
                            Remove-Item -LiteralPath $fontFile -Force -ErrorAction SilentlyContinue
                            $removedFontCount++
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($prop.Name, "Remove $($scope.Name) font registry entry")) {
                        Remove-ItemProperty -Path $scope.Reg -Name $prop.Name -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            # Then sweep files whose registry entry was already gone.
            foreach ($orphan in @(Get-ChildItem -LiteralPath $scope.Dir -ErrorAction SilentlyContinue |
                    Where-Object { $fontExtensions -contains $_.Extension -and $_.Name -match $fileNamePattern })) {
                if (-not $handledFontFiles.Add($orphan.FullName)) { continue }
                $fontMatches++
                if ($PSCmdlet.ShouldProcess($orphan.FullName, 'Remove font file')) {
                    Remove-Item -LiteralPath $orphan.FullName -Force -ErrorAction SilentlyContinue
                    $removedFontCount++
                }
            }
        }

        if ($removedFontCount -gt 0) {
            Write-PspHost "  Removed $removedFontCount $fontDisplayName font file(s)." -ForegroundColor Green
        }
        elseif ($fontMatches -eq 0) {
            Write-PspHost "  No Nerd Font files matching '$fontDisplayName' found to remove." -ForegroundColor DarkGray
        }
        if ($skippedMachineScope) {
            Write-Warning '  Machine-wide font files need an elevated (admin) terminal. Re-run elevated to remove them.'
            $preserved += 'Nerd Fonts installed machine-wide (re-run elevated with -RemoveFonts)'
        }
    }
    else { $preserved += 'Nerd Fonts (use -RemoveFonts to remove)' }

    # Phase 7: Profile files
    $docsRoot = Split-Path (Split-Path $PROFILE)
    $profileDirs = @(
        Join-Path $docsRoot 'PowerShell'
        Join-Path $docsRoot 'WindowsPowerShell'
    )
    foreach ($dir in $profileDirs) {
        $mainProfile = Join-Path $dir 'Microsoft.PowerShell_profile.ps1'
        $originalBackup = Join-Path $dir 'profile.original.ps1'
        $originalRestored = $false
        $hasOriginal = Test-Path -LiteralPath $originalBackup
        if ($hasOriginal -and (Test-PspProfileFile -Path $originalBackup)) {
            # Setup versions before 1.0.0 could save an installed copy of this profile as the original; it is not the user's.
            $hasOriginal = $false
            if ($PSCmdlet.ShouldProcess($originalBackup, 'Remove profile.original.ps1 (a copy of this profile, not the pre-install one)')) {
                Remove-Item -LiteralPath $originalBackup -Force -ErrorAction SilentlyContinue
            }
        }
        if ($hasOriginal) {
            # Restore the pre-install profile saved on first install instead of leaving none behind.
            if ($PSCmdlet.ShouldProcess($mainProfile, 'Restore original profile saved before first install')) {
                try {
                    Copy-Item -LiteralPath $originalBackup -Destination $mainProfile -Force -ErrorAction Stop
                    Remove-Item -LiteralPath $originalBackup -Force -ErrorAction SilentlyContinue
                    $originalRestored = $true
                    Write-PspHost "  Restored original profile to $mainProfile" -ForegroundColor Green
                }
                catch {
                    Write-Warning "  Could not restore $mainProfile from profile.original.ps1: $($_.Exception.Message)"
                    $preserved += "profile.original.ps1 in $dir (restore failed; copy it over Microsoft.PowerShell_profile.ps1 yourself)"
                }
            }
        }
        elseif (Test-Path -LiteralPath $mainProfile) {
            if ($PSCmdlet.ShouldProcess($mainProfile, 'Remove profile file')) {
                Remove-Item -LiteralPath $mainProfile -Force -ErrorAction SilentlyContinue
                Write-PspHost "  Removed $mainProfile" -ForegroundColor DarkGray
            }
        }
        # Older profile copies made on each install or update. Without profile.original.ps1 the oldest may be
        # the profile from before the first install, so they are only removed when that is not the case.
        $oldCopies = @(Get-ChildItem -LiteralPath $dir -Filter 'oldprofile*.ps1' -File -ErrorAction SilentlyContinue)
        if ($oldCopies.Count -gt 0) {
            if ($originalRestored -or $RemoveUserData) {
                foreach ($copy in $oldCopies) {
                    if ($PSCmdlet.ShouldProcess($copy.FullName, 'Remove older profile copy')) { Remove-Item -LiteralPath $copy.FullName -Force -ErrorAction SilentlyContinue }
                }
            }
            else {
                $preserved += "$($oldCopies.Count) older profile copy(ies) in $dir (oldprofile*.ps1; the oldest may be your pre-install profile; -RemoveUserData removes them)"
            }
        }
        if ($RemoveUserData) {
            foreach ($userFile in @('profile_user.ps1', 'profile_user.ps1.bak')) {
                $userProf = Join-Path $dir $userFile
                if (Test-Path -LiteralPath $userProf) {
                    if ($PSCmdlet.ShouldProcess($userProf, 'Remove user profile overrides')) {
                        Remove-Item -LiteralPath $userProf -Force -ErrorAction SilentlyContinue
                        Write-PspHost "  Removed $userProf" -ForegroundColor DarkGray
                    }
                }
            }
        }
        elseif (Test-Path -LiteralPath (Join-Path $dir 'profile_user.ps1')) {
            $preserved += "profile_user.ps1 in $dir (use -RemoveUserData to remove)"
        }
        # Leave no empty profile directory behind.
        if ((Test-Path -LiteralPath $dir) -and -not (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($PSCmdlet.ShouldProcess($dir, 'Remove empty profile directory')) { Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue }
        }
    }

    # Phase 8: Summary
    Write-PspHost ''
    if ($preserved) {
        Write-PspHost ''
        Write-PspHost 'Preserved:' -ForegroundColor Yellow
        foreach ($p in $preserved) { Write-PspHost "  - $p" -ForegroundColor DarkGray }
        Write-PspHost ''
        if (-not $All) {
            Write-PspHost 'Use Uninstall-Profile -All to remove everything.' -ForegroundColor Yellow
        }
    }
    Restart-TerminalToApply -Message "Uninstall complete. Restarting terminal..."
}

# Utility
function path {
    <#
    .SYNOPSIS
    Display PATH entries.
    #>
    $env:PATH -split ';' | Where-Object { $_ }
}

# Fetch weather by city or IP geolocation through wttr.in with an Open-Meteo fallback.
function weather {
    <#
    .SYNOPSIS
    Weather lookup.
    #>
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
        Write-PspHost "$($loc.name): ${temp}${unit}" -ForegroundColor Cyan
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not fetch weather: $_"
    }
}

# List saved WiFi profiles from netsh's XML export, which is the same in every Windows language; passwords stay masked unless -Reveal.
function wifipass {
    <#
    .SYNOPSIS
    List saved WiFi profiles (passwords masked; -Reveal to show).
    .EXAMPLE
    wifipass
    List saved WiFi profiles with masked passwords.
    .EXAMPLE
    wifipass HomeWifi -Reveal
    Show one stored password (run elevated).
    #>
    param([string]$SSID, [switch]$Reveal)
    $exportDir = Join-Path ([System.IO.Path]::GetTempPath()) ('psp-wlan-' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
    try {
        # key=clear writes plaintext keys into the export, so it is requested only with -Reveal and the folder is always deleted.
        $exportArgs = @('wlan', 'export', 'profile', "folder=$exportDir")
        if ($SSID) { $exportArgs += 'name=' + ($SSID -replace '["\r\n`&|<>^;$(){}]', '') }
        if ($Reveal) { $exportArgs += 'key=clear' }
        $null = & netsh.exe @exportArgs 2>&1
        $files = @(Get-ChildItem -LiteralPath $exportDir -Filter *.xml -File -ErrorAction SilentlyContinue)
        if ($files.Count -eq 0) {
            if ($SSID) { Write-Error "Profile '$SSID' not found." } else { Write-PspHost 'No saved WiFi profiles (or WLAN AutoConfig is not running).' -ForegroundColor Yellow }
            return
        }
        foreach ($f in $files) {
            $doc = New-Object System.Xml.XmlDocument
            $doc.Load($f.FullName)
            $name = [string]$doc.WLANProfile.name
            $shared = $doc.WLANProfile.MSM.security.sharedKey
            $display = if (-not $shared) { '(no password stored)' }
            elseif ($Reveal -and [string]$shared.protected -eq 'false') { [string]$shared.keyMaterial }
            elseif ($Reveal) { '(stored encrypted; run elevated to reveal)' }
            else { '******** (use -Reveal to show)' }
            Write-PspHost "$name : $display"
        }
    }
    catch { Write-Error "Failed to query WiFi profiles: $_" }
    finally { Remove-Item -LiteralPath $exportDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# Open the hosts file with an elevated preferred editor.
function hosts {
    <#
    .SYNOPSIS
    Open hosts file (elevated).
    #>
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $editor = Resolve-PreferredEditor
    $cmdInfo = Get-Command $editor -ErrorAction Ignore
    $editorPath = if ($cmdInfo -and $cmdInfo.Source) { $cmdInfo.Source } else { $editor }
    if ($cmdInfo -and $cmdInfo.CommandType -eq 'Application' -and $editorPath -match '\.(cmd|bat)$') {
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList (ConvertTo-NativeArgumentLine (@('/c', $editorPath) + @($script:ResolvedEditorArgs) + @($hostsPath)))
    }
    else {
        Start-Process -FilePath $editorPath -ArgumentList (ConvertTo-NativeArgumentLine (@($script:ResolvedEditorArgs) + @($hostsPath))) -Verb RunAs
    }
}

# Estimate download speed in Mbps through Cloudflare.
function speedtest {
    <#
    .SYNOPSIS
    Download speed test.
    #>
    Write-PspHost "Testing download speed..." -ForegroundColor Cyan
    $url = "https://speed.cloudflare.com/__down?bytes=25000000"
    $start = Get-Date
    $oldTitle = Push-TabTitle 'speedtest'
    try {
        Invoke-RestMethod $url -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop | Out-Null
        $elapsed = [math]::Max(((Get-Date) - $start).TotalSeconds, 0.001)
        $mbps = [math]::Round((25 * 8) / $elapsed, 1)
        Write-PspHost "Download: ~${mbps} Mbps ($([math]::Round($elapsed, 1))s for 25 MB)" -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Speed test failed: $_"
    }
    finally { Pop-TabTitle $oldTitle }
}

# Return a human-readable file size or recursive directory size.
function sizeof {
    <#
    .SYNOPSIS
    Human-readable size.
    #>
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

# Show recent System and Application events with timestamp, level, ID, and message.
function eventlog {
    <#
    .SYNOPSIS
    Last event log entries.
    #>
    param([ValidateRange(1, 10000)][int]$Count = 20)
    Get-WinEvent -LogName System, Application -MaxEvents $Count -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated -Descending |
    Select-Object -First $Count TimeCreated, LogName, LevelDisplayName, Id, Message |
    Format-Table -AutoSize -Wrap
}

# SSH & Remote
if (Get-Command ssh -CommandType Application -ErrorAction Ignore) {
    # Add short SSH timeout and keepalive defaults without overriding user options.
    function ssh {
        <#
        .SYNOPSIS
        Ssh.exe wrapper with fast-fail timeout + keepalive.
        #>
        # Match both spaced and compact OpenSSH -o option forms.
        $argText = ($args -join ' ')
        # Use the first positional SSH argument as the tab title and as the host for config lookup.
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

        # Add timeout/keepalive defaults only where neither the command line nor the host's effective
        # config already set them, so the user's ~/.ssh/config is never overridden. ssh -G reports an
        # unset ConnectTimeout as "none" and an unset ServerAliveInterval as "0".
        $effective = @{}
        if ($target) {
            try {
                foreach ($line in (& ssh.exe -G $target 2>$null)) {
                    if ($line -match '^\s*(\S+)\s+(.+?)\s*$') { $effective[$matches[1].ToLowerInvariant()] = $matches[2] }
                }
            }
            catch { $null = $_ }
        }
        $extra = @()
        if ($argText -notmatch '-o\s*ConnectTimeout' -and
            (-not $effective.ContainsKey('connecttimeout') -or $effective['connecttimeout'] -eq 'none')) {
            $extra += '-o'; $extra += 'ConnectTimeout=10'
        }
        if ($argText -notmatch '-o\s*ServerAliveInterval' -and
            (-not $effective.ContainsKey('serveraliveinterval') -or $effective['serveraliveinterval'] -eq '0')) {
            $extra += '-o'; $extra += 'ServerAliveInterval=30'
        }
        if ($argText -notmatch '-o\s*ServerAliveCountMax' -and
            (-not $effective.ContainsKey('serveralivecountmax') -or $effective['serveralivecountmax'] -eq '3')) {
            $extra += '-o'; $extra += 'ServerAliveCountMax=3'
        }

        $oldTitle = if ($target) { Push-TabTitle "ssh $target" } else { $null }
        try {
            if ($MyInvocation.ExpectingInput) { $input | & ssh.exe @extra @args }
            else { & ssh.exe @extra @args }
        }
        finally { Pop-TabTitle $oldTitle }
    }

    # Copy SSH public key to remote host (ssh-copy-id equivalent; the remote side needs a POSIX shell)
    function Copy-SshKey {
        <#
        .SYNOPSIS
        Copy SSH key to remote.
        .EXAMPLE
        Copy-SshKey user@server
        Append your public key to the remote authorized_keys unless it is already there.
        #>
        param([Parameter(Mandatory)][string]$RemoteHost)
        # Remote script: skips a key that is already present and never glues a key onto an unterminated last line.
        $remoteScript = 'umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && tmp=~/.ssh/.psp-key-$$ && tr -d ''\r'' | sed ''/^$/d'' > $tmp && { [ $(tail -c1 $tmp | wc -l) -gt 0 ] || echo >> $tmp; } && if grep -qxFf $tmp ~/.ssh/authorized_keys; then echo PSP_KEY_ALREADY_PRESENT; else { [ ! -s ~/.ssh/authorized_keys ] || [ $(tail -c1 ~/.ssh/authorized_keys | wc -l) -gt 0 ] || echo >> ~/.ssh/authorized_keys; } && cat $tmp >> ~/.ssh/authorized_keys; fi; rc=$?; rm -f $tmp; chmod 600 ~/.ssh/authorized_keys; chmod 700 ~/.ssh; exit $rc'
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        $keyPath = @('id_ed25519.pub', 'id_rsa.pub') | ForEach-Object { Join-Path $sshDir $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $keyPath) { Write-Error "No SSH public key found in $sshDir\"; return }
        $keyContent = Get-Content -LiteralPath $keyPath -Raw
        if (-not $keyContent) { Write-Error "SSH key file is empty: $keyPath"; return }
        $key = $keyContent.Trim() -replace "`r", ''
        Write-PspHost "Copying $keyPath to $RemoteHost..." -ForegroundColor Cyan
        $output = @($key | ssh $RemoteHost $remoteScript)
        if ($LASTEXITCODE -ne 0) { Write-Error "Failed to copy key."; return }
        if ($output -contains 'PSP_KEY_ALREADY_PRESENT') { Write-PspHost "Key already authorized on $RemoteHost; nothing changed." -ForegroundColor DarkGray }
        else { Write-PspHost "Key copied successfully." -ForegroundColor Green }
    }
    Set-Alias -Name ssh-copy-key -Value Copy-SshKey

    # Generate a named ED25519 key pair without overwriting an existing key.
    function keygen {
        <#
        .SYNOPSIS
        Generate ed25519 key pair.
        #>
        param([string]$Name = 'id_ed25519')
        $keyPath = Join-Path "$env:USERPROFILE\.ssh" $Name
        ssh-keygen -t ed25519 -f $keyPath
    }
}

# Open Remote Desktop Connection for a computer name or IP address.
function rdp {
    <#
    .SYNOPSIS
    Launch RDP session.
    #>
    param([Parameter(Mandatory)][string]$Computer)
    mstsc "/v:$Computer"
}

# Developer Utilities
# Stop the processes using a TCP port; core Windows processes (svchost, lsass, ...) are never stopped.
function killport {
    <#
    .SYNOPSIS
    Kill process on TCP port.
    .EXAMPLE
    killport 3000 -WhatIf
    Show which process listens on port 3000.
    .EXAMPLE
    killport 3000
    Stop it.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][int]$Port)
    $connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if (-not $connections) { Write-PspHost "Nothing listening on port $Port." -ForegroundColor Yellow; return }
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    $killed = 0
    foreach ($procId in $pids) {
        if ($procId -le 4) {
            Write-Warning "Port $Port is owned by System (PID $procId) - skipping."
            continue
        }
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc -and $script:ProtectedProcessNames -contains $proc.ProcessName) {
            Write-Warning "Port $Port belongs to $($proc.ProcessName) (PID $procId), a core Windows process; stopping it can crash or restart Windows. Skipping."
            continue
        }
        if ($proc -and $PSCmdlet.ShouldProcess("$($proc.ProcessName) (PID $procId) on port $Port", 'Stop process')) {
            Write-PspHost "Stopping $($proc.ProcessName) (PID $procId) on port $Port" -ForegroundColor Cyan
            try {
                Stop-Process -Id $procId -Force -ErrorAction Stop
                $killed++
            }
            catch { Write-Warning "Could not stop PID ${procId}: $_" }
        }
    }
    if ($killed -gt 0) { Write-PspHost "Port $Port freed." -ForegroundColor Green }
    else { Write-Warning "No processes were stopped on port $Port." }
}

# Select listening processes through fzf or Out-GridView and terminate them.
function Stop-ListeningPort {
    <#
    .SYNOPSIS
    Interactive picker for listening ports (alias: killports).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $conns = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort)
    if (-not $conns) { Write-PspHost "No listening TCP ports." -ForegroundColor Yellow; return }
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
    if (Get-Command fzf -ErrorAction Ignore) {
        # Format each row into a single fzf line; parse selection back to PID via last column.
        $lines = $rows | ForEach-Object {
            ('{0,-7} {1,-20} {2,-8} {3}' -f $_.Port, $_.Address, $_.PID, $_.Process)
        }
        $picked = $lines | fzf --multi --header='Tab to multi-select, Enter to kill' --prompt='killport> '
        if (-not $picked) { Write-PspHost 'Nothing selected.' -ForegroundColor DarkGray; return }
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
        if (-not $selected) { Write-PspHost 'Nothing selected.' -ForegroundColor DarkGray; return }
    }
    foreach ($row in $selected) {
        if ($row.PID -le 4 -or $script:ProtectedProcessNames -contains $row.Process) {
            Write-Warning "Skipping core Windows process $($row.Process) (PID $($row.PID)) on port $($row.Port)."
            continue
        }
        if ($PSCmdlet.ShouldProcess("PID $($row.PID) ($($row.Process)) on port $($row.Port)", 'Stop process')) {
            try {
                Stop-Process -Id $row.PID -Force -ErrorAction Stop
                Write-PspHost ("Killed: {0} (PID {1}) on port {2}" -f $row.Process, $row.PID, $row.Port) -ForegroundColor Green
            }
            catch { Write-Warning ("Could not stop PID {0}: {1}" -f $row.PID, $_.Exception.Message) }
        }
    }
}
Set-Alias -Name killports -Value Stop-ListeningPort

# Stuck processes / locked files

# Compile the Windows Restart Manager wrapper once per session.
function Initialize-RestartManagerType {
    if ('PSP.RestartManagerV2' -as [type]) { return }
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace PSP {
    public static class RestartManagerV2 {
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
        public static List<int> WhoIsLocking(string[] paths) {
            uint handle; string key = Guid.NewGuid().ToString();
            List<int> ids = new List<int>();
            int r = RmStartSession(out handle, 0, key);
            if (r != 0) throw new Exception("RmStartSession failed: " + r);
            try {
                r = RmRegisterResources(handle, (uint)paths.Length, paths, 0, null, 0, null);
                if (r != 0) throw new Exception("RmRegisterResources failed: " + r);
                uint needed = 0; uint count = 0; uint reason = 0;
                r = RmGetList(handle, out needed, ref count, new RM_PROCESS_INFO[0], ref reason);
                if (r == 234) {
                    RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed]; count = needed;
                    r = RmGetList(handle, out needed, ref count, info, ref reason);
                    if (r != 0) throw new Exception("RmGetList failed: " + r);
                    for (int i = 0; i < count; i++) { if (!ids.Contains(info[i].Process.dwProcessId)) ids.Add(info[i].Process.dwProcessId); }
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

# Find processes holding a file open, or any file inside a folder (up to -MaxFiles files are checked).
function Find-FileLocker {
    <#
    .SYNOPSIS
    Show processes holding a file/folder lock.
    .EXAMPLE
    Find-FileLocker .\app.log
    List the processes that have the file open.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [ValidateRange(1, 100000)][int]$MaxFiles = 1000)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    try { Initialize-RestartManagerType }
    catch { Write-Error "Could not load Restart-Manager API: $($_.Exception.Message)"; return }
    # Restart Manager tracks open files, not folders, so a folder is checked through the files inside it.
    $paths = @($resolved.ProviderPath)
    if (Test-Path -LiteralPath $resolved.ProviderPath -PathType Container) {
        $paths = @(Get-ChildItem -LiteralPath $resolved.ProviderPath -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles | ForEach-Object { $_.FullName })
        if ($paths.Count -eq 0) {
            Write-PspHost "No files inside $($resolved.ProviderPath) to check (Restart Manager cannot see handles on the folder itself)." -ForegroundColor Yellow
            return
        }
        if ($paths.Count -ge $MaxFiles) { Write-Warning "Checked the first $MaxFiles files only; raise -MaxFiles to check more." }
    }
    $ids = [PSP.RestartManagerV2]::WhoIsLocking([string[]]$paths)
    if (-not $ids -or $ids.Count -eq 0) {
        Write-PspHost "No process is holding a lock on: $($resolved.ProviderPath)" -ForegroundColor Green
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

# Escalate process termination from Stop-Process to taskkill for names, IDs, or pipeline input.
function Stop-StuckProcess {
    <#
    .SYNOPSIS
    Escalating kill: Stop-Process -> taskkill /F -> /F /T.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ByName')]
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
            if (-not $p) { Write-PspHost "PID $procId already gone." -ForegroundColor DarkGray; continue }
            # Never escalate termination for core processes or system PIDs.
            if ($procId -le 4 -or $script:ProtectedProcessNames -contains $p.ProcessName) {
                Write-Warning "Refusing to stop protected system process: $($p.ProcessName) (PID $procId)."
                continue
            }
            $label = "$($p.ProcessName) (PID $procId)"
            if (-not $PSCmdlet.ShouldProcess($label, 'Stop process (escalating)')) { continue }
            # Stage 1: Stop-Process -Force
            try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { $null = $_ }
            Start-Sleep -Milliseconds 200
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                Write-PspHost "Stopped: $label" -ForegroundColor Green
                continue
            }
            # Stage 2: taskkill /F (with /T if requested)
            $tkArgs = @('/F', '/PID', $procId)
            if ($Tree) { $tkArgs += '/T' }
            & taskkill.exe @tkArgs 2>&1 | Out-Null
            Start-Sleep -Milliseconds 300
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                Write-PspHost "Force-killed: $label" -ForegroundColor Yellow
            }
            else {
                Write-Error "Could not stop: $label. Likely needs SYSTEM privileges (protected process, antivirus, driver-held handle)."
            }
        }
    }
}

# Terminate file lockers before retrying deletion.
# Delete a locked file or folder: list the processes holding it, confirm each one, stop them, then retry the delete.
function Remove-LockedItem {
    <#
    .SYNOPSIS
    Find lockers, kill, and delete (combo).
    .EXAMPLE
    Remove-LockedItem .\build -Recurse
    Delete a folder, stopping the processes that lock files in it after confirming each one.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [switch]$Recurse,
        # Also end child processes of each locker (taskkill /T); off by default because it can close unrelated windows.
        [switch]$Tree,
        [switch]$KillSystem  # include PID 0/4 lockers (usually pointless, always dangerous)
    )
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    if (-not $PSCmdlet.ShouldProcess($resolved.ProviderPath, 'Delete')) { return }
    # Try direct deletion before investigating locks.
    try {
        Remove-Item -LiteralPath $resolved.ProviderPath -Recurse:$Recurse -Force -ErrorAction Stop
        Write-PspHost "Deleted: $($resolved.ProviderPath)" -ForegroundColor Green
        return
    }
    catch {
        Write-PspHost "Initial delete failed, investigating lockers..." -ForegroundColor Yellow
    }
    $lockers = @(Find-FileLocker -Path $resolved.ProviderPath | Where-Object { $_ -is [System.Management.Automation.PSCustomObject] })
    if (-not $lockers) {
        Write-Error "Delete failed but no lockers reported. Check permissions or path." -ErrorAction Continue
        return
    }
    Write-PspHost "Lockers found:" -ForegroundColor Cyan
    $lockers | Format-Table PID, Name, WindowTitle | Out-Host
    foreach ($l in $lockers) {
        if (-not $KillSystem -and ($l.PID -le 4 -or $l.Name -eq 'System')) {
            Write-Warning "Skipping system process $($l.Name) (PID $($l.PID)). Use -KillSystem to override (usually pointless)."
            continue
        }
        # One confirmation per process, now that the user can see what holds the lock.
        if (-not $PSCmdlet.ShouldProcess("$($l.Name) (PID $($l.PID)) holding $($resolved.ProviderPath)", 'Stop process')) { continue }
        Stop-StuckProcess -Id $l.PID -Tree:$Tree -Confirm:$false
    }
    Start-Sleep -Milliseconds 500
    try {
        Remove-Item -LiteralPath $resolved.ProviderPath -Recurse:$Recurse -Force -ErrorAction Stop
        Write-PspHost "Deleted after unlocking: $($resolved.ProviderPath)" -ForegroundColor Green
    }
    catch {
        Write-Error "Still locked after killing reported lockers: $($_.Exception.Message)"
        Write-PspHost 'Next steps: reboot, or check for SYSTEM/driver lock via Sysinternals Handle/Process Explorer.' -ForegroundColor DarkGray
    }
}

# Make configurable HTTP requests with JSON formatting and binary response handling.
function http {
    <#
    .SYNOPSIS
    HTTP requests with auto JSON format.
    .EXAMPLE
    http https://api.github.com/zen
    GET a URL and print the body.
    .EXAMPLE
    http https://httpbin.org/post -Method POST -Body '{"a":1}'
    POST JSON.
    #>
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
            Write-PspHost "Binary response ($contentTypeHeader), $($response.RawContentLength) bytes" -ForegroundColor Yellow
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
            Write-PspHost "$status $($_.Exception.Response.StatusCode)" -ForegroundColor Red
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

# Pretty-print JSON from a file or pipeline input.
function prettyjson {
    <#
    .SYNOPSIS
    Pretty-print JSON.
    #>
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
            Get-Utf8FileText $File | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        else { Write-Error 'Usage: prettyjson <file> or <pipeline> | prettyjson' }
    }
    catch { Write-Error "Invalid JSON: $_" }
}

# JWT decode (strips Bearer prefix, decodes header + payload without verification)
function jwtd {
    <#
    .SYNOPSIS
    Decode JWT.
    #>
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
            Write-PspHost "${label}:" -ForegroundColor Cyan
            $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
        }
        catch { Write-Error "Failed to decode ${label}: $_" }
    }
}

# Unix timestamp converter (no args = now, number = epoch to date, date string = date to epoch)
function epoch {
    <#
    .SYNOPSIS
    Unix timestamp converter.
    #>
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
    <#
    .SYNOPSIS
    Generate UUID.
    #>
    $id = [guid]::NewGuid().ToString()
    Set-Clipboard $id
    Write-PspHost "$id (copied)" -ForegroundColor Green
}

# URL encode / decode
function urlencode {
    <#
    .SYNOPSIS
    URL encode.
    #>
    param([Parameter(Mandatory)][string]$Text)
    [System.Uri]::EscapeDataString($Text)
}
# Decode URL-encoded string
function urldecode {
    <#
    .SYNOPSIS
    URL decode.
    #>
    param([Parameter(Mandatory)][string]$Text)
    [System.Uri]::UnescapeDataString($Text)
}

# Measure execution time of a scriptblock
function timer {
    <#
    .SYNOPSIS
    Measure execution time.
    #>
    param([Parameter(Mandatory)][scriptblock]$Command)
    $oldTitle = Push-TabTitle 'timer'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Command }
    finally {
        $sw.Stop()
        Pop-TabTitle $oldTitle
    }
    Write-PspHost ('Elapsed: {0:N3}s' -f $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
}

# Return $true when an environment variable looks like a secret, by its name or by a credential-shaped value.
function Test-PspSensitiveVariable {
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][string]$Value)
    if ($Name -match '(?i)(passw|(^|_)pass($|_|phrase)|_pwd$|secret|token|api[_-]?key|apikey|credential|connection[_-]?string|private[_-]?key|access[_-]?key|account[_-]?key|session[_-]?key|signing[_-]?key|_pat$|^pat$)') { return $true }
    if (-not $Value) { return $false }
    $shapes = @(
        '\bgh[pousr]_[A-Za-z0-9]{20,}', '\bgithub_pat_[A-Za-z0-9_]{20,}', '\b(AKIA|ASIA)[0-9A-Z]{16}\b', '(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}',
        '\bAIza[0-9A-Za-z_\-]{35}\b', '\bsk-[A-Za-z0-9_-]{20,}', '(?i)\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}', '-----BEGIN[A-Z ]*PRIVATE KEY-----',
        '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', '(?i)://[^/\s:@]+:[^/\s:@]+@',
        '(?i)\bAccountKey=[A-Za-z0-9+/=]{20,}', '(?i)(^|;)\s*(password|pwd)\s*=\s*[^;]+', '(?i)\bSharedAccessSignature=|[?&]sig=[A-Za-z0-9%+/=]{20,}'
    )
    foreach ($shape in $shapes) { if ($Value -match $shape) { return $true } }
    return $false
}

# Search/list environment variables; values that look like secrets are masked unless -ShowValues.
function env {
    <#
    .SYNOPSIS
    Search/list environment variables.
    .EXAMPLE
    env PATH
    Show variables whose name or value matches PATH.
    .EXAMPLE
    env TOKEN -ShowValues
    Show matching variables without masking.
    #>
    param([string]$Pattern, [switch]$ShowValues)
    $vars = Get-ChildItem env: | Sort-Object Name
    if ($Pattern) { $vars = $vars | Where-Object { $_.Name -match $Pattern -or $_.Value -match $Pattern } }
    $vars | ForEach-Object {
        $masked = -not $ShowValues -and (Test-PspSensitiveVariable -Name $_.Name -Value $_.Value)
        [PSCustomObject]@{ Name = $_.Name; Value = $(if ($masked) { '******** (env -ShowValues to reveal)' } else { $_.Value }) }
    } | Format-Table Name, Value -AutoSize -Wrap
}

# Open a TLS session for inspection, capturing the validation errors instead of failing on them.
function Get-PspTlsSession {
    param([Parameter(Mandatory)][string]$Domain, [Parameter(Mandatory)][int]$Port)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect($Domain, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { throw "Connection to ${Domain}:${Port} timed out after 5 seconds" }
        $tcp.EndConnect($async)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 10000
        $stream.WriteTimeout = 10000
        $policy = @{ Errors = [System.Net.Security.SslPolicyErrors]::None }
        # Accept every certificate so it can be shown, but remember why Windows would have rejected it.
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $policy.Errors = $e; $true }.GetNewClosure()
        $ssl = New-Object System.Net.Security.SslStream($stream, $false, $callback)
        $ssl.AuthenticateAsClient($Domain)
        [PSCustomObject]@{ Tcp = $tcp; Ssl = $ssl; Errors = $policy.Errors }
    }
    catch {
        $tcp.Dispose()
        throw
    }
}

# Describe SslPolicyErrors in plain words ('' when the certificate validates).
function Format-PspTlsErrors {
    param([System.Net.Security.SslPolicyErrors]$Errors, [string]$Domain)
    $problems = @()
    if ($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) { $problems += "name does not match $Domain" }
    if ($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) { $problems += 'chain not trusted (expired, self-signed, revoked or unknown CA)' }
    if ($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) { $problems += 'no certificate presented' }
    $problems -join '; '
}

# Check TLS certificate expiry, details and validation status for a domain
function tlscert {
    <#
    .SYNOPSIS
    TLS certificate details.
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$Port = 443
    )
    $session = $null; $cert = $null
    try {
        $session = Get-PspTlsSession -Domain $Domain -Port $Port
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($session.Ssl.RemoteCertificate)
        $daysLeft = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $color = if ($daysLeft -lt 30) { 'Red' } elseif ($daysLeft -lt 90) { 'Yellow' } else { 'Green' }
        $problems = Format-PspTlsErrors -Errors $session.Errors -Domain $Domain
        Write-PspHost "  Subject:     $($cert.Subject)" -ForegroundColor White
        Write-PspHost "  Issuer:      $($cert.Issuer)" -ForegroundColor White
        Write-PspHost "  Valid from:  $($cert.NotBefore)" -ForegroundColor White
        Write-PspHost "  Expires:     $($cert.NotAfter)" -ForegroundColor White
        Write-PspHost "  Days left:   $daysLeft" -ForegroundColor $color
        if ($problems) { Write-PspHost "  Validation:  FAILED - $problems" -ForegroundColor Red }
        else { Write-PspHost "  Validation:  OK (trusted chain, name matches)" -ForegroundColor Green }
        Write-PspHost "  Thumbprint:  $($cert.Thumbprint)" -ForegroundColor DarkGray
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to check certificate for ${Domain}:${Port} - $_"
    }
    finally {
        if ($cert) { $cert.Dispose() }
        if ($session) { $session.Ssl.Dispose(); $session.Tcp.Dispose() }
    }
}

# Quick TCP port scan
function portscan {
    <#
    .SYNOPSIS
    Quick TCP port scan.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [int[]]$Ports = @(21, 22, 25, 53, 80, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017)
    )
    Write-PspHost 'Scan only systems you own or are explicitly authorized to test.' -ForegroundColor DarkYellow
    if (-not $PSCmdlet.ShouldProcess($Hostname, "TCP connect scan of $($Ports.Count) port(s)")) { return }
    Write-PspHost "Scanning $Hostname..." -ForegroundColor Cyan
    $open = 0
    foreach ($port in $Ports) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $connected = $false
            $async = $tcp.BeginConnect($Hostname, $port, $null, $null)
            # Call EndConnect only after completion to preserve the per-port timeout.
            if ($async.AsyncWaitHandle.WaitOne(500)) {
                try { $tcp.EndConnect($async); $connected = $tcp.Connected }
                catch { if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }; $connected = $false }
            }
            if ($connected) {
                Write-PspHost ("  {0,-6} open" -f $port) -ForegroundColor Green
                $open++
            }
        }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Verbose "Port $port closed or filtered"
        }
        finally { $tcp.Dispose() }
    }
    if ($open -eq 0) { Write-PspHost "  No open ports found." -ForegroundColor Yellow }
    Write-PspHost ("Scan complete ({0}/{1} open)." -f $open, $Ports.Count) -ForegroundColor Cyan
}

# Look up IP geolocation through the keyless ipwho.is HTTPS API.
function ipinfo {
    <#
    .SYNOPSIS
    IP geolocation lookup.
    #>
    param([string]$IpAddress)
    $url = if ($IpAddress) { "https://ipwho.is/$IpAddress" } else { "https://ipwho.is/" }
    try {
        $info = Invoke-RestMethod -Uri $url -TimeoutSec 10 -UseBasicParsing
        if (-not $info) { Write-Error "IP lookup returned no data."; return }
        if (-not $info.success) { Write-Error "Lookup failed: $($info.message)"; return }
        Write-PspHost "  IP:       $($info.ip)" -ForegroundColor White
        Write-PspHost "  Location: $($info.city), $($info.region), $($info.country)" -ForegroundColor White
        Write-PspHost "  ISP:      $($info.connection.isp)" -ForegroundColor White
        Write-PspHost "  Org:      $($info.connection.org)" -ForegroundColor DarkGray
        Write-PspHost "  AS:       AS$($info.connection.asn)" -ForegroundColor DarkGray
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Failed to lookup IP info: $_"
    }
}

# Quick timestamped backup of a file
function bak {
    <#
    .SYNOPSIS
    Timestamped backup.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Error "File not found: $Path"; return }
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $dest = "$Path.$timestamp.bak"
    Copy-Item -LiteralPath $Path -Destination $dest -Force
    Write-PspHost "Backup: $dest" -ForegroundColor Green
}

# Repeat a command at intervals (like Linux watch)
function watch {
    <#
    .SYNOPSIS
    Repeat command every n seconds.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Command,
        [int]$Interval = 2
    )
    $cmdLabel = ($Command.ToString().Trim() -replace '\s+', ' ')
    if ($cmdLabel.Length -gt 40) { $cmdLabel = $cmdLabel.Substring(0, 40) + '...' }
    $oldTitle = Push-TabTitle "watch: $cmdLabel"
    try {
        Write-PspHost "Every ${Interval}s. Ctrl+C to stop." -ForegroundColor DarkGray
        while ($true) {
            Clear-Host
            Write-PspHost ("watch: every {0}s | {1}" -f $Interval, (Get-Date -Format "HH:mm:ss")) -ForegroundColor DarkGray
            Write-PspHost ""
            try { & $Command }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-PspHost $_.Exception.Message -ForegroundColor Red
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
    <#
    .SYNOPSIS
    WHOIS domain lookup.
    #>
    param([Parameter(Mandatory)][string]$Domain)
    $Domain = $Domain -replace '^https?://', '' -replace '/.*$', ''
    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$Domain" -TimeoutSec 10 -UseBasicParsing
        Write-PspHost "  Domain:     $($rdap.ldhName)" -ForegroundColor White
        Write-PspHost "  Status:     $(@($rdap.status) -join ', ')" -ForegroundColor White
        if ($rdap.entities) {
            $registrar = $rdap.entities | Where-Object { $_.roles -contains 'registrar' } | Select-Object -First 1
            if ($registrar -and $registrar.vcardArray -and @($registrar.vcardArray).Count -gt 1) {
                $fn = $registrar.vcardArray[1] | Where-Object { $_ -and $_[0] -eq 'fn' } | ForEach-Object { $_[3] }
                if ($fn) { Write-PspHost "  Registrar:  $fn" -ForegroundColor White }
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
                # Preserve unparseable registrar event dates as raw values.
                $date = try { ([DateTime]$ev.eventDate).ToString('yyyy-MM-dd') } catch { [string]$ev.eventDate }
                Write-PspHost "  ${label}:$((' ' * [math]::Max(1, 12 - $label.Length)))$date" -ForegroundColor White
            }
        }
        if ($rdap.nameservers) {
            $ns = ($rdap.nameservers | ForEach-Object { $_.ldhName }) -join ', '
            Write-PspHost "  Nameservers: $ns" -ForegroundColor DarkGray
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
function cpy {
    <#
    .SYNOPSIS
    Copy text to clipboard.
    #>
    if (-not $args) { Write-Error "Usage: cpy <text>"; return }; Set-Clipboard ($args -join ' ')
}
# Paste from clipboard
function pst {
    <#
    .SYNOPSIS
    Paste from clipboard.
    #>
    Get-Clipboard
}

# Safely insert clipboard text into the prompt buffer (never executes directly)
function Invoke-Clipboard {
    <#
    .SYNOPSIS
    Safely insert clipboard text into the prompt buffer (never executes directly).
    #>
    $clipboardText = Get-Clipboard -Raw
    if ([string]::IsNullOrWhiteSpace($clipboardText)) {
        Write-PspHost "Clipboard is empty." -ForegroundColor Yellow
        return
    }

    # Insert clipboard contents into the prompt buffer without execution.
    try {
        if ($script:PSP.IsInteractive -and (Get-Module PSReadLine -ErrorAction SilentlyContinue)) {
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

# Complete WSL distro names when wsl.exe is available.
Register-ArgumentCompleter -CommandName Enter-WslHere, ConvertTo-WslPath, ConvertTo-WindowsPath, Stop-Wsl, Get-WslIp, Get-WslFile, Show-WslTree, Open-WslExplorer -ParameterName Distro -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $null = $commandName, $parameterName, $commandAst, $fakeBoundParameters
    if (-not (Get-Command Get-WslDistro -ErrorAction Ignore)) { return }
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

# Read Windows events with optional severity filtering and two-second follow polling.
function journal {
    <#
    .SYNOPSIS
    Tail Windows Event Log.
    .EXAMPLE
    journal System -Count 20 -Level Error
    Show the last 20 errors from the System log.
    #>
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
        Write-PspHost ("{0} [{1,-11}] {2}: {3}" -f $Entry.TimeCreated, $Entry.LevelDisplayName, $Entry.ProviderName, $msg) -ForegroundColor $color
    }
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction SilentlyContinue
    if (-not $events) { Write-PspHost "No events matched." -ForegroundColor Yellow; return }
    $events | Sort-Object TimeCreated | ForEach-Object { Write-JournalLine $_ }
    if (-not $Follow) { return }
    Write-PspHost "Following $LogName. Ctrl+C to stop." -ForegroundColor DarkGray
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
    <#
    .SYNOPSIS
    List disks and partitions.
    #>
    $disks = Get-Disk -ErrorAction SilentlyContinue | Sort-Object Number
    if (-not $disks) { Write-Warning "Get-Disk returned no disks."; return }
    foreach ($disk in $disks) {
        $sizeGB = [math]::Round($disk.Size / 1GB, 1)
        Write-PspHost ("Disk {0}: {1} ({2} GB, {3})" -f $disk.Number, $disk.FriendlyName, $sizeGB, $disk.BusType) -ForegroundColor Cyan
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
            Write-PspHost ("  {0,-3} {1,-6} {2,7} GB  {3,-22} {4}" -f $p.PartitionNumber, $letter, $pSize, $p.Type, $label)
        }
    }
}

# Open an installed terminal process viewer or fall back to svc -Live.
function htop {
    <#
    .SYNOPSIS
    Interactive process viewer.
    #>
    foreach ($c in @('btop', 'ntop', 'htop')) {
        # -CommandType Application so 'htop' resolves to a real binary, not this function (which would self-shadow and skip the svc fallback).
        $cmd = Get-Command $c -CommandType Application -ErrorAction Ignore
        if ($cmd) { & $cmd.Source; return }
    }
    Write-PspHost 'No TUI process viewer installed. Tip: winget install aristocratos.btop4win' -ForegroundColor Yellow
    Write-PspHost 'Falling back to svc -Live.' -ForegroundColor DarkGray
    svc -Live
}

# Combine traceroute with a configurable number of pings per hop.
function mtr {
    <#
    .SYNOPSIS
    Traceroute + per-hop ping.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateRange(1, 50)][int]$Count = 3,
        [ValidateRange(1, 64)][int]$MaxHops = 30
    )
    $oldTitle = Push-TabTitle "mtr: $Target"
    try {
    Write-PspHost "Tracing route to $Target..." -ForegroundColor Cyan
    $trace = Test-NetConnection $Target -TraceRoute -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if (-not $trace -or -not $trace.TraceRoute) { Write-Error "Traceroute failed for $Target"; return }
    Write-PspHost ("  {0,-4} {1,-20} {2,7} {3,7} {4,7}  Samples" -f 'Hop', 'Address', 'Loss%', 'Avg', 'Best') -ForegroundColor DarkGray
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
        Write-PspHost ("  {0,-4} {1,-20} {2,6}% {3,7} {4,7}   {5}" -f $i, $hop, $lossPct, $avg, $best, $times.Count) -ForegroundColor $color
    }
    }
    finally { Pop-TabTitle $oldTitle }
}

# Create an elevated firewall allow rule after confirmation.
function fwallow {
    <#
    .SYNOPSIS
    Quick firewall allow rule (supports -WhatIf/-Confirm).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Port,
        [ValidateSet('TCP', 'UDP', 'Any')][string]$Protocol = 'TCP',
        [ValidateSet('Inbound', 'Outbound')][string]$Direction = 'Inbound'
    )
    if (-not $script:PSP.IsAdmin) { Write-Error 'Firewall changes require an elevated shell.'; return }
    $splat = @{ DisplayName = $Name; Direction = $Direction; Action = 'Allow'; Protocol = $Protocol }
    if ($Port) { $splat.LocalPort = $Port }
    $portText = if ($Port) { " port $Port" } else { '' }
    if (-not $PSCmdlet.ShouldProcess($Name, "Add firewall allow rule ($Direction $Protocol$portText)")) { return }
    New-NetFirewallRule @splat | Out-Null
    Write-PspHost ("Allow rule added: {0} ({1} {2}{3})" -f $Name, $Direction, $Protocol, $portText) -ForegroundColor Green
}

# Create an elevated firewall block rule after confirmation.
function fwblock {
    <#
    .SYNOPSIS
    Quick firewall block rule (supports -WhatIf/-Confirm).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Port,
        [ValidateSet('TCP', 'UDP', 'Any')][string]$Protocol = 'TCP',
        [ValidateSet('Inbound', 'Outbound')][string]$Direction = 'Inbound'
    )
    if (-not $script:PSP.IsAdmin) { Write-Error 'Firewall changes require an elevated shell.'; return }
    $splat = @{ DisplayName = $Name; Direction = $Direction; Action = 'Block'; Protocol = $Protocol }
    if ($Port) { $splat.LocalPort = $Port }
    $portText = if ($Port) { " port $Port" } else { '' }
    if (-not $PSCmdlet.ShouldProcess($Name, "Add firewall block rule ($Direction $Protocol$portText)")) { return }
    New-NetFirewallRule @splat | Out-Null
    Write-PspHost ("Block rule added: {0} ({1} {2}{3})" -f $Name, $Direction, $Protocol, $portText) -ForegroundColor Yellow
}

# Cybersec

# Run curated nmap profiles; the intrusive Full, Stealth and Vuln profiles ask first unless -Force.
function nscan {
    <#
    .SYNOPSIS
    Nmap wrapper.
    .EXAMPLE
    nscan 192.168.1.10
    Quick scan of the top ports of a host you are authorized to scan.
    .EXAMPLE
    nscan 192.168.1.10 -Mode Services
    Detect service versions.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('Quick', 'Full', 'Services', 'Stealth', 'Vuln', 'Ports')]
        [string]$Mode = 'Quick',
        [int[]]$Ports,
        [switch]$Force
    )
    if (-not (Get-Command nmap -CommandType Application -ErrorAction Ignore)) {
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
    Write-PspHost 'Scan only systems you own or are explicitly authorized to test.' -ForegroundColor DarkYellow
    if (-not $PSCmdlet.ShouldProcess($Target, "nmap $($nmapArgs -join ' ')")) { return }
    if ($Mode -in 'Full', 'Stealth', 'Vuln' -and -not $Force) {
        $go = $false
        $why = if ($Mode -eq 'Vuln') { 'runs intrusive NSE scripts that can disrupt services' } else { 'is a heavy or evasive scan that monitoring will flag' }
        try { $go = $PSCmdlet.ShouldContinue("The $Mode profile $why. Scan ${Target}?", 'nscan') }
        catch { Write-Warning "nscan: cannot ask for confirmation in this session; re-run with -Force." }
        if (-not $go) { return }
    }
    Write-PspHost ("nmap {0} {1}" -f ($nmapArgs -join ' '), $Target) -ForegroundColor DarkGray
    $oldTitle = Push-TabTitle "nscan $Mode`: $Target"
    try { nmap @nmapArgs $Target }
    finally { Pop-TabTitle $oldTitle }
}

# Report Authenticode status, signer, and expiry for files or directories.
function sigcheck {
    <#
    .SYNOPSIS
    Authenticode signature details.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $targets = if ((Get-Item -LiteralPath $resolved.ProviderPath).PSIsContainer) {
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
        Write-PspHost ''
        Write-PspHost ("File:      {0}" -f $t.FullName) -ForegroundColor Cyan
        Write-PspHost ("Status:    {0}" -f $sig.Status) -ForegroundColor $color
        if ($sig.StatusMessage) { Write-PspHost ("Message:   {0}" -f $sig.StatusMessage) -ForegroundColor DarkGray }
        if ($sig.SignerCertificate) {
            Write-PspHost ("Signer:    {0}" -f $sig.SignerCertificate.Subject)
            Write-PspHost ("Issuer:    {0}" -f $sig.SignerCertificate.Issuer)
            Write-PspHost ("Expires:   {0}" -f $sig.SignerCertificate.NotAfter)
            Write-PspHost ("Thumb:     {0}" -f $sig.SignerCertificate.Thumbprint) -ForegroundColor DarkGray
        }
        if ($sig.TimeStamperCertificate) {
            Write-PspHost ("Timestamp: {0}" -f $sig.TimeStamperCertificate.Subject) -ForegroundColor DarkGray
        }
    }
}

# List NTFS alternate data streams for files or directories.
function ads {
    <#
    .SYNOPSIS
    Alternate data streams.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $items = if ((Get-Item -LiteralPath $resolved.ProviderPath).PSIsContainer) {
        Get-ChildItem -LiteralPath $resolved.ProviderPath -Recurse -File -ErrorAction SilentlyContinue
    }
    else { Get-Item -LiteralPath $resolved.ProviderPath }
    # Emit structured objects that remain readable with default formatting.
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

# Run quick, full, or path-specific Windows Defender scans.
function defscan {
    <#
    .SYNOPSIS
    Defender scan wrapper.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Path,
        [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick'
    )
    if (-not (Get-Command Start-MpScan -ErrorAction Ignore)) {
        Write-Error 'Windows Defender cmdlets not available on this system.'
        return
    }
    $titleLabel = if ($Path) { "defscan: $Path" } else { "defscan: $Mode" }
    $oldTitle = Push-TabTitle $titleLabel
    try {
        if ($Path) {
            $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
            if (-not $resolved) { Write-Error "Path not found: $Path"; return }
            Write-PspHost ("Custom scan: {0}" -f $resolved.Path) -ForegroundColor Cyan
            Start-MpScan -ScanType CustomScan -ScanPath $resolved.Path
        }
        else {
            $scanType = if ($Mode -eq 'Full') { 'FullScan' } else { 'QuickScan' }
            Write-PspHost ("Running {0}..." -f $scanType) -ForegroundColor Cyan
            Start-MpScan -ScanType $scanType
        }
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            Write-PspHost 'Recent threats:' -ForegroundColor Yellow
            $threats | Select-Object -First 10 | Format-Table ThreatName, SeverityID, DetectionID -AutoSize
        }
        else { Write-PspHost 'No threats recorded.' -ForegroundColor Green }
    }
    finally { Pop-TabTitle $oldTitle }
}

# Check a password through HIBP k-anonymity using only five SHA1 characters.
function pwnd {
    <#
    .SYNOPSIS
    HIBP breach check.
    .EXAMPLE
    pwnd
    Prompt for a password without echo and check it against Have I Been Pwned.
    #>
    # Omit -Candidate to be prompted: a password typed as an argument stays in scrollback and Get-History.
    param([string]$Candidate)
    if (-not $Candidate) {
        $secure = Read-Host -Prompt 'Password to check (not echoed)' -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $Candidate = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if (-not $Candidate) { Write-Error 'No password entered.'; return }
    }
    else {
        Write-Warning 'The password you typed is now in this session''s scrollback and Get-History; run pwnd without arguments to be prompted instead.'
    }
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
                Write-PspHost ("PWNED: seen in {0} breach(es). Do not use this password." -f $count) -ForegroundColor Red
                return
            }
        }
        Write-PspHost 'Safe: password not found in known breaches.' -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "HIBP lookup failed: $_"
    }
}

# Extend tlscert with protocol, cipher, chain, SAN, and SHA256 details.
function certcheck {
    <#
    .SYNOPSIS
    TLS cert chain + pinning.
    .EXAMPLE
    certcheck example.com
    Show the certificate chain, SANs, pin and any validation errors.
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        [int]$Port = 443
    )
    $session = $null; $chain = $null; $cert = $null
    try {
        $session = Get-PspTlsSession -Domain $Domain -Port $Port
        $ssl = $session.Ssl
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chainValid = $chain.Build($cert)
        $problems = Format-PspTlsErrors -Errors $session.Errors -Domain $Domain
        $nameOk = -not ($session.Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)
        $daysLeft = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $expiryColor = if ($daysLeft -lt 30) { 'Red' } elseif ($daysLeft -lt 90) { 'Yellow' } else { 'Green' }
        Write-PspHost ("Host:         {0}:{1}" -f $Domain, $Port) -ForegroundColor Cyan
        Write-PspHost ("TLS:          {0}" -f $ssl.SslProtocol)
        Write-PspHost ("Cipher:       {0} {1} bits" -f $ssl.CipherAlgorithm, $ssl.CipherStrength)
        Write-PspHost ("Subject:      {0}" -f $cert.Subject)
        Write-PspHost ("Issuer:       {0}" -f $cert.Issuer)
        Write-PspHost ("Serial:       {0}" -f $cert.SerialNumber) -ForegroundColor DarkGray
        Write-PspHost ("SHA256 pin:   {0}" -f $cert.GetCertHashString('SHA256')) -ForegroundColor DarkGray
        Write-PspHost ("Not before:   {0}" -f $cert.NotBefore)
        Write-PspHost ("Not after:    {0}" -f $cert.NotAfter)
        Write-PspHost ("Days left:    {0}" -f $daysLeft) -ForegroundColor $expiryColor
        Write-PspHost ("Chain valid:  {0}" -f $chainValid) -ForegroundColor $(if ($chainValid) { 'Green' } else { 'Red' })
        Write-PspHost ("Name match:   {0}" -f $nameOk) -ForegroundColor $(if ($nameOk) { 'Green' } else { 'Red' })
        if ($problems) { Write-PspHost ("Validation:   FAILED - {0}" -f $problems) -ForegroundColor Red }
        else { Write-PspHost 'Validation:   OK' -ForegroundColor Green }
        $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($sanExt) {
            $san = ($sanExt.Format($false) -replace 'DNS Name=', '' -replace ',\s*', ', ')
            Write-PspHost ("SAN:          {0}" -f $san) -ForegroundColor DarkGray
        }
        Write-PspHost 'Chain:' -ForegroundColor DarkGray
        foreach ($element in $chain.ChainElements) {
            $ec = $element.Certificate
            Write-PspHost ("  {0} (exp {1})" -f $ec.Subject, $ec.NotAfter.ToString('yyyy-MM-dd')) -ForegroundColor DarkGray
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "certcheck failed for ${Domain}:${Port} - $_"
    }
    finally {
        if ($chain) { $chain.Dispose() }
        if ($cert) { $cert.Dispose() }
        if ($session) { $session.Ssl.Dispose(); $session.Tcp.Dispose() }
    }
}

# Report file entropy from 0.0 to 8.0 as an indicator of packing or encryption.
function entropy {
    <#
    .SYNOPSIS
    Shannon entropy.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $bytes = [System.IO.File]::ReadAllBytes($resolved.Path)
    if ($bytes.Length -eq 0) { Write-PspHost 'Empty file.' -ForegroundColor Yellow; return }
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
    Write-PspHost ("File:    {0} ({1} bytes)" -f (Split-Path $resolved.Path -Leaf), $bytes.Length) -ForegroundColor Cyan
    Write-PspHost ("Entropy: {0:N3} / 8.000 ({1})" -f $e, $label) -ForegroundColor $color
}

# Developer

# Serve a directory through Python or npx. Loopback only by default: both servers
# listen on every interface unless told otherwise. Use -Bind 0.0.0.0 to share on the LAN.
function serve {
    <#
    .SYNOPSIS
    One-line HTTP server.
    .EXAMPLE
    serve 8080
    Serve the current folder on http://127.0.0.1:8080.
    #>
    param(
        [int]$Port = 8000,
        [string]$Path = '.',
        [string]$Bind = '127.0.0.1'
    )
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "Path not found: $Path"; return }
    $oldTitle = Push-TabTitle "serve :$Port"
    try {
        # The Microsoft Store 'python' alias exists even when Python is not installed; it only opens the Store.
        $hasPython = $false
        if (Get-Command python -CommandType Application -ErrorAction Ignore) {
            $null = & python -c "import http.server" 2>$null
            $hasPython = $LASTEXITCODE -eq 0
        }
        if ($hasPython) {
            Write-PspHost ("Serving {0} on http://{1}:{2} (Ctrl+C to stop)" -f $resolved.Path, $Bind, $Port) -ForegroundColor Cyan
            Push-Location -LiteralPath $resolved.Path
            try { & python -m http.server $Port --bind $Bind }
            finally { Pop-Location }
            return
        }
        if (Get-Command npx -ErrorAction Ignore) {
            # Pinned so npx never fetches and runs whatever version was published last.
            $httpServer = 'http-server@' + (Get-PspComponentPins).HttpServer
            Write-PspHost ("Serving {0} via npx {1} on http://{2}:{3}" -f $resolved.Path, $httpServer, $Bind, $Port) -ForegroundColor Cyan
            Push-Location -LiteralPath $resolved.Path
            try { & npx --yes $httpServer -p $Port -a $Bind }
            finally { Pop-Location }
            return
        }
        Write-Error 'Install python or node/npx first. E.g. winget install Python.Python.3.12'
    }
    finally { Pop-TabTitle $oldTitle }
}

# Generate a multi-language .gitignore through the Toptal API.
function gitignore {
    <#
    .SYNOPSIS
    Generate .gitignore from gitignore.io.
    #>
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Language)
    $joined = ($Language -join ',').ToLower()
    try {
        $content = Invoke-RestMethod -Uri "https://www.toptal.com/developers/gitignore/api/$joined" -TimeoutSec 15 -UseBasicParsing
        if (-not $content) { Write-Error 'Empty response from gitignore service.'; return }
        $target = Join-Path (Get-Location).ProviderPath '.gitignore'
        if (Test-Path -LiteralPath $target) {
            $backup = "$target.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
            Copy-Item -LiteralPath $target -Destination $backup -ErrorAction Stop
            Write-PspHost ("Backed up existing .gitignore to {0}" -f $backup) -ForegroundColor DarkGray
        }
        [System.IO.File]::WriteAllText($target, $content, [System.Text.UTF8Encoding]::new($false))
        Write-PspHost ("Wrote .gitignore for: {0}" -f $joined) -ForegroundColor Green
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "gitignore fetch failed: $_"
    }
}

# Check out local or remote Git branches through fzf.
function gcof {
    <#
    .SYNOPSIS
    Fuzzy git branch checkout (fzf).
    #>
    if (-not (Get-Command git -ErrorAction Ignore)) { Write-Error 'git is not installed'; return }
    if (-not (Get-Command fzf -ErrorAction Ignore)) { Write-Error 'fzf is not installed (winget install junegunn.fzf)'; return }
    $branches = git branch --all --format='%(refname:short)' 2>$null | Where-Object { $_ -and $_ -notmatch '^origin/HEAD' }
    if (-not $branches) { Write-Error 'No branches found'; return }
    $selected = $branches | fzf --height 40% --reverse --prompt 'checkout> '
    if ($selected) {
        $clean = ($selected -replace '^origin/', '').Trim()
        git checkout $clean
    }
}

# Load exported or quoted .env values into the current session.
function envload {
    <#
    .SYNOPSIS
    Load .env file.
    #>
    param([string]$Path = '.env')
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $loaded = 0
    Get-Content -LiteralPath $resolved.ProviderPath -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        if ($line -match '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $k = $matches[1]; $v = $matches[2].Trim()
            if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
            elseif ($v.Length -ge 2 -and $v.StartsWith("'") -and $v.EndsWith("'")) { $v = $v.Substring(1, $v.Length - 2) }
            # Unquoted values end at an inline comment, as in dotenv.
            else { $v = ($v -replace '\s+#.*$', '').Trim() }
            Set-Item -LiteralPath "env:$k" -Value $v
            $loaded++
        }
    }
    Write-PspHost ("Loaded {0} variable(s) from {1}" -f $loaded, $resolved.Path) -ForegroundColor Green
}

# Look up command examples through an installed tldr client or tldr-pages.
function tldr {
    <#
    .SYNOPSIS
    Quick command examples.
    #>
    if (Get-Command tldr.exe -ErrorAction Ignore) { & tldr.exe @args; return }
    if (-not $args) { Write-Error 'Usage: tldr <command>'; return }
    $cmd = ($args[0]).ToString().ToLower()
    foreach ($platform in @('common', 'windows', 'linux', 'osx')) {
        try {
            $url = "https://raw.githubusercontent.com/tldr-pages/tldr/main/pages/$platform/$cmd.md"
            $page = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            Write-PspHost $page -ForegroundColor White
            return
        }
        catch { continue }
    }
    Write-Error "No tldr page found for '$cmd'. Install native client: winget install tldr-pages.tldr"
}

# Run a scriptblock repeatedly with optional success-based termination.
function repeat {
    <#
    .SYNOPSIS
    Repeat scriptblock N times.
    #>
    param(
        [Parameter(Mandatory, Position = 0)][ValidateRange(1, 10000)][int]$Count,
        [Parameter(Mandatory, Position = 1)][scriptblock]$Command,
        [switch]$UntilSuccess,
        [int]$DelaySeconds = 0
    )
    # Preserve the original title while updating the iteration counter in place.
    $originalTitle = $null
    try { $originalTitle = $Host.UI.RawUI.WindowTitle } catch { $null = $_ }
    try {
        for ($i = 1; $i -le $Count; $i++) {
            try { $Host.UI.RawUI.WindowTitle = "repeat $i/$Count" } catch { $null = $_ }
            Write-PspHost ("[{0}/{1}]" -f $i, $Count) -ForegroundColor DarkGray
            # Clear stale native exit codes before evaluating -UntilSuccess.
            $global:LASTEXITCODE = $null
            $threwError = $false
            try {
                & $Command
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-PspHost $_.Exception.Message -ForegroundColor Red
                $threwError = $true
            }
            if ($UntilSuccess -and -not $threwError -and ($null -eq $LASTEXITCODE -or $LASTEXITCODE -eq 0)) {
                Write-PspHost ("Success on attempt {0}." -f $i) -ForegroundColor Green
                return
            }
            if ($DelaySeconds -gt 0 -and $i -lt $Count) { Start-Sleep -Seconds $DelaySeconds }
        }
        if ($UntilSuccess) { Write-Warning ("Command did not succeed in {0} attempts." -f $Count) }
    }
    finally { Pop-TabTitle $originalTitle }
}

# Create and activate a Python virtual environment.
function mkvenv {
    <#
    .SYNOPSIS
    Create + activate Python venv.
    #>
    param(
        [string]$Name = '.venv',
        [string]$PythonPath
    )
    $python = if ($PythonPath) { $PythonPath }
    elseif (Get-Command python -ErrorAction Ignore) { 'python' }
    elseif (Get-Command py -ErrorAction Ignore) { 'py' }
    else { $null }
    if (-not $python) { Write-Error 'python not found on PATH (winget install Python.Python.3.12)'; return }
    Write-PspHost ("Creating venv at ./{0}..." -f $Name) -ForegroundColor Cyan
    & $python -m venv $Name
    if ($LASTEXITCODE -ne 0) { Write-Error 'venv creation failed'; return }
    $venvRoot = Resolve-Path -LiteralPath $Name
    $activate = Join-Path $venvRoot 'Scripts\Activate.ps1'
    if (-not (Test-Path $activate)) { $activate = Join-Path $venvRoot 'bin/Activate.ps1' }
    if (Test-Path $activate) {
        . $activate
        Write-PspHost ("Activated {0}." -f $Name) -ForegroundColor Green
    }
    else { Write-Warning "Created $Name but Activate.ps1 not found." }
}

# Detection / AST (inspired by vscode-powershell language service)

# Emit function and alias outline entries from a PowerShell file.
function outline {
    <#
    .SYNOPSIS
    AST outline of a .ps1 file.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolved.ProviderPath, [ref]$tokens, [ref]$parseErrors)
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
    $raw = Get-Utf8FileText $resolved.ProviderPath
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

# Search PowerShell function names through the AST.
function psym {
    <#
    .SYNOPSIS
    Symbol search across .ps1 files.
    #>
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
    if ($results.Count -eq 0) { Write-PspHost 'No matches.' -ForegroundColor Yellow; return }
    $results | Sort-Object Name | Format-Table Name, Line, File -AutoSize
}

# Run PSScriptAnalyzer presets with optional automatic fixes.
function lint {
    <#
    .SYNOPSIS
    PSScriptAnalyzer wrapper with presets.
    #>
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
    if (-not $results) { Write-PspHost 'No issues found.' -ForegroundColor Green; return }
    $byRule = $results | Group-Object RuleName | Sort-Object Count -Descending
    Write-PspHost ''
    foreach ($g in $byRule) {
        Write-PspHost ("[{0}] {1}" -f $g.Count, $g.Name) -ForegroundColor Cyan
        foreach ($r in $g.Group) {
            $color = switch ($r.Severity) { 'Error' { 'Red' } 'Warning' { 'Yellow' } default { 'DarkGray' } }
            $rel = try { Resolve-Path -LiteralPath $r.ScriptPath -Relative } catch { $r.ScriptPath }
            Write-PspHost ("  {0,-40} L{1,-5} {2}" -f $rel, $r.Line, $r.Message) -ForegroundColor $color
        }
    }
    Write-PspHost ''
    Write-PspHost ("Total: {0}" -f $results.Count) -ForegroundColor Magenta
}

# AST walker that finds unused parameters and top-level functions with no call sites in the same file.
function Find-DeadCode {
    <#
    .SYNOPSIS
    Unused params / uncalled fns.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { Write-Error "File not found: $Path"; return }
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolved.ProviderPath, [ref]$tokens, [ref]$parseErrors)
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

    Write-PspHost 'Unused parameters:' -ForegroundColor Cyan
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
                Write-PspHost ("  {0} L{1}: `${2}" -f $f.Name, $p.Extent.StartLineNumber, $name) -ForegroundColor Yellow
                $anyUnused = $true
            }
        }
    }
    if (-not $anyUnused) { Write-PspHost '  (none)' -ForegroundColor DarkGray }

    Write-PspHost ''
    Write-PspHost 'Possibly uncalled functions (same-file check):' -ForegroundColor Cyan
    $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.CommandElements[0].Extent.Text }
    $anyUncalled = $false
    foreach ($f in $fns) {
        if ($calls -notcontains $f.Name) {
            Write-PspHost ("  {0} (L{1})" -f $f.Name, $f.Extent.StartLineNumber) -ForegroundColor Yellow
            $anyUncalled = $true
        }
    }
    if (-not $anyUncalled) { Write-PspHost '  (none)' -ForegroundColor DarkGray }
}

# Profile self-diagnostics: version, policy, caches, tools, environment flags.
function Test-Profile {
    <#
    .SYNOPSIS
    Profile diagnostics.
    #>
    Write-PspHost 'Profile Diagnostics' -ForegroundColor Cyan
    Write-PspHost ''
    Write-PspHost ("  PS Version:        {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
    Write-PspHost ("  Language Mode:     {0}" -f $ExecutionContext.SessionState.LanguageMode)
    Write-PspHost ("  Execution Policy:  {0}" -f (Get-ExecutionPolicy))
    Write-PspHost ("  Profile Path:      {0}" -f $PROFILE)
    Write-PspHost ("  Profile Exists:    {0}" -f (Test-Path $PROFILE))
    $userOverride = Join-Path (Split-Path $PROFILE) 'profile_user.ps1'
    Write-PspHost ("  profile_user.ps1:  {0}" -f $(if (Test-Path $userOverride) { 'present' } else { 'absent' }))
    $cache = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
    Write-PspHost ("  Cache Dir:         {0}" -f $cache)
    if (Test-Path $cache) {
        $cacheFiles = Get-ChildItem $cache -File -ErrorAction SilentlyContinue
        Write-PspHost ("  Cache Files:       {0}" -f $cacheFiles.Count)
        foreach ($cf in $cacheFiles) {
            $sz = if ($cf.Length -gt 1024) { '{0} KB' -f [math]::Round($cf.Length / 1KB, 1) } else { '{0} B' -f $cf.Length }
            Write-PspHost ("    {0,-28} {1}" -f $cf.Name, $sz) -ForegroundColor DarkGray
        }
    }
    Write-PspHost ("  Modules Loaded:    {0}" -f (Get-Module).Count)
    Write-PspHost ''
    Write-PspHost 'Managed Tools:' -ForegroundColor Cyan
    foreach ($tool in $script:ProfileTools) {
        $found = Get-Command $tool.Cmd -ErrorAction Ignore
        $status = if ($found) { 'OK' } else { 'MISSING' }
        $color = if ($found) { 'Green' } else { 'Yellow' }
        Write-PspHost ("  {0,-14} {1}" -f $tool.Cmd, $status) -ForegroundColor $color
    }
    Write-PspHost ''
    Write-PspHost 'Environment:' -ForegroundColor Cyan
    Write-PspHost ("  Profile Version:   {0}" -f $script:PSP.Version)
    Write-PspHost ("  Interactive:       {0}" -f $script:PSP.IsInteractive)
    Write-PspHost ("  Admin:             {0}" -f $script:PSP.IsAdmin)
    Write-PspHost ("  CI:                {0}" -f [bool]$env:CI)
    Write-PspHost ("  AI_AGENT:          {0}" -f [bool]$env:AI_AGENT)
}

# Enumerate every installed PowerShell (5.1 Desktop + all Core/7+ locations).
function Get-PwshVersions {
    <#
    .SYNOPSIS
    All installed PowerShell versions.
    #>
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
    $candidates += (Get-Command pwsh -ErrorAction Ignore -All | ForEach-Object { $_.Source })
    $candidates += (Get-ChildItem (Join-Path $env:ProgramFiles 'PowerShell') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'pwsh.exe' })
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

# Emit metadata for every installed version of a module.
function modinfo {
    <#
    .SYNOPSIS
    Module details.
    #>
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

# Search structural PowerShell patterns with an optional AST kind.
function psgrep {
    <#
    .SYNOPSIS
    AST-based code search.
    #>
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
            Write-PspHost ("{0}:{1}: {2}" -f $file, $h.Extent.StartLineNumber, $snippet)
        }
    }
}

function Test-ProfileHistorySafeLine {
    param([AllowNull()][string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $true }
    $sensitivePatterns = @(
        '(?i)password'
        '(?i)secret'
        '(?i)token'
        '(?i)api[_-]?key'
        '(?i)connectionstring'
        '(?i)credential'
        '(?i)bearer'
        '(?i)\b(VTCLI_APIKEY|VT_API_KEY)\b'
        # Scrub pwnd and jwtd invocations anywhere in a command line while excluding embedded verb names.
        '(?i)\bpwnd\s'
        '(?i)\bjwtd\s'
        '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b'
        # Scrub recognizable credential shapes even when no sensitive keyword is present.
        '\bghp_[A-Za-z0-9]{20,}'                          # GitHub personal access token
        '\bgh[ousr]_[A-Za-z0-9]{20,}'                     # GitHub oauth/user/server/refresh tokens
        '\bgithub_pat_[A-Za-z0-9_]{20,}'                  # GitHub fine-grained PAT
        '\bAKIA[0-9A-Z]{16}\b'                            # AWS access key id
        '\bASIA[0-9A-Z]{16}\b'                            # AWS temporary access key id
        '(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}'              # Slack token
        '\bAIza[0-9A-Za-z_\-]{35}\b'                      # Google API key
        '\bsk-[A-Za-z0-9]{20,}'                           # OpenAI-style secret key
        '(?i)\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}'      # Stripe secret/restricted key (underscore style)
        '-----BEGIN[A-Z ]*PRIVATE KEY-----'              # PEM private key material
        '(?i)://[^/\s:@]+:[^/\s:@]+@'                     # credentials embedded in a URL (user:pass@host)
        '(?i)--password[=\s]\S'                           # explicit --password flag with a value
        '(?i)\b(?:mysql|mysqldump|mariadb|psql)\b.*\s-p\S'  # db client password attached to -p (not mkdir -p)
    )
    foreach ($pattern in $sensitivePatterns) {
        if ($Line -match $pattern) { return $false }
    }
    return $true
}

# Apply known feature toggles with explicit parsing for false-like strings.
function Set-PspFeatureOverride {
    param($Settings)
    if (-not $Settings -or -not $Settings.PSObject.Properties['features']) { return }
    foreach ($prop in $Settings.features.PSObject.Properties) {
        if ($script:PSP.Features.ContainsKey($prop.Name)) {
            $val = $prop.Value
            if ($val -is [string]) { $script:PSP.Features[$prop.Name] = ($val -notmatch '^(?i:false|0|no|off|)$') }
            else { $script:PSP.Features[$prop.Name] = [bool]$val }
        }
    }
}

# Configure PSReadLine from theme defaults and user color overrides.
$_pspReadlineColors = $null
try {
    $_pspThemeConfig = Read-JsonFile (Join-Path $cacheDir 'theme.json')
    if ($_pspThemeConfig) {
        if ($_pspThemeConfig.psreadline -and $_pspThemeConfig.psreadline.colors) {
            $_pspReadlineColors = @{}
            foreach ($_pspProp in $_pspThemeConfig.psreadline.colors.PSObject.Properties) {
                $_pspReadlineColors[$_pspProp.Name] = $_pspProp.Value
            }
        }
    }
    # Merge user-settings.json.psreadline.colors on top so wizard/manual overrides win.
    $_pspRlUser = Read-JsonFile (Join-Path $cacheDir 'user-settings.json')
    if ($_pspRlUser) {
        # Apply feature toggles before initializing their load-time consumers.
        Set-PspFeatureOverride $_pspRlUser
        if ($_pspRlUser.psreadline -and $_pspRlUser.psreadline.colors) {
            if ($null -eq $_pspReadlineColors) { $_pspReadlineColors = @{} }
            foreach ($_pspProp in $_pspRlUser.psreadline.colors.PSObject.Properties) {
                $_pspReadlineColors[$_pspProp.Name] = $_pspProp.Value
            }
        }
    }
}
catch { $null = $_ }
$_pspPSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    BellStyle                     = 'None'
}
if ($_pspReadlineColors) { $_pspPSReadLineOptions.Colors = $_pspReadlineColors }
# Retry without custom colors if PSReadLine rejects them.
try { Set-PSReadLineOption @_pspPSReadLineOptions }
catch {
    Write-Warning "PSReadLine options rejected ($($_.Exception.Message)); applying without custom colors."
    $_pspPSReadLineOptions.Remove('Colors')
    try { Set-PSReadLineOption @_pspPSReadLineOptions } catch { Write-Warning "PSReadLine base options failed: $($_.Exception.Message)" }
}

# PSReadLine features that require an interactive console host
if ($script:PSP.IsInteractive -and (Get-Module PSReadLine)) {
    # Enable Core-only predictions on VT-capable hosts unless disabled in user-settings.json.
    if ($PSVersionTable.PSEdition -eq "Core" -and $script:PSP.Features.predictions) {
        $_pspSupportsPrediction = $false
        try {
            $_pspSupportsPrediction = [bool]$Host.UI.SupportsVirtualTerminal -and -not [Console]::IsOutputRedirected
        }
        catch {
            $_pspSupportsPrediction = $false
        }

        if ($_pspSupportsPrediction) {
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
    $_pspSmartPasteHandler = {
        try { Invoke-Clipboard }
        catch { [Microsoft.PowerShell.PSConsoleReadLine]::Ding() }
    }
    Set-PSReadLineKeyHandler -Chord 'Alt+v' -BriefDescription SmartPaste -Description 'Paste clipboard as one block into prompt' -ScriptBlock $_pspSmartPasteHandler

    # Collapse accepted prompts when the customizable transientPrompt feature is enabled.
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

    # Enable PSFzf history and file search unless disabled in user-settings.json.
    if ($script:PSP.Features.psfzf -and (Get-Command fzf -CommandType Application -ErrorAction Ignore)) {
        if (-not $env:FZF_DEFAULT_COMMAND -and (Get-Command rg -CommandType Application -ErrorAction Ignore)) {
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
        return (Test-ProfileHistorySafeLine -Line $line)
    }

    # Cache native completion scripts to avoid launching each tool during shell startup.
    $_pspNativeCompleters = @(
        @{ Cmd = 'kubectl'; Cache = 'kubectl-completion.ps1'; Args = @('completion', 'powershell') }
        @{ Cmd = 'gh';      Cache = 'gh-completion.ps1';      Args = @('completion', '-s', 'powershell') }
        @{ Cmd = 'docker';  Cache = 'docker-completion.ps1';  Args = @('completion', 'powershell') }
    )
    foreach ($_pspNc in $_pspNativeCompleters) {
        if (-not (Get-Command $_pspNc.Cmd -CommandType Application -ErrorAction Ignore)) { continue }
        $_pspNcCachePath = Join-Path $cacheDir $_pspNc.Cache
        $_pspNcReady = (Test-Path -LiteralPath $_pspNcCachePath) -and ((Get-Item -LiteralPath $_pspNcCachePath -ErrorAction SilentlyContinue).Length -gt 0)
        if (-not $_pspNcReady) {
            try {
                $_pspNcOutput = & $_pspNc.Cmd @($_pspNc.Args) 2>$null | Out-String
                if ($_pspNcOutput -and $_pspNcOutput.Trim().Length -gt 0) {
                    [System.IO.File]::WriteAllText($_pspNcCachePath, $_pspNcOutput, [System.Text.UTF8Encoding]::new($false))
                    $_pspNcReady = $true
                }
            }
            catch { $null = $_ }
        }
        if ($_pspNcReady) {
            try { . $_pspNcCachePath }
            catch {
                # Corrupt cache; delete so next load regenerates.
                Remove-Item -LiteralPath $_pspNcCachePath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Prepend active environment, cloud, Kubernetes, and job indicators to the tab title.
    $script:PSP.BaseTitle = "PowerShell {0}{1}" -f $PSVersionTable.PSVersion, $script:PSP.AdminSuffix
    Register-ProfileHook -EventName PrePrompt -Action {
        try {
            $parts = @()
            if ($env:VIRTUAL_ENV) { $parts += "venv:$(Split-Path $env:VIRTUAL_ENV -Leaf)" }
            if ($env:CONDA_DEFAULT_ENV) { $parts += "conda:$env:CONDA_DEFAULT_ENV" }
            if ($env:AWS_PROFILE) { $parts += "aws:$env:AWS_PROFILE" }
            if ($env:AWS_VAULT) { $parts += "aws-vault:$env:AWS_VAULT" }
            # Kubernetes context from the kubeconfig (first KUBECONFIG entry), re-read only when the file changes.
            $kubeConfig = if ($env:KUBECONFIG) { @($env:KUBECONFIG -split ';' | Where-Object { $_ })[0] } else { Join-Path $HOME '.kube/config' }
            if ($kubeConfig -and (Test-Path -LiteralPath $kubeConfig -PathType Leaf)) {
                $kubeItem = Get-Item -LiteralPath $kubeConfig -Force
                $stamp = '{0}|{1}|{2}' -f $kubeItem.FullName, $kubeItem.LastWriteTimeUtc.Ticks, $kubeItem.Length
                $kubeCache = $script:PSP.KubeContextCache
                if (-not $kubeCache -or $kubeCache.Stamp -ne $stamp) {
                    $kubeCtx = $null
                    try {
                        $match = Select-String -LiteralPath $kubeItem.FullName -Pattern '^current-context:\s*(.+)$' -ErrorAction Stop | Select-Object -First 1
                        # Remove YAML quotes from the Kubernetes context name.
                        if ($match) { $kubeCtx = $match.Matches[0].Groups[1].Value.Trim().Trim('"').Trim("'") }
                    }
                    catch { $null = $_ }
                    $kubeCache = @{ Stamp = $stamp; Context = $kubeCtx }
                    $script:PSP.KubeContextCache = $kubeCache
                }
                if ($kubeCache.Context) { $parts += "k8s:$($kubeCache.Context)" }
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
$_pspScriptblock = {
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
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $_pspScriptblock

# dotnet completion (only if dotnet is installed)
if (Get-Command dotnet -CommandType Application -ErrorAction Ignore) {
    $_pspDotnetScriptblock = {
        param($wordToComplete, $commandAst, $cursorPosition)
        dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $_pspDotnetScriptblock
}

# Oh My Posh initialization (interactive only; render with explicit --config every prompt)
if ($script:PSP.IsInteractive) {
    $_pspOmpExecutablePath = Get-OhMyPoshExecutablePath
    if ($_pspOmpExecutablePath) {
        # Read the selected theme from cached config; user-settings.json can override the theme name.
        $_pspThemeName = $null
        try {
            $_pspCfg = Read-JsonFile (Join-Path $cacheDir 'theme.json')
            if ($_pspCfg -and $_pspCfg.theme -and $_pspCfg.theme.name) { $_pspThemeName = $_pspCfg.theme.name }
        }
        catch { Write-Verbose "Failed to parse theme.json: $_" }
        try {
            $_pspUserCfg = Read-JsonFile (Join-Path $cacheDir 'user-settings.json')
            if ($_pspUserCfg -and $_pspUserCfg.theme -and $_pspUserCfg.theme.name) { $_pspThemeName = $_pspUserCfg.theme.name }
        }
        catch { Write-Verbose "Failed to parse user-settings.json: $_" }

        if (-not $_pspThemeName) {
            Write-Warning "No cached OMP theme is configured. Run Update-Profile or setup.ps1 to restore theme.json."
        }

        $_pspLocalThemePath = if ($_pspThemeName) { Join-Path $cacheDir "$_pspThemeName.omp.json" } else { $null }
        if ($_pspLocalThemePath -and -not (Test-Path -LiteralPath $_pspLocalThemePath)) {
            # Startup recovery is limited to local theme files.
            $_pspOldThemePath = Join-Path (Split-Path $PROFILE) "$_pspThemeName.omp.json"
            if (Test-Path -LiteralPath $_pspOldThemePath) {
                try { Move-Item -LiteralPath $_pspOldThemePath -Destination $_pspLocalThemePath -Force -ErrorAction Stop }
                catch { Write-Warning "Could not migrate theme from Documents: $_" }
            }
        }

        if ($_pspLocalThemePath -and (Test-Path -LiteralPath $_pspLocalThemePath)) {
            try {
                if ($null -eq (Read-JsonFile $_pspLocalThemePath)) { throw 'Theme file is empty' }
            }
            catch {
                Write-Warning "Configured OMP theme is invalid at '$_pspLocalThemePath': $_"
                $_pspLocalThemePath = $null
            }
        }

        if ($_pspLocalThemePath -and (Test-Path -LiteralPath $_pspLocalThemePath)) {
            try {
                # Render with the validated local theme.
                $script:OhMyPoshExecutablePath = $_pspOmpExecutablePath
                $script:OhMyPoshConfigPath = $_pspLocalThemePath
                $script:OhMyPoshLastHistoryId = $null
                $env:VIRTUAL_ENV_DISABLE_PROMPT = 1
                $env:PYENV_VIRTUALENV_DISABLE_PROMPT = 1
                $env:POWERLINE_COMMAND = 'oh-my-posh'
                $env:POSH_SHELL = 'pwsh'
                $env:POSH_SHELL_VERSION = $PSVersionTable.PSVersion.ToString()
                $env:CONDA_PROMPT_MODIFIER = $false

                try {
                    if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
                        $_pspSecondaryPrompt = Get-OhMyPoshPromptText `
                            -Type 'secondary' `
                            -ExecutablePath $script:OhMyPoshExecutablePath `
                            -ConfigPath $script:OhMyPoshConfigPath
                        if (-not [string]::IsNullOrWhiteSpace($_pspSecondaryPrompt)) {
                            Set-PSReadLineOption -ContinuationPrompt ($_pspSecondaryPrompt -join "`n")
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

                        # The prompt stage already ran above, so fall back to the text alone.
                        if ([string]::IsNullOrWhiteSpace($output)) {
                            return Get-PspPlainPrompt
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
                        return Get-PspPlainPrompt
                    }
                    finally {
                        $global:LASTEXITCODE = $originalLastExitCode
                    }
                }
            }
            catch {
                Write-Warning "Failed to initialize oh-my-posh with '$_pspLocalThemePath': $_"
            }
        }
        elseif ($_pspThemeName) {
            Write-Warning "Configured OMP theme '$_pspThemeName' was not found locally at '$_pspLocalThemePath'. Run Update-Profile or setup.ps1 to restore it."
        }
    }
    else {
        Write-Warning "oh-my-posh not found. Install the MSI build or use: winget install JanDeDobbeleer.OhMyPosh"
    }
}

# zoxide initialization (interactive only, cached for fast startup)
if ($script:PSP.IsInteractive) {
    $_pspZoxideExecutablePath = Get-ExternalCommandPath -CommandName 'zoxide'
    if ($_pspZoxideExecutablePath) {
        $_pspZoxideCachePath = Join-Path $cacheDir "zoxide-init.ps1"
        # Reuse a non-empty zoxide cache and time out regeneration.
        $_pspCacheValid = $false
        if (Test-Path $_pspZoxideCachePath) {
            try {
                $_pspFileSize = (Get-Item $_pspZoxideCachePath).Length
                if ($_pspFileSize -gt 0) {
                    $_pspCacheContent = Get-Content $_pspZoxideCachePath -First 1 -ErrorAction Stop
                    if ($_pspCacheContent -match '^# ZOXIDE_CACHE_VERSION: .+') { $_pspCacheValid = $true }
                }
            }
            catch { Write-Verbose "Zoxide cache read failed (will regenerate)." }
            if (-not $_pspCacheValid) { Remove-Item $_pspZoxideCachePath -Force -ErrorAction SilentlyContinue }
        }
        if (-not $_pspCacheValid) {
            $_pspZoxideVersionResult = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath --version 2>$null | Out-String).Trim()
            } -ArgumentList @($_pspZoxideExecutablePath) -TimeoutSec 5
            $_pspZoxideVersion = if ($_pspZoxideVersionResult) { $_pspZoxideVersionResult } else { 'unknown' }
            $_pspInitScript = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath init --cmd z powershell | Out-String)
            } -ArgumentList @($_pspZoxideExecutablePath) -TimeoutSec 10
            if ($_pspInitScript) {
                $_pspZoxideInitStr = @($_pspInitScript) -join "`n"
                $_pspZoxideHeader = "# ZOXIDE_CACHE_VERSION: $_pspZoxideVersion"
                $_pspUtf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($_pspZoxideCachePath, ($_pspZoxideHeader + "`n" + $_pspZoxideInitStr), $_pspUtf8NoBom)
            }
            else {
                Write-Warning "zoxide init timed out or produced no output. Cache not written."
            }
        }
        try {
            . $_pspZoxideCachePath
        }
        catch {
            Remove-Item $_pspZoxideCachePath -Force -ErrorAction SilentlyContinue
            $_pspZoxideVersionResult = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath --version 2>$null | Out-String).Trim()
            } -ArgumentList @($_pspZoxideExecutablePath) -TimeoutSec 5
            $_pspZoxideVersion = if ($_pspZoxideVersionResult) { $_pspZoxideVersionResult } else { 'unknown' }
            $_pspInitScript = Invoke-WithTimeout -ScriptBlock {
                param($exePath)
                (& $exePath init --cmd z powershell | Out-String)
            } -ArgumentList @($_pspZoxideExecutablePath) -TimeoutSec 10
            if ($_pspInitScript) {
                $_pspZoxideInitStr = @($_pspInitScript) -join "`n"
                $_pspZoxideHeader = "# ZOXIDE_CACHE_VERSION: $_pspZoxideVersion"
                $_pspUtf8NoBom = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($_pspZoxideCachePath, ($_pspZoxideHeader + "`n" + $_pspZoxideInitStr), $_pspUtf8NoBom)
                try { . $_pspZoxideCachePath } catch { Write-Warning "Failed to initialize zoxide: $_" }
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

# Query core and plugin commands by category or name substring.
function Get-ProfileCommand {
    <#
    .SYNOPSIS
    Query command registry.
    .EXAMPLE
    Get-ProfileCommand -Category Git
    List the git commands.
    #>
    [CmdletBinding()]
    param(
        [string]$Category,
        [string]$Name
    )
    $cmds = @($script:PSP.Commands)
    if ($Category) { $cmds = $cmds | Where-Object { $_.Category -like "*$Category*" } }
    if ($Name) { $cmds = $cmds | Where-Object { $_.Name -like "*$Name*" } }
    # Hide registered commands that are unavailable on the current host.
    $cmds = $cmds | Where-Object { Get-Command $_.Name -ErrorAction Ignore }
    $cmds | Sort-Object Category, Name
}

# Walk through command categories interactively on first run.
function Start-ProfileTour {
    <#
    .SYNOPSIS
    Interactive walkthrough.
    #>
    if (-not [Environment]::UserInteractive) { Write-Warning 'Tour requires an interactive session.'; return }
    # Skip seeded commands that aren't defined on this host (WSL/SSH helpers without their binary).
    $available = $script:PSP.Commands | Where-Object { Get-Command $_.Name -ErrorAction Ignore }
    $categories = @($available | Group-Object Category | Sort-Object Name)
    if ($categories.Count -eq 0) { Write-Warning 'Command registry is empty. Is the profile loaded?'; return }
    $oldTitle = Push-TabTitle 'profile tour'
    try {
    Write-PspHost ''
    Write-PspHost 'PowerShellPerfect Tour' -ForegroundColor Cyan
    Write-PspHost '======================' -ForegroundColor Cyan
    Write-PspHost 'Press Enter to see each category, Ctrl+C to quit.' -ForegroundColor DarkGray
    Write-PspHost ''
    $null = Read-Host 'Ready'
    foreach ($cat in $categories) {
        Write-PspHost ''
        $countLabel = if ($cat.Count -eq 1) { 'command' } else { 'commands' }
        Write-PspHost ("-- {0} ({1} {2}) --" -f $cat.Name, $cat.Count, $countLabel) -ForegroundColor Cyan
        foreach ($entry in ($cat.Group | Sort-Object Name | Select-Object -First 8)) {
            $synopsis = if ($entry.Synopsis) { $entry.Synopsis } else { '' }
            Write-PspHost ("  {0,-22} {1}" -f $entry.Name, $synopsis) -ForegroundColor Gray
        }
        if ($cat.Group.Count -gt 8) {
            Write-PspHost ("  ...{0} more (Get-ProfileCommand -Category '{1}')" -f ($cat.Group.Count - 8), $cat.Name) -ForegroundColor DarkGray
        }
        $null = Read-Host 'Press Enter'
    }
    Write-PspHost ''
    Write-PspHost 'Extend the profile:' -ForegroundColor Cyan
    Write-PspHost '  profile_user.ps1   - PS overrides (after user-settings.json, before plugins)'
    Write-PspHost '  plugins\*.ps1      - drop files in %LOCALAPPDATA%\PowerShellProfile\plugins'
    Write-PspHost '  user-settings.json - features toggles, commandOverrides, trustedDirs'
    Write-PspHost '  .psprc.ps1         - per-directory profile (opt-in via Add-TrustedDirectory)'
    Write-PspHost ''
    Write-PspHost 'Tour complete.' -ForegroundColor Green
    }
    finally { Pop-TabTitle $oldTitle }
}

# Trust a directory for .psprc.ps1 loading, approving the file's current content (run it again after the file changes).
function Add-TrustedDirectory {
    <#
    .SYNOPSIS
    Trust a dir and approve its current .psprc.ps1.
    .EXAMPLE
    Add-TrustedDirectory
    Approve the .psprc.ps1 in the current directory as it is now.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (-not $Path) { $Path = (Get-Location).ProviderPath }
    # Store the resolved provider path used by directory-change checks.
    $resolved = try { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath }
    catch {
        Write-Error "Cannot trust '$Path': path does not exist or is not resolvable."
        return
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        Write-Error "Cannot trust '$resolved': not a directory."
        return
    }
    # Read once: the approved hash and the text loaded below are the same bytes.
    $rcContent = Get-PspRcContent -Directory $resolved
    $rcHash = if ($rcContent) { $rcContent.Hash } else { '' }
    $existing = $script:PSP.TrustedDirs | Where-Object { $_ -ieq $resolved } | Select-Object -First 1
    if ($existing) {
        if ($script:PSP.TrustedRcHashes.ContainsKey($existing) -and [string]$script:PSP.TrustedRcHashes[$existing] -eq $rcHash) {
            Write-PspHost "Already trusted, and .psprc.ps1 is unchanged since it was approved: $existing" -ForegroundColor DarkGray
            return
        }
        $resolved = $existing
    }
    $action = if ($existing) { 'Approve the current .psprc.ps1 content' } else { 'Trust for .psprc.ps1 auto-load' }
    if (-not $PSCmdlet.ShouldProcess($resolved, $action)) { return }
    $saved = $false
    try { $saved = Save-TrustedDirectories -Add $resolved -AddHash $rcHash }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "Save failed: $($_.Exception.Message)"
    }
    if (-not $saved) {
        Write-Warning "Trust was not persisted. Fix user-settings.json and retry."
        return
    }
    if ($rcHash) {
        Write-PspHost ("Trusted: {0} (.psprc.ps1 SHA-256 {1})" -f $resolved, $rcHash) -ForegroundColor Green
        Write-PspHost 'Any later change to .psprc.ps1 (git pull, checkout) stops it from loading until you run Add-TrustedDirectory again.' -ForegroundColor DarkGray
        # The prompt hook only loads on a directory change, so load it now when this is the current directory.
        if ($resolved -ieq (Get-Location).ProviderPath) {
            Write-PspHost 'Loading .psprc.ps1 now...' -ForegroundColor DarkGray
            try { . (New-PspRcScriptBlock -Text $rcContent.Text -Path (Join-Path $resolved '.psprc.ps1')) }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-Warning ".psprc.ps1 failed: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-PspHost "Trusted: $resolved (no .psprc.ps1 yet; run Add-TrustedDirectory again after creating one)." -ForegroundColor Green
    }
}

# Remove a directory from the trust list with case-insensitive support for stale paths.
function Remove-TrustedDirectory {
    <#
    .SYNOPSIS
    Remove trusted directory.
    .EXAMPLE
    Remove-TrustedDirectory C:\src\project
    Stop auto-loading that directory's .psprc.ps1.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (-not $Path) { $Path = (Get-Location).ProviderPath }
    $resolved = try { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath } catch { $Path }
    # Case-insensitive match so Windows path casing differences don't hide the entry.
    $match = $script:PSP.TrustedDirs | Where-Object { $_ -ieq $resolved } | Select-Object -First 1
    if (-not $match) {
        Write-PspHost "Not trusted: $resolved" -ForegroundColor DarkGray
        return
    }
    $resolved = $match
    if (-not $PSCmdlet.ShouldProcess($resolved, 'Remove from trusted directories')) { return }
    $saved = $false
    try { $saved = Save-TrustedDirectories -Remove $resolved }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Warning "Save failed: $($_.Exception.Message)"
    }
    if (-not $saved) {
        Write-Warning "Untrust was not persisted. Fix user-settings.json and retry."
        return
    }
    Write-PspHost "Untrusted: $resolved" -ForegroundColor Yellow
}

# Persist and apply a Windows Terminal background image or clear it.
function Set-TerminalBackground {
    <#
    .SYNOPSIS
    Set/clear WT background image (live + persisted).
    .EXAMPLE
    Set-TerminalBackground "$env:USERPROFILE\Pictures\bg.png" -Opacity 0.1
    Use an image as a faint Windows Terminal background.
    .EXAMPLE
    Set-TerminalBackground -Clear
    Remove the background image.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Position = 0)][string]$Path,
        [ValidateRange(0.0, 1.0)][double]$Opacity = 0.3,
        [ValidateSet('none', 'fill', 'uniform', 'uniformToFill')][string]$StretchMode = 'uniformToFill',
        [ValidateSet('center', 'left', 'top', 'right', 'bottom', 'topLeft', 'topRight', 'bottomLeft', 'bottomRight')][string]$Alignment = 'center',
        # Resize and cache the image at this width while preserving its aspect ratio.
        [ValidateRange(32, 4096)][int]$ResizeWidth,
        [switch]$Clear
    )
    $bgProps = @('backgroundImage', 'backgroundImageOpacity', 'backgroundImageStretchMode', 'backgroundImageAlignment')
    if (-not $Clear -and -not $Path) { Write-Error 'Usage: Set-TerminalBackground <path> | Set-TerminalBackground -Clear'; return }
    $cacheDir = Get-PspCacheDir
    $resolved = $null
    if (-not $Clear) {
        try { $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath }
        catch { Write-Error "Image not found: $Path"; return }
        if ($resolved -notmatch '\.(jpg|jpeg|png|gif|tif|tiff|bmp)$') {
            Write-Warning 'Unusual image extension. Windows Terminal supports jpg/png/gif/tif/bmp.'
        }
        # Reuse a cached PNG for the same source and width.
        if ($ResizeWidth) {
            try {
                Add-Type -AssemblyName System.Drawing -ErrorAction Stop
                $srcName = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
                # The source path hash keeps same-named images from different folders apart.
                $srcTag = (Get-CombinedSha256 -Parts @($resolved.ToLowerInvariant())).Substring(0, 8)
                $resizedPath = Join-Path $cacheDir ("bg-{0}-{1}-{2}.png" -f $srcName, $srcTag, $ResizeWidth)
                $regen = $true
                if (Test-Path -LiteralPath $resizedPath) {
                    $srcTime = (Get-Item -LiteralPath $resolved).LastWriteTimeUtc
                    $cachedTime = (Get-Item -LiteralPath $resizedPath).LastWriteTimeUtc
                    if ($cachedTime -ge $srcTime) { $regen = $false }
                }
                if ($regen -and $PSCmdlet.ShouldProcess($resizedPath, "Write a $ResizeWidth px wide copy of the image")) {
                    if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
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
                    Write-PspHost ("Resized to {0}px wide: {1}" -f $ResizeWidth, $resizedPath) -ForegroundColor DarkGray
                }
                $resolved = $resizedPath
            }
            catch {
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
                Write-Warning "Resize failed (using original image): $($_.Exception.Message)"
            }
        }
    }

    # 1. Persist to user-settings.json under defaults.*; only supplied appearance settings change, missing ones get the defaults.
    $settingsPath = Join-Path $cacheDir 'user-settings.json'
    try {
        $settings = Read-UserSettingsForWrite -Path $settingsPath
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not read user-settings.json: $($_.Exception.Message). Background not persisted."
        return
    }
    $userDefaults = Get-PspProp $settings 'defaults'
    if ($null -eq $userDefaults) {
        $userDefaults = [PSCustomObject]@{}
        Set-PspProp $settings 'defaults' $userDefaults
    }
    if ($Clear) {
        foreach ($p in $bgProps) { Remove-PspProp $userDefaults $p }
    }
    else {
        Set-PspProp $userDefaults 'backgroundImage' $resolved
        $requested = [ordered]@{
            backgroundImageOpacity     = @('Opacity', $Opacity)
            backgroundImageStretchMode = @('StretchMode', $StretchMode)
            backgroundImageAlignment   = @('Alignment', $Alignment)
        }
        foreach ($name in $requested.Keys) {
            if ($PSBoundParameters.ContainsKey($requested[$name][0]) -or -not (Test-PspProp $userDefaults $name)) {
                Set-PspProp $userDefaults $name $requested[$name][1]
            }
        }
    }
    if ($PSCmdlet.ShouldProcess($settingsPath, 'Persist terminal background in user-settings.json')) {
        try {
            if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
            Write-Utf8FileAtomic -Path $settingsPath -Content ($settings | ConvertTo-Json -Depth 10) -BackupPath "$settingsPath.bak"
        }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Error "Could not write user-settings.json: $($_.Exception.Message). Background not persisted."
            return
        }
    }

    # 2. Apply the same values to every installed Windows Terminal variant; the change manifest lets Uninstall-Profile revert them.
    if ((Get-PspProp (Get-PspProp $settings 'windowsTerminal') 'manage') -eq $false) {
        Write-PspHost 'Windows Terminal settings.json is managed elsewhere (windowsTerminal.manage = false). Background persisted to user-settings.json only.' -ForegroundColor DarkGray
        return
    }
    $wtSettingsPaths = @(Get-WindowsTerminalSettingsPaths)
    if ($wtSettingsPaths.Count -eq 0) {
        Write-PspHost 'Windows Terminal settings.json not found (Store/Preview/Canary/unpackaged). Change persisted; will apply after next Update-Profile.' -ForegroundColor DarkGray
        return
    }
    $wtArgs = @{ ManifestPath = (Join-Path $cacheDir 'wt-changes.json') }
    if ($Clear) { $wtArgs.RemoveDefaults = $bgProps }
    else {
        $bgValues = [PSCustomObject]@{}
        foreach ($p in $bgProps) { if (Test-PspProp $userDefaults $p) { Set-PspProp $bgValues $p (Get-PspProp $userDefaults $p) } }
        $wtArgs.Defaults = $bgValues
    }
    foreach ($wtSettingsPath in $wtSettingsPaths) {
        try { [void](Update-WindowsTerminalSettingsFile -Path $wtSettingsPath @wtArgs) }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning "Live apply to WT settings.json failed for $wtSettingsPath`: $($_.Exception.Message)"
        }
    }
    if ($Clear) { Write-PspHost 'Terminal background cleared.' -ForegroundColor Yellow }
    else {
        Write-PspHost ("Terminal background: {0} (opacity {1}, {2}, {3})" -f $resolved, (Get-PspProp $userDefaults 'backgroundImageOpacity'),
            (Get-PspProp $userDefaults 'backgroundImageStretchMode'), (Get-PspProp $userDefaults 'backgroundImageAlignment')) -ForegroundColor Green
    }
}

# Read user-settings.json (comments and trailing commas allowed), or return an empty object when it is missing; throws when it does not parse.
function Read-UserSettingsForWrite {
    param([Parameter(Mandatory)][string]$Path)
    $parsed = Read-JsonFile $Path
    if ($null -eq $parsed) { return [PSCustomObject]@{} }
    if ($parsed -isnot [System.Management.Automation.PSCustomObject]) { throw "$Path does not contain a JSON object." }
    return $parsed
}

# Return the trusted directories (as provider paths) and the approved .psprc.ps1 hashes stored in a settings object.
function Get-PspTrustState {
    param([AllowNull()][object]$Settings)
    $dirs = [System.Collections.Generic.List[string]]::new()
    $hashes = @{}
    $stored = Get-PspProp $Settings 'trustedRcHashes'
    foreach ($entry in (Get-PspArray $Settings 'trustedDirs')) {
        if (-not [string]$entry) { continue }
        # Entries that no longer resolve (a removed folder or drive) stay as written.
        $normalized = try { (Resolve-Path -LiteralPath ([string]$entry) -ErrorAction Stop).ProviderPath } catch { [string]$entry }
        if ($dirs -contains $normalized) { continue }
        $dirs.Add($normalized)
        $hash = Get-PspProp $stored ([string]$entry)
        if ($null -ne $hash) { $hashes[$normalized] = [string]$hash }
    }
    [PSCustomObject]@{ Dirs = $dirs; Hashes = $hashes }
}

# Apply one trust change to user-settings.json as it is on disk now, so trust changes made in other sessions are kept,
# then reload this session's lists from the result. Returns $false when the file could not be read or written.
function Save-TrustedDirectories {
    param([string]$Add, [AllowEmptyString()][string]$AddHash = '', [string]$Remove)
    $settingsPath = Join-Path (Get-PspCacheDir) 'user-settings.json'
    try {
        $settings = Read-UserSettingsForWrite -Path $settingsPath
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not read user-settings.json: $($_.Exception.Message). Trust changes not persisted."
        return $false
    }
    $state = Get-PspTrustState $settings
    if ($Remove) {
        foreach ($d in @($state.Dirs | Where-Object { $_ -ieq $Remove })) { [void]$state.Dirs.Remove($d) }
        $state.Hashes.Remove($Remove)
    }
    if ($Add) {
        if ($state.Dirs -notcontains $Add) { $state.Dirs.Add($Add) }
        $state.Hashes[$Add] = $AddHash
    }
    $hashes = [ordered]@{}
    foreach ($d in $state.Dirs) {
        if ($state.Hashes.ContainsKey($d)) { $hashes[$d] = [string]$state.Hashes[$d] }
    }
    Set-PspProp $settings 'trustedDirs' ([object[]]@($state.Dirs))
    Set-PspProp $settings 'trustedRcHashes' ([PSCustomObject]$hashes)
    try {
        $dir = Split-Path -Parent $settingsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Write-Utf8FileAtomic -Path $settingsPath -Content ($settings | ConvertTo-Json -Depth 10) -BackupPath "$settingsPath.bak"
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
        Write-Error "Could not write user-settings.json: $($_.Exception.Message)"
        return $false
    }
    $script:PSP.TrustedDirs = $state.Dirs
    $script:PSP.TrustedRcHashes = $state.Hashes
    return $true
}

# Help Function (PS5-compatible - $PSStyle only exists in PS7.2+)
function Show-Help {
    <#
    .SYNOPSIS
    Show this help message.
    #>
    # Plain text when NO_COLOR is set (https://no-color.org) or on Windows PowerShell 5.1, which has no $PSStyle.
    if ($null -ne $PSStyle -and [string]::IsNullOrEmpty($env:NO_COLOR)) {
        $c = $PSStyle.Foreground.Cyan; $g = $PSStyle.Foreground.Green
        $y = $PSStyle.Foreground.Yellow; $m = $PSStyle.Foreground.Magenta; $r = $PSStyle.Reset
    }
    else {
        $c = ""; $g = ""; $y = ""; $m = ""; $r = ""
    }
    $helpText = @"
${c}PowerShell Profile Help${r} (version $($script:PSP.Version))
${y}=======================${r}
Get-Help <command> shows the details and examples for a command.

${c}Profile & Updates${r}
${g}Edit-Profile${r} / ${g}ep${r} - Open profile in preferred editor.
${g}edit${r} <file> - Open file in preferred editor.
${g}Update-Profile${r} [-Ref <tag|commit>] - Sync profile, theme, caches, and WT settings (hash-checked). Use -Force to re-apply.
    -InstallMissingTools also installs missing tools with winget (accepting the source and package agreements) and the pinned PSFzf.
${g}Update-PowerShell${r} - Check for new PowerShell releases.
${g}Update-Tools${r} - Update winget-managed tools; direct/MSI Oh My Posh installs are preserved.
${g}Invoke-ProfileWizard${r} / ${g}Reconfigure-Profile${r} - Re-run the install wizard (theme, scheme, font, features).
${g}Show-Help${r} - Show this help message.
${g}reload${r} - Reload the PowerShell profile.
${g}Clear-ProfileCache${r} - Reset profile caches plus OMP internal caches.
${g}Clear-Cache${r} [-IncludeSystemCaches] - Clear the user temp folder and legacy IE cache (asks first); adds Windows\Temp and Prefetch.
${g}duration${r} - Elapsed time of the last command.
${g}Test-ProfileHealth${r} [-PassThru] / ${g}psp-doctor${r} - Diagnose install: tools, caches, fonts, PATH. -PassThru also returns the rows for scripting.
${g}Uninstall-Profile${r} - Remove profile and caches and revert the WT changes it made (later WT edits are kept).
    -RemoveUserData/-RemoveTools/-RemoveFonts or -All for more, -HardResetWindowsTerminal to reset WT to defaults, -Force to uninstall PSFzf/tools even under CI/agent env vars.

${c}Git${r}
${g}gs${r} - git status.  ${g}ga${r} - git add .  ${g}gcmsg${r} <msg> - git commit -m.
${g}gpush${r} / ${g}gpull${r} - git push / pull.  ${g}gcl${r} <repo> - git clone.
${g}gcom${r} <msg> - add + commit.  ${g}lazyg${r} <msg> - add + commit + push.
${g}g${r} - zoxide jump to github dir.

${c}Files & Navigation${r}
${g}la${r} / ${g}ll${r} / ${g}lt${r} - eza listings (hidden, long+git, tree). ${g}ls${r} stays Get-ChildItem.
${g}bcat${r} <file> - Syntax-highlighted viewer (bat). ${g}cat${r} stays Get-Content.
${g}ff${r} <name> - Find files recursively.  ${g}nf${r} <name> - Create new file.
${g}mkcd${r} <dir> - Create dir and cd into it.
${g}touch${r} <file> - Create file or update timestamp.
${g}trash${r} <path> - Move to Recycle Bin.
${g}extract${r} <file> [-Force] - Universal extractor (.zip, .tar, .gz, .7z, .rar); -Force overwrites existing files.
${g}file${r} <path> - Identify file type via magic bytes (like Linux file command).
${g}sizeof${r} <path> - Human-readable file/directory size.
${g}docs${r} / ${g}dtop${r} - Jump to Documents / Desktop.
${g}cdb${r} [N] - cd back N entries in directory history (default 1, previous dir).
${g}cdh${r} - List the cd history stack (most-recent first).

${c}Unix-like${r}
${g}grep${r} <regex> [dir] - Search for pattern in files (uses ripgrep when available).
${g}head${r} <path> [n] / ${g}tail${r} <path> [n] [-f] - First/last n lines.
${g}sed${r} <file> <find> <replace> - Find and replace in file (keeps the encoding, writes <file>.bak).
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
${g}tlscert${r} <domain> [port] - Check TLS certificate expiry, details, and validation errors.
${g}ipinfo${r} [ip] - IP geolocation lookup (no args = your IP).
${g}whois${r} <domain> - WHOIS domain lookup (registrar, dates, nameservers).
${g}nslook${r} <domain> [type] - DNS lookup (A, MX, TXT, etc.).
${g}env${r} [pattern] [-ShowValues] - Search/list environment variables (secret-looking values are masked).
${g}svc${r} [name] [-Count n] [-Live] - htop-like process viewer.
${g}eventlog${r} [n] - Last n event log entries (default 20).
${g}path${r} - Display PATH entries one per line.
${g}weather${r} [city] - Quick weather lookup.
${g}speedtest${r} - Download speed test.
${g}wifipass${r} [ssid] [-Reveal] - List saved WiFi profiles (passwords masked unless -Reveal).
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
${g}vtscan${r} <file> [-Upload] - VirusTotal hash lookup; ${g}-Upload${r} submits unknown files.
${g}vt${r} <subcommand> - Full VirusTotal CLI (vt-cli). Run ${g}vt --help${r} for details.

${c}Developer${r}
${g}killport${r} <port> - Kill process on a TCP port (refuses protected system processes).
${g}killports${r} / ${g}Stop-ListeningPort${r} - Interactive picker: lists all listening ports, pick one or many via fzf, kill.
${g}http${r} <url> [-Method POST] [-Body '...'] - HTTP requests, auto-formats JSON.
${g}prettyjson${r} <file> - Pretty-print JSON (or pipe: ${g}cat data.json | prettyjson${r}).
${g}hb${r} <file> - Upload to a PUBLIC paste (asks first), copy URL.
${g}timer${r} { command } - Measure execution time.
${g}watch${r} { command } [-Interval n] - Repeat command every n seconds (default 2).
${g}bak${r} <file> - Quick timestamped backup.

${c}Docker${r} (when installed)
${g}dps${r} / ${g}dpa${r} - Running / all containers.  ${g}dimg${r} - Images.
${g}dlogs${r} <container> - Follow logs.  ${g}dex${r} <container> [shell] - Exec into container.
${g}dstop${r} - Stop all running containers.  ${g}dprune${r} - System prune. Both ask first.

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
${g}Find-FileLocker${r} <path> [-MaxFiles n] - Show which processes hold a file open, or any file inside a folder (Restart Manager API).
${g}Stop-StuckProcess${r} <name|-Id n> [-Tree] - Escalating kill for processes that ignore Stop-Process.
${g}Remove-LockedItem${r} <path> [-Recurse] [-Tree] - Find lockers, confirm, stop them, then delete. For "file is in use" errors.

${c}Cybersec${r}
${g}nscan${r} <target> [-Mode Quick/Full/Services/Stealth/Vuln/Ports] - Curated nmap profiles; Full/Stealth/Vuln ask first.
    Scan only systems you own or are explicitly authorized to test.
${g}sigcheck${r} <path> - Authenticode signature details (file or directory).
${g}ads${r} <path> - List NTFS alternate data streams.
${g}defscan${r} [path] [-Mode Quick/Full] - Windows Defender scan wrapper.
${g}pwnd${r} [password] - HIBP k-anonymity breach lookup (only first 5 SHA1 chars leave the host); prompts without echo when no argument is given.
${g}certcheck${r} <host> [port] - Full TLS probe: chain and host-name validation, SAN, SHA256 pin, cipher.
${g}entropy${r} <file> - Shannon entropy (detect packed/encrypted payloads).

${c}Developer+${r}
${g}serve${r} [port] [path] [-Bind addr] - One-line HTTP server (python, or a pinned http-server via npx; loopback only by default).
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
${g}Register-ProfileHook${r} -EventName OnProfileLoad/PrePrompt/OnCd -Action { ... } - Hook lifecycle events.
${g}Register-HelpSection${r} -Title ... -Lines @(...) - Add a section to this help.
${g}Register-ProfileCommand${r} -Name ... -Category ... [-Synopsis ...] - Add to command registry.
${g}Add-TrustedDirectory${r} / ${g}Remove-TrustedDirectory${r} [path] - Trust a dir and approve its current .psprc.ps1 (run again after it changes).

${c}Theme${r}
${g}Set-TerminalBackground${r} <image> [-Opacity 0.3] [-StretchMode ...] [-Alignment ...] - Set WT background image (live + persisted).
${g}Set-TerminalBackground${r} -Clear - Remove the background image.

Extend the profile without forking:
  ${m}profile_user.ps1${r}                        - PS-level overrides (after user-settings.json, before plugins).
  ${m}%LOCALAPPDATA%\PowerShellProfile\plugins\*.ps1${r} - drop-in plugins (auto-loaded).
  ${m}user-settings.json${r}                      - features toggles, commandOverrides, trustedDirs (with approved .psprc.ps1 hashes).
  ${m}.psprc.ps1${r}                              - per-directory profile (opt-in via Add-TrustedDirectory).
    For lasting functions/aliases inside .psprc.ps1, use ${g}function global:foo${r} or ${g}Set-Alias -Scope Global${r}.
    ${y}`$env:VAR = ...${r} always persists. Plain function/alias definitions are scoped and disappear after prompt render.
"@
    Write-PspHost $helpText
    if ($script:PSP -and $script:PSP.HelpSections.Count -gt 0) {
        foreach ($section in $script:PSP.HelpSections) {
            Write-PspHost ''
            Write-PspHost ("${c}$($section.Title)${r}")
            foreach ($line in $section.Lines) { Write-PspHost $line }
        }
    }
}

# Seed the extensible command registry used by discovery and the profile tour.
$script:_seedCommands = @(
    @{ Name = 'Update-Profile'; Category = 'Profile'; Synopsis = 'Sync profile, theme, caches, WT settings from a branch, tag or commit' }
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
    @{ Name = 'gcmsg'; Category = 'Git'; Synopsis = 'git commit -m' }
    @{ Name = 'gpush'; Category = 'Git'; Synopsis = 'git push' }
    @{ Name = 'gpull'; Category = 'Git'; Synopsis = 'git pull' }
    @{ Name = 'gcl'; Category = 'Git'; Synopsis = 'git clone' }
    @{ Name = 'gcom'; Category = 'Git'; Synopsis = 'add + commit' }
    @{ Name = 'lazyg'; Category = 'Git'; Synopsis = 'add + commit + push' }
    @{ Name = 'g'; Category = 'Git'; Synopsis = 'zoxide jump to github dir' }
    @{ Name = 'gcof'; Category = 'Git'; Synopsis = 'Fuzzy git branch checkout (fzf)' }
    @{ Name = 'gitignore'; Category = 'Git'; Synopsis = 'Generate .gitignore from gitignore.io' }
    @{ Name = 'la'; Category = 'Files'; Synopsis = 'eza listing with hidden' }
    @{ Name = 'll'; Category = 'Files'; Synopsis = 'eza long + git listing' }
    @{ Name = 'lt'; Category = 'Files'; Synopsis = 'eza tree listing' }
    @{ Name = 'bcat'; Category = 'Files'; Synopsis = 'Syntax-highlighted viewer (bat)' }
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
    @{ Name = 'wifipass'; Category = 'System'; Synopsis = 'List saved WiFi profiles (passwords masked; -Reveal to show)' }
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
    @{ Name = 'vtscan'; Category = 'Cybersec'; Synopsis = 'VirusTotal hash lookup (-Upload submits)' }
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
    @{ Name = 'ssh'; Category = 'SSH'; Synopsis = 'ssh.exe wrapper with fast-fail timeout + keepalive' }
    @{ Name = 'edit'; Category = 'Profile'; Synopsis = 'Open file in preferred editor' }
    @{ Name = 'vt'; Category = 'Cybersec'; Synopsis = 'VirusTotal CLI (vt-cli)' }
    @{ Name = 'dps'; Category = 'Docker'; Synopsis = 'List running containers' }
    @{ Name = 'dpa'; Category = 'Docker'; Synopsis = 'List all containers' }
    @{ Name = 'dimg'; Category = 'Docker'; Synopsis = 'List images' }
    @{ Name = 'dlogs'; Category = 'Docker'; Synopsis = 'Follow container logs' }
    @{ Name = 'dex'; Category = 'Docker'; Synopsis = 'Exec into container' }
    @{ Name = 'dstop'; Category = 'Docker'; Synopsis = 'Stop all running containers' }
    @{ Name = 'dprune'; Category = 'Docker'; Synopsis = 'docker system prune' }
    @{ Name = 'cpy'; Category = 'Clipboard'; Synopsis = 'Copy text to clipboard' }
    @{ Name = 'pst'; Category = 'Clipboard'; Synopsis = 'Paste from clipboard' }
    @{ Name = 'icb'; Category = 'Clipboard'; Synopsis = 'Insert clipboard into prompt' }
    @{ Name = 'Get-ProfileCommand'; Category = 'Extensibility'; Synopsis = 'Query command registry' }
    @{ Name = 'Start-ProfileTour'; Category = 'Extensibility'; Synopsis = 'Interactive walkthrough' }
    @{ Name = 'Register-ProfileHook'; Category = 'Extensibility'; Synopsis = 'Hook lifecycle events' }
    @{ Name = 'Register-HelpSection'; Category = 'Extensibility'; Synopsis = 'Add section to Show-Help' }
    @{ Name = 'Register-ProfileCommand'; Category = 'Extensibility'; Synopsis = 'Register a command for discovery' }
    @{ Name = 'Add-TrustedDirectory'; Category = 'Extensibility'; Synopsis = 'Trust a dir and approve its current .psprc.ps1' }
    @{ Name = 'Remove-TrustedDirectory'; Category = 'Extensibility'; Synopsis = 'Remove trusted directory' }
    @{ Name = 'Set-TerminalBackground'; Category = 'Theme'; Synopsis = 'Set/clear WT background image (live + persisted)' }
)
foreach ($_pspEntry in $script:_seedCommands) {
    $script:PSP.Commands.Add([PSCustomObject]$_pspEntry)
}
Remove-Variable -Name _seedCommands -Scope Script -ErrorAction SilentlyContinue

# Load user settings before PowerShell overrides and plugins.
$script:UserSettings = $null
try { $script:UserSettings = Read-JsonFile (Join-Path $cacheDir 'user-settings.json') }
catch { Write-Warning "user-settings.json unreadable: $($_.Exception.Message)" }
if ($script:UserSettings) {
    # Authoritative feature apply (also covers the case where the early PSReadLine-block apply was skipped/failed).
    Set-PspFeatureOverride $script:UserSettings
    # Trusted directories carry the SHA-256 of the .psprc.ps1 that was approved; entries without one need a new approval.
    $_pspTrust = Get-PspTrustState $script:UserSettings
    $script:PSP.TrustedDirs = $_pspTrust.Dirs
    $script:PSP.TrustedRcHashes = $_pspTrust.Hashes
    if ($script:UserSettings.PSObject.Properties['commandOverrides']) {
        $_pspOverrideCount = @($script:UserSettings.commandOverrides.PSObject.Properties).Count
        if (-not $script:PSP.Features.commandOverrides) {
            # Warn when commandOverrides entries exist without explicit code-execution opt-in.
            if ($_pspOverrideCount -gt 0 -and $script:PSP.IsInteractive -and $script:PSP.Features.startupMessage) {
                Write-PspHost ("commandOverrides ignored ({0} entries): set features.commandOverrides = true in user-settings.json to apply." -f $_pspOverrideCount) -ForegroundColor DarkYellow
            }
        }
        else {
            $_pspAppliedOverrides = @()
            foreach ($_pspProp in $script:UserSettings.commandOverrides.PSObject.Properties) {
                $_pspOvName = $_pspProp.Name
                # Ignore underscore-prefixed documentation keys.
                if ($_pspOvName -like '_*') { continue }
                $_pspOvBody = [string]$_pspProp.Value
                if ([string]::IsNullOrWhiteSpace($_pspOvBody)) { continue }
                try {
                    Remove-Item "function:$_pspOvName" -ErrorAction SilentlyContinue
                    Remove-Item "alias:$_pspOvName" -ErrorAction SilentlyContinue
                    Set-Item "function:$_pspOvName" -Value ([scriptblock]::Create($_pspOvBody))
                    $_pspAppliedOverrides += $_pspOvName
                }
                catch { Write-Warning "commandOverride '$_pspOvName' failed: $($_.Exception.Message)" }
            }
            # Visible notice every interactive load so JSON-sourced code execution is not invisible.
            if ($_pspAppliedOverrides.Count -gt 0 -and $script:PSP.IsInteractive -and $script:PSP.Features.startupMessage) {
                Write-PspHost ("commandOverrides active ({0}): {1}" -f $_pspAppliedOverrides.Count, ($_pspAppliedOverrides -join ', ')) -ForegroundColor Yellow
            }
        }
    }
}

# Load persistent PowerShell overrides after JSON settings and before plugins.
$_pspUserProfile = Join-Path (Split-Path $PROFILE) "profile_user.ps1"
if (Test-Path -LiteralPath $_pspUserProfile) {
    try { . $_pspUserProfile }
    catch { Write-Warning "Failed to load profile_user.ps1: $_" }
}

# Dot-source plugins with script scope while isolating errors per file.
$_pspPluginDir = Join-Path $cacheDir 'plugins'
if (-not (Test-Path -LiteralPath $_pspPluginDir)) {
    try { New-Item -ItemType Directory -Path $_pspPluginDir -Force | Out-Null } catch { $null = $_ }
}
if (Test-Path -LiteralPath $_pspPluginDir) {
    foreach ($_pspPlugin in (Get-ChildItem -LiteralPath $_pspPluginDir -Filter *.ps1 -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try { . $_pspPlugin.FullName }
        catch {
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Warning "Plugin '$($_pspPlugin.Name)' failed to load: $($_.Exception.Message)"
        }
    }
}

# Check GitHub weekly for updates when the interactive updateCheck feature is enabled.
if ($script:PSP.IsInteractive -and $script:PSP.Features.updateCheck) {
    try {
        $_pspUcStampFile = Join-Path $cacheDir 'last-update-check.txt'
        $_pspUcDoCheck = $true
        if (Test-Path -LiteralPath $_pspUcStampFile) {
            $_pspUcRaw = (Get-Utf8FileText $_pspUcStampFile).Trim()
            $_pspUcLast = [datetime]::MinValue
            if ([datetime]::TryParse($_pspUcRaw, [ref]$_pspUcLast)) {
                if (((Get-Date) - $_pspUcLast).TotalDays -lt 7) { $_pspUcDoCheck = $false }
            }
        }
        if ($_pspUcDoCheck) {
            $_pspUcLatest = Get-LatestMainCommitSha
            if ($_pspUcLatest) {
                $_pspUcBaselineFile = Join-Path $cacheDir 'applied-commit.sha'
                $_pspUcStored = if (Test-Path -LiteralPath $_pspUcBaselineFile) { (Get-Utf8FileText $_pspUcBaselineFile).Trim() } else { $null }
                if (-not $_pspUcStored) {
                    # First check: record baseline so future checks can compare without false negatives.
                    Write-Utf8FileAtomic -Path $_pspUcBaselineFile -Content $_pspUcLatest
                    Write-PspHost ("Update-check enabled. Baseline: {0}. You'll see a notification here when main moves past this commit." -f $_pspUcLatest.Substring(0, 7)) -ForegroundColor DarkGray
                }
                elseif ($_pspUcStored -ne $_pspUcLatest) {
                    Write-PspHost ("Update available: main is at {0}... (applied {1}...). Run: Update-Profile" -f $_pspUcLatest.Substring(0, 7), $_pspUcStored.Substring(0, 7)) -ForegroundColor Yellow
                }
                # Record the check time only after a successful API response.
                Write-Utf8FileAtomic -Path $_pspUcStampFile -Content (Get-Date).ToString('o')
            }
        }
    }
    catch { $null = $_ }
}

# Fire OnProfileLoad hooks (user/plugin extensions).
Invoke-ProfileHook -EventName 'OnProfileLoad'

# Startup complete - show load time
$_pspStopwatch.Stop()
$script:PSP.LoadTimeMs = $_pspStopwatch.ElapsedMilliseconds
if ($script:PSP.IsInteractive -and $script:PSP.Features.startupMessage) {
    Write-PspHost "Profile loaded in $($_pspStopwatch.ElapsedMilliseconds)ms." -ForegroundColor DarkGray
    Write-PspHost "Use 'Show-Help' or 'Start-ProfileTour' to explore." -ForegroundColor Yellow
}
# Load-time temporaries all start with _psp, so variables that profile_user.ps1 or plugins define are left alone.
foreach ($_pspName in @(Get-Variable -Name '_psp*' -Scope Script -ErrorAction Ignore | ForEach-Object { $_.Name })) {
    Remove-Variable -Name $_pspName -Scope Script -ErrorAction Ignore
}
Remove-Variable -Name '_pspName' -Scope Script -ErrorAction Ignore
