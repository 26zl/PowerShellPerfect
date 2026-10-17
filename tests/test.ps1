# Run CI-equivalent and local profile checks. Every step that loads the profile or runs setup.ps1 does so inside a
# disposable sandbox (LOCALAPPDATA, TEMP and $PROFILE redirected, machine-changing commands blocked).
#   pwsh -NoProfile -File tests/test.ps1               # from a normal (non-elevated) shell
#   pwsh -NoProfile -File tests/test.ps1 -SkipPS5      # without Windows PowerShell 5.1
param(
    [switch]$SkipPS5,  # Skip PS5 parse check if powershell.exe is unavailable
    # Elevated runs are refused because a test mistake could then change machine-wide state; use only in a disposable VM.
    [switch]$AllowElevated
)

$ErrorActionPreference = 'Stop'
# Use the platform temp directory when TEMP is unavailable.
if (-not $env:TEMP) { $env:TEMP = [System.IO.Path]::GetTempPath() }
. (Join-Path $PSScriptRoot 'lib\Sandbox.ps1')
Assert-PspTestSafety -AllowElevated:$AllowElevated -ScriptName 'tests/test.ps1'
# Resolve repoRoot as the parent of tests/.
$repoRoot = Split-Path -Parent $PSScriptRoot
$passed = 0
$failed = 0
$skipped = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Clean test sandboxes on terminating errors and normal script exit.
$script:TestArtifactPatterns = @('psp-test-*', 'psp-child-*')
$script:SweepTestArtifacts = {
    foreach ($pat in $script:TestArtifactPatterns) {
        Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter $pat -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $script:SweepTestArtifacts | Out-Null
trap {
    Write-Host ''
    Write-Host ('Aborted: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host 'Sweeping sandbox artifacts ...' -ForegroundColor Yellow
    & $script:SweepTestArtifacts
    break
}

# Files that are excluded from static scans (test.ps1 itself contains patterns it checks for)
$selfExclude = 'test.ps1'

function Write-Result {
    param([string]$Name, [string]$Status, [string]$Detail)
    switch ($Status) {
        'PASS' { Write-Host "  PASS  $Name" -ForegroundColor Green; $script:passed++ }
        'FAIL' {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            if ($Detail) { Write-Host "        $Detail" -ForegroundColor Yellow }
            $script:failed++
        }
        'SKIP' {
            Write-Host "  SKIP  $Name" -ForegroundColor DarkGray
            if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGray }
            $script:skipped++
        }
    }
}

# Run a script body in a child process whose first lines enter a fresh sandbox; returns its output lines and exit code.
# The body sees $RepoRoot, $ProfileSource and $Sandbox and runs with the profile not yet loaded.
function Invoke-SandboxChild {
    param([Parameter(Mandatory)][string]$Body, [string]$Exe = 'pwsh', [string[]]$ExtraArgs = @())
    $childScript = Join-Path ([System.IO.Path]::GetTempPath()) ("psp-child-{0}.ps1" -f [System.IO.Path]::GetRandomFileName())
    $prelude = @'
param([string]$RepoRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $RepoRoot 'tests\lib\Sandbox.ps1')
$ProfileSource = Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1'
$Sandbox = New-PspSandbox -Name 'child'
Enter-PspSandbox -Sandbox $Sandbox
try {
'@
    $postlude = @'

}
finally { Exit-PspSandbox -Sandbox $Sandbox }
'@
    [System.IO.File]::WriteAllText($childScript, ($prelude + "`r`n" + $Body + "`r`n" + $postlude), [System.Text.UTF8Encoding]::new($false))
    try {
        $output = & $Exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $childScript -RepoRoot $repoRoot @ExtraArgs 2>&1
        [PSCustomObject]@{ Output = @($output | ForEach-Object { "$_" }); ExitCode = $LASTEXITCODE }
    }
    finally { Remove-Item -LiteralPath $childScript -Force -ErrorAction SilentlyContinue }
}

# Print child output with colors matched to its status prefixes.
function Show-ChildOutput {
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        $color = if ($line -match '^\s+(OK|PASS)') { 'Green' } elseif ($line -match 'ASSERT:|^\s+FAIL') { 'Red' } elseif ($line -match '^\s+(WARN|NET)') { 'Yellow' } elseif ($line -match '^\s+SKIP') { 'DarkGray' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
}

Write-Host ''
Write-Host '========== PowerShellPerfect Full Test Suite ==========' -ForegroundColor Cyan
Write-Host ''

# Collect source files once for reuse (exclude .git and self)
$srcPs1 = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1 |
    Where-Object { $_.FullName -notlike '*\.git\*' -and $_.Name -ne $selfExclude }
$srcAll = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1,*.json,*.md,*.yml |
    Where-Object { $_.FullName -notlike '*\.git\*' -and $_.Name -ne $selfExclude }

$profilePath = Join-Path $repoRoot 'Microsoft.PowerShell_profile.ps1'
$setupPath = Join-Path $repoRoot 'setup.ps1'
$hasPs5 = -not $SkipPS5 -and [bool](Get-Command powershell.exe -ErrorAction SilentlyContinue)

# =====================================================================
#  INSTALL: fresh install sandbox
# =====================================================================
Write-Host '--- Install: fresh setup sandbox ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 1. Fresh install sandbox (setup.ps1 -LocalRepo -CiMode against a disposable sandbox, no network)
# -------------------------------------------------------
Write-Host '[1/27] Fresh install sandbox' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$errors = @()
New-Item -ItemType Directory -Path $Sandbox.WtDir -Force | Out-Null
$wtPath = Join-Path $Sandbox.WtDir 'settings.json'
[System.IO.File]::WriteAllText($wtPath, '{"profiles":{"defaults":{"font":{"face":"Consolas"}},"list":[]},"schemes":[],"actions":[]}', [System.Text.UTF8Encoding]::new($false))
# No network: downloads fail as if offline (the Oh My Posh theme download is optional).
function global:Invoke-RestMethod { param([string]$Uri) throw "offline (test sandbox): $Uri" }
& (Join-Path $RepoRoot 'setup.ps1') -LocalRepo $RepoRoot -CiMode -SkipWizard *> $null
Remove-Item -Path function:global:Invoke-RestMethod -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) { $errors += "setup.ps1 exit code $LASTEXITCODE" }
foreach ($p in (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1'), (Join-Path $Sandbox.Ps5Dir 'Microsoft.PowerShell_profile.ps1'), (Join-Path $Sandbox.Ps7Dir 'profile_user.ps1')) {
    if (-not (Test-Path -LiteralPath $p)) { $errors += "missing $p" }
}
foreach ($f in 'theme.json', 'terminal-config.json', 'user-settings.json', 'installed.json', 'wt-changes.json') {
    if (-not (Test-Path -LiteralPath (Join-Path $Sandbox.Cache $f))) { $errors += "cache is missing $f" }
}
$wt = Get-Content -LiteralPath $wtPath -Raw | ConvertFrom-Json
if ($wt.profiles.defaults.font.face -ne 'CaskaydiaCove NF') { $errors += 'Windows Terminal defaults not applied' }
Write-Host '  OK    setup.ps1 installed into the sandbox'
. (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1')
. $PspPostLoadStubs
if (-not (Get-Command Show-Help -ErrorAction SilentlyContinue)) { $errors += 'installed profile did not load' }
else { Write-Host '  OK    installed profile loads' }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'Fresh install sandbox failed' }
    Write-Result 'Fresh install sandbox' 'PASS'
}
catch { Write-Result 'Fresh install sandbox' 'FAIL' $_.Exception.Message }

# =====================================================================
#  CI JOB 1: lint
# =====================================================================
Write-Host ''
Write-Host '--- CI: lint ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 2. PSScriptAnalyzer (same version and settings as CI)
# -------------------------------------------------------
Write-Host '[2/27] PSScriptAnalyzer' -ForegroundColor Cyan
try {
    # The gate never installs modules; without the pinned analyzer the step is skipped with the install command.
    $lintOutput = & pwsh -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'lint.ps1') -NoInstall 2>&1
    if ($LASTEXITCODE -ne 0 -and (($lintOutput | Out-String) -match 'PSScriptAnalyzer [\d.]+ is not installed')) {
        Write-Result 'PSScriptAnalyzer' 'SKIP' 'PSScriptAnalyzer 1.25.0 is not installed: Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser (or run tests/lint.ps1, which installs it)'
    }
    elseif ($LASTEXITCODE -ne 0) {
        $lintOutput | ForEach-Object { Write-Host "        $_" }
        Write-Result 'PSScriptAnalyzer' 'FAIL' 'warnings or errors (see above)'
    }
    else { Write-Result 'PSScriptAnalyzer' 'PASS' }
}
catch { Write-Result 'PSScriptAnalyzer' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 3./4. Smoke test (non-interactive load in a sandbox, both editions)
# -------------------------------------------------------
$smokeBody = @'
$Error.Clear()
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
if ($Error.Count -gt 0) { $Error | ForEach-Object { Write-Host "ASSERT: load error: $_" }; exit 1 }
Write-Host ("  OK    loaded in {0} ms" -f $script:PSP.LoadTimeMs)
'@
foreach ($edition in @(@{ Step = '[3/27]'; Name = 'Smoke test (pwsh)'; Exe = 'pwsh' }, @{ Step = '[4/27]'; Name = 'Smoke test (PS5)'; Exe = 'powershell.exe' })) {
    Write-Host "$($edition.Step) $($edition.Name)" -ForegroundColor Cyan
    if ($env:OS -ne 'Windows_NT') { Write-Result $edition.Name 'SKIP' 'non-Windows host (profile is Windows-targeted)'; continue }
    if ($edition.Exe -eq 'powershell.exe' -and -not $hasPs5) { Write-Result $edition.Name 'SKIP' 'powershell.exe not available or -SkipPS5'; continue }
    try {
        $r = Invoke-SandboxChild -Body $smokeBody -Exe $edition.Exe
        Show-ChildOutput $r.Output
        if ($r.ExitCode -ne 0) { throw "load reported errors (exit $($r.ExitCode))" }
        Write-Result $edition.Name 'PASS'
    }
    catch { Write-Result $edition.Name 'FAIL' $_.Exception.Message }
}

# -------------------------------------------------------
# 5. PS5 parse check (all .ps1 files)
# -------------------------------------------------------
Write-Host '[5/27] PS5 parse check' -ForegroundColor Cyan
if (-not $hasPs5) {
    Write-Result 'PS5 parse check' 'SKIP' 'powershell.exe not available or -SkipPS5'
}
else {
    $ps5Errors = 0
    # Include ALL .ps1 in the repo (same as CI)
    $allPs1 = Get-ChildItem -Path $repoRoot -Filter *.ps1 -Recurse | Where-Object { $_.FullName -notlike '*\.git\*' }
    foreach ($file in $allPs1) {
        $escaped = $file.FullName -replace "'", "''"
        powershell.exe -NoProfile -Command "`$t = `$null; `$e = `$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$escaped', [ref]`$t, [ref]`$e); if (`$e.Count -gt 0) { `$e | ForEach-Object { Write-Host `$_ }; exit 1 }"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "        FAIL: $($file.Name)" -ForegroundColor Red
            $ps5Errors++
        }
    }
    if ($ps5Errors -gt 0) { Write-Result 'PS5 parse check' 'FAIL' "$ps5Errors file(s) failed" }
    else { Write-Result 'PS5 parse check' 'PASS' }
}

# -------------------------------------------------------
# 6. Hardcoded user paths
# -------------------------------------------------------
Write-Host '[6/27] Hardcoded paths' -ForegroundColor Cyan
$pathPatterns = @('C:\\Users\\', 'C:/Users/', '/home/', '\\\\Users\\\\')
$pathFinds = @()
foreach ($file in $srcPs1) {
    $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($p in $pathPatterns) {
            if ($lines[$i] -match $p) {
                $pathFinds += [PSCustomObject]@{ File = $file.Name; Line = $i + 1; Match = $lines[$i].Trim() }
            }
        }
    }
}
if ($pathFinds) {
    $pathFinds | Format-Table -AutoSize
    Write-Result 'Hardcoded paths' 'FAIL' "$($pathFinds.Count) match(es)"
}
else { Write-Result 'Hardcoded paths' 'PASS' }

# -------------------------------------------------------
# 7. Non-ASCII characters
# -------------------------------------------------------
Write-Host '[7/27] Non-ASCII characters' -ForegroundColor Cyan
$asciiFinds = @()
foreach ($file in $srcPs1) {
    $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '[^\x00-\x7E]') {
            $asciiFinds += [PSCustomObject]@{ File = $file.Name; Line = $i + 1; Match = $lines[$i].Trim() }
        }
    }
}
if ($asciiFinds) {
    $asciiFinds | Format-Table -AutoSize
    Write-Result 'Non-ASCII characters' 'FAIL' "$($asciiFinds.Count) line(s)"
}
else { Write-Result 'Non-ASCII characters' 'PASS' }

# -------------------------------------------------------
# 8. UTF-8 BOM
# -------------------------------------------------------
Write-Host '[8/27] UTF-8 BOM' -ForegroundColor Cyan
$bomFinds = @()
$bomFiles = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1,*.psd1,*.json |
    Where-Object { $_.FullName -notlike '*\.git\*' -and $_.Name -ne $selfExclude }
foreach ($file in $bomFiles) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $bomFinds += $file.Name
    }
}
if ($bomFinds) {
    $bomFinds | ForEach-Object { Write-Host "        BOM: $_" -ForegroundColor Red }
    Write-Result 'UTF-8 BOM' 'FAIL' "$($bomFinds.Count) file(s)"
}
else { Write-Result 'UTF-8 BOM' 'PASS' }

# -------------------------------------------------------
# 9. Set-Content -Encoding UTF8 (produces BOM on PS5)
# -------------------------------------------------------
Write-Host '[9/27] Set-Content Encoding check' -ForegroundColor Cyan
$scFinds = @()
foreach ($file in $srcPs1) {
    $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Set-Content\s.*-Encoding\s+UTF8' -and $lines[$i] -notmatch '^\s*#') {
            $scFinds += [PSCustomObject]@{ File = $file.Name; Line = $i + 1; Match = $lines[$i].Trim() }
        }
    }
}
if ($scFinds) {
    $scFinds | Format-Table -AutoSize
    Write-Result 'Set-Content UTF8' 'FAIL' "$($scFinds.Count) match(es)"
}
else { Write-Result 'Set-Content UTF8' 'PASS' }

# -------------------------------------------------------
# 10. Secrets scan
# -------------------------------------------------------
Write-Host '[10/27] Secrets scan' -ForegroundColor Cyan
$secretPatterns = @(
    '(?i)(api[_-]?key|apikey)\s*[:=]\s*[''"][A-Za-z0-9+/=]{16,}[''"]'
    '(?i)(secret|token|password)\s*[:=]\s*[''"][^''"]{8,}[''"]'
    '(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]'
    'ghp_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{82}'
    'sk-[A-Za-z0-9]{32,}'
    '(?i)connectionstring\s*[:=]\s*[''"]Server='
)
$scanFiles = $srcAll | Where-Object { $_.FullName -notlike '*\.github\workflows\*' }
$secretFinds = @()
foreach ($file in $scanFiles) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }
    foreach ($sp in $secretPatterns) {
        if ($content -match $sp) {
            $secretFinds += [PSCustomObject]@{ File = $file.Name; Pattern = $sp.Substring(0, [Math]::Min(40, $sp.Length)) + '...' }
        }
    }
}
if ($secretFinds) {
    $secretFinds | Format-Table -AutoSize
    Write-Result 'Secrets scan' 'FAIL' "$($secretFinds.Count) match(es)"
}
else { Write-Result 'Secrets scan' 'PASS' }

# =====================================================================
#  CI JOB 2: install-flow
# =====================================================================
Write-Host ''
Write-Host '--- CI: install-flow ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 11. JSON config validation
# -------------------------------------------------------
Write-Host '[11/27] JSON config validation' -ForegroundColor Cyan
$jsonErrors = 0
foreach ($jf in @('theme.json', 'terminal-config.json')) {
    $jfPath = Join-Path $repoRoot $jf
    try {
        $null = Get-Content $jfPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch { Write-Host "        FAIL: $jf - $_" -ForegroundColor Red; $jsonErrors++ }
}
if ($jsonErrors -gt 0) { Write-Result 'JSON configs' 'FAIL' "$jsonErrors file(s)" }
else { Write-Result 'JSON configs' 'PASS' }

# -------------------------------------------------------
# 12. Config schema (required keys and pins)
# -------------------------------------------------------
Write-Host '[12/27] Config schema' -ForegroundColor Cyan
$theme = Get-Content (Join-Path $repoRoot 'theme.json') -Raw | ConvertFrom-Json
$terminal = Get-Content (Join-Path $repoRoot 'terminal-config.json') -Raw | ConvertFrom-Json
$schemaErrors = @()
if (-not $theme.theme.name) { $schemaErrors += 'theme.json: missing theme.name' }
if (-not $theme.theme.url) { $schemaErrors += 'theme.json: missing theme.url' }
if ($theme.theme.url -match '/main/') { $schemaErrors += 'theme.json: theme.url follows a branch instead of a release tag' }
if ($theme.theme.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { $schemaErrors += 'theme.json: theme.sha256 missing or malformed' }
if (-not $terminal.defaults) { $schemaErrors += 'terminal-config.json: missing defaults' }
if (-not $terminal.fontInstall) { $schemaErrors += 'terminal-config.json: missing fontInstall' }
if (-not $terminal.fontInstall.name) { $schemaErrors += 'terminal-config.json: missing fontInstall.name' }
if (-not $terminal.fontInstall.displayName) { $schemaErrors += 'terminal-config.json: missing fontInstall.displayName' }
if ($terminal.fontInstall.version -notmatch '^\d+\.\d+\.\d+$') { $schemaErrors += 'terminal-config.json: fontInstall.version missing or not x.y.z' }
if ($terminal.fontInstall.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { $schemaErrors += 'terminal-config.json: fontInstall.sha256 missing or malformed' }
if ($schemaErrors) {
    $schemaErrors | ForEach-Object { Write-Host "        $_" -ForegroundColor Red }
    Write-Result 'Config schema' 'FAIL' "$($schemaErrors.Count) issue(s)"
}
else { Write-Result 'Config schema' 'PASS' }

# -------------------------------------------------------
# 13. setup.ps1 structure (functions, copies identical to the profile, verification before changes)
# -------------------------------------------------------
Write-Host '[13/27] setup.ps1 structure' -ForegroundColor Cyan
try {
    $problems = @()
    $setupContent = Get-Content $setupPath -Raw
    foreach ($fn in 'Test-InternetConnection', 'Install-NerdFonts', 'Install-OhMyPoshTheme', 'Install-WingetPackage', 'Select-PreferredEditor',
        'Remove-SafeTempDirectory', 'Initialize-InstallBundle', 'Save-WizardChoices', 'Resolve-WizardState', 'Invoke-SetupInstall') {
        if ($setupContent -notmatch "function\s+$fn\b") { $problems += "missing function $fn" }
    }
    # Helpers setup.ps1 needs before the bundle is verified are copies; they must match the profile exactly.
    foreach ($fn in 'Write-PspHost', 'Invoke-DownloadWithRetry', 'Get-CombinedSha256', 'Resolve-PspCommitSha', 'Get-PspReleaseChecksums') {
        $a = (Get-PspFunctionSource -Path $setupPath -Name $fn) -replace "`r`n", "`n"
        $b = (Get-PspFunctionSource -Path $profilePath -Name $fn) -replace "`r`n", "`n"
        if ($a -cne $b) { $problems += "$fn in setup.ps1 differs from the profile" }
    }
    # Everything else setup.ps1 loads from the verified profile must exist there.
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupPath -Variable '$script:SharedFunctionNames')))
    try { $null = Get-PspFunctionSource -Path $profilePath -Name $script:SharedFunctionNames }
    catch { $problems += $_.Exception.Message }
    # The main flow verifies the bundle before it installs anything.
    $verifyAt = $setupContent.IndexOf('$script:Bundle = Initialize-InstallBundle')
    $installAt = $setupContent.IndexOf('$installed = Invoke-SetupInstall')
    if ($verifyAt -lt 0 -or $installAt -lt 0 -or $verifyAt -gt $installAt) { $problems += 'bundle verification does not come before installation' }
    if ($problems) {
        $problems | ForEach-Object { Write-Host "        $_" -ForegroundColor Red }
        Write-Result 'setup.ps1 structure' 'FAIL' "$($problems.Count) problem(s)"
    }
    else { Write-Result 'setup.ps1 structure' 'PASS' }
}
catch { Write-Result 'setup.ps1 structure' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 14. Merge-JsonObject tests (the profile's own function)
# -------------------------------------------------------
Write-Host '[14/27] Merge-JsonObject tests' -ForegroundColor Cyan
try {
    . ([scriptblock]::Create((Get-PspFunctionSource -Path $profilePath -Name 'Merge-JsonObject')))

    # Flat merge
    $b = [PSCustomObject]@{ a = 1; b = 2 }
    Merge-JsonObject $b ([PSCustomObject]@{ b = 99; c = 3 })
    if ($b.a -ne 1 -or $b.b -ne 99 -or $b.c -ne 3) { throw 'Flat merge failed' }

    # Deep merge preserves nested keys
    $b = [PSCustomObject]@{ font = [PSCustomObject]@{ face = 'Consolas'; size = 11 }; opacity = 75 }
    Merge-JsonObject $b ([PSCustomObject]@{ font = [PSCustomObject]@{ size = 14 } })
    if ($b.font.face -ne 'Consolas' -or $b.font.size -ne 14 -or $b.opacity -ne 75) { throw 'Deep merge failed' }

    # Override replaces scalar with object
    $b = [PSCustomObject]@{ theme = 'simple' }
    Merge-JsonObject $b ([PSCustomObject]@{ theme = [PSCustomObject]@{ name = 'pure' } })
    if ($b.theme.name -ne 'pure') { throw 'Object replacement failed' }

    # A null base is a caller bug and must not be ignored.
    $threw = $false
    try { Merge-JsonObject $null ([PSCustomObject]@{ a = 1 }) } catch { $threw = $true }
    if (-not $threw) { throw 'Null base accepted' }

    Write-Result 'Merge-JsonObject tests' 'PASS'
}
catch { Write-Result 'Merge-JsonObject tests' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 15. Regression tests (tests/unit.ps1, both editions)
# -------------------------------------------------------
Write-Host '[15/27] Regression tests (tests/unit.ps1)' -ForegroundColor Cyan
$unitArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'unit.ps1'))
if ($AllowElevated) { $unitArgs += '-AllowElevated' }
foreach ($exe in @('pwsh') + @(if ($hasPs5) { 'powershell.exe' })) {
    try {
        $unitOutput = & $exe @unitArgs 2>&1 | ForEach-Object { "$_" }
        $unitExit = $LASTEXITCODE
        Show-ChildOutput @($unitOutput | Where-Object { $_ -match '^\s+(PASS|FAIL)|passed|^\s{8}' })
        if ($unitExit -ne 0) { throw "tests/unit.ps1 failed under $exe" }
        Write-Result "Regression tests ($exe)" 'PASS'
    }
    catch { Write-Result "Regression tests ($exe)" 'FAIL' $_.Exception.Message }
}

# =====================================================================
#  LOCAL-ONLY: profile-level validation
# =====================================================================
Write-Host ''
Write-Host '--- Local: profile validation ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 16. ProfileTools metadata (every entry has required fields)
# -------------------------------------------------------
Write-Host '[16/27] ProfileTools metadata' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$requiredKeys = @('Name', 'Id', 'Cmd', 'Cache', 'VerCmd')
$errors = @()
foreach ($tool in $script:ProfileTools) {
    foreach ($k in $requiredKeys) {
        if (-not $tool.ContainsKey($k)) { $errors += "$($tool.Name): missing $k" }
    }
    if ($tool.Id -and $tool.Id -notmatch '^[A-Za-z0-9._-]+$') { $errors += "$($tool.Name): invalid Id format" }
}
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
Write-Host "  OK    $($script:ProfileTools.Count) tools validated"
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw "Validation errors (see above)" }
    Write-Result 'ProfileTools metadata' 'PASS'
}
catch { Write-Result 'ProfileTools metadata' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 17. Key functions exist after profile load
# -------------------------------------------------------
Write-Host '[17/27] Key functions exist' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$expected = @(
    'Update-Profile','Update-PowerShell','Update-Tools','Uninstall-Profile',
    'Clear-ProfileCache','Clear-Cache','Show-Help','Resolve-PreferredEditor',
    'edit','Edit-Profile','Invoke-DownloadWithRetry',
    'Get-SystemBootTime','prompt',
    'touch','ff','grep','head','tail','sed','which','file','export',
    'pkill','pgrep','mkcd','trash','extract','sizeof',
    'pubip','localip','uptime','sysinfo','df','flushdns','ports',
    'checkport','portscan','tlscert','ipinfo','whois','nslook',
    'hash','checksum','genpass','b64','b64d','jwtd','uuid','epoch','vt',
    'urlencode','urldecode','vtscan',
    'killport','http','prettyjson','hb','timer','watch','bak',
    'hosts','weather','speedtest','wifipass','eventlog','path','env',
    'svc','rdp','cpy','pst','Invoke-Clipboard',
    'gs','ga','gcmsg','gpush','gpull','g','gcl','gcom','lazyg',
    'ls','la','ll','lt','cat','docs','dtop','admin','reload',
    'ep','su'
)
if (Get-Command ssh -ErrorAction SilentlyContinue) {
    $expected += @('Copy-SshKey','keygen','ssh-copy-key')
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $expected += @('dps','dpa','dimg','dlogs','dex','dstop','dprune')
}
$missing = @()
foreach ($fn in $expected) {
    if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { $missing += $fn }
}
if ($missing) {
    $missing | ForEach-Object { Write-Host "ASSERT: missing $_" }
    exit 1
}
Write-Host "  OK    $($expected.Count) functions verified"
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw "Missing functions (see above)" }
    Write-Result 'Key functions exist' 'PASS'
}
catch { Write-Result 'Key functions exist' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 18. Uninstall-Profile -All -WhatIf (all phases produce output, nothing changes)
# -------------------------------------------------------
Write-Host '[18/27] Uninstall-Profile -WhatIf' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$utf8 = [System.Text.UTF8Encoding]::new($false)
New-Item -ItemType Directory -Path $Sandbox.Cache -Force | Out-Null
foreach ($f in 'theme.json', 'omp-init.ps1') { [System.IO.File]::WriteAllText((Join-Path $Sandbox.Cache $f), '{}', $utf8) }
[System.IO.File]::WriteAllText((Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1'), '# profile', $utf8)
# WhatIf messages go straight to the host, so capture them through a transcript.
$log = Join-Path $Sandbox.Work 'whatif.log'
Start-Transcript -LiteralPath $log | Out-Null
Uninstall-Profile -All -WhatIf
Stop-Transcript | Out-Null
$whatIf = @(Get-Content -LiteralPath $log | Where-Object { $_ -match 'What if' })
$errors = @()
if ($whatIf.Count -eq 0) { $errors += 'no WhatIf output' }
foreach ($phase in 'Remove cache', 'Remove profile file') { if (-not ($whatIf | Where-Object { $_ -match $phase })) { $errors += "missing phase: $phase" } }
foreach ($p in (Join-Path $Sandbox.Cache 'theme.json'), (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1')) { if (-not (Test-Path -LiteralPath $p)) { $errors += "WhatIf removed $p" } }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
Write-Host "  OK    $($whatIf.Count) planned action(s), nothing changed"
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'WhatIf assertions failed' }
    Write-Result 'Uninstall-Profile -WhatIf' 'PASS'
}
catch { Write-Result 'Uninstall-Profile -WhatIf' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 19. Uninstall-Profile sandbox: core (real file deletion inside the sandbox)
# -------------------------------------------------------
Write-Host '[19/27] Uninstall sandbox: core' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$utf8 = [System.Text.UTF8Encoding]::new($false)
$errors = @()
New-Item -ItemType Directory -Path $Sandbox.WtDir, $Sandbox.Cache, $Sandbox.Ps5Dir -Force | Out-Null
# A settings file from an older profile version: no change record, two timestamped backups.
$wtPath = Join-Path $Sandbox.WtDir 'settings.json'
[System.IO.File]::WriteAllText($wtPath, '{"modified": true}', $utf8)
[System.IO.File]::WriteAllText("$wtPath.20240101-100000.bak", '{"original": "old"}', $utf8)
(Get-Item -LiteralPath "$wtPath.20240101-100000.bak").LastWriteTime = (Get-Date).AddDays(-30)
[System.IO.File]::WriteAllText("$wtPath.20240601-120000.bak", '{"original": "newest"}', $utf8)
foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json') {
    [System.IO.File]::WriteAllText((Join-Path $Sandbox.Cache $f), '{}', $utf8)
}
$pluginsDir = Join-Path $Sandbox.Cache 'plugins'
New-Item -ItemType Directory -Path $pluginsDir -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $pluginsDir 'myplugin.ps1'), '# user plugin', $utf8)
foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) {
    [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), '# profile', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user overrides', $utf8)
}

Uninstall-Profile -Confirm:$false 6>$null
# The oldest backup is the closest record of the pre-install file; the current file is kept next to it.
$wtContent = [System.IO.File]::ReadAllText($wtPath)
if ($wtContent -ne '{"original": "old"}') { $errors += "WT restore: expected the oldest backup, got: $wtContent" }
if (Get-ChildItem -LiteralPath $Sandbox.WtDir -Filter '*.bak') { $errors += 'WT backups left after a successful restore' }
if (-not (Get-ChildItem -LiteralPath $Sandbox.WtDir -Filter 'settings.json.pre-uninstall-*.json')) { $errors += 'current WT settings not kept' }
foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json') {
    if (Test-Path -LiteralPath (Join-Path $Sandbox.Cache $f)) { $errors += "Cache: $f still exists" }
}
if (-not (Test-Path -LiteralPath (Join-Path $Sandbox.Cache 'user-settings.json'))) { $errors += 'user-settings.json deleted without -RemoveUserData' }
if (-not (Test-Path -LiteralPath (Join-Path $pluginsDir 'myplugin.ps1'))) { $errors += 'plugins deleted without -RemoveUserData' }
foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) {
    if (Test-Path -LiteralPath (Join-Path $d 'Microsoft.PowerShell_profile.ps1')) { $errors += "profile still in $d" }
    if (-not (Test-Path -LiteralPath (Join-Path $d 'profile_user.ps1'))) { $errors += "profile_user.ps1 deleted in $d" }
}

foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) { [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), '# profile', $utf8) }
Uninstall-Profile -RemoveUserData -Confirm:$false 6>$null
if (Test-Path -LiteralPath (Join-Path $Sandbox.Cache 'user-settings.json')) { $errors += 'RemoveUserData: user-settings.json still exists' }
if (Test-Path -LiteralPath $pluginsDir) { $errors += 'RemoveUserData: plugins/ still exists' }
foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) {
    if (Test-Path -LiteralPath (Join-Path $d 'profile_user.ps1')) { $errors += "RemoveUserData: profile_user.ps1 still in $d" }
}
if ((Test-Path -LiteralPath $Sandbox.Cache) -and (Get-ChildItem -LiteralPath $Sandbox.Cache -Force)) { $errors += "cache not empty: $((Get-ChildItem -LiteralPath $Sandbox.Cache -Force).Name -join ', ')" }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
Write-Host '  OK    core uninstall and -RemoveUserData'
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'Sandbox assertions failed' }
    Write-Result 'Uninstall sandbox: core' 'PASS'
}
catch { Write-Result 'Uninstall sandbox: core' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 20. Uninstall-Profile sandbox: -All (font removal limited to the sandbox)
# -------------------------------------------------------
Write-Host '[20/27] Uninstall sandbox: -All' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$utf8 = [System.Text.UTF8Encoding]::new($false)
$errors = @()
New-Item -ItemType Directory -Path $Sandbox.WtDir, $Sandbox.Cache, $Sandbox.Ps5Dir -Force | Out-Null
$wtPath = Join-Path $Sandbox.WtDir 'settings.json'
[System.IO.File]::WriteAllText($wtPath, '{"modified": true}', $utf8)
[System.IO.File]::WriteAllText("$wtPath.20240601-120000.bak", '{"original": true}', $utf8)
foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json') {
    [System.IO.File]::WriteAllText((Join-Path $Sandbox.Cache $f), '{}', $utf8)
}
foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) {
    [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), '# profile', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user', $utf8)
}
$fonts = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'
New-Item -ItemType Directory -Path $fonts -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $fonts 'CaskaydiaCoveNerdFont-Regular.ttf'), 'x', $utf8)
$script:PSP.TestFontScopes = @(@{ Name = 'per-user'; Dir = $fonts; Reg = 'HKCU:\SOFTWARE\PowerShellPerfectTest\Fonts-NotPresent'; NeedsAdmin = $false })

# CI is set inside the sandbox, so -All skips the winget and module removals.
Uninstall-Profile -All -Confirm:$false 6>$null
if ([System.IO.File]::ReadAllText($wtPath) -ne '{"original": true}') { $errors += 'WT restore failed' }
if (Get-ChildItem -LiteralPath $Sandbox.WtDir -Filter '*.bak') { $errors += 'Backups remain' }
foreach ($f in 'omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json') {
    if (Test-Path -LiteralPath (Join-Path $Sandbox.Cache $f)) { $errors += "Cache: $f still exists" }
}
foreach ($d in $Sandbox.Ps7Dir, $Sandbox.Ps5Dir) {
    foreach ($f in 'Microsoft.PowerShell_profile.ps1', 'profile_user.ps1') {
        if (Test-Path -LiteralPath (Join-Path $d $f)) { $errors += "$f still in $d" }
    }
}
if (Test-Path -LiteralPath (Join-Path $fonts 'CaskaydiaCoveNerdFont-Regular.ttf')) { $errors += 'sandbox Nerd Font not removed' }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
Write-Host '  OK    -All removed everything inside the sandbox'
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'Sandbox assertions failed' }
    Write-Result 'Uninstall sandbox: -All' 'PASS'
}
catch { Write-Result 'Uninstall sandbox: -All' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 21. Lifecycle: install -> uninstall -> reinstall (setup.ps1 -LocalRepo, no network)
# -------------------------------------------------------
Write-Host '[21/27] Lifecycle: install -> uninstall -> reinstall' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
$utf8 = [System.Text.UTF8Encoding]::new($false)
$errors = @()
New-Item -ItemType Directory -Path $Sandbox.WtDir -Force | Out-Null
$wtPath = Join-Path $Sandbox.WtDir 'settings.json'
$wtOriginal = '{"profiles":{"defaults":{"font":{"face":"Consolas"}},"list":[]},"schemes":[],"actions":[]}'
[System.IO.File]::WriteAllText($wtPath, $wtOriginal, $utf8)
$installed = @(
    (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1'), (Join-Path $Sandbox.Ps5Dir 'Microsoft.PowerShell_profile.ps1'),
    (Join-Path $Sandbox.Cache 'theme.json'), (Join-Path $Sandbox.Cache 'terminal-config.json'), (Join-Path $Sandbox.Cache 'user-settings.json'),
    (Join-Path $Sandbox.Ps7Dir 'profile_user.ps1'), (Join-Path $Sandbox.Ps5Dir 'profile_user.ps1')
)

Write-Host '  --- Phase 1: Install ---'
& (Join-Path $RepoRoot 'setup.ps1') -LocalRepo $RepoRoot -CiMode -SkipWizard *> $null
$missing = @($installed | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing) { $errors += "Install missing: $($missing -join ', ')" } else { Write-Host '  OK    Install: all files created' }
. (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1')
. $PspPostLoadStubs
if (-not (Get-Command 'Uninstall-Profile' -ErrorAction SilentlyContinue)) { throw 'Uninstall-Profile not available after install' }

Write-Host '  --- Phase 2: Uninstall -All ---'
Uninstall-Profile -All -Confirm:$false 6>$null
$left = @($installed | Where-Object { Test-Path -LiteralPath $_ })
if ($left) { $errors += "After uninstall: $($left -join ', ')" }
$restored = Get-Content -LiteralPath $wtPath -Raw | ConvertFrom-Json
if ((ConvertTo-PspCanonicalJson $restored) -ne (ConvertTo-PspCanonicalJson ($wtOriginal | ConvertFrom-Json))) { $errors += 'WT settings not restored to the pre-install values' }
if (Get-WtProfileBackups -Path $wtPath) { $errors += 'WT backups remain after uninstall' }
Write-Host '  OK    Uninstall: removed and restored'

Write-Host '  --- Phase 3: Reinstall ---'
& (Join-Path $RepoRoot 'setup.ps1') -LocalRepo $RepoRoot -CiMode -SkipWizard *> $null
$missing = @($installed | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing) { $errors += "Reinstall missing: $($missing -join ', ')" } else { Write-Host '  OK    Reinstall: all files recreated' }
. (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1')
. $PspPostLoadStubs
if (-not (Get-Command 'Show-Help' -ErrorAction SilentlyContinue)) { $errors += 'Reinstall: profile failed to load' }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'Lifecycle test failed' }
    Write-Result 'Lifecycle: install -> uninstall -> reinstall' 'PASS'
}
catch { Write-Result 'Lifecycle: install -> uninstall -> reinstall' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 22. Execute every command (sandbox)
# -------------------------------------------------------
Write-Host '[22/27] Execute every command' -ForegroundColor Cyan
try {
    $online = $false
    try { $online = (Invoke-WebRequest -Uri 'https://github.com' -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop).StatusCode -eq 200 } catch { $online = $false }
    # The child reads the result through the environment (its param block takes only -RepoRoot).
    $env:PSP_TEST_ONLINE = [string]$online
    $r = Invoke-SandboxChild -Body @'
$ErrorActionPreference = 'Continue'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$Online = $env:PSP_TEST_ONLINE -eq 'True'

$ok = 0; $fail = 0; $skip = 0; $netFail = 0
# Return $true when an exception chain contains a transport failure (DNS, TCP, TLS handshake, timeout), judged by type, not message text.
function Test-TransportFailure {
    param([System.Exception]$Exception)
    # Compared by name: System.Net.Http is not always loaded in Windows PowerShell 5.1.
    $transportTypes = @('System.Net.Http.HttpRequestException', 'System.Net.WebException', 'System.Net.Sockets.SocketException', 'System.TimeoutException', 'System.Threading.Tasks.TaskCanceledException', 'System.Security.Authentication.AuthenticationException')
    for ($e = $Exception; $e; $e = $e.InnerException) {
        for ($t = $e.GetType(); $t; $t = $t.BaseType) { if ($transportTypes -contains $t.FullName) { return $true } }
    }
    return $false
}
# Run one command. -Net marks commands that need the internet: they are skipped offline, and only a transport exception counts as a network failure.
function T {
    param([string]$N, [scriptblock]$C, [string]$S, [switch]$Net)
    if ($S) { Write-Host "  SKIP  $N  ($S)"; $script:skip++; return }
    if ($Net -and -not $Online) { Write-Host "  SKIP  $N  (offline)"; $script:skip++; return }
    try {
        $null = & { $ErrorActionPreference = 'Stop'; & $C } 2>&1
        Write-Host "  OK    $N"; $script:ok++
    }
    catch {
        $msg = $_.Exception.Message
        if ($Net -and (Test-TransportFailure $_.Exception)) {
            Write-Host "  NET   $N  ($msg)"; $script:netFail++
        } else {
            Write-Host "  FAIL  $N  ($msg)"; $script:fail++
        }
    }
}

# --- Temp workspace ---
$ws = $Sandbox.Work
$tf  = Join-Path $ws 'sample.txt'
$tf2 = Join-Path $ws 'sample2.txt'
$jf  = Join-Path $ws 'sample.json'
$zf  = Join-Path $ws 'sample.zip'
$sd  = Join-Path $ws 'subdir'
New-Item -ItemType Directory $sd -Force | Out-Null
[System.IO.File]::WriteAllText($tf, "old line1`nold line2`nline3`nline4`nline5`nline6`nline7`nline8`nline9`nline10", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($tf2, "hello world", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($jf, '{"name":"test","nested":{"a":1}}', [System.Text.UTF8Encoding]::new($false))
Compress-Archive -Path $tf -DestinationPath $zf -Force

# Temp git repo for git commands
$gr = Join-Path $ws 'gitrepo'
New-Item -ItemType Directory $gr -Force | Out-Null
Push-Location $gr
git init --quiet 2>$null
git config user.email "test@test.com" 2>$null
git config user.name "Test" 2>$null
[System.IO.File]::WriteAllText((Join-Path $gr 'readme.txt'), 'init', [System.Text.UTF8Encoding]::new($false))
git add . 2>$null
git commit -m "init" --quiet 2>$null

# ===== PROFILE & UPDATES =====
T 'Show-Help'         { Show-Help }
T 'path'              { path }
T 'prompt'            { $p = prompt; if ([string]::IsNullOrWhiteSpace($p)) { throw 'prompt returned empty string' } }
T 'Get-SystemBootTime' { $b = Get-SystemBootTime; if (-not $b) { throw 'no boot time returned' } }
T 'reload'            $null 'reloads profile mid-test'
T 'Edit-Profile'      $null 'opens editor UI'
T 'ep'                $null 'opens editor UI'
T 'edit'              $null 'opens editor UI'
T 'Update-Profile'    {
    $cmd = Get-Command Update-Profile
    foreach ($p in @('Force', 'SkipHashCheck', 'ExpectedSha256', 'Ref', 'InstallMissingTools', 'WhatIf')) {
        if (-not $cmd.Parameters.ContainsKey($p)) { throw "Update-Profile missing parameter: $p" }
    }
    # -WhatIf must prevent Phase 1 downloads via the ShouldProcess gate.
    $filters = @('psp-profile-*.ps1', 'psp-theme-*.json', 'psp-terminal-*.json')
    $pre = foreach ($f in $filters) { Get-ChildItem -Path $env:TEMP -Filter $f -ErrorAction SilentlyContinue }
    Update-Profile -WhatIf -Confirm:$false | Out-Null
    $post = foreach ($f in $filters) { Get-ChildItem -Path $env:TEMP -Filter $f -ErrorAction SilentlyContinue }
    if (@($post).Count -gt @($pre).Count) { throw 'Update-Profile -WhatIf leaked temp files' }
}
T 'Update-PowerShell' {
    # -WhatIf: a live run spawns a winget MSI upgrade that replaces the running pwsh.
    Update-PowerShell -WhatIf *> $null
} -Net
T 'Update-Tools'      {
    # winget is replaced by a recorder and one tool is reported as installed, so the upgrade path runs without changing anything.
    $script:wingetCalls = @()
    function winget { $script:wingetCalls += ($args -join ' '); $global:LASTEXITCODE = -1978335189 }
    function Get-ProfileToolExecutablePath { param($Tool) if ($Tool.Name -eq 'bat') { 'C:\psp-test\bat.exe' } }
    function Get-ProfileToolVersionText { param($Tool, $ExecutablePath) '1.0.0' }
    Update-Tools -Confirm:$false *> $null
    if (@($script:wingetCalls | Where-Object { $_ -match '^upgrade --id sharkdp\.bat\b' }).Count -ne 1) { throw "unexpected winget calls: $($script:wingetCalls -join ' | ')" }
}
T 'Clear-ProfileCache' {
    [System.IO.File]::WriteAllText((Join-Path (Get-PspCacheDir) 'omp-init.ps1'), '# cache', [System.Text.UTF8Encoding]::new($false))
    Clear-ProfileCache -Confirm:$false *> $null
    if (Test-Path -LiteralPath (Join-Path (Get-PspCacheDir) 'omp-init.ps1')) { throw 'cache file not removed' }
}
T 'Clear-Cache'       {
    $junk = Join-Path $env:TEMP 'psp-clear-cache-probe.tmp'
    [System.IO.File]::WriteAllText($junk, 'x', [System.Text.UTF8Encoding]::new($false))
    Clear-Cache -Confirm:$false *> $null
    if (Test-Path -LiteralPath $junk) { throw 'sandbox temp file not removed' }
}
T 'Uninstall-Profile' $null 'tested in sandbox 19/20/21'
T 'Invoke-ProfileWizard' {
    # -WhatIf must prevent the network download via the ShouldProcess gate.
    $pre = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*' -ErrorAction SilentlyContinue)
    Invoke-ProfileWizard -WhatIf -Confirm:$false | Out-Null
    $post = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*' -ErrorAction SilentlyContinue)
    if ($post.Count -gt $pre.Count) { throw "Invoke-ProfileWizard -WhatIf leaked temp files" }
    $cmd = Get-Command Invoke-ProfileWizard
    foreach ($p in @('Resume', 'NoElevate', 'ExpectedSha256', 'BundleExpectedSha256', 'SkipHashCheck', 'Ref', 'WhatIf')) {
        if (-not $cmd.Parameters.ContainsKey($p)) { throw "Invoke-ProfileWizard missing parameter: $p" }
    }
}
T 'Reconfigure-Profile' {
    $alias = Get-Alias Reconfigure-Profile -ErrorAction SilentlyContinue
    if (-not $alias) { throw 'Reconfigure-Profile alias missing' }
    if ($alias.ResolvedCommandName -ne 'Invoke-ProfileWizard') { throw "Alias resolves to $($alias.ResolvedCommandName)" }
}

# ===== GIT =====
T 'gs'    { gs }
T 'ga'    { [System.IO.File]::WriteAllText((Join-Path $gr 'new.txt'), 'x', [System.Text.UTF8Encoding]::new($false)); ga }
T 'gcmsg' { gcmsg "test commit" }
T 'gcom'  { [System.IO.File]::WriteAllText((Join-Path $gr 'new2.txt'), 'y', [System.Text.UTF8Encoding]::new($false)); gcom "test gcom" }
T 'gpush' $null 'no remote configured'
T 'gpull' $null 'no remote configured'
T 'gcl'   $null 'network + clones repo'
T 'lazyg' $null 'no remote configured'
T 'g'     $null 'needs zoxide github dir'
Pop-Location

# ===== FILES & NAVIGATION =====
T 'ls'      { ls $ws }
T 'la'      { la $ws }
T 'll'      { ll $ws }
T 'lt'      { lt $ws }
T 'cat'     { cat $tf }
$batSkip = if (Get-Command bcat -ErrorAction SilentlyContinue) { $null } else { 'bat not installed (bcat is defined only with bat)' }
T 'bcat'    { bcat $tf } $batSkip
T 'ff'      { Push-Location $ws; ff "sample.txt"; Pop-Location }
T 'touch'   { touch (Join-Path $ws 'touched.txt') }
T 'nf'      { touch (Join-Path $ws 'newfile.txt') }
T 'mkcd'    { $d = Join-Path $ws 'mkcdtest'; mkcd $d; Pop-Location }
T 'head'    { head $tf 3 }
T 'tail'    { tail $tf 3 }
T 'file'    { file $tf }
T 'sizeof'  { sizeof $ws }
# -WhatIf: a real run moves the file into this user's Recycle Bin.
T 'trash'   { $t = Join-Path $ws 'trashme.txt'; [System.IO.File]::WriteAllText($t, 'bye', [System.Text.UTF8Encoding]::new($false)); trash $t -WhatIf; if (-not (Test-Path -LiteralPath $t)) { throw 'trash -WhatIf removed the file' } }
T 'extract' { $ed = Join-Path $ws 'extracted'; New-Item -ItemType Directory $ed -Force | Out-Null; Push-Location $ed; extract $zf; Pop-Location }
T 'docs'    { docs }
T 'dtop'    { dtop }
T 'cdh'     {
    $before = Get-Location
    try {
        $sub = Join-Path $ws 'cdh-t'
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        Set-Location $sub; Invoke-PromptStage
        Set-Location $ws; Invoke-PromptStage
        $out = cdh 6>&1 | Out-String
        if ($out -notmatch 'cdh-t') { throw 'cdh missing seeded entry' }
    }
    finally { Set-Location $before }
}
T 'cdb'     {
    $before = Get-Location
    try {
        $sub = Join-Path $ws 'cdb-t'
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        Set-Location $sub; Invoke-PromptStage
        Set-Location $ws; Invoke-PromptStage
        cdb 1
        if ((Get-Location).Path -ne $sub) { throw 'cdb 1 did not navigate back' }
    }
    finally { Set-Location $before }
}
T 'duration' {
    Get-Date | Out-Null
    $out = duration 6>&1 | Out-String
    if ([string]::IsNullOrWhiteSpace($out)) { throw 'duration produced no output' }
}
T 'Test-ProfileHealth' {
    $report = Test-ProfileHealth -PassThru
    if (-not $report) { throw 'Test-ProfileHealth -PassThru returned no rows' }
    # A bare call must stay silent on the pipeline or the rendered table prints twice.
    $bare = Test-ProfileHealth 6>$null
    if ($bare) { throw 'Test-ProfileHealth emitted objects without -PassThru' }
}
T 'psp-doctor' {
    $alias = Get-Alias psp-doctor -ErrorAction SilentlyContinue
    if (-not $alias) { throw 'psp-doctor alias missing' }
}
T 'bak'     { bak $tf }

# ===== UNIX-LIKE =====
T 'grep'    { grep "line" $ws }
T 'sed'     { $sf = Join-Path $ws 'sedtest.txt'; [System.IO.File]::WriteAllText($sf, 'foo bar foo', [System.Text.UTF8Encoding]::new($false)); sed $sf "foo" "baz" }
T 'which'   { which pwsh }
T 'pgrep'   { pgrep "pwsh" }
T 'pkill'   { pkill 'psp-no-such-process' 3>$null }
T 'export'  { export "PSP_TEST_VAR" "testvalue" }

# ===== SYSTEM & NETWORK =====
T 'admin'     $null 'opens elevated terminal'
T 'su'        $null 'opens elevated terminal'
T 'pubip'     { pubip } -Net
T 'localip'   { localip }
T 'uptime'    { uptime }
T 'sysinfo'   { sysinfo }
T 'df'        { df }
T 'flushdns'  $null 'requires admin'
T 'ports'     { ports }
T 'checkport' { checkport "dns.google" 443 } -Net
T 'portscan'  { portscan "dns.google" -Ports @(53, 443) } -Net
T 'tlscert'   { tlscert "google.com" } -Net
T 'ipinfo'    { ipinfo "8.8.8.8" } -Net
T 'whois'     { whois "example.com" } -Net
T 'nslook'    { nslook "google.com" } -Net
T 'env'       { env "PATH" }
T 'svc'       { svc "idle" -Count 1 }
T 'eventlog'  { eventlog 1 }
T 'weather'   { weather "London" } -Net
T 'speedtest' $null 'takes 30s+ download'
T 'wifipass'  $null 'requires admin/netsh'
T 'hosts'     $null 'opens elevated editor'
T 'winutil' {
    $marker = Join-Path $ws 'winutil-ran.txt'
    $markerLiteral = $marker -replace "'", "''"
    $scriptBody = "[System.IO.File]::WriteAllText('$markerLiteral', 'ran', [System.Text.UTF8Encoding]::new(`$false))"
    $script:winutilBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptBody)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $expectedHash = [BitConverter]::ToString($sha.ComputeHash($script:winutilBytes)).Replace('-', '') } finally { $sha.Dispose() }
    $savedAdmin = $script:PSP.IsAdmin
    try {
        # winutil hashes and runs the downloaded bytes in memory; serve a local script instead of the real one.
        function Invoke-WebRequest {
            param([string]$Uri, [int]$TimeoutSec, [switch]$UseBasicParsing, $ErrorAction)
            [PSCustomObject]@{ RawContentStream = [System.IO.MemoryStream]::new($script:winutilBytes) }
        }

        winutil 6>$null
        if (Test-Path $marker) { throw 'winutil executed without explicit opt-in' }

        winutil -Force -WhatIf 6>$null
        if (Test-Path $marker) { throw 'winutil executed under -WhatIf' }

        # Unelevated, WinUtil would relaunch itself from its latest release, so a pinned run needs an elevated shell.
        $script:PSP.IsAdmin = $false
        winutil -ExpectedSha256 $expectedHash -Confirm:$false -ErrorAction SilentlyContinue 6>$null
        if (Test-Path $marker) { throw 'winutil executed unelevated' }
        $script:PSP.IsAdmin = $true

        winutil -ExpectedSha256 ('0' * 64) -Confirm:$false -ErrorAction SilentlyContinue 6>$null
        if (Test-Path $marker) { throw 'winutil executed after a hash mismatch' }

        winutil -ExpectedSha256 $expectedHash -Confirm:$false 6>$null
        if (-not (Test-Path $marker)) { throw 'winutil did not execute after hash match + explicit confirmation bypass' }
    }
    finally {
        $script:PSP.IsAdmin = $savedAdmin
        Remove-Item Function:\Invoke-WebRequest -ErrorAction SilentlyContinue
        Remove-Item $marker -Force -ErrorAction SilentlyContinue
    }
}
T 'harden' {
    $script:startedHarden = $null
    try {
        function Get-ExternalCommandPath {
            param([string]$CommandName)
            if ($CommandName -eq 'hss.exe') { return 'C:\Tools\hss.exe' }
            return $null
        }
        function Start-Process {
            param([string]$FilePath)
            $script:startedHarden = $FilePath
        }

        harden -WhatIf
        if ($script:startedHarden) { throw 'harden launched tool under -WhatIf' }

        harden -Confirm:$false
        if ($script:startedHarden -ne 'C:\Tools\hss.exe') { throw "unexpected launch target: $script:startedHarden" }
    }
    finally {
        Remove-Item Function:\Get-ExternalCommandPath -ErrorAction SilentlyContinue
        Remove-Item Function:\Start-Process -ErrorAction SilentlyContinue
        Remove-Variable -Name startedHarden -Scope Script -ErrorAction SilentlyContinue
    }
}

# Commands that write to the clipboard run only on CI runners: locally they would overwrite the developer's clipboard.
$clipSkip = if ($env:GITHUB_ACTIONS) { $null } else { 'would overwrite your clipboard (runs on CI only)' }

# ===== SECURITY & CRYPTO =====
$hashOut = $null
T 'hash'      { $script:hashOut = hash $tf; $script:hashOut }
T 'hash MD5'  { hash $tf -Algorithm MD5 }
T 'checksum'  { if ($script:hashOut) { $h = ($script:hashOut | Out-String).Trim().Split(' ')[-1]; checksum $tf $h } else { throw 'no hash' } }
T 'genpass'   { genpass 16 } $clipSkip
T 'b64'       { b64 "hello world" }
T 'b64d'      { b64d "aGVsbG8gd29ybGQ=" }
T 'jwtd'      { jwtd "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" }
T 'Test-ProfileHistorySafeLine' {
    if (Test-ProfileHistorySafeLine 'pwnd hunter2') { throw 'pwnd input allowed into history' }
    if (Test-ProfileHistorySafeLine 'jwtd eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig') { throw 'jwt decode allowed into history' }
    # pwnd/jwtd must be scrubbed wherever the command can start, not just at line start
    foreach ($leaky in @('$p = pwnd hunter2', 'cls; pwnd hunter2', 'history | pwnd hunter2', '1..3 | % { pwnd s }')) {
        if (Test-ProfileHistorySafeLine $leaky) { throw "pwnd not scrubbed in chained form: $leaky" }
    }
    # value-shaped secrets caught even with no keyword present
    foreach ($secret in @('git remote add o https://ghp_abcdefghij1234567890ABCDEFGH@github.com', 'export K=AKIAIOSFODNN7EXAMPLE', 'mysql -uroot -pHunter2024', 'curl https://user:s3cr3t@example.com')) {
        if (Test-ProfileHistorySafeLine $secret) { throw "value-shaped secret allowed into history: $secret" }
    }
    # benign lines must NOT be blocked (no false positives on common flags/URLs)
    foreach ($safe in @('git status --short', 'mkdir -p src/lib', 'docker run -p 8080:80 nginx', 'git clone https://github.com/foo/bar')) {
        if (-not (Test-ProfileHistorySafeLine $safe)) { throw "safe command blocked from history: $safe" }
    }
}
T 'uuid'      { uuid } $clipSkip
T 'epoch'     { epoch }
T 'epoch 0'   { epoch 0 }
T 'urlencode' { urlencode "hello world" }
T 'urldecode' { urldecode "hello%20world" }
T 'vtscan'    $null 'needs API key; -Upload submits file content'
T 'vt'        {
    if (Get-Command vt.exe -ErrorAction SilentlyContinue) { vt --help }
    else { vt }
}

# ===== DEVELOPER =====
T 'killport'            { killport 1 -WhatIf 3>$null 6>$null }
T 'Stop-ListeningPort'  $null 'interactive fzf picker'
T 'killports'           $null 'alias to Stop-ListeningPort'
T 'Find-FileLocker'   {
    $lf = Join-Path $ws 'locktest.txt'
    [System.IO.File]::WriteAllText($lf, 'x', [System.Text.UTF8Encoding]::new($false))
    $s = [System.IO.File]::Open($lf, 'Open', 'ReadWrite', 'None')
    try {
        $r = @(Find-FileLocker $lf)
        if (-not ($r | Where-Object PID -eq $PID)) { throw 'did not report self PID' }
    } finally { $s.Close(); $s.Dispose() }
}
T 'Stop-StuckProcess' $null 'destructive - kills processes'
T 'Remove-LockedItem' { $li = Join-Path $ws 'locked-probe.txt'; [System.IO.File]::WriteAllText($li, 'x', [System.Text.UTF8Encoding]::new($false)); Remove-LockedItem $li -WhatIf 6>$null; if (-not (Test-Path -LiteralPath $li)) { throw 'Remove-LockedItem -WhatIf deleted the file' } }
T 'http'       { http "https://httpbin.org/get" } -Net
T 'prettyjson' { prettyjson $jf }
# -WhatIf stops at the ShouldProcess gate; a live call publishes $tf to a PUBLIC paste.
T 'hb'         { if (hb $tf -WhatIf) { throw 'hb published under -WhatIf' } }
T 'timer'      { timer { Start-Sleep -Milliseconds 10 } }
T 'watch'      $null 'infinite loop'

# ===== DOCKER =====
$hasDocker = [bool](Get-Command docker -ErrorAction SilentlyContinue)
$dockerRunning = $false
if ($hasDocker) { $null = docker info 2>&1; $dockerRunning = ($LASTEXITCODE -eq 0) }
$dockerSkip = if (-not $hasDocker) { 'docker not installed' } elseif (-not $dockerRunning) { 'docker daemon not running' } else { $null }
T 'dps'    { dps }    $dockerSkip
T 'dpa'    { dpa }    $dockerSkip
T 'dimg'   { dimg }   $dockerSkip
T 'dlogs'  $null 'needs running container'
T 'dex'    $null 'needs running container'
T 'dstop'  $null 'destructive'
T 'dprune' $null 'destructive'

# ===== SSH & REMOTE =====
$hasSsh = [bool](Get-Command ssh -ErrorAction SilentlyContinue)
T 'Copy-SshKey' $null 'needs remote host (remote script covered by tests/unit.ps1)'
T 'ssh-copy-key' $null 'needs remote host'
T 'keygen'      $null 'creates keys on disk'
T 'rdp'         $null 'opens RDP UI'

# ===== CLIPBOARD =====
T 'cpy'  { cpy "psp-test-clip" } $clipSkip
T 'pst'  { $r = pst; if ($r -ne "psp-test-clip") { throw "expected psp-test-clip, got: $r" } } $clipSkip
T 'icb'           $null 'PSReadLine handler only'
T 'Invoke-Clipboard' $null 'PSReadLine handler only'

# ===== SSH WRAPPER =====
T 'ssh'           $null 'wraps ssh.exe; real TCP connect'
T 'wsl'                   $null 'wraps wsl.exe; launches distro shell'
T 'Get-WslDistro'         { Get-WslDistro | Out-Null }
T 'Enter-WslHere'         $null 'opens interactive WSL shell'
T 'wsl-here'              $null 'alias to Enter-WslHere'
T 'ConvertTo-WslPath'     $null 'requires WSL distro'
T 'ConvertTo-WindowsPath' $null 'requires WSL distro'
T 'Stop-Wsl'              $null 'destructive: terminates distros'
T 'Get-WslIp'             $null 'requires running distro'
T 'Get-WslFile'           $null 'requires running distro'
T 'Show-WslTree'          $null 'requires running distro'
T 'wsl-tree'              $null 'alias to Show-WslTree'
T 'Open-WslExplorer'      $null 'opens Windows Explorer'
T 'wsl-explorer'          $null 'alias to Open-WslExplorer'

# ===== SYSADMIN =====
T 'journal'       { journal -Count 2 }
T 'lsblk'         { lsblk }
T 'htop'          $null 'launches TUI'
T 'mtr'           $null 'long traceroute+ping loop'
T 'fwallow' {
    $origIsAdmin = $script:PSP.IsAdmin
    $script:PSP.IsAdmin = $true
    $script:fwCalls = @()
    try {
        function New-NetFirewallRule {
            param(
                [string]$DisplayName,
                [string]$Direction,
                [string]$Action,
                [string]$Protocol,
                [int]$LocalPort
            )
            $script:fwCalls += [PSCustomObject]@{
                DisplayName = $DisplayName
                Direction   = $Direction
                Action      = $Action
                Protocol    = $Protocol
                LocalPort   = $LocalPort
            }
        }

        fwallow -Name 'PSP Test Allow' -Port 443 -WhatIf
        if ($script:fwCalls.Count -ne 0) { throw 'fwallow changed firewall under -WhatIf' }

        fwallow -Name 'PSP Test Allow' -Port 443 -Confirm:$false
        if ($script:fwCalls.Count -ne 1) { throw "fwallow expected 1 rule, got $($script:fwCalls.Count)" }
        if ($script:fwCalls[0].Action -ne 'Allow') { throw "fwallow recorded wrong action: $($script:fwCalls[0].Action)" }
    }
    finally {
        $script:PSP.IsAdmin = $origIsAdmin
        Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-Variable -Name fwCalls -Scope Script -ErrorAction SilentlyContinue
    }
}
T 'fwblock' {
    $origIsAdmin = $script:PSP.IsAdmin
    $script:PSP.IsAdmin = $true
    $script:fwCalls = @()
    try {
        function New-NetFirewallRule {
            param(
                [string]$DisplayName,
                [string]$Direction,
                [string]$Action,
                [string]$Protocol,
                [int]$LocalPort
            )
            $script:fwCalls += [PSCustomObject]@{
                DisplayName = $DisplayName
                Direction   = $Direction
                Action      = $Action
                Protocol    = $Protocol
                LocalPort   = $LocalPort
            }
        }

        fwblock -Name 'PSP Test Block' -Port 53 -WhatIf
        if ($script:fwCalls.Count -ne 0) { throw 'fwblock changed firewall under -WhatIf' }

        fwblock -Name 'PSP Test Block' -Port 53 -Confirm:$false
        if ($script:fwCalls.Count -ne 1) { throw "fwblock expected 1 rule, got $($script:fwCalls.Count)" }
        if ($script:fwCalls[0].Action -ne 'Block') { throw "fwblock recorded wrong action: $($script:fwCalls[0].Action)" }
    }
    finally {
        $script:PSP.IsAdmin = $origIsAdmin
        Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-Variable -Name fwCalls -Scope Script -ErrorAction SilentlyContinue
    }
}

# ===== CYBERSEC =====
T 'nscan'         $null 'requires nmap'
T 'sigcheck'      { sigcheck (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') }
T 'ads'           { $a = Join-Path $ws 'ads.txt'; [System.IO.File]::WriteAllText($a, 'x', [System.Text.UTF8Encoding]::new($false)); Set-Content -LiteralPath $a -Stream 'zone' -Value 'marker'; ads $a }
T 'defscan'       $null 'triggers Defender scan'
T 'pwnd'          { pwnd 'password' 3>$null } -Net
T 'certcheck'     { certcheck 'example.com' } -Net
T 'entropy'       { entropy $tf }

# ===== DEVELOPER+ =====
T 'serve'         $null 'long-running HTTP server'
T 'gitignore'     { Push-Location $ws; try { gitignore 'python' } finally { Pop-Location } } -Net
T 'gcof'          $null 'interactive fzf picker'
T 'envload'       { $ef = Join-Path $ws '.env'; [System.IO.File]::WriteAllText($ef, 'PSP_TST=ok', [System.Text.UTF8Encoding]::new($false)); envload $ef }
T 'tldr'          { tldr 'ls' } -Net
T 'repeat'        { $script:rc=0; repeat 3 { $script:rc++ }; if ($script:rc -ne 3) { throw "expected 3, got $script:rc" } }
T 'mkvenv'        $null 'creates venv dir'

# ===== DETECTION / AST =====
T 'outline'       { outline $ProfileSource | Out-Null }
T 'psym'          { psym 'Update-Profile' (Split-Path $ProfileSource) | Out-Null }
T 'lint'          $null 'requires PSScriptAnalyzer'
T 'Find-DeadCode' { $f = Join-Path $ws 'dc.ps1'; [System.IO.File]::WriteAllText($f, "function a { `$b = 1; a }", [System.Text.UTF8Encoding]::new($false)); Find-DeadCode $f | Out-Null }
T 'Test-Profile'  { Test-Profile | Out-Null }
T 'Get-PwshVersions' { Get-PwshVersions | Out-Null }
T 'modinfo'       { modinfo 'PSReadLine' | Out-Null }
T 'psgrep'        { psgrep 'Update-Profile' (Split-Path $ProfileSource) -Kind Function | Out-Null }

# ===== EXTENSIBILITY =====
T 'Register-ProfileHook'    { Register-ProfileHook -EventName PrePrompt -Action { } }
T 'Register-HelpSection'    { Register-HelpSection -Title 'T' -Lines @('x') }
T 'Register-ProfileCommand' { Register-ProfileCommand -Name 't' -Category 'T' -Synopsis 's' }
T 'Get-ProfileCommand'      { if (@(Get-ProfileCommand).Count -lt 50) { throw 'registry too small' } }
T 'Start-ProfileTour'       $null 'interactive Read-Host loop'
T 'Add-TrustedDirectory'    { $td = Join-Path $ws 'trusted'; New-Item -ItemType Directory -Path $td -Force | Out-Null; Add-TrustedDirectory -Path $td -Confirm:$false 6>$null; if ($script:PSP.TrustedDirs -notcontains $td) { throw 'not trusted' } }
T 'Remove-TrustedDirectory' { Remove-TrustedDirectory -Path (Join-Path $ws 'trusted') -Confirm:$false 6>$null; if ($script:PSP.TrustedDirs -contains (Join-Path $ws 'trusted')) { throw 'still trusted' } }

# ===== THEME =====
T 'Set-TerminalBackground'  { $img = Join-Path $ws 'bg.png'; [System.IO.File]::WriteAllBytes($img, [byte[]](0x89, 0x50, 0x4E, 0x47)); Set-TerminalBackground -Path $img -Confirm:$false 6>$null; Set-TerminalBackground -Clear -Confirm:$false 6>$null }

# --- Result ---
Write-Host ""
$summary = "  Functions: $ok ok, $fail fail, $netFail net-fail, $skip skip"
Write-Host $summary
if ($fail -gt 0) { exit 1 }
'@
    Show-ChildOutput $r.Output
    $fnFails = @($r.Output | Where-Object { $_ -match '^\s+FAIL' })
    if ($r.ExitCode -ne 0 -or $fnFails.Count -gt 0) { throw "$($fnFails.Count) function(s) failed" }
    Write-Result 'Execute every command' 'PASS'
}
catch { Write-Result 'Execute every command' 'FAIL' $_.Exception.Message }

# =====================================================================
#  SETUP & INSTALL VERIFICATION
# =====================================================================
Write-Host ''
Write-Host '--- Setup & install verification ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 23. setup.ps1 functions (hermetic: nothing is installed)
# -------------------------------------------------------
Write-Host '[23/27] setup.ps1 functions sandbox' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$WarningPreference = 'SilentlyContinue'
. $ProfileSource
. $PspPostLoadStubs
$setupFile = Join-Path $RepoRoot 'setup.ps1'
foreach ($definition in (Get-PspFunctionSource -Path $setupFile -Name @('Install-WingetPackage', 'Install-NerdFonts', 'Invoke-SetupNative', 'Test-InternetConnection', 'Get-OmpThemeUrl', 'Remove-SafeTempDirectory'))) {
    . ([scriptblock]::Create($definition))
}
foreach ($variable in '$EditorCandidates', '$script:CuratedFonts', '$script:CuratedSchemes', '$script:NerdFontVersion', '$script:OmpThemesRef') {
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $setupFile -Variable $variable)))
}
$script:IsElevated = $false
$ok = 0; $fail = 0
function T($N, $C) {
    try { $null = & $C 2>&1; Write-Host "  OK    $N"; $script:ok++ }
    catch { Write-Host "  FAIL  $N  ($_)"; $script:fail++ }
}
T 'Install-WingetPackage -WhatIf installs nothing' {
    # The sandbox puts a recording winget.cmd first on PATH, so even a broken -WhatIf cannot reach the real winget.
    $r = Install-WingetPackage -Name 'PowerShell' -Id 'Microsoft.PowerShell' -WhatIf 6>$null
    if ($r -ne $true) { throw "expected true, got $r" }
    $calls = @(Get-PspSandboxWingetCalls -Sandbox $Sandbox)
    if ($calls.Count -gt 0) { throw "winget ran under -WhatIf: $($calls -join ' | ')" }
}
T 'Install-WingetPackage reaches only the sandbox winget' {
    $r = Install-WingetPackage -Name 'PowerShell' -Id 'Microsoft.PowerShell' 6>$null
    $calls = @(Get-PspSandboxWingetCalls -Sandbox $Sandbox)
    if ($r -ne $false -or $calls.Count -ne 1 -or $calls[0] -notmatch '^install -e --id Microsoft\.PowerShell\b') { throw "unexpected: result $r, calls $($calls -join ' | ')" }
}
T 'Install-NerdFonts -WhatIf downloads nothing' {
    $r = Install-NerdFonts -WhatIf 6>$null
    if ($r -ne $true) { throw "expected true, got $r" }
    if (Get-ChildItem -LiteralPath $env:TEMP -Filter 'psp-font-*' -ErrorAction SilentlyContinue) { throw 'font download started under -WhatIf' }
}
T 'Install-NerdFonts rejects a bad asset name' {
    if (Install-NerdFonts -FontName '../x' 6>$null) { throw 'bad asset accepted' }
}
T 'Curated fonts are pinned' {
    foreach ($f in $script:CuratedFonts) { if ($f.Sha256 -notmatch '^[A-F0-9]{64}$') { throw "$($f.Name) has no pinned hash" } }
    if ($script:NerdFontVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Nerd Fonts version not pinned' }
}
T 'Theme URLs use the pinned Oh My Posh release' {
    if ((Get-OmpThemeUrl -Name 'pure') -notmatch "/oh-my-posh/$([regex]::Escape($script:OmpThemesRef))/themes/pure\.omp\.json$") { throw 'theme URL not pinned' }
}
T 'EditorCandidates' {
    if (-not $EditorCandidates -or $EditorCandidates.Count -lt 5) { throw "only $($EditorCandidates.Count) candidates" }
    foreach ($ed in $EditorCandidates) {
        if (-not $ed.Cmd -or -not $ed.Display) { throw "invalid: $($ed | ConvertTo-Json -Compress)" }
    }
}
Write-Host ''
Write-Host "  setup.ps1 functions: $ok ok, $fail fail"
if ($fail -gt 0) { exit 1 }
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw 'setup.ps1 function checks failed' }
    Write-Result 'setup.ps1 functions sandbox' 'PASS'
}
catch { Write-Result 'setup.ps1 functions sandbox' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 24. setprofile.ps1 sandbox (copy to both PS dirs, -WhatIf writes nothing)
# -------------------------------------------------------
Write-Host '[24/27] setprofile.ps1 sandbox' -ForegroundColor Cyan
try {
    $r = Invoke-SandboxChild -Body @'
$errors = @()
$srcDir = Join-Path $Sandbox.Work 'src'
New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
Copy-Item (Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1') $srcDir
Copy-Item (Join-Path $RepoRoot 'setprofile.ps1') $srcDir
Remove-Item -LiteralPath $Sandbox.Ps7Dir -Recurse -Force
& (Join-Path $srcDir 'setprofile.ps1') -WhatIf *> $null
if (Test-Path -LiteralPath (Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1')) { $errors += '-WhatIf wrote a profile' }
# The user's own PowerShell 7 profile from before the first install; Windows PowerShell has none.
New-Item -ItemType Directory -Path $Sandbox.Ps7Dir -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $Sandbox.Ps7Dir 'Microsoft.PowerShell_profile.ps1'), '# my own profile', [System.Text.UTF8Encoding]::new($false))
& (Join-Path $srcDir 'setprofile.ps1') *> $null
if ($LASTEXITCODE -ne 0) { $errors += "setprofile.ps1 exit code $LASTEXITCODE" }
foreach ($dir in @($Sandbox.Ps7Dir, $Sandbox.Ps5Dir)) {
    $pf = Join-Path $dir 'Microsoft.PowerShell_profile.ps1'
    if (-not (Test-Path $pf)) { $errors += "Not created: $pf" }
    elseif ((Get-Content (Join-Path $srcDir 'Microsoft.PowerShell_profile.ps1') -Raw) -ne (Get-Content $pf -Raw)) { $errors += "Content mismatch: $pf" }
}
# A second run backs up the installed profile, which must never become the "original".
& (Join-Path $srcDir 'setprofile.ps1') *> $null
$original = Join-Path $Sandbox.Ps7Dir 'profile.original.ps1'
if (-not (Test-Path $original) -or (Get-Content $original -Raw).Trim() -ne '# my own profile') { $errors += 'profile.original.ps1 is not the pre-install profile' }
if (Test-Path (Join-Path $Sandbox.Ps5Dir 'profile.original.ps1')) { $errors += 'a copy of this profile was saved as profile.original.ps1' }
if ($errors) { $errors | ForEach-Object { Write-Host "ASSERT: $_" }; exit 1 }
Write-Host '  OK    setprofile.ps1 copies, backs up and honors -WhatIf'
'@
    Show-ChildOutput $r.Output
    if ($r.ExitCode -ne 0) { throw "setprofile sandbox failed" }
    Write-Result 'setprofile.ps1 sandbox' 'PASS'
}
catch { Write-Result 'setprofile.ps1 sandbox' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 25. Install verification (read-only look at this machine's real install; the profile is not executed)
# -------------------------------------------------------
Write-Host '[25/27] Install verification' -ForegroundColor Cyan
try {
    $errors = @()
    $warnings = @()
    # Read $script:ProfileTools and the JSON helpers from the source instead of loading the profile.
    . ([scriptblock]::Create((Get-PspAssignmentSource -Path $profilePath -Variable '$script:ProfileTools')))
    foreach ($definition in (Get-PspFunctionSource -Path $profilePath -Name @('ConvertFrom-JsonC', 'Get-Utf8FileText', 'Read-JsonFile'))) { . ([scriptblock]::Create($definition)) }
    $toolsFound = 0; $toolsMissing = 0
    foreach ($tool in $script:ProfileTools) {
        if (Get-Command $tool.Cmd -CommandType Application -ErrorAction SilentlyContinue) { Write-Host "        OK    $($tool.Name)" -ForegroundColor Green; $toolsFound++ }
        else { $warnings += "$($tool.Name): not installed"; $toolsMissing++ }
    }
    $cachePath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
    if (-not (Test-Path -LiteralPath $cachePath)) { throw [System.Management.Automation.ItemNotFoundException]::new("no install on this machine ($cachePath is missing); run setup.ps1 to check one") }
    else {
        foreach ($cf in @('theme.json', 'terminal-config.json')) {
            $cfPath = Join-Path $cachePath $cf
            if (-not (Test-Path -LiteralPath $cfPath)) { $errors += "$cf not cached" }
            else { try { $null = Read-JsonFile $cfPath } catch { $errors += "$cf corrupt: $_" } }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $cachePath 'user-settings.json'))) { $errors += 'user-settings.json not found' }
        if (-not (Get-ChildItem -LiteralPath $cachePath -Filter '*.omp.json' -ErrorAction SilentlyContinue)) { $warnings += 'No OMP theme in cache' }
    }
    if (-not (Test-Path -LiteralPath (Join-Path (Split-Path $PROFILE) 'profile_user.ps1'))) { $errors += 'profile_user.ps1 not found' }
    if (Get-Module -ListAvailable -Name PSFzf) { Write-Host '        OK    PSFzf module available' -ForegroundColor Green } else { $warnings += 'PSFzf not installed' }
    $wtPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
    if (Test-Path -LiteralPath $wtPath) {
        try {
            $wt = Read-JsonFile $wtPath
            if ($wt.profiles.defaults.font.face) { Write-Host "        OK    WT font: $($wt.profiles.defaults.font.face)" -ForegroundColor Green } else { $warnings += 'WT missing font.face in defaults' }
        }
        catch { $warnings += "WT parse failed: $_" }
    }
    foreach ($w in $warnings) { Write-Host "        WARN  $w" -ForegroundColor Yellow }
    if ($errors) {
        foreach ($e in $errors) { Write-Host "        FAIL  $e" -ForegroundColor Red }
        throw 'Required verification checks failed (see FAIL above)'
    }
    Write-Result 'Install verification' 'PASS'
}
catch [System.Management.Automation.ItemNotFoundException] { Write-Result 'Install verification' 'SKIP' $_.Exception.Message }
catch { Write-Result 'Install verification' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 26. Static checks for the hermetic-test rules
# -------------------------------------------------------
Write-Host '[26/27] Test hygiene' -ForegroundColor Cyan
try {
    $problems = @()
    foreach ($file in Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.ps1 -File) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        # Uninstall-Profile -All includes -RemoveFonts; only sandboxes that set TestFontScopes may call it.
        if ($text -match 'Uninstall-Profile -All -Confirm' -and $text -notmatch 'TestFontScopes') { $problems += "$($file.Name) runs Uninstall-Profile -All without a sandboxed font scope" }
    }
    if ($problems) { $problems | ForEach-Object { Write-Host "        $_" -ForegroundColor Red }; Write-Result 'Test hygiene' 'FAIL' "$($problems.Count) problem(s)" }
    else { Write-Result 'Test hygiene' 'PASS' }
}
catch { Write-Result 'Test hygiene' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 27. Command coverage audit (test.ps1 vs profile exports)
# -------------------------------------------------------
Write-Host '[27/27] Command coverage audit' -ForegroundColor Cyan
try {
    # Exported function names from profile source (AST)
    $tokens = $null; $parseErrors = $null
    $profileAst = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "Profile parse errors: $($parseErrors.Count)" }
    $allFns = $profileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object Name | Sort-Object -Unique

    # Alias names from profile source
    $profileRaw = Get-Content $profilePath -Raw
    $aliasNames = [regex]::Matches($profileRaw, 'Set-Alias\s+-Name\s+([A-Za-z0-9\-]+)\s+-Value\s+([A-Za-z0-9\-]+)') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    # Internal helpers are not direct user commands: everything named *-Psp* or *-Wt* plus the list below.
    $internalOnly = @(
        'Get-ExternalCommandPath'
        'Update-SessionPathFromRegistry'
        'Get-OhMyPoshInstallInfo'
        'Get-OhMyPoshMsiProductCode'
        'Get-OhMyPoshExecutablePath'
        'Get-ProfileToolExecutablePath'
        'Get-ProfileToolVersionText'
        'Test-WingetPackageInstalled'
        'Invoke-OhMyPoshCommand'
        'Get-OhMyPoshPromptContext'
        'Get-OhMyPoshPromptText'
        'Invoke-DownloadWithRetry'
        'Merge-JsonObject'
        'Invoke-WithTimeout'
        'Restart-TerminalToApply'
        'Clear-OhMyPoshCaches'
        'Write-JournalLine'
        'Invoke-PromptStage'
        'Invoke-ProfileHook'
        'Test-ProfileHistorySafeLine'
        'Save-TrustedDirectories'
        'Read-UserSettingsForWrite'
        'Get-WindowsTerminalSettingsPath'
        'Get-WindowsTerminalSettingsPaths'
        'Push-TabTitle'
        'Pop-TabTitle'
        'Resolve-WslUncPath'
        'Initialize-RestartManagerType'
        'ConvertTo-NativeArgumentLine'
        'Get-Utf8FileText'
        'Write-Utf8FileAtomic'
        'Set-PspFeatureOverride'
        'Get-LatestMainCommitSha'
        'ConvertFrom-JsonC'
        'Read-JsonFile'
        'Get-CombinedSha256'
        'Resolve-PspCommitSha'
        'Update-WindowsTerminalSettingsFile'
        'Undo-WindowsTerminalSettingsFile'
        'Copy-PspObject'
        'Merge-PspUserSettings'
        'ConvertTo-PspSortedNode'
    )
    $commandFns = $allFns | Where-Object { $internalOnly -notcontains $_ -and $_ -notmatch '-(Psp|Wt)[A-Z]' }

    # Commands explicitly checked in step 17 existence list
    $existNames = @()
    $inExistBlock = $false
    foreach ($line in (Get-Content $MyInvocation.MyCommand.Path)) {
        if ($line -match '^\$expected = @\($') { $inExistBlock = $true; continue }
        if ($inExistBlock -and $line -match "^\s*\)") { break }
        if ($inExistBlock) {
            foreach ($m in [regex]::Matches($line, "'([^']+)'")) {
                $existNames += $m.Groups[1].Value
            }
        }
    }

    # Compare commands executed in step 22 with commands explicitly skipped.
    $execActual = @()
    $execSkipped = @()
    foreach ($line in (Get-Content $MyInvocation.MyCommand.Path)) {
        $m = [regex]::Match($line, "^\s*T\s+'([^']+)'\s+(.+)")
        if ($m.Success) {
            $name = $m.Groups[1].Value
            $rest = $m.Groups[2].Value.Trim()
            if ($rest -match '^\$null\b' -or $rest -match "^'[^']+'\s*$") {
                $execSkipped += $name
            } else {
                $execActual += $name
            }
        }
    }

    $coveredNames = @($existNames + $execActual + $execSkipped) | Sort-Object -Unique
    $testedNames  = @($existNames + $execActual) | Sort-Object -Unique
    $missingFns = $commandFns | Where-Object { $coveredNames -notcontains $_ }
    $missingAliases = $aliasNames | Where-Object { $coveredNames -notcontains $_ }

    # Skip-only: commands that appear ONLY as skipped (not in existence check or actual execution)
    $skipOnly = $execSkipped | Where-Object { $testedNames -notcontains $_ }

    # Allowed skip-only: commands that cannot be tested safely.
    $allowedSkipOnly = @(
        'reload'             # reloads profile mid-test
        'Edit-Profile'       # opens editor UI
        'ep'                 # opens editor UI (alias)
        'edit'               # opens editor UI
        'Uninstall-Profile'  # tested in dedicated sandbox (steps 19/20/21) and tests/unit.ps1
        'gpush'              # no remote configured
        'gpull'              # no remote configured
        'gcl'                # network + clones repo
        'lazyg'              # no remote configured
        'g'                  # needs zoxide github dir
        'Stop-StuckProcess'  # destructive - kills processes
        'Stop-ListeningPort' # interactive fzf picker
        'killports'          # alias to Stop-ListeningPort
        'admin'              # opens elevated terminal
        'su'                 # opens elevated terminal (alias)
        'flushdns'           # requires admin
        'speedtest'          # takes 30s+ download
        'wifipass'           # requires admin/netsh
        'hosts'              # opens elevated editor
        'vtscan'             # needs API key
        'watch'              # infinite loop
        'dlogs'              # needs running container
        'dex'                # needs running container
        'dstop'              # destructive
        'dprune'             # destructive
        'Copy-SshKey'        # needs remote host (remote script tested in tests/unit.ps1)
        'ssh-copy-key'       # needs remote host (alias)
        'keygen'             # writes keys to ~/.ssh
        'rdp'                # opens RDP UI
        'icb'                # PSReadLine handler only
        'Invoke-Clipboard'   # PSReadLine handler only
        'ssh'                # wraps ssh.exe; would open real TCP connect
        'wsl'                # wraps wsl.exe; would launch distro shell
        'Enter-WslHere'      # opens interactive WSL shell
        'wsl-here'           # alias to Enter-WslHere
        'ConvertTo-WslPath'  # requires WSL distro
        'ConvertTo-WindowsPath' # requires WSL distro
        'Stop-Wsl'           # destructive: terminates distros
        'Get-WslIp'          # requires running distro
        'Get-WslFile'        # requires running distro
        'Show-WslTree'       # requires running distro
        'wsl-tree'           # alias to Show-WslTree
        'Open-WslExplorer'   # opens Windows Explorer
        'wsl-explorer'       # alias to Open-WslExplorer
        'htop'               # launches TUI process viewer
        'mtr'                # long traceroute+ping loop
        'nscan'              # requires nmap binary
        'defscan'            # triggers Defender scan
        'serve'              # long-running HTTP server
        'gcof'               # interactive fzf branch picker
        'mkvenv'             # creates venv dir + activates
        'lint'               # requires PSScriptAnalyzer (covered by lint job)
        'Start-ProfileTour'  # interactive Read-Host walkthrough
    )
    $unexpectedSkips = @($skipOnly | Where-Object { $allowedSkipOnly -notcontains $_ })

    if ($missingFns -or $missingAliases) {
        if ($missingFns) {
            Write-Host "        Missing functions in tests: $($missingFns -join ', ')" -ForegroundColor Red
        }
        if ($missingAliases) {
            Write-Host "        Missing aliases in tests: $($missingAliases -join ', ')" -ForegroundColor Red
        }
        throw "Coverage gaps found"
    }

    if ($unexpectedSkips.Count -gt 0) {
        Write-Host "        Unexpected skip-only commands: $($unexpectedSkips -join ', ')" -ForegroundColor Red
        Write-Host "        These must be executed or added to allowedSkipOnly with justification" -ForegroundColor Red
        throw "$($unexpectedSkips.Count) command(s) skipped without justification"
    }

    # Registration is not execution: require a minimum share of the covered commands to actually run.
    $minimumExecPct = 70
    $execPct = if ($coveredNames.Count -gt 0) { [math]::Round(($testedNames.Count / $coveredNames.Count) * 100) } else { 0 }
    $detail = "functions=$($commandFns.Count), aliases=$($aliasNames.Count), executed=$($execActual.Count), skip-only=$($skipOnly.Count)/$($allowedSkipOnly.Count) allowed, exec%=$execPct (minimum $minimumExecPct)"
    if ($skipOnly.Count -gt 0) {
        Write-Host "        Allowed skip-only ($($skipOnly.Count)): $($skipOnly -join ', ')" -ForegroundColor DarkGray
    }
    if ($execPct -lt $minimumExecPct) { throw "Only $execPct% of covered commands are executed (minimum $minimumExecPct%). $detail" }
    Write-Result 'Command coverage audit' 'PASS' $detail
}
catch { Write-Result 'Command coverage audit' 'FAIL' $_.Exception.Message }

# =====================================================================
#  Summary
# =====================================================================
$stopwatch.Stop()
Write-Host ''
Write-Host '========================================================' -ForegroundColor Cyan
$total = $passed + $failed + $skipped
$color = if ($failed -gt 0) { 'Red' } elseif ($skipped -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  $passed passed, $failed failed, $skipped skipped ($total total) in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor $color
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

if ($failed -gt 0) { exit 1 }
