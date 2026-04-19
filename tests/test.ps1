# test.ps1 - Full local test suite (mirrors CI lint + install-flow, plus local-only checks)
# Usage: pwsh -NoProfile -File tests/test.ps1
#        pwsh -NoProfile -File tests/test.ps1 -SkipPS5
# Covers every check from .github/workflows/ci.yml plus profile-level validation.
param(
    [switch]$SkipPS5  # Skip PS5 parse check if powershell.exe is unavailable
)

$ErrorActionPreference = 'Stop'
# This script lives in tests/. repoRoot points at the parent directory (where the profile lives).
$repoRoot = Split-Path -Parent $PSScriptRoot
$passed = 0
$failed = 0
$skipped = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Always-on sandbox cleanup. Child pwsh processes usually clean their own $sb in a finally
# block, but a Ctrl+C at this orchestrator kills the child before that runs, leaving psp-*
# dirs behind. The trap fires on terminating errors (including StopUpstreamCommandsException
# from Ctrl+C) and Register-EngineEvent fires on normal script exit.
$script:TestArtifactPatterns = @(
    'psp-install-*', 'psp-sandbox-*', 'psp-sandbox-all-*', 'psp-lifecycle-*',
    'psp-setprofile-*', 'psp-exec-*', 'psp-dltest-*', 'psp-omp-*', 'fresh-install-*'
)
$script:SweepTestArtifacts = {
    foreach ($pat in $script:TestArtifactPatterns) {
        Get-ChildItem -LiteralPath $env:TEMP -Filter $pat -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $script:SweepTestArtifacts | Out-Null
trap {
    Write-Host ''
    Write-Host ('Aborted: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host 'Sweeping sandbox artifacts in $env:TEMP ...' -ForegroundColor Yellow
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

# =====================================================================
#  INSTALL: fresh install sandbox
# =====================================================================
Write-Host '--- Install: fresh setup sandbox ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 1. Fresh install sandbox (simulates setup.ps1 on clean system)
# -------------------------------------------------------
Write-Host '[1/26] Fresh install sandbox' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "fresh-install-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($RepoRoot)
$ErrorActionPreference = 'Stop'

# Parse setup.ps1 AST to extract functions without running install flow
$setupFile = Join-Path $RepoRoot 'setup.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($setupFile, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "setup.ps1 has $($parseErrors.Count) parse error(s)" }

$fnDefs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($fn in $fnDefs) { Invoke-Expression $fn.Extent.Text }
Write-Host "  Extracted $($fnDefs.Count) functions from setup.ps1"

# Extract $EditorCandidates
$varDefs = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $args[0].Left.Extent.Text -eq '$EditorCandidates'
}, $true)
if ($varDefs.Count -gt 0) { Invoke-Expression $varDefs[0].Extent.Text }

# ===== Create sandbox =====
$sb = Join-Path $env:TEMP "psp-install-$([System.IO.Path]::GetRandomFileName())"
$cacheDir = Join-Path $sb 'Local\PowerShellProfile'
$ps7Dir   = Join-Path $sb 'Documents\PowerShell'
$ps5Dir   = Join-Path $sb 'Documents\WindowsPowerShell'
$wtLocal  = Join-Path $sb 'Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
New-Item -ItemType Directory -Path $cacheDir, $ps7Dir, $ps5Dir, $wtLocal -Force | Out-Null
$configCachePath = $cacheDir

# Minimal WT settings.json
[System.IO.File]::WriteAllText(
    (Join-Path $wtLocal 'settings.json'),
    '{"profiles":{"defaults":{"font":{"face":"Consolas"}},"list":[]},"schemes":[],"actions":[]}',
    [System.Text.UTF8Encoding]::new($false)
)

$origLocal   = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = Join-Path $sb 'Local'
$global:PROFILE   = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$errors = @()
try {
    # --- Phase 1: Profile copy (simulates setprofile.ps1) ---
    $profileSrc = Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1'
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        Copy-Item $profileSrc (Join-Path $d 'Microsoft.PowerShell_profile.ps1')
    }
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        $pf = Join-Path $d 'Microsoft.PowerShell_profile.ps1'
        if (-not (Test-Path $pf)) { $errors += "Profile not copied to $d" }
    }
    Write-Host '  OK    Phase 1: profile copy'

    # --- Phase 2: Config download (theme.json, terminal-config.json) ---
    $themeUrl = 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/theme.json'
    $tcUrl    = 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/terminal-config.json'
    Invoke-DownloadWithRetry -Uri $themeUrl -OutFile (Join-Path $cacheDir 'theme.json')
    Invoke-DownloadWithRetry -Uri $tcUrl    -OutFile (Join-Path $cacheDir 'terminal-config.json')
    foreach ($cf in @('theme.json', 'terminal-config.json')) {
        $cfPath = Join-Path $cacheDir $cf
        if (-not (Test-Path $cfPath) -or (Get-Item $cfPath).Length -eq 0) { $errors += "$cf download failed" }
        else { $null = Get-Content $cfPath -Raw | ConvertFrom-Json }
    }
    Write-Host '  OK    Phase 2: config download'

    # --- Phase 3: OMP theme download ---
    $themeJson = Get-Content (Join-Path $cacheDir 'theme.json') -Raw | ConvertFrom-Json
    $themeName = $themeJson.theme.name
    $themeFileUrl = $themeJson.theme.url
    Invoke-DownloadWithRetry -Uri $themeFileUrl -OutFile (Join-Path $cacheDir "$themeName.omp.json")
    $ompFile = Join-Path $cacheDir "$themeName.omp.json"
    if (-not (Test-Path $ompFile) -or (Get-Item $ompFile).Length -eq 0) { $errors += 'OMP theme download failed' }
    else { Write-Host "  OK    Phase 3: OMP theme ($themeName)" }

    # --- Phase 4: user-settings.json template ---
    $usPath = Join-Path $cacheDir 'user-settings.json'
    $usTemplate = '{"_comment": "User overrides. Keys mirror theme.json / terminal-config.json.", "windowsTerminal": {}}'
    [System.IO.File]::WriteAllText($usPath, $usTemplate, [System.Text.UTF8Encoding]::new($false))
    if (-not (Test-Path $usPath)) { $errors += 'user-settings.json not created' }
    else { Write-Host '  OK    Phase 4: user-settings.json' }

    # --- Phase 5: profile_user.ps1 template ---
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        $upPath = Join-Path $d 'profile_user.ps1'
        [System.IO.File]::WriteAllText($upPath, '# Personal overrides', [System.Text.UTF8Encoding]::new($false))
        if (-not (Test-Path $upPath)) { $errors += "profile_user.ps1 not created in $d" }
    }
    Write-Host '  OK    Phase 5: profile_user.ps1'

    # --- Phase 6: WT settings merge ---
    $tcJson = Get-Content (Join-Path $cacheDir 'terminal-config.json') -Raw | ConvertFrom-Json
    $wtPath = Join-Path $wtLocal 'settings.json'
    $wt = Get-Content $wtPath -Raw | ConvertFrom-Json
    $wtDefaults = $wt.profiles.defaults
    $tcJson.defaults.PSObject.Properties | ForEach-Object {
        $wtDefaults | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
    }
    if ($themeJson.windowsTerminal.colorScheme) {
        $wtDefaults | Add-Member -NotePropertyName 'colorScheme' -NotePropertyValue $themeJson.windowsTerminal.colorScheme -Force
    }
    [System.IO.File]::WriteAllText($wtPath, ($wt | ConvertTo-Json -Depth 100), [System.Text.UTF8Encoding]::new($false))
    $wtCheck = Get-Content $wtPath -Raw | ConvertFrom-Json
    if (-not $wtCheck.profiles.defaults.font.face) { $errors += 'WT merge: missing font.face' }
    if ($tcJson.defaults.opacity -and $wtCheck.profiles.defaults.opacity -ne $tcJson.defaults.opacity) { $errors += 'WT merge: opacity mismatch' }
    Write-Host '  OK    Phase 6: WT settings merge'

    # --- Phase 7: Verify profile loads in sandbox ---
    $env:CI = 'true'
    . (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')
    if (-not (Get-Command 'Show-Help' -ErrorAction SilentlyContinue)) { $errors += 'Profile did not load (Show-Help missing)' }
    if (-not (Get-Command 'Update-Profile' -ErrorAction SilentlyContinue)) { $errors += 'Profile did not load (Update-Profile missing)' }
    Write-Host '  OK    Phase 7: profile loads in sandbox'

    # --- Phase 8: Nerd Font detection ---
    try {
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
        $fc = New-Object System.Drawing.Text.InstalledFontCollection
        $nfMatch = @($fc.Families | Where-Object { $_.Name -match 'Caskaydia|NF|Nerd' })
        $fc.Dispose()
        if ($nfMatch.Count -gt 0) { Write-Host "  OK    Phase 8: Nerd Font found ($($nfMatch[0].Name))" }
        else { Write-Host '  WARN  Phase 8: No Nerd Font detected (optional)' }
    }
    catch { Write-Host "  WARN  Phase 8: Font check skipped ($_)" }
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE   = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "ASSERT: $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'Fresh install sandbox passed'
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $instOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -RepoRoot $repoRoot 2>&1
    foreach ($line in $instOutput) {
        $color = if ($line -match '^\s+OK') { 'Green' } elseif ($line -match 'ASSERT:|FAIL') { 'Red' } elseif ($line -match 'WARN') { 'Yellow' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
    $assertLines = @($instOutput | Where-Object { $_ -match 'ASSERT:' })
    if ($assertLines) { $assertLines | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    if ($LASTEXITCODE -ne 0) { throw 'Fresh install sandbox failed' }
    Write-Result 'Fresh install sandbox' 'PASS'
}
catch { Write-Result 'Fresh install sandbox' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# =====================================================================
#  CI JOB 1: lint
# =====================================================================
Write-Host ''
Write-Host '--- CI: lint ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 2. PSScriptAnalyzer
# -------------------------------------------------------
Write-Host '[2/26] PSScriptAnalyzer' -ForegroundColor Cyan
try {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.24.0 -Force -Scope CurrentUser
    }
    $results = Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -ExcludeRule @(
        'PSAvoidUsingWriteHost'
        'PSAvoidUsingWMICmdlet'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseBOMForUnicodeEncodedFile'
        'PSReviewUnusedParameter'
        'PSUseSingularNouns'
    )
    $issues = $results | Where-Object Severity -in 'Error','Warning'
    if ($issues) {
        $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
        Write-Result 'PSScriptAnalyzer' 'FAIL' "$($issues.Count) warning(s)/error(s)"
    }
    else { Write-Result 'PSScriptAnalyzer' 'PASS' }
}
catch { Write-Result 'PSScriptAnalyzer' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 3. Smoke test (pwsh, non-interactive)
# -------------------------------------------------------
Write-Host '[3/26] Smoke test (pwsh)' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    pwsh -NonInteractive -NoProfile -Command ". '$profilePath'"
    if ($LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE" }
    Write-Result 'Smoke test (pwsh)' 'PASS'
}
catch { Write-Result 'Smoke test (pwsh)' 'FAIL' $_.Exception.Message }
finally { $env:CI = $null }

# -------------------------------------------------------
# 4. Smoke test (PS5, non-interactive)
# -------------------------------------------------------
Write-Host '[4/26] Smoke test (PS5)' -ForegroundColor Cyan
if ($SkipPS5 -or -not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
    Write-Result 'Smoke test (PS5)' 'SKIP' 'powershell.exe not available or -SkipPS5'
}
else {
    try {
        $escaped = $profilePath -replace "'", "''"
        powershell.exe -NoProfile -Command "`$env:CI = 'true'; . '$escaped'"
        if ($LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE" }
        Write-Result 'Smoke test (PS5)' 'PASS'
    }
    catch { Write-Result 'Smoke test (PS5)' 'FAIL' $_.Exception.Message }
}

# -------------------------------------------------------
# 5. PS5 parse check (all .ps1 files)
# -------------------------------------------------------
Write-Host '[5/26] PS5 parse check' -ForegroundColor Cyan
if ($SkipPS5 -or -not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
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
Write-Host '[6/26] Hardcoded paths' -ForegroundColor Cyan
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
Write-Host '[7/26] Non-ASCII characters' -ForegroundColor Cyan
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
Write-Host '[8/26] UTF-8 BOM' -ForegroundColor Cyan
$bomFinds = @()
$bomFiles = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1,*.json |
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
Write-Host '[9/26] Set-Content Encoding check' -ForegroundColor Cyan
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
Write-Host '[10/26] Secrets scan' -ForegroundColor Cyan
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
Write-Host '[11/26] JSON config validation' -ForegroundColor Cyan
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
# 12. Config schema (required keys)
# -------------------------------------------------------
Write-Host '[12/26] Config schema' -ForegroundColor Cyan
$theme = Get-Content (Join-Path $repoRoot 'theme.json') -Raw | ConvertFrom-Json
$terminal = Get-Content (Join-Path $repoRoot 'terminal-config.json') -Raw | ConvertFrom-Json
$schemaErrors = @()
if (-not $theme.theme.name) { $schemaErrors += 'theme.json: missing theme.name' }
if (-not $theme.theme.url) { $schemaErrors += 'theme.json: missing theme.url' }
if (-not $terminal.defaults) { $schemaErrors += 'terminal-config.json: missing defaults' }
if (-not $terminal.fontInstall) { $schemaErrors += 'terminal-config.json: missing fontInstall' }
if (-not $terminal.fontInstall.name) { $schemaErrors += 'terminal-config.json: missing fontInstall.name' }
if (-not $terminal.fontInstall.displayName) { $schemaErrors += 'terminal-config.json: missing fontInstall.displayName' }
if (-not $terminal.fontInstall.version) { $schemaErrors += 'terminal-config.json: missing fontInstall.version' }
if ($schemaErrors) {
    $schemaErrors | ForEach-Object { Write-Host "        $_" -ForegroundColor Red }
    Write-Result 'Config schema' 'FAIL' "$($schemaErrors.Count) issue(s)"
}
else { Write-Result 'Config schema' 'PASS' }

# -------------------------------------------------------
# 13. setup.ps1 dry-run (required function definitions)
# -------------------------------------------------------
Write-Host '[13/26] setup.ps1 function definitions' -ForegroundColor Cyan
try {
    $setupContent = Get-Content $setupPath -Raw
    $requiredFunctions = @(
        'Test-InternetConnection', 'Install-NerdFonts', 'Install-OhMyPoshTheme',
        'Install-WingetPackage', 'Merge-JsonObject', 'Select-PreferredEditor',
        'Invoke-DownloadWithRetry'
    )
    $missingFns = @()
    foreach ($fn in $requiredFunctions) {
        if ($setupContent -notmatch "function\s+$fn\b") { $missingFns += $fn }
    }
    if ($missingFns) {
        $missingFns | ForEach-Object { Write-Host "        Missing: $_" -ForegroundColor Red }
        Write-Result 'setup.ps1 functions' 'FAIL' "$($missingFns.Count) missing"
    }
    else { Write-Result 'setup.ps1 functions' 'PASS' }
}
catch { Write-Result 'setup.ps1 functions' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 14. Merge-JsonObject unit tests
# -------------------------------------------------------
Write-Host '[14/26] Merge-JsonObject tests' -ForegroundColor Cyan
try {
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

    Write-Result 'Merge-JsonObject tests' 'PASS'
}
catch { Write-Result 'Merge-JsonObject tests' 'FAIL' $_.Exception.Message }

# -------------------------------------------------------
# 15. WT settings merge mock (defaults + scheme + keybindings + JSON roundtrip)
# -------------------------------------------------------
Write-Host '[15/26] WT settings merge mock' -ForegroundColor Cyan
try {
    $mockWt = [PSCustomObject]@{
        profiles = [PSCustomObject]@{
            defaults = [PSCustomObject]@{ font = [PSCustomObject]@{ face = 'Consolas'; size = 10 } }
            list = @()
        }
        schemes = @(); actions = @()
    }
    $defaults = $mockWt.profiles.defaults

    # Apply terminal-config defaults
    $terminal.defaults.PSObject.Properties | ForEach-Object {
        $defaults | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
    }
    if ($theme.windowsTerminal.colorScheme) {
        $defaults | Add-Member -NotePropertyName 'colorScheme' -NotePropertyValue $theme.windowsTerminal.colorScheme -Force
    }
    if ($defaults.opacity -ne $terminal.defaults.opacity) { throw "opacity mismatch" }
    if ($defaults.colorScheme -ne $theme.windowsTerminal.colorScheme) { throw "colorScheme mismatch" }
    if ($defaults.font.face -ne $terminal.defaults.font.face) { throw "font.face mismatch" }

    # Scheme upsert
    $schemeDef = $theme.windowsTerminal.scheme
    $mockWt.schemes = @(@($mockWt.schemes | Where-Object { $_ -and $_.name -ne $schemeDef.name }) + ([PSCustomObject]$schemeDef))
    if ($mockWt.schemes.Count -ne 1 -or $mockWt.schemes[0].name -ne $schemeDef.name) { throw 'Scheme upsert failed' }

    # Keybinding upsert
    foreach ($kb in $terminal.keybindings) {
        $mockWt.actions = @($mockWt.actions) + ([PSCustomObject]@{ keys = $kb.keys; command = $kb.command })
    }
    $firstKb = @($terminal.keybindings)[0]
    $found = $mockWt.actions | Where-Object { $_.keys -eq $firstKb.keys }
    if (-not $found -or $found.command -ne $firstKb.command) { throw 'Keybinding upsert failed' }

    # JSON roundtrip (depth matches production profile/setup writes)
    $null = ($mockWt | ConvertTo-Json -Depth 100) | ConvertFrom-Json -ErrorAction Stop

    Write-Result 'WT merge mock' 'PASS'
}
catch { Write-Result 'WT merge mock' 'FAIL' $_.Exception.Message }

# =====================================================================
#  LOCAL-ONLY: profile-level validation
# =====================================================================
Write-Host ''
Write-Host '--- Local: profile validation ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 16. ProfileTools metadata (every entry has required fields)
# -------------------------------------------------------
Write-Host '[16/26] ProfileTools metadata' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    $output = pwsh -NonInteractive -NoProfile -Command @"
. '$profilePath'
`$requiredKeys = @('Name','Id','Cmd','Cache','VerCmd')
`$errors = @()
foreach (`$tool in `$script:ProfileTools) {
    foreach (`$k in `$requiredKeys) {
        if (-not `$tool.ContainsKey(`$k)) { `$errors += "`$(`$tool.Name): missing `$k" }
    }
    if (`$tool.Id -and `$tool.Id -notmatch '^[A-Za-z0-9._-]+$') { `$errors += "`$(`$tool.Name): invalid Id format" }
}
if (`$errors) { `$errors | ForEach-Object { Write-Host `$_ }; exit 1 }
Write-Host "OK: `$(`$script:ProfileTools.Count) tools validated"
"@
    if ($LASTEXITCODE -ne 0) { throw "Validation errors (see above)" }
    Write-Result 'ProfileTools metadata' 'PASS'
}
catch { Write-Result 'ProfileTools metadata' 'FAIL' $_.Exception.Message }
finally { $env:CI = $null }

# -------------------------------------------------------
# 17. Key functions exist after profile load
# -------------------------------------------------------
Write-Host '[17/26] Key functions exist' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    $output = pwsh -NonInteractive -NoProfile -Command @"
. '$profilePath'
`$expected = @(
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
    'gs','ga','gc','gpush','gpull','g','gcl','gcom','lazyg',
    'ls','la','ll','lt','cat','docs','dtop','admin','reload',
    'ep','su'
)
if (Get-Command ssh -ErrorAction SilentlyContinue) {
    `$expected += @('Copy-SshKey','keygen','ssh-copy-key')
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    `$expected += @('dps','dpa','dimg','dlogs','dex','dstop','dprune')
}
`$missing = @()
foreach (`$fn in `$expected) {
    if (-not (Get-Command `$fn -ErrorAction SilentlyContinue)) { `$missing += `$fn }
}
if (`$missing) {
    `$missing | ForEach-Object { Write-Host "Missing: `$_" }
    exit 1
}
Write-Host "OK: `$(`$expected.Count) functions verified"
"@
    if ($LASTEXITCODE -ne 0) { throw "Missing functions (see above)" }
    Write-Result 'Key functions exist' 'PASS'
}
catch { Write-Result 'Key functions exist' 'FAIL' $_.Exception.Message }
finally { $env:CI = $null }

# -------------------------------------------------------
# 18. Uninstall-Profile -WhatIf (all phases produce output)
# -------------------------------------------------------
Write-Host '[18/26] Uninstall-Profile -WhatIf' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    $output = pwsh -NonInteractive -NoProfile -Command ". '$profilePath'; Uninstall-Profile -All -WhatIf *>&1" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE" }
    $whatifLines = @($output | Where-Object { $_ -match 'What if' })
    if ($whatifLines.Count -eq 0) { throw 'No WhatIf output produced' }
    # Core phases that always produce output when sandboxed with real profile + cache files.
    # 'Restore WT' is NOT required because it only fires when Windows Terminal is installed;
    # after Get-WindowsTerminalSettingsPath became variant-aware, WT-less hosts skip that phase.
    $requiredPhases = @('Remove cache', 'Remove profile file')
    $missingPhases = @()
    foreach ($ph in $requiredPhases) {
        if (-not ($whatifLines | Where-Object { $_ -match $ph })) { $missingPhases += $ph }
    }
    if ($missingPhases) {
        $missingPhases | ForEach-Object { Write-Host "        Missing phase: $_" -ForegroundColor Yellow }
        throw "$($missingPhases.Count) phase(s) missing from WhatIf output"
    }
    Write-Result 'Uninstall-Profile -WhatIf' 'PASS' "$($whatifLines.Count) action(s), all phases OK"
}
catch { Write-Result 'Uninstall-Profile -WhatIf' 'FAIL' $_.Exception.Message }
finally { $env:CI = $null }

# -------------------------------------------------------
# 19. Uninstall-Profile sandbox: core (real file deletion)
# -------------------------------------------------------
Write-Host '[19/26] Uninstall sandbox: core' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    # Build sandbox test as a temp script (avoids escaping hell)
    $sandboxScript = Join-Path $env:TEMP "uninstall-sandbox-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

# 2. Load profile with real env to get function definitions
$env:CI = 'true'
. $ProfileSource

# 3. Create sandbox directory tree
$sb = Join-Path $env:TEMP "psp-sandbox-$([System.IO.Path]::GetRandomFileName())"

$wtLocal  = Join-Path $sb 'Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
$cacheDir = Join-Path $sb 'Local\PowerShellProfile'
$ps7Dir   = Join-Path $sb 'Documents\PowerShell'
$ps5Dir   = Join-Path $sb 'Documents\WindowsPowerShell'

New-Item -ItemType Directory -Path $wtLocal, $cacheDir, $ps7Dir, $ps5Dir -Force | Out-Null

# WT: original settings + 2 backups with different content
[System.IO.File]::WriteAllText((Join-Path $wtLocal 'settings.json'), '{"modified": true}', [System.Text.UTF8Encoding]::new($false))
$bakOld = Join-Path $wtLocal 'settings.json.20240101-100000.bak'
$bakNew = Join-Path $wtLocal 'settings.json.20240601-120000.bak'
[System.IO.File]::WriteAllText($bakOld, '{"original": "old"}', [System.Text.UTF8Encoding]::new($false))
Start-Sleep -Milliseconds 50
[System.IO.File]::WriteAllText($bakNew, '{"original": "newest"}', [System.Text.UTF8Encoding]::new($false))

# Cache files
foreach ($f in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json')) {
    [System.IO.File]::WriteAllText((Join-Path $cacheDir $f), "# $f placeholder", [System.Text.UTF8Encoding]::new($false))
}

# Profile files in both dirs
foreach ($d in @($ps7Dir, $ps5Dir)) {
    [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), '# profile', [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user overrides', [System.Text.UTF8Encoding]::new($false))
}

# 4. Override environment to point at sandbox
$origLocal   = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = Join-Path $sb 'Local'
$global:PROFILE   = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$errors = @()
try {
    # ===== TEST A: Core uninstall (no switches) =====
    Uninstall-Profile -Confirm:$false

    # WT settings.json should have backup content
    $wtContent = [System.IO.File]::ReadAllText((Join-Path $wtLocal 'settings.json'))
    if ($wtContent -ne '{"original": "newest"}') { $errors += "WT restore: expected backup content, got: $wtContent" }

    # All backups should be gone
    $remainingBaks = Get-ChildItem $wtLocal -Filter '*.bak' -ErrorAction SilentlyContinue
    if ($remainingBaks) { $errors += "WT backups: $($remainingBaks.Count) backup(s) still exist" }

    # Cache: omp-init, zoxide-init, theme.json, terminal-config.json should be gone
    foreach ($f in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json')) {
        if (Test-Path (Join-Path $cacheDir $f)) { $errors += "Cache: $f still exists" }
    }

    # Cache: user-settings.json should be PRESERVED (no -RemoveUserData)
    if (-not (Test-Path (Join-Path $cacheDir 'user-settings.json'))) { $errors += 'Cache: user-settings.json was deleted (should be preserved)' }

    # Profile files should be gone from both dirs
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        $pf = Join-Path $d 'Microsoft.PowerShell_profile.ps1'
        if (Test-Path $pf) { $errors += "Profile: $pf still exists" }
    }

    # profile_user.ps1 should be PRESERVED (no -RemoveUserData)
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        $uf = Join-Path $d 'profile_user.ps1'
        if (-not (Test-Path $uf)) { $errors += "User profile: $uf was deleted (should be preserved)" }
    }

    # ===== TEST B: Recreate and test -RemoveUserData =====
    # Recreate the files that were deleted
    [System.IO.File]::WriteAllText((Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'), '# profile', [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $ps5Dir 'Microsoft.PowerShell_profile.ps1'), '# profile', [System.Text.UTF8Encoding]::new($false))

    Uninstall-Profile -RemoveUserData -Confirm:$false

    # user-settings.json should now be gone
    if (Test-Path (Join-Path $cacheDir 'user-settings.json')) { $errors += 'RemoveUserData: user-settings.json still exists' }

    # profile_user.ps1 should now be gone from both dirs
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        $uf = Join-Path $d 'profile_user.ps1'
        if (Test-Path $uf) { $errors += "RemoveUserData: $uf still exists" }
    }

    # Cache dir itself should be gone (empty after full removal)
    if ((Test-Path $cacheDir) -and (Get-ChildItem $cacheDir -ErrorAction SilentlyContinue)) {
        $leftover = (Get-ChildItem $cacheDir).Name -join ', '
        $errors += "Cache dir not empty: $leftover"
    }
}
finally {
    # 4. Restore real env
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE   = $origProfile
    # Cleanup sandbox
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "ASSERT: $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'All sandbox assertions passed'
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $sandboxOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    $sandboxExit = $LASTEXITCODE
    # Show any assertion failures from subprocess
    $assertLines = @($sandboxOutput | Where-Object { $_ -match 'ASSERT:' })
    if ($assertLines) { $assertLines | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    if ($sandboxExit -ne 0) { throw "Sandbox assertions failed" }
    Write-Result 'Uninstall sandbox: core' 'PASS'
}
catch { Write-Result 'Uninstall sandbox: core' 'FAIL' $_.Exception.Message }
finally {
    $env:CI = $null
    Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue
}

# -------------------------------------------------------
# 20. Uninstall-Profile sandbox: -All (everything removed)
# -------------------------------------------------------
Write-Host '[20/26] Uninstall sandbox: -All' -ForegroundColor Cyan
try {
    $env:CI = 'true'
    $sandboxScript = Join-Path $env:TEMP "uninstall-all-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

$env:CI = 'true'
. $ProfileSource

$sb = Join-Path $env:TEMP "psp-sandbox-all-$([System.IO.Path]::GetRandomFileName())"

$wtLocal  = Join-Path $sb 'Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
$cacheDir = Join-Path $sb 'Local\PowerShellProfile'
$ps7Dir   = Join-Path $sb 'Documents\PowerShell'
$ps5Dir   = Join-Path $sb 'Documents\WindowsPowerShell'

New-Item -ItemType Directory -Path $wtLocal, $cacheDir, $ps7Dir, $ps5Dir -Force | Out-Null

[System.IO.File]::WriteAllText((Join-Path $wtLocal 'settings.json'), '{"modified": true}', [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $wtLocal 'settings.json.20240601-120000.bak'), '{"original": true}', [System.Text.UTF8Encoding]::new($false))

foreach ($f in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json')) {
    [System.IO.File]::WriteAllText((Join-Path $cacheDir $f), "# $f", [System.Text.UTF8Encoding]::new($false))
}

foreach ($d in @($ps7Dir, $ps5Dir)) {
    [System.IO.File]::WriteAllText((Join-Path $d 'Microsoft.PowerShell_profile.ps1'), '# profile', [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user', [System.Text.UTF8Encoding]::new($false))
}

$origLocal   = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = Join-Path $sb 'Local'
$global:PROFILE   = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$errors = @()
try {
    # -All removes everything (except tools/fonts which need winget/admin)
    Uninstall-Profile -All -Confirm:$false

    # WT restored
    $wtContent = [System.IO.File]::ReadAllText((Join-Path $wtLocal 'settings.json'))
    if ($wtContent -ne '{"original": true}') { $errors += "WT restore failed: $wtContent" }

    # No backups
    if (Get-ChildItem $wtLocal -Filter '*.bak' -ErrorAction SilentlyContinue) { $errors += 'Backups remain' }

    # ALL cache files gone (including user-settings.json)
    foreach ($f in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json')) {
        if (Test-Path (Join-Path $cacheDir $f)) { $errors += "Cache: $f still exists" }
    }

    # ALL profile files gone (including profile_user.ps1)
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        foreach ($f in @('Microsoft.PowerShell_profile.ps1', 'profile_user.ps1')) {
            if (Test-Path (Join-Path $d $f)) { $errors += "$f still in $d" }
        }
    }
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE   = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "ASSERT: $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'All -All sandbox assertions passed'
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $sandboxOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    $sandboxExit = $LASTEXITCODE
    $assertLines = @($sandboxOutput | Where-Object { $_ -match 'ASSERT:' })
    if ($assertLines) { $assertLines | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    if ($sandboxExit -ne 0) { throw "Sandbox assertions failed" }
    Write-Result 'Uninstall sandbox: -All' 'PASS'
}
catch { Write-Result 'Uninstall sandbox: -All' 'FAIL' $_.Exception.Message }
finally {
    $env:CI = $null
    Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue
}

# -------------------------------------------------------
# 21. Lifecycle: install -> uninstall -> reinstall
# -------------------------------------------------------
Write-Host '[21/26] Lifecycle: install -> uninstall -> reinstall' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "lifecycle-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($RepoRoot)
$ErrorActionPreference = 'Stop'

# Parse setup.ps1 AST to extract functions
$setupFile = Join-Path $RepoRoot 'setup.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($setupFile, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "setup.ps1 parse errors: $($parseErrors.Count)" }
$fnDefs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($fn in $fnDefs) { Invoke-Expression $fn.Extent.Text }

# ===== Create sandbox =====
$sb = Join-Path $env:TEMP "psp-lifecycle-$([System.IO.Path]::GetRandomFileName())"
$cacheDir = Join-Path $sb 'Local\PowerShellProfile'
$ps7Dir   = Join-Path $sb 'Documents\PowerShell'
$ps5Dir   = Join-Path $sb 'Documents\WindowsPowerShell'
$wtLocal  = Join-Path $sb 'Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
New-Item -ItemType Directory -Path $cacheDir, $ps7Dir, $ps5Dir, $wtLocal -Force | Out-Null
$configCachePath = $cacheDir

# Minimal WT settings.json
$wtOriginal = '{"profiles":{"defaults":{"font":{"face":"Consolas"}},"list":[]},"schemes":[],"actions":[]}'
[System.IO.File]::WriteAllText((Join-Path $wtLocal 'settings.json'), $wtOriginal, [System.Text.UTF8Encoding]::new($false))

$origLocal   = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = Join-Path $sb 'Local'
$global:PROFILE   = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$errors = @()
try {
    # ===== PHASE 1: INSTALL =====
    Write-Host '  --- Phase 1: Install ---'
    $profileSrc = Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1'
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        Copy-Item $profileSrc (Join-Path $d 'Microsoft.PowerShell_profile.ps1')
    }

    # Download configs
    Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/theme.json' -OutFile (Join-Path $cacheDir 'theme.json')
    Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/terminal-config.json' -OutFile (Join-Path $cacheDir 'terminal-config.json')

    # OMP theme
    $themeJson = Get-Content (Join-Path $cacheDir 'theme.json') -Raw | ConvertFrom-Json
    Invoke-DownloadWithRetry -Uri $themeJson.theme.url -OutFile (Join-Path $cacheDir "$($themeJson.theme.name).omp.json")

    # user-settings.json + profile_user.ps1
    [System.IO.File]::WriteAllText((Join-Path $cacheDir 'user-settings.json'), '{}', [System.Text.UTF8Encoding]::new($false))
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user', [System.Text.UTF8Encoding]::new($false))
    }

    # WT backup (simulates what Update-Profile does)
    $bakFile = Join-Path $wtLocal 'settings.json.20240601-120000.bak'
    Copy-Item (Join-Path $wtLocal 'settings.json') $bakFile

    # Verify install
    $installFiles = @(
        (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'),
        (Join-Path $ps5Dir 'Microsoft.PowerShell_profile.ps1'),
        (Join-Path $cacheDir 'theme.json'),
        (Join-Path $cacheDir 'terminal-config.json'),
        (Join-Path $cacheDir 'user-settings.json'),
        (Join-Path $ps7Dir 'profile_user.ps1'),
        (Join-Path $ps5Dir 'profile_user.ps1')
    )
    $missingInstall = @($installFiles | Where-Object { -not (Test-Path $_) })
    if ($missingInstall) { $errors += "Install missing: $($missingInstall -join ', ')" }
    else { Write-Host '  OK    Install: all files created' }

    # Load profile to get Uninstall-Profile
    $env:CI = 'true'
    . (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')
    if (-not (Get-Command 'Uninstall-Profile' -ErrorAction SilentlyContinue)) { throw 'Uninstall-Profile not available after install' }
    Write-Host '  OK    Install: profile loaded, Uninstall-Profile available'

    # ===== PHASE 2: UNINSTALL (-All) =====
    Write-Host '  --- Phase 2: Uninstall -All ---'
    Uninstall-Profile -All -Confirm:$false

    # Verify everything removed
    foreach ($f in @('omp-init.ps1', 'zoxide-init.ps1', 'theme.json', 'terminal-config.json', 'user-settings.json')) {
        if (Test-Path (Join-Path $cacheDir $f)) { $errors += "After uninstall: $f still in cache" }
    }
    # OMP theme file should be gone
    $ompFiles = Get-ChildItem $cacheDir -Filter '*.omp.json' -ErrorAction SilentlyContinue
    if ($ompFiles) { $errors += "After uninstall: OMP theme still in cache" }

    foreach ($d in @($ps7Dir, $ps5Dir)) {
        foreach ($f in @('Microsoft.PowerShell_profile.ps1', 'profile_user.ps1')) {
            if (Test-Path (Join-Path $d $f)) { $errors += "After uninstall: $f still in $d" }
        }
    }

    # WT should be restored (backup content)
    $wtContent = [System.IO.File]::ReadAllText((Join-Path $wtLocal 'settings.json'))
    if ($wtContent -ne $wtOriginal) { Write-Host "  WARN  WT content differs (backup was modified copy, not original)" }

    # No backups should remain
    $baks = Get-ChildItem $wtLocal -Filter '*.bak' -ErrorAction SilentlyContinue
    if ($baks) { $errors += "After uninstall: $($baks.Count) backup(s) remain" }

    Write-Host '  OK    Uninstall: all files removed'

    # ===== PHASE 3: REINSTALL =====
    Write-Host '  --- Phase 3: Reinstall ---'
    # Recreate cache dir (uninstall may have cleaned it)
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    $configCachePath = $cacheDir

    foreach ($d in @($ps7Dir, $ps5Dir)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Copy-Item $profileSrc (Join-Path $d 'Microsoft.PowerShell_profile.ps1')
    }

    Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/theme.json' -OutFile (Join-Path $cacheDir 'theme.json')
    Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/terminal-config.json' -OutFile (Join-Path $cacheDir 'terminal-config.json')
    $themeJson = Get-Content (Join-Path $cacheDir 'theme.json') -Raw | ConvertFrom-Json
    Invoke-DownloadWithRetry -Uri $themeJson.theme.url -OutFile (Join-Path $cacheDir "$($themeJson.theme.name).omp.json")
    [System.IO.File]::WriteAllText((Join-Path $cacheDir 'user-settings.json'), '{}', [System.Text.UTF8Encoding]::new($false))
    foreach ($d in @($ps7Dir, $ps5Dir)) {
        [System.IO.File]::WriteAllText((Join-Path $d 'profile_user.ps1'), '# user', [System.Text.UTF8Encoding]::new($false))
    }

    # Verify reinstall
    $missingReinstall = @($installFiles | Where-Object { -not (Test-Path $_) })
    if ($missingReinstall) { $errors += "Reinstall missing: $($missingReinstall -join ', ')" }
    else { Write-Host '  OK    Reinstall: all files recreated' }

    # Reload profile and verify it works
    . (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')
    if (-not (Get-Command 'Show-Help' -ErrorAction SilentlyContinue)) { $errors += 'Reinstall: profile failed to load' }
    if (-not (Get-Command 'Uninstall-Profile' -ErrorAction SilentlyContinue)) { $errors += 'Reinstall: Uninstall-Profile missing' }
    Write-Host '  OK    Reinstall: profile loads correctly'
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE   = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "ASSERT: $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'Lifecycle test passed (install -> uninstall -> reinstall)'
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $lcOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -RepoRoot $repoRoot 2>&1
    foreach ($line in $lcOutput) {
        $color = if ($line -match '^\s+OK') { 'Green' } elseif ($line -match 'ASSERT:|FAIL') { 'Red' } elseif ($line -match 'WARN') { 'Yellow' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
    $assertLines = @($lcOutput | Where-Object { $_ -match 'ASSERT:' })
    if ($assertLines) { $assertLines | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    if ($LASTEXITCODE -ne 0) { throw 'Lifecycle test failed' }
    Write-Result 'Lifecycle: install -> uninstall -> reinstall' 'PASS'
}
catch { Write-Result 'Lifecycle: install -> uninstall -> reinstall' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# -------------------------------------------------------
# 22. Execute every command (sandbox)
# -------------------------------------------------------
Write-Host '[22/26] Execute every command' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "fn-exec-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($ProfileSource)
$ErrorActionPreference = 'Continue'
$env:CI = 'true'
. $ProfileSource

$ok = 0; $fail = 0; $skip = 0; $netFail = 0
function T {
    param([string]$N, [scriptblock]$C, [string]$S)
    if ($S) { Write-Host "  SKIP  $N  ($S)"; $script:skip++; return }
    try {
        $null = & { $ErrorActionPreference = 'Stop'; & $C } 2>&1
        Write-Host "  OK    $N"; $script:ok++
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'Timeout|timed out|HttpClient|Unable to connect') {
            Write-Host "  NET   $N  ($msg)"; $script:netFail++
        } else {
            Write-Host "  FAIL  $N  ($msg)"; $script:fail++
        }
    }
}

# --- Temp workspace ---
$ws = Join-Path $env:TEMP "psp-exec-$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory $ws -Force | Out-Null
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
    foreach ($p in @('Force', 'SkipHashCheck', 'ExpectedSha256', 'WhatIf')) {
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
    # Safe early-exit paths: PS5 prints guidance and returns; PS7 without winget warns and returns.
    Update-PowerShell *> $null
}
T 'Update-Tools'      {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        # winget present - would mutate installs; just verify command exists
        if (-not (Get-Command Update-Tools)) { throw 'Update-Tools missing' }
    }
    else {
        Update-Tools *> $null
    }
}
T 'Clear-ProfileCache' $null 'destructive to real cache'
T 'Clear-Cache'       $null 'destructive to real cache'
T 'Uninstall-Profile' $null 'tested in sandbox 19/20'
T 'Invoke-ProfileWizard' {
    # -WhatIf must prevent the network download via the ShouldProcess gate.
    $pre = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*.ps1' -ErrorAction SilentlyContinue)
    Invoke-ProfileWizard -WhatIf -Confirm:$false | Out-Null
    $post = @(Get-ChildItem -Path $env:TEMP -Filter 'psp-reconfigure-*.ps1' -ErrorAction SilentlyContinue)
    if ($post.Count -gt $pre.Count) { throw "Invoke-ProfileWizard -WhatIf leaked temp files" }
    $cmd = Get-Command Invoke-ProfileWizard
    foreach ($p in @('Resume', 'NoElevate', 'ExpectedSha256', 'SkipHashCheck', 'WhatIf')) {
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
T 'gc'    { gc "test commit" }
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
T 'ff'      { Push-Location $ws; ff "sample.txt"; Pop-Location }
T 'touch'   { touch (Join-Path $ws 'touched.txt') }
T 'nf'      { touch (Join-Path $ws 'newfile.txt') }
T 'mkcd'    { $d = Join-Path $ws 'mkcdtest'; mkcd $d; Pop-Location }
T 'head'    { head $tf 3 }
T 'tail'    { tail $tf 3 }
T 'file'    { file $tf }
T 'sizeof'  { sizeof $ws }
T 'trash'   { $t = Join-Path $ws 'trashme.txt'; [System.IO.File]::WriteAllText($t, 'bye', [System.Text.UTF8Encoding]::new($false)); trash $t }
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
        $out = cdh | Out-String
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
    $out = duration | Out-String
    if ([string]::IsNullOrWhiteSpace($out)) { throw 'duration produced no output' }
}
T 'Test-ProfileHealth' {
    $report = Test-ProfileHealth
    if (-not $report) { throw 'Test-ProfileHealth returned no rows' }
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
T 'pkill'   $null 'destructive - kills processes'
T 'export'  { export "PSP_TEST_VAR" "testvalue" }

# ===== SYSTEM & NETWORK =====
T 'admin'     $null 'opens elevated terminal'
T 'su'        $null 'opens elevated terminal'
T 'pubip'     { pubip }
T 'localip'   { localip }
T 'uptime'    { uptime }
T 'sysinfo'   { sysinfo }
T 'df'        { df }
T 'flushdns'  $null 'requires admin'
T 'ports'     { ports }
T 'checkport' { checkport "dns.google" 443 }
T 'portscan'  { portscan "dns.google" -Ports @(53, 443) }
T 'tlscert'   { tlscert "google.com" }
T 'ipinfo'    { ipinfo "8.8.8.8" }
T 'whois'     { whois "example.com" }
T 'nslook'    { nslook "google.com" }
T 'env'       { env "PATH" }
T 'svc'       { svc "idle" -Count 1 }
T 'eventlog'  { eventlog 1 }
T 'weather'   { weather "Oslo" }
T 'speedtest' $null 'takes 30s+ download'
T 'wifipass'  $null 'requires admin/netsh'
T 'hosts'     $null 'opens elevated editor'
T 'winutil' {
    $marker = Join-Path $ws 'winutil-ran.txt'
    $expectedHash = ('AB' * 32)
    try {
        function Invoke-RestMethod {
            param(
                [string]$Uri,
                [string]$OutFile,
                [int]$TimeoutSec,
                [switch]$UseBasicParsing,
                $ErrorAction
            )
            $utf8 = [System.Text.UTF8Encoding]::new($false)
            $markerLiteral = $marker -replace "'", "''"
            $scriptBody = "[System.IO.File]::WriteAllText('$markerLiteral', 'ran', [System.Text.UTF8Encoding]::new(`$false))"
            [System.IO.File]::WriteAllText($OutFile, $scriptBody, $utf8)
        }
        function Get-FileHash {
            param(
                [string]$LiteralPath,
                [string]$Algorithm
            )
            [PSCustomObject]@{ Hash = $expectedHash }
        }

        winutil
        if (Test-Path $marker) { throw 'winutil executed without explicit opt-in' }

        winutil -Force -WhatIf
        if (Test-Path $marker) { throw 'winutil executed under -WhatIf' }

        winutil -ExpectedSha256 $expectedHash -Confirm:$false
        if (-not (Test-Path $marker)) { throw 'winutil did not execute after hash match + explicit confirmation bypass' }
    }
    finally {
        Remove-Item Function:\Invoke-RestMethod -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-FileHash -ErrorAction SilentlyContinue
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

# ===== SECURITY & CRYPTO =====
$hashOut = $null
T 'hash'      { $script:hashOut = hash $tf; $script:hashOut }
T 'hash MD5'  { hash $tf -Algorithm MD5 }
T 'checksum'  { if ($script:hashOut) { $h = ($script:hashOut | Out-String).Trim().Split(' ')[-1]; checksum $tf $h } else { throw 'no hash' } }
T 'genpass'   { genpass 16 }
T 'b64'       { b64 "hello world" }
T 'b64d'      { b64d "aGVsbG8gd29ybGQ=" }
T 'jwtd'      { jwtd "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" }
T 'uuid'      { uuid }
T 'epoch'     { epoch }
T 'epoch 0'   { epoch 0 }
T 'urlencode' { urlencode "hello world" }
T 'urldecode' { urldecode "hello%20world" }
T 'vtscan'    $null 'needs API key + uploads file'
T 'vt'        {
    if (Get-Command vt.exe -ErrorAction SilentlyContinue) { vt --help }
    else { vt }
}

# ===== DEVELOPER =====
T 'killport'            $null 'destructive - kills process'
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
T 'Remove-LockedItem' $null 'destructive - kills + deletes'
T 'http'       { http "https://httpbin.org/get" }
T 'prettyjson' { prettyjson $jf }
T 'hb'         { hb $tf }
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
T 'Copy-SshKey' $null 'needs remote host'
T 'ssh-copy-key' $null 'needs remote host'
T 'keygen'      $null 'creates keys on disk'
T 'rdp'         $null 'opens RDP UI'

# ===== CLIPBOARD =====
T 'cpy'  { cpy "psp-test-clip" }
T 'pst'  { $r = pst; if ($r -ne "psp-test-clip") { throw "expected psp-test-clip, got: $r" } }
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
    $origIsAdmin = $script:isAdmin
    $script:isAdmin = $true
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
        $script:isAdmin = $origIsAdmin
        Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-Variable -Name fwCalls -Scope Script -ErrorAction SilentlyContinue
    }
}
T 'fwblock' {
    $origIsAdmin = $script:isAdmin
    $script:isAdmin = $true
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
        $script:isAdmin = $origIsAdmin
        Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-Variable -Name fwCalls -Scope Script -ErrorAction SilentlyContinue
    }
}

# ===== CYBERSEC =====
T 'nscan'         $null 'requires nmap'
T 'sigcheck'      { sigcheck (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') }
T 'ads'           { $a = Join-Path $ws 'ads.txt'; [System.IO.File]::WriteAllText($a, 'x', [System.Text.UTF8Encoding]::new($false)); Set-Content -LiteralPath $a -Stream 'zone' -Value 'marker'; ads $a }
T 'defscan'       $null 'triggers Defender scan'
T 'pwnd'          { pwnd 'password' }
T 'certcheck'     { certcheck 'example.com' }
T 'entropy'       { entropy $tf }

# ===== DEVELOPER+ =====
T 'serve'         $null 'long-running HTTP server'
T 'gitignore'     { Push-Location $ws; try { gitignore 'python' } finally { Pop-Location } }
T 'gcof'          $null 'interactive fzf picker'
T 'envload'       { $ef = Join-Path $ws '.env'; [System.IO.File]::WriteAllText($ef, 'PSP_TST=ok', [System.Text.UTF8Encoding]::new($false)); envload $ef }
T 'tldr'          { tldr 'ls' }
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
T 'Add-TrustedDirectory'    $null 'persists to user-settings.json (tested in sandbox)'
T 'Remove-TrustedDirectory' $null 'persists to user-settings.json (tested in sandbox)'

# ===== THEME =====
T 'Set-TerminalBackground'  $null 'persists to user-settings.json (tested in sandbox)'

# --- Cleanup ---
Remove-Item $ws -Recurse -Force -ErrorAction SilentlyContinue

# --- Result ---
Write-Host ""
$summary = "  Functions: $ok ok, $fail fail, $netFail net-fail, $skip skip"
Write-Host $summary -ForegroundColor $(if ($fail -gt 0) { 'Red' } elseif ($netFail -gt 0) { 'Yellow' } else { 'Green' })
if ($fail -gt 0) { exit 1 }
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $fnOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    # Show all output
    foreach ($line in $fnOutput) {
        $color = if ($line -match '^\s+OK') { 'Green' } elseif ($line -match '^\s+FAIL') { 'Red' } elseif ($line -match '^\s+NET') { 'Yellow' } elseif ($line -match '^\s+SKIP') { 'DarkGray' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
    $fnFails = @($fnOutput | Where-Object { $_ -match '^\s+FAIL' })
    if ($LASTEXITCODE -ne 0 -or $fnFails.Count -gt 0) { throw "$($fnFails.Count) function(s) failed" }
    Write-Result 'Execute every command' 'PASS'
}
catch { Write-Result 'Execute every command' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# =====================================================================
#  SETUP & INSTALL VERIFICATION
# =====================================================================
Write-Host ''
Write-Host '--- Setup & install verification ---' -ForegroundColor Magenta
Write-Host ''

# -------------------------------------------------------
# 23. setup.ps1 functions sandbox (AST extract + execute)
# -------------------------------------------------------
Write-Host '[23/26] setup.ps1 functions sandbox' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "setup-fn-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($SetupSource)
$ErrorActionPreference = 'Stop'

# Parse setup.ps1 AST to extract functions without running install flow
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($SetupSource, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "setup.ps1 has $($parseErrors.Count) parse error(s)" }

# Extract and define all top-level functions
$fnDefs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($fn in $fnDefs) { Invoke-Expression $fn.Extent.Text }
Write-Host "  Extracted $($fnDefs.Count) functions from setup.ps1"

# Extract $EditorCandidates assignment
$varDefs = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $args[0].Left.Extent.Text -eq '$EditorCandidates'
}, $true)
if ($varDefs.Count -gt 0) { Invoke-Expression $varDefs[0].Extent.Text }

$ok = 0; $fail = 0
function T($N, $C) {
    try { $null = & $C 2>&1; Write-Host "  OK    $N"; $script:ok++ }
    catch { Write-Host "  FAIL  $N  ($_)"; $script:fail++ }
}

# --- Test-InternetConnection ---
T 'Test-InternetConnection' {
    $r = Test-InternetConnection
    if ($r -ne $true) { throw "expected true, got $r" }
}

# --- Invoke-DownloadWithRetry (real download) ---
T 'Invoke-DownloadWithRetry' {
    $tmp = Join-Path $env:TEMP "psp-dltest-$([System.IO.Path]::GetRandomFileName()).json"
    try {
        Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/theme.json' -OutFile $tmp
        if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) { throw 'download empty' }
        $null = Get-Content $tmp -Raw | ConvertFrom-Json
    }
    finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

# --- Merge-JsonObject (setup.ps1 copy) ---
T 'Merge-JsonObject (setup copy)' {
    $b = [PSCustomObject]@{ a = 1; n = [PSCustomObject]@{ x = 10; y = 20 } }
    Merge-JsonObject $b ([PSCustomObject]@{ a = 99; n = [PSCustomObject]@{ y = 30; z = 40 } })
    if ($b.a -ne 99 -or $b.n.x -ne 10 -or $b.n.y -ne 30 -or $b.n.z -ne 40) { throw 'merge mismatch' }
}

# --- Install-WingetPackage (already-installed path) ---
T 'Install-WingetPackage' {
    $r = Install-WingetPackage -Name 'PowerShell' -Id 'Microsoft.PowerShell'
    if ($r -ne $true) { throw "expected true, got $r" }
}

# --- Install-NerdFonts (font detection) ---
T 'Install-NerdFonts (detection)' {
    $r = Install-NerdFonts
    if ($r -ne $true) { throw "expected true, got $r" }
}

# --- Install-OhMyPoshTheme (real download to temp) ---
$configCachePath = Join-Path $env:TEMP "psp-omp-$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory $configCachePath -Force | Out-Null
T 'Install-OhMyPoshTheme' {
    $r = Install-OhMyPoshTheme -ThemeName 'testtheme' -ThemeUrl 'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/agnoster.omp.json'
    if ($r -ne $true) { throw "expected true, got $r" }
    if (-not (Test-Path (Join-Path $configCachePath 'testtheme.omp.json'))) { throw 'theme file missing' }
}
Remove-Item $configCachePath -Recurse -Force -ErrorAction SilentlyContinue

# --- EditorCandidates validation ---
T 'EditorCandidates' {
    if (-not $EditorCandidates -or $EditorCandidates.Count -lt 5) { throw "only $($EditorCandidates.Count) candidates" }
    foreach ($ed in $EditorCandidates) {
        if (-not $ed.Cmd -or -not $ed.Display) { throw "invalid: $($ed | ConvertTo-Json -Compress)" }
    }
}

Write-Host ''
Write-Host "  setup.ps1 functions: $ok ok, $fail fail" -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })
if ($fail -gt 0) { exit 1 }
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $fnOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -SetupSource $setupPath 2>&1
    foreach ($line in $fnOutput) {
        $color = if ($line -match '^\s+OK') { 'Green' } elseif ($line -match '^\s+FAIL') { 'Red' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
    $fnFails = @($fnOutput | Where-Object { $_ -match '^\s+FAIL' })
    if ($LASTEXITCODE -ne 0 -or $fnFails.Count -gt 0) { throw "$($fnFails.Count) function(s) failed" }
    Write-Result 'setup.ps1 functions sandbox' 'PASS'
}
catch { Write-Result 'setup.ps1 functions sandbox' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# -------------------------------------------------------
# 24. setprofile.ps1 sandbox (copy to both PS dirs)
# -------------------------------------------------------
Write-Host '[24/26] setprofile.ps1 sandbox' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "setprofile-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($RepoRoot)
$ErrorActionPreference = 'Stop'

$sb = Join-Path $env:TEMP "psp-setprofile-$([System.IO.Path]::GetRandomFileName())"
$srcDir  = Join-Path $sb 'src'
$docsDir = Join-Path $sb 'Documents'
$ps7Dir  = Join-Path $docsDir 'PowerShell'
$ps5Dir  = Join-Path $docsDir 'WindowsPowerShell'
New-Item -ItemType Directory -Path $srcDir -Force | Out-Null

Copy-Item (Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1') $srcDir
Copy-Item (Join-Path $RepoRoot 'setprofile.ps1') $srcDir

$origProfile = $PROFILE
$global:PROFILE = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$errors = @()
try {
    Push-Location $srcDir
    & (Join-Path $srcDir 'setprofile.ps1')
    Pop-Location

    foreach ($dir in @($ps7Dir, $ps5Dir)) {
        $pf = Join-Path $dir 'Microsoft.PowerShell_profile.ps1'
        if (-not (Test-Path $pf)) { $errors += "Not created: $pf" }
        else {
            $src = Get-Content (Join-Path $srcDir 'Microsoft.PowerShell_profile.ps1') -Raw
            $dst = Get-Content $pf -Raw
            if ($src -ne $dst) { $errors += "Content mismatch: $pf" }
        }
    }
}
finally {
    $global:PROFILE = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "ASSERT: $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'setprofile.ps1 sandbox passed'
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $spOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -RepoRoot $repoRoot 2>&1
    $assertLines = @($spOutput | Where-Object { $_ -match 'ASSERT:' })
    if ($assertLines) { $assertLines | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    if ($LASTEXITCODE -ne 0) { throw "setprofile sandbox failed" }
    Write-Result 'setprofile.ps1 sandbox' 'PASS'
}
catch { Write-Result 'setprofile.ps1 sandbox' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# -------------------------------------------------------
# 25. Install verification (tools, configs, fonts)
# -------------------------------------------------------
Write-Host '[25/26] Install verification' -ForegroundColor Cyan
try {
    $sandboxScript = Join-Path $env:TEMP "install-verify-$([System.IO.Path]::GetRandomFileName()).ps1"
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $sandboxCode = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

# Refresh PATH from registry (catches winget/scoop installs missed by parent shell)
$env:PATH = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')

# Load profile to get $script:ProfileTools and tool-dependent function definitions
$env:CI = 'true'
. $ProfileSource

$errors = @()
$warnings = @()

# --- Tools: check each ProfileTools entry via Get-Command (warn-only, profile works without them) ---
$toolsFound = 0; $toolsMissing = 0
foreach ($tool in $script:ProfileTools) {
    $cmd = Get-Command $tool.Cmd -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $ver = & $tool.Cmd $tool.VerCmd 2>&1 | Out-String
            Write-Host "  OK    $($tool.Name) = $($ver.Trim().Split([char]10)[0])"
            $toolsFound++
        }
        catch { $warnings += "$($tool.Name): found but --version failed"; $toolsMissing++ }
    }
    else { $warnings += "$($tool.Name): not installed"; $toolsMissing++ }
}

# --- Required: cache directory and config files ---
$cachePath = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'
if (-not (Test-Path $cachePath)) { $errors += "Cache dir missing: $cachePath" }
else {
    foreach ($cf in @('theme.json', 'terminal-config.json')) {
        $cfPath = Join-Path $cachePath $cf
        if (-not (Test-Path $cfPath)) { $errors += "$cf not cached" }
        else {
            try { $null = Get-Content $cfPath -Raw | ConvertFrom-Json }
            catch { $errors += "$cf corrupt: $_" }
        }
    }
    $userSettings = Join-Path $cachePath 'user-settings.json'
    if (-not (Test-Path $userSettings)) { $errors += 'user-settings.json not found' }
}

# --- Required: profile_user.ps1 ---
$userProfile = Join-Path (Split-Path $PROFILE) 'profile_user.ps1'
if (-not (Test-Path $userProfile)) { $errors += 'profile_user.ps1 not found' }

# --- OMP theme file in cache ---
$themeFiles = Get-ChildItem $cachePath -Filter '*.omp.json' -ErrorAction SilentlyContinue
if (-not $themeFiles) { $warnings += 'No OMP theme in cache (oh-my-posh may not be installed)' }
else { Write-Host "  OK    OMP theme: $($themeFiles[0].Name)" }

# --- Nerd Font installed ---
try {
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    $fc = New-Object System.Drawing.Text.InstalledFontCollection
    $nfMatch = @($fc.Families | Where-Object { $_.Name -match 'Caskaydia|NF|Nerd' })
    $fc.Dispose()
    if ($nfMatch.Count -eq 0) { $warnings += 'No Nerd Font detected' }
    else { Write-Host "  OK    Nerd Font: $($nfMatch[0].Name)" }
}
catch { $warnings += "Font check failed: $_" }

# --- PSFzf module ---
if (Get-Module -ListAvailable -Name PSFzf) { Write-Host '  OK    PSFzf module available' }
else { $warnings += 'PSFzf not installed' }

# --- Windows Terminal settings (if WT installed) ---
$wtPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
if (Test-Path $wtPath) {
    try {
        $wtRaw = Get-Content $wtPath -Raw
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $wtRaw = $wtRaw -replace $jsoncPattern, ''
        $wt = $wtRaw | ConvertFrom-Json
        if ($wt.profiles.defaults.font.face) { Write-Host "  OK    WT font: $($wt.profiles.defaults.font.face)" }
        else { $warnings += 'WT missing font.face in defaults' }
        if ($wt.profiles.defaults.colorScheme) { Write-Host "  OK    WT colorScheme: $($wt.profiles.defaults.colorScheme)" }
        else { $warnings += 'WT missing colorScheme in defaults' }
    }
    catch { $warnings += "WT parse failed: $_" }
}
else { Write-Host '  SKIP  Windows Terminal not found' }

# --- Tool strictness: fail if winget is available but zero tools found (skip in CI) ---
$hasWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
if ($toolsFound -eq 0 -and $toolsMissing -gt 0 -and $hasWinget -and -not $env:GITHUB_ACTIONS) {
    $errors += "All $toolsMissing managed tools missing (winget available - run setup.ps1 or Update-Profile to install)"
}

# --- Summary ---
Write-Host ""
Write-Host "  Tools: $toolsFound found, $toolsMissing missing (winget=$(if ($hasWinget) {'yes'} else {'no'}))"
if ($warnings) {
    foreach ($w in $warnings) { Write-Host "  WARN  $w" -ForegroundColor Yellow }
}
if ($errors) {
    foreach ($e in $errors) { Write-Host "  FAIL  $e" -ForegroundColor Red }
    exit 1
}
'@
    [System.IO.File]::WriteAllText($sandboxScript, $sandboxCode, $utf8NoBom)
    $ivOutput = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    foreach ($line in $ivOutput) {
        $color = if ($line -match '^\s+OK') { 'Green' } elseif ($line -match '^\s+FAIL') { 'Red' } elseif ($line -match '^\s+WARN') { 'Yellow' } elseif ($line -match '^\s+SKIP') { 'DarkGray' } else { 'White' }
        Write-Host "        $line" -ForegroundColor $color
    }
    if ($LASTEXITCODE -ne 0) { throw 'Required verification checks failed (see FAIL above)' }
    Write-Result 'Install verification' 'PASS'
}
catch { Write-Result 'Install verification' 'FAIL' $_.Exception.Message }
finally { Remove-Item $sandboxScript -Force -ErrorAction SilentlyContinue }

# -------------------------------------------------------
# 26. Command coverage audit (test.ps1 vs profile exports)
# -------------------------------------------------------
Write-Host '[26/26] Command coverage audit' -ForegroundColor Cyan
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

    # Internal helper functions that are intentionally not direct user commands
    $internalOnly = @(
        'Get-ExternalCommandPath'
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
        'Save-TrustedDirectories'
        'Read-UserSettingsForWrite'
        'Get-WindowsTerminalSettingsPath'
        'Push-TabTitle'
        'Pop-TabTitle'
        'Resolve-WslUncPath'
        'Initialize-RestartManagerType'
    )
    $commandFns = $allFns | Where-Object { $internalOnly -notcontains $_ }

    # Commands explicitly checked in step 17 existence list
    $existNames = @()
    $inExistBlock = $false
    foreach ($line in (Get-Content $MyInvocation.MyCommand.Path)) {
        if ($line.Contains('`$expected = @(')) { $inExistBlock = $true; continue }
        if ($inExistBlock -and $line -match "^\s*\)") { break }
        if ($inExistBlock) {
            foreach ($m in [regex]::Matches($line, "'([^']+)'")) {
                $existNames += $m.Groups[1].Value
            }
        }
    }

    # Commands actually executed in step 22 (T 'name' { ... } with a scriptblock)
    # vs commands skipped (T 'name' $null 'reason')
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

    # Allowed skip-only: commands that genuinely cannot be tested safely.
    # Update-Profile/Update-PowerShell/Update-Tools/Invoke-ProfileWizard/Reconfigure-Profile
    # are now probed via signature checks and safe early-exit paths.
    $allowedSkipOnly = @(
        'reload'             # reloads profile mid-test
        'Edit-Profile'       # opens editor UI
        'ep'                 # opens editor UI (alias)
        'edit'               # opens editor UI
        'Clear-ProfileCache' # destructive to real cache
        'Clear-Cache'        # destructive to real cache
        'Uninstall-Profile'  # tested in dedicated sandbox (steps 19/20/21)
        'gpush'              # no remote configured
        'gpull'              # no remote configured
        'gcl'                # network + clones repo
        'lazyg'              # no remote configured
        'g'                  # needs zoxide github dir
        'pkill'              # destructive - kills processes
        'Stop-StuckProcess'  # destructive - kills processes
        'Remove-LockedItem'  # destructive - kills + deletes
        'Stop-ListeningPort' # interactive fzf picker
        'killports'          # alias to Stop-ListeningPort
        'admin'              # opens elevated terminal
        'su'                 # opens elevated terminal (alias)
        'flushdns'           # requires admin
        'speedtest'          # takes 30s+ download
        'wifipass'           # requires admin/netsh
        'hosts'              # opens elevated editor
        'vtscan'             # needs API key
        'killport'           # destructive - kills process
        'watch'              # infinite loop
        'dlogs'              # needs running container
        'dex'                # needs running container
        'dstop'              # destructive
        'dprune'             # destructive
        'Copy-SshKey'        # needs remote host
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
        'Add-TrustedDirectory'    # persists to user-settings.json (tested in sandbox)
        'Remove-TrustedDirectory' # persists to user-settings.json (tested in sandbox)
        'Set-TerminalBackground'  # persists to user-settings.json + WT live (tested in sandbox)
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

    $execPct = if ($coveredNames.Count -gt 0) { [math]::Round(($testedNames.Count / $coveredNames.Count) * 100) } else { 0 }
    $detail = "functions=$($commandFns.Count), aliases=$($aliasNames.Count), executed=$($execActual.Count), skip-only=$($skipOnly.Count)/$($allowedSkipOnly.Count) allowed, exec%=$execPct"
    if ($skipOnly.Count -gt 0) {
        Write-Host "        Allowed skip-only ($($skipOnly.Count)): $($skipOnly -join ', ')" -ForegroundColor DarkGray
    }
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
