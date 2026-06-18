# RAW Bug Hunt - comprehensive profile test suite
# Exercises every profile function, install/uninstall, caching, and config merge
# Run: pwsh -NoProfile -File rawhunt.ps1
$ErrorActionPreference = 'Continue'

$ok = 0; $fail = 0; $bugs = @()
function T {
    param([string]$Name, [scriptblock]$Code)
    try {
        $null = & { $ErrorActionPreference = 'Stop'; & $Code } 2>&1
        Write-Host "  OK    $Name" -ForegroundColor Green
        $script:ok++
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'Timeout|timed out|HttpClient|Unable to connect|SocketException') {
            Write-Host "  NET   $Name  ($msg)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  BUG   $Name  ($msg)" -ForegroundColor Red
            $script:fail++
            $script:bugs += [PSCustomObject]@{ Command = $Name; Error = $msg }
        }
    }
}

function Test-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Code,
        [string]$Message = 'Expected command to throw'
    )

    $threw = $false
    try {
        & { $ErrorActionPreference = 'Stop'; & $Code } 2>&1 | Out-Null
    }
    catch {
        $threw = $true
    }

    if (-not $threw) { throw $Message }
}

Write-Host "`n==================== RAW Bug Hunt ====================" -ForegroundColor Cyan

# This script lives in tests/. repoRoot is the parent directory (where profile + setup.ps1 live).
$repoRoot = Split-Path -Parent $PSScriptRoot
$profilePath = Join-Path $repoRoot 'Microsoft.PowerShell_profile.ps1'
$setupPath = Join-Path $repoRoot 'setup.ps1'

# Load profile in CI mode (suppresses OMP/zoxide init, network calls)
$env:CI = 'true'
. $profilePath
Remove-Item env:CI

Write-Host "Profile loaded from: $repoRoot" -ForegroundColor DarkGray

# Extract nested Merge-JsonObject via AST (lives inside Update-Profile)
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$parseErrors)
$mergeFn = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Merge-JsonObject'
}, $true) | Select-Object -First 1
if ($mergeFn) { . ([scriptblock]::Create($mergeFn.Extent.Text)) }

# Extract setup.ps1 functions via AST
$tokens2 = $null; $parseErrors2 = $null
$setupAst = [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$tokens2, [ref]$parseErrors2)
$setupFns = $setupAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($fn in $setupFns) { . ([scriptblock]::Create($fn.Extent.Text)) }
$varDefs = $setupAst.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $args[0].Left.Extent.Text -eq '$EditorCandidates'
}, $true)
if ($varDefs.Count -gt 0) { . ([scriptblock]::Create($varDefs[0].Extent.Text)) }

# Workspace
$ws = Join-Path $env:TEMP "psp-raw-$([System.IO.Path]::GetRandomFileName())"
New-Item -ItemType Directory -Path $ws -Force | Out-Null
$origDir = Get-Location

# #####################################################################
#  PART 1: UTILITY FUNCTIONS
# #####################################################################

# --- File Operations ---
Write-Host "`n--- File Operations ---" -ForegroundColor Magenta

$tf = Join-Path $ws "testfile.txt"
"hello world" | Set-Content $tf
$jf = Join-Path $ws "test.json"
'{"key":"value","nested":{"a":1}}' | Set-Content $jf

T 'touch (new file)' {
    $f = Join-Path $ws "touchtest.txt"
    touch $f
    if (-not (Test-Path $f)) { throw "file not created" }
}

T 'touch (update timestamp)' {
    $f = Join-Path $ws "touchtest.txt"
    $before = (Get-Item $f).LastWriteTime
    Start-Sleep -Milliseconds 100
    touch $f
    $after = (Get-Item $f).LastWriteTime
    if ($after -le $before) { throw "timestamp not updated" }
}

T 'nf (alias for touch)' {
    $f = Join-Path $ws "nftest.txt"
    nf $f
    if (-not (Test-Path $f)) { throw "file not created" }
}

T 'ff (find files)' {
    Set-Location $ws
    $r = ff "testfile"
    if (-not $r) { throw "no results" }
    Set-Location $origDir
}

T 'mkcd' {
    $d = Join-Path $ws "mkcdtest"
    mkcd $d
    if ((Get-Location).Path -ne $d) { throw "not in expected dir: $(Get-Location)" }
    Set-Location $origDir
}

T 'head' {
    $r = head $tf 5
    if (-not $r) { throw "no output" }
}

T 'tail' {
    $r = tail $tf 5
    if (-not $r) { throw "no output" }
}

T 'sed' {
    $sf = Join-Path $ws "sedtest.txt"
    "foo bar baz" | Set-Content $sf
    sed $sf "bar" "qux"
    $c = Get-Content $sf -Raw
    if ($c -notmatch "qux") { throw "replace failed: $c" }
}

T 'which (pwsh)' {
    $r = which pwsh
    if (-not $r) { throw "no output" }
}

T 'which (nonexistent)' {
    Test-Throws { which "zzz_nonexistent_cmd_zzz" } "which should fail for a nonexistent command"
}

T 'file (text)' { file $tf }
T 'file (json)' { file $jf }
T 'file (binary/exe)' { file "$env:SystemRoot\System32\cmd.exe" }
T 'file (directory)' { file $ws }

T 'sizeof (file)' {
    $r = sizeof $tf
    if (-not $r) { throw "no output" }
}

T 'sizeof (directory)' {
    $r = sizeof $ws
    if (-not $r) { throw "no output" }
}

T 'export' {
    export "PSP_RAW_TEST" "testval"
    if ($env:PSP_RAW_TEST -ne "testval") { throw "env var not set" }
    Remove-Item env:PSP_RAW_TEST -ErrorAction SilentlyContinue
}

T 'bak' {
    bak $tf
    $baks = Get-ChildItem $ws -Filter "testfile.txt.*.bak"
    if ($baks.Count -eq 0) { throw "no backup created" }
}

T 'extract (.zip)' {
    $zipDir = Join-Path $ws "ziptest"
    New-Item -ItemType Directory $zipDir -Force | Out-Null
    $zipSrc = Join-Path $zipDir "content.txt"
    "zip content" | Set-Content $zipSrc
    $zipPath = Join-Path $ws "test.zip"
    Compress-Archive -Path $zipSrc -DestinationPath $zipPath -Force
    $extractDir = Join-Path $ws "extracted"
    New-Item -ItemType Directory $extractDir -Force | Out-Null
    Set-Location $extractDir
    extract $zipPath
    $extracted = Get-ChildItem $extractDir -Recurse -File
    if ($extracted.Count -eq 0) { throw "nothing extracted" }
    Set-Location $origDir
}

T 'trash' {
    $trashFile = Join-Path $ws "trashme.txt"
    "delete me" | Set-Content $trashFile
    trash $trashFile
    Start-Sleep -Milliseconds 500
    if (Test-Path $trashFile) { throw "file not moved to recycle bin" }
}

# --- Navigation ---
Write-Host "`n--- Navigation ---" -ForegroundColor Magenta

T 'docs' {
    $before = Get-Location
    docs
    $after = Get-Location
    Set-Location $before
    if ($after.Path -notmatch 'Documents') { throw "not in Documents: $after" }
}

T 'dtop' {
    $before = Get-Location
    dtop
    $after = Get-Location
    Set-Location $before
    if ($after.Path -notmatch 'Desktop') { throw "not in Desktop: $after" }
}

# --- Listing (eza/bat) ---
Write-Host "`n--- Listing ---" -ForegroundColor Magenta

T 'ls' { & (Get-Command 'ls').Name $ws }
T 'la' { la $ws }
T 'll' { ll $ws }
T 'lt' { lt $ws }
T 'cat' { & (Get-Command 'cat').Name $tf }
T 'grep (in file)' {
    Set-Location $ws
    grep "hello" $ws
    Set-Location $origDir
}

# --- System ---
Write-Host "`n--- System ---" -ForegroundColor Magenta

T 'uptime' { & (Get-Command 'uptime').Name }
T 'df' { df }
T 'path' { $r = path; if (-not $r) { throw "no output" } }
T 'env (no filter)' { env }
T 'env (filter)' { env "PATH" }
T 'svc (snapshot)' { svc -Count 5 }
T 'sysinfo' { sysinfo }
T 'eventlog' { & (Get-Command 'eventlog').Name 5 }
T 'pgrep' { $r = pgrep "pwsh"; if (-not $r) { throw "no pwsh process found" } }
T 'ports' { ports }

# --- Network ---
Write-Host "`n--- Network ---" -ForegroundColor Magenta

T 'pubip' { $r = pubip; if (-not $r -or $r.Trim().Length -lt 5) { throw "invalid IP: $r" } }
T 'localip' { localip }
T 'checkport (open)' { checkport "google.com" 443 }
T 'checkport (closed)' { checkport "localhost" 59999 }
T 'nslook (A)' { nslook "google.com" }
T 'nslook (MX)' { nslook "google.com" "MX" }
T 'nslook (TXT)' { nslook "google.com" "TXT" }
T 'tlscert' { tlscert "google.com" }
T 'portscan' { portscan "localhost" -Ports @(80, 443, 3389) }
T 'ipinfo' { ipinfo "8.8.8.8" }
T 'whois' { whois "google.com" }
T 'weather' { weather "Oslo" }
T 'http GET' { $r = http "https://httpbin.org/get"; if (-not $r) { throw "no response" } }
T 'http POST' { $r = http "https://httpbin.org/post" -Method POST -Body '{"test":true}'; if (-not $r) { throw "no response" } }
T 'hb' { hb $tf }

# --- Crypto & Encoding ---
Write-Host "`n--- Crypto & Encoding ---" -ForegroundColor Magenta

T 'hash (SHA256)' {
    $r = hash $tf
    if (-not $r -or $r.Length -ne 64) { throw "invalid hash: $r" }
}

T 'hash (SHA512)' {
    $r = hash $tf -Algorithm SHA512
    if (-not $r -or $r.Length -ne 128) { throw "invalid hash: $r" }
}

T 'checksum (match)' {
    $expected = hash $tf
    checksum $tf $expected
}

T 'checksum (mismatch)' {
    checksum $tf "0000000000000000000000000000000000000000000000000000000000000000"
}

T 'genpass (default)' {
    $r = genpass
    if (-not $r -or $r.Length -ne 20) { throw "invalid password length: $($r.Length)" }
}

T 'genpass (custom length)' {
    $r = genpass 50
    if (-not $r -or $r.Length -ne 50) { throw "invalid password length: $($r.Length)" }
}

T 'b64 encode' {
    $r = b64 "hello world"
    if ($r -ne "aGVsbG8gd29ybGQ=") { throw "wrong encoding: $r" }
}

T 'b64d decode' {
    $r = b64d "aGVsbG8gd29ybGQ="
    if ($r -ne "hello world") { throw "wrong decoding: $r" }
}

T 'b64d (invalid)' {
    Test-Throws { b64d "not_valid_base64!!!" } "b64d should fail on invalid base64"
}

T 'jwtd' {
    jwtd "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}

T 'uuid' {
    uuid
    $clip = Get-Clipboard
    if (-not $clip -or $clip.Length -lt 30) { throw "uuid not on clipboard" }
}

T 'epoch (now)' {
    $r = epoch
    if (-not $r -or $r -lt 1000000000) { throw "invalid epoch: $r" }
}

T 'epoch (from timestamp)' {
    $r = epoch 0
    if (-not $r) { throw "no output" }
    if ($r.Year -ne 1970) { throw "wrong year: $($r.Year)" }
}

T 'epoch (from date string)' {
    $r = epoch "2000-01-01"
    if (-not $r -or $r -lt 946000000) { throw "invalid epoch from date: $r" }
}

T 'epoch (milliseconds)' {
    $r = epoch 1516239022000
    if (-not $r) { throw "no output" }
    if ($r.Year -ne 2018) { throw "wrong year for ms epoch: $($r.Year)" }
}

T 'urlencode' {
    $r = urlencode "hello world&foo=bar"
    if ($r -ne "hello%20world%26foo%3Dbar") { throw "wrong encoding: $r" }
}

T 'urldecode' {
    $r = urldecode "hello%20world%26foo%3Dbar"
    if ($r -ne "hello world&foo=bar") { throw "wrong decoding: $r" }
}

# --- Developer ---
Write-Host "`n--- Developer ---" -ForegroundColor Magenta

T 'prettyjson (file)' {
    $r = prettyjson $jf
    if (-not $r) { throw "no output" }
}

T 'prettyjson (invalid json)' {
    $badjson = Join-Path $ws "bad.json"
    "not json {{{" | Set-Content $badjson
    Test-Throws { prettyjson $badjson } "prettyjson should fail on invalid JSON"
}

T 'timer' {
    timer { Start-Sleep -Milliseconds 50 }
}

# --- Git (temp repo) ---
Write-Host "`n--- Git ---" -ForegroundColor Magenta

$gitDir = Join-Path $ws "gitrepo"
New-Item -ItemType Directory $gitDir -Force | Out-Null
Set-Location $gitDir
git init 2>&1 | Out-Null
git config user.email "test@test.com" 2>&1 | Out-Null
git config user.name "Test" 2>&1 | Out-Null
"initial" | Set-Content (Join-Path $gitDir "readme.md")
git add . 2>&1 | Out-Null
git commit -m "init" 2>&1 | Out-Null

T 'gs' { gs }

T 'ga' {
    "change" | Set-Content (Join-Path $gitDir "newfile.txt")
    ga
    $status = git status --porcelain 2>&1
    if ($status -match '^\?\?') { throw "unstaged files remain" }
}

T 'gc (commit)' {
    & (Get-Command 'gc' -CommandType Function).Name "test commit message"
    $log = git log --oneline -1 2>&1
    if ($log -notmatch "test commit") { throw "commit not found: $log" }
}

T 'gcom' {
    "another" | Set-Content (Join-Path $gitDir "another.txt")
    gcom "gcom test"
    $log = git log --oneline -1 2>&1
    if ($log -notmatch "gcom test") { throw "gcom commit not found: $log" }
}

Set-Location $origDir

# --- Clipboard ---
Write-Host "`n--- Clipboard ---" -ForegroundColor Magenta

T 'cpy' {
    cpy "raw-test-clipboard-value"
}

T 'pst' {
    $r = pst
    if ($r -ne "raw-test-clipboard-value") { throw "clipboard mismatch: expected 'raw-test-clipboard-value', got '$r'" }
}

# --- Docker (if available) ---
$hasDocker = [bool](Get-Command docker -ErrorAction SilentlyContinue)
$dockerRunning = $false
if ($hasDocker) { $null = docker info 2>&1; $dockerRunning = ($LASTEXITCODE -eq 0) }
if ($dockerRunning) {
    Write-Host "`n--- Docker ---" -ForegroundColor Magenta
    T 'dps' { dps }
    T 'dpa' { dpa }
    T 'dimg' { dimg }
}

# #####################################################################
#  PART 2: CACHING
# #####################################################################
Write-Host "`n--- Caching: OMP & zoxide init ---" -ForegroundColor Magenta

$realCacheDir = Join-Path $env:LOCALAPPDATA 'PowerShellProfile'

T 'Cache dir exists' {
    if (-not (Test-Path $realCacheDir)) { throw "Cache dir missing: $realCacheDir" }
}

T 'theme.json cached' {
    $f = Join-Path $realCacheDir 'theme.json'
    if (-not (Test-Path $f)) { throw "theme.json not in cache" }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if (-not $j.theme.name) { throw "theme.name missing" }
    if (-not $j.theme.url) { throw "theme.url missing" }
}

T 'terminal-config.json cached' {
    $f = Join-Path $realCacheDir 'terminal-config.json'
    if (-not (Test-Path $f)) { throw "terminal-config.json not in cache" }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if (-not $j.defaults) { throw "defaults missing" }
    if (-not $j.fontInstall) { throw "fontInstall missing" }
}

T 'user-settings.json exists' {
    $f = Join-Path $realCacheDir 'user-settings.json'
    if (-not (Test-Path $f)) { throw "user-settings.json not found" }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if (-not $j._comment) { throw "template _comment missing" }
}

T 'OMP theme file in cache' {
    $themes = Get-ChildItem $realCacheDir -Filter '*.omp.json' -ErrorAction SilentlyContinue
    if (-not $themes -or $themes.Count -eq 0) { throw "No OMP theme file in cache" }
    $j = Get-Content $themes[0].FullName -Raw | ConvertFrom-Json
    if (-not $j) { throw "Theme file is not valid JSON" }
}

T 'OMP init cache format' {
    $f = Join-Path $realCacheDir 'omp-init.ps1'
    if (-not (Test-Path $f)) { throw "omp-init.ps1 not in cache" }
    $size = (Get-Item $f).Length
    if ($size -eq 0) { throw "omp-init.ps1 is 0 bytes (corrupt)" }
    $header = Get-Content $f -First 1
    if ($header -notmatch '^# OMP_CACHE:') { throw "Invalid header: $header" }
    if ($header -notmatch '\|') { throw "Header missing pipe separator (no theme path): $header" }
}

T 'zoxide init cache format' {
    $f = Join-Path $realCacheDir 'zoxide-init.ps1'
    if (-not (Test-Path $f)) { throw "zoxide-init.ps1 not in cache" }
    $size = (Get-Item $f).Length
    if ($size -eq 0) { throw "zoxide-init.ps1 is 0 bytes (corrupt)" }
    $header = Get-Content $f -First 1
    if ($header -notmatch '^# ZOXIDE_CACHE_VERSION:') { throw "Invalid header: $header" }
}

# --- Cache corruption recovery ---
Write-Host "`n--- Cache corruption recovery ---" -ForegroundColor Magenta

T 'OMP cache: 0-byte recovery' {
    $f = Join-Path $ws 'omp-init.ps1'
    New-Item $f -ItemType File -Force | Out-Null
    $size = (Get-Item $f).Length
    if ($size -ne 0) { throw "Setup failed - file not 0 bytes" }
    $fileSize = (Get-Item $f).Length
    $cacheValid = $false
    if ($fileSize -gt 0) {
        $cacheContent = Get-Content $f -First 1
        if ($cacheContent -eq '# OMP_CACHE: test | test') { $cacheValid = $true }
    }
    if ($cacheValid) { throw "0-byte file was treated as valid cache" }
}

T 'OMP cache: wrong version invalidation' {
    $f = Join-Path $ws 'omp-init.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($f, "# OMP_CACHE: old_version | old_path`nWrite-Host test", $utf8)
    $header = Get-Content $f -First 1
    $expected = '# OMP_CACHE: current_version | current_path'
    $cacheValid = ($header -eq $expected)
    if ($cacheValid) { throw "Wrong version was accepted as valid" }
}

T 'zoxide cache: wrong version invalidation' {
    $f = Join-Path $ws 'zoxide-init.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($f, "# ZOXIDE_CACHE_VERSION: old_ver`nWrite-Host test", $utf8)
    $header = Get-Content $f -First 1
    $expected = '# ZOXIDE_CACHE_VERSION: current_ver'
    $cacheValid = ($header -eq $expected)
    if ($cacheValid) { throw "Wrong version was accepted as valid" }
}

T 'Corrupt JSON config recovery' {
    $f = Join-Path $ws 'theme.json'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($f, "{ this is not valid json !!!", $utf8)
    $recovered = $false
    try {
        $null = Get-Content $f -Raw | ConvertFrom-Json
    }
    catch {
        Remove-Item $f -Force -ErrorAction SilentlyContinue
        $recovered = $true
    }
    if (-not $recovered) { throw "Corrupt JSON was not caught" }
}

# #####################################################################
#  PART 3: CONFIG MERGE
# #####################################################################
Write-Host "`n--- Config merge (Merge-JsonObject) ---" -ForegroundColor Magenta

T 'Merge-JsonObject: flat override' {
    $base = [PSCustomObject]@{ a = 1; b = 2 }
    Merge-JsonObject $base ([PSCustomObject]@{ b = 99; c = 3 })
    if ($base.a -ne 1) { throw "a changed: $($base.a)" }
    if ($base.b -ne 99) { throw "b not overridden: $($base.b)" }
    if ($base.c -ne 3) { throw "c not added: $($base.c)" }
}

T 'Merge-JsonObject: deep nested' {
    $base = [PSCustomObject]@{ font = [PSCustomObject]@{ face = 'Consolas'; size = 11 }; opacity = 75 }
    Merge-JsonObject $base ([PSCustomObject]@{ font = [PSCustomObject]@{ size = 14 } })
    if ($base.font.face -ne 'Consolas') { throw "face lost: $($base.font.face)" }
    if ($base.font.size -ne 14) { throw "size not overridden: $($base.font.size)" }
    if ($base.opacity -ne 75) { throw "opacity changed: $($base.opacity)" }
}

T 'Merge-JsonObject: replace scalar with object' {
    $base = [PSCustomObject]@{ theme = 'simple' }
    Merge-JsonObject $base ([PSCustomObject]@{ theme = [PSCustomObject]@{ name = 'pure' } })
    if ($base.theme.name -ne 'pure') { throw "replacement failed" }
}

T 'Merge-JsonObject: add to empty base' {
    $base = [PSCustomObject]@{}
    Merge-JsonObject $base ([PSCustomObject]@{ a = 1; b = [PSCustomObject]@{ x = 10 } })
    if ($base.a -ne 1) { throw "a not added" }
    if ($base.b.x -ne 10) { throw "nested not added" }
}

T 'Merge-JsonObject: null base property' {
    $base = [PSCustomObject]@{ a = 1 }
    Merge-JsonObject $base ([PSCustomObject]@{ b = [PSCustomObject]@{ x = 1 } })
    if ($base.b.x -ne 1) { throw "merge into missing property failed" }
}

T 'Config merge precedence: terminal-config < user-settings < theme' {
    $terminalConfig = '{"defaults":{"opacity":75,"font":{"face":"CaskaydiaCove NF","size":11}}}' | ConvertFrom-Json
    $userSettings = '{"defaults":{"opacity":90,"font":{"size":14}}}' | ConvertFrom-Json
    Merge-JsonObject $terminalConfig.defaults $userSettings.defaults
    if ($terminalConfig.defaults.opacity -ne 90) { throw "user opacity not applied: $($terminalConfig.defaults.opacity)" }
    if ($terminalConfig.defaults.font.size -ne 14) { throw "user font size not applied: $($terminalConfig.defaults.font.size)" }
    if ($terminalConfig.defaults.font.face -ne 'CaskaydiaCove NF') { throw "font face lost: $($terminalConfig.defaults.font.face)" }
}

T 'Config merge: keybindings append (not replace)' {
    $terminalConfig = '{"keybindings":[{"keys":"ctrl+a","command":"selectAll"}]}' | ConvertFrom-Json
    $userSettings = '{"keybindings":[{"keys":"ctrl+b","command":"copy"}]}' | ConvertFrom-Json
    $terminalConfig.keybindings = @($terminalConfig.keybindings) + @($userSettings.keybindings)
    if ($terminalConfig.keybindings.Count -ne 2) { throw "expected 2 keybindings, got $($terminalConfig.keybindings.Count)" }
    if ($terminalConfig.keybindings[0].keys -ne 'ctrl+a') { throw "original lost" }
    if ($terminalConfig.keybindings[1].keys -ne 'ctrl+b') { throw "user binding not appended" }
}

# #####################################################################
#  PART 4: WINDOWS TERMINAL SETTINGS
# #####################################################################
Write-Host "`n--- Windows Terminal settings ---" -ForegroundColor Magenta

$wtSettingsPath = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
$hasWT = Test-Path $wtSettingsPath

if ($hasWT) {
    T 'WT settings: can parse real file' {
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $raw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncPattern, ''
        $wt = $raw | ConvertFrom-Json
        if (-not $wt.profiles) { throw "profiles missing" }
    }

    T 'WT settings: backups exist' {
        $wtDir = Split-Path $wtSettingsPath
        $baks = Get-ChildItem $wtDir -Filter 'settings.json.*.bak' -ErrorAction SilentlyContinue
        if (-not $baks -or $baks.Count -eq 0) { throw "No WT backups found" }
    }

    T 'WT settings: backup count <= 5' {
        $wtDir = Split-Path $wtSettingsPath
        $baks = Get-ChildItem $wtDir -Filter 'settings.json.*.bak' -ErrorAction SilentlyContinue
        if ($baks.Count -gt 5) { throw "Too many backups: $($baks.Count) (max 5)" }
    }

    T 'WT settings: defaults have expected keys' {
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $raw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncPattern, ''
        $wt = $raw | ConvertFrom-Json
        $d = $wt.profiles.defaults
        if (-not $d) { throw "profiles.defaults missing" }
        if (-not $d.font) { throw "font missing" }
        if (-not $d.font.face) { throw "font.face missing" }
        if ($null -eq $d.opacity) { throw "opacity missing" }
        if (-not $d.colorScheme) { throw "colorScheme missing" }
    }

    T 'WT settings: color scheme installed' {
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $raw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncPattern, ''
        $wt = $raw | ConvertFrom-Json
        $schemeName = $wt.profiles.defaults.colorScheme
        if (-not $schemeName) { throw "no colorScheme set" }
        $scheme = $wt.schemes | Where-Object { $_.name -eq $schemeName }
        if (-not $scheme) { throw "Scheme '$schemeName' not in schemes array" }
    }

    T 'WT settings: keybinding upsert format' {
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $raw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncPattern, ''
        $wt = $raw | ConvertFrom-Json
        $hasNewFormat = $null -ne $wt.PSObject.Properties['keybindings']
        if ($hasNewFormat) {
            $kb = $wt.keybindings | Where-Object { $_.keys -eq 'ctrl+a' }
            if (-not $kb) { throw "ctrl+a not in keybindings array" }
            if (-not $kb.id) { throw "keybinding missing id" }
            $action = $wt.actions | Where-Object { $_.id -eq $kb.id }
            if (-not $action) { throw "No action for id '$($kb.id)'" }
        } else {
            $action = $wt.actions | Where-Object { $_.keys -eq 'ctrl+a' }
            if (-not $action) { throw "ctrl+a not in actions (old format)" }
        }
    }

    T 'WT settings: -NoLogo on PowerShell profiles' {
        $_q = [char]34
        $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
        $raw = (Get-Content $wtSettingsPath -Raw) -replace $jsoncPattern, ''
        $wt = $raw | ConvertFrom-Json
        if ($wt.profiles.list) {
            $pwshProfiles = @($wt.profiles.list | Where-Object {
                $cmd = if ($_.commandline) { $_.commandline } else { '' }
                $src = if ($_.source) { $_.source } else { '' }
                ($cmd -match 'pwsh' -or $src -match 'PowerShellCore' -or $cmd -match 'powershell\.exe' -or $_.name -match 'Windows PowerShell')
            })
            foreach ($p in $pwshProfiles) {
                $cmd = if ($p.commandline) { $p.commandline } else { '' }
                if ($cmd -match '(?i)-(Command|File|EncodedCommand)') { continue }
                if ($cmd -and $cmd -notmatch '-NoLogo') {
                    throw "Profile '$($p.name)' missing -NoLogo: $cmd"
                }
            }
        }
    }

    T 'WT merge: sandbox roundtrip' {
        $mockWt = [PSCustomObject]@{
            profiles = [PSCustomObject]@{
                defaults = [PSCustomObject]@{ font = [PSCustomObject]@{ face = 'Consolas'; size = 10 } }
                list = @()
            }
            schemes = @()
            actions = @()
        }
        $theme = Get-Content (Join-Path $repoRoot 'theme.json') -Raw | ConvertFrom-Json
        $tc = Get-Content (Join-Path $repoRoot 'terminal-config.json') -Raw | ConvertFrom-Json
        $d = $mockWt.profiles.defaults
        $tc.defaults.PSObject.Properties | ForEach-Object {
            $d | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
        }
        if ($theme.windowsTerminal.colorScheme) {
            $d | Add-Member -NotePropertyName 'colorScheme' -NotePropertyValue $theme.windowsTerminal.colorScheme -Force
        }
        $schemeDef = $theme.windowsTerminal.scheme
        $mockWt.schemes = @(@($mockWt.schemes | Where-Object { $_ -and $_.name -ne $schemeDef.name }) + ([PSCustomObject]$schemeDef))
        foreach ($kb in $tc.keybindings) {
            $mockWt.actions = @($mockWt.actions | Where-Object { $_ -and $_.keys -ne $kb.keys })
            $mockWt.actions = @($mockWt.actions) + ([PSCustomObject]@{ keys = $kb.keys; command = $kb.command })
        }
        $json = $mockWt | ConvertTo-Json -Depth 100
        $parsed = $json | ConvertFrom-Json
        if ($parsed.profiles.defaults.font.face -ne 'CaskaydiaCove NF') { throw "font.face wrong" }
        if ($parsed.profiles.defaults.opacity -ne 75) { throw "opacity wrong" }
        if ($parsed.profiles.defaults.colorScheme -ne 'Tokyo Night') { throw "colorScheme wrong" }
        if ($parsed.schemes.Count -ne 1) { throw "expected 1 scheme" }
        if ($parsed.schemes[0].name -ne 'Tokyo Night') { throw "scheme name wrong" }
    }
} else {
    Write-Host "  SKIP  Windows Terminal not installed" -ForegroundColor DarkGray
}

# #####################################################################
#  PART 5: SETUP.PS1 FUNCTIONS
# #####################################################################
Write-Host "`n--- setup.ps1 functions ---" -ForegroundColor Magenta

T 'setup.ps1 parses without errors' {
    if ($parseErrors2.Count -gt 0) { throw "$($parseErrors2.Count) parse error(s)" }
}

T 'Test-InternetConnection' {
    $r = Test-InternetConnection
    if ($r -ne $true) { throw "Expected true, got $r" }
}

T 'Invoke-DownloadWithRetry (real download)' {
    $tmp = Join-Path $ws 'dl-test.json'
    Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/theme.json' -OutFile $tmp
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) { throw 'download empty' }
    $j = Get-Content $tmp -Raw | ConvertFrom-Json
    if (-not $j.theme.name) { throw "downloaded theme.json has no theme.name" }
}

T 'Invoke-DownloadWithRetry (bad URL fails)' {
    $tmp = Join-Path $ws 'bad-dl.json'
    Test-Throws {
        Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/26zl/PowerShellPerfect/main/NONEXISTENT.json' -OutFile $tmp -MaxAttempts 1
    } "Invoke-DownloadWithRetry should fail on 404"
    if (Test-Path $tmp) { throw "Corrupt file not cleaned up" }
}

T 'Install-WingetPackage (already installed)' {
    $r = Install-WingetPackage -Name 'PowerShell' -Id 'Microsoft.PowerShell'
    if ($r -ne $true) { throw "Expected true, got $r" }
}

T 'Install-NerdFonts (detection only)' {
    $r = Install-NerdFonts
    if ($r -ne $true) { throw "Expected true, got $r" }
}

T 'Install-OhMyPoshTheme (real download)' {
    $tmpCache = Join-Path $ws 'omp-cache'
    New-Item -ItemType Directory $tmpCache -Force | Out-Null
    $origConfigCache = $configCachePath
    $script:configCachePath = $tmpCache
    try {
        $r = Install-OhMyPoshTheme -ThemeName 'test-theme' -ThemeUrl 'https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/agnoster.omp.json'
        if ($r -ne $true) { throw "Expected true, got $r" }
        $themeFile = Join-Path $tmpCache 'test-theme.omp.json'
        if (-not (Test-Path $themeFile)) { throw "Theme file not written" }
        $j = Get-Content $themeFile -Raw | ConvertFrom-Json
        if (-not $j) { throw "Theme file not valid JSON" }
    }
    finally { $script:configCachePath = $origConfigCache }
}

T 'EditorCandidates valid' {
    if (-not $EditorCandidates -or $EditorCandidates.Count -lt 5) { throw "Only $($EditorCandidates.Count) candidates" }
    foreach ($ed in $EditorCandidates) {
        if (-not $ed.Cmd -or -not $ed.Display) { throw "Invalid: $($ed | ConvertTo-Json -Compress)" }
    }
}

T 'Merge-JsonObject from setup.ps1' {
    $b = [PSCustomObject]@{ x = 1; n = [PSCustomObject]@{ a = 10 } }
    Merge-JsonObject $b ([PSCustomObject]@{ x = 99; n = [PSCustomObject]@{ b = 20 } })
    if ($b.x -ne 99 -or $b.n.a -ne 10 -or $b.n.b -ne 20) { throw "merge mismatch" }
}

# #####################################################################
#  PART 6: UNINSTALL-PROFILE
# #####################################################################
Write-Host "`n--- Uninstall-Profile (-WhatIf) ---" -ForegroundColor Magenta

T 'Uninstall-Profile -WhatIf (no changes)' {
    $before = @{ Profile = Test-Path $PROFILE; Cache = Test-Path $realCacheDir }
    Uninstall-Profile -WhatIf -Confirm:$false
    $after = @{ Profile = Test-Path $PROFILE; Cache = Test-Path $realCacheDir }
    if ($before.Profile -ne $after.Profile) { throw "Profile changed during -WhatIf!" }
    if ($before.Cache -ne $after.Cache) { throw "Cache changed during -WhatIf!" }
}

T 'Uninstall-Profile -All -WhatIf (no changes)' {
    $before = @{ Profile = Test-Path $PROFILE; Cache = Test-Path $realCacheDir }
    Uninstall-Profile -All -WhatIf -Confirm:$false
    $after = @{ Profile = Test-Path $PROFILE; Cache = Test-Path $realCacheDir }
    if ($before.Profile -ne $after.Profile) { throw "Profile changed during -All -WhatIf!" }
    if ($before.Cache -ne $after.Cache) { throw "Cache changed during -All -WhatIf!" }
}

Write-Host "`n--- Uninstall sandbox (isolated) ---" -ForegroundColor Magenta

T 'Uninstall sandbox: core cleanup' {
    $sandboxScript = Join-Path $ws 'uninstall-sandbox.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $code = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

$sb = Join-Path $env:TEMP "psp-uninst-$([System.IO.Path]::GetRandomFileName())"
$docsRoot = Join-Path $sb 'Documents'
$cacheDir = Join-Path $sb 'PowerShellProfile'
$ps7Dir = Join-Path $docsRoot 'PowerShell'
$ps5Dir = Join-Path $docsRoot 'WindowsPowerShell'
New-Item -ItemType Directory -Path $cacheDir, $ps7Dir, $ps5Dir -Force | Out-Null

$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'theme.json'), '{"theme":{"name":"test"}}', $utf8)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'terminal-config.json'), '{"defaults":{}}', $utf8)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'omp-init.ps1'), '# cache', $utf8)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'zoxide-init.ps1'), '# cache', $utf8)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'test.omp.json'), '{}', $utf8)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'user-settings.json'), '{"_comment":"test"}', $utf8)
Copy-Item $ProfileSource (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')
Copy-Item $ProfileSource (Join-Path $ps5Dir 'Microsoft.PowerShell_profile.ps1')
[System.IO.File]::WriteAllText((Join-Path $ps7Dir 'profile_user.ps1'), '# user', $utf8)
[System.IO.File]::WriteAllText((Join-Path $ps5Dir 'profile_user.ps1'), '# user', $utf8)

$origLocal = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = $sb
$global:PROFILE = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$env:CI = 'true'
. $ProfileSource
Remove-Item env:CI

try {
    Uninstall-Profile -Confirm:$false

    $errors = @()
    if (Test-Path (Join-Path $cacheDir 'theme.json')) { $errors += 'theme.json not removed' }
    if (Test-Path (Join-Path $cacheDir 'omp-init.ps1')) { $errors += 'omp-init.ps1 not removed' }
    if (Test-Path (Join-Path $cacheDir 'zoxide-init.ps1')) { $errors += 'zoxide-init.ps1 not removed' }
    if (Test-Path (Join-Path $cacheDir 'test.omp.json')) { $errors += 'test.omp.json not removed' }
    if (-not (Test-Path (Join-Path $cacheDir 'user-settings.json'))) { $errors += 'user-settings.json removed without -RemoveUserData!' }
    if (Test-Path (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')) { $errors += 'PS7 profile not removed' }
    if (Test-Path (Join-Path $ps5Dir 'Microsoft.PowerShell_profile.ps1')) { $errors += 'PS5 profile not removed' }
    if (-not (Test-Path (Join-Path $ps7Dir 'profile_user.ps1'))) { $errors += 'PS7 profile_user.ps1 removed without -RemoveUserData!' }
    if (-not (Test-Path (Join-Path $ps5Dir 'profile_user.ps1'))) { $errors += 'PS5 profile_user.ps1 removed without -RemoveUserData!' }

    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { Write-Host "  ASSERT: $e" -ForegroundColor Red }
        exit 1
    }
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}
'@
    [System.IO.File]::WriteAllText($sandboxScript, $code, $utf8)
    $output = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    foreach ($line in $output) {
        if ($line -match 'ASSERT:') { Write-Host "        $line" -ForegroundColor Red }
    }
    if ($LASTEXITCODE -ne 0) {
        $asserts = @($output | Where-Object { $_ -match 'ASSERT:' })
        throw "Uninstall sandbox failed: $($asserts -join '; ')"
    }
}

T 'Uninstall sandbox: -RemoveUserData' {
    $sandboxScript = Join-Path $ws 'uninstall-userdata.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $code = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

$sb = Join-Path $env:TEMP "psp-uninst2-$([System.IO.Path]::GetRandomFileName())"
$docsRoot = Join-Path $sb 'Documents'
$cacheDir = Join-Path $sb 'PowerShellProfile'
$ps7Dir = Join-Path $docsRoot 'PowerShell'
$ps5Dir = Join-Path $docsRoot 'WindowsPowerShell'
New-Item -ItemType Directory -Path $cacheDir, $ps7Dir, $ps5Dir -Force | Out-Null

$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $cacheDir 'user-settings.json'), '{"_comment":"test"}', $utf8)
Copy-Item $ProfileSource (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')
[System.IO.File]::WriteAllText((Join-Path $ps7Dir 'profile_user.ps1'), '# user', $utf8)
[System.IO.File]::WriteAllText((Join-Path $ps5Dir 'profile_user.ps1'), '# user', $utf8)

$origLocal = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = $sb
$global:PROFILE = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$env:CI = 'true'
. $ProfileSource
Remove-Item env:CI

try {
    Uninstall-Profile -RemoveUserData -Confirm:$false

    $errors = @()
    if (Test-Path (Join-Path $cacheDir 'user-settings.json')) { $errors += 'user-settings.json not removed' }
    if (Test-Path (Join-Path $ps7Dir 'profile_user.ps1')) { $errors += 'PS7 profile_user.ps1 not removed' }
    if (Test-Path (Join-Path $ps5Dir 'profile_user.ps1')) { $errors += 'PS5 profile_user.ps1 not removed' }

    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { Write-Host "  ASSERT: $e" -ForegroundColor Red }
        exit 1
    }
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}
'@
    [System.IO.File]::WriteAllText($sandboxScript, $code, $utf8)
    $output = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    foreach ($line in $output) {
        if ($line -match 'ASSERT:') { Write-Host "        $line" -ForegroundColor Red }
    }
    if ($LASTEXITCODE -ne 0) {
        $asserts = @($output | Where-Object { $_ -match 'ASSERT:' })
        throw "-RemoveUserData sandbox failed: $($asserts -join '; ')"
    }
}

T 'Uninstall sandbox: WT backup restore' {
    $sandboxScript = Join-Path $ws 'uninstall-wt.ps1'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $code = @'
param($ProfileSource)
$ErrorActionPreference = 'Stop'

$sb = Join-Path $env:TEMP "psp-uninst3-$([System.IO.Path]::GetRandomFileName())"
$docsRoot = Join-Path $sb 'Documents'
$cacheDir = Join-Path $sb 'PowerShellProfile'
$ps7Dir = Join-Path $docsRoot 'PowerShell'
$wtDir = Join-Path $sb 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState'
New-Item -ItemType Directory -Path $cacheDir, $ps7Dir, $wtDir -Force | Out-Null

$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $wtDir 'settings.json'), '{"profiles":{"defaults":{"modified":true}}}', $utf8)
[System.IO.File]::WriteAllText((Join-Path $wtDir 'settings.json.20250101-000000.bak'), '{"profiles":{"defaults":{"original_old":true}}}', $utf8)
Start-Sleep -Milliseconds 50
[System.IO.File]::WriteAllText((Join-Path $wtDir 'settings.json.20260101-000000.bak'), '{"profiles":{"defaults":{"original_new":true}}}', $utf8)

Copy-Item $ProfileSource (Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1')

$origLocal = $env:LOCALAPPDATA
$origProfile = $PROFILE
$env:LOCALAPPDATA = $sb
$global:PROFILE = Join-Path $ps7Dir 'Microsoft.PowerShell_profile.ps1'

$env:CI = 'true'
. $ProfileSource
Remove-Item env:CI

try {
    Uninstall-Profile -Confirm:$false

    $errors = @()
    $wtSettings = Join-Path $wtDir 'settings.json'
    if (-not (Test-Path $wtSettings)) { $errors += 'WT settings.json deleted instead of restored!' }
    else {
        $content = Get-Content $wtSettings -Raw | ConvertFrom-Json
        if (-not $content.profiles.defaults.original_new) { $errors += "WT not restored from newest backup" }
    }
    $remainingBaks = Get-ChildItem $wtDir -Filter 'settings.json.*.bak' -ErrorAction SilentlyContinue
    if ($remainingBaks.Count -gt 0) { $errors += "WT backups not cleaned up ($($remainingBaks.Count) remaining)" }

    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { Write-Host "  ASSERT: $e" -ForegroundColor Red }
        exit 1
    }
}
finally {
    $env:LOCALAPPDATA = $origLocal
    $global:PROFILE = $origProfile
    Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
}
'@
    [System.IO.File]::WriteAllText($sandboxScript, $code, $utf8)
    $output = pwsh -NonInteractive -NoProfile -File $sandboxScript -ProfileSource $profilePath 2>&1
    foreach ($line in $output) {
        if ($line -match 'ASSERT:') { Write-Host "        $line" -ForegroundColor Red }
    }
    if ($LASTEXITCODE -ne 0) {
        $asserts = @($output | Where-Object { $_ -match 'ASSERT:' })
        throw "WT restore sandbox failed: $($asserts -join '; ')"
    }
}

# #####################################################################
#  PART 7: PROFILE LOAD & INIT
# #####################################################################
Write-Host "`n--- Profile load & init ---" -ForegroundColor Magenta

T 'Profile loads without errors (CI mode)' {
    $output = pwsh -NonInteractive -NoProfile -Command "`$env:CI = 'true'; . '$profilePath'" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Profile load failed: $($output -join '; ')" }
}

T 'ProfileTools has 6 tools' {
    if ($script:ProfileTools.Count -ne 6) { throw "Expected 6, got $($script:ProfileTools.Count)" }
}

T 'ProfileTools: all have required keys' {
    foreach ($tool in $script:ProfileTools) {
        if (-not $tool.Name) { throw "Missing Name" }
        if (-not $tool.Id) { throw "Missing Id for $($tool.Name)" }
        if (-not $tool.Cmd) { throw "Missing Cmd for $($tool.Name)" }
        if (-not $tool.VerCmd) { throw "Missing VerCmd for $($tool.Name)" }
    }
}

T 'All 6 tools installed and accessible' {
    $missing = @()
    foreach ($tool in $script:ProfileTools) {
        if (-not (Get-Command $tool.Cmd -ErrorAction SilentlyContinue)) { $missing += $tool.Name }
    }
    if ($missing.Count -gt 0) { throw "Missing: $($missing -join ', ')" }
}

T 'All tools report valid version' {
    foreach ($tool in $script:ProfileTools) {
        $cmd = Get-Command $tool.Cmd -ErrorAction SilentlyContinue
        if ($cmd) {
            $ver = & $tool.Cmd $tool.VerCmd 2>&1 | Out-String
            $verLine = ($ver.Trim().Split([char]10) | Select-Object -First 1).Trim()
            if (-not $verLine -or $verLine.Length -lt 3) { throw "$($tool.Name) version too short: '$verLine'" }
        }
    }
}

T 'profile_user.ps1 exists' {
    $f = Join-Path (Split-Path $PROFILE) 'profile_user.ps1'
    if (-not (Test-Path $f)) { throw "not found at $f" }
}

T 'profile_user.ps1 has EditorPriority' {
    $f = Join-Path (Split-Path $PROFILE) 'profile_user.ps1'
    $content = Get-Content $f -Raw
    if ($content -notmatch 'EditorPriority') { throw "No EditorPriority" }
}

T 'Nerd Font installed' {
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    $fc = New-Object System.Drawing.Text.InstalledFontCollection
    $nf = @($fc.Families | Where-Object { $_.Name -match 'Caskaydia|NF|Nerd' })
    $fc.Dispose()
    if ($nf.Count -eq 0) { throw "No Nerd Font detected" }
}

T 'PSFzf module available' {
    if (-not (Get-Module -ListAvailable -Name PSFzf)) { throw "PSFzf not installed" }
}

T 'Resolve-PreferredEditor' {
    $r = Resolve-PreferredEditor
    if (-not $r) { throw "no editor resolved" }
}

T 'Get-SystemBootTime' {
    $r = Get-SystemBootTime
    if (-not $r) { throw "no boot time" }
    if ($r -gt (Get-Date)) { throw "boot time is in the future: $r" }
}

# #####################################################################
#  PART 8: EDGE CASES
# #####################################################################
Write-Host "`n--- Edge cases ---" -ForegroundColor Magenta

T 'touch (no args)' {
    Test-Throws { touch } "touch should require a path"
}

T 'head (no args)' {
    Test-Throws { head } "head should require a path"
}

T 'tail (no args)' {
    Test-Throws { tail } "tail should require a path"
}

T 'sed (nonexistent file)' {
    Test-Throws { sed "C:\nonexistent\file.txt" "a" "b" } "sed should fail for a nonexistent file"
}

T 'sed (empty find)' {
    Test-Throws { sed $tf "" "b" } "sed should require a non-empty find value"
}

T 'mkcd (no args)' {
    Test-Throws { mkcd } "mkcd should require a directory name"
}

T 'extract (nonexistent)' {
    Test-Throws { extract "C:\nonexistent\file.zip" } "extract should fail for a nonexistent archive"
}

T 'extract (unsupported format)' {
    $unsup = Join-Path $ws "test.xyz"
    "data" | Set-Content $unsup
    Test-Throws { extract $unsup } "extract should fail for unsupported archive types"
}

T 'hash (nonexistent file)' {
    Test-Throws { hash "C:\nonexistent\file.bin" } "hash should fail for a nonexistent file"
}

T 'sizeof (nonexistent)' {
    Test-Throws { sizeof "C:\nonexistent\path" } "sizeof should fail for a nonexistent path"
}

T 'checksum (nonexistent file)' {
    Test-Throws { checksum "C:\nonexistent\file.bin" "abc" } "checksum should fail for a nonexistent file"
}

T 'file (nonexistent)' {
    Test-Throws { file "C:\nonexistent\file.bin" } "file should fail for a nonexistent file"
}

T 'cpy (no args)' {
    Test-Throws { cpy } "cpy should require input text"
}

T 'gc (no args)' {
    Test-Throws { & (Get-Command 'gc' -CommandType Function).Name } "gc should require a commit message"
}

T 'gcom (no args)' {
    Test-Throws { gcom } "gcom should require a commit message"
}

T 'lazyg (no args)' {
    Test-Throws { lazyg } "lazyg should require a commit message"
}

T 'genpass (min length)' {
    $r = genpass 1
    if ($r.Length -ne 1) { throw "expected length 1, got $($r.Length)" }
}

T 'epoch (negative)' {
    $r = epoch -100
    if (-not $r) { throw "no output for negative epoch" }
}

T 'sed (null replace = delete)' {
    $sf = Join-Path $ws "sed-null.txt"
    "remove_this_word here" | Set-Content $sf
    sed $sf "remove_this_word " $null
    $c = Get-Content $sf -Raw
    if ($c -match "remove_this_word") { throw "word not removed: $c" }
}

T 'checksum (auto-detect SHA384 by length)' {
    $sha384 = hash $tf -Algorithm SHA384
    checksum $tf $sha384
}

T 'checksum (auto-detect SHA512 by length)' {
    $sha512 = hash $tf -Algorithm SHA512
    checksum $tf $sha512
}

T 'file (empty file)' {
    $ef = Join-Path $ws "empty.txt"
    New-Item $ef -ItemType File -Force | Out-Null
    file $ef
}

T 'file (PNG magic bytes)' {
    $png = Join-Path $ws "fake.png"
    [byte[]]$bytes = @(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + (0..100 | ForEach-Object { 0 })
    [System.IO.File]::WriteAllBytes($png, $bytes)
    file $png
}

T 'file (JPEG magic bytes)' {
    $jpg = Join-Path $ws "fake.jpg"
    [byte[]]$bytes = @(0xFF, 0xD8, 0xFF, 0xE0) + (0..100 | ForEach-Object { 0 })
    [System.IO.File]::WriteAllBytes($jpg, $bytes)
    file $jpg
}

T 'JSONC comment stripping' {
    $_q = [char]34
    $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
    $input1 = @'
{
    // This is a comment
    "key": "value", // inline comment
    "url": "https://example.com/path", // URL with double slashes
    "nested": {
        "a": 1 // deep comment
    }
}
'@
    $stripped = $input1 -replace $jsoncPattern, ''
    $parsed = $stripped | ConvertFrom-Json
    if ($parsed.key -ne 'value') { throw "key wrong: $($parsed.key)" }
    if ($parsed.url -ne 'https://example.com/path') { throw "URL corrupted: $($parsed.url)" }
    if ($parsed.nested.a -ne 1) { throw "nested wrong" }
}

T 'JSONC: strings with // not stripped' {
    $_q = [char]34
    $jsoncPattern = "(?m)(?<=^([^$_q]*$_q[^$_q]*$_q)*[^$_q]*)\s*//.*$"
    $input2 = '{"url": "https://example.com"}'
    $stripped = $input2 -replace $jsoncPattern, ''
    $parsed = $stripped | ConvertFrom-Json
    if ($parsed.url -ne 'https://example.com') { throw "URL in string corrupted: $($parsed.url)" }
}

T 'Clear-ProfileCache preserves user-settings.json' {
    $userSettings = Join-Path $realCacheDir 'user-settings.json'
    if (-not (Test-Path $userSettings)) { throw "user-settings.json missing" }
    $excluded = Get-ChildItem $realCacheDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'user-settings.json' }
    if (-not $excluded) { throw "user-settings.json not found" }
}

T 'Update-Tools: ProfileTools drive data' {
    $installed = $script:ProfileTools | Where-Object { Get-Command $_.Cmd -ErrorAction SilentlyContinue }
    if ($installed.Count -eq 0) { throw "No tools installed" }
    foreach ($tool in $installed) {
        $ver = try { (& $tool.Cmd $tool.VerCmd 2>$null | Where-Object { $_ -match '\d+\.\d+' } | Select-Object -First 1) } catch { $null }
        if (-not $ver) { throw "$($tool.Name): VerCmd returned no version" }
    }
}

T 'setup.ps1 and profile Merge-JsonObject identical' {
    $profileMerge = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Merge-JsonObject'
    }, $true) | Select-Object -First 1
    $setupMerge = $setupAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Merge-JsonObject'
    }, $true) | Select-Object -First 1
    if (-not $profileMerge) { throw "Not found in profile" }
    if (-not $setupMerge) { throw "Not found in setup.ps1" }
    $pBody = ($profileMerge.Extent.Text -replace '\s+', ' ').Trim()
    $sBody = ($setupMerge.Extent.Text -replace '\s+', ' ').Trim()
    if ($pBody -ne $sBody) { throw "Merge-JsonObject differs between profile and setup.ps1" }
}

T 'setup.ps1 and profile Invoke-DownloadWithRetry match' {
    $profileDl = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Invoke-DownloadWithRetry'
    }, $true) | Select-Object -First 1
    $setupDl = $setupAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Invoke-DownloadWithRetry'
    }, $true) | Select-Object -First 1
    if (-not $profileDl) { throw "Not found in profile" }
    if (-not $setupDl) { throw "Not found in setup.ps1" }
    $pText = $profileDl.Extent.Text
    $sText = $setupDl.Extent.Text
    if ($pText -notmatch 'MaxAttempts') { throw "Profile missing MaxAttempts" }
    if ($sText -notmatch 'MaxAttempts') { throw "Setup missing MaxAttempts" }
    if ($pText -notmatch 'BackoffSec') { throw "Profile missing BackoffSec" }
    if ($sText -notmatch 'BackoffSec') { throw "Setup missing BackoffSec" }
}

# #####################################################################
#  CLEANUP & SUMMARY
# #####################################################################
Set-Location $origDir
Remove-Item $ws -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n========================================================" -ForegroundColor Cyan
$color = if ($fail -gt 0) { 'Red' } else { 'Green' }
Write-Host "  Results: $ok ok, $fail bugs found" -ForegroundColor $color

if ($bugs.Count -gt 0) {
    Write-Host "`n  BUGS FOUND:" -ForegroundColor Red
    foreach ($b in $bugs) {
        Write-Host "    - $($b.Command): $($b.Error)" -ForegroundColor Red
    }
}

Write-Host "========================================================`n" -ForegroundColor Cyan
