# Load the profile non-interactively inside a sandbox in fresh processes of the running edition, fail on any load error,
# and fail when the median load time exceeds the budget (catches startup regressions).
#   pwsh -NoProfile -File tests/smoke.ps1
#   powershell -NoProfile -File tests/smoke.ps1 -BudgetMs 6000
param(
    [ValidateRange(1, 10)][int]$Runs = 3,
    [int]$BudgetMs = 4000
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$exe = (Get-Process -Id $PID).Path
$child = @'
param([string]$RepoRoot)
. (Join-Path $RepoRoot 'tests\lib\Sandbox.ps1')
$sb = New-PspSandbox -Name 'smoke'
Enter-PspSandbox -Sandbox $sb
try {
    $WarningPreference = 'SilentlyContinue'
    $Error.Clear()
    . (Join-Path $RepoRoot 'Microsoft.PowerShell_profile.ps1')
    foreach ($e in $Error) { Write-Output ("LOADERROR {0}" -f ($e.ToString() -replace '\s+', ' ')) }
    Write-Output ("LOADTIME {0}" -f $script:PSP.LoadTimeMs)
}
finally { Exit-PspSandbox -Sandbox $sb }
'@
$childPath = Join-Path ([System.IO.Path]::GetTempPath()) ('psp-child-smoke-' + [System.IO.Path]::GetRandomFileName() + '.ps1')
[System.IO.File]::WriteAllText($childPath, $child, [System.Text.UTF8Encoding]::new($false))
$times = @()
$failed = $false
try {
    for ($i = 1; $i -le $Runs; $i++) {
        $out = @(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $childPath -RepoRoot $repoRoot 2>&1 | ForEach-Object { "$_" })
        $loadErrors = @($out | Where-Object { $_ -like 'LOADERROR *' })
        $timeLine = $out | Where-Object { $_ -like 'LOADTIME *' } | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0 -or $loadErrors.Count -gt 0 -or -not $timeLine) {
            $failed = $true
            Write-Host "Run ${i}: the profile did not load cleanly (exit $LASTEXITCODE)" -ForegroundColor Red
            $out | ForEach-Object { Write-Host "  $_" }
            break
        }
        $ms = [int]($timeLine -replace '^LOADTIME\s+', '')
        $times += $ms
        Write-Host "Run ${i}: loaded in $ms ms"
    }
}
finally { Remove-Item -LiteralPath $childPath -Force -ErrorAction SilentlyContinue }
if ($failed) { exit 1 }
$median = ($times | Sort-Object)[[int][Math]::Floor(($times.Count - 1) / 2)]
Write-Host ("PowerShell {0}: median load {1} ms (budget {2} ms)" -f $PSVersionTable.PSVersion, $median, $BudgetMs) -ForegroundColor Cyan
if ($median -gt $BudgetMs) {
    Write-Host 'Load time is over budget. Find the slow step with Measure-Command or a profiler before raising the budget.' -ForegroundColor Red
    exit 1
}
