<#
.SYNOPSIS
    Copy the profile from this checkout into the Windows PowerShell 5.1 and PowerShell 7 profile folders.

.DESCRIPTION
    Profile-only install for development. An existing profile is backed up as oldprofile.<timestamp>.ps1 (the
    newest five are kept) and, the first time, as profile.original.ps1, which Uninstall-Profile restores.
    Tools, fonts, the theme and Windows Terminal settings are left alone; run setup.ps1 for those.

.EXAMPLE
    .\setprofile.ps1
    Copy the profile into both profile folders.

.EXAMPLE
    .\setprofile.ps1 -WhatIf
    Show which files would be written.

.NOTES
    Exit codes: 0 = the profile was copied to every profile folder; 1 = the profile was not found or a copy failed.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# Copy the profile to PS5 and PS7 directories while normalizing agent detection.
if (-not [bool]$env:AI_AGENT -and ([bool]$env:AGENT_ID -or [bool]$env:CLAUDE_CODE -or [bool]$env:CODEX -or [bool]$env:CODEX_AGENT)) { $env:AI_AGENT = '1' }
$source = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'Microsoft.PowerShell_profile.ps1' } else { $null }
if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Leaf)) {
    Write-Error "Cannot find profile script. Run this script from the repo directory (e.g. .\setprofile.ps1)." -ErrorAction Continue
    exit 1
}
# Return $true when a file is a copy of this profile (its header line), so it is never kept as the user's original.
function Test-PspProfileFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    [bool]@(Get-Content -LiteralPath $Path -TotalCount 3 -ErrorAction SilentlyContinue | Where-Object { $_ -match '^### PowerShell Profile \(26zl\)' }).Count
}

$docsRoot = Split-Path (Split-Path $PROFILE)
$profileDirs = @(
    Join-Path $docsRoot "PowerShell"          # PS7 (Core)
    Join-Path $docsRoot "WindowsPowerShell"    # PS5 (Desktop)
)
$failed = 0
foreach ($dir in $profileDirs) {
    $targetProfile = Join-Path $dir "Microsoft.PowerShell_profile.ps1"
    if (-not $PSCmdlet.ShouldProcess($targetProfile, 'Copy the profile (the current one is backed up)')) { continue }
    try {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $targetProfile -PathType Leaf) {
            # Keep the pre-install profile once; Uninstall-Profile restores it and rotation never touches it. When the current
            # profile is this one already, the oldest backup that is not is the user's; a saved copy of this profile is replaced.
            $originalBackup = Join-Path $dir 'profile.original.ps1'
            $originalIsOurs = Test-PspProfileFile $originalBackup
            if ($originalIsOurs -or -not (Test-Path -LiteralPath $originalBackup)) {
                $originalSource = if (-not (Test-PspProfileFile $targetProfile)) { $targetProfile }
                else {
                    Get-ChildItem -LiteralPath $dir -Filter 'oldprofile*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime |
                        Where-Object { -not (Test-PspProfileFile $_.FullName) } | Select-Object -First 1 | ForEach-Object { $_.FullName }
                }
                if ($originalSource) { Copy-Item -LiteralPath $originalSource -Destination $originalBackup -Force }
                elseif ($originalIsOurs) { Remove-Item -LiteralPath $originalBackup -Force }
            }
            # Keep the latest five timestamped profile backups; a failed backup stops the copy.
            $backupPath = Join-Path $dir ("oldprofile.{0}.ps1" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Copy-Item -LiteralPath $targetProfile -Destination $backupPath -Force
            Write-Host "  Backup saved to [$backupPath]" -ForegroundColor DarkGray
            Get-ChildItem -LiteralPath $dir -Filter 'oldprofile*.ps1' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
                ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
        }
        Copy-Item -LiteralPath $source -Destination $targetProfile -Force
        Write-Host "Profile copied to $dir" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to copy the profile to ${dir}: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}
if ([Environment]::UserInteractive -and -not [bool]$env:CI -and -not [bool]$env:AI_AGENT -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "Press Enter to close..." -ForegroundColor Yellow
    try { $null = Read-Host } catch { $null = $_ }
}
exit ([int]($failed -gt 0))
