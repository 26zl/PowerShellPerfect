# Copy profile to both PS7 and PS5 directories
# Derive Documents root from $PROFILE (works correctly even when Documents is in OneDrive)
if (-not $PSScriptRoot -or -not (Test-Path (Join-Path $PSScriptRoot "Microsoft.PowerShell_profile.ps1"))) {
    Write-Error "Cannot find profile script. Run this script from the repo directory (e.g. .\setprofile.ps1)."
    exit 1
}
$docsRoot = Split-Path (Split-Path $PROFILE)
$profileDirs = @(
    Join-Path $docsRoot "PowerShell"          # PS7 (Core)
    Join-Path $docsRoot "WindowsPowerShell"    # PS5 (Desktop)
)
foreach ($dir in $profileDirs) {
    if (!(Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType "directory" -Force | Out-Null
    }
    Copy-Item (Join-Path $PSScriptRoot "Microsoft.PowerShell_profile.ps1") $dir
    Write-Host "Profile copied to $dir" -ForegroundColor Green
}
