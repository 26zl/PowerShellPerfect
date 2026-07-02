# Run the CI PSScriptAnalyzer rules locally while excluding test harnesses.
$repoRoot = Split-Path -Parent $PSScriptRoot
# Pin the PSScriptAnalyzer version used by CI.
$pinnedPSSAVersion = '1.24.0'
$have = Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [version]$pinnedPSSAVersion }
if (-not $have) {
    Install-Module -Name PSScriptAnalyzer -RequiredVersion $pinnedPSSAVersion -Force -Scope CurrentUser -ErrorAction Stop
}
Import-Module PSScriptAnalyzer -RequiredVersion $pinnedPSSAVersion -ErrorAction Stop
$results = Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -ExcludeRule PSAvoidUsingWriteHost,PSAvoidUsingWMICmdlet,PSUseShouldProcessForStateChangingFunctions,PSUseBOMForUnicodeEncodedFile,PSReviewUnusedParameter,PSUseSingularNouns |
    Where-Object { $_.ScriptName -notin @('ci-functional.ps1', 'rawhunt.ps1', 'test.ps1', 'locallab.ps1', 'lint.ps1') }
if ($results) {
    $results | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
    exit 1
} else {
    Write-Host 'PSScriptAnalyzer: clean' -ForegroundColor Green
}
