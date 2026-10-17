# PSScriptAnalyzer settings shared by CI (.github/workflows/ci.yml) and tests/lint.ps1.
# tests/ is not analyzed: the harnesses call profile aliases by their short names and hold fixtures that trip the rules.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console output is the interface of an interactive profile; Write-PspHost wraps it for NO_COLOR.
        'PSAvoidUsingWriteHost'
        # uptime keeps a Get-WmiObject fallback for Windows PowerShell 5.1.
        'PSAvoidUsingWMICmdlet'
        # Short Unix-style helpers (touch, mkcd, export) change state by design; destructive commands support -WhatIf.
        'PSUseShouldProcessForStateChangingFunctions'
        # Files are ASCII-only, which CI checks separately; a BOM is not needed.
        'PSUseBOMForUnicodeEncodedFile'
        # Argument-completer and event scriptblocks must accept parameters they do not use.
        'PSReviewUnusedParameter'
        # Plural nouns keep established names such as Get-WindowsTerminalSettingsPaths and Update-Tools.
        'PSUseSingularNouns'
    )
}
