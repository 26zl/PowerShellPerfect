# Contributing to PowerShellPerfect

Thanks for your interest in contributing! This guide covers the dev setup, coding conventions, and PR process.

## Dev Environment Setup

1. Clone the repo:

   ```powershell
   git clone https://github.com/26zl/PowerShellPerfect.git
   cd PowerShellPerfect
   ```

2. Copy the profile to your PowerShell profile directories:

   ```powershell
   .\setprofile.ps1
   ```

3. Restart your terminal to load the profile.

## Coding Conventions

### Dual PS5/PS7 Compatibility

All code must work under both PowerShell 5.1 and 7+. Key differences:

- `Remove-Alias` only exists in PS6+; PS5 uses `Remove-Item Alias:\<name>`
- `$PSStyle` only exists in PS7.2+
- `PredictionSource`/`PredictionViewStyle` are PowerShell Core-only PSReadLine options
- Guard version-specific code with `$PSVersionTable.PSEdition` or `$PSVersionTable.PSVersion.Major`

### Source File Rules

- **No em dashes** (U+2014) or non-ASCII characters - CI PS5 parse fails on them
- **No BOM**: Never use `Set-Content -Encoding UTF8`. Use `[System.IO.File]::WriteAllText()` with `[System.Text.UTF8Encoding]::new($false)`
- Avoid `<angle brackets>` and `|` pipes inside double-quoted strings - use single quotes or `-f` format operator
- Use approved PowerShell verbs for function names (e.g., `Copy-SshKey` with alias `ssh-copy-key`)

### Adding a New Tool

1. Add an entry to the `$script:ProfileTools` array in `Microsoft.PowerShell_profile.ps1` with `Name`, `Id` (winget), `Cmd`, `Cache`, and `VerCmd`
   Also set `UpgradeStrategy` (`winget` for normal tools, `preserve-direct` only when a direct/MSI install must not be pushed back through winget).
2. Add a numbered install step in `setup.ps1` (it cannot read `ProfileTools`)

### Adding a New User-Facing Command

1. Write the function in `Microsoft.PowerShell_profile.ps1`. Prefer approved PowerShell verbs for `Verb-Noun` names; short non-verb names are acceptable for Unix-style utilities (`grep`, `journal`, `nscan`).
2. Seed the command registry so it shows up in `Get-ProfileCommand` and `Start-ProfileTour`. Add an entry to the `$script:_seedCommands` array near the end of the profile:

   ```powershell
   @{ Name = 'mycmd'; Category = 'Developer'; Synopsis = 'One-line description' }
   ```

3. Add an `Invoke-CommandProbe` entry in `tests/ci-functional.ps1` - either executing real code or `-SkipReason '...'` for destructive/interactive/tool-dependent commands. CI enforces 100% coverage, so missing a probe fails the `functional` job.
4. If the command has nested internal helpers (e.g. `Write-JournalLine` inside `journal`), add them to `$internalOnly` in the coverage audit so they are not flagged as missing public commands.
5. Update the appropriate section in `Show-Help` and `README.md`.

### Adding an Argument Completer

For new commands with parameters that benefit from Tab-complete (ports, log names, modes with descriptions, etc.), add a `Register-ArgumentCompleter` block near the top of the Sysadmin section. Use `$null = $commandName, $parameterName, $commandAst, $fakeBoundParameters` to mark unused `param()` entries as intentional and satisfy `PSReviewUnusedParameter`.

## Running the Linter

CI uses PSScriptAnalyzer and fails on both warnings and errors. Run it locally before pushing:

```powershell
Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.24.0 -Force -Scope CurrentUser

Invoke-ScriptAnalyzer -Path . -Recurse -ExcludeRule PSAvoidUsingWriteHost, PSAvoidUsingWMICmdlet, PSUseShouldProcessForStateChangingFunctions, PSUseBOMForUnicodeEncodedFile, PSReviewUnusedParameter, PSUseSingularNouns
```

### Smoke Test

```powershell
$env:CI = 'true'; . .\Microsoft.PowerShell_profile.ps1
```

(Non-interactive mode is triggered by `$env:CI` or `$env:AI_AGENT`. Known agent env vars are normalized to `$env:AI_AGENT`.)

### PS5 Parse Check

CI checks all `.ps1` files recursively. To match locally:

```powershell
Get-ChildItem -Filter *.ps1 -Recurse | ForEach-Object { powershell -NoProfile -Command "`$t = `$null; `$e = `$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$($_.FullName)', [ref]`$t, [ref]`$e); if (`$e.Count -gt 0) { `$e; exit 1 }" }
```

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes following the conventions above
3. Run PSScriptAnalyzer locally and fix any warnings/errors
4. Test on both PS5.1 and PS7+ if possible
5. Open a PR - the template will guide you through the checklist
6. CI must pass before merge

## CI Checks

CI runs on push/PR to `main` with three jobs:

- **lint**: PSScriptAnalyzer, smoke test, PS5 parse, hardcoded-path check, non-ASCII/BOM/secrets checks
- **install-flow**: JSON config validation, schema checks, Merge-JsonObject tests, WT merge mock, required function checks (`Test-InternetConnection`, `Install-NerdFonts`, `Install-OhMyPoshTheme`, `Install-WingetPackage`, `Merge-JsonObject`, `Select-PreferredEditor`, `Invoke-DownloadWithRetry`)
- **functional**: Runs `tests/ci-functional.ps1` (elevated): full install flow, sandbox install/execute/uninstall, and 100% command-probe coverage

All three jobs must pass. CI also fails on hardcoded user paths and embedded secrets.
