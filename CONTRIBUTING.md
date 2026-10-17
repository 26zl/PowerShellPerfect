# Contributing to PowerShellPerfect

Thanks for your interest in contributing! This guide covers the dev setup, coding conventions, tests, and the PR and release process. Please also read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Dev Environment Setup

1. Clone the repo:

   ```powershell
   git clone https://github.com/26zl/PowerShellPerfect.git
   cd PowerShellPerfect
   ```

2. Copy the profile to your PowerShell profile directories (`-WhatIf` shows what it would write):

   ```powershell
   .\setprofile.ps1
   ```

   Or install this checkout with its configs and Windows Terminal settings but without tools: `pwsh -NoProfile -File tests/locallab.ps1 -Install`.

3. Restart your terminal to load the profile.

## Coding Conventions

### Dual PS5/PS7 Compatibility

All code must work under both PowerShell 5.1 and 7+. Key differences:

- `Remove-Alias` only exists in PS6+; PS5 uses `Remove-Item Alias:\<name>`
- `$PSStyle` only exists in PS7.2+
- `PredictionSource`/`PredictionViewStyle` are PowerShell Core-only PSReadLine options
- `ConvertFrom-Json` on PS5 rejects comments and trailing commas; read JSON through `Read-JsonFile` / `ConvertFrom-JsonC`
- A function that returns a list with `return , $list` hands back one array object: wrap the call in parentheses, not `@()`, before piping or counting it (`(Get-PspArray $x 'k').Count`)
- Guard version-specific code with `$PSVersionTable.PSEdition` or `$PSVersionTable.PSVersion.Major`

### Source File Rules

- **No em dashes** (U+2014) or non-ASCII characters - CI PS5 parse fails on them
- **No BOM**: Never use `Set-Content -Encoding UTF8`. Use `Write-Utf8FileAtomic` (or `[System.IO.File]::WriteAllText()` with `[System.Text.UTF8Encoding]::new($false)`)
- Read text files with `Get-Utf8FileText` and pass paths with `-LiteralPath`
- Use `Write-PspHost` instead of `Write-Host` for colored output, so `NO_COLOR` is honored
- Avoid `<angle brackets>` and `|` pipes inside double-quoted strings - use single quotes or `-f` format operator
- Use approved PowerShell verbs for function names (e.g., `Copy-SshKey` with alias `ssh-copy-key`)
- Give public commands comment-based help (`.SYNOPSIS`, and `.EXAMPLE` for anything with options)
- Keep implementation comments to one sentence about current behavior, not change history
- Keep load-time state in `$script:PSP`; functions should not read load-time variables such as `$cacheDir` (call `Get-PspCacheDir`)
- Name load-time temporaries `$_pspSomething`: the end of the profile removes every `_psp*` variable, and only those, so names that `profile_user.ps1` or plugins define survive

### Code Shared With setup.ps1

`setup.ps1` loads most of its helpers (JSON handling, the Windows Terminal change recorder, cache paths) from the profile **after** the downloaded bundle has been verified, so both always run the same code. The five helpers it needs before that point (`Write-PspHost`, `Invoke-DownloadWithRetry`, `Get-CombinedSha256`, `Resolve-PspCommitSha`, `Get-PspReleaseChecksums`) are copies: change both copies together. CI fails when a copy differs from the profile or when a name in `$script:SharedFunctionNames` is missing from the profile.

### Adding a New Tool

1. Add an entry to the `$script:ProfileTools` array in `Microsoft.PowerShell_profile.ps1` with `Name`, `Id` (winget), `Cmd`, `Cache`, and `VerCmd`
   Also set `UpgradeStrategy` (`winget` for normal tools, `preserve-direct` only when a direct/MSI install must not be pushed back through winget).
2. Add a numbered install step in `setup.ps1` (it cannot read `ProfileTools`)
3. Pin anything downloaded at runtime (a version, and a SHA-256 where upstream publishes one) and add it to the pin check in `.github/workflows/scheduled.yml`

### Adding a New User-Facing Command

1. Write the function in `Microsoft.PowerShell_profile.ps1`. Prefer approved PowerShell verbs for `Verb-Noun` names; short non-verb names are acceptable for Unix-style utilities (`grep`, `journal`, `nscan`). Commands that delete, kill or change system settings need `SupportsShouldProcess` (and `ConfirmImpact = 'High'` when the effect is hard to undo).
2. Seed the command registry so it shows up in `Get-ProfileCommand` and `Start-ProfileTour`. Add an entry to the `$script:_seedCommands` array near the end of the profile:

   ```powershell
   @{ Name = 'mycmd'; Category = 'Developer'; Synopsis = 'One-line description' }
   ```

3. Add an `Invoke-CommandProbe` entry in `tests/ci-functional.ps1` and a `T` entry in `tests/test.ps1` - either executing real code (inside the sandbox; use `-WhatIf` or stubs for anything destructive) or with a skip reason for interactive/tool-dependent commands. Every export must be covered, and at least 60% of them must actually execute, or the coverage audit fails. Commands that call a third-party web service need a mock in `Install-NetworkMocks` in `tests/ci-functional.ps1` (pull-request CI never calls those services).
4. If the command has nested internal helpers (e.g. `Write-JournalLine` inside `journal`), add them to `$internalOnly` in the coverage audits so they are not flagged as missing public commands. Helpers named `*-Psp*` and `*-Wt*` are treated as internal automatically.
5. Update the appropriate section in `Show-Help` and `README.md`, and list user-visible data flows in `SECURITY.md`.

### Adding an Argument Completer

For new commands with parameters that benefit from Tab-complete (ports, log names, modes with descriptions, etc.), add a `Register-ArgumentCompleter` block near the top of the Sysadmin section. Use `$null = $commandName, $parameterName, $commandAst, $fakeBoundParameters` to mark unused `param()` entries as intentional and satisfy `PSReviewUnusedParameter`.

## Tests

Run the suites from a **normal (non-elevated)** shell. They redirect `LOCALAPPDATA`, `TEMP` and `$PROFILE` into disposable sandboxes and block commands that would change the machine, and they refuse to run elevated unless you pass `-AllowElevated` (meant for CI runners and disposable VMs).

```powershell
pwsh -NoProfile -File tests/unit.ps1        # regression tests (also run them with: powershell -NoProfile -File tests/unit.ps1)
pwsh -NoProfile -File tests/lint.ps1        # PSScriptAnalyzer 1.25.0 with PSScriptAnalyzerSettings.psd1
pwsh -NoProfile -File tests/smoke.ps1       # sandboxed load with a load-time budget
pwsh -NoProfile -File tests/test.ps1        # the full local gate (includes the above)
pwsh -NoProfile -File tests/ci-functional.ps1   # what the CI functional job runs (third-party endpoints mocked)
```

`tests/rawhunt.ps1 -AllowSideEffects` is the one harness that is not sandboxed: it uses your real profile settings, live services, the clipboard and winget, and uploads a probe file to a public paste.

**Bug fixes need a regression test.** Add a case to `tests/unit.ps1` that fails without the fix. The helpers in `tests/lib/Sandbox.ps1` (`New-PspSandbox`, `Enter-PspSandbox`, `$PspPostLoadStubs`, `Get-PspFunctionSource`) give each case a disposable environment. Inside a sandbox, `winget` is a throwing function and, for code that looks it up as an application, a `winget.cmd` first on `PATH` that fails and logs each call (`Get-PspSandboxWingetCalls`); replace it with a recording function in the case when the test needs winget to succeed.

### Manual Checks Before a Release

CI runs on Windows Server images with an English display language. Before tagging a release, check on a Windows 10 and a Windows 11 client (a VM is fine), in both Windows PowerShell 5.1 and PowerShell 7: the README install command, the wizard, `Update-Profile -Ref <tag>`, `Uninstall-Profile` (with Windows Terminal Stable and Preview installed), and `wifipass` / `Get-WslDistro` under a non-English display language.

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes following the conventions above
3. Run `tests/lint.ps1` and `tests/unit.ps1` locally and fix any warnings/errors
4. Test on both PS5.1 and PS7+ if possible
5. Add an entry under **Unreleased** in `CHANGELOG.md` for anything users will notice
6. Open a PR - the template will guide you through the checklist
7. All three CI jobs must pass before merge. The repository ruleset enforces `lint` and `install-flow` as required checks; `functional` must pass as well

## CI Checks

CI runs on push/PR to `main` with three jobs (on a pinned `windows-2025` image):

- **lint**: PSScriptAnalyzer (`tests/lint.ps1`), sandboxed load on PS7 and PS5.1 with a load-time budget (`tests/smoke.ps1`), PS5 parse, hardcoded-path check, non-ASCII/BOM/secrets checks
- **install-flow**: JSON config validation, schema and pin checks, curated-data validation (schemes + fonts), `setup.ps1` structure (copies match the profile, verification before changes), `tests/unit.ps1` on PS7 and PS5.1
- **functional**: `tests/ci-functional.ps1`: full install flow, sandbox install/execute/uninstall, coverage audit

`scheduled.yml` runs every Monday: the functional suite against the real web services, and a check that every pinned download still matches its hash. CI also fails on hardcoded user paths and embedded secrets.

## Releases

1. Update `Version` in `$script:PSP` in `Microsoft.PowerShell_profile.ps1` (SemVer).
2. Move the **Unreleased** entries in `CHANGELOG.md` under a new `## [X.Y.Z] - YYYY-MM-DD` heading.
3. Merge to `main`, then tag that commit `vX.Y.Z` and push the tag. `release.yml` checks that the tag matches `Version`, publishes the committed files with `SHA256SUMS.txt` and a build provenance attestation, and uses the CHANGELOG section as release notes.
4. Update the version in the README install command if it names a specific release.
