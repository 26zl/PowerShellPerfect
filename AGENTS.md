# Instructions for AI coding agents

PowerShellPerfect is a Windows PowerShell profile (`Microsoft.PowerShell_profile.ps1`), its installer (`setup.ps1`), a profile-only copier (`setprofile.ps1`), shipped config (`theme.json`, `terminal-config.json`) and test harnesses in `tests/`. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the full conventions; the rules below are the ones that are easy to get wrong.

## Safety: this code changes real machines

- Never run `setup.ps1` (without `-WhatIf`), `Update-Profile`, `Uninstall-Profile`, `Clear-Cache` or `Clear-ProfileCache` against the real environment. Run them only inside a sandbox from `tests/lib/Sandbox.ps1` (`New-PspSandbox` + `Enter-PspSandbox`, then dot-source `$PspPostLoadStubs` after loading the profile).
- `Uninstall-Profile -All`/`-RemoveFonts` touches the machine font store unless `$script:PSP.TestFontScopes` points into the sandbox; `$PspPostLoadStubs` sets it.
- Do not create `telemetry.owned` in a sandbox before calling `Uninstall-Profile`: uninstall would then remove the real `POWERSHELL_TELEMETRY_OPTOUT` variable.
- Run tests from a non-elevated shell. Pass `-AllowElevated` only on CI runners or disposable VMs.
- `tests/rawhunt.ps1` is not sandboxed (public paste upload, clipboard, winget); do not run it.

## Checks to run

```powershell
pwsh -NoProfile -File tests/unit.ps1          # and: powershell -NoProfile -File tests/unit.ps1
pwsh -NoProfile -File tests/lint.ps1          # PSScriptAnalyzer 1.25.0 + PSScriptAnalyzerSettings.psd1
pwsh -NoProfile -File tests/smoke.ps1
pwsh -NoProfile -File tests/test.ps1          # full local gate
```

A bug fix needs a regression case in `tests/unit.ps1` that fails without the fix.

## Code rules

- Must run on Windows PowerShell 5.1 and PowerShell 7. `.ps1` files are ASCII only, no BOM, CRLF (`.gitattributes`).
- Read JSON with `Read-JsonFile`/`ConvertFrom-JsonC`, text with `Get-Utf8FileText`, write with `Write-Utf8FileAtomic`; use `-LiteralPath`.
- Helpers such as `Get-PspProp`, `Get-PspArray` and `Read-JsonFile` return lists with `return , $list`. Wrap such calls in parentheses before piping or counting (`(Get-PspArray $o 'k').Count`); `@(Get-PspArray ...)` nests the array.
- Windows Terminal `settings.json` is changed only through `Update-WindowsTerminalSettingsFile` / `Undo-WindowsTerminalSettingsFile`, which record each change so uninstall can revert it.
- `setup.ps1` loads the helpers named in `$script:SharedFunctionNames` from the verified profile; every profile helper that a shared function calls must be in that list (`tests/unit.ps1` checks it). The five pre-bundle helpers (`Write-PspHost`, `Invoke-DownloadWithRetry`, `Get-CombinedSha256`, `Resolve-PspCommitSha`, `Get-PspReleaseChecksums`) exist in both files and must stay identical; CI compares them.
- Destructive commands use `SupportsShouldProcess`; pin and hash anything downloaded at runtime; new third-party calls need a mock in `tests/ci-functional.ps1` and a row in `SECURITY.md`.
- Use `Write-PspHost` (honors `NO_COLOR`), keep state in `$script:PSP`, name load-time temporaries `$_psp*` (removed after load), and keep comments to one sentence about current behavior.

## Releases

Bump `Version` in `$script:PSP`, add a `CHANGELOG.md` section, then tag `vX.Y.Z`; `release.yml` publishes the files with `SHA256SUMS.txt` and an attestation. Do not create tags or releases unless asked.
