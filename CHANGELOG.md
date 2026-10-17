# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/): the version is `Version` in `$script:PSP` in the profile, and releases are tagged `vX.Y.Z`. Changes before 1.0.0 are in the git history.

## [Unreleased]

## [1.0.0] - 2026-10-17

First versioned release.

### Security

- `.psprc.ps1` trust is bound to the file's content: `Add-TrustedDirectory` stores its SHA-256, and a changed file (for example after `git pull` or a branch checkout) no longer runs until it is approved again. **Directories trusted with an earlier version must be approved once more** with `Add-TrustedDirectory`; until then their `.psprc.ps1` is skipped with a warning, and `psp-doctor` lists them.
- Releases are tagged and published with `SHA256SUMS.txt` and a build provenance attestation. `setup.ps1 -Ref vX.Y.Z` and `Update-Profile -Ref vX.Y.Z` resolve the tag to a commit and check every downloaded file against the release's checksums before changing anything. Branches and commits still require `-ExpectedSha256` or `-SkipHashCheck`.
- `setup.ps1` no longer requires administrator rights. Unelevated, the Nerd Font and the optional telemetry opt-out are installed for the current user; elevated, they are machine-wide and the terminal is not restarted, so you are not left in an elevated shell. `Invoke-ProfileWizard` runs the downloaded setup in the current session instead of an elevated one.
- Runtime downloads are pinned: Oh My Posh themes to `v31.8.0` (default and preset themes with SHA-256), Nerd Fonts to `v3.5.1` (every curated archive's SHA-256 checked), PSFzf `2.7.12`, and `http-server` `14.1.1` for `serve`.
- `winutil` hashes the downloaded script and runs the same in-memory bytes.
- Resumed wizard state is rebuilt from the curated lists, the editor name is quoted in `profile_user.ps1`, and a folder that merely contains files with the repository's names is no longer treated as a local checkout when `-Ref` or `-ExpectedSha256` is given.
- `certcheck` and `tlscert` report name-mismatch and chain errors instead of accepting every certificate silently; `env` masks secret-looking values unless `-ShowValues`; `pwnd` prompts without echo when no argument is given.
- `nscan` prints an authorization notice and asks before its Full, Stealth and Vuln profiles.
- A `.psprc.ps1` is read once per directory change and the text that was hashed is what runs (with `$PSScriptRoot` set to its folder), so the file cannot be swapped between the check and the run.
- `winutil -ExpectedSha256` and `winutil -Force` need an elevated shell: unelevated, WinUtil relaunches itself from its latest release, which the hash check never saw.
- `Invoke-ProfileWizard -Ref vX.Y.Z` checks `setup.ps1` against the release's `SHA256SUMS.txt` and passes the tag on, so setup verifies the bundle against the same release.
- `trash` refuses in SSH, WinRM and service sessions, where Windows deletes permanently instead of recycling.
- `env` masks more secret names (`*_PASS`, `*_PWD`, `*_PASSPHRASE`, account keys, connection strings) and connection-string values (`Password=`, `AccountKey=`, SAS signatures).

### Changed

- `Uninstall-Profile` reverts Windows Terminal changes value by value in every installed variant (Stable, Preview, Canary, unpackaged), keeping values you changed after install. Each change is recorded in `wt-changes.json`, and the untouched pre-install file is kept as `settings.json.psp-original`. Older installs without a record restore the oldest backup and keep the current file next to it. `windowsTerminal.manage = false` is honored, `-HardResetWindowsTerminal` keeps backups unless `-RemoveUserData`, and `-RemoveUserData` also removes the `oldprofile.*.ps1` copies. Kept files are listed under **Preserved**.
- `Set-TerminalBackground` and `setup.ps1` write Windows Terminal settings through the same change recorder as `Update-Profile`; arrays the profile adds to a file that had none are removed again on uninstall.
- `Update-Profile` installs missing tools only with `-InstallMissingTools` (which accepts the winget agreements and installs the pinned PSFzf); without it, missing tools are listed. New `-Ref <tag|commit>`.
- `setup.ps1`: strict error handling, a log in `%LOCALAPPDATA%\PowerShellProfile\logs`, `-WhatIf`, documented exit codes and `Get-Help` text; a failed backup stops the write it protects; settings are written atomically; `profile_user.ps1` is backed up before the editor line changes and is not rewritten when nothing changes; the wizard state moved to `%LOCALAPPDATA%\PowerShellProfile\wizard-state.json` and is removed only after the choices are saved.
- `setup.ps1` no longer uninstalls the Terminal-Icons module on every run; it asks first (default No) and never in CI mode.
- `setup.ps1` loads its shared helpers from the verified profile, so setup and the profile run the same code; an install record (`installed.json`) is written for `psp-doctor` and the update check.
- `user-settings.json` and Windows Terminal's `settings.json` are read with comment and trailing-comma support on both editions; a `user-settings.json` that does not parse is never overwritten, and the previous file is kept as `user-settings.json.bak`.
- `Clear-ProfileCache` keeps state files (`telemetry.owned`, `wt-changes.json`, `installed.json`) and the resized background images Windows Terminal points at; the telemetry marker is removed only after the variable is.
- Windows Terminal values that an earlier profile version wrote are recorded against `settings.json.psp-original` (or the oldest backup), so uninstall restores what was there before the first install. `settings.json.psp-original` is kept after uninstall unless `-RemoveUserData`. A `user-settings.json` that does not parse makes `setup.ps1`, `Update-Profile` and `Uninstall-Profile` leave `settings.json` alone.
- `profile.original.ps1` is never a copy of this profile: setup and `setprofile.ps1` save the user's own profile (the oldest backup that is not this profile when the current one already is), and `Uninstall-Profile` does not restore a copy of this profile.
- `setup.ps1` run as a script block removes the variables it created in the caller's session; after a failed install it no longer offers to restart the terminal; the quick-start preset uses an editor that is already installed; `-LocalRepo` prints the bundle hash of the local files.
- Load-time temporaries are named `_psp*` and removed after load, so variables that `profile_user.ps1` or plugins define are no longer removed.
- Command guards: `killport` and `Stop-ListeningPort` refuse core Windows processes; `Remove-LockedItem` lists the lockers and confirms each process (`-Tree` is opt-in); `Clear-Cache` refuses a `TEMP` that does not look like a temp folder and asks first; `pkill` refuses match-everything patterns and asks before wildcard matches; `dstop` and `dprune` ask first; `extract` refuses to overwrite without `-Force`; `trash` reports cancelled or permanent deletes.
- `sed` keeps the file's encoding and byte order mark; `Copy-SshKey` never glues a key onto an unterminated last line and skips a key that is already present; `wifipass` and `Get-WslDistro` work with any display language; `Find-FileLocker` checks the files inside a folder.
- `NO_COLOR` turns off colored output; `Show-Help` and `psp-doctor` show the version, and `psp-doctor` shows where the install came from; a hung oh-my-posh prompt falls back to the plain prompt after `PromptTimeoutMs` (5 s).
- Startup: tool probes no longer trigger module discovery, the kubeconfig is re-read only when it changes, and load-time variables no longer leak into the session.

### Fixed

- Windows Terminal JSONC handling no longer breaks valid files with escaped quotes or `//` inside strings, and handles block comments and trailing commas.
- `user-settings.json` and other UTF-8 files are read as UTF-8 on Windows PowerShell 5.1.
- User keybindings from `user-settings.json` are appended to the shipped ones as one flat list.
- The wizard's quick-start preset now selects the CascadiaCode Nerd Font; before, its lookup never matched and no font was chosen.
- Windows Terminal: single-element arrays are recorded as arrays (and reverted), `-NoLogo` is recorded for pre-2020 files with a bare `profiles` list, an action the user bound to more keys is kept on uninstall, and `-HardResetWindowsTerminal` drops the change record of the file it deletes.
- `Update-Profile -InstallMissingTools` installs missing tools when the profile is already up to date, and its re-run hint keeps the switch.
- Trust changes merge into `user-settings.json` as it is on disk, so entries saved by another session are kept.
- `Uninstall-Profile -RemoveFonts` finds the font named in `terminal-config.json` (it was read after the cache was removed); a failed restore of `profile.original.ps1` keeps the file.
- An oh-my-posh render that times out is stopped with its child processes, and the fallback prompt no longer runs the prompt hooks twice.
- `Set-PspInstallState` drops values that are passed empty (a local install no longer keeps an old commit); internal writes never prompt or honor `-WhatIf` a second time.
- The wizard treats `[` and `*` in a reply literally instead of aborting; `nscan` names the target in its prompt; `extract` accepts paths on PowerShell drives; `Clear-Cache` accepts Remote Desktop temp folders.

### Tests and CI

- New `tests/unit.ps1` regression suite (Windows PowerShell 5.1 and PowerShell 7), `tests/smoke.ps1` load-time budget, and `tests/lib/Sandbox.ps1` shared sandbox helpers. Every suite redirects `LOCALAPPDATA`, `TEMP` and `$PROFILE`, blocks machine-changing commands (winget also when it is looked up as an application: a logging `winget.cmd` comes first on `PATH`), keeps font removal inside the sandbox, and refuses to run elevated without `-AllowElevated`. `tests/rawhunt.ps1` runs only with `-AllowSideEffects`.
- `tests/test.ps1` never installs modules (PSScriptAnalyzer is skipped when missing), leaves the clipboard alone outside CI, and skips the install check on a machine without an install.
- `tests/ci-functional.ps1` mocks third-party web services in pull-request CI (`-LiveNetwork` for the weekly run), soft-fails only on transport exceptions, never uploads to the public paste, and requires at least 60% of exports to execute.
- CI uses PSScriptAnalyzer 1.25.0 with `PSScriptAnalyzerSettings.psd1`, a pinned `windows-2025` image, `persist-credentials: false` and job timeouts, and tests the shipped functions instead of copies. New `release.yml` and `scheduled.yml` workflows.
- New `CHANGELOG.md`, `AGENTS.md`, `CODE_OF_CONDUCT.md`, `.editorconfig` and `.mailmap`.
