# PowerShellPerfect

[![CI](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A modern PowerShell profile for Windows. The installer drops you into a **`p10k configure`-style install wizard** that picks your theme, color scheme, font, and feature toggles, then ships 145+ commands (Unix-style utilities plus git, network, security, sysadmin, WSL, and docker), a tuned Oh My Posh prompt, fuzzy search, zoxide, and a full uninstall + self-update behind it.

> **Stability.** The command surface, install flow, and extension points are settled; new work stays additive where it can and is described in each [release](https://github.com/26zl/PowerShellPerfect/releases)'s notes. Every push and pull request runs PSScriptAnalyzer, Windows PowerShell 5.1 and PowerShell 7 parse and load checks with a load-time budget, regression tests on both editions, a sandboxed install/uninstall cycle, and a functional command suite. Releases are tagged `vX.Y.Z` and published with `SHA256SUMS.txt` and a build provenance attestation.

## Install

Run in a **normal (non-elevated)** PowerShell window; setup needs no administrator rights. Replace `v1.0.0` with the [latest release](https://github.com/26zl/PowerShellPerfect/releases/latest):

```powershell
$v = 'v1.0.0'
$base = "https://github.com/26zl/PowerShellPerfect/releases/download/$v"
$dir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "psp-$v-$(Get-Random)")
foreach ($f in 'setup.ps1', 'SHA256SUMS.txt') { Invoke-WebRequest "$base/$f" -OutFile (Join-Path $dir $f) -UseBasicParsing }
# Check setup.ps1 against the release's checksum before running it.
$bytes = [IO.File]::ReadAllBytes((Join-Path $dir 'setup.ps1'))
$hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
$line = Get-Content (Join-Path $dir 'SHA256SUMS.txt') | Where-Object { $_ -match '\ssetup\.ps1$' }
if (-not $line -or $line.Split(' ')[0] -ne $hash) { throw 'setup.ps1 does not match SHA256SUMS.txt; do not run it.' }
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($bytes))) -Ref $v
```

With `-Ref vX.Y.Z`, setup resolves the tag to its commit, downloads the profile, `theme.json` and `terminal-config.json` from that commit, and checks them against the same release's `SHA256SUMS.txt` **before changing anything**. The checksum file and the downloads come from GitHub, so they protect against a changed `main` branch and broken downloads; to check that a release was really built by this repository's workflow, use the [GitHub CLI](https://cli.github.com/) instead:

```powershell
gh release download v1.0.0 --repo 26zl/PowerShellPerfect --dir psp-release
gh attestation verify psp-release\setup.ps1 --repo 26zl/PowerShellPerfect --source-ref refs/tags/v1.0.0 --signer-workflow 26zl/PowerShellPerfect/.github/workflows/release.yml   # repeat for the other files
cd psp-release; powershell -ExecutionPolicy Bypass -File .\setup.ps1          # installs from the verified files
```

**Latest `main` instead of a release.** Without a release tag, setup prints the hashes of what it downloaded and stops. Check the commit it names, then re-run pinned to the printed hash (or accept trust-on-first-use with `-SkipHashCheck`):

```powershell
$setup = irm "https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1"
& ([scriptblock]::Create($setup))                                        # prints the bundle hash and the commit, then stops
& ([scriptblock]::Create($setup)) -Ref <commit> -ExpectedSha256 '<hash>' # installs exactly that commit
```

Run setup as a script block, as shown, or as a file; `irm ... | iex` is not supported. As a script block it sets `$LASTEXITCODE` instead of exiting and removes the variables it created in your session, except after a successful install in an interactive, non-elevated window: setup then asks you to press Enter, opens a new terminal and closes the one it ran in.

The printed hash is computed over the bytes you just downloaded: it makes the install reproducible and detects changes in transit, but it cannot tell you whether those bytes are what the maintainer intended. That is what release checksums and attestations are for. See [SECURITY.md](SECURITY.md).

The **install wizard runs by default** in an interactive window (pass `-SkipWizard` for repo defaults). Every run is logged to `%LOCALAPPDATA%\PowerShellProfile\logs\setup-<timestamp>.log`; `-WhatIf` shows the changes without making them. For the best experience use [PowerShell 7+](https://github.com/PowerShell/PowerShell).

## Contents

- [Requirements](#requirements) · [What setup changes](#what-setup-changes) · [Install Wizard](#install-wizard) · [At a glance](#at-a-glance) · [Install (alternatives)](#install-alternatives)
- [Updates](#updates) · [Uninstall](#uninstall) · [Customization](#customization) · [Keyboard Shortcuts](#keyboard-shortcuts)
- [Commands](#commands) · [Compared to alternatives](#compared-to-alternatives) · [Limitations](#limitations) · [Troubleshooting](#troubleshooting) · [Tests](#tests) · [Roadmap](#roadmap)

## Requirements

| | |
| --- | --- |
| **OS** | Windows 10 1809+ / Windows 11 (Windows Terminal recommended). CI runs on Windows Server images; client versions are checked by hand. |
| **Shell** | Windows PowerShell 5.1 (works) or [PowerShell 7+](https://github.com/PowerShell/PowerShell) (recommended; every PS5/PS7 API fork is guarded) |
| **Privileges** | None. Without elevation the Nerd Font is installed for your user and the optional telemetry opt-out is set for your user; in an elevated shell both are machine-wide. Run setup unelevated so the terminal it restarts into is not elevated. |
| **Network** | Setup fetches the profile bundle from GitHub, the Oh My Posh theme, the portable Oh My Posh build and the Nerd Font at pinned versions, and the other CLI tools through winget. `Update-Profile` fetches the bundle and the theme; it installs missing tools (the portable Oh My Posh build, winget packages, PSFzf) only with `-InstallMissingTools` and never installs fonts. TLS 1.2+ is enforced on PS5.1. |
| **Optional tools** | `eza`, `bat`, `ripgrep`, `fzf`, `zoxide`, `oh-my-posh`; installed by setup. Every command degrades gracefully if a tool is absent. |

## What setup changes

| Change | Where | Reverted by |
| --- | --- | --- |
| Profile for both editions, previous profile kept as `profile.original.ps1` (once; a copy of this profile is never kept as the original) and `oldprofile.<timestamp>.ps1` (latest 5) | `Documents\PowerShell`, `Documents\WindowsPowerShell` | `Uninstall-Profile` (restores `profile.original.ps1`; `-RemoveUserData` also removes the `oldprofile` copies) |
| Starter `profile_user.ps1` for your own overrides (every line commented out), created only when missing | `Documents\PowerShell`, `Documents\WindowsPowerShell` | `Uninstall-Profile -RemoveUserData` |
| Interactive runs: the editor you pick, as a `$script:EditorPriority` line in each `profile_user.ps1` (the previous file is kept as `profile_user.ps1.bak`) | `Documents\PowerShell`, `Documents\WindowsPowerShell` | `Uninstall-Profile -RemoveUserData` (removes `profile_user.ps1` and the `.bak`) |
| Caches (each run clears the generated zoxide and Oh My Posh caches so the next load rebuilds them), `user-settings.json`, install record (`installed.json`), Windows Terminal change record (`wt-changes.json`), logs | `%LOCALAPPDATA%\PowerShellProfile` | `Uninstall-Profile` (`user-settings.json` and `plugins\` stay unless `-RemoveUserData`) |
| Windows Terminal: font, opacity, color scheme, tab theme, the keybindings you list in `user-settings.json` (none are shipped; a `Ctrl+A` binding left by an earlier version is removed again), and `-NoLogo` on the PowerShell profiles' command lines. Every installed variant (Stable, Preview, Canary, unpackaged); each value is recorded with what it replaced, and the untouched pre-install file is kept as `settings.json.psp-original` | `settings.json` of each variant | `Uninstall-Profile` reverts each recorded value it still finds; values you changed later are kept |
| Oh My Posh portable build, pinned release, SHA-256 and Authenticode signer checked (winget is the fallback when the download fails; an existing direct or MSI install is left alone) | `%LOCALAPPDATA%\Programs\oh-my-posh\bin` | `Uninstall-Profile -RemoveTools`, which also removes a winget or MSI install of Oh My Posh, even one made before setup |
| winget packages: eza, zoxide, fzf, bat, ripgrep (winget accepts the source and package agreements for you) | winget | `Uninstall-Profile -RemoveTools`, which removes these packages even when they were installed before setup |
| PSFzf module, pinned version, current user | PowerShell Gallery | `Uninstall-Profile -RemoveTools` |
| Nerd Font, pinned release, archive SHA-256 checked | per-user font store (machine-wide when elevated) | `Uninstall-Profile -RemoveFonts` |
| Optional, asked first: the editor you pick, when it is not installed; setup then installs it with winget (this accepts its license) | winget | not reverted (`Uninstall-Profile` does not remove it) |
| Optional, asked first: `POWERSHELL_TELEMETRY_OPTOUT=true` | user environment (machine when elevated) | `Uninstall-Profile` (only if setup set it) |
| Optional, asked first: CurrentUser execution policy `AllSigned` -> `RemoteSigned`; uninstalling the Terminal-Icons module (this profile shows icons through eza instead) | | not reverted (you chose it) |

## Install Wizard

Inspired by [powerlevel10k](https://github.com/romkatv/powerlevel10k)'s `p10k configure`. **Runs automatically on every interactive install**; non-interactive environments skip it.

```powershell
# Bypass the wizard and apply repo defaults (Tokyo Night + CascadiaCode):
.\setup.ps1 -SkipWizard

# Resume a half-finished wizard (state in %LOCALAPPDATA%\PowerShellProfile\wizard-state.json):
.\setup.ps1 -Resume

# Re-run the wizard any time after install (setup.ps1 of a release is checked against its SHA256SUMS.txt; runs in a child PowerShell in this window):
Reconfigure-Profile -Ref v1.0.0
# From a branch or commit, pin setup.ps1 and then the bundle to the hashes the runs print:
Reconfigure-Profile -Ref <commit> -ExpectedSha256 '<setup.ps1 hash>' -BundleExpectedSha256 '<bundle hash>'
```

**Steps** (all accept Enter to keep the default / skip):

1. **Quick start**: one-key preset: Tokyo Night scheme, CascadiaCode Nerd Font, the first editor of the list below that is already installed (nothing is installed for it), dark chrome, default features. Answer yes to jump straight to the summary.
2. **Oh My Posh theme**: the theme catalog of the pinned Oh My Posh release ([v31.8.0](https://github.com/JanDeDobbeleer/oh-my-posh/tree/v31.8.0/themes)). Pick by number or partial name. The default and preset themes are checked against pinned SHA-256 hashes. Network failure falls back to `pure`.
3. **Color scheme**: curated 7-pack: Tokyo Night (default), Gruvbox Dark, Dracula, Catppuccin Mocha, Nord, One Half Dark, Solarized Dark. Full scheme definitions embedded; no extra network.
4. **Nerd Font**: Caskaydia, JetBrainsMono, FiraCode, Meslo, Hack, or Iosevka from [Nerd Fonts v3.5.1](https://github.com/ryanoasis/nerd-fonts/releases/tag/v3.5.1); each archive is checked against the hash from that release's `SHA-256.txt`.
5. **Tab bar color + window chrome**: presets (scheme-match, pure black, custom hex) + `applicationTheme` dark/light.
6. **Terminal appearance**: opacity, `useAcrylic`, font size, cursor shape, padding, scrollbar state, history size. Each prompt keeps the current default on Enter.
7. **PSReadLine colors**: derive from chosen scheme (default) / shipped palette / skip.
8. **Background image**: optional path + opacity (0.05-0.50). Skipped by default.
9. **Editor preference**: Visual Studio Code, Neovim, Vim, Microsoft Edit, Sublime Text, Notepad++, or Notepad. If the one you pick is not installed, you are asked whether setup should install it with winget, which accepts its license; the install runs after the summary. Used by `edit`, `ep`, `hosts`, etc.
10. **Telemetry opt-out + feature toggles**: `psfzf`, `predictions`, `startupMessage`, `perDirProfiles`, `commandOverrides`; y/n per item with sensible defaults.

**Design**:

- All choices persist to `user-settings.json` so `Update-Profile` re-applies them; nothing hardcoded into the profile. A `user-settings.json` that does not parse is never overwritten (comments and trailing commas are fine); the previous file is kept as `user-settings.json.bak`.
- Summary screen at the end with "apply all?" confirmation.
- The state file enables `-Resume`; resumed values are re-checked against the curated lists before they are used.
- All 145+ commands and the extensibility system ship regardless of wizard choices; the wizard only selects cosmetics and opt-ins.

## At a glance

| | |
| --- | --- |
| **145+ commands** | git, files, unix tools, network, security, developer, sysadmin, WSL, docker, ssh, clipboard |
| **Install wizard (default)** | Picks OMP theme, WT color scheme (7 curated), Nerd Font (6 curated), tab-bar + window chrome, terminal appearance, PSReadLine colors, background, editor, telemetry opt-out, feature toggles. See [Install Wizard](#install-wizard). |
| **Transient prompt** | Scrollback shows collapsed `$`; new input gets the full OMP prompt (opt-in feature flag) |
| **Verified updates** | `Update-Profile -Ref vX.Y.Z` checks downloads against the release's `SHA256SUMS.txt`; branches and commits need a pinned hash. `profile_user.ps1` and `user-settings.json` survive updates. |
| **Reversible** | Windows Terminal changes are recorded value by value and reverted on uninstall without discarding your later edits; see [What setup changes](#what-setup-changes). |
| **PS5 + PS7** | Installs to both profile directories; every PS5/PS7 API fork is guarded |
| **Sandbox-safe** | Non-interactive environments skip network calls and UI setup so sessions don't hang |
| **Hardened** | Passwords/tokens filtered from PSReadLine history; `env` masks secret-looking values; per-directory `.psprc.ps1` files run only while their content matches what you approved |
| **Tested** | Regression tests on PS 5.1 and 7, sandboxed install/uninstall cycles, and a functional suite in which every exported command is either executed or skipped with a recorded reason (at least 60% must execute) |

Inspired by [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile); design cues from [powerlevel10k](https://github.com/romkatv/powerlevel10k) and [starship](https://github.com/starship/starship).

## Install (alternatives)

> **Oh My Posh:** setup installs the portable release build of [Oh My Posh](https://github.com/JanDeDobbeleer/oh-my-posh) (pinned version, SHA-256 and signer checked) to `%LOCALAPPDATA%\Programs\oh-my-posh\bin`; the profile adds that folder to `PATH` for each session, so `oh-my-posh` also runs by name. The `winget`/Store MSIX build adds about 30 ms to every prompt, so `Update-Tools` replaces it with the portable build; a direct or MSI install you made yourself is left as is.

### Manual Setup (local clone)

```powershell
git clone https://github.com/26zl/PowerShellPerfect.git
cd PowerShellPerfect
.\setup.ps1             # wizard runs by default
.\setup.ps1 -SkipWizard # apply repo defaults instead
.\setup.ps1 -WhatIf     # show what would change
```

`setup.ps1` uses the folder it runs from when that folder holds the profile, `theme.json`, `terminal-config.json` and `setprofile.ps1` (a clone or an extracted release), so nothing is downloaded and nothing is hash-checked; it prints the bundle hash of the files it installs, and `-LocalRepo . -ExpectedSha256 '<hash>'` checks the local files first. A git clone has CRLF line endings in `.ps1` files, so a release hash (which covers the published LF files) only matches an extracted release. Passing `-Ref` or `-ExpectedSha256` without `-LocalRepo` turns detection off, so a folder that merely contains files with those names cannot replace the verified download. A separate `.\setprofile.ps1` copies only the profile (`-WhatIf` supported).

When running locally you can override terminal defaults:

```powershell
.\setup.ps1 -SkipWizard -Opacity 85 -ColorScheme "One Half Dark" -FontSize 12
```

Exit codes: `0` when the profile is installed (optional tools that were skipped or failed are listed in the summary), `1` when nothing was applied (verification failed, unsupported system) or the profile could not be installed, `2` when the wizard was cancelled (nothing is installed). `Get-Help .\setup.ps1 -Full` lists every parameter.

> **Controlled Folder Access:** setup writes the profile to `Documents`, which CFA protects. The
> symptom is a misleading `Could not find file` and a Defender event 1123. Allow the PowerShell
> you are running **for the install only**, then take it out again. A permanent entry lets every
> PowerShell script, ransomware included, write to your protected folders. Changing the list needs
> an elevated window, while setup runs in a normal one:
>
> ```powershell
> # In the normal window you will run setup from: print the PowerShell to allow
> (Get-Process -Id $PID).Path   # also right for the Store build, whose path changes per version
>
> # In an elevated window: allow it
> $ps = '<the path printed above>'
> Add-MpPreference -ControlledFolderAccessAllowedApplications $ps
>
> # In the normal window: install
> .\setup.ps1
>
> # In the elevated window: take it out again and check it is gone
> Remove-MpPreference -ControlledFolderAccessAllowedApplications $ps
> (Get-MpPreference).ControlledFolderAccessAllowedApplications
> ```
>
> Later profile and module updates write to the same folder and need the same allow and remove steps around them.

## Updates

```powershell
Update-Profile -Ref v1.1.0           # Install a release, checked against its SHA256SUMS.txt
Update-Profile                       # Latest main: prints the hashes and stops; re-run with -Ref <commit> -ExpectedSha256 '<hash>'
Update-Profile -InstallMissingTools  # Also install missing managed tools with winget (accepting the agreements) and the pinned PSFzf
Update-PowerShell                    # Check for new PowerShell 7 releases
Update-Tools                         # Update winget-managed tools and the portable Oh My Posh build; tools installed another way are left alone
```

`Update-Profile` resolves `-Ref` to a commit, so the profile, `theme.json` and `terminal-config.json` always come from the same commit. For a release tag it checks the downloads against the release's `SHA256SUMS.txt`; for a branch or commit it needs `-ExpectedSha256` (the hash printed by the previous run) or `-SkipHashCheck`. Nothing is installed unless you pass `-InstallMissingTools` (which also works when the profile is already up to date); without it, missing tools are only listed. A `user-settings.json` that does not parse leaves Windows Terminal's `settings.json` alone until it is fixed. `-Force` re-applies settings even when nothing changed. `psp-doctor` shows the installed version, ref and commit.

## Uninstall

```powershell
Uninstall-Profile              # Profile files, caches, and the Windows Terminal changes the profile made
Uninstall-Profile -RemoveUserData -RemoveFonts # Everything except the tools (CLI tools and PSFzf stay)
Uninstall-Profile -RemoveTools # Also uninstall the managed CLI tools, the portable Oh My Posh build and PSFzf; winget packages and an Oh My Posh MSI go even if they were installed before setup
Uninstall-Profile -All         # Remove everything including tools, fonts, and user data
Uninstall-Profile -All -HardResetWindowsTerminal # Same as -All, but also delete WT settings.json so WT recreates factory defaults
Uninstall-Profile -All -Force  # Also uninstall PSFzf/managed tools when CI or agent guards are active
```

Windows Terminal is reverted change by change in every installed variant: each value the profile set goes back to what it was before install, unless you have changed it since, in which case your value stays. Installs made by older versions without a change record restore the oldest backup (closest to the pre-install file) and keep the current file next to it as `settings.json.pre-uninstall-<timestamp>.json`. With `windowsTerminal.manage = false`, a `user-settings.json` that does not parse, or a symlinked `settings.json`, uninstall leaves the file alone. `-HardResetWindowsTerminal` deletes `settings.json` but keeps the backups unless `-RemoveUserData` is also given.

A plain `Uninstall-Profile` keeps `user-settings.json`, `profile_user.ps1`, `plugins/`, the `oldprofile.*.ps1` copies and `settings.json.psp-original` (Windows Terminal settings from before the first install), and lists them under **Preserved**; `-RemoveUserData` (or `-All`) removes them. Machine-wide fonts and a machine-wide telemetry opt-out need an elevated shell to remove; uninstall says so and lists them. All switches support `-WhatIf`.

## Customization

Four extension points survive updates. From simplest to most powerful:

- **`user-settings.json`** (`%LOCALAPPDATA%\PowerShellProfile\`) - JSON overrides (comments and trailing commas allowed). Keys:
  - `theme`, `windowsTerminal`, `defaults`, `keybindings` - terminal and OMP theme; `keybindings` are the only Windows Terminal bindings the profile sets, and one you remove here is removed from `settings.json` on the next update
  - `theme.allowCommands` - set to `true` to use a theme that can run commands on every prompt: `command` segments, template functions such as `cmd`, `readFile` or `getHostByName`, or `extends` (which pulls in a config the profile does not check). Without it such a theme is refused at download and at load (none of the official themes uses any of these).
  - `windowsTerminal.manage` - set to `false` when another tool owns Windows Terminal's `settings.json` (a dotfiles repo, for example). `setup.ps1`, `Update-Profile`, `Set-TerminalBackground` and `Uninstall-Profile` then leave that file alone, and `psp-doctor` reports who owns it. A symlinked `settings.json` is always written in place, so the link survives updates.
  - `defaults.backgroundImage` / `backgroundImageOpacity` / `backgroundImageStretchMode` / `backgroundImageAlignment` - Windows Terminal background image
  - `features` - toggle heavy/optional behavior: `psfzf`, `predictions`, `startupMessage`, `perDirProfiles`, `fastGitPrompt` (renders git-heavy themes from a copy without the upstream and stash lookups, one git process fewer per prompt) (all `true` by default), `transientPrompt` (collapses previous prompt on Enter; default `false`, customize via `$script:PSP.TransientPrompt = { ... }` in `profile_user.ps1`), `updateCheck` (notifies once a week when main has advanced past the applied commit; default `false` so `irm | iex` in scripts does not trigger a surprise network call)
  - `commandOverrides` - redefine any command without editing source: `{ "gs": "git status --short" }`. Opt-in: set `features.commandOverrides = true` in the same file. Default off because it compiles JSON strings into executable scriptblocks.
  - `trustedDirs` and `trustedRcHashes` - directories whose `.psprc.ps1` auto-loads and the SHA-256 of the file you approved (managed by `Add-TrustedDirectory`)
- **`profile_user.ps1`** (`Split-Path $PROFILE`) - PowerShell overrides (aliases, functions, editor, colors, modules), dot-sourced after `user-settings.json` (so PS-level definitions win over JSON `commandOverrides` and feature toggles) and before `plugins/`
- **`plugins/*.ps1`** (`%LOCALAPPDATA%\PowerShellProfile\plugins\`) - drop-in plugins, loaded in name order (hidden files are skipped). Each file is auto-loaded; errors are isolated per plugin
- **`.psprc.ps1`** (per directory) - project-specific profile. `Add-TrustedDirectory` approves the file as it is now; it then auto-loads on `cd` into that directory **only while its content is unchanged**. After any change (for example a `git pull` or branch switch) it is skipped with a warning until you review it and run `Add-TrustedDirectory` again, like `direnv allow`. The file is read once and the checked text is what runs (`$PSScriptRoot` is its folder). Use `function global:foo` / `Set-Alias -Scope Global` for lasting definitions; `$env:VAR` always persists

Set `NO_COLOR` (any value, see [no-color.org](https://no-color.org)) to turn off colored output from the profile's commands and `Show-Help`. Call `Start-ProfileTour` for a live walkthrough, `Get-ProfileCommand -Category <cat>` to list what's available, or `Get-Help <command>` for a command's details.

### Background Image

```powershell
Set-TerminalBackground "$env:USERPROFILE\Pictures\bg.png" -Opacity 0.1
Set-TerminalBackground -Clear
```

Default fills the whole tab with low opacity (typical backdrop). For a small corner watermark, add `-ResizeWidth 200 -StretchMode none -Alignment bottomRight`. Persisted to `user-settings.json` and applied live to every Windows Terminal variant through the same change record, so `Uninstall-Profile` reverts it.

## Keyboard Shortcuts

| Key | Action |
| --- | --- |
| `Up` / `Down` | Search history matching current input |
| `Tab` | Menu-style tab completion |
| `Ctrl+R` | Fuzzy search command history (fzf) |
| `Ctrl+T` | Fuzzy file finder (fzf) |
| `Ctrl+D` | Delete character |
| `Ctrl+W` | Delete word backwards |
| `Alt+D` | Delete word forwards |
| `Ctrl+Left` / `Ctrl+Right` | Jump word backwards / forwards |
| `Ctrl+Z` / `Ctrl+Y` | Undo / Redo |
| `Alt+V` | Smart paste (inserts clipboard without executing) |

## Commands

Run `Show-Help` in your terminal for a colored version of this list.

### Profile & Updates

| Command | Description |
| --- | --- |
| `edit <file>` | Open file in preferred editor |
| `Edit-Profile` / `ep` | Open profile in preferred editor |
| `Update-Profile [-Ref <tag\|commit>]` | Sync profile, theme, caches, and WT settings (hash-checked); `-InstallMissingTools` also installs missing tools |
| `Update-PowerShell` | Check for new PowerShell 7 releases |
| `Update-Tools` | Update winget-managed tools and the portable Oh My Posh build (an MSIX install is replaced); tools installed another way (scoop, choco, by hand, a direct/MSI Oh My Posh) are left alone and reported as preserved |
| `Invoke-ProfileWizard` / `Reconfigure-Profile` | Re-run the install wizard to pick a new theme / scheme / font / feature set |
| `reload` | Reload the PowerShell profile; run it as `. reload` so new and changed functions reach the session |
| `Show-Help` | Show help in terminal |
| `Uninstall-Profile` | Remove profile, caches, and the WT changes it made (`-All` for everything) |

### Git

| Command | Description |
| --- | --- |
| `gs` | git status |
| `ga` | git add . |
| `gcmsg <msg>` | git commit -m |
| `gpush` / `gpull` | git push / pull |
| `gcl <repo>` | git clone |
| `gcom <msg>` | git add . + commit |
| `lazyg <msg>` | git add . + commit + push |
| `g` | zoxide jump to github directory |

### Files & Navigation

| Command | Description |
| --- | --- |
| `la` / `ll` / `lt` | eza listings (hidden, long+git, tree); `ls` stays the built-in Get-ChildItem |
| `bcat <file>` | Syntax-highlighted viewer (bat); `cat` stays the built-in Get-Content |
| `ff <name>` | Find files recursively |
| `nf <name>` | Create new file |
| `mkcd <dir>` | Create directory and cd into it |
| `touch <file>` | Create file or update timestamp |
| `trash <path>` | Move to Recycle Bin (reports when it was cancelled or the drive has no Recycle Bin); refuses in SSH, WinRM and service sessions, where Windows would delete permanently |
| `extract <file> [-Force]` | Universal extractor (.zip, .tar, .gz, .7z, .rar); refuses to overwrite existing files without `-Force` |
| `file <path>` | Identify file type via magic bytes |
| `sizeof <path>` | Human-readable file/directory size |
| `docs` / `dtop` | Jump to Documents / Desktop |
| `cdb [N]` | cd back N entries in history (default 1, previous dir) |
| `cdh` | List the cd history stack (most-recent first) |

### Unix-like

| Command | Description |
| --- | --- |
| `grep <regex> [dir]` | Search for pattern in files (ripgrep) |
| `head <path> [n]` | First n lines of file |
| `tail <path> [n] [-f]` | Last n lines of file |
| `sed <file> <find> <replace>` | Find and replace in file; keeps the file's encoding and writes `<file>.bak` |
| `which <cmd>` | Show command path |
| `pkill <name>` | Kill processes by name (asks before stopping wildcard matches; refuses match-everything patterns and core Windows processes) |
| `pgrep <name>` | List processes by name |
| `export <name> <value>` | Set environment variable |

### System & Network

| Command | Description |
| --- | --- |
| `admin` / `su` | Open elevated terminal |
| `pubip` | Public IP address |
| `localip` | Local IPv4 addresses |
| `uptime` | System uptime |
| `sysinfo` | Detailed system info |
| `df` | Disk volumes |
| `flushdns` | Clear DNS cache |
| `ports` | Listening TCP ports |
| `checkport <host> <port>` | Test TCP connectivity |
| `portscan <host> [-Ports]` | Quick TCP port scan (15 common ports) |
| `tlscert <domain> [port]` | Check TLS certificate expiry, details, and validation errors |
| `ipinfo [ip]` | IP geolocation lookup over HTTPS (no args = your IP) |
| `whois <domain>` | WHOIS domain lookup (registrar, dates, nameservers) |
| `nslook <domain> [type]` | DNS lookup (A, MX, TXT, etc.) |
| `env [pattern] [-ShowValues]` | Search/list environment variables; secret-looking values are masked unless `-ShowValues` |
| `svc [name] [-Count n] [-Live]` | htop-like process viewer |
| `eventlog [n]` | Last n event log entries (default 20) |
| `path` | Display PATH entries one per line |
| `weather [city]` | Quick weather lookup |
| `speedtest` | Download speed test |
| `wifipass [ssid] [-Reveal]` | List saved WiFi profiles (passwords masked unless `-Reveal`) |
| `hosts` | Open hosts file in elevated editor |
| `Clear-Cache` [-IncludeSystemCaches] | Clear the user temp folder and the legacy Internet Explorer (WinINet) cache after confirmation; refuses a `TEMP` that is not a `Temp`/`Tmp` folder (or a Remote Desktop session folder such as `Temp\2`) and keeps going past files in use. `-IncludeSystemCaches` adds `Windows\Temp` and `Prefetch` (admin) |
| `Clear-ProfileCache` | Reset profile caches plus OMP internal caches (settings, state and theme files are kept) |
| `duration` | Show elapsed time of the last executed command |
| `Test-ProfileHealth [-PassThru]` / `psp-doctor` | Diagnose install (version, tools, caches, fonts, PATH, modules); `-PassThru` also emits the result rows for scripting |
| `winutil [-ExpectedSha256 <hash>]` / `winutil -Force` | Fetch [Chris Titus WinUtil](https://github.com/ChrisTitusTech/winutil). Safe-by-default: prints source URL and SHA256, then stops. Re-run with `-ExpectedSha256 '<hash>'` (hash-pinned) or `-Force` (trust without verification) from an elevated shell (`admin`): unelevated, WinUtil relaunches itself from its latest release, which the hash check never saw. The script is hashed and run from memory, and PowerShell still asks for a high-impact confirmation before launch. |
| `harden` | Open [Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security) with an explicit confirmation prompt before launch. |

### Sysadmin

| Command | Description |
| --- | --- |
| `journal [log] [-Count n] [-Follow] [-Level ...]` | Tail Windows Event Log (journalctl-style) |
| `lsblk` | List disks and partitions with volume info |
| `htop` | Interactive process viewer (uses btop/ntop/htop if installed, else svc -Live) |
| `mtr <host>` | Traceroute with per-hop ping stats |
| `fwallow` / `fwblock <name> [-Port n]` | Quick Windows Firewall rule (needs admin; supports `-WhatIf` / `-Confirm`) |
| `Find-FileLocker <path> [-MaxFiles n]` | Show processes holding a file open, or any file inside a folder (Windows Restart Manager API) |
| `Stop-StuckProcess <name\|-Id> [-Tree]` | Escalating kill: `Stop-Process -Force`, then `taskkill /F` (`/T` with `-Tree`) for processes that ignore normal kill |
| `Remove-LockedItem <path> [-Recurse] [-Tree]` | Find lockers, confirm each process, stop them, then delete. For "file is in use" errors |

### Security & Crypto

| Command | Description |
| --- | --- |
| `hash <file> [algo]` | File hash (default SHA256) |
| `checksum <file> <expected>` | Verify file hash |
| `genpass [length]` | Random password (default 20), copied to the clipboard and kept out of Windows clipboard history and cloud sync |
| `b64` / `b64d <text>` | Base64 encode / decode |
| `jwtd <token>` | Decode JWT header and payload |
| `uuid` | Generate random UUID (copies to clipboard) |
| `epoch [value]` | Unix timestamp converter (no args = now) |
| `urlencode` / `urldecode <text>` | URL encode / decode |
| `vtscan <file> [-Upload]` | VirusTotal hash lookup; `-Upload` submits unknown files, which VirusTotal shares with its community and partners |
| `vt <subcommand>` | Full VirusTotal CLI (vt-cli) |
| `nscan <target> [-Mode ...]` | Nmap wrapper with curated scan profiles (Quick/Full/Services/Stealth/Vuln/Ports); Full, Stealth and Vuln ask first. Scan only systems you own or are authorized to test |
| `sigcheck <path>` | Authenticode signature details (file or directory) |
| `ads <path>` | List NTFS alternate data streams |
| `defscan [path] [-Mode Quick/Full]` | Windows Defender scan wrapper |
| `pwnd [password]` | HIBP k-anonymity breach lookup (only first 5 SHA1 chars leave the host); prompts without echo when no argument is given |
| `certcheck <host> [port]` | Full TLS probe: chain and host-name validation, SAN, SHA256 pin, cipher |
| `entropy <file>` | Shannon entropy (detect packed/encrypted payloads) |

### Developer

| Command | Description |
| --- | --- |
| `killport <port>` | Kill process on a TCP port (refuses core Windows processes) |
| `killports` (alias for `Stop-ListeningPort`) | Interactive fzf picker: lists all listening ports (port/PID/process), Tab for multi-select, Enter to kill |
| `http <url> [-Method POST] [-Body '...']` | HTTP requests, auto-formats JSON |
| `prettyjson <file>` | Pretty-print JSON (accepts pipeline input) |
| `hb <file>` | Upload to a PUBLIC paste (bin.christitus.com) and copy the URL; asks first (`-Force`/`-Confirm:$false` to skip) |
| `timer { command }` | Measure execution time |
| `watch { command } [-Interval n]` | Repeat command every n seconds (default 2; like Linux watch) |
| `bak <file>` | Quick timestamped backup |
| `serve [port] [path] [-Bind addr]` | One-line HTTP server (python, or a pinned `http-server` via npx). Loopback only by default; `-Bind 0.0.0.0` shares it on the LAN |
| `gitignore <lang...>` | Generate .gitignore from gitignore.io (Toptal) |
| `gcof` | Fuzzy git branch checkout (fzf) |
| `envload [path] [-AllowSensitive]` | Load .env file into current session; names that change which programs run or where they connect (`PATH`, `NODE_OPTIONS`, `GIT_*`, proxies, ...) are skipped unless `-AllowSensitive` |
| `tldr <cmd>` | Quick command-example lookup (tldr-pages) |
| `repeat <count> { cmd } [-UntilSuccess]` | Repeat a scriptblock |
| `mkvenv [name]` | Create and activate a Python venv |

### Detection & AST

Inspired by the PowerShell VSCode extension: AST-powered tools that understand PowerShell code.

| Command | Description |
| --- | --- |
| `outline <file>` | List functions/params/aliases via AST parser |
| `psym [pattern] [root]` | Symbol search across .ps1 files |
| `lint [path] [-Mode Standard/Strict/Security/CI] [-Fix]` | PSScriptAnalyzer wrapper with presets |
| `Find-DeadCode <file>` | Unused params and same-file uncalled functions |
| `Test-Profile` | Profile diagnostics: version, policy, caches, tools, env |
| `Get-PwshVersions` | Enumerate every installed PowerShell |
| `modinfo <name>` | Module details: path, version(s), exports, signature |
| `psgrep <pattern> [-Kind Command/Variable/String/Function]` | AST-based code search (structural grep) |

### Extensibility

| Command | Description |
| --- | --- |
| `Get-ProfileCommand [-Category ...] [-Name ...]` | Query the command registry |
| `Start-ProfileTour` | Interactive walkthrough of every category |
| `Register-ProfileHook -EventName OnProfileLoad/PrePrompt/OnCd -Action { ... }` | Hook lifecycle events |
| `Register-HelpSection -Title ... -Lines @(...)` | Add a section to `Show-Help` |
| `Register-ProfileCommand -Name ... -Category ... [-Synopsis ...]` | Add to command registry |
| `Add-TrustedDirectory` / `Remove-TrustedDirectory [path]` | Trust a directory and approve its current `.psprc.ps1`; run again after the file changes |
| `Set-TerminalBackground <image> [-Opacity] [-StretchMode] [-Alignment]` | Set WT background image (live + persisted); `-Clear` to remove |

### Docker (when installed)

| Command | Description |
| --- | --- |
| `dps` / `dpa` | Running / all containers |
| `dimg` | List images |
| `dlogs <container>` | Follow container logs |
| `dex <container> [shell]` | Exec into container |
| `dstop [names]` | Stop the named containers, or all running ones (asks first) |
| `dprune` | System prune (asks first) |

### SSH & Remote

| Command | Description |
| --- | --- |
| `ssh <user@host>` | Wraps `ssh.exe` with `ConnectTimeout=10` + keepalive so hung connects fail fast and respond to Ctrl+C (user `-o` values take precedence) |
| `Copy-SshKey` / `ssh-copy-key <user@host>` | Copy SSH key to remote (when ssh installed); skips a key that is already there |
| `keygen [name]` | Generate ED25519 key pair (when ssh installed) |
| `rdp <host>` | Launch RDP session |

### WSL (when `wsl.exe` is installed)

| Command | Description |
| --- | --- |
| `wsl [args]` | Wraps `wsl.exe` and sets tab title to the distro name during the session |
| `Get-WslDistro` | List installed distros with state + version + default flag (pipe-friendly objects) |
| `Enter-WslHere` / `wsl-here [-Distro]` | Open a WSL shell in the current Windows directory (auto path-translated) |
| `Get-WslFile <distro> [path] [-Recurse]` | List files inside a distro via the `\\wsl$\` UNC path; returns FileInfo objects |
| `Show-WslTree` / `wsl-tree <distro> [path] [-Depth N]` | Tree-view of a distro path (uses `eza` when available) |
| `Open-WslExplorer` / `wsl-explorer <distro> [path]` | Open the distro path in Windows Explorer (GUI file browsing) |
| `ConvertTo-WslPath <winpath>` | Translate Windows path to WSL (handles backslash-dropping quirk) |
| `ConvertTo-WindowsPath <wslpath>` | Translate WSL path to Windows |
| `Get-WslIp [-Distro]` | IPv4 of a running distro (for connecting to in-distro services from Windows) |
| `Stop-Wsl [-Distro]` | Shutdown all distros, or terminate one by name |

Tab-complete works on `-Distro` for all of these via live `Get-WslDistro` lookup.

### Clipboard

| Command | Description |
| --- | --- |
| `cpy <text>` | Copy to clipboard |
| `pst` | Paste from clipboard |
| `icb` | Insert clipboard into prompt (never executes) |

## Compared to alternatives

PowerShellPerfect bundles a **prompt** (via Oh My Posh), a **command suite**, and a **wizard-driven installer** in one. The prompt engines below are great at theming but aren't command suites; ChrisTitusTech's profile is the closest peer.

| | **PowerShellPerfect** | [ChrisTitusTech](https://github.com/ChrisTitusTech/powershell-profile) | [Oh My Posh](https://ohmyposh.dev) | [Starship](https://starship.rs) |
| --- | :---: | :---: | :---: | :---: |
| p10k-style install wizard | ✅ | — | — | — |
| 145+ commands (Unix-style + git/net/security/sysadmin) | ✅ | partial | — | — |
| Prompt theming | ✅ (via Oh My Posh) | ✅ (via Oh My Posh) | ✅ (engine) | ✅ (engine) |
| Self-update checked against published hashes | ✅ | — (a hash compare only detects changes) | n/a | n/a |
| Full uninstall | ✅ | — | n/a | n/a |
| PS 5.1 + PS 7 (guarded forks) | ✅ | ✅ | ✅ | ✅ (cross-shell) |
| Secret-scrubbed history | ✅ | — | — | — |
| Customization surfaces | `user-settings.json` + `profile_user.ps1` + `plugins/` + `.psprc.ps1` | profile edits | themes | `starship.toml` |

## Limitations

- **Windows only.** The profile and installer target Windows 10 1809+ and Windows 11 with Windows PowerShell 5.1 or PowerShell 7; they are not built for Linux or macOS.
- **Unsigned scripts.** Releases are checksummed and attested, not Authenticode-signed. Under an `AllSigned` execution policy you have to sign them yourself (setup offers to switch the CurrentUser policy to `RemoteSigned`).
- **Constrained Language Mode / WDAC / AppLocker.** Not supported: the profile compiles helper types with `Add-Type` and calls .NET APIs that Constrained Language Mode blocks, so it will not load under such a policy.
- **Single user, not a sandbox.** Commands run with your rights. `user-settings.json`, `profile_user.ps1`, `plugins\` and approved `.psprc.ps1` files are code you trust; protect them like any dotfile.
- **Third-party services.** Some commands send data to outside services (listed in [SECURITY.md](SECURITY.md#data-flows)); nothing is sent unless you run those commands.
- **Tested environments.** CI uses GitHub's Windows Server images with English display language; Windows 10/11 client and other display languages are checked by hand.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Setup blocked by Windows Defender (Controlled Folder Access), often shown as `Could not find file` | Allow PowerShell through for the duration of the install and remove it afterwards (see [Install](#install-alternatives)). Moving the clone does not help: it is the write to `Documents` that is blocked. |
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. (The install commands run an in-memory scriptblock, which isn't subject to the script-file execution policy.) |
| Prompt shows boxes / missing glyphs | The terminal font isn't a Nerd Font. Set your Windows Terminal profile font to the one setup installed (e.g. *CaskaydiaCove Nerd Font*) and restart WT. |
| `oh-my-posh` not found right after install | Open a new terminal, or run `. reload` in the current one; confirm with `psp-doctor`. |
| Warning that Oh My Posh at `<path>` is older than 29.35.1 (CVE-2026-73505) | Builds before 29.35.1 run template code taken from folder names, so the prompt never uses them. Run `Update-Tools` to install the portable build, which the prompt then uses, or update or remove that install. |
| Windows Terminal settings keep changing back | Another tool also writes `settings.json`. Pick one owner: set `windowsTerminal.manage` to `false` in `user-settings.json` to let the other tool have it, or stop the other tool. `psp-doctor` shows whether the file is a symlink and who manages it. |
| A `.psprc.ps1` stopped loading | It changed since you approved it (a pull, a checkout). Review it, then run `Add-TrustedDirectory` in that directory again. `psp-doctor` lists directories that need re-approval. |
| Turned a feature off in the wizard but it still loads | Check the `features` block in `user-settings.json`, then restart PowerShell. |
| Prompt feels slow | Run `psp-doctor`: a WARN on Oh My Posh means the MSIX build is in use (about 30 ms per prompt for package activation), and `Update-Tools` switches to the portable build. In git repositories each prompt runs `git status`; keep `features.fastGitPrompt` on so themes do not add git calls for upstream icons and stash counts. |
| A theme is refused because it "can run commands on every prompt" | The message names what was found (a `command` segment, a template function such as `cmd`, or `extends`). Read the theme, then set `theme.allowCommands` to `true` in `user-settings.json` if you trust it. |
| Something feels off | Run `psp-doctor` (alias for `Test-ProfileHealth`): OK/WARN/FAIL per check across version, tools, caches, fonts, PATH, and modules. Setup logs are in `%LOCALAPPDATA%\PowerShellProfile\logs`. |

## Tests

Everything in `tests/` is tracked. Run the suites from a normal (non-elevated) shell: `unit.ps1`, `test.ps1`, `ci-functional.ps1`, `rawhunt.ps1` and the test steps of `locallab.ps1` refuse to run elevated unless you pass `-AllowElevated`, which is meant for disposable VMs and CI runners. `lint.ps1` and `smoke.ps1` do not check.

| File | Run | Purpose |
| --- | --- | --- |
| `tests/unit.ps1` | `pwsh -NoProfile -File tests/unit.ps1` (also with `powershell`) | Regression tests: Windows Terminal change records, uninstall semantics, `.psprc.ps1` approval, hash gates in `Update-Profile` and `setup.ps1`, wizard input checks, encoding, command guards. Fully sandboxed, no network |
| `tests/lint.ps1` | `pwsh -NoProfile -File tests/lint.ps1` | PSScriptAnalyzer 1.25.0 with `PSScriptAnalyzerSettings.psd1`, as in CI. Installs that version for the current user when it is missing; `-NoInstall` fails instead |
| `tests/smoke.ps1` | `pwsh -NoProfile -File tests/smoke.ps1` | Sandboxed non-interactive load with a load-time budget |
| `tests/test.ps1` | `pwsh -NoProfile -File tests/test.ps1` | Full local gate: lint, PS5 parse, static scans, sandboxed install/uninstall/lifecycle, both regression runs, every command in a sandbox, coverage audit. Commands that need the internet are skipped offline |
| `tests/ci-functional.ps1` | GitHub Actions `functional` job | Install via `setup.ps1 -LocalRepo -CiMode` into a sandbox, run the command matrix with third-party endpoints mocked, coverage audit (at least 60% of exports executed), uninstall. `-LiveNetwork` uses the real endpoints (weekly scheduled run) |
| `tests/rawhunt.ps1` | `pwsh -NoProfile -File tests/rawhunt.ps1 -AllowSideEffects` | Not sandboxed: exercises the real profile with real I/O (live services, clipboard, a public paste upload, winget). Opt-in only |
| `tests/locallab.ps1` | `pwsh -NoProfile -File tests/locallab.ps1` | Dev harness: runs the checks and optionally installs this checkout (`-Install`, `-FullInstall`, `-Wizard`); `-Restore` copies back only the two profile files from its last backup in `%TEMP%`, not Windows Terminal settings or caches |

CI (`.github/workflows/ci.yml`) runs three jobs on every push/PR: **lint** (PSScriptAnalyzer, PS5 parse, sandboxed loads with a load-time budget, static scans), **install-flow** (config and pin checks, curated data, setup structure, regression tests on PS 5.1 and 7), and **functional** (the end-to-end suite above). `scheduled.yml` runs the functional suite against the real endpoints every week and checks that every pinned download still matches its hash; `release.yml` publishes tagged releases. Which jobs block a merge is a repository ruleset setting, not part of the workflow files.

## Roadmap

Further ideas:

- Per-distro WSL auto-configuration (install common tools when a new distro is detected).
- `profile_user.ps1` scaffolder (`New-ProfileOverride` generates a commented starter file).
- Auto-fix mode for `psp-doctor` / `Test-ProfileHealth`: today it *diagnoses* (tools, caches, fonts, PATH, modules); add an opt-in `-Fix` that repairs the common issues it surfaces.
- Live theme preview (render OMP themes inline during picker rather than just listing names).

## License

MIT, see [LICENSE](LICENSE). The profile is derived from [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile), so the license carries his 2025 copyright next to this project's. Use it, fork it, take what you need; copies and substantial portions must keep the copyright and permission notice.

Not affiliated with or endorsed by Microsoft.
