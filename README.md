# PowerShellPerfect

[![CI](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)

> A modern PowerShell profile for Windows. `irm | iex` gives you 130+ Unix-style commands, a tuned Oh My Posh prompt, fuzzy search, zoxide, and a `p10k configure`-style install wizard - in one window, with a full uninstall, self-update, and CI behind it.

```powershell
irm "https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1" | iex
```

Run that in an **elevated** PowerShell window. The terminal restarts when setup finishes (new tab in Windows Terminal, or a new window otherwise). For the best experience use [PowerShell 7+](https://github.com/PowerShell/PowerShell).

## At a glance

| | |
| --- | --- |
| **130+ commands** | git, files, unix tools, network, security, developer, sysadmin, WSL, docker, ssh, clipboard |
| **Install wizard** | Pick OMP theme, WT color scheme (8 curated), Nerd Font (6 curated), tab-bar + window chrome, terminal appearance (opacity, font size, cursor shape, scrollbar, padding, history size, acrylic), PSReadLine colors (default/scheme-derived/skip), background, editor, telemetry opt-out, feature toggles. `-Resume` on interrupt. |
| **Transient prompt** | Scrollback shows collapsed `$`; new input gets the full OMP prompt (opt-in feature flag) |
| **Self-updating** | `Update-Profile` syncs profile + theme + WT config with SHA-256 verification. Survives custom `profile_user.ps1` + `user-settings.json`. |
| **Full uninstall** | `Uninstall-Profile` restores WT, removes caches, `-RemoveTools` drops winget packages, `-All` wipes everything |
| **PS5 + PS7** | Installs to both profile directories; every PS5/PS7 API fork is guarded |
| **Sandbox-safe** | CI + AI agents auto-detected; network calls and UI setup suppressed so sessions don't hang |
| **Hardened** | Passwords/tokens filtered from PSReadLine history; `Merge-JsonObject` + WT settings merge are unit-tested in CI |
| **Tested** | Lint, PS5 parse, 100% command-coverage audit, full install + uninstall sandbox - all run on every PR |

Inspired by [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile); design cues from [powerlevel10k](https://github.com/romkatv/powerlevel10k) and [starship](https://github.com/starship/starship).

## Install

> **Recommended for Oh My Posh:** Install the x64 MSI from the [releases](https://github.com/JanDeDobbeleer/oh-my-posh/releases) page (see [Oh My Posh](https://github.com/JanDeDobbeleer/oh-my-posh)) instead of `winget`/Store—this profile preserves a direct install and avoids the WindowsApps path. If you already have the MSI install, setup leaves it as is.

### Manual Setup

```powershell
git clone https://github.com/26zl/PowerShellPerfect.git
cd PowerShellPerfect
.\setup.ps1
```

`setup.ps1` auto-detects the local clone when run from the repo directory, so the profile, `theme.json`, and `terminal-config.json` are copied from your working tree instead of downloaded from GitHub. It installs the profile to both PS5 and PS7 directories as part of step [1/10]; a separate `.\setprofile.ps1` run is only needed if you later want a quick profile-only refresh without re-running the full installer.

When running locally you can override terminal defaults (not available via `irm | iex`):

```powershell
.\setup.ps1 -Opacity 85 -ColorScheme "One Half Dark" -FontSize 12
```

> **Controlled Folder Access:** If Windows Defender blocks the setup, allow PowerShell through:
>
> ```powershell
> Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
> Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\PowerShell\7\pwsh.exe"
> ```

## Updates

```powershell
Update-Profile      # Sync profile, theme, caches, and Windows Terminal settings
Update-PowerShell   # Check for new PowerShell 7 releases
Update-Tools        # Update winget-managed tools; direct/MSI Oh My Posh installs are preserved
```

`Update-Profile` requires hash input by default — either pass the hash the previous run printed as `-ExpectedSha256 '<hash>'` (ensures file integrity and a reproducible apply) or `-SkipHashCheck` to bypass. For actual trust pinning against a specific upstream commit, verify the commit SHA out-of-band (browser, signed tag) before using `-ExpectedSha256`; the hash the tool prints for a first-time download is computed over what was just fetched, so it confirms "this is what I just downloaded" but not "this is what upstream really published". Use `-Force` to re-apply settings even when nothing changed upstream.

## Uninstall

Remove the profile, caches, and Windows Terminal changes:

```powershell
Uninstall-Profile              # Core cleanup: profile files, caches, WT restore, PSFzf
Uninstall-Profile -RemoveTools # Also uninstall managed CLI tools (including direct/MSI Oh My Posh when detected)
Uninstall-Profile -All         # Remove everything including tools, fonts, and user data
Uninstall-Profile -All -HardResetWindowsTerminal # Same as -All, but also delete WT settings.json so WT recreates factory defaults
```

Optional switches: `-RemoveTools` (winget-managed tools plus direct/MSI Oh My Posh when registered as MSI), `-RemoveUserData` (profile_user.ps1, user-settings.json), `-RemoveFonts` (Nerd Fonts, requires admin), `-All` (everything), `-HardResetWindowsTerminal` (delete WT settings.json and backups so Windows Terminal recreates defaults). Supports `-WhatIf` to preview without making changes.

## Customization

Four extension points survive updates. From simplest to most powerful:

- **`user-settings.json`** (`%LOCALAPPDATA%\PowerShellProfile\`) - JSON overrides. Keys:
  - `theme`, `windowsTerminal`, `defaults`, `keybindings` - terminal and OMP theme
  - `defaults.backgroundImage` / `backgroundImageOpacity` / `backgroundImageStretchMode` / `backgroundImageAlignment` - Windows Terminal background image
  - `features` - toggle heavy/optional behavior: `psfzf`, `predictions`, `startupMessage`, `perDirProfiles` (all `true` by default), `transientPrompt` (collapses previous prompt on Enter; default `false`, customize via `$script:PSP.TransientPrompt = { ... }` in `profile_user.ps1`), `updateCheck` (notifies once a week when main has advanced past the applied commit; default `false` so `irm | iex` in scripts does not trigger a surprise network call)
  - `commandOverrides` - redefine any command without editing source: `{ "gs": "git status --short" }`. Opt-in: set `features.commandOverrides = true` in the same file. Default off because it compiles JSON strings into executable scriptblocks.
  - `trustedDirs` - directories whose `.psprc.ps1` auto-loads (managed by `Add-TrustedDirectory`)
- **`profile_user.ps1`** (`Split-Path $PROFILE`) - PowerShell overrides dot-sourced last: aliases, functions, editor, colors, modules
- **`plugins/*.ps1`** (`%LOCALAPPDATA%\PowerShellProfile\plugins\`) - drop-in plugins. Each file is auto-loaded; errors are isolated per plugin
- **`.psprc.ps1`** (per directory) - project-specific profile. Auto-loads on `cd` into a directory registered with `Add-TrustedDirectory`. Use `function global:foo` / `Set-Alias -Scope Global` for lasting definitions; `$env:VAR` always persists

Call `Start-ProfileTour` for a live walkthrough, or `Get-ProfileCommand -Category <cat>` to list what's available.

### Background Image

```powershell
Set-TerminalBackground "$env:USERPROFILE\Pictures\bg.png" -Opacity 0.1
Set-TerminalBackground -Clear
```

Default fills the whole tab with low opacity (typical backdrop). For a small corner watermark, add `-ResizeWidth 200 -StretchMode none -Alignment bottomRight`. Persisted to `user-settings.json`, applied live to WT.

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
| `Ctrl+A` | Select entire terminal buffer (Windows Terminal) |

## Commands

Run `Show-Help` in your terminal for a colored version of this list.

### Profile & Updates

| Command | Description |
| --- | --- |
| `edit <file>` | Open file in preferred editor |
| `Edit-Profile` / `ep` | Open profile in preferred editor |
| `Update-Profile` | Sync profile, theme, caches, and WT settings |
| `Update-PowerShell` | Check for new PowerShell 7 releases |
| `Update-Tools` | Update winget-managed tools; direct/MSI Oh My Posh installs are preserved |
| `Invoke-ProfileWizard` / `Reconfigure-Profile` | Re-run the install wizard to pick a new theme / scheme / font / feature set |
| `reload` | Reload the PowerShell profile |
| `Show-Help` | Show help in terminal |
| `Uninstall-Profile` | Remove profile, caches, and WT changes (`-All` for everything) |

### Git

| Command | Description |
| --- | --- |
| `gs` | git status |
| `ga` | git add . |
| `gc <msg>` | git commit -m |
| `gpush` / `gpull` | git push / pull |
| `gcl <repo>` | git clone |
| `gcom <msg>` | git add . + commit |
| `lazyg <msg>` | git add . + commit + push |
| `g` | zoxide jump to github directory |

### Files & Navigation

| Command | Description |
| --- | --- |
| `ls` / `la` / `ll` / `lt` | eza listings (icons, hidden, long+git, tree) |
| `cat <file>` | Syntax-highlighted viewer (bat) |
| `ff <name>` | Find files recursively |
| `nf <name>` | Create new file |
| `mkcd <dir>` | Create directory and cd into it |
| `touch <file>` | Create file or update timestamp |
| `trash <path>` | Move to Recycle Bin |
| `extract <file>` | Universal extractor (.zip, .tar, .gz, .7z, .rar) |
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
| `sed <file> <find> <replace>` | Find and replace in file |
| `which <cmd>` | Show command path |
| `pkill <name>` | Kill processes by name |
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
| `tlscert <domain> [port]` | Check TLS certificate expiry and details |
| `ipinfo [ip]` | IP geolocation lookup (no args = your IP) |
| `whois <domain>` | WHOIS domain lookup (registrar, dates, nameservers) |
| `nslook <domain> [type]` | DNS lookup (A, MX, TXT, etc.) |
| `env [pattern]` | Search/list environment variables |
| `svc [name] [-Count n] [-Live]` | htop-like process viewer |
| `eventlog [n]` | Last n event log entries (default 20) |
| `path` | Display PATH entries one per line |
| `weather [city]` | Quick weather lookup |
| `speedtest` | Download speed test |
| `wifipass [ssid]` | Show saved WiFi passwords |
| `hosts` | Open hosts file in elevated editor |
| `Clear-Cache` [-IncludeSystemCaches] | Clear user temp/browser caches (optionally system dirs) |
| `Clear-ProfileCache` | Reset profile caches plus OMP internal caches |
| `duration` | Show elapsed time of the last executed command |
| `Test-ProfileHealth` / `psp-doctor` | Diagnose install (tools, caches, fonts, PATH, modules) |
| `winutil [-ExpectedSha256 <hash>]` / `winutil -Force` | Fetch [Chris Titus WinUtil](https://github.com/ChrisTitusTech/winutil). Safe-by-default: prints source URL and SHA256, then stops. Re-run with `-ExpectedSha256 '<hash>'` (hash-pinned) or `-Force` (trust without verification) to stage execution, and PowerShell still asks for a high-impact confirmation before launch. |
| `harden` | Open [Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security) with an explicit confirmation prompt before launch. |

### Sysadmin

| Command | Description |
| --- | --- |
| `journal [log] [-Count n] [-Follow] [-Level ...]` | Tail Windows Event Log (journalctl-style) |
| `lsblk` | List disks and partitions with volume info |
| `htop` | Interactive process viewer (uses btop/ntop/htop if installed, else svc -Live) |
| `mtr <host>` | Traceroute with per-hop ping stats |
| `fwallow` / `fwblock <name> [-Port n]` | Quick Windows Firewall rule (needs admin; supports `-WhatIf` / `-Confirm`) |
| `Find-FileLocker <path>` | Show processes holding a file/folder lock (uses Windows Restart Manager API) |
| `Stop-StuckProcess <name\|-Id>` | Escalating kill: `Stop-Process -Force` → `taskkill /F` → `/F /T` for processes that ignore normal kill |
| `Remove-LockedItem <path> [-Recurse]` | Find lockers, kill them, then delete. For "file is in use" errors |

### Security & Crypto

| Command | Description |
| --- | --- |
| `hash <file> [algo]` | File hash (default SHA256) |
| `checksum <file> <expected>` | Verify file hash |
| `genpass [length]` | Random password (default 20), copies to clipboard |
| `b64` / `b64d <text>` | Base64 encode / decode |
| `jwtd <token>` | Decode JWT header and payload |
| `uuid` | Generate random UUID (copies to clipboard) |
| `epoch [value]` | Unix timestamp converter (no args = now) |
| `urlencode` / `urldecode <text>` | URL encode / decode |
| `vtscan <file>` | VirusTotal scan + open in browser |
| `vt <subcommand>` | Full VirusTotal CLI (vt-cli) |
| `nscan <target> [-Mode ...]` | Nmap wrapper with curated scan profiles (Quick/Full/Services/Stealth/Vuln/Ports) |
| `sigcheck <path>` | Authenticode signature details (file or directory) |
| `ads <path>` | List NTFS alternate data streams |
| `defscan [path] [-Mode Quick/Full]` | Windows Defender scan wrapper |
| `pwnd <password>` | HIBP k-anonymity breach lookup (only first 5 SHA1 chars leave the host) |
| `certcheck <host> [port]` | Full TLS probe: chain, SAN, SHA256 pin, cipher |
| `entropy <file>` | Shannon entropy (detect packed/encrypted payloads) |

### Developer

| Command | Description |
| --- | --- |
| `killport <port>` | Kill process on a TCP port |
| `killports` (alias for `Stop-ListeningPort`) | Interactive fzf picker: lists all listening ports (port/PID/process), Tab for multi-select, Enter to kill |
| `http <url> [-Method POST] [-Body '...']` | HTTP requests, auto-formats JSON |
| `prettyjson <file>` | Pretty-print JSON (accepts pipeline input) |
| `hb <file>` | Upload to hastebin, copy URL |
| `timer { command }` | Measure execution time |
| `watch { command } [-Interval n]` | Repeat command every n seconds (default 2; like Linux watch) |
| `bak <file>` | Quick timestamped backup |
| `serve [port] [path]` | One-line HTTP server (python or npx) |
| `gitignore <lang...>` | Generate .gitignore from gitignore.io |
| `gcof` | Fuzzy git branch checkout (fzf) |
| `envload [path]` | Load .env file into current session |
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
| `Add-TrustedDirectory` / `Remove-TrustedDirectory [path]` | Trust a dir so `.psprc.ps1` auto-loads |
| `Set-TerminalBackground <image> [-Opacity] [-StretchMode] [-Alignment]` | Set WT background image (live + persisted); `-Clear` to remove |

### Docker (when installed)

| Command | Description |
| --- | --- |
| `dps` / `dpa` | Running / all containers |
| `dimg` | List images |
| `dlogs <container>` | Follow container logs |
| `dex <container> [shell]` | Exec into container |
| `dstop` | Stop all containers |
| `dprune` | System prune |

### SSH & Remote

| Command | Description |
| --- | --- |
| `ssh <user@host>` | Wraps `ssh.exe` with `ConnectTimeout=10` + keepalive so hung connects fail fast and respond to Ctrl+C (user `-o` values take precedence) |
| `Copy-SshKey` / `ssh-copy-key <user@host>` | Copy SSH key to remote (when ssh installed) |
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

## Install Wizard

Inspired by [powerlevel10k](https://github.com/romkatv/powerlevel10k)'s `p10k configure`. Auto-runs on interactive installs; `setup.ps1 -SkipWizard` bypasses it (and CI/AI-agent environments always skip).

```powershell
# Force-run the wizard during install:
.\setup.ps1 -Wizard

# Skip and use repo defaults:
.\setup.ps1 -SkipWizard

# Resume a half-finished wizard (state in %TEMP%\psp-wizard-state.json):
.\setup.ps1 -Resume

# Re-run the wizard any time after install (downloads latest setup.ps1 + elevates):
Reconfigure-Profile
```

**Steps**:

1. **Oh My Posh theme** — live fetch from [JanDeDobbeleer/oh-my-posh/themes](https://github.com/JanDeDobbeleer/oh-my-posh) via GitHub API. Pick by number or partial name. Network failure falls back to `pure`.
2. **Color scheme** — curated 8-pack: Breaking Bad, Tokyo Night, Gruvbox Dark, Dracula, Catppuccin Mocha, Nord, One Half Dark, Solarized Dark. Full scheme definitions embedded; no extra network.
3. **Nerd Font** — Caskaydia, JetBrainsMono, FiraCode, Meslo, Hack, or Iosevka. Fetches latest release tag from [ryanoasis/nerd-fonts](https://github.com/ryanoasis/nerd-fonts/releases) automatically.
4. **Tab bar color** — presets: scheme-match (seamless), pure black, warm brown, custom hex, or skip. Applied via a custom WT theme definition.
5. **Background image** — optional path + opacity (0.05-0.50). Skipped by default.
6. **Feature toggles** — `psfzf`, `predictions`, `startupMessage`, `perDirProfiles`, `commandOverrides` — y/n per item with sensible defaults.

**Design**:

- All choices persist to `user-settings.json` so `Update-Profile` re-applies them; nothing hardcoded into the profile.
- Summary screen at the end with "apply all?" confirmation.
- State file enables `-Resume` if the wizard is interrupted or cancelled.
- All 130+ commands and the extensibility system ship regardless of wizard choices; the wizard only selects cosmetics and opt-ins.

## Tests

Everything in `tests/` is tracked and runs locally in seconds.

| File | Run | Purpose |
| --- | --- | --- |
| `tests/lint.ps1` | `pwsh -NoProfile -File tests/lint.ps1` | PSScriptAnalyzer with the exact rule set CI enforces |
| `tests/test.ps1` | `pwsh -NoProfile -File tests/test.ps1` | Full quality gate: lint, PS5 parse, BOM/secret/path scans, install + uninstall sandboxes, 100% command-coverage audit. A trap + `PowerShell.Exiting` handler sweeps any `psp-*` sandbox dirs from `%TEMP%` if you Ctrl+C mid-run. |
| `tests/rawhunt.ps1` | `pwsh -NoProfile -File tests/rawhunt.ps1` | Loads the real profile and exercises every function with real I/O (file ops, network, crypto, git, clipboard, caching, WT settings) |
| `tests/locallab.ps1` | `pwsh -NoProfile -File tests/locallab.ps1 -Wizard` | Dev harness: runs all the above and optionally drives `setup.ps1 -LocalRepo -Wizard` end-to-end; `-Restore` rolls back to the last sandbox backup |
| `tests/ci-functional.ps1` | GitHub Actions `functional` job | What CI runs: full install via `setup.ps1 -LocalRepo`, profile load under `$env:CI`, uninstall sandbox, and a coverage audit that refuses to pass unless every function/alias has an `Invoke-CommandProbe` entry |

CI (`.github/workflows/ci.yml`) runs three jobs on every push/PR: **lint** (rule set + secret scan + PS5 parse), **install-flow** (JSON config + `Merge-JsonObject` unit tests + curated-scheme/font validation), **functional** (the full end-to-end). Both `lint` and `install-flow` are required status checks.

## Roadmap

Further ideas:

- Per-distro WSL auto-configuration (install common tools when a new distro is detected).
- `profile_user.ps1` scaffolder (`New-ProfileOverride` generates a commented starter file).
- `psp doctor` command - runs `Test-Profile` + environment checks + auto-fixes common issues.
- Live theme preview (render OMP themes inline during picker rather than just listing names).

## License

MIT. Use it, fork it, rip out what you need. Credit appreciated, not required.
