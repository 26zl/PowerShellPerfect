# PowerShellPerfect

[![CI](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/PowerShellPerfect/actions/workflows/ci.yml)

A PowerShell profile made to make a CLI nerd's life easier. Brings the Linux terminal experience to Windows - grep, cat, ls with icons, fuzzy search, zoxide, and 60+ utility commands out of the box. One command installs everything and keeps it updated. Works on both PowerShell 5.1 and 7+.

**Why use this?**

- **One command, fully configured** - installs 6 tools, Nerd Fonts, Oh My Posh theme, and Windows Terminal settings in one run
- **Self-updating** - profile, theme, and terminal config sync from upstream with hash verification
- **AI/CI sandbox safe** - detects non-interactive environments and suppresses network calls and UI setup automatically
- **PS5 + PS7** - installs to both profile directories and handles every API difference between editions
- **Hardened** - sensitive commands filtered from PSReadLine history; no secrets in source
- **Fast startup** - prompt renders directly from a local Oh My Posh theme; only zoxide init is cached
- **Survives updates** - personal overrides in `profile_user.ps1` and `user-settings.json` are never touched

Originally forked and inspired by [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile).

## Install

Run in an **elevated** PowerShell window:

```powershell
irm "https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1" | iex
```

The terminal restarts automatically when setup finishes (new tab in Windows Terminal, or new window otherwise). For the best experience use [PowerShell 7](https://github.com/PowerShell/PowerShell).

> **Recommended for Oh My Posh:** Install the x64 MSI release manually instead of relying on `winget`/Store (`WindowsApps`/MSIX). This repo preserves a direct MSI install and avoids the WindowsApps path when possible.

If Oh My Posh is already installed directly via MSI, setup preserves that install instead of forcing it back through the WindowsApps/MSIX path.

### Manual Setup

```powershell
git clone https://github.com/26zl/PowerShellPerfect.git
cd PowerShellPerfect
.\setup.ps1
.\setprofile.ps1
```

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

`Update-Profile` requires hash verification by default. Confirm with `-ExpectedSha256 '<hash>'`, or use `-SkipHashCheck` to bypass. Use `-Force` to re-apply settings even when nothing changed upstream.

## Uninstall

Remove the profile, caches, and Windows Terminal changes:

```powershell
Uninstall-Profile              # Core cleanup: profile files, caches, WT restore, PSFzf
Uninstall-Profile -RemoveTools # Also uninstall managed CLI tools (Oh My Posh, eza, etc.)
Uninstall-Profile -All         # Remove everything including tools, fonts, and user data
Uninstall-Profile -All -HardResetWindowsTerminal # Same as -All, but also delete WT settings.json so WT recreates factory defaults
```

Optional switches: `-RemoveTools` (winget packages), `-RemoveUserData` (profile_user.ps1, user-settings.json), `-RemoveFonts` (Nerd Fonts, requires admin), `-All` (everything), `-HardResetWindowsTerminal` (delete WT settings.json and backups so Windows Terminal recreates defaults). Supports `-WhatIf` to preview without making changes.

## Customization

Two files survive updates and override everything:

- **`profile_user.ps1`** (`Split-Path $PROFILE`) - PowerShell overrides: aliases, functions, editor, colors, modules
- **`user-settings.json`** (`%LOCALAPPDATA%\PowerShellProfile\`) - Terminal overrides: theme, opacity, font, keybindings

Both are created automatically during setup. `profile_user.ps1` is dot-sourced last so your settings always win.

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
| `winutil` | Launch [Chris Titus WinUtil](https://github.com/ChrisTitusTech/winutil) |
| `harden` | Open [Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security) |

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

### Developer

| Command | Description |
| --- | --- |
| `killport <port>` | Kill process on a TCP port |
| `http <url> [-Method POST] [-Body '...']` | HTTP requests, auto-formats JSON |
| `prettyjson <file>` | Pretty-print JSON (accepts pipeline input) |
| `hb <file>` | Upload to hastebin, copy URL |
| `timer { command }` | Measure execution time |
| `watch { command } [-Interval n]` | Repeat command every n seconds (default 2; like Linux watch) |
| `bak <file>` | Quick timestamped backup |

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
| `Copy-SshKey` / `ssh-copy-key <user@host>` | Copy SSH key to remote (when ssh installed) |
| `keygen [name]` | Generate ED25519 key pair (when ssh installed) |
| `rdp <host>` | Launch RDP session |

### Clipboard

| Command | Description |
| --- | --- |
| `cpy <text>` | Copy to clipboard |
| `pst` | Paste from clipboard |
| `icb` | Insert clipboard into prompt (never executes) |
