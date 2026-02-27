# PowerShell Profile

[![PSScriptAnalyzer](https://github.com/26zl/PowerShellPerfect/actions/workflows/lint.yml/badge.svg)](https://github.com/26zl/PowerShellPerfect/actions/workflows/lint.yml)

A PowerShell profile with Oh My Posh theming, Unix-like aliases, git shortcuts, and useful utilities. Originally inspired by and forked: [ChrisTitusTech/powershell-profile](https://github.com/ChrisTitusTech/powershell-profile).

## Quick Install

Run this in an **elevated** PowerShell window:

```powershell
irm "https://github.com/26zl/PowerShellPerfect/raw/main/setup.ps1" | iex
```

Installs Oh My Posh, eza, zoxide, fzf, bat, ripgrep, Nerd Fonts, configures Windows Terminal, and copies the profile into place (both PS5 and PS7). Restart your terminal after running.

> **Note:** The profile works on both PowerShell 5.1 and 7+, but some features are PS7-only. For the best experience use [PowerShell 7](https://github.com/PowerShell/PowerShell).
>
> **Controlled Folder Access:** If Windows Defender blocks the setup, allow PowerShell through Controlled Folder Access (run as admin):
>
> ```powershell
> Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
> Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\PowerShell\7\pwsh.exe"
> ```

### Manual Setup

```powershell
git clone https://github.com/26zl/PowerShellPerfect.git
cd powershell-profile
.\setup.ps1
.\setprofile.ps1
```

When running `setup.ps1` locally you can override Windows Terminal defaults:

```powershell
.\setup.ps1 -Opacity 85 -ColorScheme "One Half Dark" -FontSize 12
```

| Parameter | Default | Description |
| --- | --- | --- |
| `-Opacity` | from `terminal-config.json` | Background opacity (0–100) |
| `-ColorScheme` | from `theme.json` | Color scheme name |
| `-FontSize` | from `terminal-config.json` | Font size in points |

These parameters are not available with the `irm | iex` one-liner.

## Updates

```powershell
Update-Profile      # Sync profile, theme, caches, and Windows Terminal settings
Update-PowerShell   # Check for new PowerShell releases
Update-Tools        # Update Oh My Posh, eza, zoxide, fzf, bat, and ripgrep
```

`Update-Profile` requires hash verification by default — confirm with `-ExpectedSha256 '<hash>'`, or use `-SkipHashCheck` to bypass. Use `-Force` to re-apply settings even when upstream files haven't changed.

## Customization

Add personal customizations to `profile_user.ps1` in the same directory as your profile (`Split-Path $PROFILE`). This file is dot-sourced last, so your settings always win. `Update-Profile` never touches it.

### Terminal & Theme Overrides (`user-settings.json`)

Edit `%LOCALAPPDATA%\PowerShellProfile\user-settings.json` to persistently override Windows Terminal or Oh My Posh settings. `setup.ps1` creates a starter template. All keys are optional:

```json
{
    "theme": {
        "name": "catppuccin",
        "url": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/catppuccin.omp.json"
    },
    "windowsTerminal": { "colorScheme": "One Half Dark" },
    "defaults": { "opacity": 90, "font": { "size": 14 } },
    "keybindings": [{ "keys": "ctrl+shift+t", "command": { "action": "newTab" } }]
}
```

| Section | What it overrides |
| --- | --- |
| `theme` | Oh My Posh theme name and download URL |
| `windowsTerminal` | Color scheme and cursor color |
| `defaults` | Font, opacity, padding, scrollbar, etc. |
| `keybindings` | Additive — merged with base keybindings; same `keys` = user wins |

## Keyboard Shortcuts

| Key | Action |
| --- | --- |
| `Up` / `Down` | Search history matching current input |
| `Tab` | Menu-style tab completion |
| `Ctrl+D` | Delete character |
| `Ctrl+W` | Delete word backwards |
| `Alt+D` | Delete word forwards |
| `Ctrl+Left` / `Ctrl+Right` | Jump word backwards / forwards |
| `Ctrl+Z` / `Ctrl+Y` | Undo / Redo |
| `Alt+V` | Smart paste — inserts clipboard into prompt without executing |
| `Ctrl+R` | Fuzzy search command history (fzf) |
| `Ctrl+T` | Fuzzy file finder (fzf) |
| `Ctrl+A` | Select entire terminal buffer (Windows Terminal) |

## Commands

Run `Show-Help` in your terminal for a quick reference.

| Command | Description |
| --- | --- |
| `Edit-Profile` / `ep` | Open the profile in your editor |
| `Update-Profile` | Sync profile, theme, caches, and WT settings |
| `Update-PowerShell` | Check for new PowerShell releases |
| `Update-Tools` | Update Oh My Posh, eza, zoxide, fzf, bat, and ripgrep via winget |
| `Show-Help` | Show all commands in the terminal |
| `admin` / `su` | Open elevated terminal |
| `b64 <text>` / `b64d <text>` | Base64 encode / decode |
| `cat <file>` | Syntax-highlighted file viewer (bat), falls back to `Get-Content` |
| `checkport <host> <port>` | Test TCP connectivity to host:port |
| `checksum <file> <expected>` | Verify file hash (auto-detects algorithm from length) |
| `Clear-Cache` | Clear user temp/cache (`-IncludeSystemCaches` for system dirs) |
| `Clear-ProfileCache` | Reset all profile caches (OMP, zoxide, configs) |
| `Copy-SshKey` / `ssh-copy-key <user@host>` | Copy SSH public key to remote (requires ssh) |
| `cpy <text>` / `pst` | Copy to / paste from clipboard |
| `df` | Disk volumes |
| `dex <container> [shell]` | Exec into container, default bash (requires docker) |
| `dimg` | List images (requires docker) |
| `dlogs <container>` | Follow container logs (requires docker) |
| `docs` / `dtop` | Jump to Documents / Desktop |
| `dpa` / `dps` | All containers / running containers (requires docker) |
| `dprune` | `docker system prune -f` (requires docker) |
| `dstop` | Stop all running containers (requires docker) |
| `eventlog [n]` | Last *n* System+Application event log entries (default 20) |
| `export <name> <value>` | Set environment variable |
| `ff <name>` | Find files recursively |
| `flushdns` | Clear DNS cache |
| `g` | `z github` (zoxide jump to github dir) |
| `ga` | `git add .` |
| `gc <msg>` | `git commit -m` |
| `gcl <repo>` | `git clone` |
| `gcom <msg>` | `git add .` + `git commit -m` |
| `genpass [length]` | Cryptographically random password (default 20), copies to clipboard |
| `gpush` / `gpull` | `git push` / `git pull` |
| `grep <regex> [dir]` | Search for pattern in files (uses ripgrep when available) |
| `gs` | `git status` |
| `hash <file> [algo]` | File hash (default SHA256) |
| `hb <file>` | Upload file to hastebin, copy URL |
| `head <path> [n]` | First *n* lines (default 10) |
| `http <url> [-Method POST] [-Body '...']` | Quick HTTP requests, auto-formats JSON responses |
| `icb` | Insert clipboard text into prompt (never executes) |
| `keygen [name]` | Generate ED25519 SSH key pair (requires ssh) |
| `killport <port>` | Kill process listening on a TCP port |
| `la` / `ll` / `ls` / `lt` | eza listings: hidden, long+git, icons, tree |
| `lazyg <msg>` | add + commit + push in one go |
| `localip` | Show local IPv4 addresses per adapter |
| `mkcd <dir>` | Create directory and cd into it |
| `nf <name>` | Create new file |
| `nslook <domain> [type]` | DNS lookup (A, MX, TXT, CNAME, etc.) |
| `path` | Display PATH entries one per line |
| `pgrep <name>` / `pkill <name>` | List / kill processes by name |
| `ports` | Show listening TCP ports with owning process |
| `prettyjson <file>` | Pretty-print JSON file (or pipe: `cat data.json \| prettyjson`) |
| `pubip` | Show public IP |
| `rdp <host>` | Launch RDP session |
| `reload` | Reload the PowerShell profile |
| `sed <file> <find> <replace>` | Find and replace in file |
| `sizeof <path>` | Human-readable file/directory size |
| `svc [name] [-Count n] [-Live]` | htop-like process viewer with CPU/mem/uptime header (default top 25, `-Live` auto-refreshes) |
| `sysinfo` | Detailed system info |
| `tail <path> [n] [-f]` | Last *n* lines, optional follow |
| `touch <file>` | Create file or update timestamp |
| `trash <path>` | Move to Recycle Bin |
| `unzip <file>` | Extract zip to current directory |
| `extract <file>` | Universal extractor (.zip, .tar, .gz, .7z, .rar) |
| `uptime` | System uptime |
| `weather [city]` | Quick weather lookup via wttr.in |
| `wifipass [ssid]` | Show saved WiFi passwords |
| `hosts` | Open hosts file in elevated editor |
| `speedtest` | Download speed test via Cloudflare |
| `which <cmd>` | Show command path |
| `winutil` | Launch Chris Titus WinUtil |
| `harden` | Open [Harden System Security](https://github.com/HotCakeX/Harden-Windows-Security) |
