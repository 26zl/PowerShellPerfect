# Security Policy

## Supported Versions

Security fixes go to `main` and ship in the next release. Only the latest release and `main` are supported.

| Version | Supported |
| ------- | --------- |
| Latest release (`vX.Y.Z`) | Yes |
| `main` | Yes |
| Older releases | No |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Use [GitHub Security Advisories](https://github.com/26zl/PowerShellPerfect/security/advisories/new) to report privately
3. You should receive an acknowledgment within 48 hours

## Scope

The following areas are in scope for security reports:

- **Profile code** (`Microsoft.PowerShell_profile.ps1`) - command injection, unintended code execution
- **Setup scripts** (`setup.ps1`, `setprofile.ps1`) - privilege escalation, unsafe downloads
- **Update and release mechanism** (`Update-Profile`, `.github/workflows/release.yml`) - verification bypass, MITM concerns
- **Credential handling** - API key exposure (e.g., VirusTotal), PSReadLine history filtering

## Verifying What You Install

- **Releases.** Each tag `vX.Y.Z` is published by `release.yml` with `SHA256SUMS.txt` and a [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations). The release files are the committed files of that tag, byte for byte what `raw.githubusercontent.com` serves for it. `gh attestation verify <file> --repo 26zl/PowerShellPerfect` checks with Sigstore that a file was built by this repository's workflow from that tag; that check does not depend on the files or checksums being served correctly.
- **`setup.ps1 -Ref vX.Y.Z` and `Update-Profile -Ref vX.Y.Z`** resolve the tag to a commit, download every file from that commit, and compare each file with the release's `SHA256SUMS.txt` before anything is changed. The README shows how to check `setup.ps1` itself against the same file before running it.
- **Branches and commits** have no published checksum. Setup and `Update-Profile` then print the SHA-256 of what they downloaded and the commit it came from, and stop. `-ExpectedSha256` makes a later install reproducible and detects changes in transit, but the hash is computed over the same download, so it cannot tell you whether the bytes are what the maintainer intended: check the commit out-of-band first. `-SkipHashCheck` installs without any check (trust on first use).
- **Elevation.** `setup.ps1` needs no administrator rights and should be run unelevated. When it is elevated anyway, fonts and the telemetry opt-out are installed machine-wide and the terminal is not restarted, so you are not left in an elevated shell. `Invoke-ProfileWizard` runs the downloaded `setup.ps1` in the current session; for a release tag it checks `setup.ps1` against the release's `SHA256SUMS.txt` and passes the tag on, so setup checks the bundle the same way.
- **Downloaded scripts.** `winutil` hashes the downloaded script and runs those same in-memory bytes, so a file on disk cannot be swapped between the check and the run. A pinned or forced run needs an elevated shell: unelevated, WinUtil would relaunch itself as administrator from its latest release, which the hash check never saw.
- **Third-party components** are pinned: Oh My Posh themes to release `v31.8.0` with SHA-256 for the default and preset themes, Nerd Fonts to release `v3.5.1` with the SHA-256 of each curated archive, PSFzf and `http-server` (used by `serve`) to exact versions. A weekly workflow checks that every pinned hash still matches upstream. Themes picked from the wizard catalog, and theme URLs you set in `user-settings.json`, are fetched from the pinned release without a hash.
- **Software installs.** `setup.ps1` installs winget packages and accepts the winget source and package agreements for you; `Update-Profile` installs nothing unless you pass `-InstallMissingTools`.

## Security Measures

- PSReadLine history filters out lines containing: `password`, `secret`, `token`, `api[_-]?key`, `connectionstring`, `credential`, `bearer`, VirusTotal API key variable names, direct JWT values, value-shaped secrets (GitHub, AWS, Slack, Stripe, OpenAI-style keys, private keys, URLs with credentials), and sensitive command forms such as `pwnd <candidate>` and `jwtd <token>`.
- `env` masks values whose names or shapes look like secrets unless you pass `-ShowValues`. `pwnd` prompts without echo when called without an argument.
- Repository download URLs are built in one place from the repository name and a ref.
- When in CI or when `$env:AI_AGENT` is set, the profile and setup skip network calls and interactive prompts, reducing exposure in automated or AI/agent environments.
- Destructive commands refuse core Windows processes (`killport`, `pkill`, `Stop-StuckProcess`), ask before stopping processes or deleting (`Remove-LockedItem`, `Clear-Cache`, `dstop`, `dprune`), and `Clear-Cache` refuses a `TEMP` that does not look like a temp folder. `nscan` asks before its intrusive profiles; scan only systems you are authorized to test.

## Code-Execution Surfaces

The profile has four mechanisms that execute code from places other than the main profile file. All are user-owned and opt-in, but the trust model should be explicit:

- **`profile_user.ps1`** - dot-sourced every profile load. Lives in the user's `$PROFILE` directory. Equivalent to editing the profile itself.
- **`plugins/*.ps1`** - dot-sourced every profile load. Lives in `%LOCALAPPDATA%\PowerShellProfile\plugins\`. Each file is isolated so one crash doesn't break others, but a plugin has full profile trust.
- **`user-settings.json` `commandOverrides`** - values are passed to `[scriptblock]::Create()` and defined as functions. **Default off** - requires explicit opt-in via `features.commandOverrides = true` in the same file, so a silently-edited JSON file cannot redefine commands on next shell launch. When the feature is off but entries exist, the profile prints a notice at startup and ignores them. Do not copy `user-settings.json` from untrusted sources.
- **`.psprc.ps1` per-directory profiles** - auto-loaded on `cd` into a trusted directory. `Add-TrustedDirectory` stores the SHA-256 of the file as it is when you approve it, and the file runs only while it still has that hash. Any change, including one that arrives through `git pull`, `git checkout` or `gh pr checkout`, stops it from running (with a warning) until you review it and approve it again, as `direnv allow` does. The file is read once per directory change and the text that was hashed is the text that runs, so it cannot be swapped between the check and the run. Directories trusted by versions before 1.0.0 have no stored hash and need one new approval. Untrusted directories only print a notice.

The first three need write access to your profile folders. `.psprc.ps1` files can arrive through version control, which is why their trust is bound to the approved content rather than the directory.

## Data Flows

Commands that send data to a third party (all over HTTPS). Nothing is sent unless you run the command.

| Command | Endpoint | Data sent |
| ------- | -------- | --------- |
| `pubip` | `ifconfig.me` | Your public IP (that is what it reports) |
| `ipinfo [ip]` | `ipwho.is` | The IP you pass, or none (your public IP is then revealed to the service) |
| `weather [city]` | `wttr.in`, fallback `open-meteo.com` + `ipinfo.io` | City name; with no city, your public IP is used for geolocation |
| `whois <domain>` | `rdap.org` | The domain |
| `gitignore <lang...>` | `www.toptal.com` | The language names |
| `tldr <cmd>` | `raw.githubusercontent.com` (tldr-pages) | The command name (only when the native `tldr` client is not installed) |
| `pwnd [password]` | `api.pwnedpasswords.com` | The first 5 hex characters of the password's SHA-1 (k-anonymity); the password never leaves the machine |
| `speedtest` | `speed.cloudflare.com` | None beyond the connection (downloads 25 MB) |
| `hb <file>` | `bin.christitus.com` | The **entire file contents**, posted to a public paste. Confirms first (`-Force`/`-Confirm:$false` to skip) |
| `vtscan <file> [-Upload]` | VirusTotal API | The file's SHA-256; with `-Upload`, the file itself, which VirusTotal shares with its community and security partners. Needs `VTCLI_APIKEY`/`VT_API_KEY` |
| `serve` (npx fallback) | `registry.npmjs.org` | Downloads the pinned `http-server` package |
| `winutil` | `christitus.com` | None (downloads the WinUtil script) |
| `Update-PowerShell` | `api.github.com` | `$env:GITHUB_TOKEN` as a bearer token when it is set |
| `Update-Profile`, `setup.ps1`, the opt-in weekly update check | `api.github.com`, `raw.githubusercontent.com`, `github.com` release downloads | `$env:GITHUB_TOKEN` as a bearer token to `api.github.com` when it is set; nothing is uploaded |
| `setup.ps1` installs | winget sources, the PowerShell Gallery, `github.com` (Nerd Fonts), the Oh My Posh repository | None beyond the requests |

Commands that only contact targets you explicitly name (`http`, `nslook`, `checkport`, `portscan`, `tlscert`, `certcheck`, `nscan`, `ssh`) send no profile-owned data.
