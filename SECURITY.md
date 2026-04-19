# Security Policy

## Supported Versions

Only the latest version on `main` is supported with security updates.

| Branch | Supported |
| ------ | --------- |
| main   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Use [GitHub Security Advisories](https://github.com/26zl/PowerShellPerfect/security/advisories/new) to report privately
3. You should receive an acknowledgment within 48 hours

## Scope

The following areas are in scope for security reports:

- **Profile code** (`Microsoft.PowerShell_profile.ps1`) - command injection, unintended code execution
- **Setup scripts** (`setup.ps1`, `setprofile.ps1`) - privilege escalation, unsafe downloads
- **Update mechanism** (`Update-Profile`) - hash verification bypass, MITM concerns
- **Credential handling** - API key exposure (e.g., VirusTotal), PSReadLine history filtering

## Security Measures

- `Update-Profile` and `Invoke-ProfileWizard` require SHA-256 hash input before executing a downloaded payload, or explicit `-SkipHashCheck`. **What this protects**: file integrity (truncated/corrupted downloads) and reproducible installs (the same `-ExpectedSha256` value always resolves to the same applied content). **What this does NOT protect against**: a first-time install where the attacker controls the download path. The initial SHA the profile prints is computed over what was just fetched; a MITMed first download would produce a hash that matches the malicious payload, not the real upstream. For real trust pinning, verify the published commit SHA out-of-band (e.g. against `https://github.com/26zl/PowerShellPerfect/commits/main` in a browser) before running `Update-Profile -ExpectedSha256 <hash>`.
- PSReadLine history filters out lines containing: `password`, `secret`, `token`, `api[_-]?key`, `connectionstring`, `credential`, `bearer`
- Repository download URLs are centralized (not hardcoded inline)
- When in CI or when `$env:AI_AGENT` is set, the profile and setup skip network calls and interactive prompts, reducing exposure in automated or AI/agent environments

## Code-Execution Surfaces

The profile has four mechanisms that execute code from places other than the main profile file. All are user-owned and opt-in, but the trust model should be explicit:

- **`profile_user.ps1`** - dot-sourced every profile load. Lives in the user's `$PROFILE` directory. Equivalent to editing the profile itself.
- **`plugins/*.ps1`** - dot-sourced every profile load. Lives in `%LOCALAPPDATA%\PowerShellProfile\plugins\`. Each file is isolated so one crash doesn't break others, but a plugin has full profile trust.
- **`user-settings.json` `commandOverrides`** - values are passed to `[scriptblock]::Create()` and defined as functions. **Default off** - requires explicit opt-in via `features.commandOverrides = true` in the same file, so a silently-edited JSON file cannot redefine commands on next shell launch. When the feature is off but entries exist, the profile prints a notice at startup and ignores them. Do not copy `user-settings.json` from untrusted sources.
- **`.psprc.ps1` per-directory profiles** - auto-loaded on `cd` into a trusted directory only. Trust is explicit and per-directory via `Add-TrustedDirectory`; untrusted directories only print a warning. This is modeled after `direnv`.

Because all four surfaces require local filesystem write access (or explicit `Add-TrustedDirectory` for `.psprc.ps1`), they are not exploitable by remote attackers without first achieving arbitrary file write. Treat user-settings.json and plugin files as carefully as any dotfile.
