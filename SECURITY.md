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

- `Update-Profile` requires SHA-256 hash verification (or explicit `-SkipHashCheck`)
- PSReadLine history filters out lines containing: `password`, `secret`, `token`, `api[_-]?key`, `connectionstring`, `credential`, `bearer`
- Repository download URLs are centralized (not hardcoded inline)
- When in CI or when `$env:AI_AGENT` is set, the profile and setup skip network calls and interactive prompts, reducing exposure in automated or AI/agent environments
