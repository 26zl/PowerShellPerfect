# Pull Request

## Summary

<!-- Brief description of what this PR does -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Configuration change
- [ ] Documentation

## Checklist

- [ ] `tests/lint.ps1` passes with no warnings or errors
- [ ] `tests/unit.ps1` passes on PowerShell 5.1 and 7+
- [ ] Bug fix: a regression case in `tests/unit.ps1` fails without the fix
- [ ] Tested on PowerShell 5.1 (if script behavior changed)
- [ ] Tested on PowerShell 7+ (if script behavior changed)
- [ ] User-visible change listed under **Unreleased** in `CHANGELOG.md`
- [ ] New downloads are pinned (version and SHA-256 where available); new third-party calls are mocked in CI and listed in `SECURITY.md`
- [ ] No hardcoded user paths (`C:\Users\`, `/home/`)
- [ ] No embedded secrets or tokens
- [ ] No em dashes or non-ASCII characters in source files
- [ ] UTF-8 without BOM for all file writes (`Write-Utf8FileAtomic` or `[System.IO.File]::WriteAllText()`)
