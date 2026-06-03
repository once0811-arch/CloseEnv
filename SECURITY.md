# Security Policy

CloseEnv is a static scanner. It should not print detected secret values, and
reports should include only paths, line numbers, and detector labels.

## Reporting a Vulnerability

Please report security issues privately by opening a GitHub security advisory
on this repository. Do not include live secrets in the report. If a real secret
was committed to a public repository, rotate it in the provider before sharing
details.

## Supported Versions

The `main` branch is the active development branch until the first stable
release.
