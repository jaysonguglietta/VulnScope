# Security Policy

VulnScope is currently intended for local or tightly controlled private use.

## Supported Version

The `main` branch is the active development version.

## Current Security Posture

- The server binds to `127.0.0.1` by default.
- Authentication is not implemented.
- Request logging is not implemented.
- Source API tokens are read from environment variables and are not bundled into the frontend.
- Browser-rendered external links are restricted to `http` and `https`.
- Saved cases and watchlist entries are stored in browser local storage.

Do not expose VulnScope to untrusted users without adding authentication, authorization, and an approved deployment boundary.

## Reporting Issues

Open a private issue or contact the repository owner with:

- A clear description of the issue.
- Affected version or commit.
- Reproduction steps.
- Impact and suggested fix, if known.
