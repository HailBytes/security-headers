# Changelog

## [Unreleased]

### Security
- `fetchHeaders`/`analyze(url)` now reject non-`http(s)` schemes and, by default, refuse to fetch hostnames that resolve to loopback, link-local (including the cloud metadata endpoint `169.254.169.254`), or private (RFC1918) addresses. Redirects are validated hop-by-hop instead of only checking the initial URL, and bounded to 5 hops. Opt out with `{ allowPrivateNetworks: true }` or CLI `--allow-private` for local/staging targets.

## [1.0.1] - 2025-05-19

### Added
- Initial release
- Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin policies
- A+ to F grading scale
- `analyze(url | headers)` convenience function
- `analyzeHeaders(headers)` for offline analysis
- `fetchHeaders(url)` for raw header fetching
- CLI: `npx @hailbytes/security-headers <url> [--json]`
- TypeScript types included
