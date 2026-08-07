# Changelog

## [Unreleased]

### Security
- `fetchHeaders`/`analyze(url)` now reject non-`http(s)` schemes and, by default, refuse to fetch hostnames that resolve to loopback, link-local (including the cloud metadata endpoint `169.254.169.254`), or private (RFC1918) addresses. Redirects are validated hop-by-hop instead of only checking the initial URL, and bounded to 5 hops. Opt out with `{ allowPrivateNetworks: true }` or CLI `--allow-private` for local/staging targets.
- The private/internal-IP guard now also recognizes IPv6 addresses that embed a private or metadata IPv4 address via the NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052) or the 6to4 prefix (`2002::/16`) — closing a bypass reachable on NAT64/464XLAT networks (the default IPv6-only mode on several cellular carriers and some cloud node pools).

## [1.0.3] - 2026-06-11

### Fixed
- CSP: bare-scheme sources (e.g. `https:`) in `script-src`, `connect-src`, `form-action`, `frame-src`, `worker-src`, and `default-src` are now flagged as permissive, since they match any host just like a wildcard (#68)

## [1.0.2] - 2026-05-26

### Added
- Dependabot configuration for automated dependency updates
- Full README with badges, quick start, grading scale, and headers-checked table
- npm publish and auto-tag CI workflows, gated on full CI success (#69)
- CLI `--help` and `--version` flags, plus a configurable fetch timeout

### Changed
- **Grading is stricter and can lower previously-A/A+ scores:**
  - Permissions-Policy now requires `camera=()`, `microphone=()`, and `geolocation=()` to score full marks — any other value previously scored "good" regardless of what it restricted (#4)
  - CSP and Cross-Origin-* header checks tightened (#50)
  - CSP now flags a missing `base-uri` directive (#51)

### Fixed
- CLI `--version` now loads the package version correctly under ESM (#47)
- Test files are excluded from the build `tsconfig` so they no longer get compiled into `dist` (#48)
- High-severity `vite` vulnerability patched; `npm audit --audit-level=high` is now enforced in CI (#71)

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
