# Changelog

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
