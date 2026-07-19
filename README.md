# @hailbytes/security-headers

> Analyze HTTP security headers for your web application. Get an A–F grade, per-header findings, and one-line remediation — as a library, CLI, or CI gate.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fsecurity-headers.svg)](https://www.npmjs.com/package/@hailbytes/security-headers)
[![npm downloads](https://img.shields.io/npm/dw/%40hailbytes%2Fsecurity-headers.svg)](https://www.npmjs.com/package/@hailbytes/security-headers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/%40hailbytes%2Fsecurity-headers)](https://bundlephobia.com/package/@hailbytes/security-headers)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-davidhailbytes-blue?logo=linkedin&style=flat)](https://www.linkedin.com/in/davidhailbytes/)

---

## What it does

Fetches (or accepts raw header objects) and grades 7 security header categories — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cross-Origin policies. Returns an A+ to F letter grade, a 0–100 percentage score, per-header findings, and specific remediation steps.

---

## Install

```bash
npm install @hailbytes/security-headers
# or run directly
npx @hailbytes/security-headers https://example.com
```

---

## Quick Start

### CLI

```bash
# Scan a URL and print a color report
npx @hailbytes/security-headers https://example.com

# Output raw JSON
npx @hailbytes/security-headers https://example.com --json

# Use as a CI gate (exits 1 on grade D or F)
npx @hailbytes/security-headers https://staging.example.com || echo "Security headers gate failed"

# Use a stricter CI gate threshold (exits 1 on grade C or below)
npx @hailbytes/security-headers https://staging.example.com --fail-on C

# Scan an internal/local target (disabled by default, see Security below)
npx @hailbytes/security-headers http://localhost:3000 --allow-private
```

`--fail-on <grade>` sets the CI-gate threshold — the CLI exits 1 when the report's grade is at or below the given grade (best→worst: `A+`, `A`, `B`, `C`, `D`, `F`). Defaults to `D`, matching the exit-1-on-D-or-F behavior above.

### Library — analyze a URL

```ts
import { analyze } from '@hailbytes/security-headers';

const report = await analyze('https://example.com');

console.log(report.grade);       // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(report.score);       // 0–100
console.log(report.percentage);  // 0–100
console.log(report.headers);     // HeaderFinding[]
```

### Library — analyze raw headers (offline / in tests)

```ts
import { analyzeHeaders } from '@hailbytes/security-headers';

const report = analyzeHeaders({
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; form-action 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
});

console.log(report.grade); // 'B' or higher
for (const h of report.headers) {
  if (h.status !== 'good') {
    console.log(h.header, h.recommendations);
  }
}
```

---

## Report Shape

```ts
interface SecurityHeaderReport {
  url?: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  maxScore: number;
  percentage: number;       // 0–100
  headers: HeaderFinding[]; // one per checked header
  analyzedAt: string;       // ISO 8601 timestamp
}

interface HeaderFinding {
  header: string;           // header name
  score: number;            // points earned
  maxScore: number;         // max available
  status: 'good' | 'warning' | 'missing' | 'error';
  raw?: string;             // raw header value
  findings: string[];       // what is wrong
  recommendations: string[]; // how to fix it
}
```

---

## Grading Scale

| Grade | Score |
|---|---|
| A+ | ≥ 90% |
| A | ≥ 75% |
| B | ≥ 60% |
| C | ≥ 40% |
| D | ≥ 20% |
| F | < 20% |

---

## Headers Checked

| Header | Max Points | Key Checks |
|---|---|---|
| Strict-Transport-Security | 20 | max-age ≥ 1 year, includeSubDomains, preload |
| Content-Security-Policy | 30 | presence, no unsafe-inline/eval, no wildcards, form-action/base-uri/object-src fallback set |
| X-Frame-Options | 15 | DENY or SAMEORIGIN (or CSP frame-ancestors) |
| X-Content-Type-Options | 10 | nosniff |
| Referrer-Policy | 10 | strict values only |
| Permissions-Policy | 10 | presence |
| Cross-Origin Policies | 5 | COEP, COOP, CORP |

---

## Security

`analyze(url)` / `fetchHeaders(url)` refuse non-`http(s)` schemes and, by default, refuse to fetch hostnames that resolve to loopback, link-local (including the `169.254.169.254` cloud metadata endpoint), or private (RFC1918) addresses — including via a redirect chain, which is validated hop-by-hop rather than trusting only the initial URL. This matters when the URL being scanned comes from an untrusted source (e.g. a customer-supplied target in an ASM pipeline), where an unguarded fetch is an SSRF vector.

For legitimate local/staging use, pass `{ allowPrivateNetworks: true }` (library) or `--allow-private` (CLI) to opt out.

---

## Who Is This For

Security engineers, DevSecOps teams, and ASM platform integrations that need automated header auditing on every deployment, pentesters who run this against every target scope, and developers who want to verify their app's security posture without leaving the terminal.

---

## See Also

- [`@hailbytes/asm-scope-parser`](https://github.com/HailBytes/asm-scope-parser) — Parse and normalize attack surface scope definitions
- [`@hailbytes/mcp-security-scanner`](https://github.com/HailBytes/mcp-security-scanner) — Security scanner for MCP server configurations
- [HailBytes ASM](https://hailbytes.com/asm) — Attack Surface Management platform

---

*Part of the [HailBytes](https://hailbytes.com) open-source security toolkit.*