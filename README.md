# @hailbytes/security-headers

> Analyze HTTP security headers for your web application. Get an A-F grade, per-header findings, and one-line remediation as a library, CLI, or CI gate.

---

## What It Does

Fetches (or accepts raw header objects) and grades **7 security header categories**:

| Category | Header |
|---|---|
| HSTS | Strict-Transport-Security |
| CSP | Content-Security-Policy |
| Clickjacking | X-Frame-Options / frame-ancestors |
| MIME Sniffing | X-Content-Type-Options |
| Referrer Leakage | Referrer-Policy |
| Browser Features | Permissions-Policy |
| Cross-Origin Isolation | COEP / COOP / CORP |

Returns an **A+ to F grade**, per-header scores, findings, and one-line remediation steps.

---

## Install

```bash
npm install @hailbytes/security-headers
```

Or use without installing:

```bash
npx @hailbytes/security-headers https://example.com
```

---

## Quick Start

### CLI

```bash
# Scan a URL
npx @hailbytes/security-headers https://example.com

# JSON output
npx @hailbytes/security-headers https://example.com --json

# CI gate -- fail if grade is D or F
npx @hailbytes/security-headers https://example.com || echo 'fail'
```

### Library -- Analyze a URL

```typescript
import { analyze } from "@hailbytes/security-headers";

const report = await analyze("https://example.com");
console.log(report.grade);
console.log(report.score);
```

### Library -- Analyze static header object

```typescript
import { analyzeHeaders } from "@hailbytes/security-headers";

const report = analyzeHeaders({
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
});

for (const h of report.headers) {
  for (const rec of h.recommendations) {
    console.log("Fix: " + rec);
  }
}
```

---

## Report Shape

```typescript
interface SecurityHeaderReport {
  url?: string;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  score: number;
  maxScore: number;
  percentage: number;
  headers: HeaderFinding[];
  analyzedAt: string;
}

interface HeaderFinding {
  header: string;
  score: number;
  maxScore: number;
  status: "good" | "warning" | "missing" | "error";
  raw?: string;
  findings: string[];
  recommendations: string[];
}
```

---

## Grading Scale

| Grade | Score |
|---|---|
| A+ | >= 90% |
| A  | >= 75% |
| B  | >= 60% |
| C  | >= 40% |
| D  | >= 20% |
| F  | < 20%  |

---

## Who Is This For?

- **Security Engineers** running header audits across a fleet of apps
- **DevSecOps** integrating header checks into CI/CD pipelines
- **ASM Platform** integrations that need programmatic header scoring

---

## See Also

- [@hailbytes/asm-scope-parser](https://npmjs.com/package/@hailbytes/asm-scope-parser) -- Parse and validate ASM scope definitions
- [@hailbytes/mcp-security-scanner](https://npmjs.com/package/@hailbytes/mcp-security-scanner) -- MCP-compatible security scanner
- [HailBytes ASM Platform](https://hailbytes.com/asm) -- Attack Surface Management

---

Made with love by [HailBytes](https://hailbytes.com)
