---
title: "Stop Pasting URLs into Security Header Sites — Use This CLI"
published: false
description: Get an A–F grade for your site's HTTP security headers without leaving the terminal. Use it as a library, a CLI, or a CI gate that fails deploys on regression.
tags: security, webdev, devops, javascript
cover_image: <COVER_IMAGE_URL>
canonical_url: https://github.com/hailbytes/security-headers
published_at: 2026-05-21 13:00 +0000
---

<!--
COVER IMAGE PROMPT (1000x420, 2.4:1 banner):

Flat vector illustration, isometric perspective. A stylized laptop with an open terminal
window showing a list of HTTP security header names (CSP, HSTS, X-Frame-Options) as
abstract bars — readable as a list but not literal text. A large translucent report-card or
badge floats above the terminal displaying a bold letter grade in the shape of an "A+"
(rendered as a graphic emblem, not typed text). Decorative padlock and shield icons orbit
the laptop. Dark navy (#0a1628) background, electric cyan (#00d4ff) primary, soft green
(#5eead4) for the grade badge, amber (#ffb347) accent. Banner composition. Avoid any
literal text strings — render letters only as iconic shapes.

Suggested generators: Midjourney v6+ with `--ar 1000:420 --style raw`, DALL-E 3, or Flux.
After generation, host on Cloudinary or GitHub raw and replace <COVER_IMAGE_URL> above.
-->

The flow goes like this:

1. Ship a deploy.
2. Alt-tab to securityheaders.com.
3. Paste in the URL.
4. Squint at the report.
5. Realize someone removed the CSP three weeks ago and nobody noticed.

I wanted step 2 to be `npx`.

## CLI

```bash
npx @hailbytes/security-headers https://example.com
```

Prints a color report to the terminal. Add `--json` to feed it into other tools, or just rely on the non-zero exit code on grade D or F to use it as a CI gate:

```bash
npx @hailbytes/security-headers https://staging.example.com || exit 1
```

## Library

```ts
import { analyze } from '@hailbytes/security-headers';

const report = await analyze('https://example.com');
// { grade: 'A+', score: 95, percentage: 95, headers: [...] }
```

Or pass raw headers (for unit tests, or middleware that wants to grade its own response before sending):

```ts
import { analyzeHeaders } from '@hailbytes/security-headers';

const report = analyzeHeaders({
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  // ...
});
```

## What it checks

Seven categories — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and the Cross-Origin family (COEP/COOP/CORP). Each header gets a numeric score, a status (`good` / `warning` / `missing` / `error`), and specific remediation strings you can drop straight into a ticket.

The grading scale is the obvious one:

| Grade | Score |
|---|---|
| A+ | ≥ 90% |
| A  | ≥ 75% |
| B  | ≥ 60% |
| C  | ≥ 40% |
| D  | ≥ 20% |
| F  | < 20% |

```bash
npm install @hailbytes/security-headers
```

Source: [github.com/hailbytes/security-headers](https://github.com/hailbytes/security-headers) — MIT licensed.
