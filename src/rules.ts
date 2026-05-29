import type { HeaderFinding } from './types.js';

type RawHeaders = Record<string, string>;

function getHeader(headers: RawHeaders, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return undefined;
}

/**
 * Returns the source tokens of a CSP directive, or undefined if the directive
 * is absent. e.g. extractCspDirective("default-src 'self'; frame-ancestors 'none'", 'frame-ancestors')
 * => ["'none'"].
 */
function extractCspDirective(csp: string, directive: string): string[] | undefined {
  const lower = directive.toLowerCase();
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length && tokens[0].toLowerCase() === lower) {
      return tokens.slice(1);
    }
  }
  return undefined;
}

/**
 * A source token offers no host restriction if it is a bare wildcard (`*`) or a
 * scheme-only source (`https:`, `http:`, `data:`, etc.) that matches any host.
 */
function isPermissiveSource(token: string): boolean {
  return token === '*' || /^[a-z][a-z0-9+.-]*:$/i.test(token);
}

export function checkHSTS(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'strict-transport-security');
  if (!raw) return {
    header: 'Strict-Transport-Security', score: 0, maxScore: 20, status: 'missing',
    findings: ['Header not present — HTTPS not enforced by the browser'],
    recommendations: ['Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'],
  };

  let score = 10;
  const findings: string[] = [];
  const recommendations: string[] = [];

  const m = raw.match(/max-age=(\d+)/i);
  const maxAge = m ? parseInt(m[1], 10) : 0;
  if (maxAge >= 31536000) {
    score += 5;
  } else if (maxAge > 0) {
    findings.push(`max-age=${maxAge} is below recommended 31536000 (1 year)`);
    recommendations.push('Set max-age=31536000');
    score += 2;
  } else {
    // max-age=0 (or absent) explicitly revokes HSTS — the browser purges the
    // host from its HSTS cache and stops enforcing HTTPS.
    findings.push('max-age=0 revokes HSTS — HTTPS enforcement is disabled');
    recommendations.push('Set max-age=31536000 to enforce HTTPS');
  }
  // includeSubDomains / preload only add protection when HSTS is actually
  // enforced; awarding their bonuses under max-age=0 would mask a revocation.
  if (maxAge > 0) {
    if (/includesubdomains/i.test(raw)) { score += 3; }
    else { findings.push('includeSubDomains not set'); recommendations.push('Add includeSubDomains directive'); }
    if (/preload/i.test(raw)) score += 2;
  }

  return { header: 'Strict-Transport-Security', score, maxScore: 20, status: score >= 15 ? 'good' : 'warning', raw, findings, recommendations };
}

export function checkCSP(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'content-security-policy');
  if (!raw) {
    // A report-only policy is the standard incremental-rollout pattern. It does
    // not enforce anything, so it can't earn full credit, but it is materially
    // different from having no CSP at all and deserves targeted feedback.
    const reportOnly = getHeader(headers, 'content-security-policy-report-only');
    if (reportOnly) return {
      header: 'Content-Security-Policy', score: 10, maxScore: 30, status: 'warning', raw: reportOnly,
      findings: ['CSP is report-only — violations are reported but not enforced, so it does not mitigate XSS'],
      recommendations: ['Promote the policy to an enforcing Content-Security-Policy header once validated'],
    };
    return {
      header: 'Content-Security-Policy', score: 0, maxScore: 30, status: 'missing',
      findings: ['CSP header not present — XSS attacks are not mitigated'],
      recommendations: ["Add a Content-Security-Policy header. Start with: default-src 'self'"],
    };
  }

  let score = 20;
  const findings: string[] = [];
  const recommendations: string[] = [];

  // 'unsafe-inline' is ignored by browsers that support 'strict-dynamic' when a
  // nonce/hash is also present — that combination is the recommended Strict CSP
  // pattern (the 'unsafe-inline' is a backwards-compat fallback), so don't penalize it.
  const hasStrictDynamic = /'strict-dynamic'/i.test(raw);
  const hasNonceOrHash = /'nonce-[^']+'/i.test(raw) || /'sha(?:256|384|512)-[^']+'/i.test(raw);
  if (/'unsafe-inline'/i.test(raw) && !(hasStrictDynamic && hasNonceOrHash)) {
    score -= 5;
    findings.push("'unsafe-inline' weakens XSS protection");
    recommendations.push("Remove 'unsafe-inline'; use nonces or hashes instead");
  }
  if (/'unsafe-eval'/i.test(raw)) {
    score -= 5;
    findings.push("'unsafe-eval' allows eval() — potential code injection");
    recommendations.push("Remove 'unsafe-eval'");
  }
  if (/(?:default-src|script-src)\s+\*/i.test(raw)) {
    score -= 5;
    findings.push('Wildcard (*) in default-src or script-src allows any origin');
    recommendations.push('Replace wildcards with specific trusted domains');
  }
  // form-action does NOT inherit from default-src, so its absence leaves form
  // submissions unrestricted even under a strict default-src 'self'.
  if (extractCspDirective(raw, 'form-action') === undefined) {
    score -= 3;
    findings.push('No form-action directive — form submissions are unrestricted (form-action does not inherit from default-src)');
    recommendations.push("Add form-action 'self' (or 'none') to restrict where forms can submit");
  }
  score = Math.max(5, score); // at least 5 for having any CSP

  return { header: 'Content-Security-Policy', score, maxScore: 30, status: findings.length === 0 ? 'good' : 'warning', raw, findings, recommendations };
}

export function checkXFrameOptions(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'x-frame-options');
  const csp = getHeader(headers, 'content-security-policy');
  const frameAncestors = csp ? extractCspDirective(csp, 'frame-ancestors') : undefined;
  const hasFrameAncestors = frameAncestors !== undefined;
  // A frame-ancestors directive only protects if it actually restricts origins.
  // `frame-ancestors *` / `frame-ancestors https:` allow embedding by any origin.
  const frameAncestorsProtective =
    hasFrameAncestors && frameAncestors!.length > 0 && !frameAncestors!.some(isPermissiveSource);

  if (!raw && !hasFrameAncestors) return {
    header: 'X-Frame-Options', score: 0, maxScore: 15, status: 'missing',
    findings: ['Site may be embeddable in iframes — clickjacking risk'],
    recommendations: ['Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors'],
  };
  if (frameAncestorsProtective) {
    return { header: 'X-Frame-Options', score: 15, maxScore: 15, status: 'good', raw: raw ?? '(set via CSP frame-ancestors)', findings: [], recommendations: [] };
  }
  // frame-ancestors present but permissive (e.g. `*`). Per CSP spec it takes
  // precedence over X-Frame-Options, so it cannot be relied on for protection.
  if (hasFrameAncestors && !frameAncestorsProtective) {
    return {
      header: 'X-Frame-Options', score: 8, maxScore: 15, status: 'warning',
      raw: raw ?? `(CSP frame-ancestors ${frameAncestors!.join(' ') || '<empty>'})`,
      findings: ['CSP frame-ancestors allows embedding by any origin — no clickjacking protection'],
      recommendations: ["Restrict frame-ancestors to 'none', 'self', or specific trusted origins"],
    };
  }
  const val = (raw ?? '').toUpperCase().trim();
  const score = (val === 'DENY' || val === 'SAMEORIGIN') ? 15 : 8;
  return { header: 'X-Frame-Options', score, maxScore: 15, status: score === 15 ? 'good' : 'warning', raw,
    findings: score < 15 ? [`X-Frame-Options value '${raw}' is not DENY or SAMEORIGIN`] : [],
    recommendations: score < 15 ? ['Use DENY or SAMEORIGIN'] : [] };
}

export function checkXContentTypeOptions(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'x-content-type-options');
  if (!raw) return {
    header: 'X-Content-Type-Options', score: 0, maxScore: 10, status: 'missing',
    findings: ['MIME-type sniffing not disabled — potential content injection'],
    recommendations: ['Add X-Content-Type-Options: nosniff'],
  };
  const score = raw.toLowerCase().trim() === 'nosniff' ? 10 : 5;
  return { header: 'X-Content-Type-Options', score, maxScore: 10, status: score === 10 ? 'good' : 'warning', raw,
    findings: score < 10 ? ['Value should be exactly "nosniff"'] : [],
    recommendations: score < 10 ? ['Set value to nosniff'] : [] };
}

export function checkReferrerPolicy(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'referrer-policy');
  if (!raw) return {
    header: 'Referrer-Policy', score: 0, maxScore: 10, status: 'missing',
    findings: ['Referrer-Policy not set — browser default may leak URLs in Referer header'],
    recommendations: ['Add Referrer-Policy: strict-origin-when-cross-origin'],
  };
  // no-referrer-when-downgrade is intentionally excluded: it sends the full URL
  // (path + query) to every cross-origin HTTPS destination. It was the historical
  // browser default precisely because it was the least restrictive option.
  const strongValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
  const isStrong = strongValues.includes(raw.toLowerCase().trim());
  const score = isStrong ? 10 : 5;
  return { header: 'Referrer-Policy', score, maxScore: 10, status: isStrong ? 'good' : 'warning', raw,
    findings: isStrong ? [] : [`Value '${raw}' may leak referrer information`],
    recommendations: isStrong ? [] : ['Use: strict-origin-when-cross-origin'] };
}

export function checkPermissionsPolicy(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'permissions-policy') ?? getHeader(headers, 'feature-policy');
  if (!raw) return {
    header: 'Permissions-Policy', score: 0, maxScore: 10, status: 'missing',
    findings: ['Permissions-Policy not set — browser features are not restricted'],
    recommendations: ['Add Permissions-Policy: camera=(), microphone=(), geolocation=()'],
  };
  const lc = raw.toLowerCase();
  const hasCam = lc.includes("camera=()");
  const hasMic = lc.includes("microphone=()");
  const hasGeo = lc.includes("geolocation=()");
  const score = (hasCam && hasMic && hasGeo) ? 10 : 5;
  const isGood = score === 10;
  return {
    header: "Permissions-Policy",
    score,
    maxScore: 10,
    status: isGood ? "good" : "warning",
    raw,
    findings: isGood ? [] : ["Permissions-Policy does not restrict at least camera, microphone, and geolocation"],
    recommendations: isGood ? [] : ["Set Permissions-Policy to camera=(), microphone=(), geolocation=(), and any other features needed by your app"]
  };
}

export function checkCrossOriginPolicies(headers: RawHeaders): HeaderFinding {
  const coep = getHeader(headers, 'cross-origin-embedder-policy');
  const coop = getHeader(headers, 'cross-origin-opener-policy');
  const corp = getHeader(headers, 'cross-origin-resource-policy');
  const count = [coep, coop, corp].filter(Boolean).length;
  const score = Math.min(count * 2, 5);
  const missing = [
    !coep && 'Cross-Origin-Embedder-Policy',
    !coop && 'Cross-Origin-Opener-Policy',
    !corp && 'Cross-Origin-Resource-Policy',
  ].filter(Boolean) as string[];

  return {
    header: 'Cross-Origin Policies', score, maxScore: 5,
    status: score >= 4 ? 'good' : score > 0 ? 'warning' : 'missing',
    raw: [coep && `COEP: ${coep}`, coop && `COOP: ${coop}`, corp && `CORP: ${corp}`].filter(Boolean).join('; ') || undefined,
    findings: missing.map(h => `${h} not set`),
    recommendations: missing.map(h => `Add ${h}`),
  };
}
