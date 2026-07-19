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
  // Check a wildcard (*) source anywhere in the source list of any sensitive
  // fetch/navigation directive — not just as the first token of default-src/
  // script-src. img-src/style-src/font-src/media-src are intentionally omitted
  // as a wildcard there is low-risk and commonly legitimate.
  const wildcardDirectives = ['default-src', 'script-src', 'connect-src', 'form-action', 'frame-src', 'worker-src', 'object-src'];
  const wildcarded = wildcardDirectives.filter(d => {
    const sources = extractCspDirective(raw, d);
    return sources !== undefined && sources.some(isPermissiveSource);
  });
  if (wildcarded.length > 0) {
    score -= 5;
    findings.push(`Wildcard or bare-scheme source in ${wildcarded.join(', ')} allows any origin`);
    recommendations.push('Replace wildcards and bare schemes (e.g. https:) with specific trusted domains');
  }
  // form-action does NOT inherit from default-src, so its absence leaves form
  // submissions unrestricted even under a strict default-src 'self'.
  if (extractCspDirective(raw, 'form-action') === undefined) {
    score -= 3;
    findings.push('No form-action directive — form submissions are unrestricted (form-action does not inherit from default-src)');
    recommendations.push("Add form-action 'self' (or 'none') to restrict where forms can submit");
  }
  // base-uri does NOT inherit from default-src. Without it an attacker who can
  // inject a <base> element can redirect relative URLs — including relative-URL
  // nonce sources — to an attacker-controlled host (base-uri injection attack).
  if (extractCspDirective(raw, 'base-uri') === undefined) {
    score -= 2;
    findings.push("No base-uri directive — <base> injection can redirect relative nonce sources (base-uri does not inherit from default-src)");
    recommendations.push("Add base-uri 'self' or base-uri 'none' to prevent <base> injection");
  }
  // object-src DOES inherit from default-src, but only when default-src is
  // actually set. If neither is present, <object>/<embed> plugin content is
  // completely unrestricted — a legacy but still-audited XSS vector — and every
  // other fetch directive not explicitly listed (img-src, media-src, connect-src,
  // etc.) also silently defaults to allow-all with no default-src to fall back to.
  if (extractCspDirective(raw, 'default-src') === undefined && extractCspDirective(raw, 'object-src') === undefined) {
    score -= 2;
    findings.push('No default-src or object-src directive — plugin content (<object>/<embed>) is unrestricted, and any other fetch directive not explicitly listed defaults to allow-all');
    recommendations.push("Add object-src 'none' (or set default-src as a fallback that covers it)");
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
  if (val === 'DENY' || val === 'SAMEORIGIN') {
    return { header: 'X-Frame-Options', score: 15, maxScore: 15, status: 'good', raw, findings: [], recommendations: [] };
  }
  // ALLOW-FROM was dropped by every current browser engine (Chrome, Firefox,
  // Safari, Edge) years ago — it is silently ignored, not honored, so it
  // provides zero real clickjacking protection despite looking like a valid directive.
  if (val.startsWith('ALLOW-FROM')) {
    return {
      header: 'X-Frame-Options', score: 0, maxScore: 15, status: 'warning', raw,
      findings: ['ALLOW-FROM is non-standard and ignored by all current browsers — provides no clickjacking protection'],
      recommendations: ["Use DENY or SAMEORIGIN, or CSP frame-ancestors to allowlist specific origins"],
    };
  }
  return { header: 'X-Frame-Options', score: 8, maxScore: 15, status: 'warning', raw,
    findings: [`X-Frame-Options value '${raw}' is not DENY or SAMEORIGIN`],
    recommendations: ['Use DENY or SAMEORIGIN'] };
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
  // Per W3C Referrer Policy spec the header value may be a comma-separated list;
  // browsers parse left-to-right and use the last token they recognise. Unrecognised
  // tokens are skipped, so `unsafe-url, strict-origin-when-cross-origin` is effectively
  // strong. We must apply the same last-recognised-wins logic here.
  const allValidPolicies = ['no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin',
    'strict-origin', 'origin-when-cross-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];
  const tokens = raw.toLowerCase().split(',').map(t => t.trim()).filter(Boolean);
  const effective = [...tokens].reverse().find(t => allValidPolicies.includes(t)) ?? tokens[tokens.length - 1] ?? '';
  const isStrong = strongValues.includes(effective);
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

  const norm = (v?: string) => v?.toLowerCase().trim() ?? '';
  // Only restrictive values provide isolation. The defaults (unsafe-none / the
  // permissive cross-origin) explicitly opt out and earn no credit.
  const coepOk = ['require-corp', 'credentialless'].includes(norm(coep));
  const coopOk = ['same-origin', 'same-origin-allow-popups'].includes(norm(coop));
  const corpOk = ['same-origin', 'same-site'].includes(norm(corp));

  const protective = [coepOk, coopOk, corpOk].filter(Boolean).length;
  const score = Math.min(protective * 2, 5);

  const findings: string[] = [];
  const recommendations: string[] = [];
  const consider = (val: string | undefined, ok: boolean, name: string, recommended: string) => {
    if (!val) {
      findings.push(`${name} not set`);
      recommendations.push(`Add ${name}: ${recommended}`);
    } else if (!ok) {
      findings.push(`${name}: '${val}' provides no cross-origin isolation`);
      recommendations.push(`Set ${name}: ${recommended}`);
    }
  };
  consider(coep, coepOk, 'Cross-Origin-Embedder-Policy', 'require-corp');
  consider(coop, coopOk, 'Cross-Origin-Opener-Policy', 'same-origin');
  consider(corp, corpOk, 'Cross-Origin-Resource-Policy', 'same-origin');

  const anyPresent = Boolean(coep || coop || corp);
  return {
    header: 'Cross-Origin Policies', score, maxScore: 5,
    status: score >= 4 ? 'good' : (score > 0 || anyPresent) ? 'warning' : 'missing',
    raw: [coep && `COEP: ${coep}`, coop && `COOP: ${coop}`, corp && `CORP: ${corp}`].filter(Boolean).join('; ') || undefined,
    findings,
    recommendations,
  };
}
