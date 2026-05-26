import type { HeaderFinding } from './types.js';

type RawHeaders = Record<string, string>;

function getHeader(headers: RawHeaders, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return undefined;
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
  } else {
    findings.push(`max-age=${maxAge} is below recommended 31536000 (1 year)`);
    recommendations.push('Set max-age=31536000');
    if (maxAge > 0) score += 2;
  }
  if (/includesubdomains/i.test(raw)) { score += 3; }
  else { findings.push('includeSubDomains not set'); recommendations.push('Add includeSubDomains directive'); }
  if (/preload/i.test(raw)) score += 2;

  return { header: 'Strict-Transport-Security', score, maxScore: 20, status: score >= 15 ? 'good' : 'warning', raw, findings, recommendations };
}

export function checkCSP(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'content-security-policy');
  if (!raw) return {
    header: 'Content-Security-Policy', score: 0, maxScore: 30, status: 'missing',
    findings: ['CSP header not present — XSS attacks are not mitigated'],
    recommendations: ["Add a Content-Security-Policy header. Start with: default-src 'self'"],
  };

  let score = 20;
  const findings: string[] = [];
  const recommendations: string[] = [];

  if (/'unsafe-inline'/i.test(raw)) {
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
  score = Math.max(5, score); // at least 5 for having any CSP

  return { header: 'Content-Security-Policy', score, maxScore: 30, status: findings.length === 0 ? 'good' : 'warning', raw, findings, recommendations };
}

export function checkXFrameOptions(headers: RawHeaders): HeaderFinding {
  const raw = getHeader(headers, 'x-frame-options');
  const csp = getHeader(headers, 'content-security-policy');
  const cspFrameAncestors = csp && /frame-ancestors/i.test(csp);

  if (!raw && !cspFrameAncestors) return {
    header: 'X-Frame-Options', score: 0, maxScore: 15, status: 'missing',
    findings: ['Site may be embeddable in iframes — clickjacking risk'],
    recommendations: ['Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors'],
  };
  if (cspFrameAncestors) {
    return { header: 'X-Frame-Options', score: 15, maxScore: 15, status: 'good', raw: raw ?? '(set via CSP frame-ancestors)', findings: [], recommendations: [] };
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
  const strongValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade', 'same-origin'];
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
    recommendations: ["Set Permissions-Policy to camera=(), microphone=(), geolocation=(), and any other features needed by your app"]
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
