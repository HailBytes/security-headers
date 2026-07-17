import { describe, it, expect, vi, afterEach } from 'vitest';
import { analyzeHeaders } from '../src/analyzer.js';
import { analyze } from '../src/index.js';
import {
  checkHSTS, checkCSP, checkXFrameOptions, checkXContentTypeOptions,
  checkReferrerPolicy, checkPermissionsPolicy, checkCrossOriginPolicies
} from '../src/rules.js';

const STRONG_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; img-src *; form-action 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

describe('analyzeHeaders', () => {
  it('gives high score for well-configured headers', () => {
    const r = analyzeHeaders(STRONG_HEADERS);
    expect(r.score).toBeGreaterThan(70);
    expect(['A+', 'A', 'B']).toContain(r.grade);
  });

  it('gives grade F for empty headers', () => {
    const r = analyzeHeaders({});
    expect(r.score).toBe(0);
    expect(r.grade).toBe('F');
    expect(r.headers.every(h => h.status === 'missing')).toBe(true);
  });

  it('header scores sum to total score', () => {
    const r = analyzeHeaders(STRONG_HEADERS);
    const sum = r.headers.reduce((s, h) => s + h.score, 0);
    expect(sum).toBe(r.score);
  });

  it('includes url in report', () => {
    const r = analyzeHeaders({}, 'https://example.com');
    expect(r.url).toBe('https://example.com');
  });

  it('has an ISO timestamp', () => {
    const r = analyzeHeaders({});
    expect(r.analyzedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('maxScore is 100', () => {
    const r = analyzeHeaders({});
    expect(r.maxScore).toBe(100);
  });
});

describe('analyze convenience function', () => {
  it('analyze with object returns same result as analyzeHeaders', async () => {
    const direct = analyzeHeaders(STRONG_HEADERS);
    const viaAnalyze = await analyze(STRONG_HEADERS);
    // analyzedAt is wall-clock and is computed independently in each call, so
    // compare everything else and assert both timestamps are valid ISO strings.
    const { analyzedAt: directAt, ...directRest } = direct;
    const { analyzedAt: viaAt, ...viaRest } = viaAnalyze;
    expect(viaRest).toEqual(directRest);
    expect(directAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(viaAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('analyze with empty object returns grade F', async () => {
    const r = await analyze({});
    expect(r.grade).toBe('F');
  });

  describe('with a fetched URL', () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('sets finalUrl when the response was redirected', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        url: 'https://www.example.com/',
        headers: new Headers({ 'x-content-type-options': 'nosniff' }),
        body: { cancel: vi.fn().mockResolvedValue(undefined) },
      }));

      const r = await analyze('https://example.com/');
      expect(r.url).toBe('https://example.com/');
      expect(r.finalUrl).toBe('https://www.example.com/');
    });

    it('leaves finalUrl unset when there is no redirect', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        url: 'https://example.com/',
        headers: new Headers({ 'x-content-type-options': 'nosniff' }),
        body: { cancel: vi.fn().mockResolvedValue(undefined) },
      }));

      const r = await analyze('https://example.com/');
      expect(r.finalUrl).toBeUndefined();
    });
  });
});

describe('checkHSTS', () => {
  it('missing header returns score 0', () => {
    expect(checkHSTS({}).score).toBe(0);
    expect(checkHSTS({}).status).toBe('missing');
  });

  it('full HSTS returns score 20', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
    expect(r.score).toBe(20);
    expect(r.status).toBe('good');
  });

  it('short max-age triggers finding', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=3600' });
    expect(r.findings.some(f => f.includes('max-age'))).toBe(true);
  });

  it('missing includeSubDomains triggers finding', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000' });
    expect(r.findings.some(f => f.includes('includeSubDomains'))).toBe(true);
    expect(r.score).toBe(15);
  });

  it('preload adds 2 bonus points', () => {
    const withPreload = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
    const withoutPreload = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' });
    expect(withPreload.score).toBe(withoutPreload.score + 2);
  });

  it('case-insensitive header name matching', () => {
    const r = checkHSTS({ 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload' });
    expect(r.score).toBe(20);
  });

  it('max-age=0 is a revocation: warning, no includeSubDomains/preload bonus', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=0; includeSubDomains; preload' });
    expect(r.score).toBe(10);
    expect(r.status).toBe('warning');
    expect(r.findings.some(f => /revoke/i.test(f))).toBe(true);
  });

  it('max-age between 1 and 31536000 gives partial credit', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=86400; includeSubDomains' });
    expect(r.score).toBeGreaterThan(10);
    expect(r.score).toBeLessThan(20);
  });
});

describe('checkCSP', () => {
  it('missing CSP returns score 0', () => {
    expect(checkCSP({}).score).toBe(0);
  });

  it('report-only CSP gets partial credit and a warning, not missing', () => {
    const r = checkCSP({ 'content-security-policy-report-only': "default-src 'self'" });
    expect(r.status).toBe('warning');
    expect(r.score).toBe(10);
    expect(r.findings.some(f => /report-only/i.test(f))).toBe(true);
  });

  it('enforcing CSP takes precedence over report-only', () => {
    const r = checkCSP({
      'content-security-policy': "default-src 'self'; form-action 'self'",
      'content-security-policy-report-only': "default-src *",
    });
    expect(r.score).toBe(18);
    expect(r.status).toBe('warning');
  });

  it('detects unsafe-inline', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" });
    expect(r.findings.some(f => f.includes('unsafe-inline'))).toBe(true);
    expect(r.score).toBeLessThan(20);
  });

  it('detects unsafe-eval', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-eval'" });
    expect(r.findings.some(f => f.includes('unsafe-eval'))).toBe(true);
    expect(r.score).toBeLessThan(20);
  });

  it('detects wildcard in default-src', () => {
    const r = checkCSP({ 'content-security-policy': 'default-src *' });
    expect(r.findings.some(f => f.includes('Wildcard'))).toBe(true);
  });

  it('detects wildcard in script-src', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src *" });
    expect(r.findings.some(f => f.includes('Wildcard'))).toBe(true);
  });

  it("does not penalize 'unsafe-inline' when 'strict-dynamic' + nonce present", () => {
    const r = checkCSP({ 'content-security-policy': "script-src 'strict-dynamic' 'nonce-abc123' 'unsafe-inline' https://example.com; form-action 'self'; base-uri 'none'" });
    expect(r.findings.some(f => f.includes('unsafe-inline'))).toBe(false);
    expect(r.score).toBe(20);
  });

  it("still penalizes 'unsafe-inline' when 'strict-dynamic' present without nonce/hash", () => {
    const r = checkCSP({ 'content-security-policy': "script-src 'strict-dynamic' 'unsafe-inline'" });
    expect(r.findings.some(f => f.includes('unsafe-inline'))).toBe(true);
  });

  it('detects wildcard in connect-src', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; connect-src *" });
    expect(r.findings.some(f => /Wildcard.*connect-src/i.test(f))).toBe(true);
    expect(r.score).toBe(13);
  });

  it('detects wildcard in form-action', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action *" });
    expect(r.findings.some(f => /Wildcard.*form-action/i.test(f))).toBe(true);
  });

  it("detects mid-policy wildcard (default-src 'self' *)", () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self' *; form-action 'self'" });
    expect(r.findings.some(f => /Wildcard/i.test(f))).toBe(true);
    expect(r.score).toBe(13);
  });

  it('does not flag a wildcard in low-risk img-src', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; img-src *" });
    expect(r.findings.some(f => /Wildcard/i.test(f))).toBe(false);
    expect(r.score).toBe(18);
  });

  it('detects bare scheme (https:) in script-src as permissive', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src https:; form-action 'self'; base-uri 'self'" });
    expect(r.findings.some(f => /Wildcard or bare-scheme/i.test(f))).toBe(true);
    expect(r.score).toBeLessThan(20);
  });

  it('detects bare scheme (https:) in default-src as permissive', () => {
    const r = checkCSP({ 'content-security-policy': "default-src https:" });
    expect(r.findings.some(f => /Wildcard or bare-scheme/i.test(f))).toBe(true);
  });

  it('does not flag bare scheme in low-risk img-src', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; img-src https:" });
    expect(r.findings.some(f => /Wildcard or bare-scheme/i.test(f))).toBe(false);
  });

  it('clean CSP returns score 20', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; base-uri 'self'" });
    expect(r.score).toBe(20);
    expect(r.status).toBe('good');
  });

  it('flags missing form-action directive', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'" });
    expect(r.findings.some(f => /form-action/i.test(f))).toBe(true);
    expect(r.status).toBe('warning');
    expect(r.score).toBe(15);
  });

  it("form-action 'none' satisfies the form-action check", () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'none'; base-uri 'none'" });
    expect(r.findings.some(f => /form-action/i.test(f))).toBe(false);
    expect(r.score).toBe(20);
  });

  it('CSP with both unsafe-inline and unsafe-eval scores 8', () => {
    // 20 - 5 (unsafe-inline) - 5 (unsafe-eval) - 2 (no base-uri) = 8, above the floor of 5
    const r = checkCSP({ 'content-security-policy': "default-src 'unsafe-inline' 'unsafe-eval'; form-action 'self'" });
    expect(r.score).toBe(8);
  });

  it('minimum score for any CSP is 5', () => {
    // 20 - 5 (unsafe-inline) - 5 (unsafe-eval) - 5 (wildcard) = 5, floor is 5
    const r = checkCSP({ 'content-security-policy': "default-src * 'unsafe-inline' 'unsafe-eval'" });
    expect(r.score).toBe(5);
  });

  it('flags missing base-uri directive', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'" });
    expect(r.findings.some(f => /base-uri/i.test(f))).toBe(true);
    expect(r.status).toBe('warning');
    expect(r.score).toBe(18);
  });

  it("base-uri 'none' satisfies the base-uri check", () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; base-uri 'none'" });
    expect(r.findings.some(f => /base-uri/i.test(f))).toBe(false);
    expect(r.score).toBe(20);
  });

  it("base-uri 'self' satisfies the base-uri check", () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; form-action 'self'; base-uri 'self'" });
    expect(r.findings.some(f => /base-uri/i.test(f))).toBe(false);
    expect(r.score).toBe(20);
  });
});

describe('checkXFrameOptions', () => {
  it('missing header returns score 0', () => {
    expect(checkXFrameOptions({}).score).toBe(0);
    expect(checkXFrameOptions({}).status).toBe('missing');
  });

  it('DENY returns score 15', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'DENY' });
    expect(r.score).toBe(15);
    expect(r.status).toBe('good');
  });

  it('SAMEORIGIN returns score 15', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'SAMEORIGIN' });
    expect(r.score).toBe(15);
    expect(r.status).toBe('good');
  });

  it('lowercase deny works', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'deny' });
    expect(r.score).toBe(15);
  });

  it('invalid value returns score 8', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'ALLOW-FROM https://example.com' });
    expect(r.score).toBe(8);
    expect(r.status).toBe('warning');
  });

  it('CSP frame-ancestors satisfies X-Frame-Options check', () => {
    const r = checkXFrameOptions({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" });
    expect(r.score).toBe(15);
    expect(r.status).toBe('good');
  });

  it("CSP frame-ancestors 'self' with specific origins is protective", () => {
    const r = checkXFrameOptions({ 'content-security-policy': "frame-ancestors 'self' https://trusted.example" });
    expect(r.score).toBe(15);
    expect(r.status).toBe('good');
  });

  it('CSP frame-ancestors * is not protective', () => {
    const r = checkXFrameOptions({ 'content-security-policy': 'frame-ancestors *' });
    expect(r.score).toBe(8);
    expect(r.status).toBe('warning');
    expect(r.findings.some(f => /any origin/i.test(f))).toBe(true);
  });

  it('CSP frame-ancestors with bare scheme (https:) is not protective', () => {
    const r = checkXFrameOptions({ 'content-security-policy': 'frame-ancestors https:' });
    expect(r.score).toBe(8);
    expect(r.status).toBe('warning');
  });

  it('case-insensitive header name matching', () => {
    const r = checkXFrameOptions({ 'X-Frame-Options': 'DENY' });
    expect(r.score).toBe(15);
  });
});

describe('checkXContentTypeOptions', () => {
  it('nosniff returns score 10', () => {
    expect(checkXContentTypeOptions({ 'x-content-type-options': 'nosniff' }).score).toBe(10);
  });

  it('missing returns score 0', () => {
    expect(checkXContentTypeOptions({}).score).toBe(0);
    expect(checkXContentTypeOptions({}).status).toBe('missing');
  });

  it('wrong value returns score 5', () => {
    const r = checkXContentTypeOptions({ 'x-content-type-options': 'sniff' });
    expect(r.score).toBe(5);
    expect(r.status).toBe('warning');
  });

  it('case-insensitive header name matching', () => {
    expect(checkXContentTypeOptions({ 'X-Content-Type-Options': 'nosniff' }).score).toBe(10);
  });
});

describe('checkReferrerPolicy', () => {
  it('strong value returns score 10', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'strict-origin-when-cross-origin' });
    expect(r.score).toBe(10);
    expect(r.status).toBe('good');
  });

  it('missing returns score 0', () => {
    expect(checkReferrerPolicy({}).score).toBe(0);
  });

  it('no-referrer is strong', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'no-referrer' });
    expect(r.score).toBe(10);
    expect(r.status).toBe('good');
  });

  it('strict-origin is strong', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'strict-origin' });
    expect(r.score).toBe(10);
  });

  it('same-origin is strong', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'same-origin' });
    expect(r.score).toBe(10);
  });

  it('no-referrer-when-downgrade is not strong (leaks full URL cross-origin)', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'no-referrer-when-downgrade' });
    expect(r.score).toBe(5);
    expect(r.status).toBe('warning');
  });

  it('unsafe-url returns score 5', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'unsafe-url' });
    expect(r.score).toBe(5);
    expect(r.status).toBe('warning');
  });

  it('origin is not in strong list', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'origin' });
    expect(r.score).toBe(5);
    expect(r.status).toBe('warning');
  });
});

describe('checkPermissionsPolicy', () => {
  it('missing returns score 0', () => {
    expect(checkPermissionsPolicy({}).score).toBe(0);
    expect(checkPermissionsPolicy({}).status).toBe('missing');
  });

  it('present returns score 10', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=(), microphone=(), geolocation=()' });
    expect(r.score).toBe(10);
    expect(r.status).toBe('good');
  });

  it('falls back to feature-policy header', () => {
    const r = checkPermissionsPolicy({ 'feature-policy': 'camera=(), microphone=(), geolocation=()' });
    expect(r.score).toBe(10);
    expect(r.status).toBe('good');
  });

  it('permissions-policy takes precedence over feature-policy', () => {
    const r = checkPermissionsPolicy({
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      'feature-policy': 'camera *',
    });
    expect(r.score).toBe(10);
    expect(r.raw).toBe('camera=(), microphone=(), geolocation=()');
  });

  it('partial policy (camera only) returns warning, not full score', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=()' });
    expect(r.score).toBe(5);
    expect(r.status).toBe('warning');
  });

  it('good policy emits no recommendations', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=(), microphone=(), geolocation=()' });
    expect(r.status).toBe('good');
    expect(r.findings).toEqual([]);
    expect(r.recommendations).toEqual([]);
  });

  it('warning policy still emits a recommendation', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=()' });
    expect(r.recommendations.length).toBeGreaterThan(0);
  });

  it('case-insensitive header name matching', () => {
    const r = checkPermissionsPolicy({ 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()' });
    expect(r.score).toBe(10);
  });
});

describe('checkCrossOriginPolicies', () => {
  it('missing all returns score 0', () => {
    const r = checkCrossOriginPolicies({});
    expect(r.score).toBe(0);
    expect(r.status).toBe('missing');
  });

  it('all three present returns score 5 (capped)', () => {
    const r = checkCrossOriginPolicies({
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
    });
    expect(r.score).toBe(5);
    expect(r.status).toBe('good');
  });

  it('one present returns score 2', () => {
    const r = checkCrossOriginPolicies({ 'cross-origin-opener-policy': 'same-origin' });
    expect(r.score).toBe(2);
    expect(r.status).toBe('warning');
  });

  it('two present returns score 4', () => {
    const r = checkCrossOriginPolicies({
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
    });
    expect(r.score).toBe(4);
    expect(r.status).toBe('good');
  });

  it('permissive values (unsafe-none / cross-origin) earn no credit', () => {
    const r = checkCrossOriginPolicies({
      'cross-origin-embedder-policy': 'unsafe-none',
      'cross-origin-opener-policy': 'unsafe-none',
      'cross-origin-resource-policy': 'cross-origin',
    });
    expect(r.score).toBe(0);
    expect(r.status).toBe('warning');
    expect(r.findings.every(f => /no cross-origin isolation/i.test(f))).toBe(true);
  });

  it('mixed: only protective values count', () => {
    const r = checkCrossOriginPolicies({
      'cross-origin-opener-policy': 'same-origin',     // protective
      'cross-origin-resource-policy': 'cross-origin',  // permissive
    });
    expect(r.score).toBe(2);
    expect(r.status).toBe('warning');
  });

  it('COOP same-origin-allow-popups counts as protective', () => {
    const r = checkCrossOriginPolicies({ 'cross-origin-opener-policy': 'same-origin-allow-popups' });
    expect(r.score).toBe(2);
  });

  it('includes raw values in output', () => {
    const r = checkCrossOriginPolicies({ 'cross-origin-opener-policy': 'same-origin' });
    expect(r.raw).toContain('COOP: same-origin');
  });

  it('case-insensitive header name matching', () => {
    const r = checkCrossOriginPolicies({ 'Cross-Origin-Opener-Policy': 'same-origin' });
    expect(r.score).toBe(2);
  });
});

describe('grade boundaries', () => {
  it('A+ at 90%', () => {
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; form-action 'self'; base-uri 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
    };
    const r = analyzeHeaders(headers);
    expect(r.percentage).toBeGreaterThanOrEqual(90);
    expect(r.grade).toBe('A+');
  });

  it('A at 75%', () => {
    // Drop preload from HSTS: score = 18 (HSTS) + 20 (CSP) + 15 + 10 + 10 + 10 + 5 = 88 -- too high
    // Let's use stricter combo: missing permissions-policy too
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; form-action 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
    };
    const r = analyzeHeaders(headers);
    // 18 + 20 + 15 + 10 + 10 + 0 + 5 = 78
    expect(r.grade).toBe('A');
  });

  it('B at 60%', () => {
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; form-action 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
    };
    const r = analyzeHeaders(headers);
    // 18 + 20 + 15 + 10 + 10 + 0 + 0 = 73 -- still A
    // Need to drop more: B = 60-74%
    // HSTS=18, CSP=20, XFO=15, XCIO=10 = 63 -> B
    expect(r.grade).toBe('B');
  });

  it('C at 40%', () => {
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
    };
    const r = analyzeHeaders(headers);
    // 18 + 0 + 15 + 10 = 43 -> C
    expect(r.grade).toBe('C');
  });

  it('D at 20%', () => {
    const headers = {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
    };
    const r = analyzeHeaders(headers);
    // 18 + 10 = 28 -> D
    expect(r.grade).toBe('D');
  });

  it('F below 20%', () => {
    const r = analyzeHeaders({});
    expect(r.grade).toBe('F');
  });
});
