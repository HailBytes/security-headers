import { describe, it, expect } from 'vitest';
import { analyzeHeaders } from '../src/analyzer.js';
import { checkHSTS, checkCSP, checkXContentTypeOptions, checkReferrerPolicy } from '../src/rules.js';

const STRONG_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; img-src *",
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
});

describe('checkCSP', () => {
  it('missing CSP returns score 0', () => {
    expect(checkCSP({}).score).toBe(0);
  });
  it('detects unsafe-inline', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" });
    expect(r.findings.some(f => f.includes('unsafe-inline'))).toBe(true);
    expect(r.score).toBeLessThan(20);
  });
  it('clean CSP returns score 20', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'" });
    expect(r.score).toBe(20);
  });
});

describe('checkXContentTypeOptions', () => {
  it('nosniff returns score 10', () => {
    expect(checkXContentTypeOptions({ 'x-content-type-options': 'nosniff' }).score).toBe(10);
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
});
