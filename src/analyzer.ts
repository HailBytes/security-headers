import type { SecurityHeaderReport, Grade } from './types.js';
import { checkHSTS, checkCSP, checkXFrameOptions, checkXContentTypeOptions, checkReferrerPolicy, checkPermissionsPolicy, checkCrossOriginPolicies, checkSetCookie } from './rules.js';

function toGrade(pct: number): Grade {
  if (pct >= 90) return 'A+';
  if (pct >= 75) return 'A';
  if (pct >= 60) return 'B';
  if (pct >= 40) return 'C';
  if (pct >= 20) return 'D';
  return 'F';
}

export function analyzeHeaders(headers: Record<string, string>, url?: string): SecurityHeaderReport {
  const checks = [
    checkHSTS(headers),
    checkCSP(headers),
    checkXFrameOptions(headers),
    checkXContentTypeOptions(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkCrossOriginPolicies(headers),
    checkSetCookie(headers),
  ];
  const score = checks.reduce((s, c) => s + c.score, 0);
  const maxScore = checks.reduce((s, c) => s + c.maxScore, 0);
  const percentage = Math.round((score / maxScore) * 100);
  return { url, grade: toGrade(percentage), score, maxScore, percentage, headers: checks, analyzedAt: new Date().toISOString() };
}
