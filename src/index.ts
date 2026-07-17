export { analyzeHeaders } from './analyzer.js';
export { fetchHeaders, fetchHeadersWithMeta } from './fetch.js';
export type { SecurityHeaderReport, HeaderFinding, Grade, HeaderStatus } from './types.js';
export type { FetchOptions, FetchHeadersResult } from './fetch.js';

import { fetchHeadersWithMeta } from './fetch.js';
import { analyzeHeaders } from './analyzer.js';
import type { SecurityHeaderReport } from './types.js';
import type { FetchOptions } from './fetch.js';

export async function analyze(input: string | Record<string, string>, options?: FetchOptions): Promise<SecurityHeaderReport> {
  if (typeof input === 'string') {
    const { headers, finalUrl } = await fetchHeadersWithMeta(input, options);
    const report = analyzeHeaders(headers, input);
    if (finalUrl && finalUrl !== input) report.finalUrl = finalUrl;
    return report;
  }
  return analyzeHeaders(input);
}
