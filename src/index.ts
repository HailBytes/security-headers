export { analyzeHeaders } from './analyzer.js';
export { fetchHeaders } from './fetch.js';
export type { SecurityHeaderReport, HeaderFinding, Grade, HeaderStatus } from './types.js';

import { fetchHeaders } from './fetch.js';
import { analyzeHeaders } from './analyzer.js';
import type { SecurityHeaderReport } from './types.js';

export async function analyze(input: string | Record<string, string>): Promise<SecurityHeaderReport> {
  if (typeof input === 'string') {
    const headers = await fetchHeaders(input);
    return analyzeHeaders(headers, input);
  }
  return analyzeHeaders(input);
}
