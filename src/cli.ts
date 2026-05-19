#!/usr/bin/env node
import { analyze } from './index.js';
import type { SecurityHeaderReport } from './types.js';

const R = '\x1b[0m';
const B = '\x1b[1m';
const D = '\x1b[2m';
const RED = '\x1b[31m';
const GRN = '\x1b[32m';
const YLW = '\x1b[33m';

const GRADE_COLOR: Record<string, string> = {
  'A+': '\x1b[92m', A: GRN, B: YLW, C: YLW, D: RED, F: '\x1b[91m',
};
const STATUS_ICON: Record<string, string> = {
  good: `${GRN}✓${R}`, warning: `${YLW}⚠${R}`, missing: `${RED}✗${R}`, error: `${RED}✗${R}`,
};

function printReport(r: SecurityHeaderReport) {
  const gc = GRADE_COLOR[r.grade] ?? '';
  console.log(`\n${B}Security Headers Report${R}`);
  if (r.url) console.log(`${D}${r.url}${R}`);
  console.log(`${D}Analyzed: ${r.analyzedAt}${R}\n`);
  console.log(`Grade: ${B}${gc}${r.grade}${R}   Score: ${r.score}/${r.maxScore} (${r.percentage}%)\n`);
  console.log('\u2500'.repeat(60));
  for (const h of r.headers) {
    const icon = STATUS_ICON[h.status] ?? '?';
    console.log(`${icon} ${B}${h.header}${R} ${D}(${h.score}/${h.maxScore})${R}`);
    if (h.raw) console.log(`  ${D}${h.raw.slice(0, 80)}${h.raw.length > 80 ? '\u2026' : ''}${R}`);
    for (const f of h.findings) console.log(`  ${YLW}\u2192${R} ${f}`);
    for (const rec of h.recommendations) console.log(`  ${D}  Fix: ${rec}${R}`);
  }
  console.log('\u2500'.repeat(60) + '\n');
}

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const url = args.find(a => !a.startsWith('--'));
  if (!url) {
    console.error('Usage: security-headers <url> [--json]');
    console.error('Example: security-headers https://example.com');
    process.exit(1);
  }
  try {
    const report = await analyze(url);
    if (jsonMode) { console.log(JSON.stringify(report, null, 2)); }
    else { printReport(report); }
    if (report.grade === 'D' || report.grade === 'F') process.exit(1);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
