#!/usr/bin/env node
import { createRequire } from 'node:module';
import { analyze } from './index.js';
import type { SecurityHeaderReport } from './types.js';

const require = createRequire(import.meta.url);

const R = '\x1b[0m';
const B = '\x1b[1m';
const D = '\x1b[2m';
const RED = '\x1b[31m';
const GRN = '\x1b[32m';
const YLW = '\x1b[33m';

const GRADE_COLOR: Record<string, string> = {
  'A+': '\x1b[92m', A: GRN, B: YLW, C: YLW, D: RED, F: '\x1b[91m',
};
// Numeric rank so grade comparisons are order-independent string operations.
const GRADE_RANK: Record<string, number> = { 'A+': 6, A: 5, B: 4, C: 3, D: 2, F: 1 };
const VALID_GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];
const STATUS_ICON: Record<string, string> = {
  good: `${GRN}✓${R}`, warning: `${YLW}⚠${R}`, missing: `${RED}✗${R}`, error: `${RED}✗${R}`,
};

function getVersion(): string {
  try {
    const pkg = require('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function printHelp() {
  const v = getVersion();
  console.log(`${B}@hailbytes/security-headers${R} v${v}`);
  console.log('');
  console.log(`${B}Usage:${R}`);
  console.log('  security-headers <url> [options]');
  console.log('  npx @hailbytes/security-headers <url> [options]');
  console.log('');
  console.log(`${B}Options:${R}`);
  console.log('  --json             Output report as JSON');
  console.log('  --timeout ms       Fetch timeout in milliseconds (default: 10000)');
  console.log('  --min-grade grade  Exit 1 if grade is below this threshold (default: C)');
  console.log('                     Valid grades: A+, A, B, C, D, F');
  console.log('  --version          Print version and exit');
  console.log('  --help             Print this help and exit');
  console.log('');
  console.log(`${B}Examples:${R}`);
  console.log('  security-headers https://example.com');
  console.log('  security-headers https://example.com --json');
  console.log('  security-headers https://example.com --timeout 5000');
  console.log('  security-headers https://example.com --min-grade B');
  console.log('  security-headers https://staging.example.com || echo "Gate failed"');
}

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

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(getVersion());
    process.exit(0);
  }

  const jsonMode = args.includes('--json');
  const timeoutArg = args.find((a, i) => a === '--timeout' && args[i + 1]);
  const timeoutMs = timeoutArg ? parseInt(args[args.indexOf('--timeout') + 1], 10) : undefined;

  const minGradeArg = args.find((a, i) => a === '--min-grade' && args[i + 1]);
  const rawMinGrade = minGradeArg ? args[args.indexOf('--min-grade') + 1].toUpperCase() : 'C';
  // Normalise lowercase 'a+' -> 'A+' etc., but also accept 'a' -> 'A'.
  const minGrade = rawMinGrade === 'A+' ? 'A+' : rawMinGrade.charAt(0);
  const resolvedMinGrade = VALID_GRADES.includes(rawMinGrade) ? rawMinGrade : (VALID_GRADES.includes(minGrade) ? minGrade : null);
  if (!resolvedMinGrade) {
    console.error(`Invalid --min-grade value '${rawMinGrade}'. Valid grades: ${VALID_GRADES.join(', ')}`);
    process.exit(1);
  }

  const knownValueArgs = new Set([String(timeoutMs), resolvedMinGrade, rawMinGrade]);
  const url = args.find(a => !a.startsWith('--') && !knownValueArgs.has(a));
  if (!url) {
    console.error('Usage: security-headers <url> [--json] [--timeout ms] [--help] [--version]');
    console.error('Run with --help for full usage information.');
    process.exit(1);
  }
  try {
    const report = await analyze(url, timeoutMs !== undefined ? { timeoutMs } : undefined);
    if (jsonMode) { console.log(JSON.stringify(report, null, 2)); }
    else { printReport(report); }
    if ((GRADE_RANK[report.grade] ?? 0) < (GRADE_RANK[resolvedMinGrade] ?? 0)) process.exit(1);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
