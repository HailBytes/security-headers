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

const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'] as const;
type Grade = typeof GRADES[number];

// Returns true when reportGrade is at or worse than threshold (higher index = worse).
function gradeAtOrBelow(reportGrade: string, threshold: Grade): boolean {
  return GRADES.indexOf(reportGrade as Grade) >= GRADES.indexOf(threshold);
}

const GRADE_COLOR: Record<string, string> = {
  'A+': '\x1b[92m', A: GRN, B: YLW, C: YLW, D: RED, F: '\x1b[91m',
};
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
  console.log('  --json           Output report as JSON');
  console.log('  --timeout ms     Fetch timeout in milliseconds (default: 10000)');
  console.log('  --fail-on grade  Exit 1 when grade is at or below this threshold');
  console.log('                   (default: D — exits 1 on D or F)');
  console.log('                   Valid grades: A+, A, B, C, D, F');
  console.log('  --version        Print version and exit');
  console.log('  --help           Print this help and exit');
  console.log('');
  console.log(`${B}Examples:${R}`);
  console.log('  security-headers https://example.com');
  console.log('  security-headers https://example.com --json');
  console.log('  security-headers https://example.com --timeout 5000');
  console.log('  security-headers https://staging.example.com --fail-on C || echo "Gate failed"');
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

  const failOnIdx = args.indexOf('--fail-on');
  const failOnRaw = failOnIdx !== -1 ? args[failOnIdx + 1] : undefined;
  let failOn: Grade = 'D';
  if (failOnRaw !== undefined) {
    if (!(GRADES as readonly string[]).includes(failOnRaw)) {
      console.error(`Invalid --fail-on value: "${failOnRaw}". Valid grades: ${GRADES.join(', ')}`);
      process.exit(1);
    }
    failOn = failOnRaw as Grade;
  }

  const url = args.find(a => !a.startsWith('--') && a !== String(timeoutMs) && a !== failOnRaw);
  if (!url) {
    console.error('Usage: security-headers <url> [--json] [--timeout ms] [--fail-on grade] [--help] [--version]');
    console.error('Run with --help for full usage information.');
    process.exit(1);
  }
  try {
    const report = await analyze(url, timeoutMs !== undefined ? { timeoutMs } : undefined);
    if (jsonMode) { console.log(JSON.stringify(report, null, 2)); }
    else { printReport(report); }
    if (gradeAtOrBelow(report.grade, failOn)) process.exit(1);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
