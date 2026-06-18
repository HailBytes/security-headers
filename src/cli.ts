#!/usr/bin/env node
import { createRequire } from 'node:module';
import { analyze } from './index.js';
import type { SecurityHeaderReport, Grade } from './types.js';

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
const STATUS_ICON: Record<string, string> = {
  good: `${GRN}✓${R}`, warning: `${YLW}⚠${R}`, missing: `${RED}✗${R}`, error: `${RED}✗${R}`,
};

// Ordered from best to worst so index comparisons work for threshold logic.
const GRADE_ORDER: readonly Grade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

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
  console.log('  --fail-on grade    Exit 1 when grade is at or below this level (default: D)');
  console.log(`                     Valid grades (best→worst): ${GRADE_ORDER.join(', ')}`);
  console.log('  --version          Print version and exit');
  console.log('  --help             Print this help and exit');
  console.log('');
  console.log(`${B}Examples:${R}`);
  console.log('  security-headers https://example.com');
  console.log('  security-headers https://example.com --json');
  console.log('  security-headers https://example.com --timeout 5000');
  console.log('  security-headers https://staging.example.com --fail-on C');
  console.log('  security-headers https://staging.example.com || echo "Gate failed"');
}

function printReport(r: SecurityHeaderReport) {
  const gc = GRADE_COLOR[r.grade] ?? '';
  console.log(`\n${B}Security Headers Report${R}`);
  if (r.url) console.log(`${D}${r.url}${R}`);
  console.log(`${D}Analyzed: ${r.analyzedAt}${R}\n`);
  console.log(`Grade: ${B}${gc}${r.grade}${R}   Score: ${r.score}/${r.maxScore} (${r.percentage}%)\n`);
  console.log('─'.repeat(60));
  for (const h of r.headers) {
    const icon = STATUS_ICON[h.status] ?? '?';
    console.log(`${icon} ${B}${h.header}${R} ${D}(${h.score}/${h.maxScore})${R}`);
    if (h.raw) console.log(`  ${D}${h.raw.slice(0, 80)}${h.raw.length > 80 ? '…' : ''}${R}`);
    for (const f of h.findings) console.log(`  ${YLW}→${R} ${f}`);
    for (const rec of h.recommendations) console.log(`  ${D}  Fix: ${rec}${R}`);
  }
  console.log('─'.repeat(60) + '\n');
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

  // Collect values that follow named flags so they are not mistaken for the
  // URL positional argument.
  const flagValues = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '--timeout' || args[i] === '--fail-on') && i + 1 < args.length) {
      flagValues.add(args[i + 1]);
    }
  }

  const timeoutIdx = args.indexOf('--timeout');
  const timeoutMs = timeoutIdx !== -1 ? parseInt(args[timeoutIdx + 1], 10) : undefined;

  const failOnIdx = args.indexOf('--fail-on');
  const failOnGrade = failOnIdx !== -1 ? (args[failOnIdx + 1]?.toUpperCase() as Grade) : undefined;

  if (failOnGrade !== undefined && !GRADE_ORDER.includes(failOnGrade)) {
    console.error(`Error: --fail-on must be one of: ${GRADE_ORDER.join(', ')}`);
    process.exit(1);
  }

  const url = args.find(a => !a.startsWith('--') && !flagValues.has(a));
  if (!url) {
    console.error('Usage: security-headers <url> [--json] [--timeout ms] [--fail-on grade] [--help] [--version]');
    console.error('Run with --help for full usage information.');
    process.exit(1);
  }

  try {
    const report = await analyze(url, timeoutMs !== undefined ? { timeoutMs } : undefined);
    if (jsonMode) { console.log(JSON.stringify(report, null, 2)); }
    else { printReport(report); }

    const threshold = failOnGrade ?? 'D';
    if (GRADE_ORDER.indexOf(report.grade) >= GRADE_ORDER.indexOf(threshold)) process.exit(1);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
