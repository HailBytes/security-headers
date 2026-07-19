#!/usr/bin/env node
import { createRequire } from 'node:module';
import { analyze } from './index.js';
import { parseArgs, GRADE_ORDER } from './cli-args.js';
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
  console.log('  --fail-on grade    Exit 1 when grade is at or below this level (default: D)');
  console.log(`                     Valid grades (best→worst): ${GRADE_ORDER.join(', ')}`);
  console.log('  --allow-private    Allow scanning hosts that resolve to private/internal IPs');
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
  if (r.finalUrl) console.log(`${YLW}Redirected to: ${r.finalUrl}${R}`);
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
  const parsed = parseArgs(args);

  if (parsed.help) {
    printHelp();
    process.exit(0);
  }

  if (parsed.version) {
    console.log(getVersion());
    process.exit(0);
  }

  if (parsed.error) {
    console.error(`Error: ${parsed.error}`);
    console.error('Run with --help for full usage information.');
    process.exit(1);
  }

  if (!parsed.url) {
    console.error('Usage: security-headers <url> [--json] [--timeout ms] [--fail-on grade] [--allow-private] [--help] [--version]');
    console.error('Run with --help for full usage information.');
    process.exit(1);
  }
  const allowPrivateNetworks = args.includes('--allow-private');
  try {
    const report = await analyze(parsed.url, {
      ...(parsed.timeoutMs !== undefined ? { timeoutMs: parsed.timeoutMs } : {}),
      ...(allowPrivateNetworks ? { allowPrivateNetworks } : {}),
    });
    if (parsed.json) { console.log(JSON.stringify(report, null, 2)); }
    else { printReport(report); }
    const threshold = parsed.failOnGrade ?? 'D';
    if (GRADE_ORDER.indexOf(report.grade) >= GRADE_ORDER.indexOf(threshold)) process.exit(1);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

await main();
