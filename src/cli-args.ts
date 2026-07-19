import type { Grade } from './types.js';

// Ordered best to worst so index comparisons work for --fail-on threshold logic.
export const GRADE_ORDER: readonly Grade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

export interface ParsedArgs {
  help: boolean;
  version: boolean;
  json: boolean;
  timeoutMs?: number;
  failOnGrade?: Grade;
  url?: string;
  error?: string;
}

export function parseArgs(args: string[]): ParsedArgs {
  const help = args.includes('--help') || args.includes('-h');
  const version = args.includes('--version') || args.includes('-v');
  const json = args.includes('--json');

  const timeoutIndex = args.indexOf('--timeout');
  let timeoutMs: number | undefined;
  if (timeoutIndex !== -1) {
    const raw = args[timeoutIndex + 1];
    const parsed = raw !== undefined ? Number(raw) : NaN;
    if (!Number.isFinite(parsed) || parsed <= 0) {
      const got = raw === undefined ? '<nothing>' : JSON.stringify(raw);
      return { help, version, json, error: `--timeout requires a positive number of milliseconds (got ${got})` };
    }
    timeoutMs = parsed;
  }

  const failOnIndex = args.indexOf('--fail-on');
  let failOnGrade: Grade | undefined;
  if (failOnIndex !== -1) {
    const raw = args[failOnIndex + 1];
    const normalized = raw?.toUpperCase();
    if (!normalized || !(GRADE_ORDER as readonly string[]).includes(normalized)) {
      const got = raw === undefined ? '<nothing>' : JSON.stringify(raw);
      return { help, version, json, error: `--fail-on must be one of: ${GRADE_ORDER.join(', ')} (got ${got})` };
    }
    failOnGrade = normalized as Grade;
  }

  // Exclude the values consumed by --timeout/--fail-on by position, not by string
  // equality against the parsed value — matching by value broke whenever a URL
  // happened to coincide with a (possibly NaN-stringified) flag argument.
  const url = args.find((a, i) =>
    !a.startsWith('--') &&
    !(timeoutIndex !== -1 && i === timeoutIndex + 1) &&
    !(failOnIndex !== -1 && i === failOnIndex + 1)
  );

  return { help, version, json, timeoutMs, failOnGrade, url };
}
