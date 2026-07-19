export interface ParsedArgs {
  help: boolean;
  version: boolean;
  json: boolean;
  timeoutMs?: number;
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

  // Exclude the value consumed by --timeout by position, not by string equality
  // against the parsed number — matching by value broke whenever a URL happened
  // to coincide with the (possibly NaN-stringified) timeout argument.
  const url = args.find((a, i) => !a.startsWith('--') && !(timeoutIndex !== -1 && i === timeoutIndex + 1));

  return { help, version, json, timeoutMs, url };
}
