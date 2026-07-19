import { vi, describe, it, expect, afterEach } from 'vitest';

// Stable reference defined outside the factory so it survives vi.resetModules().
// When the module registry is cleared and fetch.js is re-imported, Vitest runs
// the factory again — but the factory closes over this same vi.fn() instance.
const fetchHeadersMock = vi.fn();

vi.mock('../src/fetch.js', () => ({
  fetchHeadersWithMeta: fetchHeadersMock,
}));

// index.ts only sets report.finalUrl when it differs from the requested URL,
// so defaulting finalUrl to the same URL keeps existing assertions (which
// don't care about redirects) unaffected.
function withMeta(headers: Record<string, string>, finalUrl = 'https://example.com') {
  return { headers, finalUrl };
}

// A fully-configured set of headers → A+ (90/100, 90%)
const A_PLUS_HEADERS: Record<string, string> = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; form-action 'self'; base-uri 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

// Partial HSTS + nosniff only → 28/100 → D grade
const D_HEADERS: Record<string, string> = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
};

/**
 * Runs the CLI with the given argv arguments and returns captured
 * stdout, stderr, and the exit code passed to process.exit().
 *
 * The CLI module uses top-level `await main()`, so the dynamic import
 * resolves only after main() has fully finished (or thrown via the mocked
 * process.exit). vi.resetModules() ensures main() is re-executed on every
 * call — the vi.mock() registration for fetch.js persists across resets.
 */
async function runCli(args: string[]): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number;
}> {
  const savedArgv = process.argv;
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  let exitCode = 0;

  process.argv = ['node', 'cli.js', ...args];

  const logSpy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    stdoutChunks.push(a.map(String).join(' '));
  });
  const errorSpy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    stderrChunks.push(a.map(String).join(' '));
  });
  vi.spyOn(process, 'exit').mockImplementation((code?: number | string) => {
    exitCode = typeof code === 'number' ? code : 0;
    // Throwing causes main() to reject, which propagates through the
    // top-level `await main()` in cli.ts and rejects the dynamic import.
    throw new Error(`process.exit(${exitCode})`);
  });

  vi.resetModules();
  try {
    await import('../src/cli.js');
  } catch {
    // swallow the throw from the mocked process.exit()
  }

  process.argv = savedArgv;
  logSpy.mockRestore();
  errorSpy.mockRestore();
  vi.restoreAllMocks();

  return {
    stdout: stdoutChunks.join('\n'),
    stderr: stderrChunks.join('\n'),
    exitCode,
  };
}

describe('cli', () => {
  afterEach(() => {
    fetchHeadersMock.mockReset();
  });

  it('exits 0 and prints a report for an A+ site', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(A_PLUS_HEADERS));
    const { exitCode, stdout } = await runCli(['https://example.com']);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Security Headers Report');
  });

  it('exits 1 for an F-grade site — CI gate enforced', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta({}, 'https://bad.example.com'));
    const { exitCode } = await runCli(['https://bad.example.com']);
    expect(exitCode).toBe(1);
  });

  it('exits 1 for a D-grade site — CI gate enforced', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(D_HEADERS, 'https://d-grade.example.com'));
    const { exitCode } = await runCli(['https://d-grade.example.com']);
    expect(exitCode).toBe(1);
  });

  it('--json emits valid JSON with grade, score, and headers array', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(A_PLUS_HEADERS));
    const { stdout, exitCode } = await runCli(['https://example.com', '--json']);
    expect(exitCode).toBe(0);
    const report = JSON.parse(stdout);
    expect(report).toHaveProperty('grade');
    expect(report).toHaveProperty('score');
    expect(Array.isArray(report.headers)).toBe(true);
  });

  it('--json includes the url field', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(A_PLUS_HEADERS));
    const { stdout } = await runCli(['https://example.com', '--json']);
    const report = JSON.parse(stdout);
    expect(report.url).toBe('https://example.com');
  });

  it('--json includes finalUrl when the scan followed a redirect', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(A_PLUS_HEADERS, 'https://example.com/final'));
    const { stdout } = await runCli(['https://example.com', '--json']);
    const report = JSON.parse(stdout);
    expect(report.finalUrl).toBe('https://example.com/final');
  });

  it('--version prints a semver string and exits 0', async () => {
    const { stdout, exitCode } = await runCli(['--version']);
    expect(stdout).toMatch(/^\d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });

  it('-v is an alias for --version', async () => {
    const { stdout, exitCode } = await runCli(['-v']);
    expect(stdout).toMatch(/^\d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });

  it('--help prints usage information and exits 0', async () => {
    const { stdout, exitCode } = await runCli(['--help']);
    expect(stdout).toContain('Usage');
    expect(exitCode).toBe(0);
  });

  it('-h is an alias for --help', async () => {
    const { stdout, exitCode } = await runCli(['-h']);
    expect(stdout).toContain('Usage');
    expect(exitCode).toBe(0);
  });

  it('missing URL exits 1 with a usage hint on stderr', async () => {
    const { stderr, exitCode } = await runCli([]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Usage');
  });

  it('network error exits 1 with the error message on stderr', async () => {
    fetchHeadersMock.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const { stderr, exitCode } = await runCli(['https://unreachable.example.com']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('ECONNREFUSED');
  });

  it('--timeout passes the parsed integer value to fetchHeadersWithMeta', async () => {
    fetchHeadersMock.mockResolvedValueOnce(withMeta(A_PLUS_HEADERS));
    await runCli(['https://example.com', '--timeout', '3000']);
    expect(fetchHeadersMock).toHaveBeenCalledWith('https://example.com', { timeoutMs: 3000 });
  });
});
