import { describe, it, expect } from 'vitest';
import { parseArgs } from '../src/cli-args.js';

describe('parseArgs', () => {
  it('parses a plain URL with no flags', () => {
    const r = parseArgs(['https://example.com']);
    expect(r.url).toBe('https://example.com');
    expect(r.timeoutMs).toBeUndefined();
    expect(r.error).toBeUndefined();
  });

  it('parses --json and --timeout alongside the URL', () => {
    const r = parseArgs(['https://example.com', '--json', '--timeout', '3000']);
    expect(r.url).toBe('https://example.com');
    expect(r.json).toBe(true);
    expect(r.timeoutMs).toBe(3000);
  });

  it('parses the URL when it precedes --timeout', () => {
    const r = parseArgs(['https://example.com', '--timeout', '3000']);
    expect(r.url).toBe('https://example.com');
    expect(r.timeoutMs).toBe(3000);
  });

  it('rejects a non-numeric --timeout value instead of silently using NaN', () => {
    const r = parseArgs(['https://example.com', '--timeout', 'abc']);
    expect(r.error).toMatch(/--timeout requires a positive number/);
    expect(r.timeoutMs).toBeUndefined();
  });

  it('rejects --timeout with no value (e.g. it precedes the URL by mistake)', () => {
    const r = parseArgs(['--timeout', 'https://example.com']);
    expect(r.error).toMatch(/--timeout requires a positive number/);
  });

  it('rejects a zero or negative --timeout', () => {
    expect(parseArgs(['https://example.com', '--timeout', '0']).error).toBeDefined();
    expect(parseArgs(['https://example.com', '--timeout', '-500']).error).toBeDefined();
  });

  it('rejects --timeout as the trailing argument with nothing after it', () => {
    const r = parseArgs(['https://example.com', '--timeout']);
    expect(r.error).toMatch(/<nothing>/);
  });

  it('leaves url undefined when only flags are given', () => {
    const r = parseArgs(['--json']);
    expect(r.url).toBeUndefined();
  });

  it('recognizes --help and --version', () => {
    expect(parseArgs(['--help']).help).toBe(true);
    expect(parseArgs(['-h']).help).toBe(true);
    expect(parseArgs(['--version']).version).toBe(true);
    expect(parseArgs(['-v']).version).toBe(true);
  });

  it('leaves failOnGrade undefined when --fail-on is omitted (preserves current D/F-only default)', () => {
    const r = parseArgs(['https://example.com']);
    expect(r.failOnGrade).toBeUndefined();
  });

  it('parses a valid --fail-on grade case-insensitively', () => {
    expect(parseArgs(['https://example.com', '--fail-on', 'C']).failOnGrade).toBe('C');
    expect(parseArgs(['https://example.com', '--fail-on', 'c']).failOnGrade).toBe('C');
    expect(parseArgs(['https://example.com', '--fail-on', 'A+']).failOnGrade).toBe('A+');
  });

  it('rejects an invalid --fail-on grade', () => {
    const r = parseArgs(['https://example.com', '--fail-on', 'Z']);
    expect(r.error).toMatch(/--fail-on must be one of/);
    expect(r.failOnGrade).toBeUndefined();
  });

  it('rejects --fail-on with no value', () => {
    const r = parseArgs(['https://example.com', '--fail-on']);
    expect(r.error).toMatch(/--fail-on must be one of/);
  });

  it('excludes both --timeout and --fail-on values from URL detection', () => {
    const r = parseArgs(['--timeout', '3000', '--fail-on', 'C', 'https://example.com']);
    expect(r.url).toBe('https://example.com');
    expect(r.timeoutMs).toBe(3000);
    expect(r.failOnGrade).toBe('C');
  });
});
