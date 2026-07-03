import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';
import { fetchHeaders } from '../src/fetch.js';

function mockResponse(status: number, headers: Record<string, string>) {
  return {
    status,
    headers: {
      has: (k: string) => k.toLowerCase() in headers,
      get: (k: string) => headers[k.toLowerCase()] ?? null,
      forEach: (cb: (v: string, k: string) => void) => {
        for (const [k, v] of Object.entries(headers)) cb(v, k);
      },
    },
    body: { cancel: vi.fn() },
  };
}

describe('fetchHeaders — SSRF protection', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    vi.mocked(lookup).mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('rejects non-http(s) schemes', async () => {
    await expect(fetchHeaders('file:///etc/passwd')).rejects.toThrow(/scheme/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects literal loopback IPs', async () => {
    await expect(fetchHeaders('http://127.0.0.1/')).rejects.toThrow(/private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects cloud metadata endpoint', async () => {
    await expect(fetchHeaders('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(/private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects RFC1918 private ranges', async () => {
    await expect(fetchHeaders('http://10.0.0.5/')).rejects.toThrow(/private\/internal/i);
    await expect(fetchHeaders('http://192.168.1.1/')).rejects.toThrow(/private\/internal/i);
    await expect(fetchHeaders('http://172.16.0.1/')).rejects.toThrow(/private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects IPv6 loopback and unique-local addresses', async () => {
    await expect(fetchHeaders('http://[::1]/')).rejects.toThrow(/private\/internal/i);
    await expect(fetchHeaders('http://[fc00::1]/')).rejects.toThrow(/private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects hostnames that resolve to a private address', async () => {
    vi.mocked(lookup).mockResolvedValue({ address: '169.254.169.254', family: 4 } as any);
    await expect(fetchHeaders('http://metadata.internal/')).rejects.toThrow(/resolves to private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('allows public hostnames that resolve to a public address', async () => {
    vi.mocked(lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 } as any);
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, { 'content-security-policy': "default-src 'self'" }) as any);
    const headers = await fetchHeaders('https://example.com/');
    expect(headers['content-security-policy']).toBe("default-src 'self'");
  });

  it('rejects a redirect hop that points at a private address', async () => {
    vi.mocked(lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 } as any);
    vi.mocked(fetch).mockResolvedValueOnce(mockResponse(302, { location: 'http://169.254.169.254/latest/meta-data/' }) as any);
    await expect(fetchHeaders('https://example.com/')).rejects.toThrow(/private\/internal/i);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('follows redirects between public hosts', async () => {
    vi.mocked(lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 } as any);
    vi.mocked(fetch)
      .mockResolvedValueOnce(mockResponse(301, { location: 'https://example.com/next' }) as any)
      .mockResolvedValueOnce(mockResponse(200, { 'x-frame-options': 'DENY' }) as any);
    const headers = await fetchHeaders('https://example.com/');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('gives up after too many redirects', async () => {
    vi.mocked(lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 } as any);
    vi.mocked(fetch).mockResolvedValue(mockResponse(302, { location: 'https://example.com/loop' }) as any);
    await expect(fetchHeaders('https://example.com/')).rejects.toThrow(/too many redirects/i);
  });

  it('allowPrivateNetworks opts out of address validation', async () => {
    vi.mocked(fetch).mockResolvedValue(mockResponse(200, { 'x-content-type-options': 'nosniff' }) as any);
    const headers = await fetchHeaders('http://localhost:3000/', { allowPrivateNetworks: true });
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(lookup).not.toHaveBeenCalled();
  });

  it('still rejects non-http(s) schemes even with allowPrivateNetworks', async () => {
    await expect(fetchHeaders('ftp://internal/', { allowPrivateNetworks: true })).rejects.toThrow(/scheme/i);
    expect(fetch).not.toHaveBeenCalled();
  });
});
