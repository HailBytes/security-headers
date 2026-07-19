import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';
import { fetchHeaders, fetchHeadersWithMeta } from '../src/fetch.js';

function fakeResponse(status: number, headers: Record<string, string>) {
  return {
    status,
    headers: {
      has: (k: string) => k.toLowerCase() in headers,
      get: (k: string) => headers[k.toLowerCase()] ?? null,
      forEach: (cb: (value: string, key: string) => void) => {
        for (const [k, v] of Object.entries(headers)) cb(v, k);
      },
    },
    body: { cancel: vi.fn().mockResolvedValue(undefined) },
  };
}

describe('fetchHeaders', () => {
  beforeEach(() => {
    vi.mocked(lookup).mockReset();
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches and lower-cases headers for a public host', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch).mockResolvedValue(fakeResponse(200, { 'Content-Security-Policy': "default-src 'self'" }) as never);

    const headers = await fetchHeaders('https://example.com');
    expect(headers['content-security-policy']).toBe("default-src 'self'");
  });

  it('rejects non-http(s) schemes', async () => {
    await expect(fetchHeaders('file:///etc/passwd')).rejects.toThrow(/unsupported scheme/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects hosts that resolve to loopback addresses', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '127.0.0.1', family: 4 }] as never);
    await expect(fetchHeaders('http://localhost')).rejects.toThrow(/private\/internal/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects the cloud metadata endpoint (link-local range)', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '169.254.169.254', family: 4 }] as never);
    await expect(fetchHeaders('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(/private\/internal/i);
  });

  it('rejects RFC1918 private addresses', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '10.0.0.5', family: 4 }] as never);
    await expect(fetchHeaders('http://internal.example.com')).rejects.toThrow(/private\/internal/i);
  });

  it('rejects IPv6 loopback and unique-local addresses', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '::1', family: 6 }] as never);
    await expect(fetchHeaders('http://ipv6-loopback.example.com')).rejects.toThrow(/private\/internal/i);

    vi.mocked(lookup).mockResolvedValue([{ address: 'fd12:3456::1', family: 6 }] as never);
    await expect(fetchHeaders('http://ipv6-ula.example.com')).rejects.toThrow(/private\/internal/i);
  });

  it('rejects a redirect that targets a private address', async () => {
    vi.mocked(lookup).mockImplementation(async (hostname: string) => {
      if (hostname === 'public.example.com') return [{ address: '93.184.216.34', family: 4 }] as never;
      return [{ address: '169.254.169.254', family: 4 }] as never;
    });
    vi.mocked(fetch).mockResolvedValue(
      fakeResponse(302, { location: 'http://internal.example.com/latest/meta-data/' }) as never
    );

    await expect(fetchHeaders('https://public.example.com')).rejects.toThrow(/private\/internal/i);
  });

  it('follows a bounded number of redirects to a public host', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch)
      .mockResolvedValueOnce(fakeResponse(301, { location: 'https://example.com/final' }) as never)
      .mockResolvedValueOnce(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);

    const headers = await fetchHeaders('https://example.com/start');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('fetchHeadersWithMeta reports the post-redirect URL', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch)
      .mockResolvedValueOnce(fakeResponse(301, { location: 'https://example.com/final' }) as never)
      .mockResolvedValueOnce(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);

    const result = await fetchHeadersWithMeta('https://example.com/start');
    expect(result.headers['x-frame-options']).toBe('DENY');
    expect(result.finalUrl).toBe('https://example.com/final');
  });

  it('fetchHeadersWithMeta reports the original URL as finalUrl when there is no redirect', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch).mockResolvedValueOnce(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);

    const result = await fetchHeadersWithMeta('https://example.com/start');
    expect(result.finalUrl).toBe('https://example.com/start');
  });

  it('throws after exceeding the redirect limit', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch).mockImplementation(async () => fakeResponse(302, { location: 'https://example.com/next' }) as never);

    await expect(fetchHeaders('https://example.com/start')).rejects.toThrow(/too many redirects/i);
  });

  it('allows private networks when allowPrivateNetworks is set', async () => {
    vi.mocked(fetch).mockResolvedValue(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);

    const headers = await fetchHeaders('http://localhost:3000', { allowPrivateNetworks: true });
    expect(headers['x-frame-options']).toBe('DENY');
    expect(lookup).not.toHaveBeenCalled();
  });
});
