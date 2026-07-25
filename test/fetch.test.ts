import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';
import { fetchHeaders, fetchHeadersWithMeta } from '../src/fetch.js';

function fakeResponse(status: number, headers: Record<string, string>, setCookies: string[] = []) {
  return {
    status,
    headers: {
      has: (k: string) => k.toLowerCase() in headers,
      get: (k: string) => headers[k.toLowerCase()] ?? null,
      forEach: (cb: (value: string, key: string) => void) => {
        for (const [k, v] of Object.entries(headers)) cb(v, k);
        // Mirrors the real Fetch API/undici: Headers#forEach yields one 'set-cookie'
        // entry per cookie rather than combining them into a single value.
        for (const cookie of setCookies) cb(cookie, 'set-cookie');
      },
      getSetCookie: () => setCookies,
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

  it('rejects NAT64-synthesized addresses that embed a private/metadata IPv4 (RFC 6052)', async () => {
    // 64:ff9b::a9fe:a9fe embeds 169.254.169.254 (cloud metadata endpoint)
    vi.mocked(lookup).mockResolvedValue([{ address: '64:ff9b::a9fe:a9fe', family: 6 }] as never);
    await expect(fetchHeaders('http://nat64-metadata.example.com')).rejects.toThrow(/private\/internal/i);

    // Same address, mixed dotted-decimal notation for the embedded IPv4.
    vi.mocked(lookup).mockResolvedValue([{ address: '64:ff9b::169.254.169.254', family: 6 }] as never);
    await expect(fetchHeaders('http://nat64-metadata-dotted.example.com')).rejects.toThrow(/private\/internal/i);

    // 64:ff9b::a00:1 embeds 10.0.0.1 (RFC1918)
    vi.mocked(lookup).mockResolvedValue([{ address: '64:ff9b::a00:1', family: 6 }] as never);
    await expect(fetchHeaders('http://nat64-rfc1918.example.com')).rejects.toThrow(/private\/internal/i);
  });

  it('rejects 6to4-synthesized addresses that embed a private IPv4', async () => {
    // 2002:7f00:1:: embeds 127.0.0.1 (loopback) in the next 32 bits
    vi.mocked(lookup).mockResolvedValue([{ address: '2002:7f00:1::', family: 6 }] as never);
    await expect(fetchHeaders('http://6to4-loopback.example.com')).rejects.toThrow(/private\/internal/i);
  });

  it('allows a NAT64/6to4 address whose embedded IPv4 is public', async () => {
    // 64:ff9b::5db8:d822 embeds 93.184.216.34 (public)
    vi.mocked(lookup).mockResolvedValue([{ address: '64:ff9b::5db8:d822', family: 6 }] as never);
    vi.mocked(fetch).mockResolvedValue(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);
    const headers = await fetchHeaders('http://nat64-public.example.com');
    expect(headers['x-frame-options']).toBe('DENY');
  });

  it('rejects IPv4-mapped IPv6 addresses in non-dotted (all-hex) notation', async () => {
    // ::ffff:7f00:1 is the hex-group form of ::ffff:127.0.0.1 (loopback)
    vi.mocked(lookup).mockResolvedValue([{ address: '::ffff:7f00:1', family: 6 }] as never);
    await expect(fetchHeaders('http://ipv4-mapped-hex.example.com')).rejects.toThrow(/private\/internal/i);
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

  it('preserves multiple Set-Cookie headers instead of collapsing to the last one', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    vi.mocked(fetch).mockResolvedValue(
      fakeResponse(200, {}, ['a=1; Path=/', 'b=2; Path=/']) as never
    );

    const headers = await fetchHeaders('https://example.com');
    expect(headers['set-cookie']).toBe('a=1; Path=/\nb=2; Path=/');
  });

  it('allows private networks when allowPrivateNetworks is set', async () => {
    vi.mocked(fetch).mockResolvedValue(fakeResponse(200, { 'x-frame-options': 'DENY' }) as never);

    const headers = await fetchHeaders('http://localhost:3000', { allowPrivateNetworks: true });
    expect(headers['x-frame-options']).toBe('DENY');
    expect(lookup).not.toHaveBeenCalled();
  });
});
