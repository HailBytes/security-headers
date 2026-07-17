import { describe, it, expect, vi, afterEach } from 'vitest';
import { fetchHeaders, fetchHeadersWithMeta } from '../src/fetch.js';

function mockResponse(opts: { url: string; headers?: Record<string, string> }) {
  const headers = new Headers(opts.headers ?? {});
  return {
    url: opts.url,
    headers,
    body: { cancel: vi.fn().mockResolvedValue(undefined) },
  } as unknown as Response;
}

describe('fetchHeadersWithMeta', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns the post-redirect URL when it differs from the request URL', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse({ url: 'https://www.example.com/', headers: { 'x-content-type-options': 'nosniff' } })
    ));

    const { headers, finalUrl } = await fetchHeadersWithMeta('https://example.com/');
    expect(finalUrl).toBe('https://www.example.com/');
    expect(headers['x-content-type-options']).toBe('nosniff');
  });

  it('falls back to the requested URL when res.url is empty', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({ url: '' })));

    const { finalUrl } = await fetchHeadersWithMeta('https://example.com/');
    expect(finalUrl).toBe('https://example.com/');
  });

  it('fetchHeaders still returns only the header map', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse({ url: 'https://example.com/', headers: { 'x-frame-options': 'DENY' } })
    ));

    const headers = await fetchHeaders('https://example.com/');
    expect(headers).toEqual({ 'x-frame-options': 'DENY' });
  });
});
