import { vi, describe, it, expect, afterEach } from 'vitest';
import { fetchHeaders } from '../src/fetch.js';

describe('fetchHeaders', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns response headers as lowercase key-value pairs', async () => {
    const mockHeaders = new Headers({
      'Content-Type': 'text/html; charset=utf-8',
      'X-Custom-Header': 'SomeValue',
      'Strict-Transport-Security': 'max-age=31536000',
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      headers: mockHeaders,
      body: { cancel: vi.fn() },
    }));

    const result = await fetchHeaders('https://example.com');
    expect(result).toEqual({
      'content-type': 'text/html; charset=utf-8',
      'x-custom-header': 'SomeValue',
      'strict-transport-security': 'max-age=31536000',
    });
  });

  it('uses GET — not HEAD — to avoid sites that omit CSP on HEAD responses', async () => {
    const fetchFn = vi.fn().mockResolvedValueOnce({
      headers: new Headers(),
      body: null,
    });
    vi.stubGlobal('fetch', fetchFn);

    await fetchHeaders('https://example.com');
    expect(fetchFn).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('passes an AbortSignal to fetch for timeout control', async () => {
    const fetchFn = vi.fn().mockResolvedValueOnce({
      headers: new Headers(),
      body: null,
    });
    vi.stubGlobal('fetch', fetchFn);

    await fetchHeaders('https://example.com');
    expect(fetchFn).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it('cancels the response body after collecting headers', async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      headers: new Headers({ 'x-test': 'value' }),
      body: { cancel },
    }));

    await fetchHeaders('https://example.com');
    expect(cancel).toHaveBeenCalled();
  });

  it('handles a null body without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      headers: new Headers(),
      body: null,
    }));

    await expect(fetchHeaders('https://example.com')).resolves.toEqual({});
  });

  it('aborts the request after timeoutMs elapses', async () => {
    const fetchFn = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      const signal = opts.signal as AbortSignal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')));
      });
    });
    vi.stubGlobal('fetch', fetchFn);

    // 1 ms timeout — fires almost immediately; the fetch mock never resolves
    await expect(fetchHeaders('https://slow.example.com', { timeoutMs: 1 })).rejects.toThrow('aborted');
  });

  it('clears the abort timer after a successful fetch', async () => {
    // If the timer were not cleared, it would fire after the test ends and
    // could abort a subsequent request or log a warning.
    const cancel = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      headers: new Headers({ 'x-ok': '1' }),
      body: { cancel },
    }));

    const result = await fetchHeaders('https://example.com', { timeoutMs: 50 });
    // Waiting past the original timeout should not throw or abort anything
    await new Promise(r => setTimeout(r, 60));
    expect(result).toHaveProperty('x-ok', '1');
  });
});
