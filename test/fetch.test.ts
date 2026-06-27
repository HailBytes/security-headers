import { describe, it, expect, vi, afterEach } from 'vitest';
import { fetchHeaders } from '../src/fetch.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/** A fetch stub whose returned promise rejects when the AbortSignal fires. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function abortableFetch(onSignal?: (s: AbortSignal) => void): any {
  return vi.fn((_url: unknown, opts: { signal: AbortSignal }) => {
    const { signal } = opts;
    onSignal?.(signal);
    return new Promise<never>((_, reject) => {
      signal.addEventListener('abort', () =>
        reject(new DOMException('The operation was aborted.', 'AbortError')),
      );
    });
  });
}

/** A fetch stub that resolves immediately with the given headers and body. */
function resolvedFetch(
  headerEntries: Record<string, string> = {},
  body: { cancel: () => Promise<void> } | null = null,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): any {
  const headers = new Headers(headerEntries);
  return vi.fn().mockResolvedValue({ headers, body });
}

describe('fetchHeaders', () => {
  describe('request shape', () => {
    it('uses GET and follows redirects', async () => {
      const fetchMock = resolvedFetch();
      vi.stubGlobal('fetch', fetchMock);
      await fetchHeaders('https://example.com');
      expect(fetchMock).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({ method: 'GET', redirect: 'follow' }),
      );
    });

    it('attaches an AbortSignal to the request', async () => {
      const fetchMock = resolvedFetch();
      vi.stubGlobal('fetch', fetchMock);
      await fetchHeaders('https://example.com');
      const [, opts] = fetchMock.mock.calls[0] as [unknown, RequestInit];
      expect(opts.signal).toBeInstanceOf(AbortSignal);
    });
  });

  describe('header normalization', () => {
    it('lowercases all header keys', async () => {
      vi.stubGlobal(
        'fetch',
        resolvedFetch({
          'Content-Type': 'text/html',
          'X-Frame-Options': 'DENY',
          'Strict-Transport-Security': 'max-age=31536000',
        }),
      );
      const headers = await fetchHeaders('https://example.com');
      expect(headers['content-type']).toBe('text/html');
      expect(headers['x-frame-options']).toBe('DENY');
      expect(headers['strict-transport-security']).toBe('max-age=31536000');
    });

    it('returns an empty object when the response has no headers', async () => {
      vi.stubGlobal('fetch', resolvedFetch());
      expect(await fetchHeaders('https://example.com')).toEqual({});
    });
  });

  describe('body cleanup', () => {
    it('cancels the response body to discard it without reading', async () => {
      const cancel = vi.fn().mockResolvedValue(undefined);
      vi.stubGlobal('fetch', resolvedFetch({ 'x-foo': 'bar' }, { cancel }));
      await fetchHeaders('https://example.com');
      expect(cancel).toHaveBeenCalledOnce();
    });

    it('handles a null body without throwing', async () => {
      vi.stubGlobal('fetch', resolvedFetch({}, null));
      await expect(fetchHeaders('https://example.com')).resolves.toEqual({});
    });

    it('swallows body.cancel() errors and still returns headers', async () => {
      const cancel = vi.fn().mockRejectedValue(new Error('body already closed'));
      vi.stubGlobal('fetch', resolvedFetch({ 'x-test': 'value' }, { cancel }));
      const headers = await fetchHeaders('https://example.com');
      expect(headers['x-test']).toBe('value');
    });
  });

  describe('timeout', () => {
    it('schedules a timeout with the provided timeoutMs value', async () => {
      const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
      vi.stubGlobal('fetch', resolvedFetch());
      await fetchHeaders('https://example.com', { timeoutMs: 3000 });
      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 3000);
    });

    it('defaults to a 10-second timeout', async () => {
      const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout');
      vi.stubGlobal('fetch', resolvedFetch());
      await fetchHeaders('https://example.com');
      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 10000);
    });

    it('aborts the fetch when the timeout fires', async () => {
      vi.useFakeTimers();
      vi.stubGlobal('fetch', abortableFetch());
      const promise = fetchHeaders('https://example.com', { timeoutMs: 3000 });
      vi.advanceTimersByTime(3001);
      await expect(promise).rejects.toThrow();
    });

    it('does not abort the fetch before the timeout elapses', async () => {
      vi.useFakeTimers();
      let signal!: AbortSignal;
      vi.stubGlobal('fetch', abortableFetch(s => { signal = s; }));
      const promise = fetchHeaders('https://example.com', { timeoutMs: 3000 });
      vi.advanceTimersByTime(2999);
      expect(signal.aborted).toBe(false);
      // advance past the timeout so the promise settles cleanly
      vi.advanceTimersByTime(1);
      await expect(promise).rejects.toThrow();
    });

    it('clears the timer after a successful fetch', async () => {
      vi.useFakeTimers();
      const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
      vi.stubGlobal('fetch', resolvedFetch());
      await fetchHeaders('https://example.com');
      expect(clearSpy).toHaveBeenCalled();
    });

    it('clears the timer even when fetch rejects', async () => {
      vi.useFakeTimers();
      const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network error')));
      await expect(fetchHeaders('https://example.com')).rejects.toThrow('network error');
      expect(clearSpy).toHaveBeenCalled();
    });
  });

  describe('error propagation', () => {
    it('propagates network errors from fetch', async () => {
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
      await expect(fetchHeaders('https://example.com')).rejects.toThrow('Failed to fetch');
    });
  });
});
