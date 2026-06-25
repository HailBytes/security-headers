import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchHeaders } from '../src/fetch.js';

describe('fetchHeaders', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  function mockFetch(headers: Record<string, string> = {}, body: ReadableStream | null = null) {
    vi.mocked(fetch).mockResolvedValue({
      headers: new Headers(headers),
      body,
    } as unknown as Response);
  }

  it('returns response headers as lowercase key-value pairs', async () => {
    mockFetch({
      'Content-Type': 'text/html',
      'X-Frame-Options': 'DENY',
      'Strict-Transport-Security': 'max-age=31536000',
    });

    const result = await fetchHeaders('https://example.com');

    expect(result).toEqual({
      'content-type': 'text/html',
      'x-frame-options': 'DENY',
      'strict-transport-security': 'max-age=31536000',
    });
  });

  it('uses GET method with redirect:follow', async () => {
    mockFetch();

    await fetchHeaders('https://example.com');

    expect(fetch).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({ method: 'GET', redirect: 'follow' }),
    );
  });

  it('passes an AbortSignal to fetch', async () => {
    mockFetch();

    await fetchHeaders('https://example.com');

    expect(fetch).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });

  it('cancels the response body to free resources', async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    vi.mocked(fetch).mockResolvedValue({
      headers: new Headers(),
      body: { cancel } as unknown as ReadableStream,
    } as unknown as Response);

    await fetchHeaders('https://example.com');

    expect(cancel).toHaveBeenCalledOnce();
  });

  it('handles null body without throwing', async () => {
    vi.mocked(fetch).mockResolvedValue({
      headers: new Headers(),
      body: null,
    } as unknown as Response);

    await expect(fetchHeaders('https://example.com')).resolves.toEqual({});
  });

  it('returns empty object when no headers are present', async () => {
    mockFetch();
    const result = await fetchHeaders('https://example.com');
    expect(result).toEqual({});
  });

  it('propagates network errors', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(fetchHeaders('https://example.com')).rejects.toThrow('Failed to fetch');
  });

  it('aborts and rejects after the configured timeout', async () => {
    vi.useFakeTimers();

    let capturedSignal: AbortSignal | undefined;
    vi.mocked(fetch).mockImplementation((_url, init) => {
      capturedSignal = init?.signal as AbortSignal;
      return new Promise((_resolve, reject) => {
        capturedSignal?.addEventListener('abort', () =>
          reject(new DOMException('The operation was aborted.', 'AbortError')),
        );
      });
    });

    const promise = fetchHeaders('https://example.com', { timeoutMs: 1000 });
    // Attach rejection handler before advancing timers to avoid unhandled-rejection warnings.
    promise.catch(() => {});

    await vi.advanceTimersByTimeAsync(1001);

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
    expect(capturedSignal?.aborted).toBe(true);

    vi.useRealTimers();
  });

  it('does not abort before the timeout elapses', async () => {
    vi.useFakeTimers();

    let capturedSignal: AbortSignal | undefined;
    vi.mocked(fetch).mockImplementation((_url, init) => {
      capturedSignal = init?.signal as AbortSignal;
      return new Promise(() => {});
    });

    fetchHeaders('https://example.com', { timeoutMs: 5000 }).catch(() => {});
    await vi.advanceTimersByTimeAsync(4999);

    expect(capturedSignal?.aborted).toBe(false);

    vi.useRealTimers();
  });

  it('uses 10 seconds as the default timeout', async () => {
    vi.useFakeTimers();

    let capturedSignal: AbortSignal | undefined;
    vi.mocked(fetch).mockImplementation((_url, init) => {
      capturedSignal = init?.signal as AbortSignal;
      return new Promise((_resolve, reject) => {
        capturedSignal?.addEventListener('abort', () =>
          reject(new DOMException('Aborted', 'AbortError')),
        );
      });
    });

    const promise = fetchHeaders('https://example.com');
    // Attach rejection handler before advancing timers to avoid unhandled-rejection warnings.
    promise.catch(() => {});

    await vi.advanceTimersByTimeAsync(9999);
    expect(capturedSignal?.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(capturedSignal?.aborted).toBe(true);

    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });

    vi.useRealTimers();
  });

  it('clears the timer after a successful fetch', async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');
    mockFetch({ 'x-test': 'value' });

    await fetchHeaders('https://example.com');

    expect(clearTimeoutSpy).toHaveBeenCalledOnce();
  });

  it('clears the timer even when fetch throws', async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');
    vi.mocked(fetch).mockRejectedValue(new Error('oops'));

    await fetchHeaders('https://example.com').catch(() => {});

    expect(clearTimeoutSpy).toHaveBeenCalledOnce();
  });
});
