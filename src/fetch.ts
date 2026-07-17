export interface FetchOptions {
  timeoutMs?: number;
}

export interface FetchHeadersResult {
  headers: Record<string, string>;
  /** The URL the response actually came from, after following redirects. */
  finalUrl: string;
}

export async function fetchHeadersWithMeta(url: string, options?: FetchOptions): Promise<FetchHeadersResult> {
  const timeoutMs = options?.timeoutMs ?? 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Use GET rather than HEAD: many sites (and CDNs/edge workers) emit security
    // headers — notably Content-Security-Policy — only on full responses, so a
    // HEAD request systematically under-reports them. We only need the headers,
    // so the response body is discarded without being read.
    const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    try { await res.body?.cancel(); } catch { /* body may be absent or already closed */ }
    // res.url reflects the final URL after following redirects (fetch spec).
    return { headers, finalUrl: res.url || url };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchHeaders(url: string, options?: FetchOptions): Promise<Record<string, string>> {
  return (await fetchHeadersWithMeta(url, options)).headers;
}
