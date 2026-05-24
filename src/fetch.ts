export interface FetchOptions {
  timeoutMs?: number;
}

export async function fetchHeaders(url: string, options?: FetchOptions): Promise<Record<string, string>> {
  const timeoutMs = options?.timeoutMs ?? 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    return headers;
  } finally {
    clearTimeout(timer);
  }
}
