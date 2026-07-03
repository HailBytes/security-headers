import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface FetchOptions {
  timeoutMs?: number;
  /**
   * By default, requests to loopback, link-local, and private-use addresses
   * (RFC1918/RFC4193, cloud metadata endpoints, etc.) are rejected to prevent
   * SSRF when this library scans user- or customer-supplied URLs server-side.
   * Set true to scan local/staging targets (e.g. http://localhost:3000).
   */
  allowPrivateNetworks?: boolean;
}

const MAX_REDIRECTS = 5;

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

const IPV4_PRIVATE_RANGES: [string, string][] = [
  ['0.0.0.0', '0.255.255.255'],
  ['10.0.0.0', '10.255.255.255'],
  ['100.64.0.0', '100.127.255.255'],
  ['127.0.0.0', '127.255.255.255'],
  ['169.254.0.0', '169.254.255.255'],
  ['172.16.0.0', '172.31.255.255'],
  ['192.0.0.0', '192.0.0.255'],
  ['192.168.0.0', '192.168.255.255'],
  ['198.18.0.0', '198.19.255.255'],
  ['224.0.0.0', '255.255.255.255'],
];

function isPrivateIPv4(ip: string): boolean {
  const int = ipv4ToInt(ip);
  return IPV4_PRIVATE_RANGES.some(([start, end]) => int >= ipv4ToInt(start) && int <= ipv4ToInt(end));
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === '::1' || normalized === '::') return true;
  if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true; // fe80::/10 link-local
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true; // fc00::/7 unique local
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

function isPrivateAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true; // unresolvable family — treat as unsafe rather than silently allow
}

async function assertPublicUrl(url: URL): Promise<void> {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Refusing to fetch unsupported URL scheme "${url.protocol}" (only http/https are allowed)`);
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error(`Refusing to fetch private/internal address: ${hostname}`);
    }
    return;
  }
  const { address } = await lookup(hostname);
  if (isPrivateAddress(address)) {
    throw new Error(`Refusing to fetch host "${hostname}" — it resolves to private/internal address ${address}`);
  }
}

export async function fetchHeaders(url: string, options?: FetchOptions): Promise<Record<string, string>> {
  const timeoutMs = options?.timeoutMs ?? 10000;
  const allowPrivateNetworks = options?.allowPrivateNetworks ?? false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let currentUrl = new URL(url);
    for (let redirectCount = 0; ; redirectCount++) {
      if (allowPrivateNetworks) {
        if (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:') {
          throw new Error(`Refusing to fetch unsupported URL scheme "${currentUrl.protocol}" (only http/https are allowed)`);
        }
      } else {
        await assertPublicUrl(currentUrl);
      }

      // redirect: 'manual' so every hop — not just the initial URL — is
      // validated above before being followed, closing the SSRF-via-redirect gap.
      const res = await fetch(currentUrl, { method: 'GET', redirect: 'manual', signal: controller.signal });

      if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
        try { await res.body?.cancel(); } catch { /* body may be absent or already closed */ }
        if (redirectCount >= MAX_REDIRECTS) {
          throw new Error(`Too many redirects (> ${MAX_REDIRECTS})`);
        }
        currentUrl = new URL(res.headers.get('location')!, currentUrl);
        continue;
      }

      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
      try { await res.body?.cancel(); } catch { /* body may be absent or already closed */ }
      return headers;
    }
  } finally {
    clearTimeout(timer);
  }
}
