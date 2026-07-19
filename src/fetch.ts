import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface FetchOptions {
  timeoutMs?: number;
  /** Allow fetching hosts that resolve to loopback/private/link-local addresses. Default: false. */
  allowPrivateNetworks?: boolean;
}

const MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function ipv4ToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isPrivateIPv4(ip: string): boolean {
  const long = ipv4ToLong(ip);
  const inRange = (base: string, bits: number) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (long & mask) === (ipv4ToLong(base) & mask);
  };
  return (
    inRange('0.0.0.0', 8) ||       // "this" network
    inRange('10.0.0.0', 8) ||      // private
    inRange('100.64.0.0', 10) ||   // carrier-grade NAT
    inRange('127.0.0.0', 8) ||     // loopback
    inRange('169.254.0.0', 16) ||  // link-local (incl. cloud metadata endpoint)
    inRange('172.16.0.0', 12) ||   // private
    inRange('192.168.0.0', 16) ||  // private
    inRange('198.18.0.0', 15) ||   // benchmarking
    inRange('224.0.0.0', 4) ||     // multicast
    inRange('240.0.0.0', 4)        // reserved
  );
}

function isPrivateIPv6(ip: string): boolean {
  const lc = ip.toLowerCase();
  if (lc === '::' || lc === '::1') return true;
  if (lc.startsWith('fe80:') || lc.startsWith('fc') || lc.startsWith('fd')) return true; // link-local + unique-local (fc00::/7)
  const mapped = lc.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

function isPrivateOrReservedIP(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true; // unclassifiable address — fail closed
}

async function assertPublicUrl(url: URL, allowPrivateNetworks: boolean | undefined): Promise<void> {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Refusing to fetch unsupported scheme: ${url.protocol}`);
  }
  if (allowPrivateNetworks) return;
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  let addresses: { address: string }[];
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    throw new Error(`Could not resolve host: ${hostname}`);
  }
  for (const { address } of addresses) {
    if (isPrivateOrReservedIP(address)) {
      throw new Error(`Refusing to fetch private/internal address: ${hostname} resolved to ${address}`);
    }
  }
}

export async function fetchHeaders(url: string, options?: FetchOptions): Promise<Record<string, string>> {
  const timeoutMs = options?.timeoutMs ?? 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let current = new URL(url);
    for (let hop = 0; ; hop++) {
      await assertPublicUrl(current, options?.allowPrivateNetworks);
      // Use GET rather than HEAD: many sites (and CDNs/edge workers) emit security
      // headers — notably Content-Security-Policy — only on full responses, so a
      // HEAD request systematically under-reports them. We only need the headers,
      // so the response body is discarded without being read.
      // redirect: 'manual' so each hop can be validated against the private-network
      // check above before it's followed, instead of trusting only the first URL.
      const res = await fetch(current, { method: 'GET', redirect: 'manual', signal: controller.signal });
      if (REDIRECT_STATUSES.has(res.status) && res.headers.has('location')) {
        try { await res.body?.cancel(); } catch { /* body may be absent or already closed */ }
        if (hop >= MAX_REDIRECTS) throw new Error(`Too many redirects (> ${MAX_REDIRECTS})`);
        current = new URL(res.headers.get('location')!, current);
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
