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

/**
 * Expands any syntactically valid IPv6 literal (as returned by dns.lookup(),
 * which isIP() already confirmed to be family 6) into its 8 16-bit groups,
 * handling "::" compression and a trailing embedded-IPv4 dotted-decimal
 * suffix (e.g. "::ffff:127.0.0.1", "64:ff9b::169.254.169.254"). Returns null
 * if the address can't be confidently parsed.
 */
function expandIPv6(ip: string): number[] | null {
  let base = ip.split('%')[0]; // strip zone id, e.g. "fe80::1%eth0"

  let v4Groups: number[] = [];
  const v4 = base.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4) {
    const octets = v4[1].split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    v4Groups = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    base = base.slice(0, -v4[1].length);
    if (base.endsWith(':') && !base.endsWith('::')) base = base.slice(0, -1);
  }

  if ((base.match(/::/g) || []).length > 1) return null; // "::" may appear at most once

  const parseHex = (s: string): number | null => (/^[0-9a-f]{1,4}$/.test(s) ? parseInt(s, 16) : null);
  const toGroups = (s: string): number[] | null => {
    if (s === '') return [];
    const nums = s.split(':').map(parseHex);
    return nums.some(n => n === null) ? null : (nums as number[]);
  };

  if (base.includes('::')) {
    const [headStr, tailStr] = base.split('::');
    const head = toGroups(headStr);
    const tail = toGroups(tailStr);
    if (head === null || tail === null) return null;
    const missing = 8 - (head.length + tail.length + v4Groups.length);
    if (missing < 0) return null;
    return [...head, ...Array(missing).fill(0), ...tail, ...v4Groups];
  }
  const head = toGroups(base);
  if (head === null) return null;
  const groups = [...head, ...v4Groups];
  return groups.length === 8 ? groups : null;
}

function groupsToIPv4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function isPrivateIPv6(ip: string): boolean {
  const lc = ip.toLowerCase();
  if (lc === '::' || lc === '::1') return true;
  if (lc.startsWith('fe80:') || lc.startsWith('fc') || lc.startsWith('fd')) return true; // link-local + unique-local (fc00::/7)

  const g = expandIPv6(lc);
  if (!g) return true; // couldn't confidently parse an address isIP() already validated — fail closed

  // IPv4-mapped ::ffff:0:0/96 — embeds an IPv4 address in the low 32 bits.
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return isPrivateIPv4(groupsToIPv4(g[6], g[7]));
  }
  // NAT64 Well-Known Prefix 64:ff9b::/96 (RFC 6052) — on a NAT64/464XLAT network
  // (the default IPv6-only mode on several cellular carriers and some cloud
  // node pools) this is transparently translated and routed to the embedded
  // IPv4 address, so it must be checked the same as an IPv4-mapped address.
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPrivateIPv4(groupsToIPv4(g[6], g[7]));
  }
  // 6to4 2002::/16 embeds an IPv4 address in the next 32 bits (2002:AABB:CCDD::/48).
  if (g[0] === 0x2002) {
    return isPrivateIPv4(groupsToIPv4(g[1], g[2]));
  }
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

export interface FetchHeadersResult {
  headers: Record<string, string>;
  /** The URL the headers actually came from, after following any redirects. */
  finalUrl: string;
}

export async function fetchHeadersWithMeta(url: string, options?: FetchOptions): Promise<FetchHeadersResult> {
  // Guards direct library callers (not just the CLI, which validates its own
  // --timeout flag): a NaN/Infinity/non-positive timeoutMs would otherwise
  // reach setTimeout and fire near-instantly, aborting the request immediately.
  const rawTimeout = options?.timeoutMs;
  const timeoutMs = Number.isFinite(rawTimeout) && (rawTimeout as number) > 0 ? (rawTimeout as number) : 10000;
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
      res.headers.forEach((value, key) => {
        // Set-Cookie is excluded here and handled below: a response setting multiple
        // cookies emits one Set-Cookie entry per cookie, and naively assigning each
        // into this flat Record would silently drop all but the last one.
        if (key.toLowerCase() === 'set-cookie') return;
        headers[key.toLowerCase()] = value;
      });
      const setCookies = res.headers.getSetCookie?.() ?? [];
      if (setCookies.length > 0) headers['set-cookie'] = setCookies.join('\n');
      try { await res.body?.cancel(); } catch { /* body may be absent or already closed */ }
      return { headers, finalUrl: current.toString() };
    }
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchHeaders(url: string, options?: FetchOptions): Promise<Record<string, string>> {
  return (await fetchHeadersWithMeta(url, options)).headers;
}
