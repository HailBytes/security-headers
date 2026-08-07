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
 * Parses a (non-mixed-notation) IPv6 address into its 16 bytes, honoring a
 * single "::" zero-run compression. Returns null if malformed. Used instead of
 * a regex so RFC 5952 canonicalization — which can compress zero hextets from
 * *within* an embedded address, not just the routing prefix — doesn't produce
 * a form that a fixed-shape pattern would fail to match.
 */
function ipv6ToBytes(ip: string): number[] | null {
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (s: string): number[] | null => {
    if (s === '') return [];
    const out: number[] = [];
    for (const g of s.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      const n = parseInt(g, 16);
      out.push((n >> 8) & 0xff, n & 0xff);
    }
    return out;
  };
  if (halves.length === 1) {
    const bytes = parseGroups(halves[0]);
    return bytes && bytes.length === 16 ? bytes : null;
  }
  const head = parseGroups(halves[0]);
  const tail = parseGroups(halves[1]);
  if (!head || !tail) return null;
  const missing = 16 - head.length - tail.length;
  if (missing < 0) return null;
  return [...head, ...new Array(missing).fill(0), ...tail];
}

function embeddedIPv4FromPrefix(bytes: number[], prefixBytes: number[]): string | null {
  if (!prefixBytes.every((b, i) => bytes[i] === b)) return null;
  return bytes.slice(prefixBytes.length, prefixBytes.length + 4).join('.');
}

function isPrivateIPv6(ip: string): boolean {
  const lc = ip.toLowerCase();
  if (lc === '::' || lc === '::1') return true;
  if (lc.startsWith('fe80:') || lc.startsWith('fc') || lc.startsWith('fd')) return true; // link-local + unique-local (fc00::/7)
  const mapped = lc.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);

  const bytes = ipv6ToBytes(lc);
  if (bytes) {
    // NAT64 Well-Known Prefix 64:ff9b::/96 (RFC 6052) and the 6to4 prefix
    // 2002::/16 both embed a literal IPv4 address that NAT64/464XLAT or 6to4
    // relay infrastructure transparently routes to — a private/metadata IPv4
    // reachable through either is reachable through its embedded form too.
    const nat64 = embeddedIPv4FromPrefix(bytes, [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]);
    if (nat64) return isPrivateIPv4(nat64);
    const sixToFour = embeddedIPv4FromPrefix(bytes, [0x20, 0x02]);
    if (sixToFour) return isPrivateIPv4(sixToFour);
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
