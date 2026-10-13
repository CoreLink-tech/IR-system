import * as ipaddr from 'ipaddr.js';
import { Request } from 'express';

/** Longest X-Forwarded-For value and entry count that are read. Anything longer is treated as unreliable. */
export const MAX_FORWARDED_LENGTH = 2048;
export const MAX_FORWARDED_ENTRIES = 32;

export interface ClientIpConfig {
  /** Addresses, CIDR blocks, or the word "private". Empty means forwarding headers are never trusted. */
  trusted: string[];
  /** Optional header holding the client address, for example "CF-Connecting-IP". Used only behind a trusted proxy. */
  header?: string;
}

/** Splits a comma list such as the TRUSTED_PROXIES setting. */
export function parseTrustedProxies(raw?: string | null): string[] {
  return String(raw ?? '').split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

/** Problems with a trusted proxy list, as plain sentences. An empty array means the list is usable. */
export function trustedProxyProblems(entries: string[]): string[] {
  const out: string[] = [];
  for (const e of entries) {
    if (e.toLowerCase() === 'private') continue;
    if (!isValidCidrEntry(e)) out.push(`TRUSTED_PROXIES entry "${e}" is not an address, a CIDR block or the word private.`);
  }
  return out;
}

function isValidCidrEntry(entry: string): boolean {
  const parts = entry.split('/');
  if (parts.length > 2) return false;
  const base = normalizeIp(parts[0]);
  if (!base) return false;
  if (parts.length === 1) return true;
  if (!/^\d{1,3}$/.test(parts[1])) return false;
  return Number(parts[1]) <= (base.includes(':') ? 128 : 32);
}

/** True when the address is inside the CIDR block (or equals the single address). Same rules as the PHP library. */
export function inCidr(ip: string, entry: string): boolean {
  const parts = entry.trim().split('/');
  if (parts.length > 2) return false;
  const net = normalizeIp(parts[0]);
  const addr = normalizeIp(ip);
  if (!net || !addr) return false;
  const a = ipaddr.parse(addr);
  const n = ipaddr.parse(net);
  if (a.kind() !== n.kind()) return false;
  const max = a.kind() === 'ipv4' ? 32 : 128;
  let bits = max;
  if (parts.length === 2) {
    if (!/^\d{1,3}$/.test(parts[1]) || Number(parts[1]) > max) return false;
    bits = Number(parts[1]);
  }
  return (a as any).match(n, bits);
}

export function isTrustedProxy(ip: string, trusted: string[]): boolean {
  for (const entry of trusted) {
    if (entry.toLowerCase() === 'private') {
      if (isInternalAddress(ip)) return true;
      continue;
    }
    if (inCidr(ip, entry)) return true;
  }
  return false;
}

/** Accepts "1.2.3.4", "1.2.3.4:5678", "2001:db8::1" and "[2001:db8::1]:443". Returns undefined when malformed. */
function parseForwardedEntry(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  let v = value.trim();
  if (v.startsWith('[')) {
    const end = v.indexOf(']');
    return end === -1 ? undefined : normalizeIp(v.substring(1, end));
  }
  if (v.split(':').length - 1 === 1) v = v.substring(0, v.indexOf(':'));
  return normalizeIp(v);
}

/**
 * The one rule for "who is the visitor", shared by the PHP library (see the forwarding vectors in
 * integration/shared). The connection address is used unless it belongs to a trusted proxy.
 * Behind a trusted proxy X-Forwarded-For is read from the RIGHT, skipping trusted hops: the first
 * address that is not a trusted proxy is the visitor. The left side is whatever the visitor claimed.
 * A malformed entry, an empty entry, an over-long header or too many hops means the header cannot
 * be relied on, so the connection address is used.
 */
export function resolveClientIp(
  remoteAddress: string | undefined | null,
  forwardedFor: string | undefined | null,
  clientHeaderValue: string | undefined | null,
  config: ClientIpConfig,
): string | undefined {
  const remote = normalizeIp(remoteAddress);
  if (!remote || !isTrustedProxy(remote, config.trusted)) return remote;

  if (config.header) {
    const fromHeader = parseForwardedEntry(clientHeaderValue);
    if (fromHeader) return fromHeader;
  }

  if (typeof forwardedFor !== 'string' || forwardedFor.trim() === '') return remote;
  if (forwardedFor.length > MAX_FORWARDED_LENGTH) return remote;
  const parts = forwardedFor.split(',');
  if (parts.length > MAX_FORWARDED_ENTRIES) return remote;
  const chain = parts.map(parseForwardedEntry);
  for (let i = chain.length - 1; i >= 0; i--) {
    const entry = chain[i];
    if (!entry) return remote;
    if (!isTrustedProxy(entry, config.trusted)) return entry;
  }
  return remote;
}

let cachedKey = '\u0000';
let cachedConfig: ClientIpConfig = { trusted: [] };

/** The proxy settings from the environment. Re-read only when the settings change. */
export function clientIpConfig(): ClientIpConfig {
  const key = `${process.env.TRUSTED_PROXIES ?? ''}|${process.env.CLIENT_IP_HEADER ?? ''}`;
  if (key !== cachedKey) {
    cachedKey = key;
    const header = (process.env.CLIENT_IP_HEADER ?? '').trim();
    cachedConfig = { trusted: parseTrustedProxies(process.env.TRUSTED_PROXIES), header: header || undefined };
  }
  return cachedConfig;
}

/**
 * The client address for a request. This is the ONLY place an address is taken from a request:
 * the rate limit tracker, audit records, login records and event ingestion all call it.
 * Forwarding headers (X-Forwarded-For, the optional client header) are used only when the
 * connection comes from a proxy listed in TRUSTED_PROXIES. X-Real-IP is never read.
 */
export function extractIp(req: Request): string | undefined {
  const config = clientIpConfig();
  const header = config.header ? req.headers[config.header.toLowerCase()] : undefined;
  const xff = req.headers['x-forwarded-for'];
  return resolveClientIp(
    req.socket?.remoteAddress,
    Array.isArray(xff) ? xff.join(', ') : xff,
    Array.isArray(header) ? header[0] : header,
    config,
  );
}

export function normalizeIp(input?: string | null): string | undefined {
  if (!input) return undefined;
  let value = String(input).trim();
  // Zone identifiers ("fe80::1%eth0") name a local interface, not an internet address.
  if (value.includes('%')) return undefined;
  // An IPv6 address written with a dotted quad is accepted only in the IPv4-mapped
  // form ("::ffff:203.0.113.5", any letter case). The parser would read other forms
  // such as "::203.0.113.5" as IPv4-mapped too, although that address is something else.
  if (value.includes(':') && value.includes('.')) {
    if (!/^(?:::|(?:0{1,4}:){5})ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/i.test(value)) return undefined;
    value = value.substring(value.lastIndexOf(':') + 1);
  }
  // Be strict. The parser would otherwise accept shorthand forms such as "1.2.3"
  // (read as 1.2.0.3), "127.1", hexadecimal "0x7f.0.0.1" and octal "010.0.0.1".
  // Those would be stored or blocked as a different address than the one meant.
  if (!value.includes(':') && !ipaddr.IPv4.isValidFourPartDecimal(value)) return undefined;
  if (value.includes(':') && !ipaddr.IPv6.isValid(value)) return undefined;
  try {
    const parsed = ipaddr.parse(value);
    if (parsed.kind() === 'ipv6') {
      const v6 = parsed as ipaddr.IPv6;
      if (v6.isIPv4MappedAddress()) return v6.toIPv4Address().toString();
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}

export function isPrivateIp(ip: string): boolean {
  try {
    const parsed = ipaddr.parse(ip);
    return parsed.range() !== 'unicast';
  } catch {
    return false;
  }
}

/**
 * Addresses that must never be blocked automatically or by mistake: loopback,
 * private networks, link-local and similar. Blocking one of these could lock the
 * website out of its own security system, or take the whole site offline when
 * traffic reaches it through an internal proxy.
 */
const INTERNAL_RANGES = new Set([
  'loopback', 'private', 'linkLocal', 'uniqueLocal', 'unspecified',
  'carrierGradeNat', 'broadcast', 'multicast',
]);

export function isInternalAddress(ip: string): boolean {
  try {
    return INTERNAL_RANGES.has(ipaddr.parse(ip).range());
  } catch {
    return false;
  }
}
