import * as ipaddr from 'ipaddr.js';
import { Request } from 'express';

export function extractIp(req: Request): string | undefined {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    const first = xff.split(',')[0].trim();
    const normalized = normalizeIp(first);
    if (normalized) return normalized;
  }
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.length > 0) {
    const normalized = normalizeIp(real);
    if (normalized) return normalized;
  }
  const raw = req.socket?.remoteAddress || (req as any).ip;
  return normalizeIp(raw);
}

export function normalizeIp(input?: string | null): string | undefined {
  if (!input) return undefined;
  let value = String(input).trim();
  if (value.startsWith('::ffff:')) value = value.substring(7);
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
