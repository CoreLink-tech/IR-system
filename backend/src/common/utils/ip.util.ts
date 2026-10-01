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
