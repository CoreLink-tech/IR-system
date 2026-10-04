import { normalizeIp, isPrivateIp } from '../src/common/utils/ip.util';

describe('IP utilities', () => {
  describe('normalizeIp', () => {
    it('normalizes IPv4', () => {
      expect(normalizeIp(' 192.168.1.1 ')).toBe('192.168.1.1');
    });
    it('rejects leading zeros, which other software reads as octal and so as a different address', () => {
      expect(normalizeIp('192.168.001.001')).toBeUndefined();
      expect(normalizeIp('010.0.0.1')).toBeUndefined();
    });
    it('strips IPv4-mapped IPv6 prefix', () => {
      expect(normalizeIp('::ffff:203.0.113.5')).toBe('203.0.113.5');
    });
    it('returns undefined for invalid input', () => {
      expect(normalizeIp('not-an-ip')).toBeUndefined();
      expect(normalizeIp('')).toBeUndefined();
      expect(normalizeIp(null)).toBeUndefined();
    });
    it('normalizes IPv6', () => {
      const out = normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001');
      expect(out).toBe('2001:db8::1');
    });
  });

  describe('isPrivateIp', () => {
    it('flags RFC1918 space', () => {
      expect(isPrivateIp('192.168.1.1')).toBe(true);
      expect(isPrivateIp('10.0.0.1')).toBe(true);
      expect(isPrivateIp('172.16.5.5')).toBe(true);
    });
    it('treats public IPs as not private', () => {
      expect(isPrivateIp('1.1.1.1')).toBe(false);
      expect(isPrivateIp('8.8.8.8')).toBe(false);
    });
  });
});
