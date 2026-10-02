import { IpIntelligenceService } from '../src/ips/ip-intelligence.service';
import { IpIntelProvider, PartialIntel } from '../src/ips/providers/provider.types';
import { AbuseIpDbProvider } from '../src/ips/providers/abuseipdb.provider';
import { IpApiProvider } from '../src/ips/providers/ip-api.provider';
import { IpInfoProvider } from '../src/ips/providers/ipinfo.provider';
import { TorExitProvider } from '../src/ips/providers/tor-exit.provider';
import { buildProvidersFromEnv } from '../src/ips/providers/provider.factory';

/** In-memory stand-in for the one Prisma model the service touches. */
function fakePrisma() {
  const rows = new Map<string, any>();
  return {
    rows,
    securityIp: {
      findUnique: async ({ where }: any) => rows.get(where.ipAddress) ?? null,
      upsert: async ({ where, update, create }: any) => {
        const cur = rows.get(where.ipAddress);
        const next = cur ? { ...cur, ...update } : { ...create };
        rows.set(where.ipAddress, next);
        return next;
      },
    },
  } as any;
}

function provider(name: string, impl: (ip: string) => Promise<PartialIntel | null>) {
  const calls: string[] = [];
  const p: IpIntelProvider & { calls: string[] } = {
    name,
    calls,
    lookup: async (ip: string) => { calls.push(ip); return impl(ip); },
  };
  return p;
}

describe('IpIntelligenceService', () => {
  it('merges partial answers: geo from first provider, flags OR-ed, reputation max', async () => {
    const a = provider('a', async () => ({ country: 'NG', isProxy: true, reputationScore: 10 }));
    const b = provider('b', async () => ({ country: 'US', city: 'Lagos', isTor: true, reputationScore: 80, isMalicious: true }));
    const svc = new IpIntelligenceService(fakePrisma(), [a, b]);
    const r = await svc.lookup('8.8.8.8');
    expect(r.country).toBe('NG');
    expect(r.city).toBe('Lagos');
    expect(r.isProxy).toBe(true);
    expect(r.isTor).toBe(true);
    expect(r.isMalicious).toBe(true);
    expect(r.isVpn).toBe(false);
    expect(r.reputationScore).toBe(80);
    expect(r.sources).toEqual(['a', 'b']);
  });

  it('serves repeat lookups from the cache without calling providers', async () => {
    const a = provider('a', async () => ({ isDatacenter: true }));
    const svc = new IpIntelligenceService(fakePrisma(), [a]);
    await svc.lookup('8.8.4.4');
    const second = await svc.lookup('8.8.4.4');
    expect(a.calls.length).toBe(1);
    expect(second.isDatacenter).toBe(true);
  });

  it('force bypasses the cache', async () => {
    const a = provider('a', async () => ({}));
    const svc = new IpIntelligenceService(fakePrisma(), [a]);
    await svc.lookup('8.8.4.4');
    await svc.lookup('8.8.4.4', { force: true });
    expect(a.calls.length).toBe(2);
  });

  it('never sends private or reserved addresses to a provider', async () => {
    const a = provider('a', async () => ({ isMalicious: true }));
    const svc = new IpIntelligenceService(fakePrisma(), [a]);
    for (const ip of ['10.0.0.5', '192.168.1.1', '127.0.0.1', '::1']) {
      const r = await svc.lookup(ip);
      expect(r.isMalicious).toBe(false);
    }
    expect(a.calls.length).toBe(0);
  });

  it('does not cache a clean result when every provider fails, and backs off', async () => {
    const prisma = fakePrisma();
    const bad = provider('bad', async () => { throw new Error('boom'); });
    const svc = new IpIntelligenceService(prisma, [bad]);
    const r = await svc.lookup('8.8.8.8');
    expect(r.isMalicious).toBe(false);
    expect(prisma.rows.has('8.8.8.8')).toBe(false);
    await svc.lookup('8.8.8.8');
    expect(bad.calls.length).toBe(1);
  });

  it('keeps working when one provider fails and another succeeds', async () => {
    const bad = provider('bad', async () => { throw new Error('boom'); });
    const good = provider('good', async () => ({ isTor: true }));
    const svc = new IpIntelligenceService(fakePrisma(), [bad, good]);
    const r = await svc.lookup('8.8.8.8');
    expect(r.isTor).toBe(true);
    expect(r.sources).toEqual(['good']);
  });

  it('pauses a provider after repeated failures (circuit breaker)', async () => {
    const bad = provider('bad', async () => { throw new Error('boom'); });
    const svc = new IpIntelligenceService(fakePrisma(), [bad]);
    for (let i = 1; i <= 8; i++) await svc.lookup(`8.8.8.${i}`);
    // Threshold is 5 consecutive failures, after which calls stop.
    expect(bad.calls.length).toBe(5);
  });

  it('shares one provider call between concurrent lookups of the same address', async () => {
    const a = provider('a', async () => { await new Promise((r) => setTimeout(r, 20)); return {}; });
    const svc = new IpIntelligenceService(fakePrisma(), [a]);
    await Promise.all([svc.lookup('8.8.8.8'), svc.lookup('8.8.8.8'), svc.lookup('8.8.8.8')]);
    expect(a.calls.length).toBe(1);
  });

  it('with no providers returns a neutral result', async () => {
    const svc = new IpIntelligenceService(fakePrisma(), []);
    const r = await svc.lookup('8.8.8.8');
    expect(r).toMatchObject({ isVpn: false, isProxy: false, isTor: false, isMalicious: false, reputationScore: 0 });
  });
});

describe('provider adapters', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });

  const mockFetch = (body: any, ok = true, status = 200) => {
    const fn = jest.fn(async () => ({ ok, status, json: async () => body, text: async () => String(body) })) as any;
    global.fetch = fn;
    return fn;
  };

  it('abuseipdb maps confidence to reputation and applies the threshold', async () => {
    mockFetch({ data: { abuseConfidenceScore: 90, countryCode: 'RU', usageType: 'Data Center/Web Hosting/Transit', isTor: false } });
    const r = await new AbuseIpDbProvider(1000, 'key', 75).lookup('1.2.3.4');
    expect(r).toMatchObject({ reputationScore: 90, isMalicious: true, isDatacenter: true, country: 'RU' });

    mockFetch({ data: { abuseConfidenceScore: 20, countryCode: 'NG', usageType: 'Fixed Line ISP' } });
    const low = await new AbuseIpDbProvider(1000, 'key', 75).lookup('1.2.3.4');
    expect(low).toMatchObject({ reputationScore: 20, isMalicious: false, isDatacenter: false });
  });

  it('abuseipdb sends the key as a header, not in the URL', async () => {
    const f = mockFetch({ data: { abuseConfidenceScore: 0 } });
    await new AbuseIpDbProvider(1000, 'secret-key', 75).lookup('1.2.3.4');
    const [url, init] = f.mock.calls[0] as any[];
    expect(String(url)).not.toContain('secret-key');
    expect(init.headers.Key).toBe('secret-key');
  });

  it('abuseipdb and ipinfo refuse to start without credentials', () => {
    expect(() => new AbuseIpDbProvider(1000, undefined)).toThrow();
    expect(() => new IpInfoProvider(1000, undefined)).toThrow();
  });

  it('ipapi maps proxy to isProxy (not VPN) and hosting to datacenter', async () => {
    mockFetch({ status: 'success', country: 'Nigeria', regionName: 'Lagos', city: 'Ikeja', proxy: true, hosting: true });
    const r = await new IpApiProvider(1000, undefined).lookup('1.2.3.4');
    expect(r).toMatchObject({ country: 'Nigeria', city: 'Ikeja', isProxy: true, isDatacenter: true });
    expect(r!.isVpn).toBeUndefined();
  });

  it('ipapi surfaces API-level failures as errors', async () => {
    mockFetch({ status: 'fail', message: 'reserved range' });
    await expect(new IpApiProvider(1000, undefined).lookup('10.0.0.1')).rejects.toThrow('reserved range');
  });

  it('ipinfo reads privacy flags only when the plan returns them', async () => {
    mockFetch({ country: 'NG', city: 'Lagos' });
    const geoOnly = await new IpInfoProvider(1000, 'tok').lookup('1.2.3.4');
    expect(geoOnly).toEqual({ country: 'NG', region: undefined, city: 'Lagos' });

    mockFetch({ country: 'NG', privacy: { vpn: true, proxy: false, tor: false, hosting: true } });
    const full = await new IpInfoProvider(1000, 'tok').lookup('1.2.3.4');
    expect(full).toMatchObject({ isVpn: true, isProxy: false, isTor: false, isDatacenter: true });
  });

  it('http errors surface as thrown errors', async () => {
    mockFetch({}, false, 429);
    await expect(new IpInfoProvider(1000, 'tok').lookup('1.2.3.4')).rejects.toThrow('429');
  });

  it('tor provider flags listed exit nodes and ignores others', async () => {
    mockFetch('# comment\n185.220.101.1\n185.220.101.2\n');
    const tor = new TorExitProvider(1000, 'https://example.test/list');
    expect(await tor.lookup('185.220.101.1')).toEqual({ isTor: true, isProxy: true });
    expect(await tor.lookup('8.8.8.8')).toEqual({});
  });

  it('tor provider fails loudly when the list cannot be loaded at all', async () => {
    mockFetch('', false, 503);
    const tor = new TorExitProvider(1000, 'https://example.test/list');
    await expect(tor.lookup('8.8.8.8')).rejects.toThrow();
  });
});

describe('buildProvidersFromEnv', () => {
  it('returns nothing for none or empty', () => {
    expect(buildProvidersFromEnv({ IP_INTEL_PROVIDERS: 'none' } as any)).toHaveLength(0);
    expect(buildProvidersFromEnv({} as any)).toHaveLength(0);
  });

  it('honours the legacy single-value variable', () => {
    const p = buildProvidersFromEnv({ IP_INTEL_PROVIDER: 'ipapi' } as any);
    expect(p.map((x) => x.name)).toEqual(['ipapi']);
  });

  it('keeps the configured order and de-duplicates', () => {
    const p = buildProvidersFromEnv({ IP_INTEL_PROVIDERS: 'ipapi, tor ,ipapi' } as any);
    expect(p.map((x) => x.name)).toEqual(['ipapi', 'tor']);
  });

  it('skips misconfigured and unknown providers instead of failing startup', () => {
    const p = buildProvidersFromEnv({ IP_INTEL_PROVIDERS: 'abuseipdb,ipinfo,bogus,tor' } as any);
    expect(p.map((x) => x.name)).toEqual(['tor']);
  });
});
