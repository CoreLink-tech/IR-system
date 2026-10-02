import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isPrivateIp } from '../common/utils/ip.util';
import {
  IP_INTEL_PROVIDERS,
  IntelResult,
  IpIntelProvider,
  PartialIntel,
} from './providers/provider.types';

export { IntelResult } from './providers/provider.types';

const DEFAULT_CACHE_HOURS = 24;
/** After every provider fails for an address, do not retry it for this long. */
const FAILURE_BACKOFF_MS = 5 * 60 * 1000;
/** A provider that fails this many times in a row is skipped for the cooldown. */
const BREAKER_THRESHOLD = 5;
const BREAKER_COOLDOWN_MS = 60 * 1000;

interface BreakerState {
  failures: number;
  openUntil: number;
}

/**
 * Enriches IP addresses with geography, anonymizer signals and reputation.
 *
 * Behaviour:
 *  - Results are cached in the database (IP_INTEL_CACHE_HOURS, default 24).
 *  - Private and reserved addresses are never sent to an external provider.
 *  - Providers run in parallel, each with its own timeout (set in the provider).
 *  - Partial answers are merged: geography from the first provider that has it,
 *    boolean flags combined with OR, reputation takes the highest value.
 *  - If every provider fails, nothing is cached and the address is not retried
 *    for a few minutes, so an outage never poisons the cache with "clean".
 *  - A provider that keeps failing is skipped for a short cooldown (circuit breaker).
 *  - Concurrent lookups for the same address share one request.
 *
 * Detection never depends on this succeeding: callers receive a neutral result
 * when enrichment is unavailable.
 */
@Injectable()
export class IpIntelligenceService {
  private readonly logger = new Logger('IpIntelligence');
  private readonly inflight = new Map<string, Promise<IntelResult>>();
  private readonly failedUntil = new Map<string, number>();
  private readonly breakers = new Map<string, BreakerState>();

  constructor(
    private readonly prisma: PrismaService,
    @Inject(IP_INTEL_PROVIDERS) private readonly providers: IpIntelProvider[],
  ) {}

  /** Names of the configured providers, for diagnostics. */
  get providerNames(): string[] {
    return this.providers.map((p) => p.name);
  }

  async lookup(ip: string, opts: { force?: boolean } = {}): Promise<IntelResult> {
    const pending = this.inflight.get(ip);
    if (pending) return pending;
    const run = this.doLookup(ip, !!opts.force).finally(() => this.inflight.delete(ip));
    this.inflight.set(ip, run);
    return run;
  }

  private async doLookup(ip: string, force: boolean): Promise<IntelResult> {
    const existing = await this.prisma.securityIp.findUnique({ where: { ipAddress: ip } });

    if (!force && existing?.lastIntelUpdate) {
      const ttlMs = this.cacheHours() * 3600 * 1000;
      if (Date.now() - existing.lastIntelUpdate.getTime() < ttlMs) {
        return this.fromRecord(existing);
      }
    }

    if (isPrivateIp(ip) || this.providers.length === 0) {
      const empty = this.emptyResult();
      await this.persist(ip, empty);
      return empty;
    }

    const backoff = this.failedUntil.get(ip);
    if (!force && backoff && backoff > Date.now()) {
      return existing ? this.fromRecord(existing) : this.emptyResult();
    }

    const merged = await this.queryProviders(ip);
    if (!merged) {
      // Every provider failed or was skipped. Keep whatever we had and back off.
      this.failedUntil.set(ip, Date.now() + FAILURE_BACKOFF_MS);
      return existing ? this.fromRecord(existing) : this.emptyResult();
    }

    this.failedUntil.delete(ip);
    await this.persist(ip, merged);
    return merged;
  }

  /** Returns the merged result, or null if no provider produced an answer. */
  private async queryProviders(ip: string): Promise<IntelResult | null> {
    const now = Date.now();
    const active = this.providers.filter((p) => (this.breakers.get(p.name)?.openUntil ?? 0) <= now);
    if (active.length === 0) return null;

    const settled = await Promise.allSettled(active.map((p) => p.lookup(ip)));
    const answers: Array<{ name: string; data: PartialIntel }> = [];

    settled.forEach((outcome, i) => {
      const name = active[i].name;
      if (outcome.status === 'fulfilled') {
        this.breakers.delete(name);
        if (outcome.value) answers.push({ name, data: outcome.value });
        else answers.push({ name, data: {} });
      } else {
        this.recordFailure(name, outcome.reason);
      }
    });

    if (answers.length === 0) return null;
    return this.merge(answers);
  }

  private merge(answers: Array<{ name: string; data: PartialIntel }>): IntelResult {
    const out = this.emptyResult();
    out.sources = [];
    for (const { name, data } of answers) {
      out.sources.push(name);
      out.country = out.country ?? data.country;
      out.region = out.region ?? data.region;
      out.city = out.city ?? data.city;
      out.isVpn = out.isVpn || data.isVpn === true;
      out.isProxy = out.isProxy || data.isProxy === true;
      out.isTor = out.isTor || data.isTor === true;
      out.isDatacenter = out.isDatacenter || data.isDatacenter === true;
      out.isMalicious = out.isMalicious || data.isMalicious === true;
      out.reputationScore = Math.max(out.reputationScore, data.reputationScore ?? 0);
    }
    return out;
  }

  private recordFailure(name: string, reason: unknown) {
    const state = this.breakers.get(name) ?? { failures: 0, openUntil: 0 };
    state.failures += 1;
    if (state.failures >= BREAKER_THRESHOLD) {
      state.openUntil = Date.now() + BREAKER_COOLDOWN_MS;
      state.failures = 0;
      this.logger.warn(`Provider '${name}' paused for ${BREAKER_COOLDOWN_MS / 1000}s after repeated failures`);
    }
    this.breakers.set(name, state);
    this.logger.warn(`Provider '${name}' failed: ${(reason as Error)?.message ?? reason}`);
  }

  private async persist(ip: string, r: IntelResult) {
    const data = {
      country: r.country, region: r.region, city: r.city,
      isVpn: r.isVpn, isProxy: r.isProxy, isTor: r.isTor,
      isDatacenter: r.isDatacenter, isMalicious: r.isMalicious,
      reputationScore: r.reputationScore, lastIntelUpdate: new Date(),
    };
    await this.prisma.securityIp.upsert({
      where: { ipAddress: ip },
      update: data,
      create: { ipAddress: ip, ...data },
    });
  }

  private fromRecord(rec: any): IntelResult {
    return {
      country: rec.country ?? undefined,
      region: rec.region ?? undefined,
      city: rec.city ?? undefined,
      isVpn: rec.isVpn, isProxy: rec.isProxy, isTor: rec.isTor,
      isDatacenter: rec.isDatacenter, isMalicious: rec.isMalicious,
      reputationScore: rec.reputationScore,
    };
  }

  private cacheHours(): number {
    const v = Number(process.env.IP_INTEL_CACHE_HOURS);
    return Number.isFinite(v) && v > 0 ? v : DEFAULT_CACHE_HOURS;
  }

  private emptyResult(): IntelResult {
    return {
      isVpn: false, isProxy: false, isTor: false,
      isDatacenter: false, isMalicious: false, reputationScore: 0,
    };
  }
}
