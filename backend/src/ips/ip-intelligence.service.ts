import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface IntelResult {
  country?: string;
  region?: string;
  city?: string;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  isMalicious: boolean;
  reputationScore: number;
}

const CACHE_TTL_HOURS = 24;

@Injectable()
export class IpIntelligenceService {
  private readonly logger = new Logger('IpIntelligence');

  constructor(private readonly prisma: PrismaService) {}

  async lookup(ip: string): Promise<IntelResult> {
    const existing = await this.prisma.securityIp.findUnique({ where: { ipAddress: ip } });
    if (existing?.lastIntelUpdate) {
      const age = Date.now() - existing.lastIntelUpdate.getTime();
      if (age < CACHE_TTL_HOURS * 3600 * 1000) {
        return {
          country: existing.country ?? undefined,
          region: existing.region ?? undefined,
          city: existing.city ?? undefined,
          isVpn: existing.isVpn, isProxy: existing.isProxy, isTor: existing.isTor,
          isDatacenter: existing.isDatacenter, isMalicious: existing.isMalicious,
          reputationScore: existing.reputationScore,
        };
      }
    }

    const provider = (process.env.IP_INTEL_PROVIDER || 'none').toLowerCase();
    let result: IntelResult;
    try {
      if (provider === 'none' || !provider) {
        result = this.emptyResult();
      } else {
        this.logger.warn(`Unknown IP intel provider '${provider}', using empty result`);
        result = this.emptyResult();
      }
    } catch (err) {
      this.logger.warn(`IP intel lookup failed for ${ip}: ${(err as Error).message}`);
      result = this.emptyResult();
    }

    await this.prisma.securityIp.upsert({
      where: { ipAddress: ip },
      update: {
        country: result.country, region: result.region, city: result.city,
        isVpn: result.isVpn, isProxy: result.isProxy, isTor: result.isTor,
        isDatacenter: result.isDatacenter, isMalicious: result.isMalicious,
        reputationScore: result.reputationScore, lastIntelUpdate: new Date(),
      },
      create: {
        ipAddress: ip,
        country: result.country, region: result.region, city: result.city,
        isVpn: result.isVpn, isProxy: result.isProxy, isTor: result.isTor,
        isDatacenter: result.isDatacenter, isMalicious: result.isMalicious,
        reputationScore: result.reputationScore, lastIntelUpdate: new Date(),
      },
    });

    return result;
  }

  private emptyResult(): IntelResult {
    return {
      isVpn: false, isProxy: false, isTor: false,
      isDatacenter: false, isMalicious: false, reputationScore: 0,
    };
  }
}
