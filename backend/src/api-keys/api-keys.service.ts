import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { generateApiKey, hashApiKey, safeEqual } from '../common/utils/crypto.util';

@Injectable()
export class ApiKeysService {
  constructor(private readonly prisma: PrismaService) {}

  async create(dto: { name: string; scopes: string[]; expiresInDays?: number }, createdBy?: string) {
    const generated = generateApiKey(process.env.API_KEY_PREFIX || 'PMS_');
    const expiresAt = dto.expiresInDays && dto.expiresInDays > 0
      ? new Date(Date.now() + dto.expiresInDays * 24 * 60 * 60 * 1000)
      : null;

    const record = await this.prisma.securityApiKey.create({
      data: {
        name: dto.name, keyPrefix: generated.prefix, keyHash: generated.hash,
        scopes: dto.scopes.join(','), expiresAt, createdBy,
      },
    });

    return {
      id: record.id, name: record.name,
      scopes: record.scopes.split(','), expiresAt: record.expiresAt,
      apiKey: generated.raw,
    };
  }

  async verifyApiKey(raw: string) {
    const prefixLen = (process.env.API_KEY_PREFIX || 'PMS_').length + 16;
    const prefix = raw.slice(0, prefixLen);
    const record = await this.prisma.securityApiKey.findFirst({ where: { keyPrefix: prefix } });
    if (!record) return null;
    if (!record.isActive || record.revokedAt) return null;
    if (record.expiresAt && record.expiresAt < new Date()) return null;
    const hash = hashApiKey(raw);
    if (!safeEqual(hash, record.keyHash)) return null;
    await this.prisma.securityApiKey.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } });
    return record;
  }

  async list() {
    return this.prisma.securityApiKey.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, name: true, keyPrefix: true, scopes: true, isActive: true,
        expiresAt: true, lastUsedAt: true, revokedAt: true, createdAt: true,
      },
    });
  }

  async revoke(id: string) {
    const key = await this.prisma.securityApiKey.findUnique({ where: { id } });
    if (!key) throw new NotFoundException('API key not found');
    return this.prisma.securityApiKey.update({
      where: { id }, data: { isActive: false, revokedAt: new Date() },
    });
  }

  async rotate(id: string) {
    const old = await this.prisma.securityApiKey.findUnique({ where: { id } });
    if (!old) throw new NotFoundException('API key not found');
    const created = await this.create(
      {
        name: `${old.name} (rotated)`,
        scopes: old.scopes.split(','),
        expiresInDays: old.expiresAt
          ? Math.max(1, Math.ceil((old.expiresAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000)))
          : undefined,
      },
      old.createdBy || undefined,
    );
    await this.revoke(id);
    return created;
  }
}
