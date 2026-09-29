import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS, ROLES } from '../common/constants';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
  ) {}

  private hashRefresh(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async login(email: string, password: string, ctx: { ip?: string; userAgent?: string; requestId?: string }) {
    const user = await this.prisma.securityUser.findUnique({ where: { email: email.toLowerCase() } });
    if (!user || !user.isActive) {
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'ANONYMOUS', actorLabel: email,
        action: AUDIT_ACTIONS.LOGIN, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      });
      throw new UnauthorizedException('Invalid credentials');
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
        action: AUDIT_ACTIONS.LOGIN, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.issueTokens(user, ctx);
    await this.prisma.securityUser.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.LOGIN, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { user: this.publicUser(user), ...tokens };
  }

  private async issueTokens(user: any, ctx: { ip?: string; userAgent?: string }) {
    const accessToken = await this.jwt.signAsync(
      { sub: user.id, email: user.email, role: user.role, type: 'access' },
      { secret: process.env.JWT_SECRET, expiresIn: process.env.JWT_EXPIRES_IN || '15m' },
    );
    const refreshRaw = randomBytes(48).toString('base64url');
    const refreshToken = await this.jwt.signAsync(
      { sub: user.id, nonce: refreshRaw, type: 'refresh' },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' },
    );
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await this.prisma.securityRefreshToken.create({
      data: {
        userId: user.id, tokenHash: this.hashRefresh(refreshToken), expiresAt,
        ipAddress: ctx.ip, userAgent: ctx.userAgent,
      },
    });
    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string, ctx: { ip?: string; userAgent?: string; requestId?: string }) {
    let payload: any;
    try {
      payload = await this.jwt.verifyAsync(refreshToken, { secret: process.env.JWT_REFRESH_SECRET });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (payload.type !== 'refresh') throw new UnauthorizedException('Invalid token type');
    const hash = this.hashRefresh(refreshToken);
    const stored = await this.prisma.securityRefreshToken.findUnique({ where: { tokenHash: hash } });
    if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired or revoked');
    }
    const user = await this.prisma.securityUser.findUnique({ where: { id: payload.sub } });
    if (!user || !user.isActive) throw new UnauthorizedException('User inactive');

    await this.prisma.securityRefreshToken.update({ where: { id: stored.id }, data: { revokedAt: new Date() } });
    const tokens = await this.issueTokens(user, ctx);
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.REFRESH, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { user: this.publicUser(user), ...tokens };
  }

  async logout(refreshToken: string) {
    if (!refreshToken) return;
    const hash = this.hashRefresh(refreshToken);
    await this.prisma.securityRefreshToken.updateMany({
      where: { tokenHash: hash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async createUser(dto: { email: string; password: string; name?: string; role: string }) {
    const email = dto.email.toLowerCase();
    const existing = await this.prisma.securityUser.findUnique({ where: { email } });
    if (existing) throw new ConflictException('Email already exists');
    if (!Object.values(ROLES).includes(dto.role as any)) throw new ConflictException('Invalid role');
    const passwordHash = await bcrypt.hash(dto.password, 12);
    const user = await this.prisma.securityUser.create({
      data: { email, passwordHash, name: dto.name, role: dto.role },
    });
    return this.publicUser(user);
  }

  private publicUser(user: any) {
    return { id: user.id, email: user.email, name: user.name, role: user.role, isActive: user.isActive };
  }
}
