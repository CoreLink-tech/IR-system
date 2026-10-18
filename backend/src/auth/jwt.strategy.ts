import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../prisma/prisma.service';

interface JwtPayload {
  sub: string;
  email: string;
  role: string;
  type: 'access';
  /** Account token version the token was issued under. Missing on tokens issued before it existed (counts as 0). */
  tv?: number;
  /** The sign-in (session) the token belongs to. */
  sid?: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      // No fallback. Startup validation guarantees a real secret is present.
      secretOrKey: process.env.JWT_SECRET as string,
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload || payload.type !== 'access') throw new UnauthorizedException();
    const user = await this.prisma.securityUser.findUnique({ where: { id: payload.sub } });
    if (!user || !user.isActive) throw new UnauthorizedException('User inactive');
    // Ended on purpose (password change, sign out everywhere, administrator reset): refuse at once, not after expiry.
    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) throw new UnauthorizedException({ message: 'This session has ended. Please sign in again.', code: 'session_ended' });
    return { id: user.id, email: user.email, role: user.role, name: user.name, mustChangePassword: !!user.mustChangePassword, sessionId: payload.sid };
  }
}
