import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../prisma/prisma.service';
import { loadAccessKeyRing, secretForKid } from './jwt-keys';

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
    const ring = loadAccessKeyRing();
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      // Resolve the secret from the token's kid so rotation can keep old tokens valid during overlap.
      secretOrKeyProvider: (_request: any, rawJwt: string, done: (err: any, secret?: string | Buffer) => void) => {
        try {
          const headerPart = String(rawJwt || '').split('.')[0] || '';
          const json = Buffer.from(headerPart.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
          const header = JSON.parse(json) as { kid?: string };
          const secret = secretForKid(ring, header.kid);
          if (!secret) return done(new UnauthorizedException({ message: 'Token signed with an unknown key.', code: 'token_key_unknown' }));
          return done(null, secret);
        } catch {
          return done(null, ring.current);
        }
      },
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload || payload.type !== 'access') throw new UnauthorizedException();
    const user = await this.prisma.securityUser.findUnique({ where: { id: payload.sub } });
    if (!user || !user.isActive) throw new UnauthorizedException('User inactive');
    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) throw new UnauthorizedException({ message: 'This session has ended. Please sign in again.', code: 'session_ended' });
    return { id: user.id, email: user.email, role: user.role, name: user.name, mustChangePassword: !!user.mustChangePassword, sessionId: payload.sid };
  }
}
