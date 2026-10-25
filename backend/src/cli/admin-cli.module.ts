import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';

/** Minimal Nest context for break-glass CLI commands. No HTTP server. */
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    PrismaModule,
    AuditModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'cli-placeholder-not-used',
      signOptions: { expiresIn: '15m' },
    }),
    AuthModule,
  ],
})
export class AdminCliModule {}
