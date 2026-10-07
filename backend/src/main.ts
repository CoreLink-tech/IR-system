import 'reflect-metadata';
import 'dotenv/config';
import { NestFactory, Reflector } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import { RequestIdInterceptor } from './common/interceptors/request-id.interceptor';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';
import { AuditService } from './audit/audit.service';
import { assertValidConfig } from './config/validate-config';
import { allowedOrigins } from './common/utils/origins';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  // Fail before opening any port if a secret is missing, weak or still a placeholder.
  assertValidConfig().forEach((w) => logger.warn(w));
  const app = await NestFactory.create(AppModule, { bufferLogs: false });

  app.use(helmet());
  app.enableCors({
    origin: allowedOrigins(),
    credentials: true,
    // A browser on another origin can only read these response headers if they are exposed.
    // Without Retry-After the dashboard could never show how long to wait after a 429.
    exposedHeaders: ['Retry-After', 'X-Request-Id'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-Id'],
  });

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: { enableImplicitConversion: true },
  }));

  app.useGlobalFilters(new AllExceptionsFilter());

  const auditService = app.get(AuditService);
  app.useGlobalInterceptors(
    new RequestIdInterceptor(),
    new AuditInterceptor(auditService),
  );

  const port = Number(process.env.PORT || 4000);
  await app.listen(port, '0.0.0.0');
  logger.log(`Pishon Security API listening on http://0.0.0.0:${port}`);
}

bootstrap().catch((err) => {
  console.error('Fatal bootstrap error:', err);
  process.exit(1);
});
