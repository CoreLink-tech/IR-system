import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request & { requestId?: string }>();

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

    let message: string | object = 'Internal server error';
    // A short machine-readable reason, only when the code that threw the error gave one.
    // The dashboard uses it to tell, for example, a stolen session from a plain expiry.
    let code: string | undefined;
    if (exception instanceof HttpException) {
      const r = exception.getResponse();
      message = typeof r === 'string' ? r : (r as any).message || r;
      if (typeof r === 'object' && typeof (r as any).code === 'string') code = (r as any).code;
    }

    const body = {
      statusCode: status,
      message,
      path: req.url,
      method: req.method,
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
      ...(code ? { code } : {}),
    };

    if (status >= 500) {
      this.logger.error(
        `${req.method} ${req.url} -> ${status} [${req.requestId}]`,
        exception instanceof Error ? exception.stack : String(exception),
      );
    }

    res.status(status).json(body);
  }
}
