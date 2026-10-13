import { randomUUID } from 'crypto';
import { NextFunction, Request, Response } from 'express';

/** A caller-supplied id is kept only if it is short and plain, so it cannot forge or break log lines. */
const SAFE_ID = /^[A-Za-z0-9._:-]{8,64}$/;

export function newRequestId(incoming?: unknown): string {
  return typeof incoming === 'string' && SAFE_ID.test(incoming) ? incoming : randomUUID();
}

/**
 * Runs before every guard, so a refused request (401, 403, 429) still has a request id in its
 * response header and error body, and can be found in the logs.
 */
export function requestIdMiddleware(req: Request & { requestId?: string }, res: Response, next: NextFunction) {
  if (!req.requestId) req.requestId = newRequestId(req.headers['x-request-id']);
  res.setHeader('X-Request-Id', req.requestId);
  next();
}
