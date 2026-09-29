import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export interface ActorContext {
  type: 'USER' | 'API_KEY' | 'SYSTEM' | 'ANONYMOUS';
  id?: string;
  label?: string;
  role?: string;
  scopes?: string[];
  ip?: string;
  userAgent?: string;
  requestId?: string;
}

export const CurrentActor = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ActorContext => {
    const req = ctx.switchToHttp().getRequest();
    return req.actor || { type: 'ANONYMOUS' };
  },
);
