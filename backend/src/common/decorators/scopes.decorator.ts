import { SetMetadata } from '@nestjs/common';
import { Scope, SCOPES_KEY } from '../constants';
export { SCOPES_KEY };
export const Scopes = (...scopes: Scope[]) => SetMetadata(SCOPES_KEY, scopes);
