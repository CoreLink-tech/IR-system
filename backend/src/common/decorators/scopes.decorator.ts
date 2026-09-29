import { SetMetadata } from '@nestjs/common';
import { Scope } from '../constants';
export const SCOPES_KEY = 'scopes';
export const Scopes = (...scopes: Scope[]) => SetMetadata(SCOPES_KEY, scopes);
