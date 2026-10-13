/**
 * Writes the role matrix of every API route to frontend/src/lib/route-matrix.json.
 *
 * The backend decorators are the one source of truth for who may call what. The dashboard
 * reads this file to decide which buttons and pages to offer, and a test in each project
 * fails when the file is out of date. Run:  npm run export:routes
 */
import 'reflect-metadata';
import { writeFileSync } from 'fs';
import { join } from 'path';
import { describeRoutes } from '../test/helpers/routes';
import { ROLES } from '../src/common/constants';

export function buildMatrix(): Record<string, string[]> {
  const everyone = [ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER] as string[];
  const out: Record<string, string[]> = {};
  for (const r of describeRoutes()) {
    if (r.isPublic) continue;
    // A route behind sign-in alone (change password) is open to every role.
    out[r.key] = r.roles.length ? [...r.roles] : everyone;
  }
  return out;
}

export const MATRIX_PATH = join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'route-matrix.json');

if (require.main === module) {
  writeFileSync(MATRIX_PATH, JSON.stringify(buildMatrix(), null, 2) + '\n');
  console.log(`wrote ${MATRIX_PATH}`);
}
