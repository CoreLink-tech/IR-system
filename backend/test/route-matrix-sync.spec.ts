import 'reflect-metadata';
import { readFileSync } from 'fs';
import { buildMatrix, MATRIX_PATH } from '../scripts/export-route-matrix';

describe('dashboard role matrix', () => {
  it('matches the route decorators exactly (if this fails, run: npm run export:routes)', () => {
    const committed = JSON.parse(readFileSync(MATRIX_PATH, 'utf8'));
    expect(committed).toEqual(buildMatrix());
  });
  it('leaves out public routes and lists roles for everything else', () => {
    const m = buildMatrix();
    expect(m['POST /api/v1/auth/login']).toBeUndefined();
    expect(m['GET /api/v1/health']).toBeUndefined();
    for (const roles of Object.values(m)) expect(roles.length).toBeGreaterThan(0);
  });
});
