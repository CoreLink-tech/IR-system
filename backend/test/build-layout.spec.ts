import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Regression test: `npm run build` must put main.js at dist/main.js, because `npm run start:prod`
 * and the cleanup command (dist/retention/cleanup.js) rely on it. TypeScript derives the output
 * layout from the files it compiles, so a .ts file added under scripts/ once moved everything to
 * dist/src/ and the production start failed. The build must compile src/ only.
 */
describe('production build layout', () => {
  const cfg = JSON.parse(readFileSync(join(__dirname, '../tsconfig.build.json'), 'utf8'));
  const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));

  it('compiles only src, so output lands directly in dist', () => {
    expect(cfg.include).toEqual(['src/**/*.ts']);
    expect(cfg.exclude).toEqual(expect.arrayContaining(['test', 'scripts']));
  });

  it('start and cleanup commands point at the layout that build produces', () => {
    expect(pkg.scripts['start:prod']).toBe('node dist/main.js');
    expect(pkg.scripts.cleanup).toBe('node dist/retention/cleanup.js');
    expect(pkg.scripts['cleanup:dry']).toBe('node dist/retention/cleanup.js --dry-run');
  });
});
