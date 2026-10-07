import { readFileSync } from 'fs';
import { join } from 'path';

/** The backend's own version from package.json, read once. Works from src/ and from dist/. */
export const API_VERSION: string = (() => {
  try { return JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')).version ?? 'unknown'; } catch { return 'unknown'; }
})();
