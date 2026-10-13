import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(process.cwd(), 'src');
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => { const p = join(dir, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
}
const all = walk(root).filter((f) => /\.(ts|tsx)$/.test(f));
const source = all.filter((f) => !/\.test\.|\/test\//.test(f));
const read = (f: string) => readFileSync(f, 'utf8');

describe('the dashboard follows its own security rules', () => {
  it('never renders markup from the server: no dangerouslySetInnerHTML, innerHTML, eval or Function', () => {
    for (const f of source) {
      const t = read(f);
      expect([f, /dangerouslySetInnerHTML|\.innerHTML\s*=|\beval\s*\(|new Function\s*\(/.test(t)]).toEqual([f, false]);
    }
  });
  it('never stores tokens: no localStorage or sessionStorage use except the harmless saved place and time preference', () => {
    for (const f of source) {
      const uses = [...read(f).matchAll(/(localStorage|sessionStorage)\.(setItem|getItem)\(\s*([^,)]+)/g)].map((m) => m[3].trim());
      for (const key of uses) expect([f, key]).toEqual([f, expect.stringMatching(/RETURN_KEY|KEY$/)]);
    }
  });
  it('never puts a token in a URL or a log', () => {
    for (const f of source) {
      const t = read(f);
      expect([f, /console\.(log|info|debug|warn|error)/.test(t)]).toEqual([f, false]);
      expect([f, /[?&](token|access_token|refresh_token|key)=/.test(t)]).toEqual([f, false]);
    }
  });
  it('loads nothing from another site: no absolute http(s) URLs in the source except the local development default', () => {
    for (const f of source) {
      const urls = [...read(f).matchAll(/https?:\/\/[^\s'"`)]+/g)].map((m) => m[0]).filter((u) => !u.startsWith('http://localhost') && !u.startsWith('http://www.w3.org'));
      expect([f, urls]).toEqual([f, []]);
    }
  });
  it('asks permission through can(), never by comparing role names', () => {
    for (const f of source) {
      const t = read(f);
      expect([f, /\.role\s*[!=]==?\s*['"]/.test(t) || /role\s*===\s*['"](SUPER_ADMIN|SECURITY_ADMIN|ANALYST|VIEWER)/.test(t)]).toEqual([f, false]);
    }
  });
  it('never works out a severity, risk or posture from a number: it only shows the level the API returned', () => {
    for (const f of source) {
      const t = read(f);
      expect([f, /(riskScore|\.score|peakRisk|reputationScore)\s*[<>]=?\s*\d/.test(t)]).toEqual([f, false]);
      expect([f, /(severity|riskLevel|posture)\s*=\s*[^=]*[<>]\s*\d/.test(t)]).toEqual([f, false]);
    }
  });
  it('opens no external link without rel noopener (there are no target=_blank links at all)', () => {
    for (const f of source) expect([f, /target=["']_blank/.test(read(f))]).toEqual([f, false]);
  });
  it('index.html loads only its own script and no third-party fonts or styles', () => {
    const html = readFileSync(join(process.cwd(), 'index.html'), 'utf8');
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toMatch(/<script(?![^>]*src=)[^>]*>[^<]/); // no inline script
  });
});
