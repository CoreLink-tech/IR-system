import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { join } from 'node:path';
const css = readFileSync(join(process.cwd(), 'src/styles/global.css'), 'utf8');

function vars(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of block.matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]] = m[2];
  return out;
}
const lightBlock = css.match(/:root\s*\{([^}]*)\}/)![1];
const darkBlock = css.match(/@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}/)![1];
const light = vars(lightBlock);
const dark = { ...light, ...vars(darkBlock) };

const lum = (hex: string) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
export const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

describe.each([['light', light], ['dark', dark]] as const)('WCAG AA contrast, %s theme', (_name, t) => {
  const pairs: Array<[string, string, number]> = [
    ['--bg', '--fg', 4.5], ['--surface', '--surface-fg', 4.5], ['--surface', '--muted-fg', 4.5], ['--bg', '--muted-fg', 4.5],
    ['--primary-bg', '--primary-fg', 4.5], ['--danger-bg', '--danger-fg', 4.5],
    ['--surface', '--link', 4.5], ['--bg', '--link', 4.5],
    ['--surface', '--danger-bg', 4.5],      // error text is drawn in this colour on a card
    ['--surface', '--focus', 3],            // focus outline against the surface (non-text: 3:1)
    ['--surface', '--border', 1.2],
  ];
  for (const [a, b, min] of pairs) it(`${a} / ${b} is at least ${min}:1`, () => expect(ratio(t[a], t[b])).toBeGreaterThanOrEqual(min));

  const bgs = Object.keys(t).filter((k) => k.endsWith('-bg') && t[k.replace(/-bg$/, '-fg')]);
  for (const bg of bgs) {
    const fg = bg.replace(/-bg$/, '-fg');
    it(`${bg} / ${fg} is at least 4.5:1`, () => expect(ratio(t[bg], t[fg])).toBeGreaterThanOrEqual(4.5));
  }
  it('badge text sits on its own tint and on the card, both readable', () => {
    for (const s of ['critical', 'high', 'medium', 'low', 'info']) expect(ratio(t[`--sev-${s}-fg`], t['--surface'])).toBeGreaterThanOrEqual(4.5);
  });
});

describe('the contrast calculator itself', () => {
  it('knows black on white is 21:1 and that a pale grey fails AA', () => {
    expect(ratio('#000000', '#ffffff')).toBeCloseTo(21, 0);
    expect(ratio('#ffffff', '#777777')).toBeLessThan(4.5);
    expect(ratio('#ffffff', '#767676')).toBeGreaterThanOrEqual(4.5);
  });
});
