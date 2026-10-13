// Fails the build when the production bundle grows past its budget (gzip sizes, in KB).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

const BUDGET = {
  initialJs: 110,   // everything the first page needs: entry + react + query
  anyLazyChunk: 25, // each page loaded on demand
  css: 12,
};

const dir = new URL('../dist/assets/', import.meta.url).pathname;
const html = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
const gz = (f) => gzipSync(readFileSync(join(dir, f))).length / 1024;
const files = readdirSync(dir);
const initialNames = new Set([...html.matchAll(/assets\/([^"']+\.js)/g)].map((m) => m[1]));
// Preloaded chunks are also part of the first load.
for (const m of html.matchAll(/modulepreload"[^>]*href="\/assets\/([^"]+)"/g)) initialNames.add(m[1]);

let initial = 0; let fail = false; const rows = [];
for (const f of files.filter((x) => x.endsWith('.js'))) {
  const kb = gz(f);
  if (initialNames.has(f)) initial += kb;
  else { rows.push([f, kb]); if (kb > BUDGET.anyLazyChunk) { console.error(`over budget: ${f} is ${kb.toFixed(1)} KB (limit ${BUDGET.anyLazyChunk})`); fail = true; } }
}
const css = files.filter((x) => x.endsWith('.css')).reduce((s, f) => s + gz(f), 0);
console.log(`initial JS (gzip): ${initial.toFixed(1)} KB (budget ${BUDGET.initialJs})`);
console.log(`CSS (gzip): ${css.toFixed(1)} KB (budget ${BUDGET.css})`);
console.log(`largest lazy chunk (gzip): ${Math.max(0, ...rows.map((r) => r[1])).toFixed(1)} KB (budget ${BUDGET.anyLazyChunk}), ${rows.length} chunks`);
if (initial > BUDGET.initialJs) { console.error('initial JavaScript is over budget'); fail = true; }
if (css > BUDGET.css) { console.error('CSS is over budget'); fail = true; }
if (fail) process.exit(1);
console.log('bundle is within budget');
