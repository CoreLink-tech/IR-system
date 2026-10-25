import { readdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * A cheap guard that needs no database: every table, column and index in prisma/schema.prisma must
 * appear in the SQL of some migration. It fails when someone edits the schema and forgets the
 * migration. The full proof (real MySQL, upgrade with data) is scripts/verify-migrations.mjs.
 */
const prismaDir = join(__dirname, '../prisma');
const migrationsDir = join(prismaDir, 'migrations');
const schema = readFileSync(join(prismaDir, 'schema.prisma'), 'utf8');
const names = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
const allSql = names.map((n) => readFileSync(join(migrationsDir, n, 'migration.sql'), 'utf8')).join('\n');
const PRIMITIVES = new Set(['String', 'Int', 'Boolean', 'DateTime', 'Json']);

interface M { table: string; columns: string[]; indexes: string[] }
function models(): M[] {
  const out: M[] = [];
  for (const [, name, body] of schema.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
    const m: M = { table: name, columns: [], indexes: [] };
    const lines = body.split('\n').map((l) => l.replace(/\/\/.*$/, '').trim()).filter(Boolean);
    for (const l of lines) { const map = l.match(/^@@map\("([^"]+)"\)/); if (map) m.table = map[1]; }
    for (const l of lines) {
      if (l.startsWith('@@')) {
        const idx = l.match(/^@@index\(\[([^\]]+)\]/); const uq = l.match(/^@@unique\(\[([^\]]+)\]/);
        if (idx) m.indexes.push(`${m.table}_${idx[1].split(',').map((s) => s.trim()).join('_')}_idx`);
        if (uq) m.indexes.push(`${m.table}_${uq[1].split(',').map((s) => s.trim()).join('_')}_key`);
        continue;
      }
      const f = l.match(/^(\w+)\s+(\w+)(\?|\[\])?\s*(.*)$/);
      if (!f || f[3] === '[]' || !PRIMITIVES.has(f[2])) continue;
      m.columns.push(f[1]);
      if (/@unique\b/.test(f[4])) m.indexes.push(`${m.table}_${f[1]}_key`);
    }
    out.push(m);
  }
  return out;
}

describe('migrations', () => {
  it('are named in order, have a provider lock, and each has SQL', () => {
    expect(readFileSync(join(migrationsDir, 'migration_lock.toml'), 'utf8')).toContain('provider = "mysql"');
    expect(names.length).toBeGreaterThanOrEqual(5);
    for (const n of names) {
      expect(n).toMatch(/^\d{14}_[a-z0-9_]+$/);
      expect(existsSync(join(migrationsDir, n, 'migration.sql'))).toBe(true);
    }
    expect(new Set(names.map((n) => n.slice(0, 14))).size).toBe(names.length);
  });

  it('mention every table, column and index the schema describes (run scripts/verify-migrations.mjs for the full proof)', () => {
    const missing: string[] = [];
    for (const m of models()) {
      if (!allSql.includes(`\`${m.table}\``)) missing.push(`table ${m.table}`);
      for (const c of m.columns) if (!allSql.includes(`\`${c}\``)) missing.push(`column ${m.table}.${c}`);
      for (const i of m.indexes) if (!allSql.includes(`\`${i}\``)) missing.push(`index ${i}`);
    }
    expect(missing).toEqual([]);
  });

  it('the guard itself reads the schema (13 tables)', () => { expect(models()).toHaveLength(13); });

  it('the schema uses only comment styles Prisma accepts (// and ///), never /* */', () => {
    // A block comment is not valid Prisma syntax. It cost a failed schema parse once, and the Prisma
    // engine that would have said so is not always available where the schema is edited.
    expect(schema).not.toMatch(/\/\*/);
  });

  it('never contain a statement that discards data', () => {
    // A migration that drops a table or column must be a deliberate, reviewed change with its own test.
    expect(allSql).not.toMatch(/\bDROP\s+(TABLE|COLUMN|DATABASE)\b|\bTRUNCATE\b/i);
  });
});
