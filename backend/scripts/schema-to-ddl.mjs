#!/usr/bin/env node
/**
 * Turns a Prisma schema (the subset this project uses) into MySQL DDL in the style Prisma emits.
 *
 *   node scripts/schema-to-ddl.mjs [path/to/schema.prisma]      prints SQL to stdout
 *
 * Why it exists: the migrations in prisma/migrations are written by hand (the Prisma schema
 * engine cannot be downloaded in every environment). scripts/verify-migrations.mjs uses this
 * tool to prove that applying the migrations produces exactly the database the schema describes.
 * It is a verification aid, not something to run against production.
 *
 * Supported: String, Int, Boolean, DateTime, Json, @db.Text, @id, @unique, @default(now()),
 * @default(literal), @updatedAt, @relation(fields, references, onDelete), @@index, @@unique, @@map.
 * Anything else throws, so a new schema feature cannot be silently skipped.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CHARSET = 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';

export function parseSchema(text) {
  const models = [];
  const blocks = [...text.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)];
  const modelNames = new Set(blocks.map((b) => b[1]));
  for (const [, name, body] of blocks) {
    const model = { name, table: name, fields: [], indexes: [], uniques: [] };
    for (const raw of body.split('\n')) {
      const line = raw.replace(/\/\/.*$/, '').trim();
      if (!line) continue;
      if (line.startsWith('@@')) {
        const map = line.match(/^@@map\("([^"]+)"\)/);
        const idx = line.match(/^@@index\(\[([^\]]+)\]/);
        const uq = line.match(/^@@unique\(\[([^\]]+)\]/);
        if (map) model.table = map[1];
        else if (idx) model.indexes.push(idx[1].split(',').map((s) => s.trim()));
        else if (uq) model.uniques.push(uq[1].split(',').map((s) => s.trim()));
        else throw new Error(`Unsupported block attribute in ${name}: ${line}`);
        continue;
      }
      const m = line.match(/^(\w+)\s+(\w+)(\?|\[\])?\s*(.*)$/);
      if (!m) throw new Error(`Cannot read line in ${name}: ${line}`);
      const [, fname, type, mod, attrs] = m;
      const field = { name: fname, type, optional: mod === '?', list: mod === '[]', attrs, isRelation: modelNames.has(type) };
      model.fields.push(field);
    }
    models.push(model);
  }
  return models;
}

/** The text inside NAME( ... ), honouring nested parentheses, or null when the attribute is absent. */
function balanced(text, name) {
  const at = text.indexOf(`${name}(`);
  if (at === -1) return null;
  let depth = 0;
  for (let i = at + name.length; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(at + name.length + 1, i);
  }
  throw new Error(`Unbalanced ${name}( in: ${text}`);
}

function columnSql(f) {
  const a = f.attrs;
  let sqlType;
  if (f.type === 'String') sqlType = /@db\.Text/.test(a) ? 'TEXT' : 'VARCHAR(191)';
  else if (f.type === 'Int') sqlType = 'INTEGER';
  else if (f.type === 'Boolean') sqlType = 'BOOLEAN';
  else if (f.type === 'DateTime') sqlType = 'DATETIME(3)';
  else if (f.type === 'Json') sqlType = 'JSON';
  else throw new Error(`Unsupported type ${f.type} for ${f.name}`);
  let def = '';
  const d = balanced(a, '@default');
  if (d !== null) {
    const v = d.trim();
    if (v === 'now()') def = ' DEFAULT CURRENT_TIMESTAMP(3)';
    else if (v === 'cuid()' || v === 'uuid()') def = '';
    else if (v === 'true' || v === 'false') def = ` DEFAULT ${v}`;
    else if (/^-?\d+$/.test(v)) def = ` DEFAULT ${v}`;
    else if (/^"[^"]*"$/.test(v)) def = ` DEFAULT '${v.slice(1, -1).replace(/'/g, "''")}'`;
    else throw new Error(`Unsupported default ${v} for ${f.name}`);
  }
  return `\`${f.name}\` ${sqlType} ${f.optional ? 'NULL' : 'NOT NULL'}${def}`;
}

function checkAttrs(model) {
  for (const f of model.fields) {
    const rest = f.attrs.replace(/@db\.Text|@id|@unique|@updatedAt|@default\((?:[^()]|\([^)]*\))*\)|@relation\((?:[^()]|\([^)]*\))*\)/g, '').trim();
    if (rest) throw new Error(`Unsupported attribute on ${model.name}.${f.name}: ${rest}`);
  }
}

export function toDdl(models) {
  const byName = new Map(models.map((m) => [m.name, m]));
  const creates = [];
  const fks = [];
  for (const model of models) {
    checkAttrs(model);
    const cols = model.fields.filter((f) => !f.isRelation && !f.list);
    const lines = cols.map(columnSql);
    const pk = cols.filter((f) => /@id\b/.test(f.attrs)).map((f) => f.name);
    const indexLines = [];
    for (const f of cols) if (/@unique\b/.test(f.attrs)) indexLines.push(`UNIQUE INDEX \`${model.table}_${f.name}_key\`(\`${f.name}\`)`);
    for (const u of model.uniques) indexLines.push(`UNIQUE INDEX \`${model.table}_${u.join('_')}_key\`(${u.map((c) => `\`${c}\``).join(', ')})`);
    for (const i of model.indexes) indexLines.push(`INDEX \`${model.table}_${i.join('_')}_idx\`(${i.map((c) => `\`${c}\``).join(', ')})`);
    indexLines.push(`PRIMARY KEY (${pk.map((c) => `\`${c}\``).join(', ')})`);
    creates.push(`-- CreateTable\nCREATE TABLE \`${model.table}\` (\n${lines.map((l) => `    ${l}`).join(',\n')},\n\n${indexLines.map((l) => `    ${l}`).join(',\n')}\n) ${CHARSET};\n`);

    for (const f of model.fields) {
      const relText = balanced(f.attrs, '@relation');
      const rel = relText === null ? null : [null, relText];
      if (!rel || !f.isRelation || f.list) continue;
      const fieldsM = rel[1].match(/fields:\s*\[([^\]]+)\]/);
      const refsM = rel[1].match(/references:\s*\[([^\]]+)\]/);
      if (!fieldsM) continue;
      const local = fieldsM[1].split(',').map((s) => s.trim());
      const refs = refsM[1].split(',').map((s) => s.trim());
      const target = byName.get(f.type);
      const localFields = local.map((n) => model.fields.find((x) => x.name === n));
      const optional = localFields.some((x) => x.optional);
      const od = rel[1].match(/onDelete:\s*(\w+)/);
      const onDelete = od ? { Cascade: 'CASCADE', SetNull: 'SET NULL', Restrict: 'RESTRICT', NoAction: 'NO ACTION' }[od[1]] : optional ? 'SET NULL' : 'RESTRICT';
      if (!onDelete) throw new Error(`Unsupported onDelete on ${model.name}.${f.name}`);
      fks.push(`-- AddForeignKey\nALTER TABLE \`${model.table}\` ADD CONSTRAINT \`${model.table}_${local.join('_')}_fkey\` FOREIGN KEY (${local.map((c) => `\`${c}\``).join(', ')}) REFERENCES \`${target.table}\`(${refs.map((c) => `\`${c}\``).join(', ')}) ON DELETE ${onDelete} ON UPDATE CASCADE;\n`);
    }
  }
  return `${creates.join('\n')}\n${fks.join('\n')}`;
}

export function schemaToDdl(schemaText) {
  return toDdl(parseSchema(schemaText));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] || new URL('../prisma/schema.prisma', import.meta.url).pathname;
  process.stdout.write(schemaToDdl(readFileSync(path, 'utf8')));
}
