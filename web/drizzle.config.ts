import { defineConfig } from 'drizzle-kit';
import 'dotenv/config';

export default defineConfig({
  schema: './src/server/db/schema.ts',
  out: './drizzle',
  dialect: 'sqlite',
  dbCredentials: {
    url: process.env.DATABASE_URL || 'file:./data/ir.db',
    // Turso: set DATABASE_AUTH_TOKEN; drizzle-kit supports it via driver options when using libsql
  },
});
