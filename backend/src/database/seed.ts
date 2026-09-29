import 'reflect-metadata';
import 'dotenv/config';
import * as bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';
import { BUILT_IN_RULES } from '../detection/rules';

async function main() {
  const prisma = new PrismaClient();

  const email = (process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@pishon.local').toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || 'ChangeMeStrong!123';
  const name = process.env.BOOTSTRAP_ADMIN_NAME || 'Initial Admin';

  const hash = await bcrypt.hash(password, 12);
  const user = await prisma.securityUser.upsert({
    where: { email },
    update: {},
    create: { email, passwordHash: hash, name, role: 'SUPER_ADMIN' },
  });

  console.log(`[seed] admin ready: ${user.email} (${user.id})`);

  for (const rule of BUILT_IN_RULES) {
    await prisma.securityRule.upsert({
      where: { code: rule.code },
      update: {
        name: rule.name, description: rule.description,
        priority: rule.priority,
      },
      create: {
        code: rule.code, name: rule.name, description: rule.description,
        priority: rule.priority, isEnabled: true,
        config: rule.defaultConfig as any,
      },
    });
  }
  console.log(`[seed] ${BUILT_IN_RULES.length} detection rules ready`);

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
