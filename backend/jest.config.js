module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '.',
  testRegex: '.*\\.spec\\.ts$',
  transform: { '^.+\\.(t|j)s$': 'ts-jest' },
  // Wiring that needs a running database or the full framework (bootstrap, modules, the
  // Prisma connection, the seed script, the Passport glue) is exercised by the live
  // end-to-end run in Stage 8, not by unit tests, so it is left out of the percentage.
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/main.ts',
    '!src/**/*.module.ts',
    '!src/database/seed.ts',
    '!src/prisma/prisma.service.ts',
    '!src/**/*.d.ts',
  ],
  coverageDirectory: './coverage',
  // `npm run test:cov` fails if coverage drops below these floors, so the safety net
  // cannot quietly erode. The security-critical files have a stricter floor.
  coverageThreshold: {
    global: { statements: 88, branches: 75, functions: 82, lines: 89 },
    './src/auth/auth.service.ts': { statements: 95, branches: 90, lines: 95 },
    './src/events/events.service.ts': { statements: 95, branches: 80, lines: 95 },
    './src/blocking/blocking.service.ts': { statements: 95, branches: 85, lines: 95 },
    './src/api-keys/api-keys.service.ts': { statements: 95, lines: 95 },
    './src/common/guards/api-key.guard.ts': { statements: 95, lines: 95 },
    './src/common/guards/scopes.guard.ts': { statements: 95, lines: 95 },
    './src/common/guards/jwt-or-api-key.guard.ts': { statements: 90, lines: 90 },
    './src/common/utils/ip.util.ts': { statements: 90, lines: 90 },
    './src/config/validate-config.ts': { statements: 95, lines: 95 },
  },
  testEnvironment: 'node',
  moduleNameMapper: { '^@/(.*)$': '<rootDir>/src/$1' },
  testTimeout: 30000,
};
