import { generateApiKey, hashApiKey } from '../src/common/utils/crypto.util';

describe('API key generation', () => {
  const originalPepper = process.env.API_KEY_HASH_PEPPER;

  beforeAll(() => {
    process.env.API_KEY_HASH_PEPPER = 'unit-test-pepper';
    process.env.API_KEY_PREFIX = 'PMS_';
  });

  afterAll(() => {
    process.env.API_KEY_HASH_PEPPER = originalPepper;
  });

  it('produces a raw key with the expected prefix', () => {
    const { raw, prefix } = generateApiKey('PMS_');
    expect(raw.startsWith('PMS_')).toBe(true);
    expect(prefix.startsWith('PMS_')).toBe(true);
    expect(raw.length).toBeGreaterThan(40);
  });

  it('produces deterministic hash for the same raw key', () => {
    const raw = 'PMS_stable_test_key_value_1234567890';
    const h1 = hashApiKey(raw);
    const h2 = hashApiKey(raw);
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  it('produces different hashes for different keys', () => {
    const a = hashApiKey('PMS_aaaa');
    const b = hashApiKey('PMS_bbbb');
    expect(a).not.toBe(b);
  });
});
