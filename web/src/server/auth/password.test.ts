import { describe, it, expect } from 'vitest';
import { assertStrongPassword } from './password';

describe('assertStrongPassword', () => {
  it('accepts a strong password', () => {
    expect(() => assertStrongPassword('GoodPass1234')).not.toThrow();
  });

  it('rejects short passwords', () => {
    // 7 characters with complexity still fails minimum length 8
    expect(() => assertStrongPassword('Abcde1F')).toThrow(/8/);
  });

  it('rejects missing character classes', () => {
    expect(() => assertStrongPassword('alllowercase1')).toThrow();
    expect(() => assertStrongPassword('ALLUPPERCASE1')).toThrow();
    expect(() => assertStrongPassword('NoDigitsHere!')).toThrow();
  });
});
