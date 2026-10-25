import { describe, it, expect } from 'vitest';
import { assertStrongPassword } from './password';

describe('assertStrongPassword', () => {
  it('accepts a strong password', () => {
    expect(() => assertStrongPassword('GoodPass1234')).not.toThrow();
  });

  it('rejects short passwords', () => {
    expect(() => assertStrongPassword('Short1Aa')).toThrow(/12/);
  });

  it('rejects missing character classes', () => {
    expect(() => assertStrongPassword('alllowercase1')).toThrow();
    expect(() => assertStrongPassword('ALLUPPERCASE1')).toThrow();
    expect(() => assertStrongPassword('NoDigitsHere!')).toThrow();
  });
});
