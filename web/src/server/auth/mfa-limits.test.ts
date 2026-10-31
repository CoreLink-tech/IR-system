import { describe, it, expect } from 'vitest';

/** Pure helper mirroring challenge burn policy for unit coverage. */
function nextChallengeState(failures: number, max = 5) {
  const next = failures + 1;
  return { failures: next, burned: next >= max };
}

describe('MFA challenge burn policy', () => {
  it('burns on 5th failure', () => {
    let f = 0;
    let burned = false;
    for (let i = 0; i < 5; i++) {
      const s = nextChallengeState(f);
      f = s.failures;
      burned = s.burned;
    }
    expect(f).toBe(5);
    expect(burned).toBe(true);
  });

  it('6th attempt would already be burned', () => {
    expect(nextChallengeState(5).burned).toBe(true);
  });
});

describe('login window reset policy', () => {
  const WINDOW = 15 * 60 * 1000;
  function nextFailures(prevFailures: number, ageMs: number) {
    return ageMs > WINDOW ? 1 : prevFailures + 1;
  }
  it('resets after window', () => {
    expect(nextFailures(4, WINDOW + 1)).toBe(1);
  });
  it('increments inside window', () => {
    expect(nextFailures(4, 1000)).toBe(5);
  });
});
