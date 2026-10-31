import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';

function hashPayload(prevHash: string, body: Record<string, unknown>): string {
  return createHash('sha256').update(`${prevHash}|${JSON.stringify(body)}`).digest('hex');
}

describe('audit chain hash', () => {
  it('chains deterministically', () => {
    let prev = 'GENESIS';
    const hashes: string[] = [];
    for (let i = 0; i < 20; i++) {
      const body = { id: String(i), action: 'test', result: 'SUCCESS', createdAt: 't' };
      const h = hashPayload(prev, body);
      hashes.push(h);
      prev = h;
    }
    expect(new Set(hashes).size).toBe(20);
  });
});
