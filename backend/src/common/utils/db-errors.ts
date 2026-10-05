/**
 * True when a database write failed because it would break a unique constraint,
 * which is how a lost race shows up: another request got there first.
 */
export function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; message?: string } | null;
  if (!e) return false;
  return e.code === 'P2002' || /unique constraint|duplicate entry/i.test(e.message ?? '');
}

/** True when an update or delete found no row. */
export function isNotFound(err: unknown): boolean {
  const e = err as { code?: string } | null;
  return e?.code === 'P2025';
}
