/**
 * Retention settings. Every value has a safe default and a floor, so a typing mistake cannot erase
 * recent evidence. A retention of 0 days means "keep forever" and switches that job off.
 */
export interface RetentionConfig {
  /** Raw security events. Events attached to an unresolved incident are never removed. */
  eventDays: number;
  /** Audit log (who did what in this system). Kept longer than events by default. */
  auditDays: number;
  /** The audit row written for every accepted event (action event.ingest). The event itself is the record, so these go sooner. */
  ingestAuditDays: number;
  /** Resolved and false-positive incidents, with their timeline. */
  incidentDays: number;
  /** Blocks that are no longer active (history). Expired blocks are always switched off. */
  blockHistoryDays: number;
  /** Refresh tokens are removed this many days AFTER they expire (keeps reuse detection working). */
  tokenGraceDays: number;
  /** Expired allowlist entries are removed this many days after they expire. */
  expiredEntryDays: number;
  /** Rows per statement. Small batches keep locks short. */
  batchSize: number;
  /** Pause between batches so live traffic is never starved. */
  pauseMs: number;
  /** Stop starting new batches after this long. The next run carries on. */
  maxSeconds: number;
}

interface Spec { env: string; key: keyof RetentionConfig; def: number; min: number; max: number; zeroOff?: boolean; label: string }

const SPECS: Spec[] = [
  { env: 'RETENTION_EVENT_DAYS', key: 'eventDays', def: 90, min: 7, max: 3650, zeroOff: true, label: 'events' },
  { env: 'RETENTION_AUDIT_DAYS', key: 'auditDays', def: 365, min: 30, max: 3650, zeroOff: true, label: 'audit log' },
  { env: 'RETENTION_INGEST_AUDIT_DAYS', key: 'ingestAuditDays', def: 30, min: 7, max: 3650, zeroOff: true, label: 'ingestion audit entries' },
  { env: 'RETENTION_INCIDENT_DAYS', key: 'incidentDays', def: 730, min: 30, max: 3650, zeroOff: true, label: 'resolved incidents' },
  { env: 'RETENTION_BLOCK_HISTORY_DAYS', key: 'blockHistoryDays', def: 365, min: 30, max: 3650, zeroOff: true, label: 'block history' },
  { env: 'RETENTION_TOKEN_GRACE_DAYS', key: 'tokenGraceDays', def: 7, min: 1, max: 365, label: 'refresh token grace' },
  { env: 'RETENTION_EXPIRED_ENTRY_DAYS', key: 'expiredEntryDays', def: 7, min: 0, max: 365, label: 'expired allowlist grace' },
  { env: 'RETENTION_BATCH_SIZE', key: 'batchSize', def: 5000, min: 100, max: 20000, label: 'batch size' },
  { env: 'RETENTION_PAUSE_MS', key: 'pauseMs', def: 200, min: 0, max: 10000, label: 'pause between batches' },
  { env: 'RETENTION_MAX_SECONDS', key: 'maxSeconds', def: 600, min: 10, max: 86400, label: 'run time limit' },
];

export function loadRetentionConfig(env: NodeJS.ProcessEnv = process.env): { config: RetentionConfig; errors: string[] } {
  const config: any = {};
  const errors: string[] = [];
  for (const s of SPECS) {
    const raw = env[s.env];
    if (raw === undefined || raw.trim() === '') { config[s.key] = s.def; continue; }
    if (!/^\d+$/.test(raw.trim())) { errors.push(`${s.env} must be a whole number of ${s.label}, got "${raw}".`); config[s.key] = s.def; continue; }
    const n = Number(raw.trim());
    if (s.zeroOff && n === 0) { config[s.key] = 0; continue; }
    if (n < s.min || n > s.max) {
      errors.push(`${s.env} must be between ${s.min} and ${s.max}${s.zeroOff ? ' (or 0 to keep forever)' : ''}, got ${n}.`);
      config[s.key] = s.def;
      continue;
    }
    config[s.key] = n;
  }
  return { config: config as RetentionConfig, errors };
}
