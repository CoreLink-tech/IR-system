import type { Incident, IncidentStatus, Severity } from '@/api/types';

/** Plain words for the values the API uses. The dashboard shows the level the API returned and never works one out. */

export const SEVERITY_LABEL: Record<string, string> = {
  INFO: 'Info', LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High', CRITICAL: 'Critical',
};
export const RISK_LABEL: Record<string, string> = {
  NORMAL: 'Normal', SUSPICIOUS: 'Suspicious', HIGH: 'High', CRITICAL: 'Critical',
};
export const STATUS_LABEL: Record<string, string> = {
  OPEN: 'Open', INVESTIGATING: 'Being investigated', CONTAINED: 'Contained', RESOLVED: 'Resolved', FALSE_POSITIVE: 'False alarm',
};
export const STATUS_HELP: Record<IncidentStatus, string> = {
  OPEN: 'Nobody has started on this yet.',
  INVESTIGATING: 'Someone is looking into it.',
  CONTAINED: 'The threat has been stopped from spreading, but the case is not closed.',
  RESOLVED: 'The case is closed. New activity from the same source will open a new incident.',
  FALSE_POSITIVE: 'This was not an attack. The case is closed. New activity will open a new incident.',
};
export const POSTURE_LABEL: Record<string, string> = {
  ALL_CLEAR: 'All clear', MONITORING: 'Monitoring', ACTION_NEEDED: 'Action needed', URGENT: 'Urgent',
};
export const EVENT_LABEL: Record<string, string> = {
  login_failed: 'Failed sign-in', login_success: 'Successful sign-in', password_reset: 'Password reset',
  account_change: 'Account change', admin_access: 'Admin area access', suspicious_request: 'Suspicious request',
  rate_limit_exceeded: 'Too many requests', payment_security_event: 'Payment security event',
  application_error: 'Application error', server_error: 'Server error', logout: 'Sign-out', session_anomaly: 'Unusual session',
};

export type Scope = 'address' | 'account' | 'platform';
export function scopeOf(i: Pick<Incident, 'sourceIp' | 'userId'>): Scope {
  return i.sourceIp ? 'address' : i.userId ? 'account' : 'platform';
}
export const SCOPE_LABEL: Record<Scope, string> = {
  address: 'One address', account: 'One account, many addresses', platform: 'Platform-wide',
};

export const humanize = (s: string) => s.replace(/[._]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/^./, (c) => c.toUpperCase());

/** What happened on an incident's timeline, in plain words. */
export function timelineLabel(action: string): string {
  const map: Record<string, string> = {
    'incident.created': 'Incident opened', created: 'Incident opened',
    'incident.escalated': 'Severity raised', escalated: 'Severity raised',
    'status.changed': 'Status changed', 'incident.status': 'Status changed', status_changed: 'Status changed',
    assigned: 'Assigned', 'incident.assigned': 'Assigned', 'note.added': 'Note added',
    'ip.blocked': 'Address blocked', 'ip.autoblocked': 'Address blocked automatically',
  };
  return map[action] ?? humanize(action);
}

/** Audit log entries as sentences. Anything unknown falls back to a readable form of its code. */
export function auditSummary(a: { action: string; actorLabel: string | null; actorType: string; targetId: string | null; targetType?: string | null; result: string }): string {
  const who = a.actorLabel || (a.actorType === 'SYSTEM' ? 'The system' : 'Someone');
  const target = a.targetId ? ` (${a.targetId})` : '';
  const verbs: Record<string, string> = {
    'auth.login': 'signed in', 'auth.logout': 'signed out', 'auth.refresh': 'refreshed a session',
    'auth.password_change': 'changed a password', 'user.create': 'created an account', 'user.update': 'changed an account',
    'user.password_reset': 'reset an account password', 'api_key.create': 'created an API key', 'api_key.revoke': 'revoked an API key',
    'api_key.rotate': 'replaced an API key', 'incident.update': 'updated an incident', 'incident.assign': 'assigned an incident',
    'incident.note': 'added a note to an incident', 'incident.create': 'opened an incident',
    'ip.block': 'blocked an address', 'ip.unblock': 'unblocked an address', 'ip.allow': 'added an address to the allowlist',
    'ip.unallow': 'removed an address from the allowlist', 'ip.autoblock': 'blocked an address automatically',
    'rule.update': 'changed a detection rule', 'rule.reset': 'reset a detection rule', 'event.ingest': 'sent an event',
  };
  const verb = verbs[a.action] ?? humanize(a.action).toLowerCase();
  return `${who} ${verb}${a.targetType === 'rule' ? ` (${a.targetId})` : target}${a.result === 'FAILURE' ? ' and it did not succeed' : ''}`;
}

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;
export function ageLabel(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never';
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return 'unknown';
  if (ms < 0) return 'just now';
  if (ms < MINUTE) return 'just now';
  if (ms < HOUR) return `${Math.floor(ms / MINUTE)} min ago`;
  if (ms < DAY) return `${Math.floor(ms / HOUR)} h ago`;
  return `${Math.floor(ms / DAY)} d ago`;
}

/** "in 12 min", "in 2 h 5 min", or "expired". For block countdowns. */
export function countdownLabel(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never expires';
  const ms = new Date(iso).getTime() - now;
  if (!Number.isFinite(ms)) return 'unknown';
  if (ms <= 0) return 'expired';
  const m = Math.ceil(ms / MINUTE);
  if (m < 60) return `in ${m} min`;
  if (m < 60 * 24) { const h = Math.floor(m / 60); const r = m % 60; return r ? `in ${h} h ${r} min` : `in ${h} h`; }
  return `in ${Math.floor(m / (60 * 24))} d ${Math.floor((m % (60 * 24)) / 60)} h`;
}

export const displayName = (u: { name?: string | null; email: string } | null | undefined) => (u ? u.name || u.email : 'Unassigned');

export const sevOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
