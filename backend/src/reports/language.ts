/** Small, dependency-free helpers for producing readable English. */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const pad = (n: number) => String(n).padStart(2, '0');

export function timeUtc(d: Date): string {
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

export function dateUtc(d: Date): string {
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** "2 Oct 2026, 14:02 UTC" */
export function formatUtc(d: Date): string {
  return `${dateUtc(d)}, ${timeUtc(d)} UTC`;
}

export function sameUtcDay(a: Date, b: Date): boolean {
  return dateUtc(a) === dateUtc(b);
}

/** Describes a period of activity: "between 14:02 and 14:09 UTC on 2 Oct 2026". */
export function describeSpan(first: Date | null, last: Date | null): string {
  if (!first || !last) return 'during the monitored period';
  if (timeUtc(first) === timeUtc(last) && sameUtcDay(first, last)) {
    return `at ${timeUtc(first)} UTC on ${dateUtc(first)}`;
  }
  if (sameUtcDay(first, last)) {
    return `between ${timeUtc(first)} and ${timeUtc(last)} UTC on ${dateUtc(first)}`;
  }
  return `between ${formatUtc(first)} and ${formatUtc(last)}`;
}

export function plural(n: number, one: string, many?: string): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many ?? one + 's'}`;
}

export function humanDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return 'less than a minute';
  const m = Math.round(s / 60);
  if (m < 60) return m === 1 ? '1 minute' : `${m} minutes`;
  const h = Math.round(m / 60);
  if (h < 48) return h === 1 ? '1 hour' : `${h} hours`;
  const d = Math.round(h / 24);
  return `${d} days`;
}

/** ["a","b","c"] -> "a, b and c" */
export function joinList(items: string[]): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

export function capitalize(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

const SEVERITY_WORDS: Record<string, string> = {
  INFO: 'Informational', LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High', CRITICAL: 'Critical',
};
export function severityWord(s: string): string {
  return SEVERITY_WORDS[s] ?? capitalize(s.toLowerCase());
}

/** Removes the query string so tokens or personal data in URLs never reach a report. */
export function stripQuery(path: string): string {
  const i = path.search(/[?#]/);
  const p = i >= 0 ? path.slice(0, i) : path;
  return p.length > 120 ? `${p.slice(0, 117)}...` : p;
}
