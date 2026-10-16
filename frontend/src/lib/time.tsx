import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

export type TimeMode = 'local' | 'utc';
const KEY = 'ir-time-mode';

const Ctx = createContext<{ mode: TimeMode; toggle: () => void }>({ mode: 'local', toggle: () => {} });

export function TimeProvider({ children, initial }: { children: ReactNode; initial?: TimeMode }) {
  const [mode, setMode] = useState<TimeMode>(() => {
    if (initial) return initial;
    try { return localStorage.getItem(KEY) === 'utc' ? 'utc' : 'local'; } catch { return 'local'; }
  });
  const toggle = useCallback(() => setMode((m) => {
    const next = m === 'local' ? 'utc' : 'local';
    try { localStorage.setItem(KEY, next); } catch { /* preference only */ }
    return next;
  }), []);
  const value = useMemo(() => ({ mode, toggle }), [mode, toggle]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useTimeMode = () => useContext(Ctx);

export function formatTime(iso: string | null | undefined, mode: TimeMode): string {
  if (!iso) return 'never';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'unknown';
  const opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, ...(mode === 'utc' ? { timeZone: 'UTC' } : {}) };
  return `${new Intl.DateTimeFormat('en-GB', opts).format(d)}${mode === 'utc' ? ' UTC' : ''}`;
}

export const utcString = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
};

/** A time in the person's zone (or UTC when toggled). The UTC time is always in the tooltip. */
export function Time({ value }: { value: string | null | undefined }) {
  const { mode } = useTimeMode();
  if (!value) return <span>never</span>;
  return <time dateTime={value} title={utcString(value) || undefined}>{formatTime(value, mode)}</time>;
}
