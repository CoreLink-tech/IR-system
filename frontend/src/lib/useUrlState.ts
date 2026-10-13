import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Period } from '@/api/hooks';

/** The selected period lives in the address bar, so a page can be shared or reloaded as it was. */
export function usePeriodParam(): [Period, (p: Period) => void] {
  const [sp, setSp] = useSearchParams();
  const from = sp.get('from'), to = sp.get('to'), days = Number(sp.get('days'));
  const period = useMemo<Period>(() => {
    if (from && to && !Number.isNaN(Date.parse(from)) && !Number.isNaN(Date.parse(to))) return { from, to };
    return { days: [1, 7, 30].includes(days) ? days : 7 };
  }, [from, to, days]);
  const set = useCallback((p: Period) => {
    setSp((prev) => {
      const n = new URLSearchParams(prev);
      n.delete('days'); n.delete('from'); n.delete('to');
      if (p.from && p.to) { n.set('from', p.from); n.set('to', p.to); } else n.set('days', String(p.days ?? 7));
      return n;
    }, { replace: true });
  }, [setSp]);
  return [period, set];
}

/** Filters and paging kept in the URL. Empty values are removed so links stay short. */
export function useParams2<T extends Record<string, string>>(defaults: T): [T, (patch: Partial<T>, resetPage?: boolean) => void] {
  const [sp, setSp] = useSearchParams();
  const value = useMemo(() => {
    const out: Record<string, string> = { ...defaults };
    for (const k of Object.keys(defaults)) { const v = sp.get(k); if (v !== null) out[k] = v; }
    return out as T;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);
  const set = useCallback((patch: Partial<T>, resetPage = true) => {
    setSp((prev) => {
      const n = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) { if (v === undefined || v === '' || v === (defaults as any)[k]) n.delete(k); else n.set(k, String(v)); }
      if (resetPage && !('page' in patch)) n.delete('page');
      return n;
    }, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setSp]);
  return [value, set];
}
