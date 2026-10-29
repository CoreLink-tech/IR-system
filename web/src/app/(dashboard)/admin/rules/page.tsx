'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Rule = {
  code: string;
  title: string;
  description: string;
  isEnabled: boolean;
  config: Record<string, number>;
  limits: Record<string, { min: number; max: number }>;
};

export default function RulesPage() {
  const [rows, setRows] = useState<Rule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () =>
    api<{ data: Rule[] }>('/rules')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    setLoading(true);
    void load().finally(() => setLoading(false));
  }, []);

  async function toggle(code: string, isEnabled: boolean) {
    setBusy(code);
    setError(null);
    try {
      await api(`/rules/${code}`, { method: 'PATCH', json: { isEnabled } });
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <div className="kicker">Administration</div>
        <h1 className="text-[22px] font-[750] tracking-[-0.5px]">Detection rules</h1>
        <p className="mt-1 text-[13px] text-[#718079]">
          Control how events are scored and when automatic blocks happen. Changes apply to new events only.
        </p>
      </div>
      {error && (
        <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-4 py-3 text-[12px] text-[#a13a3a]">{error}</div>
      )}
      {loading && <div className="text-[13px] text-[#718079]">Loading rules…</div>}
      <div className="space-y-3">
        {rows.map((r) => (
          <div key={r.code} className="surface p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <h2 className="text-[14px] font-[750]">{r.title}</h2>
                <p className="mt-1 text-[12px] text-[#5f6f67]">{r.description}</p>
                <p className="mt-1 mono text-[10px] text-[#8a9690]">{r.code}</p>
                <p className="mt-1 text-[10px] text-[#8a9690]">
                  Config: {Object.entries(r.config).map(([k, v]) => `${k}=${v}`).join(', ')}
                </p>
              </div>
              <button
                type="button"
                disabled={busy === r.code}
                className={`btn text-[11px] ${r.isEnabled ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => void toggle(r.code, !r.isEnabled)}
              >
                {busy === r.code ? '…' : r.isEnabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
