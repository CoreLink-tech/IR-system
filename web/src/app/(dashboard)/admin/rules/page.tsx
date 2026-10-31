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

type Sim = {
  rule: string;
  hours: number;
  windowMinutes: number;
  threshold: number;
  loginFailedEvents: number;
  distinctIps: number;
  ipsThatWouldMatch: number;
  sampleIps: string[];
  note: string;
};

export default function RulesPage() {
  const [rows, setRows] = useState<Rule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sim, setSim] = useState<Sim | null>(null);
  const [simBusy, setSimBusy] = useState(false);

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

  async function saveConfig(code: string, config: Record<string, number>) {
    setBusy(code);
    setError(null);
    try {
      await api(`/rules/${code}`, { method: 'PATCH', json: { config } });
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    } finally {
      setBusy(null);
    }
  }

  async function runSimulate() {
    setSimBusy(true);
    setError(null);
    try {
      const r = await api<Sim>('/rules/simulate', { method: 'POST', json: { hours: 24 } });
      setSim(r);
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Simulate failed');
    } finally {
      setSimBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <div className="kicker">Administration</div>
        <h1 className="text-[22px] font-[750] tracking-[-0.5px]">Detection rules</h1>
        <p className="mt-1 text-[13px] text-[#718079]">
          Phase 2 includes velocity and log-derived bonuses. Changes apply to new events only.
        </p>
      </div>
      {error && (
        <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-4 py-3 text-[12px] text-[#a13a3a]">{error}</div>
      )}

      <div className="surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-[14px] font-[750]">Simulate brute_force (24h)</h2>
            <p className="mt-1 text-[12px] text-[#5f6f67]">Read-only backtest against stored login_failed events.</p>
          </div>
          <button type="button" className="btn btn-secondary text-[11px]" disabled={simBusy} onClick={() => void runSimulate()}>
            {simBusy ? 'Running…' : 'Run simulation'}
          </button>
        </div>
        {sim && (
          <div className="mt-3 grid gap-2 text-[12px] text-[#5f6f67] sm:grid-cols-3">
            <div>Events: <strong className="text-[var(--text)]">{sim.loginFailedEvents}</strong></div>
            <div>IPs: <strong className="text-[var(--text)]">{sim.distinctIps}</strong></div>
            <div>Would match: <strong className="text-[var(--text)]">{sim.ipsThatWouldMatch}</strong></div>
            {sim.sampleIps?.length > 0 && (
              <div className="sm:col-span-3 mono text-[10px]">Sample: {sim.sampleIps.join(', ')}</div>
            )}
          </div>
        )}
      </div>

      {loading && <div className="text-[13px] text-[#718079]">Loading rules…</div>}
      <div className="space-y-3">
        {rows.map((r) => (
          <div key={r.code} className="surface p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <h2 className="text-[14px] font-[750]">{r.title}</h2>
                <p className="mt-1 text-[12px] text-[#5f6f67]">{r.description}</p>
                <p className="mt-1 mono text-[10px] text-[#8a9690]">{r.code}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(r.config).map(([k, v]) => (
                    <label key={k} className="text-[10px] text-[#8a9690]">
                      {k}
                      <input
                        type="number"
                        className="ml-1 w-16 rounded border border-[var(--border)] bg-transparent px-1 py-0.5 text-[11px] text-[var(--text)]"
                        defaultValue={v}
                        min={r.limits[k]?.min}
                        max={r.limits[k]?.max}
                        onBlur={(e) => {
                          const n = Number(e.target.value);
                          if (Number.isFinite(n) && n !== v) {
                            void saveConfig(r.code, { ...r.config, [k]: n });
                          }
                        }}
                      />
                    </label>
                  ))}
                </div>
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
