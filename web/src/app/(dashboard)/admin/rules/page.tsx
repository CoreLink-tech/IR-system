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

  const load = () =>
    api<{ data: Rule[] }>('/rules')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
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
      <h1 className="text-2xl font-semibold">Detection rules</h1>
      <p className="text-sm text-neutral-600">
        These control how events are scored and when automatic blocks happen. Changes apply to new events only.
      </p>
      {error && <p className="text-red-600">{error}</p>}
      <div className="space-y-3">
        {rows.map((r) => (
          <div key={r.code} className="rounded-lg border bg-white p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="font-medium">{r.title}</h2>
                <p className="text-sm text-neutral-600">{r.description}</p>
                <p className="mt-1 font-mono text-xs text-neutral-500">{r.code}</p>
                <p className="mt-1 text-xs text-neutral-500">
                  Config: {Object.entries(r.config).map(([k, v]) => `${k}=${v}`).join(', ')}
                </p>
              </div>
              <button
                type="button"
                disabled={busy === r.code}
                className={`rounded px-3 py-1.5 text-sm ${r.isEnabled ? 'bg-green-600 text-white' : 'border bg-neutral-100'}`}
                onClick={() => void toggle(r.code, !r.isEnabled)}
              >
                {r.isEnabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
