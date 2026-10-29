'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  id: string;
  actorType: string;
  actorLabel: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  result: string;
  ipAddress: string | null;
  createdAt: string;
};

export default function AuditPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api<{ data: Row[] }>('/audit?pageSize=100')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-4">
      <div>
        <div className="kicker">Administration</div>
        <h1 className="text-[22px] font-[750] tracking-[-0.5px]">Audit log</h1>
        <p className="mt-1 text-[13px] text-[#718079]">Administrative actions across the workspace.</p>
      </div>
      {error && (
        <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-4 py-3 text-[12px] text-[#a13a3a]">{error}</div>
      )}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Result</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="py-8 text-center text-[#718079]">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={6} className="py-8 text-center text-[#718079]">No audit entries yet.</td></tr>
            )}
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap text-[#718079]">{new Date(r.createdAt).toLocaleString()}</td>
                <td>{r.actorLabel || r.actorType}</td>
                <td className="mono text-[11px]">{r.action}</td>
                <td className="text-[11px] text-[#5f6f67]">
                  {r.targetType}{r.targetId ? `:${r.targetId.slice(0, 8)}` : ''}
                </td>
                <td>
                  <span className={r.result === 'SUCCESS' ? 'badge badge-low' : 'badge badge-critical'}>
                    {r.result}
                  </span>
                </td>
                <td className="mono text-[11px]">{r.ipAddress || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
