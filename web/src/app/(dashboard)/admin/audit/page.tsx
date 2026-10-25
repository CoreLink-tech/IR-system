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

  useEffect(() => {
    api<{ data: Row[] }>('/audit?pageSize=100')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Audit log</h1>
      <p className="text-sm text-neutral-600">Administrative actions. Viewers cannot open this page.</p>
      {error && <p className="text-red-600">{error}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">When</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Target</th>
              <th className="px-3 py-2">Result</th>
              <th className="px-3 py-2">IP</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b last:border-0">
                <td className="px-3 py-2 text-neutral-500 whitespace-nowrap">{new Date(r.createdAt).toLocaleString()}</td>
                <td className="px-3 py-2">{r.actorLabel || r.actorType}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.action}</td>
                <td className="px-3 py-2 text-xs">{r.targetType}{r.targetId ? `:${r.targetId.slice(0, 8)}` : ''}</td>
                <td className="px-3 py-2">{r.result}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.ipAddress || '—'}</td>
              </tr>
            ))}
            {rows.length === 0 && !error && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-neutral-500">No audit entries yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
