'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  id: string;
  source: string;
  severity: string | null;
  message: string;
  ipAddress: string | null;
  path: string | null;
  method: string | null;
  statusCode: number | null;
  createdAt: string;
};

export default function LogsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');

  useEffect(() => {
    api<{ data: Row[] }>('/logs?pageSize=100')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed to load logs'));
  }, []);

  const filtered = q
    ? rows.filter(
        (r) =>
          r.message.toLowerCase().includes(q.toLowerCase()) ||
          (r.ipAddress || '').includes(q) ||
          (r.path || '').toLowerCase().includes(q.toLowerCase()),
      )
    : rows;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Server logs</h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Phase 1 MVP — POST NDJSON/JSON to <code className="text-xs">/api/v1/logs</code> with an API key. Pilot
          retention is 7 days on Turso.
        </p>
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
      <input
        className="w-full max-w-md rounded border border-[var(--border)] bg-transparent px-3 py-2 text-sm"
        placeholder="Filter message, IP, path…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
      />
      <div className="surface overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Message</th>
              <th>IP</th>
              <th>Path</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap text-xs text-[var(--text-muted)]">
                  {new Date(r.createdAt).toLocaleString()}
                </td>
                <td className="text-xs">{r.source}</td>
                <td className="max-w-md truncate text-sm" title={r.message}>
                  {r.message}
                </td>
                <td className="font-mono text-xs">{r.ipAddress || '—'}</td>
                <td className="font-mono text-xs">
                  {r.method ? `${r.method} ` : ''}
                  {r.path || '—'}
                  {r.statusCode != null ? ` · ${r.statusCode}` : ''}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-center text-sm text-[var(--text-muted)]">
                  No log lines yet. Ship JSON from your storefront or log shipper.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
