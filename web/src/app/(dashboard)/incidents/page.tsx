'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Incident = {
  id: string;
  publicNumber: number;
  title: string;
  status: string;
  severity: string;
  sourceIp: string | null;
  riskScore: number;
  eventCount: number;
  createdAt: string;
};

export default function IncidentsPage() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ data: Incident[] }>('/incidents?pageSize=50')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed to load'));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Incidents</h1>
      {error && <p className="text-red-600">{error}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">#</th>
              <th className="px-3 py-2">Title</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">IP</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Events</th>
              <th className="px-3 py-2">Opened</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono text-xs">{r.publicNumber}</td>
                <td className="px-3 py-2">{r.title}</td>
                <td className="px-3 py-2">{r.status}</td>
                <td className="px-3 py-2">{r.severity}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.sourceIp || '—'}</td>
                <td className="px-3 py-2">{r.riskScore}</td>
                <td className="px-3 py-2">{r.eventCount}</td>
                <td className="px-3 py-2 text-neutral-500">{new Date(r.createdAt).toLocaleString()}</td>
              </tr>
            ))}
            {rows.length === 0 && !error && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-neutral-500">
                  No incidents yet. Send events from a client site with an API key.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
