'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  ipAddress: string;
  riskScore: number;
  riskLevel: string;
  eventCount: number;
  failedLogins: number;
  lastSeenAt: string | null;
  country: string | null;
};

export default function IpsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ data: Row[] }>('/ips')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Addresses</h1>
      {error && <p className="text-red-600">{error}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">IP</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Level</th>
              <th className="px-3 py-2">Events</th>
              <th className="px-3 py-2">Failed logins</th>
              <th className="px-3 py-2">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.ipAddress} className="border-b last:border-0">
                <td className="px-3 py-2">
                  <Link className="font-mono text-xs text-blue-700 underline" href={`/ips/${encodeURIComponent(r.ipAddress)}`}>
                    {r.ipAddress}
                  </Link>
                </td>
                <td className="px-3 py-2">{r.riskScore}</td>
                <td className="px-3 py-2">{r.riskLevel}</td>
                <td className="px-3 py-2">{r.eventCount}</td>
                <td className="px-3 py-2">{r.failedLogins}</td>
                <td className="px-3 py-2 text-neutral-500">
                  {r.lastSeenAt ? new Date(r.lastSeenAt).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
            {rows.length === 0 && !error && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-neutral-500">
                  No addresses yet. They appear when clients send events.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
