'use client';

import { useEffect, useState } from 'react';
import { getAccessToken } from '@/lib/client-api';

type Block = {
  ipAddress: string;
  reason: string;
  expiresAt: string | null;
  permanent: boolean;
  automatic: boolean;
  createdAt: string;
};

export default function BlockingPage() {
  const [rows, setRows] = useState<Block[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getAccessToken();
    fetch('/api/v1/security/blocked-ips', {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      credentials: 'include',
    })
      .then(async (r) => {
        const body = await r.json();
        if (!r.ok) throw new Error(body.message || 'Failed');
        setRows(body.data || []);
      })
      .catch((e) => setError(String(e.message || e)));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Active blocks</h1>
      <p className="text-sm text-neutral-600">
        Client sites should poll <code className="rounded bg-neutral-100 px-1">GET /api/v1/security/blocked-ips</code>{' '}
        and refuse traffic from these addresses.
      </p>
      {error && <p className="text-red-600">{error}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Expires</th>
              <th className="px-3 py-2">Source</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.ipAddress + r.createdAt} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono text-xs">{r.ipAddress}</td>
                <td className="px-3 py-2">{r.reason}</td>
                <td className="px-3 py-2">{r.permanent ? 'Permanent' : r.expiresAt ? new Date(r.expiresAt).toLocaleString() : '—'}</td>
                <td className="px-3 py-2">{r.automatic ? 'Automatic' : 'Manual'}</td>
              </tr>
            ))}
            {rows.length === 0 && !error && (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-neutral-500">
                  No active blocks.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
