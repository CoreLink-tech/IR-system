'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  id: string;
  ipAddress: string;
  reason: string;
  expiresAt: string | null;
  createdAt: string;
};

export default function AllowlistPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api<{ data: Row[] }>('/security/allow')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
  }, []);

  async function add(e: FormEvent) {
    e.preventDefault();
    if (!ip.trim() || !reason.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api('/security/allow', { method: 'POST', json: { ipAddress: ip.trim(), reason: reason.trim() } });
      setIp('');
      setReason('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Allowlist</h1>
      <p className="text-sm text-neutral-600">
        Addresses on the allowlist are never auto-blocked and cannot be blocked manually until removed.
      </p>
      {error && <p className="text-red-600">{error}</p>}
      <form onSubmit={add} className="flex flex-wrap items-end gap-3 rounded-lg border bg-white p-4">
        <label className="text-sm">
          IP address
          <input className="mt-1 block rounded border px-3 py-2 font-mono" value={ip} onChange={(e) => setIp(e.target.value)} />
        </label>
        <label className="text-sm">
          Reason
          <input className="mt-1 block w-64 rounded border px-3 py-2" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <button type="submit" disabled={busy || !ip.trim() || !reason.trim()} className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50">
          {busy ? 'Adding…' : 'Add'}
        </button>
      </form>
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Expires</th>
              <th className="px-3 py-2">Added</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono text-xs">{r.ipAddress}</td>
                <td className="px-3 py-2">{r.reason}</td>
                <td className="px-3 py-2">{r.expiresAt ? new Date(r.expiresAt).toLocaleString() : 'Never'}</td>
                <td className="px-3 py-2 text-neutral-500">{new Date(r.createdAt).toLocaleString()}</td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    className="text-red-700 underline"
                    onClick={async () => {
                      if (!window.confirm(`Remove ${r.ipAddress} from allowlist?`)) return;
                      await api(`/security/allow/${encodeURIComponent(r.ipAddress)}`, { method: 'DELETE' });
                      await load();
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-neutral-500">Allowlist is empty.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
