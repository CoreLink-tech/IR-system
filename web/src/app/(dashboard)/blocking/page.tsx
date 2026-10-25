'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError, getAccessToken } from '@/lib/client-api';

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
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const load = () => {
    const token = getAccessToken();
    return fetch('/api/v1/security/blocked-ips', {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      credentials: 'include',
    })
      .then(async (r) => {
        const body = await r.json();
        if (!r.ok) throw new Error(body.message || 'Failed');
        setRows(body.data || []);
      })
      .catch((e) => setError(String(e.message || e)));
  };

  useEffect(() => {
    void load();
  }, []);

  async function block(e: FormEvent) {
    e.preventDefault();
    if (!ip.trim() || !reason.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api('/security/block', { method: 'POST', json: { ipAddress: ip.trim(), reason: reason.trim() } });
      setIp('');
      setReason('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function unblock(address: string) {
    if (!window.confirm(`Unblock ${address}?`)) return;
    try {
      await api('/security/unblock', { method: 'POST', json: { ipAddress: address, reason: 'Manual unblock' } });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Blocking</h1>
      <p className="text-sm text-neutral-600">
        Client sites poll <code className="rounded bg-neutral-100 px-1">GET /api/v1/security/blocked-ips</code> and
        enforce these addresses locally.
      </p>
      {error && <p className="text-red-600">{error}</p>}
      <form onSubmit={block} className="flex flex-wrap items-end gap-3 rounded-lg border bg-white p-4">
        <label className="text-sm">
          IP address
          <input className="mt-1 block rounded border px-3 py-2 font-mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.10" />
        </label>
        <label className="text-sm">
          Reason
          <input className="mt-1 block w-64 rounded border px-3 py-2" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Brute force" />
        </label>
        <button type="submit" disabled={busy || !ip.trim() || !reason.trim()} className="rounded bg-red-600 px-4 py-2 text-white disabled:opacity-50">
          {busy ? 'Blocking…' : 'Block'}
        </button>
      </form>
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Reason</th>
              <th className="px-3 py-2">Expires</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.ipAddress + r.createdAt} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono text-xs">{r.ipAddress}</td>
                <td className="px-3 py-2">{r.reason}</td>
                <td className="px-3 py-2">
                  {r.permanent ? 'Permanent' : r.expiresAt ? new Date(r.expiresAt).toLocaleString() : '—'}
                </td>
                <td className="px-3 py-2">{r.automatic ? 'Automatic' : 'Manual'}</td>
                <td className="px-3 py-2">
                  <button type="button" className="text-blue-700 underline" onClick={() => void unblock(r.ipAddress)}>
                    Unblock
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && !error && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-neutral-500">
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
