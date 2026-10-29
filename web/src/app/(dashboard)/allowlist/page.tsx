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
  const [loading, setLoading] = useState(true);

  const load = () =>
    api<{ data: Row[] }>('/security/allow')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    setLoading(true);
    void load().finally(() => setLoading(false));
  }, []);

  async function add(e: FormEvent) {
    e.preventDefault();
    if (!ip.trim() || !reason.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api('/security/allow', {
        method: 'POST',
        json: { ipAddress: ip.trim(), reason: reason.trim() },
      });
      setIp('');
      setReason('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string, address: string) {
    if (!window.confirm(`Remove ${address} from allowlist?`)) return;
    try {
      await api(`/security/allow/${encodeURIComponent(address)}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to remove');
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Allowlist</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Addresses on the allowlist are never auto-blocked and cannot be blocked manually until removed.
        </p>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      <form onSubmit={add} className="surface p-4">
        <div className="mb-3 text-sm font-medium">Allow an IP address</div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[180px] flex-1">
            <label className="mb-1 block text-xs text-[var(--text-secondary)]">IP address</label>
            <input
              className="input mono"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="203.0.113.10"
              required
            />
          </div>
          <div className="min-w-[220px] flex-[2]">
            <label className="mb-1 block text-xs text-[var(--text-secondary)]">Reason</label>
            <input
              className="input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Office network"
              required
            />
          </div>
          <button type="submit" disabled={busy || !ip.trim() || !reason.trim()} className="btn btn-primary">
            {busy ? 'Adding…' : 'Allow IP'}
          </button>
        </div>
      </form>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Reason</th>
              <th>Expires</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-[var(--text-muted)]">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-[var(--text-muted)]">
                  No allowlisted addresses
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.id || r.ipAddress}>
                <td className="mono text-sm font-medium">{r.ipAddress}</td>
                <td className="max-w-[280px] truncate">{r.reason}</td>
                <td className="text-xs text-[var(--text-muted)]">
                  {r.expiresAt ? new Date(r.expiresAt).toLocaleString() : 'Never'}
                </td>
                <td className="text-xs text-[var(--text-muted)]">
                  {new Date(r.createdAt).toLocaleString(undefined, {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </td>
                <td>
                  <button
                    type="button"
                    className="btn btn-ghost text-xs text-[var(--critical)]"
                    onClick={() => remove(r.id, r.ipAddress)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
