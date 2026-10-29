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
  const [loading, setLoading] = useState(true);

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
    setLoading(true);
    void load().finally(() => setLoading(false));
  }, []);

  async function block(e: FormEvent) {
    e.preventDefault();
    if (!ip.trim() || !reason.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api('/security/block', {
        method: 'POST',
        json: { ipAddress: ip.trim(), reason: reason.trim() },
      });
      setIp('');
      setReason('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to block');
    } finally {
      setBusy(false);
    }
  }

  async function unblock(address: string) {
    if (!window.confirm(`Unblock ${address}?`)) return;
    try {
      await api('/security/unblock', {
        method: 'POST',
        json: { ipAddress: address, reason: 'Manual unblock' },
      });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to unblock');
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Blocklist</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Client sites poll the blocklist and enforce these addresses locally.
        </p>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      {/* Add form */}
      <form onSubmit={block} className="surface p-4">
        <div className="mb-3 text-sm font-medium">Block an IP address</div>
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
              placeholder="Brute force attempts"
              required
            />
          </div>
          <button type="submit" disabled={busy || !ip.trim() || !reason.trim()} className="btn btn-primary">
            {busy ? 'Blocking…' : 'Block IP'}
          </button>
        </div>
      </form>

      {/* Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Reason</th>
              <th>Type</th>
              <th>Expires</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-[var(--text-muted)]">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-[var(--text-muted)]">
                  No blocked addresses
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.ipAddress}>
                <td className="mono text-sm font-medium">{r.ipAddress}</td>
                <td className="max-w-[240px] truncate">{r.reason}</td>
                <td>
                  <span className={r.automatic ? 'badge badge-info' : 'badge badge-neutral'}>
                    {r.automatic ? 'Automatic' : 'Manual'}
                  </span>
                  {r.permanent && <span className="badge badge-high ml-1">Permanent</span>}
                </td>
                <td className="text-xs text-[var(--text-muted)]">
                  {r.permanent ? 'Never' : r.expiresAt ? new Date(r.expiresAt).toLocaleString() : '—'}
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
                    onClick={() => unblock(r.ipAddress)}
                  >
                    Unblock
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
