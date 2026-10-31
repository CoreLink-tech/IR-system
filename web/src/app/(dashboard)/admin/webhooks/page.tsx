'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  id: string;
  url: string;
  events: string[];
  isActive: boolean;
  createdAt: string;
};

type Delivery = {
  id: string;
  eventType: string;
  success: boolean;
  attempts: number;
  statusCode: number | null;
  lastError: string | null;
  dead: boolean;
  createdAt: string;
};

export default function WebhooksPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [w, d] = await Promise.all([
      api<{ data: Row[] }>('/webhooks'),
      api<{ data: Delivery[] }>('/webhooks/deliveries').catch(() => ({ data: [] as Delivery[] })),
    ]);
    setRows(w.data || []);
    setDeliveries(d.data || []);
  };

  useEffect(() => {
    void load().catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!url.trim() || busy) return;
    setBusy(true);
    setError(null);
    setSecret(null);
    try {
      const r = await api<{ secret: string }>('/webhooks', {
        method: 'POST',
        json: { url: url.trim(), events: ['incident.created', 'block.created'] },
      });
      setSecret(r.secret);
      setUrl('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    if (!window.confirm('Remove this webhook?')) return;
    try {
      await api(`/webhooks?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  async function redeliver(id: string) {
    setBusy(true);
    try {
      await api(`/webhooks/deliveries/${encodeURIComponent(id)}/redeliver`, { method: 'POST' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Redeliver failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Webhooks</h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          HTTPS only. Signature:{' '}
          <code className="text-xs">HMAC-SHA256(secret, timestamp + &quot;.&quot; + body)</code>
        </p>
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
      {secret && (
        <div className="surface border border-amber-500/40 p-4 text-sm">
          <p className="font-medium">Signing secret (shown once)</p>
          <p className="mt-1 break-all font-mono text-xs">{secret}</p>
        </div>
      )}
      <form onSubmit={create} className="surface flex flex-wrap items-end gap-3 p-4">
        <label className="text-sm">
          HTTPS URL
          <input
            className="mt-1 block w-80 rounded border border-[var(--border)] bg-transparent px-3 py-2"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/hooks/watcher"
          />
        </label>
        <button type="submit" disabled={busy || !url.trim()} className="btn btn-primary text-sm">
          {busy ? 'Adding…' : 'Add webhook'}
        </button>
      </form>
      <div className="surface overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Events</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((w) => (
              <tr key={w.id}>
                <td className="max-w-sm truncate font-mono text-xs">{w.url}</td>
                <td className="text-xs">{(w.events || []).join(', ')}</td>
                <td>{w.isActive ? 'Active' : 'Off'}</td>
                <td>
                  <button type="button" className="text-sm text-red-600 underline" onClick={() => void remove(w.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="p-6 text-center text-sm text-[var(--text-muted)]">
                  No webhooks configured.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="surface overflow-x-auto">
        <div className="border-b border-[var(--border)] px-4 py-3 text-sm font-semibold">Recent deliveries</div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Event</th>
              <th>Status</th>
              <th>Attempts</th>
              <th>Error</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((d) => (
              <tr key={d.id}>
                <td className="text-xs">{d.eventType}</td>
                <td className="text-xs">
                  {d.success ? 'OK' : d.dead ? 'Dead' : 'Pending'}
                  {d.statusCode != null ? ` (${d.statusCode})` : ''}
                </td>
                <td className="text-xs tabular-nums">{d.attempts}</td>
                <td className="max-w-xs truncate text-xs text-[var(--text-muted)]">{d.lastError || '—'}</td>
                <td>
                  {!d.success && (
                    <button
                      type="button"
                      className="text-sm text-[var(--accent)] underline"
                      disabled={busy}
                      onClick={() => void redeliver(d.id)}
                    >
                      Redeliver
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {deliveries.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-center text-sm text-[var(--text-muted)]">
                  No deliveries yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
