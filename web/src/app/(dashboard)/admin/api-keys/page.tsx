'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type KeyRow = {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string;
  isActive: boolean;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
};

export default function ApiKeysPage() {
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [name, setName] = useState('');
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api<{ data: KeyRow[] }>('/api-keys')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    setCreated(null);
    try {
      const r = await api<{ apiKey: string }>('/api-keys', {
        method: 'POST',
        json: { name: name.trim(), scopes: ['events:write', 'block:read'] },
      });
      setCreated(r.apiKey);
      setName('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm('Revoke this API key? Client sites using it will stop working.')) return;
    try {
      await api(`/api-keys/${id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">API keys</h1>
      <p className="text-sm text-neutral-600">
        Give each client website a key. They send events and poll the blocklist with{' '}
        <code className="rounded bg-neutral-100 px-1">Authorization: Bearer IRS_…</code>
      </p>
      {error && <p className="text-red-600">{error}</p>}
      {created && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm">
          <p className="font-medium">Copy this key now — it is shown only once.</p>
          <p className="mt-2 break-all font-mono">{created}</p>
          <button type="button" className="mt-2 text-blue-700 underline" onClick={() => void navigator.clipboard.writeText(created)}>
            Copy
          </button>
        </div>
      )}
      <form onSubmit={create} className="flex flex-wrap items-end gap-3 rounded-lg border bg-white p-4">
        <label className="text-sm">
          Name
          <input className="mt-1 block rounded border px-3 py-2" value={name} onChange={(e) => setName(e.target.value)} placeholder="Production shop" />
        </label>
        <button type="submit" disabled={busy || !name.trim()} className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50">
          {busy ? 'Creating…' : 'Create key'}
        </button>
      </form>
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Prefix</th>
              <th className="px-3 py-2">Scopes</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Last used</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((k) => (
              <tr key={k.id} className="border-b last:border-0">
                <td className="px-3 py-2">{k.name}</td>
                <td className="px-3 py-2 font-mono text-xs">{k.keyPrefix}…</td>
                <td className="px-3 py-2 text-xs">{k.scopes}</td>
                <td className="px-3 py-2">{k.isActive && !k.revokedAt ? 'Active' : 'Revoked'}</td>
                <td className="px-3 py-2 text-neutral-500">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'never'}</td>
                <td className="px-3 py-2">
                  {k.isActive && !k.revokedAt && (
                    <button type="button" className="text-red-700 underline" onClick={() => void revoke(k.id)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
