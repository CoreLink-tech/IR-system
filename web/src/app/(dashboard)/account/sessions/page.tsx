'use client';

import { useEffect, useState } from 'react';
import { api, ApiError, setAccessToken } from '@/lib/client-api';
import { useRouter } from 'next/navigation';

type SessionRow = {
  id: string;
  device: string | null;
  ipAddress: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
  current?: boolean;
};

export default function SessionsPage() {
  const router = useRouter();
  const [rows, setRows] = useState<SessionRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    api<{ data: SessionRow[] }>('/auth/sessions')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Your sessions</h1>
      {error && <p className="text-red-600">{error}</p>}
      <button
        type="button"
        className="rounded bg-red-600 px-3 py-2 text-sm text-white"
        onClick={async () => {
          if (!window.confirm('Sign out on every device, including this one?')) return;
          await api('/auth/sessions/revoke-all', { method: 'POST', json: {} });
          setAccessToken(null);
          sessionStorage.removeItem('ir_at');
          router.replace('/sign-in');
        }}
      >
        Sign out everywhere
      </button>
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Device</th>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Started</th>
              <th className="px-3 py-2">Last used</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} className="border-b last:border-0">
                <td className="px-3 py-2">{s.device || 'Unknown'}{s.current ? ' (this device)' : ''}</td>
                <td className="px-3 py-2 font-mono text-xs">{s.ipAddress || '—'}</td>
                <td className="px-3 py-2">{new Date(s.createdAt).toLocaleString()}</td>
                <td className="px-3 py-2">{s.lastUsedAt ? new Date(s.lastUsedAt).toLocaleString() : '—'}</td>
                <td className="px-3 py-2">
                  {!s.current && (
                    <button
                      type="button"
                      className="text-blue-700 underline"
                      onClick={async () => {
                        await api(`/auth/sessions?id=${encodeURIComponent(s.id)}`, { method: 'DELETE' });
                        await load();
                      }}
                    >
                      End
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
