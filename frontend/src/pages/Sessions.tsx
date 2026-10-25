import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { SessionRow } from '@/api/types';
import { describeError } from '@/api/errors';
import { Notice, Skeleton } from '@/components/ui';

async function listSessions(): Promise<SessionRow[]> {
  const r = await api.get<{ data: SessionRow[] }>('/auth/sessions');
  return r.data;
}

export default function SessionsPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['sessions'], queryFn: listSessions });
  const revokeOne = useMutation({
    mutationFn: (id: string) => api.delete(`/auth/sessions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  });
  const revokeAll = useMutation({
    mutationFn: () => api.post('/auth/sessions/revoke-all', {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  });

  if (q.isLoading) return <main><Skeleton lines={6} /></main>;
  if (q.isError) return <main><Notice title="Could not load sessions"><p>{describeError(q.error).body}</p></Notice></main>;

  const rows = q.data || [];

  return (
    <main>
      <div className="stack">
        <h1>Your sessions</h1>
        <p className="muted">Each sign-in is a session. Ending one stops that device from refreshing; ending all signs you out everywhere, including this device.</p>
        <Notice title="Sign out everywhere">
          <p style={{ margin: '.3rem 0 .75rem' }}>This ends every session on your account, including the one you are using now.</p>
          <button
            type="button"
            className="btn danger"
            disabled={revokeAll.isPending}
            onClick={() => {
              if (window.confirm('Sign out on every device, including this one?')) revokeAll.mutate();
            }}
          >
            {revokeAll.isPending ? 'Signing out...' : 'Sign out everywhere'}
          </button>
        </Notice>
        <div className="card" style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Address</th>
                <th>Started</th>
                <th>Last used</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id}>
                  <td>{s.device || 'Unknown'}{s.current ? ' (this device)' : ''}</td>
                  <td>{s.ipAddress || '—'}</td>
                  <td>{new Date(s.createdAt).toLocaleString()}</td>
                  <td>{s.lastUsedAt ? new Date(s.lastUsedAt).toLocaleString() : '—'}</td>
                  <td>
                    {!s.current && (
                      <button
                        type="button"
                        className="btn"
                        disabled={revokeOne.isPending}
                        onClick={() => revokeOne.mutate(s.id)}
                      >
                        End
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={5}>No active sessions.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
