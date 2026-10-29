'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type UserRow = {
  id: string;
  email: string;
  name: string | null;
  role: string;
  isActive: boolean;
  twoFactorEnabled: boolean;
  lastLoginAt: string | null;
};

export default function AdminUsersPage() {
  const [rows, setRows] = useState<UserRow[]>([]);
  const [meId, setMeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () =>
    Promise.all([
      api<{ data: UserRow[] }>('/auth/users'),
      api<{ user: { id: string } }>('/auth/me'),
    ])
      .then(([u, me]) => {
        setRows(u.data || []);
        setMeId(me.user.id);
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed to load'));

  useEffect(() => {
    setLoading(true);
    void load().finally(() => setLoading(false));
  }, []);

  async function unlock(id: string, email: string) {
    setError(null);
    try {
      await api(`/auth/users/${id}/unlock`, { method: 'POST', json: {} });
      setDone(`Lockout cleared for ${email}.`);
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    }
  }

  async function reset2fa(id: string, email: string) {
    if (!window.confirm(`Reset two-step verification for ${email}? All their sessions will end.`)) return;
    setError(null);
    try {
      const r = await api<{ mustEnrolAtNextSignIn?: boolean }>(`/auth/users/${id}/2fa/reset`, {
        method: 'POST',
        json: {},
      });
      setDone(
        r.mustEnrolAtNextSignIn
          ? `Two-step reset for ${email}. They must enrol again at next sign-in.`
          : `Two-step reset for ${email}.`,
      );
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Users</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Super admin only. Manage platform operators and security analysts.
        </p>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}
      {done && (
        <div className="rounded-[var(--radius)] border border-[var(--success)]/30 bg-[var(--success-muted)] px-4 py-3 text-sm text-[var(--success)]">
          {done}
        </div>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>2FA</th>
              <th>Last login</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">Loading…</td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">No users</td>
              </tr>
            )}
            {rows.map((u) => (
              <tr key={u.id}>
                <td className="font-medium">{u.email}</td>
                <td className="text-[var(--text-secondary)]">{u.name || '—'}</td>
                <td>
                  <span className="badge badge-neutral">{u.role.replace('_', ' ')}</span>
                </td>
                <td>
                  {u.isActive ? (
                    <span className="badge badge-low">Active</span>
                  ) : (
                    <span className="badge badge-critical">Disabled</span>
                  )}
                </td>
                <td>
                  {u.twoFactorEnabled ? (
                    <span className="badge badge-info">Enabled</span>
                  ) : (
                    <span className="badge badge-neutral">Off</span>
                  )}
                </td>
                <td className="text-xs text-[var(--text-muted)]">
                  {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never'}
                </td>
                <td>
                  <div className="flex gap-1">
                    <button
                      type="button"
                      className="btn btn-ghost text-xs"
                      onClick={() => void unlock(u.id, u.email)}
                    >
                      Unlock
                    </button>
                    {u.id !== meId && (
                      <button
                        type="button"
                        className="btn btn-ghost text-xs"
                        onClick={() => void reset2fa(u.id, u.email)}
                      >
                        Reset 2FA
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
