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

const roles = ['SUPER_ADMIN', 'SECURITY_ADMIN'] as const;

export default function AdminUsersPage() {
  const [rows, setRows] = useState<UserRow[]>([]);
  const [meId, setMeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<(typeof roles)[number]>('SECURITY_ADMIN');

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

  async function createUser(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setDone(null);
    setCreating(true);
    try {
      const result = await api<{ data: { email: string } }>('/auth/users', {
        method: 'POST',
        json: { email, name: name || undefined, password, role },
      });
      setDone(`Account created for ${result.data.email}. They must change their password at first sign-in.`);
      setEmail('');
      setName('');
      setPassword('');
      setRole('SECURITY_ADMIN');
      setCreateOpen(false);
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed to create user');
    } finally {
      setCreating(false);
    }
  }

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
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Users</h1>
          <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
            Super admin only. Manage platform operators and security analysts.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary text-sm"
          onClick={() => {
            setError(null);
            setDone(null);
            setCreateOpen(true);
          }}
        >
          Create user
        </button>
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

      {createOpen && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center overflow-y-auto bg-black/70 p-4"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !creating) setCreateOpen(false);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-user-title"
            className="w-full max-w-lg rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-sidebar)] p-5 shadow-2xl"
          >
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <h2 id="create-user-title" className="text-lg font-semibold tracking-tight">Create user</h2>
                <p className="mt-1 text-sm text-[var(--text-muted)]">New users must change this password after signing in.</p>
              </div>
              <button
                type="button"
                className="btn btn-ghost px-2 py-1 text-sm"
                aria-label="Close create user form"
                disabled={creating}
                onClick={() => setCreateOpen(false)}
              >
                ✕
              </button>
            </div>
            <form className="space-y-4" onSubmit={createUser}>
              <label className="block space-y-1.5 text-sm">
                <span className="text-[var(--text-secondary)]">Email</span>
                <input
                  className="w-full rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-base)] px-3 py-2 text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
                  type="email"
                  autoComplete="off"
                  required
                  maxLength={254}
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              </label>
              <label className="block space-y-1.5 text-sm">
                <span className="text-[var(--text-secondary)]">Name <span className="text-[var(--text-muted)]">(optional)</span></span>
                <input
                  className="w-full rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-base)] px-3 py-2 text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
                  type="text"
                  autoComplete="off"
                  maxLength={120}
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                />
              </label>
              <label className="block space-y-1.5 text-sm">
                <span className="text-[var(--text-secondary)]">Password</span>
                <div className="flex gap-2">
                  <input
                    className="min-w-0 flex-1 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-base)] px-3 py-2 text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-ghost text-xs"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    onClick={() => setShowPassword((visible) => !visible)}
                  >
                    {showPassword ? 'Hide' : 'Show'}
                  </button>
                </div>
                <span className="block text-xs text-[var(--text-muted)]">At least 6 characters, with uppercase, lowercase, and a number.</span>
              </label>
              <label className="block space-y-1.5 text-sm">
                <span className="text-[var(--text-secondary)]">Role</span>
                <select
                  className="w-full rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-base)] px-3 py-2 text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
                  value={role}
                  onChange={(event) => setRole(event.target.value as (typeof roles)[number])}
                >
                  {roles.map((option) => <option key={option} value={option}>{option.replace('_', ' ')}</option>)}
                </select>
              </label>
              <div className="flex justify-end gap-2 pt-1">
                <button type="button" className="btn btn-ghost text-sm" disabled={creating} onClick={() => setCreateOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary text-sm" disabled={creating}>
                  {creating ? 'Creating…' : 'Create user'}
                </button>
              </div>
            </form>
          </section>
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
