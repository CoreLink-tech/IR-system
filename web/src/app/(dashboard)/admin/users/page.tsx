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
    void load();
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
      <h1 className="text-2xl font-semibold">Users</h1>
      <p className="text-sm text-neutral-600">
        Super admin only. You cannot reset your own two-step verification from here.
      </p>
      {error && <p className="text-red-600">{error}</p>}
      {done && <p className="text-green-700">{done}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Account</th>
              <th className="px-3 py-2">Role</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Two-step</th>
              <th className="px-3 py-2">Last sign-in</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.id} className="border-b last:border-0">
                <td className="px-3 py-2">
                  <div className="font-medium">{u.name || u.email}</div>
                  {u.name && <div className="text-xs text-neutral-500">{u.email}</div>}
                  {u.id === meId && <span className="text-xs text-blue-700">You</span>}
                </td>
                <td className="px-3 py-2">{u.role}</td>
                <td className="px-3 py-2">{u.isActive ? 'Active' : 'Deactivated'}</td>
                <td className="px-3 py-2">{u.twoFactorEnabled ? 'On' : 'Off'}</td>
                <td className="px-3 py-2 text-neutral-500">
                  {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'never'}
                </td>
                <td className="px-3 py-2">
                  {u.id !== meId && (
                    <span className="flex flex-wrap gap-2">
                      <button type="button" className="text-blue-700 underline" onClick={() => void unlock(u.id, u.email)}>
                        Unlock
                      </button>
                      <button type="button" className="text-red-700 underline" onClick={() => void reset2fa(u.id, u.email)}>
                        Reset two-step
                      </button>
                    </span>
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
