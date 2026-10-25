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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ data: UserRow[] }>('/auth/users')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed to load'));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Users</h1>
      {error && <p className="text-red-600">{error}</p>}
      <div className="overflow-x-auto rounded-lg border bg-white">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b bg-neutral-50 text-neutral-600">
            <tr>
              <th className="px-3 py-2">Account</th>
              <th className="px-3 py-2">Role</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Two-step</th>
              <th className="px-3 py-2">Last sign-in</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.id} className="border-b last:border-0">
                <td className="px-3 py-2">
                  <div className="font-medium">{u.name || u.email}</div>
                  {u.name && <div className="text-xs text-neutral-500">{u.email}</div>}
                </td>
                <td className="px-3 py-2">{u.role}</td>
                <td className="px-3 py-2">{u.isActive ? 'Active' : 'Deactivated'}</td>
                <td className="px-3 py-2">{u.twoFactorEnabled ? 'On' : 'Off'}</td>
                <td className="px-3 py-2 text-neutral-500">
                  {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'never'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
