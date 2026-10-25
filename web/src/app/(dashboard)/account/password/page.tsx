'use client';

import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api, ApiError, setAccessToken } from '@/lib/client-api';

export default function ChangePasswordPage() {
  const router = useRouter();
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await api('/auth/change-password', {
        method: 'POST',
        json: { currentPassword, newPassword },
      });
      setOk(true);
      setAccessToken(null);
      sessionStorage.removeItem('ir_at');
      setTimeout(() => router.replace('/sign-in'), 1500);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md space-y-4">
      <h1 className="text-2xl font-semibold">Change password</h1>
      <p className="text-sm text-neutral-600">At least 12 characters, with upper, lower, and a digit. All sessions will end.</p>
      {ok && <p className="text-green-700">Password changed. Sign in again.</p>}
      <form onSubmit={onSubmit} className="space-y-3 rounded-lg border bg-white p-4">
        <label className="block text-sm">
          Current password
          <input className="mt-1 w-full rounded border px-3 py-2" type="password" required value={currentPassword} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="block text-sm">
          New password
          <input className="mt-1 w-full rounded border px-3 py-2" type="password" required minLength={12} value={newPassword} onChange={(e) => setNew(e.target.value)} />
        </label>
        {message && <p className="text-sm text-red-600">{message}</p>}
        <button type="submit" disabled={busy} className="w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50">
          {busy ? 'Saving…' : 'Change password'}
        </button>
      </form>
    </div>
  );
}
