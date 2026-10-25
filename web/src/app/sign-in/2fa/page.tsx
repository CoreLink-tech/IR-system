'use client';

import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ApiError, api, setAccessToken } from '@/lib/client-api';

export default function TwoFactorVerifyPage() {
  const router = useRouter();
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const challengeToken = sessionStorage.getItem('ir_challenge');
    if (!challengeToken) {
      router.replace('/sign-in');
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const body = useRecovery
        ? { challengeToken, recoveryCode: code.trim() }
        : { challengeToken, code: code.replace(/\s/g, '') };
      const result = await api<{ accessToken: string }>('/auth/2fa/verify', { method: 'POST', json: body });
      setAccessToken(result.accessToken);
      
      sessionStorage.removeItem('ir_challenge');
      router.replace('/overview');
    } catch (err) {
      if (err instanceof ApiError && err.code === 'challenge_expired') {
        sessionStorage.removeItem('ir_challenge');
        router.replace('/sign-in');
        return;
      }
      setMessage(
        err instanceof ApiError && err.code === 'invalid_code'
          ? useRecovery
            ? 'That recovery code is not right, or it has already been used.'
            : 'That code is not right. Check the app and try again.'
          : err instanceof ApiError
            ? err.message
            : 'Something went wrong.',
      );
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-md p-8">
      <h1 className="text-2xl font-semibold">Two-step verification</h1>
      <p className="mt-1 text-sm text-neutral-600">
        Enter the code from your authenticator app to finish signing in.
      </p>
      <form onSubmit={onSubmit} className="mt-6 space-y-4 rounded-lg border bg-white p-5 shadow-sm">
        <label className="block text-sm">
          <span className="text-neutral-700">{useRecovery ? 'Recovery code' : '6-digit code'}</span>
          <input
            className="mt-1 w-full rounded border px-3 py-2 font-mono"
            inputMode={useRecovery ? 'text' : 'numeric'}
            autoComplete={useRecovery ? 'off' : 'one-time-code'}
            required
            value={code}
            onChange={(e) =>
              setCode(useRecovery ? e.target.value.toUpperCase() : e.target.value.replace(/\D/g, '').slice(0, 6))
            }
            placeholder={useRecovery ? 'XXXX-XXXX-XXXX-XXXX' : '000000'}
            autoFocus
          />
        </label>
        {message && (
          <p className="text-sm text-red-600" role="alert">
            {message}
          </p>
        )}
        <button type="submit" disabled={busy || !code} className="w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50">
          {busy ? 'Checking…' : 'Continue'}
        </button>
        <button
          type="button"
          className="text-sm text-blue-700 underline"
          onClick={() => {
            setUseRecovery((v) => !v);
            setCode('');
            setMessage(null);
          }}
        >
          {useRecovery ? 'Use an authenticator code instead' : 'Use a recovery code instead'}
        </button>
      </form>
    </main>
  );
}
