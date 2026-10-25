'use client';

import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ApiError, api, setAccessToken } from '@/lib/client-api';

export default function TwoFactorEnrollPage() {
  const router = useRouter();
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    const challengeToken = sessionStorage.getItem('ir_challenge');
    if (!challengeToken) {
      router.replace('/sign-in');
      return;
    }
    api<{ secret: string; otpauthUri: string }>('/auth/2fa/enroll/start', {
      method: 'POST',
      json: { challengeToken },
    })
      .then((r) => {
        setSecret(r.secret);
        setOtpauth(r.otpauthUri);
      })
      .catch((e: unknown) => {
        setLoadError(e instanceof ApiError ? e.message : 'Could not start enrolment');
      });
  }, [router]);

  const grouped = secret ? (secret.match(/.{1,4}/g) || []).join(' ') : '';

  async function onConfirm(e: FormEvent) {
    e.preventDefault();
    const challengeToken = sessionStorage.getItem('ir_challenge');
    if (!challengeToken || !code) return;
    setBusy(true);
    setMessage(null);
    try {
      const result = await api<{ accessToken: string; recoveryCodes: string[] }>('/auth/2fa/enroll/confirm', {
        method: 'POST',
        json: { challengeToken, code: code.replace(/\s/g, '') },
      });
      setAccessToken(result.accessToken);
      sessionStorage.setItem('ir_at', result.accessToken);
      setRecoveryCodes(result.recoveryCodes || []);
    } catch (err) {
      setMessage(
        err instanceof ApiError && err.code === 'invalid_code'
          ? 'That code is not right. Wait for the next one and try again.'
          : err instanceof ApiError
            ? err.message
            : 'Something went wrong.',
      );
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <main className="mx-auto max-w-md p-8">
        <p className="text-red-600">{loadError}</p>
        <button type="button" className="mt-4 text-blue-700 underline" onClick={() => router.replace('/sign-in')}>
          Back to sign in
        </button>
      </main>
    );
  }

  if (recoveryCodes) {
    return (
      <main className="mx-auto max-w-lg p-8">
        <h1 className="text-2xl font-semibold">Save your recovery codes</h1>
        <p className="mt-2 text-sm text-neutral-600">
          Shown once only. Store them offline. Each code works once.
        </p>
        <ul className="mt-4 space-y-1 rounded-lg border bg-white p-4 font-mono text-sm">
          {recoveryCodes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <label className="mt-4 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          I have saved these recovery codes
        </label>
        <button
          type="button"
          disabled={!saved}
          className="mt-4 w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50"
          onClick={() => {
            sessionStorage.removeItem('ir_challenge');
            router.replace('/overview');
          }}
        >
          Continue to the dashboard
        </button>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-lg p-8">
      <h1 className="text-2xl font-semibold">Set up two-step verification</h1>
      <p className="mt-1 text-sm text-neutral-600">
        Your role requires an authenticator app. Add this account, then enter the first code.
      </p>
      <div className="mt-6 rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="font-medium">Setup key</h2>
        {!secret ? (
          <p className="mt-2 text-neutral-500">Preparing…</p>
        ) : (
          <>
            <p className="mt-2 font-mono text-lg tracking-wide">{grouped}</p>
            <button
              type="button"
              className="mt-2 text-sm text-blue-700 underline"
              onClick={() => void navigator.clipboard.writeText(secret)}
            >
              Copy setup key
            </button>
            {otpauth && (
              <p className="mt-3 break-all text-xs text-neutral-500">
                Or open on this device: <a className="text-blue-700 underline" href={otpauth}>Add to authenticator</a>
              </p>
            )}
          </>
        )}
      </div>
      <form onSubmit={onConfirm} className="mt-4 space-y-4 rounded-lg border bg-white p-5 shadow-sm">
        <label className="block text-sm">
          <span className="text-neutral-700">6-digit code from the app</span>
          <input
            className="mt-1 w-full rounded border px-3 py-2 font-mono"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          />
        </label>
        {message && (
          <p className="text-sm text-red-600" role="alert">
            {message}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || code.length !== 6 || !secret}
          className="w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50"
        >
          {busy ? 'Confirming…' : 'Confirm and continue'}
        </button>
      </form>
    </main>
  );
}
