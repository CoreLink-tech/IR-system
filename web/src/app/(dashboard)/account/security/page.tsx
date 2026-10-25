'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

export default function AccountSecurityPage() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [password, setPassword] = useState('');
  const [regenCode, setRegenCode] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ user: { twoFactorEnabled?: boolean } }>('/auth/me')
      .then((r) => setEnabled(!!r.user.twoFactorEnabled))
      .catch(() => setEnabled(false));
  }, []);

  async function startSetup() {
    setError(null);
    try {
      const r = await api<{ secret: string; otpauthUri: string }>('/auth/2fa/setup/start', { method: 'POST', json: {} });
      setSecret(r.secret);
      setOtpauth(r.otpauthUri);
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    }
  }

  async function confirmSetup(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<{ recoveryCodes: string[] }>('/auth/2fa/setup/confirm', {
        method: 'POST',
        json: { code },
      });
      setRecovery(r.recoveryCodes);
      setEnabled(true);
      setSecret(null);
      setMessage('Two-step verification is on. Save your recovery codes.');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  async function regen(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<{ recoveryCodes: string[] }>('/auth/2fa/recovery-codes/regenerate', {
        method: 'POST',
        json: { password, code: regenCode },
      });
      setRecovery(r.recoveryCodes);
      setPassword('');
      setRegenCode('');
      setMessage('New recovery codes issued. Old codes no longer work.');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <h1 className="text-2xl font-semibold">Security</h1>
      {message && <p className="text-green-700">{message}</p>}
      {error && <p className="text-red-600">{error}</p>}
      <div className="rounded-lg border bg-white p-4">
        <p className="text-sm">
          Two-step verification:{' '}
          <strong>{enabled === null ? '…' : enabled ? 'On' : 'Off'}</strong>
        </p>
        {enabled === false && !secret && (
          <button type="button" className="mt-3 rounded bg-blue-600 px-3 py-2 text-sm text-white" onClick={() => void startSetup()}>
            Turn on authenticator app
          </button>
        )}
        {secret && (
          <form onSubmit={confirmSetup} className="mt-4 space-y-3">
            <p className="font-mono text-lg tracking-wide">{(secret.match(/.{1,4}/g) || []).join(' ')}</p>
            {otpauth && (
              <a className="text-sm text-blue-700 underline" href={otpauth}>
                Add to authenticator
              </a>
            )}
            <input
              className="block w-full rounded border px-3 py-2 font-mono"
              placeholder="6-digit code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            />
            <button type="submit" className="rounded bg-blue-600 px-3 py-2 text-sm text-white">
              Confirm
            </button>
          </form>
        )}
      </div>
      {enabled && (
        <form onSubmit={regen} className="space-y-3 rounded-lg border bg-white p-4">
          <h2 className="font-medium">Regenerate recovery codes</h2>
          <input
            className="block w-full rounded border px-3 py-2"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <input
            className="block w-full rounded border px-3 py-2 font-mono"
            placeholder="Current 6-digit code"
            value={regenCode}
            onChange={(e) => setRegenCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          />
          <button type="submit" className="rounded border px-3 py-2 text-sm">
            Issue new codes
          </button>
        </form>
      )}
      {recovery && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4">
          <p className="font-medium">Recovery codes (shown once)</p>
          <ul className="mt-2 font-mono text-sm">
            {recovery.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
