'use client';

import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ApiError, setAccessToken, signIn } from '@/lib/client-api';

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const result = await signIn(email.trim(), password);
      if ('twoFactorRequired' in result && result.twoFactorRequired) {
        sessionStorage.setItem('ir_challenge', result.challengeToken);
        router.push('/sign-in/2fa');
        return;
      }
      if ('twoFactorEnrollmentRequired' in result && result.twoFactorEnrollmentRequired) {
        sessionStorage.setItem('ir_challenge', result.challengeToken);
        router.push('/sign-in/enroll');
        return;
      }
      if ('accessToken' in result) {
        setAccessToken(result.accessToken);
        
        router.replace('/overview');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setMessage(
            err.retryAfterSeconds
              ? `Too many attempts. Try again in ${err.retryAfterSeconds} seconds.`
              : 'Too many attempts. Try again later.',
          );
        } else {
          setMessage('The email or password is not right. Check both and try again.');
        }
      } else {
        setMessage('Cannot reach the server. Check your connection.');
      }
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-md p-8">
      <h1 className="text-2xl font-semibold">Security Dashboard</h1>
      <p className="mt-1 text-sm text-neutral-600">Sign in to manage incidents and blocks.</p>
      <form onSubmit={onSubmit} className="mt-6 space-y-4 rounded-lg border bg-white p-5 shadow-sm">
        <label className="block text-sm">
          <span className="text-neutral-700">Email</span>
          <input
            className="mt-1 w-full rounded border px-3 py-2"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label className="block text-sm">
          <span className="text-neutral-700">Password</span>
          <input
            className="mt-1 w-full rounded border px-3 py-2"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {message && (
          <p className="text-sm text-red-600" role="alert">
            {message}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || !email || !password}
          className="w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
