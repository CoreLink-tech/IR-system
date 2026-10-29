'use client';

import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ApiError, setAccessToken, signIn } from '@/lib/client-api';

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
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
          setMessage('Invalid email or password. Please try again.');
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
    <div className="flex min-h-screen">
      {/* Left panel - branding */}
      <div className="hidden w-[42%] flex-col justify-between bg-[var(--bg-sidebar)] p-10 lg:flex">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-[var(--accent)] text-sm font-bold text-[var(--text-inverse)]">
              W
            </div>
            <div>
              <div className="text-base font-semibold tracking-tight">Watcher, by ZenLink</div>
              <div className="text-xs text-[var(--text-muted)]">Security Operations Platform</div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <h1 className="text-2xl font-semibold leading-tight tracking-tight">
            Monitor. Investigate.<br />Respond.
          </h1>
          <p className="max-w-sm text-sm leading-relaxed text-[var(--text-secondary)]">
            Centralized incident response and threat monitoring for your applications.
            Detect suspicious activity, manage enforcement, and maintain operational awareness.
          </p>
          <div className="grid grid-cols-2 gap-3 pt-2">
            {[
              { label: 'Event Ingestion', desc: 'Real-time security events' },
              { label: 'Incident Response', desc: 'Structured investigation' },
              { label: 'IP Intelligence', desc: 'Risk-based decisions' },
              { label: 'Enforcement', desc: 'Block & allow controls' },
            ].map((item) => (
              <div key={item.label} className="rounded-[var(--radius-md)] border border-[var(--border)] bg-[var(--bg-surface)] p-3">
                <div className="text-xs font-medium">{item.label}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{item.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="text-[11px] text-[var(--text-muted)]">
          Authorized personnel only
        </div>
      </div>

      {/* Right panel - form */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-12">
        <div className="w-full max-w-[360px]">
          {/* Mobile brand */}
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-[var(--accent)] text-xs font-bold text-[var(--text-inverse)]">
              W
            </div>
            <span className="text-sm font-semibold">Watcher, by ZenLink</span>
          </div>

          <h2 className="text-xl font-semibold tracking-tight">Sign in</h2>
          <p className="mt-1.5 text-sm text-[var(--text-secondary)]">
            Enter your credentials to access the security console.
          </p>

          <form onSubmit={onSubmit} className="mt-8 space-y-4">
            <div>
              <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)]">
                Email
              </label>
              <input
                id="email"
                className="input"
                type="email"
                autoComplete="username"
                required
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)]">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  className="input pr-10"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  onClick={() => setShowPassword((v) => !v)}
                  tabIndex={-1}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {message && (
              <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-3 py-2 text-sm text-[var(--critical)]" role="alert">
                {message}
              </div>
            )}

            <button
              type="submit"
              disabled={busy || !email || !password}
              className="btn btn-primary w-full py-2.5"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-center text-[11px] text-[var(--text-muted)]">
            Access restricted to authorized security personnel
          </p>
        </div>
      </div>
    </div>
  );
}
