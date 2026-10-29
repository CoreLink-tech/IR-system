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
    <div className="flex min-h-screen bg-[#f3f5f4]">
      {/* Left brand panel */}
      <div className="hidden w-[42%] flex-col justify-between bg-[#fcfdfc] border-r border-[#e0e7e3] p-10 lg:flex">
        <div className="flex items-center gap-3">
          <svg className="h-10 w-9 text-[#176b52]" viewBox="0 0 40 44" fill="none">
            <path d="M20 2L36 8V21C36 31 29 37 20 42C11 37 4 31 4 21V8L20 2Z" stroke="currentColor" strokeWidth="2.4"/>
            <path d="M11 14V29H15V21L20 27L25 21V29H29V14H25L20 21L15 14H11Z" fill="currentColor"/>
          </svg>
          <div>
            <div className="text-[20px] font-[760] tracking-[-0.8px]">Watcher</div>
            <div className="text-[10px] text-[#718079]">by ZenLink Technologies</div>
          </div>
        </div>

        <div className="space-y-5">
          <h1 className="text-[28px] font-[750] leading-tight tracking-[-0.9px] text-[#172923]">
            Monitor. Investigate.<br />Respond.
          </h1>
          <p className="max-w-sm text-[13px] leading-relaxed text-[#718079]">
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
              <div key={item.label} className="rounded-[6px] border border-[#e0e7e3] bg-white p-3">
                <div className="text-[11px] font-bold text-[#172923]">{item.label}</div>
                <div className="mt-0.5 text-[10px] text-[#718079]">{item.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="text-[10px] text-[#8a9690]">Authorized personnel only</div>
      </div>

      {/* Form */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-12">
        <div className="w-full max-w-[360px]">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <svg className="h-8 w-7 text-[#176b52]" viewBox="0 0 40 44" fill="none">
              <path d="M20 2L36 8V21C36 31 29 37 20 42C11 37 4 31 4 21V8L20 2Z" stroke="currentColor" strokeWidth="2.4"/>
              <path d="M11 14V29H15V21L20 27L25 21V29H29V14H25L20 21L15 14H11Z" fill="currentColor"/>
            </svg>
            <span className="text-[16px] font-[760]">Watcher</span>
          </div>

          <h2 className="text-[22px] font-[750] tracking-[-0.5px]">Sign in</h2>
          <p className="mt-1.5 text-[13px] text-[#718079]">
            Enter your credentials to access the security console.
          </p>

          <form onSubmit={onSubmit} className="mt-8 space-y-4">
            <div>
              <label htmlFor="email" className="mb-1.5 block text-[11px] font-semibold text-[#5f6f67]">
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
              <label htmlFor="password" className="mb-1.5 block text-[11px] font-semibold text-[#5f6f67]">
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
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-[#7b8881] hover:text-[#172923]"
                  onClick={() => setShowPassword((v) => !v)}
                  tabIndex={-1}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            {message && (
              <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-3 py-2 text-[12px] text-[#a13a3a]" role="alert">
                {message}
              </div>
            )}

            <button type="submit" disabled={busy || !email || !password} className="btn btn-primary w-full py-2.5 text-[12px]">
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-center text-[10px] text-[#8a9690]">
            Access restricted to authorized security personnel
          </p>
        </div>
      </div>
    </div>
  );
}
