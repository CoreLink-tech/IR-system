import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { signIn, takePlace } from '@/api/session';
import { isEnrollmentRequired, isLoginSession, isTwoFactorRequired } from '@/api/types';
import { describeError, isApiError } from '@/api/errors';
import { useAuth } from '@/auth/useSession';
import { Button, Field, Notice, useCountdown } from '@/components/ui';
import { IconShield } from '@/components/icons';

const REASONS: Record<string, { title: string; body: string }> = {
  expired: { title: 'Your session ended', body: 'You were signed out. Sign in again and you will be taken back to where you were.' },
  idle: { title: 'Signed out because you were away', body: 'For safety you are signed out after a period of no activity. Sign in again to carry on.' },
  compromised: {
    title: 'All your sessions were ended for safety',
    body: 'Your sign-in was used a second time after it had already been replaced. That can mean a copy of it was taken, so the system ended every session on your account. Sign in again. If you did not expect this, change your password after signing in and tell your administrator.',
  },
  session_ended: {
    title: 'This session has ended',
    body: 'You were signed out. Sign in again to continue.',
  },
};

export default function SignInPage() {
  const { status, reason } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const wait = useCountdown(isApiError(error) && error.status === 429 ? error.retryAfterSeconds ?? 60 : undefined);
  const changed = (loc.state as { passwordChanged?: boolean } | null)?.passwordChanged;

  if (status === 'signedIn') return <Navigate to="/" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || wait > 0) return;
    setBusy(true); setError(null);
    try {
      const result = await signIn(email.trim(), password);
      if (isLoginSession(result)) {
        nav(takePlace(), { replace: true });
      } else if (isTwoFactorRequired(result)) {
        nav('/sign-in/2fa', { replace: true, state: { challengeToken: result.challengeToken, email: email.trim() } });
      } else if (isEnrollmentRequired(result)) {
        nav('/sign-in/enroll', { replace: true, state: { challengeToken: result.challengeToken, email: email.trim() } });
      }
    } catch (err) {
      setError(err);
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  const limited = isApiError(error) && error.status === 429;
  const locked = limited && (isApiError(error) && (error.code === 'account_locked' || error.code === 'two_factor_locked'));
  // Wrong email and wrong password get the same words, so the screen never reveals which was wrong.
  const message = !error ? null
    : isApiError(error) && (error.status === 401 || error.status === 400)
      ? (error.retryAfterSeconds
          ? `The email or password is not right. Wait ${wait > 0 ? wait + ' seconds' : 'a moment'} before trying again.`
          : 'The email or password is not right. Check both and try again.')
    : locked
      ? `This account is temporarily locked. ${wait > 0 ? `Try again in ${wait} seconds.` : 'You can try again now.'}`
    : limited
      ? `Too many sign-in attempts. ${wait > 0 ? `Try again in ${wait} seconds.` : 'You can try again now.'}`
    : describeError(error).body;
  const r = reason ? REASONS[reason] : undefined;

  return (
    <main style={{ maxWidth: 440 }}>
      <div className="stack">
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '.5rem' }}>
          <span style={{ width: 28, display: 'inline-flex' }}><IconShield /></span> Security Dashboard
        </h1>
        {r && <Notice title={r.title}><p style={{ margin: '.3rem 0 0' }}>{r.body}</p></Notice>}
        {changed && <Notice tone="ok" title="Password changed"><p style={{ margin: '.3rem 0 0' }}>Sign in with your new password.</p></Notice>}
        <form className="card" onSubmit={submit} noValidate>
          <h2 style={{ marginTop: 0 }}>Sign in</h2>
          <Field label="Email">{(p) => <input {...p} name="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />}</Field>
          <Field label="Password">
            {(p) => (
              <div className="pw-row">
                <input {...p} name="password" type={show ? 'text' : 'password'} autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                <Button onClick={() => setShow((s) => !s)} aria-pressed={show}>{show ? 'Hide' : 'Show'}<span className="sr-only"> password</span></Button>
              </div>
            )}
          </Field>
          {message && <p className="error-text" role="alert" aria-live="assertive">{message}</p>}
          <button type="submit" className="btn primary" disabled={busy || wait > 0 || !email || !password} style={{ width: '100%' }}>
            {busy ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </main>
  );
}
