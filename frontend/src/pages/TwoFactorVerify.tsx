import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { verifyTwoFactor, takePlace } from '@/api/session';
import { describeError, isApiError } from '@/api/errors';
import { useAuth } from '@/auth/useSession';
import { Field, Notice, useCountdown } from '@/components/ui';

/**
 * Second step of sign-in: enter a 6-digit authenticator code or a recovery code.
 */
export default function TwoFactorVerifyPage() {
  const { status } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const state = (loc.state || {}) as { challengeToken?: string; email?: string };
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const wait = useCountdown(isApiError(error) && error.status === 429 ? error.retryAfterSeconds ?? 60 : undefined);

  if (status === 'signedIn') return <Navigate to="/" replace />;
  if (!state.challengeToken) return <Navigate to="/sign-in" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || wait > 0) return;
    setBusy(true); setError(null);
    try {
      const trimmed = code.trim();
      if (useRecovery) {
        await verifyTwoFactor(state.challengeToken!, undefined, trimmed);
      } else {
        await verifyTwoFactor(state.challengeToken!, trimmed.replace(/\s/g, ''));
      }
      nav(takePlace(), { replace: true });
    } catch (err) {
      setError(err);
      setCode('');
      if (isApiError(err) && err.code === 'challenge_expired') {
        nav('/sign-in', { replace: true });
      }
    } finally {
      setBusy(false);
    }
  };

  const message = !error ? null
    : isApiError(error) && error.code === 'invalid_code'
      ? (useRecovery ? 'That recovery code is not right, or it has already been used.' : 'That code is not right. Check the app and try the next code.')
    : isApiError(error) && error.status === 429
      ? `Too many attempts. ${wait > 0 ? `Try again in ${wait} seconds.` : 'You can try again now.'}`
    : isApiError(error) && error.code === 'challenge_expired'
      ? 'This step expired. Sign in again from the start.'
    : describeError(error).body;

  return (
    <main style={{ maxWidth: 440 }}>
      <div className="stack">
        <h1>Two-step verification</h1>
        <p className="muted">
          {state.email ? `Signed in as ${state.email}. ` : ''}
          Enter the code from your authenticator app to finish signing in.
        </p>
        <form className="card" onSubmit={submit} noValidate>
          {!useRecovery ? (
            <Field label="6-digit code">
              {(p) => (
                <input
                  {...p}
                  name="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]*"
                  maxLength={6}
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  autoFocus
                />
              )}
            </Field>
          ) : (
            <Field label="Recovery code">
              {(p) => (
                <input
                  {...p}
                  name="recoveryCode"
                  autoComplete="off"
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value.toUpperCase())}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  autoFocus
                />
              )}
            </Field>
          )}
          {message && <p className="error-text" role="alert" aria-live="assertive">{message}</p>}
          <button type="submit" className="btn primary" disabled={busy || wait > 0 || !code} style={{ width: '100%' }}>
            {busy ? 'Checking...' : 'Continue'}
          </button>
          <p style={{ marginTop: '1rem' }}>
            <button type="button" className="btn link" onClick={() => { setUseRecovery((v) => !v); setCode(''); setError(null); }}>
              {useRecovery ? 'Use an authenticator code instead' : 'Use a recovery code instead'}
            </button>
          </p>
          <p>
            <button type="button" className="btn link" onClick={() => nav('/sign-in', { replace: true })}>
              Back to sign in
            </button>
          </p>
        </form>
        <Notice title="Lost your device?">
          <p style={{ margin: '.3rem 0 0' }}>
            If you have recovery codes, use one above. Otherwise ask a super admin to reset two-step verification for your account.
          </p>
        </Notice>
      </div>
    </main>
  );
}
