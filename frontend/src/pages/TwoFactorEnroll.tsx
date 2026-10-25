import { useEffect, useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { enrollConfirm, enrollStart, takePlace } from '@/api/session';
import { describeError, isApiError } from '@/api/errors';
import { useAuth } from '@/auth/useSession';
import { Button, Field, Notice } from '@/components/ui';

/**
 * Required enrolment for SUPER_ADMIN / SECURITY_ADMIN when REQUIRE_2FA is on.
 * Shows the setup key (grouped) and, after confirm, the recovery codes once.
 */
export default function TwoFactorEnrollPage() {
  const { status } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const state = (loc.state || {}) as { challengeToken?: string; email?: string };
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [loadError, setLoadError] = useState<unknown>(null);

  if (status === 'signedIn' && !recoveryCodes) return <Navigate to="/" replace />;
  if (!state.challengeToken) return <Navigate to="/sign-in" replace />;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await enrollStart(state.challengeToken!);
        if (!cancelled) {
          setSecret(r.secret);
          setOtpauthUri(r.otpauthUri);
        }
      } catch (e) {
        if (!cancelled) setLoadError(e);
      }
    })();
    return () => { cancelled = true; };
  }, [state.challengeToken]);

  const grouped = secret ? (secret.match(/.{1,4}/g) || []).join(' ') : '';

  const copy = async (text: string) => {
    try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
  };

  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    if (busy || !code) return;
    setBusy(true); setError(null);
    try {
      const r = await enrollConfirm(state.challengeToken!, code.replace(/\s/g, ''));
      setRecoveryCodes(r.recoveryCodes);
    } catch (err) {
      setError(err);
      setCode('');
      if (isApiError(err) && err.code === 'challenge_expired') nav('/sign-in', { replace: true });
    } finally {
      setBusy(false);
    }
  };

  const finish = () => {
    if (!saved) return;
    nav(takePlace(), { replace: true });
  };

  if (loadError) {
    return (
      <main style={{ maxWidth: 480 }}>
        <Notice title="Could not start enrolment">
          <p>{describeError(loadError).body}</p>
          <button type="button" className="btn" onClick={() => nav('/sign-in', { replace: true })}>Back to sign in</button>
        </Notice>
      </main>
    );
  }

  if (recoveryCodes) {
    return (
      <main style={{ maxWidth: 520 }}>
        <div className="stack">
          <h1>Save your recovery codes</h1>
          <Notice title="Shown once only">
            <p style={{ margin: '.3rem 0 0' }}>
              Store these somewhere safe offline. Each code works once. You will not see them again.
            </p>
          </Notice>
          <div className="card">
            <ul style={{ fontFamily: 'monospace', listStyle: 'none', padding: 0, columns: '0.4rem 0' }}>
              {recoveryCodes.map((c) => <li key={c}>{c}</li>)}
            </ul>
            <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
              <Button onClick={() => copy(recoveryCodes.join('\n'))}>Copy all</Button>
              <a
                className="btn"
                download="security-dashboard-recovery-codes.txt"
                href={`data:text/plain;charset=utf-8,${encodeURIComponent(recoveryCodes.join('\n') + '\n')}`}
              >
                Download as text
              </a>
            </div>
            <label style={{ display: 'flex', gap: '.5rem', marginTop: '1rem', alignItems: 'center' }}>
              <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
              I have saved these recovery codes
            </label>
            <button type="button" className="btn primary" disabled={!saved} onClick={finish} style={{ width: '100%', marginTop: '1rem' }}>
              Continue to the dashboard
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 520 }}>
      <div className="stack">
        <h1>Set up two-step verification</h1>
        <p className="muted">
          Your role requires an authenticator app. Add this account to your app, then enter the first code below.
        </p>
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Setup key</h2>
          {!secret ? (
            <p>Preparing...</p>
          ) : (
            <>
              <p style={{ fontFamily: 'monospace', fontSize: '1.1rem', letterSpacing: '0.05em' }}>{grouped}</p>
              <Button onClick={() => secret && copy(secret)}>Copy setup key</Button>
              {otpauthUri && (
                <p className="muted" style={{ marginTop: '0.75rem', wordBreak: 'break-all', fontSize: '0.85rem' }}>
                  If your app supports it, open this link on the same device:{' '}
                  <a href={otpauthUri}>Add to authenticator</a>
                </p>
              )}
              <p className="muted" style={{ marginTop: '0.5rem' }}>
                Prefer a QR code? Most authenticator apps also accept pasting the setup key above.
              </p>
            </>
          )}
        </div>
        <form className="card" onSubmit={confirm} noValidate>
          <h2 style={{ marginTop: 0 }}>Confirm with a code</h2>
          <Field label="6-digit code from the app">
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
              />
            )}
          </Field>
          {error && (
            <p className="error-text" role="alert" aria-live="assertive">
              {isApiError(error) && error.code === 'invalid_code'
                ? 'That code is not right. Wait for the next one and try again.'
                : describeError(error).body}
            </p>
          )}
          <button type="submit" className="btn primary" disabled={busy || code.length !== 6 || !secret} style={{ width: '100%' }}>
            {busy ? 'Confirming...' : 'Confirm and continue'}
          </button>
        </form>
      </div>
    </main>
  );
}
