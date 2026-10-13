import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { changePassword } from '@/api/actions';
import { signOut } from '@/api/session';
import { ErrorPanel, Field, Notice } from '@/components/ui';
import { isApiError } from '@/api/errors';
import { useAuth } from '@/auth/useSession';

export default function ChangePasswordPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [local, setLocal] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next.length < 12) return setLocal('Use at least 12 characters.');
    if (next !== again) return setLocal('The two new passwords are not the same.');
    setLocal(null); setBusy(true);
    try {
      await changePassword(current, next);
      // The server ends every session when a password changes, including this one.
      await signOut('signedOut', false);
      nav('/sign-in', { replace: true, state: { passwordChanged: true } });
    } catch (err) { setError(err); } finally { setBusy(false); }
  };

  return (
    <div className="stack" style={{ maxWidth: 520 }}>
      <h1>Change password</h1>
      {user?.mustChangePassword && <Notice title="You must choose a new password">An administrator set a temporary password for you. Choose your own now. Nothing else in the dashboard works until you do.</Notice>}
      <form className="card" onSubmit={submit} noValidate>
        <Field label="Current password">{(p) => <input {...p} type="password" name="current" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />}</Field>
        <Field label="New password" hint="At least 12 characters. A long phrase is better than a short complicated word." error={local}>{(p) => <input {...p} type="password" name="new" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />}</Field>
        <Field label="New password again">{(p) => <input {...p} type="password" name="again" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />}</Field>
        {error && isApiError(error) && error.status === 401 ? <p className="error-text" role="alert">The current password is not right.</p> : error ? <ErrorPanel compact error={error} /> : null}
        <p className="hint">When the password changes you are signed out everywhere and sign in again with the new one.</p>
        <button type="submit" className="btn primary" disabled={busy || !current || !next}>{busy ? 'Saving...' : 'Change password'}</button>
      </form>
    </div>
  );
}
