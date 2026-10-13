import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useUsers } from '@/api/hooks';
import { createUser, resetUserPassword, updateUser } from '@/api/actions';
import { ROLE_LIST, type UserRow } from '@/api/types';
import { useAuth } from '@/auth/useSession';
import { Button, ConfirmDialog, ErrorPanel, Field, Notice, QueryState, Skeleton } from '@/components/ui';
import { Dialog } from '@/components/Dialog';
import { ResponsiveTable } from '@/components/table';
import { announce } from '@/components/announce';
import { ROLE_LABEL } from '@/lib/permissions';
import { ageLabel } from '@/lib/format';

const ROLE_HELP: Record<string, string> = {
  SUPER_ADMIN: 'Everything, including creating accounts.',
  SECURITY_ADMIN: 'Block and unblock addresses, manage API keys and detection rules, assign incidents.',
  ANALYST: 'Investigate: raw events, technical reports, the audit log, change incident status.',
  VIEWER: 'Read the overview and plain-English reports. Cannot change anything.',
};

function generatePassword(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join('');
}

function PasswordInput({ id, value, onChange, describedBy }: { id: string; value: string; onChange: (v: string) => void; describedBy?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div className="pw-row">
      <input id={id} aria-describedby={describedBy} type={show ? 'text' : 'password'} autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
      <Button onClick={() => setShow((s) => !s)} aria-pressed={show}>{show ? 'Hide' : 'Show'}</Button>
      <Button onClick={() => { onChange(generatePassword()); setShow(true); }}>Generate</Button>
    </div>
  );
}

function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ email: '', name: '', role: 'VIEWER', password: '', change: true });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const go = async () => {
    if (!f.email.trim()) return setProblem('Enter an email address.');
    if (f.password.length < 12) return setProblem('The temporary password needs at least 12 characters.');
    setProblem(null); setBusy(true); setError(null);
    try {
      await createUser({ email: f.email.trim(), name: f.name.trim() || undefined, role: f.role, password: f.password, requirePasswordChange: f.change });
      await qc.invalidateQueries({ queryKey: ['users'] }); announce('Account created'); onClose();
    } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <Dialog title="Create an account" onClose={onClose} busy={busy}>
      <Field label="Email">{(p) => <input {...p} type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />}</Field>
      <Field label="Name (optional)">{(p) => <input {...p} type="text" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
      <Field label="Role" hint={ROLE_HELP[f.role]}>{(p) => <select {...p} value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{ROLE_LIST.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</select>}</Field>
      <Field label="Temporary password" hint="At least 12 characters. Give it to the person in person or by a private message." error={problem}>{(p) => <PasswordInput id={p.id} describedBy={p['aria-describedby']} value={f.password} onChange={(v) => setF({ ...f, password: v })} />}</Field>
      <label className="check"><input type="checkbox" checked={f.change} onChange={(e) => setF({ ...f, change: e.target.checked })} /> <span>They must choose their own password at first sign-in (recommended)</span></label>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" onClick={go} busy={busy}>Create account</Button></div>
    </Dialog>
  );
}

function ResetDialog({ u, onClose, onDone }: { u: UserRow; onClose: () => void; onDone: (m: string) => void }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const go = async () => {
    if (pw.length < 12) return setProblem('The temporary password needs at least 12 characters.');
    setProblem(null); setBusy(true); setError(null);
    try { await resetUserPassword(u.id, pw); onDone(`Password reset for ${u.email}. All of their sessions were ended and they must choose a new password when they sign in.`); onClose(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <Dialog title={`Reset password for ${u.email}`} onClose={onClose} busy={busy}>
      <p>This ends every session {u.email} has. They will sign in with the temporary password below and must then choose their own. You will not see it again after you save, so note it down first.</p>
      <Field label="Temporary password" error={problem}>{(p) => <PasswordInput id={p.id} describedBy={p['aria-describedby']} value={pw} onChange={setPw} />}</Field>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="danger" onClick={go} busy={busy}>Reset password</Button></div>
    </Dialog>
  );
}

type Pending = { u: UserRow; kind: 'role'; role: string } | { u: UserRow; kind: 'active'; active: boolean };

export default function AdminUsersPage() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const users = useUsers();
  const [creating, setCreating] = useState(false);
  const [reset, setReset] = useState<UserRow | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<string | null>(null);

  const confirm = async () => {
    if (!pending) return;
    setBusy(true); setError(null);
    try {
      await updateUser(pending.u.id, pending.kind === 'role' ? { role: pending.role } : { isActive: pending.active });
      await qc.invalidateQueries({ queryKey: ['users'] }); await qc.invalidateQueries({ queryKey: ['assignees'] });
      const m = pending.kind === 'role' ? `${pending.u.email} is now ${ROLE_LABEL[pending.role as keyof typeof ROLE_LABEL]}.` : `${pending.u.email} is now ${pending.active ? 'active' : 'deactivated'}.`;
      setDone(m); announce(m); setPending(null);
    } catch (e) { setError(e); } finally { setBusy(false); }
  };

  return (
    <div className="stack">
      <div className="page-head"><h1>Users</h1><Button variant="primary" onClick={() => setCreating(true)}>Create an account</Button></div>
      <Notice title="Safeguards"><ul><li>You cannot change your own role or deactivate yourself.</li><li>The last active super admin can never be demoted or deactivated.</li><li>Deactivating an account, or resetting its password, ends all of its sessions.</li></ul></Notice>
      {done && <Notice tone="ok">{done}</Notice>}
      <QueryState query={users} skeleton={<Skeleton lines={6} height="2.2rem" />}>
        {(r) => (
          <ResponsiveTable caption="Accounts" rows={r.data} rowKey={(u) => u.id}
            columns={[
              { key: 'e', header: 'Account', cell: (u) => <span><strong>{u.name || u.email}</strong>{u.name && <><br /><span className="muted small">{u.email}</span></>}{u.id === me?.id && <span className="badge role-badge" style={{ marginLeft: '.4rem' }}>You</span>}</span> },
              { key: 'r', header: 'Role', cell: (u) => u.id === me?.id ? <span>{ROLE_LABEL[u.role]}<br /><span className="hint">You cannot change your own role.</span></span> : (
                <select aria-label={`Role for ${u.email}`} value={u.role} onChange={(e) => { setError(null); setPending({ u, kind: 'role', role: e.target.value }); }}>{ROLE_LIST.map((x) => <option key={x} value={x}>{ROLE_LABEL[x]}</option>)}</select>) },
              { key: 's', header: 'Status', cell: (u) => (u.isActive ? <span className="badge ok">Active</span> : <span className="badge sev-high">Deactivated</span>) },
              { key: 'l', header: 'Last sign-in', cell: (u) => (u.lastLoginAt ? ageLabel(u.lastLoginAt) : 'never') },
              { key: 'p', header: 'Password', cell: (u) => (u.mustChangePassword ? 'Must be changed' : 'Set') },
              { key: 'a', header: 'Actions', cell: (u) => u.id === me?.id ? <span className="hint">Use the account menu to change your own password.</span> : (
                <span className="toolbar">
                  <Button onClick={() => { setError(null); setPending({ u, kind: 'active', active: !u.isActive }); }}>{u.isActive ? 'Deactivate' : 'Reactivate'}<span className="sr-only"> {u.email}</span></Button>
                  <Button onClick={() => setReset(u)}>Reset password<span className="sr-only"> for {u.email}</span></Button>
                </span>) },
            ]} />
        )}
      </QueryState>
      {creating && <CreateUserDialog onClose={() => setCreating(false)} />}
      {reset && <ResetDialog u={reset} onClose={() => setReset(null)} onDone={(m) => { setDone(m); announce(m); void qc.invalidateQueries({ queryKey: ['users'] }); }} />}
      {pending && (
        <ConfirmDialog
          title={pending.kind === 'role' ? `Change ${pending.u.email} to ${ROLE_LABEL[pending.role as keyof typeof ROLE_LABEL]}?` : pending.active ? `Reactivate ${pending.u.email}?` : `Deactivate ${pending.u.email}?`}
          confirmLabel={pending.kind === 'role' ? 'Change role' : pending.active ? 'Reactivate' : 'Deactivate'} danger={pending.kind === 'active' && !pending.active}
          busy={busy} error={error} onConfirm={() => void confirm()} onClose={() => { setPending(null); setError(null); }}>
          {pending.kind === 'role'
            ? <p>{ROLE_HELP[pending.role]} This applies straight away, on their next action.</p>
            : pending.active ? <p>They will be able to sign in again.</p> : <p>They are signed out everywhere now and cannot sign in until you reactivate the account.</p>}
        </ConfirmDialog>
      )}
    </div>
  );
}
