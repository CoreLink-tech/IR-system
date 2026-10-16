import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useApiKeys } from '@/api/hooks';
import { createApiKey, revokeApiKey, rotateApiKey } from '@/api/actions';
import type { ApiKeyCreated, ApiKeyRow } from '@/api/types';
import { Button, ConfirmDialog, ErrorPanel, Field, Notice, QueryState, Skeleton } from '@/components/ui';
import { Dialog } from '@/components/Dialog';
import { CopyButton } from '@/components/actions';
import { ResponsiveTable } from '@/components/table';
import { announce } from '@/components/announce';
import { Time } from '@/lib/time';
import { ageLabel } from '@/lib/format';

const SCOPES: Array<{ id: string; label: string; help: string }> = [
  { id: 'events:write', label: 'Send security events', help: 'Lets the website report what happens on it. The website needs this.' },
  { id: 'block:read', label: 'Read the blocked-address list', help: 'Lets the website ask who is blocked so it can turn them away. The website needs this too.' },
];
const EXPIRY: Array<{ v: string; label: string }> = [{ v: '', label: 'Never' }, { v: '30', label: '30 days' }, { v: '90', label: '90 days' }, { v: '365', label: '1 year' }];
const scopeLabel = (s: string) => SCOPES.find((x) => x.id === s)?.label ?? s;

/** The raw key, shown once. Nothing here is stored: closing the dialog discards it. */
function ShowOnceDialog({ created, title, onClose }: { created: ApiKeyCreated; title: string; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <Dialog title={title} onClose={() => { if (saved) onClose(); }}>
      <Notice title="This is the only time you will see this key"><p style={{ margin: '.3rem 0 0' }}>It is not stored in a form that can be shown again. Copy it now and put it in the website's settings. If you lose it, create a new one.</p></Notice>
      <p>Name: <strong>{created.name}</strong></p>
      <p className="secret mono" data-testid="raw-key">{created.apiKey}</p>
      <div className="toolbar"><CopyButton text={created.apiKey} label="Copy key" /></div>
      <label className="check"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> <span>I have copied the key and saved it somewhere safe</span></label>
      <div className="actions"><Button variant="primary" disabled={!saved} onClick={onClose}>Done</Button></div>
    </Dialog>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (c: ApiKeyCreated) => void }) {
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['events:write', 'block:read']);
  const [expiry, setExpiry] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const go = async () => {
    if (!name.trim()) return setProblem('Give the key a name, such as "Main website".');
    if (scopes.length === 0) return setProblem('Choose at least one thing the key may do.');
    setProblem(null); setBusy(true); setError(null);
    try { onCreated(await createApiKey({ name: name.trim(), scopes, ...(expiry ? { expiresInDays: Number(expiry) } : {}) })); onClose(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <Dialog title="Create an API key" onClose={onClose} busy={busy}>
      <Field label="Name" error={problem}>{(p) => <input {...p} type="text" value={name} onChange={(e) => setName(e.target.value)} />}</Field>
      <fieldset style={{ border: 0, padding: 0, margin: '0 0 .9rem' }}><legend style={{ fontWeight: 600 }}>What the key may do</legend>
        {SCOPES.map((s) => (
          <label key={s.id} className="check"><input type="checkbox" checked={scopes.includes(s.id)} onChange={(e) => setScopes(e.target.checked ? [...scopes, s.id] : scopes.filter((x) => x !== s.id))} /><span><strong>{s.label}</strong><br /><span className="hint">{s.help}</span></span></label>
        ))}
      </fieldset>
      <Field label="Expires">{(p) => <select {...p} value={expiry} onChange={(e) => setExpiry(e.target.value)}>{EXPIRY.map((x) => <option key={x.v} value={x.v}>{x.label}</option>)}</select>}</Field>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" onClick={go} busy={busy}>Create key</Button></div>
    </Dialog>
  );
}

export default function AdminApiKeysPage() {
  const qc = useQueryClient();
  const keys = useApiKeys();
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<{ c: ApiKeyCreated; title: string } | null>(null);
  const [act, setAct] = useState<{ k: ApiKeyRow; kind: 'rotate' | 'revoke' } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ['api-keys'] });

  const run = async () => {
    if (!act) return;
    setBusy(true); setError(null);
    try {
      if (act.kind === 'rotate') { const c = await rotateApiKey(act.k.id); setShown({ c, title: 'New key issued' }); announce('New key issued. The old key no longer works.'); }
      else { await revokeApiKey(act.k.id); announce('Key revoked'); }
      await refresh(); setAct(null);
    } catch (e) { setError(e); } finally { setBusy(false); }
  };

  return (
    <div className="stack">
      <div className="page-head"><h1>API keys</h1><Button variant="primary" onClick={() => setCreating(true)}>Create an API key</Button></div>
      <p className="muted">Keys are how the website talks to this system. The full key is shown once when you create it and never again.</p>
      <QueryState query={keys} skeleton={<Skeleton lines={5} height="2.2rem" />}>
        {(rows) => rows.length === 0 ? <div className="card muted">No keys yet.</div> : (
          <ResponsiveTable caption="API keys" rows={rows} rowKey={(k) => k.id}
            columns={[
              { key: 'n', header: 'Name', cell: (k) => <span><strong>{k.name}</strong><br /><code>{k.keyPrefix}...</code></span> },
              { key: 's', header: 'May do', cell: (k) => k.scopes.split(',').map(scopeLabel).join(', ') },
              { key: 'st', header: 'Status', cell: (k) => (k.revokedAt || !k.isActive ? <span className="badge sev-high">Revoked</span> : k.expiresAt && new Date(k.expiresAt).getTime() < Date.now() ? <span className="badge sev-medium">Expired</span> : <span className="badge ok">Active</span>) },
              { key: 'u', header: 'Last used', cell: (k) => (k.lastUsedAt ? ageLabel(k.lastUsedAt) : 'never') },
              { key: 'e', header: 'Expires', cell: (k) => (k.expiresAt ? <Time value={k.expiresAt} /> : 'never') },
              { key: 'a', header: 'Actions', cell: (k) => (k.revokedAt || !k.isActive ? <span className="muted">none</span> : (
                <span className="toolbar"><Button onClick={() => { setError(null); setAct({ k, kind: 'rotate' }); }}>Rotate<span className="sr-only"> {k.name}</span></Button><Button variant="danger" onClick={() => { setError(null); setAct({ k, kind: 'revoke' }); }}>Revoke<span className="sr-only"> {k.name}</span></Button></span>)) },
            ]} />
        )}
      </QueryState>
      {creating && <CreateDialog onClose={() => setCreating(false)} onCreated={(c) => { setShown({ c, title: 'Your new API key' }); void refresh(); }} />}
      {shown && <ShowOnceDialog created={shown.c} title={shown.title} onClose={() => setShown(null)} />}
      {act && (
        <ConfirmDialog title={act.kind === 'rotate' ? `Replace "${act.k.name}"?` : `Revoke "${act.k.name}"?`} confirmLabel={act.kind === 'rotate' ? 'Replace the key' : 'Revoke the key'} danger busy={busy} error={error} onConfirm={() => void run()} onClose={() => { setAct(null); setError(null); }}>
          {act.kind === 'rotate'
            ? <p>A new key with the same permissions is issued and the old one stops working immediately. Anything still using the old key, such as the website, will be refused until you give it the new one.</p>
            : <p>The key stops working immediately and cannot be turned back on. Anything using it, such as the website, will be refused.</p>}
        </ConfirmDialog>
      )}
    </div>
  );
}
