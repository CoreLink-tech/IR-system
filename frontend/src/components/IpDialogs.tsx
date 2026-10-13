import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { allowIp, unallowIp, unblockIp } from '@/api/actions';
import { Button, ConfirmDialog, ErrorPanel, Field } from './ui';
import { Dialog } from './Dialog';
import { announce } from './announce';
import { ENFORCEMENT_NOTE } from './BlockDialog';

const KEYS = ['blocked-ips', 'block-history', 'allowlist', 'ip', 'ips', 'technical-report', 'incident-report'];
const useRefresh = () => { const qc = useQueryClient(); return () => Promise.all(KEYS.map((k) => qc.invalidateQueries({ queryKey: [k] }))); };

export function UnblockDialog({ ip, onClose }: { ip: string; onClose: () => void }) {
  const refresh = useRefresh();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const go = async () => {
    if (!reason.trim()) return setProblem('A reason is required. It is kept in the audit log.');
    setProblem(null); setBusy(true); setError(null);
    try { await unblockIp(ip, reason.trim()); await refresh(); announce(`${ip} is no longer blocked`); onClose(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <Dialog title="Unblock this address?" onClose={onClose} busy={busy}>
      <p>Visitors from <strong className="mono">{ip}</strong> will be allowed back in. {ENFORCEMENT_NOTE}</p>
      <Field label="Reason" error={problem}>{(p) => <textarea {...p} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />}</Field>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" onClick={go} busy={busy}>Unblock</Button></div>
    </Dialog>
  );
}

const ALLOW_FOR: Array<{ v: string; label: string }> = [
  { v: '', label: 'Until I remove it' }, { v: '60', label: '1 hour' }, { v: '1440', label: '24 hours' }, { v: '10080', label: '7 days' }, { v: '43200', label: '30 days' },
];

export function AllowDialog({ ip, onClose }: { ip?: string; onClose: () => void }) {
  const refresh = useRefresh();
  const [address, setAddress] = useState(ip ?? '');
  const [reason, setReason] = useState('');
  const [ttl, setTtl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const go = async () => {
    if (!address.trim() || !reason.trim()) return setProblem('Enter the address and a reason.');
    setProblem(null); setBusy(true); setError(null);
    try { await allowIp(address.trim(), reason.trim(), ttl ? Number(ttl) : undefined); await refresh(); announce(`${address.trim()} is on the allowlist`); onClose(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <Dialog title="Add to the allowlist" onClose={onClose} busy={busy}>
      <p>An address on the allowlist can never be blocked, and its current block is lifted. Use this for your own office, partners and monitoring services.</p>
      {!ip && <Field label="Address">{(p) => <input {...p} type="text" value={address} onChange={(e) => setAddress(e.target.value)} />}</Field>}
      {ip && <p>Address: <strong className="mono">{ip}</strong></p>}
      <Field label="For how long">{(p) => <select {...p} value={ttl} onChange={(e) => setTtl(e.target.value)}>{ALLOW_FOR.map((d) => <option key={d.v} value={d.v}>{d.label}</option>)}</select>}</Field>
      <Field label="Reason" error={problem}>{(p) => <textarea {...p} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />}</Field>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" onClick={go} busy={busy}>Add to allowlist</Button></div>
    </Dialog>
  );
}

export function RemoveAllowDialog({ ip, onClose }: { ip: string; onClose: () => void }) {
  const refresh = useRefresh();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true); setError(null);
    try { await unallowIp(ip); await refresh(); announce(`${ip} removed from the allowlist`); onClose(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  return (
    <ConfirmDialog title="Remove from the allowlist?" confirmLabel="Remove" danger busy={busy} error={error} onConfirm={go} onClose={onClose}>
      <p><strong className="mono">{ip}</strong> will no longer be protected from blocking. It can be blocked again, automatically or by an administrator.</p>
    </ConfirmDialog>
  );
}
