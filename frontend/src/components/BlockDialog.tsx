import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { blockIp } from '@/api/actions';
import { Button, ErrorPanel, Field } from './ui';
import { Dialog } from './Dialog';
import { announce } from './announce';

export const ENFORCEMENT_NOTE = 'The website applies blocks within about 30 seconds. Blocks are recorded by this system. It cannot confirm that the website actually rejected the traffic.';

const DURATIONS: Array<{ v: string; label: string; minutes?: number }> = [
  { v: '15', label: '15 minutes', minutes: 15 }, { v: '60', label: '1 hour', minutes: 60 }, { v: '1440', label: '24 hours', minutes: 1440 },
  { v: '10080', label: '7 days', minutes: 10080 }, { v: '43200', label: '30 days', minutes: 43200 }, { v: 'permanent', label: 'Permanently, until someone unblocks it' },
];

/** Blocks an address. Waits for the server and shows its refusal in plain words if it says no. */
export function BlockDialog({ ip, incidentId, onClose, onDone }: { ip?: string; incidentId?: string; onClose: () => void; onDone?: () => void }) {
  const qc = useQueryClient();
  const [address, setAddress] = useState(ip ?? '');
  const [reason, setReason] = useState('');
  const [duration, setDuration] = useState('60');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const perm = duration === 'permanent';
  const label = DURATIONS.find((d) => d.v === duration)?.label ?? '';

  const submit = async () => {
    if (!address.trim()) return setProblem('Enter the address to block.');
    if (!reason.trim()) return setProblem('A reason is required. It is kept in the audit log.');
    setProblem(null); setBusy(true); setError(null);
    try {
      await blockIp({ ipAddress: address.trim(), reason: reason.trim(), ...(perm ? { permanent: true } : { ttlMinutes: Number(duration) }), ...(incidentId ? { relatedIncidentId: incidentId } : {}) });
      await Promise.all(['blocked-ips', 'block-history', 'ip', 'ips', 'incident', 'technical-report', 'incident-report'].map((k) => qc.invalidateQueries({ queryKey: [k] })));
      announce(`${address.trim()} is now blocked`);
      onDone?.(); onClose();
    } catch (e) { setError(e); } finally { setBusy(false); }
  };

  return (
    <Dialog title="Block an address" onClose={onClose} busy={busy}>
      {!ip && <Field label="Address" error={problem && !address.trim() ? problem : null}>{(p) => <input {...p} type="text" value={address} onChange={(e) => setAddress(e.target.value)} />}</Field>}
      {ip && <p>Address: <strong className="mono">{ip}</strong></p>}
      <Field label="How long">{(p) => <select {...p} value={duration} onChange={(e) => setDuration(e.target.value)}>{DURATIONS.map((d) => <option key={d.v} value={d.v}>{d.label}</option>)}</select>}</Field>
      <Field label="Reason" hint="Required. Say why, so whoever reads the audit log understands." error={problem && address.trim() ? problem : null}>{(p) => <textarea {...p} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />}</Field>
      <div className="notice"><strong>What this does</strong><p style={{ margin: '.3rem 0 0' }}>Visitors from {address.trim() || 'this address'} will be turned away {perm ? 'permanently' : `for ${label}`}. {ENFORCEMENT_NOTE}</p></div>
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="danger" onClick={submit} busy={busy}>Block address</Button></div>
    </Dialog>
  );
}
