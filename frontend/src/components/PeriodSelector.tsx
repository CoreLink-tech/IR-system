import { useState } from 'react';
import { Button, Field } from './ui';
import type { Period } from '@/api/hooks';

const PRESETS: Array<{ id: string; label: string; days: number }> = [
  { id: '1', label: 'Last 24 hours', days: 1 }, { id: '7', label: 'Last 7 days', days: 7 }, { id: '30', label: 'Last 30 days', days: 30 },
];

export function periodLabel(p: Period): string {
  if (p.from && p.to) return `${p.from.slice(0, 10)} to ${p.to.slice(0, 10)}`;
  return PRESETS.find((x) => x.days === (p.days ?? 7))?.label ?? `Last ${p.days} days`;
}

/** 24 hours, 7 days, 30 days, or a custom range. The server checks the range; this only collects it. */
export function PeriodSelector({ value, onChange }: { value: Period; onChange: (p: Period) => void }) {
  const custom = !!(value.from && value.to);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(custom);
  const apply = () => {
    const f = new Date(from), t = new Date(to);
    if (!from || !to || Number.isNaN(f.getTime()) || Number.isNaN(t.getTime())) return setError('Choose both a start and an end.');
    if (t <= f) return setError('The end must be after the start.');
    setError(null);
    onChange({ from: f.toISOString(), to: t.toISOString() });
  };
  return (
    <div className="no-print">
      <div className="toolbar" role="group" aria-label="Time period">
        {PRESETS.map((p) => (
          <Button key={p.id} variant={!custom && (value.days ?? 7) === p.days ? 'primary' : undefined} aria-pressed={!custom && (value.days ?? 7) === p.days} onClick={() => { setOpen(false); onChange({ days: p.days }); }}>{p.label}</Button>
        ))}
        <Button variant={custom ? 'primary' : undefined} aria-pressed={custom} aria-expanded={open} onClick={() => setOpen((o) => !o)}>Custom range</Button>
      </div>
      {open && (
        <div className="filters" style={{ marginTop: '.5rem' }}>
          <Field label="From">{(p) => <input type="datetime-local" {...p} value={from} onChange={(e) => setFrom(e.target.value)} />}</Field>
          <Field label="To" error={error}>{(p) => <input type="datetime-local" {...p} value={to} onChange={(e) => setTo(e.target.value)} />}</Field>
          <Button variant="primary" onClick={apply}>Show this period</Button>
        </div>
      )}
    </div>
  );
}
