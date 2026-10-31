'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

type Incident = {
  id: string;
  publicNumber: number;
  title: string;
  status: string;
  severity: string;
  sourceIp: string | null;
  riskScore: number;
  eventCount: number;
  summary: string | null;
  assignedTo: string | null;
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
};

type Ev = { id: string; eventType: string; severity: string; riskScore: number; createdAt: string };
type Note = { id: string; body: string; authorId: string | null; createdAt: string };
type Hist = { id: string; fromStatus: string | null; toStatus: string; createdAt: string };

const STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

function severityBadge(sev: string) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'badge badge-critical';
  if (s === 'HIGH') return 'badge badge-high';
  if (s === 'MEDIUM') return 'badge badge-medium';
  if (s === 'LOW') return 'badge badge-low';
  return 'badge badge-neutral';
}

function statusBadge(status: string) {
  const s = (status || '').toUpperCase();
  if (s === 'OPEN') return 'badge badge-critical';
  if (s === 'INVESTIGATING') return 'badge badge-high';
  if (s === 'CONTAINED') return 'badge badge-medium';
  if (s === 'RESOLVED') return 'badge badge-low';
  return 'badge badge-neutral';
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [events, setEvents] = useState<Ev[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [history, setHistory] = useState<Hist[]>([]);
  const [noteBody, setNoteBody] = useState('');
  const [assignee, setAssignee] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api<{ incident: Incident; events: Ev[]; notes?: Note[]; history?: Hist[] }>(`/incidents/${id}`)
      .then((r) => {
        setIncident(r.incident);
        setEvents(r.events || []);
        setNotes(r.notes || []);
        setHistory(r.history || []);
        setAssignee(r.incident.assignedTo || '');
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps -- load reads latest state each call

  async function setStatus(status: string) {
    setBusy(true);
    setError(null);
    try {
      await api(`/incidents/${id}`, { method: 'PATCH', json: { status } });
      await load();
    } catch (e: unknown) {
      setError(e instanceof ApiError ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  if (error && !incident) {
    return (
      <div className="space-y-3">
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
        <Link href="/incidents" className="text-sm text-[var(--accent)] hover:underline">
          ← Back to incidents
        </Link>
      </div>
    );
  }

  if (!incident) {
    return <div className="py-12 text-center text-sm text-[var(--text-muted)]">Loading…</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link href="/incidents" className="text-xs text-[var(--text-muted)] hover:text-[var(--accent)]">
            ← Incidents
          </Link>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">
            #{incident.publicNumber} · {incident.title}
          </h1>
          <div className="mt-2 flex flex-wrap gap-2">
            <span className={severityBadge(incident.severity)}>{incident.severity}</span>
            <span className={statusBadge(incident.status)}>{incident.status}</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      {/* Summary metrics */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Source IP', value: incident.sourceIp || '—', mono: true },
          { label: 'Risk Score', value: String(incident.riskScore) },
          { label: 'Events', value: String(incident.eventCount) },
          {
            label: 'Opened',
            value: new Date(incident.createdAt).toLocaleString(undefined, {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            }),
          },
        ].map((m) => (
          <div key={m.label} className="surface p-4">
            <div className="text-xs text-[var(--text-secondary)]">{m.label}</div>
            <div className={`mt-1 text-sm font-medium ${m.mono ? 'mono' : 'tabular-nums'}`}>
              {m.value}
            </div>
          </div>
        ))}
      </div>

      {incident.summary && (
        <div className="surface p-4">
          <div className="text-xs font-medium text-[var(--text-secondary)]">Summary</div>
          <p className="mt-1 text-sm">{incident.summary}</p>
        </div>
      )}

      {/* Status actions */}
      <div className="surface p-4">
        <div className="mb-3 text-sm font-medium">Update status</div>
        <div className="flex flex-wrap gap-2">
          {STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              disabled={busy || incident.status === s}
              className={`btn text-xs ${incident.status === s ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => void setStatus(s)}
            >
              {s.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>


      <div className="surface p-4 space-y-3">
        <div className="text-sm font-medium">Assignment</div>
        <div className="flex flex-wrap gap-2">
          <input
            className="rounded border border-[var(--border)] bg-transparent px-3 py-1.5 text-sm"
            placeholder="Assignee user id or email"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
          />
          <button
            type="button"
            className="btn btn-secondary text-xs"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api(`/incidents/${id}`, { method: 'PATCH', json: { assignedTo: assignee || null } });
                await load();
              } catch (e: unknown) {
                setError(e instanceof ApiError ? e.message : 'Failed');
              } finally {
                setBusy(false);
              }
            }}
          >
            Save assignee
          </button>
        </div>
      </div>

      <div className="surface p-4 space-y-3">
        <div className="text-sm font-medium">Notes</div>
        <ul className="space-y-2 text-sm">
          {notes.map((n) => (
            <li key={n.id} className="border-b border-[var(--border)] pb-2">
              <p>{n.body}</p>
              <p className="text-xs text-[var(--text-muted)]">{new Date(n.createdAt).toLocaleString()}</p>
            </li>
          ))}
          {notes.length === 0 && <li className="text-[var(--text-muted)]">No notes yet.</li>}
        </ul>
        <textarea
          className="w-full rounded border border-[var(--border)] bg-transparent px-3 py-2 text-sm"
          rows={3}
          placeholder="Add a note…"
          value={noteBody}
          onChange={(e) => setNoteBody(e.target.value)}
        />
        <button
          type="button"
          className="btn btn-primary text-xs"
          disabled={busy || !noteBody.trim()}
          onClick={async () => {
            setBusy(true);
            try {
              await api(`/incidents/${id}/notes`, { method: 'POST', json: { body: noteBody.trim() } });
              setNoteBody('');
              await load();
            } catch (e: unknown) {
              setError(e instanceof ApiError ? e.message : 'Failed');
            } finally {
              setBusy(false);
            }
          }}
        >
          Add note
        </button>
      </div>

      {history.length > 0 && (
        <div className="surface p-4">
          <div className="mb-2 text-sm font-medium">Status history</div>
          <ul className="space-y-1 text-xs text-[var(--text-secondary)]">
            {history.map((h) => (
              <li key={h.id}>
                {(h.fromStatus || '—')} → {h.toStatus} · {new Date(h.createdAt).toLocaleString()}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related events */}
      <div className="surface">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold">Related Events</h2>
        </div>
        {events.length === 0 ? (
          <div className="p-6 text-center text-sm text-[var(--text-muted)]">No events linked</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="font-medium">{e.eventType}</td>
                    <td>
                      <span className={severityBadge(e.severity)}>{e.severity}</span>
                    </td>
                    <td className="tabular-nums">{e.riskScore}</td>
                    <td className="text-xs text-[var(--text-muted)]">
                      {new Date(e.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {incident.sourceIp && (
        <div>
          <Link
            href={`/ips/${encodeURIComponent(incident.sourceIp)}`}
            className="text-sm text-[var(--accent)] hover:underline"
          >
            Investigate source IP {incident.sourceIp} →
          </Link>
        </div>
      )}
    </div>
  );
}
