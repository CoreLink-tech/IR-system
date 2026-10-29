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
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api<{ incident: Incident; events: Ev[] }>(`/incidents/${id}`)
      .then((r) => {
        setIncident(r.incident);
        setEvents(r.events || []);
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    void load();
  }, [id]);

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
