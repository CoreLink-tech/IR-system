'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
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

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
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
      <div className="space-y-2">
        <p className="text-red-600">{error}</p>
        <Link href="/incidents" className="text-blue-700 underline">Back to incidents</Link>
      </div>
    );
  }
  if (!incident) return <p className="text-neutral-500">Loading…</p>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link href="/incidents" className="text-sm text-blue-700 underline">← Incidents</Link>
          <h1 className="mt-1 text-2xl font-semibold">
            #{incident.publicNumber} · {incident.title}
          </h1>
        </div>
        <div className="flex flex-wrap gap-2">
          {STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              disabled={busy || incident.status === s}
              className={`rounded px-3 py-1 text-sm ${
                incident.status === s ? 'bg-blue-600 text-white' : 'border bg-white hover:bg-neutral-50'
              } disabled:opacity-50`}
              onClick={() => void setStatus(s)}
            >
              {s.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="text-red-600">{error}</p>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card label="Status" value={incident.status} />
        <Card label="Severity" value={incident.severity} />
        <Card label="Risk" value={String(incident.riskScore)} />
        <Card label="Events" value={String(incident.eventCount)} />
        <Card label="Source IP" value={incident.sourceIp || '—'} mono />
        <Card label="Opened" value={new Date(incident.createdAt).toLocaleString()} />
        <Card label="Updated" value={new Date(incident.updatedAt).toLocaleString()} />
        <Card label="Resolved" value={incident.resolvedAt ? new Date(incident.resolvedAt).toLocaleString() : '—'} />
      </div>
      {incident.sourceIp && (
        <div className="flex gap-3 text-sm">
          <button
            type="button"
            className="rounded bg-red-600 px-3 py-1.5 text-white"
            onClick={async () => {
              if (!window.confirm(`Block ${incident.sourceIp}?`)) return;
              try {
                await api('/security/block', {
                  method: 'POST',
                  json: { ipAddress: incident.sourceIp, reason: `Incident #${incident.publicNumber}` },
                });
                router.push('/blocking');
              } catch (e: unknown) {
                setError(e instanceof ApiError ? e.message : 'Block failed');
              }
            }}
          >
            Block source IP
          </button>
        </div>
      )}
      <div>
        <h2 className="mb-2 text-lg font-medium">Related events</h2>
        <div className="overflow-x-auto rounded-lg border bg-white">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b bg-neutral-50 text-neutral-600">
              <tr>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">When</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-b last:border-0">
                  <td className="px-3 py-2">{e.eventType}</td>
                  <td className="px-3 py-2">{e.severity}</td>
                  <td className="px-3 py-2">{e.riskScore}</td>
                  <td className="px-3 py-2 text-neutral-500">{new Date(e.createdAt).toLocaleString()}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-center text-neutral-500">No events linked.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Card({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border bg-white p-3 shadow-sm">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className={`mt-1 ${mono ? 'font-mono text-sm' : 'font-medium'}`}>{value}</div>
    </div>
  );
}
