'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/client-api';

type Health = { status?: string; database?: string };
type Incident = {
  id: string;
  publicNumber: number;
  title: string;
  status: string;
  severity: string;
  createdAt?: string | number;
  updatedAt?: string | number;
};
type EventRow = {
  id: string;
  eventType: string;
  severity: string;
  ipAddress?: string | null;
  riskScore?: number;
  riskLevel?: string;
  createdAt?: string | number;
};

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
  if (s === 'FALSE_POSITIVE') return 'badge badge-neutral';
  return 'badge badge-neutral';
}

function formatTime(ts?: string | number | null) {
  if (ts == null) return '—';
  const d = typeof ts === 'number' ? new Date(ts) : new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function OverviewPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [healthRes, incidentsRes, eventsRes] = await Promise.allSettled([
          fetch('/api/v1/health/ready').then((r) => r.json()),
          api<{ data: Incident[] }>('/incidents?pageSize=8'),
          api<{ data: EventRow[] }>('/events?pageSize=10'),
        ]);

        if (cancelled) return;

        if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
        else setHealth({ status: 'error' });

        if (incidentsRes.status === 'fulfilled') {
          setIncidents(incidentsRes.value.data ?? []);
        }
        if (eventsRes.status === 'fulfilled') {
          setEvents(eventsRes.value.data ?? []);
        }
      } catch {
        if (!cancelled) setError('Failed to load dashboard data');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const openIncidents = incidents.filter((i) =>
    ['OPEN', 'INVESTIGATING', 'CONTAINED'].includes((i.status || '').toUpperCase()),
  );
  const criticalCount = incidents.filter((i) =>
    (i.severity || '').toUpperCase() === 'CRITICAL',
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
            Security posture and recent activity
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
          {health?.status === 'ready' ? (
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--success)]" />
              System ready
              {health.database ? ` · ${health.database}` : ''}
            </span>
          ) : (
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--warning)]" />
              {health?.status || 'Checking…'}
            </span>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      {/* Metric cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: 'Open Incidents',
            value: loading ? '—' : openIncidents.length,
            sub: criticalCount > 0 ? `${criticalCount} critical` : 'Active cases',
            href: '/incidents',
          },
          {
            label: 'Recent Events',
            value: loading ? '—' : events.length,
            sub: 'Latest sample',
            href: '/ips',
          },
          {
            label: 'Critical Severity',
            value: loading ? '—' : criticalCount,
            sub: 'Across incidents',
            href: '/incidents',
          },
          {
            label: 'API Status',
            value: health?.status === 'ready' ? 'Ready' : health?.status || '…',
            sub: health?.database || 'Database',
            href: null,
          },
        ].map((m) => (
          <div key={m.label} className="surface p-4">
            <div className="text-xs font-medium text-[var(--text-secondary)]">{m.label}</div>
            <div className="mt-1 text-2xl font-semibold tracking-tight tabular-nums">
              {m.value}
            </div>
            <div className="mt-1 flex items-center justify-between">
              <span className="text-[11px] text-[var(--text-muted)]">{m.sub}</span>
              {m.href && (
                <Link href={m.href} className="text-[11px] text-[var(--accent)] hover:underline">
                  View →
                </Link>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Recent incidents */}
        <div className="surface">
          <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
            <h2 className="text-sm font-semibold">Recent Incidents</h2>
            <Link href="/incidents" className="text-xs text-[var(--accent)] hover:underline">
              View all
            </Link>
          </div>
          {loading ? (
            <div className="p-6 text-center text-sm text-[var(--text-muted)]">Loading…</div>
          ) : incidents.length === 0 ? (
            <div className="p-6 text-center text-sm text-[var(--text-muted)]">
              No incidents yet
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {incidents.slice(0, 6).map((inc) => (
                <Link
                  key={inc.id}
                  href={`/incidents/${inc.id}`}
                  className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-[var(--bg-hover)]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">
                      #{inc.publicNumber} {inc.title}
                    </div>
                    <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                      {formatTime(inc.createdAt || inc.updatedAt)}
                    </div>
                  </div>
                  <span className={severityBadge(inc.severity)}>{inc.severity}</span>
                  <span className={statusBadge(inc.status)}>{inc.status}</span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Recent events */}
        <div className="surface">
          <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
            <h2 className="text-sm font-semibold">Recent Events</h2>
          </div>
          {loading ? (
            <div className="p-6 text-center text-sm text-[var(--text-muted)]">Loading…</div>
          ) : events.length === 0 ? (
            <div className="p-6 text-center text-sm text-[var(--text-muted)]">
              No events ingested yet
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>IP</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 8).map((ev) => (
                    <tr key={ev.id}>
                      <td className="font-medium">{ev.eventType}</td>
                      <td className="mono text-xs">{ev.ipAddress || '—'}</td>
                      <td>
                        <span className={severityBadge(ev.severity)}>{ev.severity}</span>
                      </td>
                      <td className="tabular-nums text-xs">
                        {ev.riskScore != null ? ev.riskScore : '—'}
                      </td>
                      <td className="text-xs text-[var(--text-muted)]">
                        {formatTime(ev.createdAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
