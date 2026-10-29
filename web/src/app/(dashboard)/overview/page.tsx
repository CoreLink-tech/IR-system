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
  sourceIp?: string | null;
  createdAt?: string | number;
  updatedAt?: string | number;
};
type EventRow = {
  id: string;
  eventType: string;
  severity: string;
  ipAddress?: string | null;
  riskScore?: number;
  createdAt?: string | number;
};

function severityClass(sev: string) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'sev';
  if (s === 'HIGH') return 'sev high';
  if (s === 'MEDIUM') return 'sev medium';
  return 'sev low';
}

function statusPill(status: string) {
  const s = (status || '').toUpperCase();
  if (s === 'OPEN') return 'badge badge-critical';
  if (s === 'INVESTIGATING') return 'badge badge-high';
  if (s === 'CONTAINED') return 'badge badge-medium';
  if (s === 'RESOLVED') return 'badge badge-low';
  return 'badge badge-neutral';
}

function formatTime(ts?: string | number | null) {
  if (ts == null) return '—';
  const d = typeof ts === 'number' ? new Date(ts) : new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function OverviewPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const [healthRes, incidentsRes, eventsRes] = await Promise.allSettled([
          fetch('/api/v1/health/ready').then((r) => r.json()),
          api<{ data: Incident[] }>('/incidents?pageSize=8'),
          api<{ data: EventRow[] }>('/events?pageSize=10'),
        ]);
        if (cancelled) return;
        if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
        if (incidentsRes.status === 'fulfilled') setIncidents(incidentsRes.value.data ?? []);
        if (eventsRes.status === 'fulfilled') setEvents(eventsRes.value.data ?? []);
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
  const criticalCount = incidents.filter((i) => (i.severity || '').toUpperCase() === 'CRITICAL').length;

  return (
    <div>
      {/* Page head */}
      <div className="mb-[23px] flex flex-wrap items-start justify-between gap-5">
        <div>
          <div className="kicker">Security operations</div>
          <h1 className="m-0 text-[27px] font-[750] leading-[1.15] tracking-[-0.9px]">Overview</h1>
          <p className="mt-2 text-[13px] text-[#718079]">
            Security posture and recent activity across your workspace.
          </p>
          <div className="mt-[13px] flex items-center gap-[7px] text-[11px] text-[#5e7066]">
            <span className={`inline-block h-[7px] w-[7px] rounded-full ${health?.status === 'ready' ? 'bg-[#2d9368]' : 'bg-[#98651f]'}`} />
            <span>
              {health?.status === 'ready'
                ? `System status: operational${health.database ? ` · ${health.database}` : ''}`
                : `System status: ${health?.status || 'checking…'}`}
            </span>
          </div>
        </div>
      </div>

      {/* Metrics */}
      <div className="mb-[18px] grid grid-cols-2 gap-[13px] lg:grid-cols-4">
        {[
          {
            label: 'Open incidents',
            value: loading ? '—' : String(openIncidents.length),
            foot: criticalCount > 0 ? <><strong>{criticalCount} critical</strong> · need attention</> : 'Active cases',
          },
          {
            label: 'Recent events',
            value: loading ? '—' : String(events.length),
            foot: 'Latest sample from API',
          },
          {
            label: 'Critical severity',
            value: loading ? '—' : String(criticalCount).padStart(2, '0'),
            foot: 'Across current incidents',
          },
          {
            label: 'API status',
            value: health?.status === 'ready' ? 'Ready' : health?.status || '…',
            foot: health?.database || 'Database connection',
            valueClass: 'text-[23px]',
          },
        ].map((m) => (
          <div key={m.label} className="metric">
            <div className="metric-label">{m.label}</div>
            <div className={`metric-value ${m.valueClass || ''}`}>{m.value}</div>
            <div className="metric-foot">{m.foot}</div>
          </div>
        ))}
      </div>

      {/* Incidents table */}
      <section className="mb-4 surface">
        <div className="flex items-center justify-between gap-3 border-b border-[#eaf0ec] px-[17px] py-[15px]">
          <div>
            <div className="text-[12px] font-[750]">Recent incidents</div>
            <div className="mt-1 text-[10px] text-[#718079]">Latest incidents recorded by Watcher</div>
          </div>
          <Link href="/incidents" className="text-[10px] font-[750] text-[#176b52] hover:underline">
            All incidents
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source IP</th>
                <th>Updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#718079]">Loading…</td>
                </tr>
              )}
              {!loading && incidents.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#718079]">
                    No incidents yet. Events from client sites will create incidents when rules match.
                  </td>
                </tr>
              )}
              {incidents.slice(0, 6).map((inc) => (
                <tr key={inc.id}>
                  <td>
                    <strong>#{inc.publicNumber}</strong>
                    &nbsp;&nbsp;{inc.title}
                  </td>
                  <td>
                    <span className={severityClass(inc.severity)}>{inc.severity}</span>
                  </td>
                  <td>
                    <span className={statusPill(inc.status)}>{inc.status}</span>
                  </td>
                  <td className="mono">{inc.sourceIp || '—'}</td>
                  <td className="text-[#718079]">{formatTime(inc.updatedAt || inc.createdAt)}</td>
                  <td>
                    <Link href={`/incidents/${inc.id}`} className="text-[10px] font-[750] text-[#176b52] hover:underline">
                      Details
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Events + Quick actions */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="surface">
          <div className="flex items-center justify-between border-b border-[#eaf0ec] px-[17px] py-[15px]">
            <div>
              <div className="text-[12px] font-[750]">Recent event stream</div>
              <div className="mt-1 text-[10px] text-[#718079]">Latest activity across the system</div>
            </div>
            <Link href="/ips" className="text-[10px] font-[750] text-[#176b52] hover:underline">
              Inspect events
            </Link>
          </div>
          <div className="px-[17px] py-1">
            {loading && <div className="py-6 text-center text-sm text-[#718079]">Loading…</div>}
            {!loading && events.length === 0 && (
              <div className="py-6 text-center text-sm text-[#718079]">No events ingested yet</div>
            )}
            {events.slice(0, 6).map((ev) => (
              <div
                key={ev.id}
                className="grid grid-cols-[28px_1fr_auto] items-start gap-[10px] border-b border-[#edf1ee] py-[13px] last:border-0"
              >
                <div className="grid h-[27px] w-[27px] place-items-center rounded-[4px] border border-[#e0e7e3] text-[#176b52]">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                    <path d="M12 3L21 20H3Z" />
                  </svg>
                </div>
                <div>
                  <strong className="text-[11px] font-bold">{ev.eventType}</strong>
                  <small className="mt-1 block text-[10px] text-[#718079]">
                    {ev.ipAddress || '—'} · {ev.severity}
                    {ev.riskScore != null ? ` · risk ${ev.riskScore}` : ''}
                  </small>
                </div>
                <time className="whitespace-nowrap text-[9px] text-[#8a9690]">
                  {formatTime(ev.createdAt)}
                </time>
              </div>
            ))}
          </div>
        </section>

        <section className="surface">
          <div className="border-b border-[#eaf0ec] px-[17px] py-[15px]">
            <div className="text-[12px] font-[750]">Quick actions</div>
            <div className="mt-1 text-[10px] text-[#718079]">Common administration tasks</div>
          </div>
          <div className="px-[17px]">
            {[
              { href: '/blocking', title: 'Manage blocklist', desc: 'Review blocked IP addresses', icon: 'block' },
              { href: '/allowlist', title: 'Manage allowlist', desc: 'Maintain trusted sources', icon: 'check' },
              { href: '/admin/api-keys', title: 'API keys', desc: 'Review integration credentials', icon: 'key' },
              { href: '/admin/rules', title: 'Detection rules', desc: 'Review active controls', icon: 'rules' },
            ].map((a) => (
              <Link
                key={a.href}
                href={a.href}
                className="flex w-full items-center gap-[11px] border-b border-[#edf1ee] py-[13px] text-left last:border-0 hover:bg-[#fafcfb]"
              >
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#176b52" strokeWidth="1.7">
                  {a.icon === 'block' && (<><circle cx="12" cy="12" r="9"/><path d="M6 6L18 18"/></>)}
                  {a.icon === 'check' && <path d="M5 12L10 17L20 6"/>}
                  {a.icon === 'key' && (<><circle cx="8" cy="15" r="5"/><path d="M12 11L21 2"/></>)}
                  {a.icon === 'rules' && <path d="M4 7H20M4 12H20M4 17H20"/>}
                </svg>
                <span>
                  <strong className="block text-[11px]">{a.title}</strong>
                  <small className="mt-[3px] block text-[10px] text-[#718079]">{a.desc}</small>
                </span>
              </Link>
            ))}
          </div>
        </section>
      </div>

      <div className="mt-[18px] text-[9px] text-[#8a9690]">
        Watcher by ZenLink Technologies
      </div>
    </div>
  );
}
