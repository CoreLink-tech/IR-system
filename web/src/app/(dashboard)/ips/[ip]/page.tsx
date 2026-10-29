'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

type EventRow = {
  id: string;
  eventType: string;
  severity: string;
  riskScore: number;
  createdAt: string;
};

type BlockRow = {
  id: string;
  reason: string;
  active: boolean;
  automatic: boolean;
  createdAt: string;
};

function severityBadge(sev: string) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'badge badge-critical';
  if (s === 'HIGH') return 'badge badge-high';
  if (s === 'MEDIUM') return 'badge badge-medium';
  if (s === 'LOW') return 'badge badge-low';
  return 'badge badge-neutral';
}

function riskBadge(level: string) {
  const s = (level || '').toUpperCase();
  if (s === 'CRITICAL') return 'badge badge-critical';
  if (s === 'HIGH') return 'badge badge-high';
  if (s === 'MEDIUM' || s === 'SUSPICIOUS') return 'badge badge-medium';
  if (s === 'LOW') return 'badge badge-low';
  return 'badge badge-neutral';
}

export default function IpDetailPage() {
  const { ip } = useParams<{ ip: string }>();
  const decoded = decodeURIComponent(ip);
  const [data, setData] = useState<{
    intelligence: Record<string, unknown> | null;
    events: EventRow[];
    blocks: BlockRow[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [blocking, setBlocking] = useState(false);

  useEffect(() => {
    api<{
      intelligence: Record<string, unknown> | null;
      events: EventRow[];
      blocks: BlockRow[];
    }>(`/ips/${encodeURIComponent(decoded)}`)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, [decoded]);

  if (error) {
    return (
      <div className="space-y-3">
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
        <Link href="/ips" className="text-sm text-[var(--accent)] hover:underline">
          ← Back to IP Intelligence
        </Link>
      </div>
    );
  }

  if (!data) {
    return <div className="py-12 text-center text-sm text-[var(--text-muted)]">Loading…</div>;
  }

  const intel = data.intelligence;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Link href="/ips" className="text-xs text-[var(--text-muted)] hover:text-[var(--accent)]">
            ← IP Intelligence
          </Link>
          <h1 className="mt-1 font-mono text-xl font-semibold tracking-tight">{decoded}</h1>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            className="btn btn-danger"
            disabled={blocking}
            onClick={async () => {
              if (!window.confirm(`Block ${decoded}?`)) return;
              setBlocking(true);
              try {
                await api('/security/block', {
                  method: 'POST',
                  json: { ipAddress: decoded, reason: 'Manual from IP detail' },
                });
                window.location.href = '/blocking';
              } catch {
                setBlocking(false);
              }
            }}
          >
            {blocking ? 'Blocking…' : 'Block IP'}
          </button>
          <Link href="/allowlist" className="btn btn-secondary">
            Allowlist
          </Link>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Risk Score', value: intel ? String(intel.riskScore ?? '—') : '—' },
          { label: 'Risk Level', value: intel ? String(intel.riskLevel ?? '—') : '—', badge: true },
          { label: 'Events', value: intel ? String(intel.eventCount ?? data.events.length) : String(data.events.length) },
          { label: 'Failed Logins', value: intel ? String(intel.failedLogins ?? '—') : '—' },
        ].map((m) => (
          <div key={m.label} className="surface p-4">
            <div className="text-xs text-[var(--text-secondary)]">{m.label}</div>
            <div className="mt-1">
              {m.badge && intel?.riskLevel ? (
                <span className={riskBadge(String(intel.riskLevel))}>{String(intel.riskLevel)}</span>
              ) : (
                <span className="text-xl font-semibold tabular-nums">{m.value}</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Events */}
      <div className="surface">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold">Recent Events</h2>
        </div>
        {data.events.length === 0 ? (
          <div className="p-6 text-center text-sm text-[var(--text-muted)]">No events for this IP</div>
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
                {data.events.map((e) => (
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

      {/* Block history */}
      <div className="surface">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold">Block History</h2>
        </div>
        {data.blocks.length === 0 ? (
          <div className="p-6 text-center text-sm text-[var(--text-muted)]">No block history</div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {data.blocks.map((b) => (
              <div key={b.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
                <span className={b.active ? 'badge badge-critical' : 'badge badge-neutral'}>
                  {b.active ? 'Active' : 'Ended'}
                </span>
                <span className={b.automatic ? 'badge badge-info' : 'badge badge-neutral'}>
                  {b.automatic ? 'Automatic' : 'Manual'}
                </span>
                <span className="flex-1 truncate">{b.reason}</span>
                <span className="text-xs text-[var(--text-muted)]">
                  {new Date(b.createdAt).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
