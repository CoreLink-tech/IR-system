'use client';

import { useEffect, useState, useMemo } from 'react';
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

function statusBadge(status: string) {
  const s = (status || '').toUpperCase();
  if (s === 'OPEN') return 'badge badge-critical';
  if (s === 'INVESTIGATING') return 'badge badge-high';
  if (s === 'CONTAINED') return 'badge badge-medium';
  if (s === 'RESOLVED') return 'badge badge-low';
  if (s === 'FALSE_POSITIVE') return 'badge badge-neutral';
  return 'badge badge-neutral';
}

export default function IncidentsPage() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  useEffect(() => {
    setLoading(true);
    api<{ data: Incident[] }>('/incidents?pageSize=100')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return rows.filter((r) => {
      if (statusFilter !== 'ALL' && (r.status || '').toUpperCase() !== statusFilter) return false;
      if (severityFilter !== 'ALL' && (r.severity || '').toUpperCase() !== severityFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const hay = `${r.publicNumber} ${r.title} ${r.sourceIp || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rows, statusFilter, severityFilter, search]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Incidents</h1>
          <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
            Investigate and manage security incidents
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          className="input max-w-[220px]"
          placeholder="Search title, IP, #"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="input max-w-[140px]"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="ALL">All statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="CONTAINED">Contained</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False positive</option>
        </select>
        <select
          className="input max-w-[140px]"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span className="text-xs text-[var(--text-muted)]">
          {filtered.length} of {rows.length}
        </span>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Title</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Risk</th>
              <th>Events</th>
              <th>Opened</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={8} className="py-8 text-center text-[var(--text-muted)]">
                  Loading incidents…
                </td>
              </tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="py-8 text-center text-[var(--text-muted)]">
                  {rows.length === 0
                    ? 'No incidents yet. Events from client sites will create incidents when rules match.'
                    : 'No incidents match the current filters.'}
                </td>
              </tr>
            )}
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="mono text-xs text-[var(--text-muted)]">{r.publicNumber}</td>
                <td>
                  <Link
                    href={`/incidents/${r.id}`}
                    className="font-medium text-[var(--text-primary)] hover:text-[var(--accent)]"
                  >
                    {r.title}
                  </Link>
                </td>
                <td>
                  <span className={statusBadge(r.status)}>{r.status}</span>
                </td>
                <td>
                  <span className={severityBadge(r.severity)}>{r.severity}</span>
                </td>
                <td className="mono text-xs">{r.sourceIp || '—'}</td>
                <td className="tabular-nums">{r.riskScore}</td>
                <td className="tabular-nums">{r.eventCount}</td>
                <td className="text-xs text-[var(--text-muted)]">
                  {new Date(r.createdAt).toLocaleString(undefined, {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
