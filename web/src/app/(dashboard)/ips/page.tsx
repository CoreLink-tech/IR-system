'use client';

import { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

type Row = {
  ipAddress: string;
  riskScore: number;
  riskLevel: string;
  eventCount: number;
  failedLogins: number;
  lastSeenAt: string | null;
  country: string | null;
};

function riskBadge(level: string) {
  const s = (level || '').toUpperCase();
  if (s === 'CRITICAL') return 'badge badge-critical';
  if (s === 'HIGH') return 'badge badge-high';
  if (s === 'MEDIUM' || s === 'SUSPICIOUS') return 'badge badge-medium';
  if (s === 'LOW') return 'badge badge-low';
  return 'badge badge-neutral';
}

export default function IpsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('ALL');

  useEffect(() => {
    setLoading(true);
    api<{ data: Row[] }>('/ips')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return rows.filter((r) => {
      if (levelFilter !== 'ALL' && (r.riskLevel || '').toUpperCase() !== levelFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!(r.ipAddress || '').toLowerCase().includes(q) && !(r.country || '').toLowerCase().includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [rows, search, levelFilter]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">IP Intelligence</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Observed addresses, risk scores, and activity
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <input
          className="input max-w-[220px] mono"
          placeholder="Search IP or country"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="input max-w-[150px]"
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
        >
          <option value="ALL">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="LOW">Low</option>
          <option value="NORMAL">Normal</option>
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
              <th>IP Address</th>
              <th>Risk Score</th>
              <th>Level</th>
              <th>Events</th>
              <th>Failed Logins</th>
              <th>Country</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">Loading…</td>
              </tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">
                  {rows.length === 0
                    ? 'No addresses yet. They appear when clients send events.'
                    : 'No addresses match the current filters.'}
                </td>
              </tr>
            )}
            {filtered.map((r) => (
              <tr key={r.ipAddress}>
                <td>
                  <Link
                    href={`/ips/${encodeURIComponent(r.ipAddress)}`}
                    className="mono text-sm font-medium text-[var(--accent)] hover:underline"
                  >
                    {r.ipAddress}
                  </Link>
                </td>
                <td className="tabular-nums font-medium">{r.riskScore}</td>
                <td>
                  <span className={riskBadge(r.riskLevel)}>{r.riskLevel}</span>
                </td>
                <td className="tabular-nums">{r.eventCount}</td>
                <td className="tabular-nums">{r.failedLogins}</td>
                <td className="text-xs text-[var(--text-secondary)]">{r.country || '—'}</td>
                <td className="text-xs text-[var(--text-muted)]">
                  {r.lastSeenAt
                    ? new Date(r.lastSeenAt).toLocaleString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
