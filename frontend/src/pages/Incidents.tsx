import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useIncidents } from '@/api/hooks';
import type { Incident } from '@/api/types';
import { EmptyState, Field, QueryState, Skeleton } from '@/components/ui';
import { Pagination, ResponsiveTable } from '@/components/table';
import { ScopeBadge, SeverityBadge, StatusBadge, UnassignedBadge } from '@/components/badges';
import { STATUS_LABEL, SEVERITY_LABEL, ageLabel, displayName, scopeOf } from '@/lib/format';
import { useParams2 } from '@/lib/useUrlState';

const SORTS: Record<string, { label: string; sortBy: string; sortOrder: 'asc' | 'desc' }> = {
  newest: { label: 'Newest first', sortBy: 'createdAt', sortOrder: 'desc' },
  oldest: { label: 'Oldest first', sortBy: 'createdAt', sortOrder: 'asc' },
  active: { label: 'Most recent activity', sortBy: 'updatedAt', sortOrder: 'desc' },
  risk: { label: 'Highest risk score', sortBy: 'riskScore', sortOrder: 'desc' },
};
const DEFAULTS = { status: '', severity: '', q: '', sort: 'newest', page: '1' };
export const isUnassignedOpen = (i: Incident) => i.status === 'OPEN' && !i.assignedTo;

export default function IncidentsPage() {
  const [p, set] = useParams2(DEFAULTS);
  const [qInput, setQInput] = useState(p.q);
  useEffect(() => { setQInput(p.q); }, [p.q]);
  useEffect(() => { const t = setTimeout(() => { if (qInput !== p.q) set({ q: qInput }); }, 300); return () => clearTimeout(t); }, [qInput]); // eslint-disable-line react-hooks/exhaustive-deps
  const sort = SORTS[p.sort] ?? SORTS.newest;
  const query = useIncidents({ page: p.page, pageSize: 20, status: p.status, severity: p.severity, search: p.q, sortBy: sort.sortBy, sortOrder: sort.sortOrder });

  return (
    <div className="stack">
      <h1>Incidents</h1>
      <form className="filters" role="search" aria-label="Filter incidents" onSubmit={(e) => e.preventDefault()}>
        <Field label="Status">{(x) => <select {...x} value={p.status} onChange={(e) => set({ status: e.target.value })}><option value="">Any status</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>}</Field>
        <Field label="Severity">{(x) => <select {...x} value={p.severity} onChange={(e) => set({ severity: e.target.value })}><option value="">Any severity</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((k) => <option key={k} value={k}>{SEVERITY_LABEL[k]}</option>)}</select>}</Field>
        <Field label="Address or incident number" hint="Matches the start, for example 197.210 or INC-2026">{(x) => <input {...x} type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} />}</Field>
        <Field label="Order">{(x) => <select {...x} value={p.sort} onChange={(e) => set({ sort: e.target.value })}>{Object.entries(SORTS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>}</Field>
      </form>
      <QueryState query={query} skeleton={<Skeleton lines={8} height="2.2rem" />}>
        {(res) => res.data.length === 0 ? (
          <EmptyState title="No incidents match">{p.status || p.severity || p.q ? 'Try removing a filter.' : 'Nothing has been flagged yet. That is good news.'}</EmptyState>
        ) : (
          <>
            <ResponsiveTable caption="Incidents" rows={res.data} rowKey={(i) => i.id} rowClass={(i) => (isUnassignedOpen(i) ? 'row-flag' : undefined)}
              columns={[
                { key: 'no', header: 'Incident', cell: (i) => <Link to={`/incidents/${encodeURIComponent(i.incidentId)}`}><strong>{i.incidentId}</strong></Link> },
                { key: 'title', header: 'What happened', cell: (i) => i.title },
                { key: 'sev', header: 'Severity', cell: (i) => <SeverityBadge value={i.severity} /> },
                { key: 'st', header: 'Status', cell: (i) => <StatusBadge value={i.status} /> },
                { key: 'scope', header: 'Affects', cell: (i) => <ScopeBadge scope={scopeOf(i)} /> },
                { key: 'who', header: 'Assigned to', cell: (i) => (isUnassignedOpen(i) ? <UnassignedBadge /> : <span>{displayName(i.assignee)}</span>) },
                { key: 'age', header: 'Opened', cell: (i) => ageLabel(i.createdAt) },
                { key: 'act', header: 'Last activity', cell: (i) => ageLabel(i.updatedAt) },
              ]} />
            <Pagination meta={res.meta} noun="incidents" onPage={(n) => set({ page: String(n) }, false)} />
          </>
        )}
      </QueryState>
    </div>
  );
}
