import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useIpList } from '@/api/hooks';
import { useAuth } from '@/auth/useSession';
import { Button, EmptyState, Field, QueryState, Skeleton } from '@/components/ui';
import { Pagination, ResponsiveTable } from '@/components/table';
import { BlockedBadge, RiskBadge } from '@/components/badges';
import { RISK_LABEL } from '@/lib/format';
import { Time } from '@/lib/time';
import { useParams2 } from '@/lib/useUrlState';

const SORTS: Record<string, { label: string; sortBy: string; sortOrder: 'asc' | 'desc' }> = {
  seen: { label: 'Seen most recently', sortBy: 'lastSeenAt', sortOrder: 'desc' },
  risk: { label: 'Highest risk score', sortBy: 'riskScore', sortOrder: 'desc' },
  events: { label: 'Most events', sortBy: 'eventCount', sortOrder: 'desc' },
  fails: { label: 'Most failed sign-ins', sortBy: 'failedLogins', sortOrder: 'desc' },
  first: { label: 'First seen', sortBy: 'firstSeenAt', sortOrder: 'desc' },
};
const DEFAULTS = { q: '', risk: '', blocked: '', country: '', sort: 'seen', page: '1' };

export default function IpsPage() {
  const { can } = useAuth();
  const nav = useNavigate();
  const [lookup, setLookup] = useState('');
  const [p, set] = useParams2(DEFAULTS);
  const sort = SORTS[p.sort] ?? SORTS.seen;
  const list = useIpList({ page: p.page, pageSize: 20, search: p.q, riskLevel: p.risk, blocked: p.blocked, country: p.country, sortBy: sort.sortBy, sortOrder: sort.sortOrder }, can('ips.list'));
  const go = (e: FormEvent) => { e.preventDefault(); if (lookup.trim()) nav(`/ips/${encodeURIComponent(lookup.trim())}`); };

  return (
    <div className="stack">
      <h1>Addresses</h1>
      <form className="card" onSubmit={go} role="search" aria-label="Look up an address">
        <Field label="Look up any address" hint="Type a full address, such as 197.210.10.5, and open its page.">{(x) => <input {...x} type="search" value={lookup} onChange={(e) => setLookup(e.target.value)} />}</Field>
        <Button variant="primary" onClick={() => lookup.trim() && nav(`/ips/${encodeURIComponent(lookup.trim())}`)} disabled={!lookup.trim()}>Open address</Button>
      </form>
      {can('ips.list') && (
        <>
          <h2>Addresses seen so far</h2>
          <form className="filters" role="search" aria-label="Filter addresses" onSubmit={(e) => e.preventDefault()}>
            <Field label="Starts with">{(x) => <input {...x} type="search" value={p.q} onChange={(e) => set({ q: e.target.value })} />}</Field>
            <Field label="Risk level">{(x) => <select {...x} value={p.risk} onChange={(e) => set({ risk: e.target.value })}><option value="">Any</option>{Object.entries(RISK_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>}</Field>
            <Field label="Blocked">{(x) => <select {...x} value={p.blocked} onChange={(e) => set({ blocked: e.target.value })}><option value="">Any</option><option value="true">Blocked now</option><option value="false">Not blocked</option></select>}</Field>
            <Field label="Country code" hint="For example NG">{(x) => <input {...x} type="text" maxLength={2} value={p.country} onChange={(e) => set({ country: e.target.value.toUpperCase() })} />}</Field>
            <Field label="Order">{(x) => <select {...x} value={p.sort} onChange={(e) => set({ sort: e.target.value })}>{Object.entries(SORTS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>}</Field>
          </form>
          <QueryState query={list} skeleton={<Skeleton lines={8} height="2.2rem" />}>
            {(res) => res.data.length === 0 ? <EmptyState title="No addresses match">Try removing a filter.</EmptyState> : (
              <>
                <ResponsiveTable caption="Addresses" rows={res.data} rowKey={(r) => r.id}
                  columns={[
                    { key: 'a', header: 'Address', cell: (r) => <Link to={`/ips/${encodeURIComponent(r.ipAddress)}`}>{r.ipAddress}</Link> },
                    { key: 'r', header: 'Risk', cell: (r) => <span><RiskBadge level={r.riskLevel} /> <span className="muted small">score {r.riskScore}</span></span> },
                    { key: 'b', header: 'Blocked', cell: (r) => <BlockedBadge blocked={r.blocked} /> },
                    { key: 'c', header: 'Country', cell: (r) => r.country ?? 'unknown' },
                    { key: 'e', header: 'Events', cell: (r) => r.eventCount },
                    { key: 'f', header: 'Failed sign-ins', cell: (r) => r.failedLogins },
                    { key: 'l', header: 'Last seen', cell: (r) => <Time value={r.lastSeenAt} /> },
                  ]} />
                <Pagination meta={res.meta} noun="addresses" onPage={(n) => set({ page: String(n) }, false)} />
              </>
            )}
          </QueryState>
        </>
      )}
    </div>
  );
}
