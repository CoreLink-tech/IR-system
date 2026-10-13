import { useAudit } from '@/api/hooks';
import { EmptyState, Field, QueryState, Skeleton } from '@/components/ui';
import { Pagination, ResponsiveTable } from '@/components/table';
import { Time } from '@/lib/time';
import { auditSummary } from '@/lib/format';
import { useParams2 } from '@/lib/useUrlState';

const DEFAULTS = { action: '', actorType: '', result: '', from: '', to: '', page: '1' };
const startOfDay = (d: string) => (d ? new Date(`${d}T00:00:00`).toISOString() : undefined);
const endOfDay = (d: string) => (d ? new Date(`${d}T23:59:59.999`).toISOString() : undefined);

export default function AdminAuditPage() {
  const [p, set] = useParams2(DEFAULTS);
  const q = useAudit({ page: p.page, pageSize: 25, action: p.action, actorType: p.actorType, result: p.result, from: startOfDay(p.from), to: endOfDay(p.to), sortBy: 'createdAt', sortOrder: 'desc' });
  return (
    <div className="stack">
      <h1>Audit log</h1>
      <p className="muted">A record of who did what. It cannot be edited from here.</p>
      <form className="filters" role="search" aria-label="Filter the audit log" onSubmit={(e) => e.preventDefault()}>
        <Field label="Action contains" hint="For example block, rule, login">{(x) => <input {...x} type="search" value={p.action} onChange={(e) => set({ action: e.target.value })} />}</Field>
        <Field label="Done by">{(x) => <select {...x} value={p.actorType} onChange={(e) => set({ actorType: e.target.value })}><option value="">Anyone</option><option value="USER">A person</option><option value="SYSTEM">The system</option><option value="API_KEY">A website key</option></select>}</Field>
        <Field label="Result">{(x) => <select {...x} value={p.result} onChange={(e) => set({ result: e.target.value })}><option value="">Any</option><option value="SUCCESS">Worked</option><option value="FAILURE">Did not work</option></select>}</Field>
        <Field label="From">{(x) => <input {...x} type="date" value={p.from} onChange={(e) => set({ from: e.target.value })} />}</Field>
        <Field label="To">{(x) => <input {...x} type="date" value={p.to} onChange={(e) => set({ to: e.target.value })} />}</Field>
      </form>
      <QueryState query={q} skeleton={<Skeleton lines={8} height="2.2rem" />}>
        {(res) => res.data.length === 0 ? <EmptyState title="Nothing matches">Try widening the dates or removing a filter.</EmptyState> : (
          <>
            <ResponsiveTable caption="Audit log" rows={res.data} rowKey={(a) => a.id}
              columns={[
                { key: 'w', header: 'When', cell: (a) => <Time value={a.createdAt} /> },
                { key: 's', header: 'What happened', cell: (a) => (
                  <details><summary>{auditSummary(a)}</summary>
                    <dl className="small" style={{ margin: '.5rem 0 0' }}>
                      <dt>Action</dt><dd><code>{a.action}</code></dd>
                      {a.ipAddress && <><dt>From address</dt><dd>{a.ipAddress}</dd></>}
                      {a.requestId && <><dt>Request</dt><dd><code>{a.requestId}</code></dd></>}
                      {a.metadata && <><dt>Details</dt><dd><pre className="mono" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{JSON.stringify(a.metadata, null, 2)}</pre></dd></>}
                    </dl>
                  </details>) },
                { key: 'r', header: 'Result', cell: (a) => (a.result === 'SUCCESS' ? <span className="badge ok">Worked</span> : <span className="badge sev-high">Did not work</span>) },
              ]} />
            <Pagination meta={res.meta} noun="entries" onPage={(n) => set({ page: String(n) }, false)} />
          </>
        )}
      </QueryState>
    </div>
  );
}
