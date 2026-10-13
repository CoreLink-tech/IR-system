import { useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { fetchText, useAssignees, useIncident, useIncidentReport, useTechnicalReport } from '@/api/hooks';
import { addNote, assignIncident, changeStatus } from '@/api/actions';
import type { Incident, TechnicalReport } from '@/api/types';
import { useAuth } from '@/auth/useSession';
import { Button, ConfirmDialog, EmptyState, ErrorPanel, Field, Notice, QueryState, Skeleton } from '@/components/ui';
import { RiskBadge, ScopeBadge, SeverityBadge, StatusBadge, UnassignedBadge } from '@/components/badges';
import { Tabs, TabPanel, type TabDef } from '@/components/Tabs';
import { ReportView } from '@/components/ReportView';
import { CopyButton, DownloadTextButton, PrintButton } from '@/components/actions';
import { Pagination, ResponsiveTable } from '@/components/table';
import { BlockDialog } from '@/components/BlockDialog';
import { announce } from '@/components/announce';
import { EVENT_LABEL, STATUS_HELP, STATUS_LABEL, displayName, scopeOf, timelineLabel } from '@/lib/format';
import { Time } from '@/lib/time';

function TimelineTab({ incident }: { incident: Incident }) {
  const items = incident.timeline ?? [];
  if (items.length === 0) return <EmptyState title="Nothing on the timeline yet" />;
  return (
    <ol className="tl" aria-label="Incident timeline">
      {items.map((t) => (
        <li key={t.id}>
          <strong>{timelineLabel(t.action)}</strong> <span className="muted">by {t.actor || 'the system'}, <Time value={t.createdAt} /></span>
          {t.details && <p style={{ margin: '.25rem 0 0' }}>{t.details}</p>}
        </li>
      ))}
    </ol>
  );
}

type Activity = { byType?: Array<{ type: string; count: number }>; topPaths?: Array<{ path: string; count: number }>; topIps?: Array<{ ip: string; count: number }>; totalEvents?: number; sampled?: boolean };
type Fired = { code: string; name: string; events: number; maxRiskDelta: number; lastReason?: string };
type TIp = { address: string; country: string | null; isVpn: boolean; isProxy: boolean; isTor: boolean; isDatacenter: boolean; isMalicious: boolean; intelligenceChecked: boolean; reputationScore: number };

function TechnicalTab({ id, incident }: { id: string; incident: Incident }) {
  const q = useTechnicalReport(id, true);
  const [page, setPage] = useState(1);
  const events = incident.events ?? [];
  const per = 20;
  const slice = events.slice((page - 1) * per, page * per);
  return (
    <div className="stack">
      <QueryState query={q} skeleton={<Skeleton lines={6} />}>
        {(t: TechnicalReport) => {
          const a = (t.activity ?? {}) as Activity;
          const fired = (t.rulesFired ?? []) as unknown as Fired[];
          const ip = t.ip as unknown as TIp | null;
          return (
            <>
              <section><h2>Rules that fired</h2>
                {fired.length === 0 ? <p className="muted">No rule data was recorded for these events.</p> : (
                  <ResponsiveTable caption="Rules that fired" rows={fired} rowKey={(r) => r.code}
                    columns={[
                      { key: 'n', header: 'Rule', cell: (r) => <span>{r.name} <code>{r.code}</code></span> },
                      { key: 'e', header: 'Events', cell: (r) => r.events },
                      { key: 'r', header: 'Highest risk added', cell: (r) => r.maxRiskDelta },
                      { key: 'w', header: 'Detector reason', cell: (r) => r.lastReason ?? 'none recorded' },
                    ]} />
                )}
              </section>
              <div className="grid-2">
                <div className="card"><h3>Events by kind</h3>
                  {(a.byType ?? []).length === 0 ? <p className="muted">None.</p> : <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>{a.byType!.map((x) => <li key={x.type}>{EVENT_LABEL[x.type] ?? x.type} <code>{x.type}</code>: {x.count}</li>)}</ul>}
                </div>
                <div className="card"><h3>Most requested paths</h3>
                  {(a.topPaths ?? []).length === 0 ? <p className="muted">None.</p> : <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>{a.topPaths!.map((x) => <li key={x.path}><code>{x.path}</code>: {x.count}</li>)}</ul>}
                </div>
              </div>
              <section><h2>Address intelligence</h2>
                {!ip ? <p className="muted">This incident is not tied to one address.</p> : !ip.intelligenceChecked ? (
                  <Notice>No intelligence provider has checked {ip.address}, so location and network flags are not known. This is not the same as the address being clean.</Notice>
                ) : (
                  <div className="card"><p style={{ margin: 0 }}>Country: {ip.country ?? 'unknown'}. VPN: {ip.isVpn ? 'yes' : 'no'}. Proxy: {ip.isProxy ? 'yes' : 'no'}. Tor: {ip.isTor ? 'yes' : 'no'}. Data centre: {ip.isDatacenter ? 'yes' : 'no'}. Known as malicious: {ip.isMalicious ? 'yes' : 'no'}. Reputation score: {ip.reputationScore}.</p></div>
                )}
              </section>
              {t.notes?.length > 0 && <Notice title="Notes from the report"><ul>{t.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></Notice>}
            </>
          );
        }}
      </QueryState>
      <section><h2>Related events</h2>
        {events.length === 0 ? <p className="muted">No events are attached to this incident.</p> : (
          <>
            <p className="small muted">The 200 most recent events are shown at most. Sensitive values were already removed by the API.</p>
            <ResponsiveTable caption="Related events" rows={slice} rowKey={(e) => e.id}
              columns={[
                { key: 't', header: 'When', cell: (e) => <Time value={e.occurredAt} /> },
                { key: 'k', header: 'Kind', cell: (e) => EVENT_LABEL[e.eventType] ?? e.eventType },
                { key: 's', header: 'Severity', cell: (e) => <SeverityBadge value={e.severity} /> },
                { key: 'a', header: 'Address', cell: (e) => (e.ipAddress ? <Link to={`/ips/${encodeURIComponent(e.ipAddress)}`}>{e.ipAddress}</Link> : 'none') },
                { key: 'p', header: 'Path', cell: (e) => <code>{e.requestMethod ? `${e.requestMethod} ` : ''}{e.requestPath ?? ''}</code> },
                { key: 'r', header: 'Risk', cell: (e) => <RiskBadge level={e.riskLevel} /> },
              ]} />
            <Pagination meta={{ page, pageSize: per, total: events.length, totalPages: Math.ceil(events.length / per) }} onPage={setPage} noun="events" />
          </>
        )}
      </section>
    </div>
  );
}

function ActionsTab({ incident, idParam }: { incident: Incident; idParam: string }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const refreshAll = () => Promise.all(['incident', 'incident-report', 'incidents', 'executive', 'technical-report'].map((k) => qc.invalidateQueries({ queryKey: [k] })));
  const [status, setStatus] = useState<string>(incident.status);
  const [notes, setNotes] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<{ where: string; error: unknown } | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [assignee, setAssignee] = useState(incident.assignedTo ?? '');
  const [note, setNote] = useState('');
  const [blocking, setBlocking] = useState(false);
  const assignees = useAssignees(can('incidents.assign'));
  const tech = useTechnicalReport(idParam, can('blocks.block'));
  const scope = scopeOf(incident);
  const closing = status === 'RESOLVED' || status === 'FALSE_POSITIVE';

  const run = async (where: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(where); setErr(null); setResult(null);
    try { await fn(); await refreshAll(); setResult(done); announce(done); }
    catch (e) { setErr({ where, error: e }); } finally { setBusy(null); }
  };
  const doStatus = async () => {
    setBusy('status'); setErr(null); setResult(null);
    try {
      const updated = await changeStatus(incident.id, status, notes.trim()) as Incident; // wait for the server; show what it says
      await refreshAll(); setConfirm(false); setNotes('');
      const msg = `The server recorded the status as: ${STATUS_LABEL[updated?.status ?? status] ?? status}.`;
      setResult(msg); announce(msg);
    } catch (e) { setErr({ where: 'status', error: e }); } finally { setBusy(null); }
  };

  const nothing = !can('incidents.status') && !can('incidents.note') && !can('incidents.assign') && !can('blocks.block');
  if (nothing) return <Notice>Your role can read incidents but not change them.</Notice>;
  const allowlisted = tech.data?.allowlisted === true;

  return (
    <div className="stack" aria-live="polite">
      {result && <Notice tone="ok">{result}</Notice>}
      {can('incidents.status') && (
        <section className="card"><h2>Change status</h2>
          <Field label="Status" hint={STATUS_HELP[status as keyof typeof STATUS_HELP]}>{(p) => <select {...p} value={status} onChange={(e) => setStatus(e.target.value)}>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>}</Field>
          <Field label="Notes (optional)">{(p) => <textarea {...p} maxLength={2000} value={notes} onChange={(e) => setNotes(e.target.value)} />}</Field>
          {err?.where === 'status' && !confirm && <ErrorPanel compact error={err.error} />}
          <Button variant="primary" disabled={status === incident.status} busy={busy === 'status' && !confirm} onClick={() => (closing ? setConfirm(true) : void doStatus())}>Change status</Button>
          {confirm && (
            <ConfirmDialog title={`Mark as ${STATUS_LABEL[status]}?`} confirmLabel={`Yes, mark as ${STATUS_LABEL[status]}`} busy={busy === 'status'} error={err?.where === 'status' ? err.error : null} onConfirm={() => void doStatus()} onClose={() => setConfirm(false)}>
              <p>{STATUS_HELP[status as keyof typeof STATUS_HELP]}</p>
            </ConfirmDialog>
          )}
        </section>
      )}
      {can('incidents.assign') && (
        <section className="card"><h2>Assign</h2>
          <p className="muted">Now: {incident.assignee ? displayName(incident.assignee) : <UnassignedBadge />}</p>
          <QueryState query={assignees} skeleton={<Skeleton lines={2} />}>
            {(r) => (
              <>
                <Field label="Assign to">{(p) => <select {...p} value={assignee} onChange={(e) => setAssignee(e.target.value)}><option value="">Choose a person</option>{r.data.map((u) => <option key={u.id} value={u.id}>{displayName(u)} ({u.email})</option>)}</select>}</Field>
                {err?.where === 'assign' && <ErrorPanel compact error={err.error} />}
                <Button variant="primary" disabled={!assignee || assignee === incident.assignedTo} busy={busy === 'assign'} onClick={() => void run('assign', () => assignIncident(incident.id, assignee), 'Assigned.')}>Assign</Button>
              </>
            )}
          </QueryState>
        </section>
      )}
      {can('incidents.note') && (
        <section className="card"><h2>Add a note</h2>
          <Field label="Note" hint="Added to the timeline. It does not change the status.">{(p) => <textarea {...p} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
          {err?.where === 'note' && <ErrorPanel compact error={err.error} />}
          <Button variant="primary" disabled={!note.trim()} busy={busy === 'note'} onClick={() => void run('note', async () => { await addNote(incident.id, note.trim()); setNote(''); }, 'Note added to the timeline.')}>Add note</Button>
        </section>
      )}
      <section className="card"><h2>The address</h2>
        {scope === 'address' ? (
          <>
            <p><Link to={`/ips/${encodeURIComponent(incident.sourceIp!)}`}>Open the page for {incident.sourceIp}</Link></p>
            {can('blocks.block') && (
              <>
                <Button variant="danger" disabled={allowlisted} onClick={() => setBlocking(true)}>Block {incident.sourceIp}</Button>
                {allowlisted && <p className="hint" style={{ marginTop: '.5rem' }}>This address is on the allowlist, which protects it from being blocked. Remove it from the allowlist first.</p>}
              </>
            )}
          </>
        ) : (
          <p className="muted">{scope === 'account' ? 'This incident involves one account across many addresses, so there is no single address to block.' : 'This incident covers the whole platform, so there is no single address to block.'}</p>
        )}
      </section>
      {blocking && <BlockDialog ip={incident.sourceIp!} incidentId={incident.id} onClose={() => setBlocking(false)} />}
    </div>
  );
}

export default function IncidentDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const [sp, setSp] = useSearchParams();
  const inc = useIncident(id);
  const rep = useIncidentReport(id);
  const canActions = can('incidents.status') || can('incidents.note') || can('incidents.assign') || can('blocks.block');
  const tabs: TabDef[] = [
    { id: 'report', label: 'Report' }, { id: 'timeline', label: 'Timeline' },
    ...(can('reports.technical') ? [{ id: 'technical', label: 'Technical' }] : []),
    ...(canActions ? [{ id: 'actions', label: 'Actions' }] : []),
  ];
  const wanted = sp.get('tab') ?? 'report';
  const tab = tabs.some((t) => t.id === wanted) ? wanted : 'report';
  const text = () => fetchText(`/reports/incidents/${encodeURIComponent(id)}`, {});

  if (inc.isPending) return <Skeleton lines={6} height="1.4rem" />;
  if (inc.isError && !inc.data) return <ErrorPanel error={inc.error} onRetry={() => void inc.refetch()} />;
  const i = inc.data!;
  return (
    <div className="stack">
      <p className="no-print"><Link to="/incidents">All incidents</Link></p>
      <div className="page-head">
        <div>
          <h1 style={{ marginBottom: '.25rem' }}>{i.incidentId}</h1>
          <p style={{ margin: 0 }}>{i.title}</p>
          <div className="toolbar" style={{ marginTop: '.5rem' }}>
            <SeverityBadge value={i.severity} /><StatusBadge value={i.status} /><ScopeBadge scope={scopeOf(i)} />
            {i.status === 'OPEN' && !i.assignedTo ? <UnassignedBadge /> : <span className="muted">Assigned to {displayName(i.assignee)}</span>}
          </div>
        </div>
      </div>
      <Tabs tabs={tabs} value={tab} label="Incident sections" idPrefix="inc" onChange={(t) => setSp((p) => { const n = new URLSearchParams(p); n.set('tab', t); return n; }, { replace: true })} />
      <TabPanel id="report" idPrefix="inc" active={tab === 'report'}>
        <div className="toolbar no-print" style={{ marginBottom: '.75rem' }}>
          <CopyButton onGetText={text} label="Copy as text" />
          <DownloadTextButton filename={`${i.incidentId}-report.txt`} onGetText={text} />
          <PrintButton />
        </div>
        <QueryState query={rep} skeleton={<Skeleton lines={8} />}>{(r) => <ReportView r={r} />}</QueryState>
      </TabPanel>
      <TabPanel id="timeline" idPrefix="inc" active={tab === 'timeline'}><TimelineTab incident={i} /></TabPanel>
      <TabPanel id="technical" idPrefix="inc" active={tab === 'technical'}><TechnicalTab id={id} incident={i} /></TabPanel>
      <TabPanel id="actions" idPrefix="inc" active={tab === 'actions'}><ActionsTab incident={i} idParam={id} /></TabPanel>
    </div>
  );
}
