import { Link } from 'react-router-dom';
import type { ExecutiveSummary, SecuritySummary } from '@/api/types';
import { PostureBanner, SeverityBadge, StatusBadge, BlockedBadge } from './badges';
import { DailyChart } from './DailyChart';
import { Notice } from './ui';
import { ResponsiveTable } from './table';
import { EVENT_LABEL, RISK_LABEL, SEVERITY_LABEL, STATUS_LABEL, ageLabel } from '@/lib/format';
import { Time } from '@/lib/time';

/** The executive summary exactly as the API wrote it. The posture and the wording are the server's. */
export function ExecutiveView({ s }: { s: ExecutiveSummary }) {
  return (
    <div className="stack report print-area">
      <PostureBanner posture={s.posture} headline={s.headline} />
      <div className="card"><p style={{ margin: 0 }}>{s.overview}</p></div>
      <section aria-labelledby="kn"><h2 id="kn">Key numbers</h2>
        <div className="grid">{s.keyNumbers.map((k) => <div key={k.label} className="card stat"><span className="muted">{k.label}</span><span className="value">{k.value}</span></div>)}</div>
      </section>
      {s.needsAttention.length > 0 && (
        <section aria-labelledby="na"><h2 id="na">What needs your attention</h2>
          <div className="card"><ul style={{ margin: 0, paddingLeft: '1.2rem' }}>{s.needsAttention.map((n, i) => <li key={i}>{n}</li>)}</ul></div>
        </section>
      )}
      {s.notableIncidents.length > 0 && (
        <section aria-labelledby="ni"><h2 id="ni">Incidents worth knowing about</h2>
          <div className="stack">{s.notableIncidents.map((n) => (
            <div key={n.incidentId} className="card">
              <div className="toolbar"><Link to={`/incidents/${encodeURIComponent(n.incidentId)}`}><strong>{n.incidentId}</strong></Link><SeverityBadge value={n.severity} /><StatusBadge value={n.status} /></div>
              <p style={{ margin: '.5rem 0 0' }}><strong>{n.title}</strong></p>
              <p className="muted" style={{ margin: '.25rem 0 0' }}>{n.summary}</p>
            </div>))}
          </div>
        </section>
      )}
      <section aria-labelledby="tr"><h2 id="tr">Compared with the period before</h2><div className="card"><p style={{ margin: 0 }}>{s.trend}</p></div></section>
      <Limitations title="What this summary cannot confirm" items={s.limitations} />
      <p className="small muted">Generated <Time value={s.generatedAt} />. Covers <Time value={s.period.from} /> to <Time value={s.period.to} />.</p>
    </div>
  );
}

/** What the report cannot confirm. Always shown, never collapsed. */
export function Limitations({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return <Notice title={title}><ul>{items.map((l, i) => <li key={i}>{l}</li>)}</ul></Notice>;
}

const Counts = ({ title, rows, label }: { title: string; rows: Array<{ k: string; n: number }>; label: (k: string) => string }) => (
  <div className="card"><h3>{title}</h3>
    {rows.length === 0 ? <p className="muted">None in this period.</p> : <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>{rows.map((r) => <li key={r.k} style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem' }}><span>{label(r.k)}</span><strong>{r.n}</strong></li>)}</ul>}
  </div>
);

export function SecurityView({ s }: { s: SecuritySummary }) {
  const t = s.trend;
  return (
    <div className="stack report print-area">
      <div className="grid">
        <div className="card stat"><span className="muted">Events</span><span className="value">{s.totals.events}</span><span className="small muted">before: {t.events.previous}</span></div>
        <div className="card stat"><span className="muted">Incidents</span><span className="value">{s.totals.incidents}</span><span className="small muted">before: {t.incidents.previous}</span></div>
        <div className="card stat"><span className="muted">Different addresses</span><span className="value">{s.totals.uniqueIps}</span></div>
        <div className="card stat"><span className="muted">Open with nobody assigned</span><span className="value">{s.response.unassignedOpen}</span></div>
        <div className="card stat"><span className="muted">Average time to resolve</span><span className="value">{s.response.meanTimeToResolveMinutes == null ? 'n/a' : `${Math.round(s.response.meanTimeToResolveMinutes)} min`}</span></div>
        <div className="card stat"><span className="muted">Oldest unresolved</span><span className="value" style={{ fontSize: '1.1rem' }}>{s.response.oldestUnresolvedAt ? ageLabel(s.response.oldestUnresolvedAt) : 'none'}</span></div>
      </div>
      <section aria-labelledby="dc"><h2 id="dc">Day by day</h2><div className="card"><DailyChart daily={s.daily} /><p className="small muted">Days are in UTC.</p></div></section>
      <div className="grid-2">
        <Counts title="Incidents by severity" rows={s.incidentsBySeverity.map((r) => ({ k: r.severity, n: r.count }))} label={(k) => SEVERITY_LABEL[k] ?? k} />
        <Counts title="Incidents by status" rows={s.incidentsByStatus.map((r) => ({ k: r.status, n: r.count }))} label={(k) => STATUS_LABEL[k] ?? k} />
        <Counts title="Events by kind" rows={s.eventsByType.map((r) => ({ k: r.type, n: r.count }))} label={(k) => EVENT_LABEL[k] ?? k} />
        <Counts title="Events by risk level" rows={s.eventsByRiskLevel.map((r) => ({ k: r.level, n: r.count }))} label={(k) => RISK_LABEL[k] ?? k} />
        <Counts title="Incidents by kind of attack" rows={s.incidentsByRule.map((r) => ({ k: r.title, n: r.count }))} label={(k) => k} />
        <div className="card"><h3>Blocking</h3>
          <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
            <li>{s.blocking.total} blocks recorded ({s.blocking.automatic} automatic, {s.blocking.manual} manual)</li>
            <li>{s.blocking.stillInForce} still in force</li><li>{s.blocking.allowlisted} addresses on the allowlist</li>
          </ul>
        </div>
      </div>
      <section aria-labelledby="ts"><h2 id="ts">Busiest addresses</h2>
        {s.topSourceIps.length === 0 ? <div className="card muted">No addresses to show.</div> : (
          <ResponsiveTable caption="Busiest addresses" rows={s.topSourceIps} rowKey={(r) => r.ip}
            columns={[
              { key: 'ip', header: 'Address', cell: (r) => <Link to={`/ips/${encodeURIComponent(r.ip)}`}>{r.ip}</Link> },
              { key: 'ev', header: 'Events', cell: (r) => r.events },
              { key: 'pk', header: 'Highest risk score', cell: (r) => r.peakRisk },
              { key: 'bl', header: 'Blocked', cell: (r) => <BlockedBadge blocked={r.blocked} /> },
            ]} />
        )}
      </section>
      {s.notes.length > 0 && <Limitations title="Notes about these numbers" items={s.notes} />}
      <p className="small muted">Generated <Time value={s.generatedAt} />. Covers <Time value={s.period.from} /> to <Time value={s.period.to} />.</p>
    </div>
  );
}
