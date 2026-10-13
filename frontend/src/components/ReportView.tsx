import type { IncidentReport } from '@/api/types';
import { RiskBadge, SeverityBadge, StatusBadge } from './badges';
import { Limitations } from './SummaryViews';
import { Time } from '@/lib/time';

/** The plain-English report, rendered exactly as returned. All text is shown as text, never as markup. */
export function ReportView({ r }: { r: IncidentReport }) {
  const s = r.sections;
  return (
    <article className="report print-area stack" aria-labelledby="rep-h">
      <header>
        <p className="muted small" style={{ margin: 0 }}>{r.incidentId}</p>
        <h2 id="rep-h" style={{ marginTop: 0 }}>{r.headline}</h2>
        <div className="toolbar"><SeverityBadge value={r.severity} /><StatusBadge value={r.status} /></div>
      </header>
      <section><h3>What happened</h3><p>{s.whatHappened}</p></section>
      <section><h3>Why it matters</h3><p>{s.whyItMatters}</p></section>
      <section><h3>Risk level</h3>
        <p><RiskBadge level={s.riskLevel.level} /> <span className="muted">(score {s.riskLevel.score})</span></p>
        <p>{s.riskLevel.explanation}</p>
      </section>
      {s.evidence.length > 0 && <section><h3>Evidence</h3><dl>{s.evidence.map((e, i) => <div key={i} style={{ display: 'contents' }}><dt>{e.label}</dt><dd>{e.value}</dd></div>)}</dl></section>}
      {s.actionTaken.length > 0 && <section><h3>What has been done</h3><ul>{s.actionTaken.map((a, i) => <li key={i}>{a}</li>)}</ul></section>}
      <section><h3>Where things stand</h3><p>{s.currentStatus}</p></section>
      {s.recommendedActions.length > 0 && <section><h3>What to do next</h3><ol>{s.recommendedActions.map((a, i) => <li key={i}>{a}</li>)}</ol></section>}
      <Limitations title="What this report cannot confirm" items={r.limitations} />
      <p className="small muted">Generated <Time value={r.generatedAt} />.</p>
    </article>
  );
}
