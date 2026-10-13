import type { SecuritySummary } from '@/api/types';

/**
 * Events as bars (left scale) and incidents as a line (right scale), one point per UTC day. Drawn as
 * plain SVG so nothing loads from elsewhere. The same numbers are in a table for screen readers.
 */
export function DailyChart({ daily }: { daily: SecuritySummary['daily'] }) {
  if (daily.length === 0) return <p className="muted">No activity in this period.</p>;
  const W = 640, H = 230, L = 44, R = 36, T = 12, B = 34;
  const maxE = Math.max(1, ...daily.map((d) => d.events));
  const maxI = Math.max(1, ...daily.map((d) => d.incidents));
  const bw = (W - L - R) / daily.length;
  const x = (i: number) => L + i * bw + bw / 2;
  const yE = (v: number) => T + (H - T - B) * (1 - v / maxE);
  const yI = (v: number) => T + (H - T - B) * (1 - v / maxI);
  const step = Math.max(1, Math.ceil(daily.length / 7));
  const total = daily.reduce((s, d) => s + d.events, 0);
  const totalInc = daily.reduce((s, d) => s + d.incidents, 0);
  return (
    <figure style={{ margin: 0 }}>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Daily activity over ${daily.length} days: ${total} events and ${totalInc} incidents in total. A table with the same numbers follows.`}>
        <line className="axis" x1={L} x2={W - R} y1={H - B} y2={H - B} />
        <line className="axis" x1={L} x2={L} y1={T} y2={H - B} />
        <text x={L - 6} y={T + 8} textAnchor="end">{maxE}</text>
        <text x={L - 6} y={H - B} textAnchor="end">0</text>
        <text x={W - R + 6} y={T + 8}>{maxI}</text>
        <text x={W - R + 6} y={H - B}>0</text>
        {daily.map((d, i) => <rect key={d.date} className="bar-events" x={x(i) - bw * 0.35} width={bw * 0.7} y={yE(d.events)} height={Math.max(0, H - B - yE(d.events))} />)}
        <polyline className="line-incidents" points={daily.map((d, i) => `${x(i)},${yI(d.incidents)}`).join(' ')} />
        {daily.map((d, i) => <circle key={`c${d.date}`} className="dot-incidents" cx={x(i)} cy={yI(d.incidents)} r={3.5} />)}
        {daily.map((d, i) => (i % step === 0 ? <text key={`t${d.date}`} x={x(i)} y={H - 12} textAnchor="middle">{d.date.slice(5)}</text> : null))}
      </svg>
      <div className="legend" aria-hidden="true">
        <span><i style={{ background: 'var(--primary-bg)' }} />Events (left scale)</span>
        <span><i style={{ background: 'var(--danger-bg)' }} />Incidents (right scale)</span>
      </div>
      <details className="small"><summary>Show the numbers as a table</summary>
        <table className="rtable" style={{ marginTop: '.5rem' }}>
          <caption className="sr-only">Events and incidents per day (UTC)</caption>
          <thead><tr><th scope="col">Day (UTC)</th><th scope="col">Events</th><th scope="col">Incidents</th></tr></thead>
          <tbody>{daily.map((d) => <tr key={d.date}><td data-label="Day (UTC)">{d.date}</td><td data-label="Events">{d.events}</td><td data-label="Incidents">{d.incidents}</td></tr>)}</tbody>
        </table>
      </details>
    </figure>
  );
}
