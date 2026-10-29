'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

type Exec = {
  periodDays: number;
  generatedAt: string;
  posture: string;
  summary: {
    openIncidents: number;
    criticalOpen: number;
    highOpen: number;
    eventsInPeriod: number;
    highRiskEvents: number;
    activeBlocks: number;
  };
  topEventTypes: Array<{ type: string; count: number }>;
  recentIncidents: Array<{
    id: string;
    publicNumber: number;
    title: string;
    status: string;
    severity: string;
    riskScore: number;
    sourceIp: string | null;
    createdAt: string;
  }>;
  plainEnglish: string;
};

export default function ReportsPage() {
  const [days, setDays] = useState(7);
  const [exec, setExec] = useState<Exec | null>(null);
  const [tech, setTech] = useState<Exec | null>(null);
  const [tab, setTab] = useState<'executive' | 'technical'>('executive');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setError(null);
    setLoading(true);
    Promise.all([
      api<Exec>(`/reports/executive?days=${days}`).then(setExec).catch((e: unknown) => {
        setError(e instanceof ApiError ? e.message : 'Failed');
      }),
      api<Exec>(`/reports/technical?days=${days}`).then(setTech).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, [days]);

  const data = tab === 'executive' ? exec : tech || exec;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="kicker">Intelligence</div>
          <h1 className="text-[22px] font-[750] tracking-[-0.5px]">Reports</h1>
          <p className="mt-1 text-[13px] text-[#718079]">Security posture summaries for the selected period.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {[7, 14, 30].map((d) => (
            <button
              key={d}
              type="button"
              className={`btn text-[11px] ${days === d ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setDays(d)}
            >
              {d} days
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-2">
        <button
          type="button"
          className={`btn text-[11px] ${tab === 'executive' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setTab('executive')}
        >
          Executive
        </button>
        <button
          type="button"
          className={`btn text-[11px] ${tab === 'technical' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setTab('technical')}
        >
          Technical
        </button>
      </div>

      {error && (
        <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-4 py-3 text-[12px] text-[#a13a3a]">{error}</div>
      )}
      {loading && !data && <div className="text-[13px] text-[#718079]">Loading…</div>}

      {data && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: 'Posture', value: data.posture },
              { label: 'Open incidents', value: String(data.summary.openIncidents) },
              { label: 'Events in period', value: String(data.summary.eventsInPeriod) },
              { label: 'Active blocks', value: String(data.summary.activeBlocks) },
            ].map((m) => (
              <div key={m.label} className="metric">
                <div className="metric-label">{m.label}</div>
                <div className="metric-value" style={{ fontSize: 22 }}>{m.value}</div>
              </div>
            ))}
          </div>

          {data.plainEnglish && (
            <div className="surface p-4">
              <div className="text-[11px] font-[750] text-[#718079]">Summary</div>
              <p className="mt-2 text-[13px] leading-relaxed text-[#405148]">{data.plainEnglish}</p>
            </div>
          )}

          <div className="surface">
            <div className="border-b border-[#eaf0ec] px-4 py-3 text-[12px] font-[750]">Recent incidents in period</div>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>IP</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.recentIncidents || []).length === 0 && (
                    <tr><td colSpan={6} className="py-6 text-center text-[#718079]">None in this period</td></tr>
                  )}
                  {(data.recentIncidents || []).map((inc) => (
                    <tr key={inc.id}>
                      <td className="mono">{inc.publicNumber}</td>
                      <td>
                        <Link href={`/incidents/${inc.id}`} className="font-medium text-[#176b52] hover:underline">
                          {inc.title}
                        </Link>
                      </td>
                      <td>{inc.severity}</td>
                      <td>{inc.status}</td>
                      <td className="mono">{inc.sourceIp || '—'}</td>
                      <td className="tabular-nums">{inc.riskScore}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
