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
  blocksInPeriod?: Array<{
    ipAddress: string;
    reason: string;
    automatic: boolean;
    active: boolean;
    createdAt: string;
  }>;
};

export default function ReportsPage() {
  const [days, setDays] = useState(7);
  const [exec, setExec] = useState<Exec | null>(null);
  const [tech, setTech] = useState<Exec | null>(null);
  const [tab, setTab] = useState<'executive' | 'technical'>('executive');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    api<Exec>(`/reports/executive?days=${days}`)
      .then(setExec)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
    api<Exec>(`/reports/technical?days=${days}`)
      .then(setTech)
      .catch(() => {
        /* viewers may not get technical */
      });
  }, [days]);

  const data = tab === 'executive' ? exec : tech || exec;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Reports</h1>
        <div className="flex flex-wrap gap-2">
          {[7, 14, 30].map((d) => (
            <button
              key={d}
              type="button"
              className={`rounded px-3 py-1 text-sm ${days === d ? 'bg-blue-600 text-white' : 'border bg-white'}`}
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
          className={`rounded px-3 py-1.5 text-sm ${tab === 'executive' ? 'bg-neutral-900 text-white' : 'border bg-white'}`}
          onClick={() => setTab('executive')}
        >
          Executive
        </button>
        <button
          type="button"
          className={`rounded px-3 py-1.5 text-sm ${tab === 'technical' ? 'bg-neutral-900 text-white' : 'border bg-white'}`}
          onClick={() => setTab('technical')}
        >
          Technical
        </button>
      </div>
      {error && <p className="text-red-600">{error}</p>}
      {!data && !error && <p className="text-neutral-500">Loading…</p>}
      {data && (
        <>
          <div className="rounded-lg border bg-white p-4">
            <div className="text-xs text-neutral-500">Posture</div>
            <div className="text-2xl font-semibold">{data.posture}</div>
            <p className="mt-2 text-sm text-neutral-700">{data.plainEnglish}</p>
            <p className="mt-1 text-xs text-neutral-400">Generated {new Date(data.generatedAt).toLocaleString()}</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <Tile label="Open incidents" value={data.summary.openIncidents} />
            <Tile label="Critical open" value={data.summary.criticalOpen} />
            <Tile label="High open" value={data.summary.highOpen} />
            <Tile label="Events in period" value={data.summary.eventsInPeriod} />
            <Tile label="High-risk events" value={data.summary.highRiskEvents} />
            <Tile label="Active blocks" value={data.summary.activeBlocks} />
          </div>
          <section>
            <h2 className="mb-2 font-medium">Top event types</h2>
            <ul className="rounded-lg border bg-white divide-y text-sm">
              {data.topEventTypes.map((t) => (
                <li key={t.type} className="flex justify-between px-3 py-2">
                  <span className="font-mono text-xs">{t.type}</span>
                  <span>{t.count}</span>
                </li>
              ))}
              {data.topEventTypes.length === 0 && (
                <li className="px-3 py-4 text-neutral-500">No events in this period.</li>
              )}
            </ul>
          </section>
          <section>
            <h2 className="mb-2 font-medium">Recent incidents</h2>
            <ul className="rounded-lg border bg-white divide-y text-sm">
              {data.recentIncidents.map((i) => (
                <li key={i.id} className="px-3 py-2">
                  <Link className="text-blue-700 underline" href={`/incidents/${i.id}`}>
                    #{i.publicNumber} {i.title}
                  </Link>
                  <span className="ml-2 text-neutral-500">
                    {i.status} · {i.severity} · risk {i.riskScore}
                  </span>
                </li>
              ))}
              {data.recentIncidents.length === 0 && (
                <li className="px-3 py-4 text-neutral-500">None in this period.</li>
              )}
            </ul>
          </section>
          {tab === 'technical' && data.blocksInPeriod && (
            <section>
              <h2 className="mb-2 font-medium">Blocks in period</h2>
              <ul className="rounded-lg border bg-white divide-y text-sm">
                {data.blocksInPeriod.map((b, idx) => (
                  <li key={idx} className="px-3 py-2 font-mono text-xs">
                    {b.ipAddress} · {b.reason} · {b.automatic ? 'auto' : 'manual'} ·{' '}
                    {b.active ? 'active' : 'ended'}
                  </li>
                ))}
                {data.blocksInPeriod.length === 0 && (
                  <li className="px-3 py-4 text-neutral-500">No blocks in this period.</li>
                )}
              </ul>
            </section>
          )}
        </>
      )}
    </div>
  );
}

function Tile({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border bg-white p-3">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}
