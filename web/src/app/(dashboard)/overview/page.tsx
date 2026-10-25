'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/client-api';

export default function OverviewPage() {
  const [health, setHealth] = useState<{ status?: string; database?: string } | null>(null);
  const [incidents, setIncidents] = useState<number | null>(null);

  useEffect(() => {
    fetch('/api/v1/health/ready')
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth({ status: 'error' }));
    api<{ data: unknown[] }>('/incidents?pageSize=5')
      .then((r) => setIncidents(r.data?.length ?? 0))
      .catch(() => setIncidents(null));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Overview</h1>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border bg-white p-4 shadow-sm">
          <h2 className="text-sm font-medium text-neutral-500">API readiness</h2>
          <p className="mt-1 text-lg">
            {health?.status === 'ready' ? 'Ready' : health?.status || '…'}
            {health?.database ? ` · DB ${health.database}` : ''}
          </p>
        </div>
        <div className="rounded-lg border bg-white p-4 shadow-sm">
          <h2 className="text-sm font-medium text-neutral-500">Recent incidents (sample)</h2>
          <p className="mt-1 text-lg">{incidents === null ? '…' : incidents}</p>
        </div>
      </div>
      <p className="text-sm text-neutral-600">
        Client websites send events to <code className="rounded bg-neutral-100 px-1">POST /api/v1/events</code>. This
        app stores them in your Turso/SQLite database — not the shop database.
      </p>
    </div>
  );
}
