'use client';

import { useEffect, useState } from 'react';

export default function StatusPage() {
  const [health, setHealth] = useState<{ status?: string; time?: string } | null>(null);
  const [ready, setReady] = useState<{ status?: string; database?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      fetch('/api/v1/health').then((r) => r.json()),
      fetch('/api/v1/health/ready').then((r) => r.json()).catch(() => null),
    ])
      .then(([h, r]) => {
        setHealth(h);
        setReady(r);
      })
      .catch(() => setError('Unable to reach health endpoints'));
  }, []);

  const ok = health?.status === 'ok';

  return (
    <main className="mx-auto max-w-lg px-6 py-16">
      <h1 className="text-2xl font-semibold">Watcher status</h1>
      <p className="mt-2 text-sm text-[var(--text-secondary)]">Public liveness for this deployment.</p>
      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
      <div className="mt-6 space-y-3 rounded border border-[var(--border)] p-4">
        <div className="flex justify-between text-sm">
          <span>API</span>
          <span className={ok ? 'text-green-600' : 'text-amber-600'}>{ok ? 'Operational' : 'Degraded / unknown'}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span>Database</span>
          <span>{ready?.database || ready?.status || '—'}</span>
        </div>
        <div className="text-xs text-[var(--text-muted)]">{health?.time || ''}</div>
      </div>
      <p className="mt-6 text-sm">
        <a className="text-[var(--accent)] underline" href="/trust">
          Trust center
        </a>
      </p>
    </main>
  );
}
