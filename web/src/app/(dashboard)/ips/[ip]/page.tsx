'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { api, ApiError } from '@/lib/client-api';

export default function IpDetailPage() {
  const { ip } = useParams<{ ip: string }>();
  const decoded = decodeURIComponent(ip);
  const [data, setData] = useState<{
    intelligence: Record<string, unknown> | null;
    events: Array<{ id: string; eventType: string; severity: string; riskScore: number; createdAt: string }>;
    blocks: Array<{ id: string; reason: string; active: boolean; automatic: boolean; createdAt: string }>;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<typeof data extends null ? never : NonNullable<typeof data>>(`/ips/${encodeURIComponent(decoded)}`)
      .then(setData)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, [decoded]);

  if (error) {
    return (
      <div>
        <p className="text-red-600">{error}</p>
        <Link href="/ips" className="text-blue-700 underline">Back</Link>
      </div>
    );
  }
  if (!data) return <p className="text-neutral-500">Loading…</p>;
  const intel = data.intelligence;

  return (
    <div className="space-y-6">
      <div>
        <Link href="/ips" className="text-sm text-blue-700 underline">← Addresses</Link>
        <h1 className="mt-1 font-mono text-2xl font-semibold">{decoded}</h1>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label="Risk" value={intel ? String(intel.riskScore) : '—'} />
        <Tile label="Level" value={intel ? String(intel.riskLevel) : '—'} />
        <Tile label="Events" value={intel ? String(intel.eventCount) : String(data.events.length)} />
        <Tile label="Failed logins" value={intel ? String(intel.failedLogins) : '—'} />
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          className="rounded bg-red-600 px-3 py-1.5 text-sm text-white"
          onClick={async () => {
            if (!window.confirm(`Block ${decoded}?`)) return;
            await api('/security/block', { method: 'POST', json: { ipAddress: decoded, reason: 'Manual from IP detail' } });
            window.location.href = '/blocking';
          }}
        >
          Block
        </button>
        <Link href="/allowlist" className="rounded border bg-white px-3 py-1.5 text-sm">Allowlist</Link>
      </div>
      <section>
        <h2 className="mb-2 font-medium">Recent events</h2>
        <ul className="rounded-lg border bg-white divide-y text-sm">
          {data.events.map((e) => (
            <li key={e.id} className="flex justify-between px-3 py-2">
              <span>{e.eventType} · {e.severity} · risk {e.riskScore}</span>
              <span className="text-neutral-500">{new Date(e.createdAt).toLocaleString()}</span>
            </li>
          ))}
          {data.events.length === 0 && <li className="px-3 py-4 text-neutral-500">None</li>}
        </ul>
      </section>
      <section>
        <h2 className="mb-2 font-medium">Block history</h2>
        <ul className="rounded-lg border bg-white divide-y text-sm">
          {data.blocks.map((b) => (
            <li key={b.id} className="px-3 py-2">
              {b.active ? 'Active' : 'Ended'} · {b.reason} · {b.automatic ? 'auto' : 'manual'} ·{' '}
              {new Date(b.createdAt).toLocaleString()}
            </li>
          ))}
          {data.blocks.length === 0 && <li className="px-3 py-4 text-neutral-500">None</li>}
        </ul>
      </section>
    </div>
  );
}

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border bg-white p-3">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="font-medium">{value}</div>
    </div>
  );
}
