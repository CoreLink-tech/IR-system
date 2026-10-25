'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

export default function SettingsPage() {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Record<string, unknown>>('/settings')
      .then(setData)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Settings</h1>
      <p className="text-sm text-neutral-600">Read-only operational settings. Secrets are never shown.</p>
      {error && <p className="text-red-600">{error}</p>}
      {data && (
        <pre className="overflow-x-auto rounded-lg border bg-white p-4 text-sm">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}
