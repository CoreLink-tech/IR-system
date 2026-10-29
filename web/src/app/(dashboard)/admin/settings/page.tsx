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
      <div>
        <div className="kicker">Administration</div>
        <h1 className="text-[22px] font-[750] tracking-[-0.5px]">Settings</h1>
        <p className="mt-1 text-[13px] text-[#718079]">Read-only operational settings. Secrets are never shown.</p>
      </div>
      {error && (
        <div className="rounded-[5px] border border-[#b64040]/30 bg-[#faeeee] px-4 py-3 text-[12px] text-[#a13a3a]">{error}</div>
      )}
      {data && (
        <pre className="surface overflow-x-auto p-4 text-[12px] text-[#405148]">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}
