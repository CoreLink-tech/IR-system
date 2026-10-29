'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/client-api';

type KeyRow = {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string;
  isActive: boolean;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
};

const BASE_URL =
  typeof window !== 'undefined' ? window.location.origin : 'https://your-app.vercel.app';

export default function ApiKeysPage() {
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [name, setName] = useState('');
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showIntegration, setShowIntegration] = useState(false);

  const load = () =>
    api<{ data: KeyRow[] }>('/api-keys')
      .then((r) => setRows(r.data || []))
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : 'Failed'));

  useEffect(() => {
    setLoading(true);
    void load().finally(() => setLoading(false));
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    setCreated(null);
    try {
      const r = await api<{ apiKey: string }>('/api-keys', {
        method: 'POST',
        json: { name: name.trim(), scopes: ['events:write', 'block:read'] },
      });
      setCreated(r.apiKey);
      setName('');
      setShowIntegration(true);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm('Revoke this API key? Client sites using it will stop working.')) return;
    try {
      await api(`/api-keys/${id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed');
    }
  }

  const phpSnippet = `<?php
// IR-System client integration
// Place this in your application bootstrap or middleware

define('IR_BASE_URL', '${BASE_URL}');
define('IR_API_KEY', 'YOUR_API_KEY_HERE'); // paste the key you generated

function ir_send_event(string \$eventType, string \$ipAddress, array \$metadata = []): void {
    \$payload = json_encode([
        'event_type' => \$eventType,
        'ip_address' => \$ipAddress,
        'event_id'   => bin2hex(random_bytes(8)),
        'metadata'   => \$metadata,
    ]);
    \$ch = curl_init(IR_BASE_URL . '/api/v1/events');
    curl_setopt_array(\$ch, [
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . IR_API_KEY,
            'Content-Type: application/json',
        ],
        CURLOPT_POSTFIELDS => \$payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
    ]);
    curl_exec(\$ch);
    curl_close(\$ch);
}

function ir_is_blocked(string \$ipAddress): bool {
    \$ch = curl_init(IR_BASE_URL . '/api/v1/security/blocked-ips');
    curl_setopt_array(\$ch, [
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . IR_API_KEY],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 2,
    ]);
    \$body = curl_exec(\$ch);
    curl_close(\$ch);
    \$data = json_decode(\$body ?: '[]', true);
    \$list = \$data['data'] ?? \$data;
    foreach (\$list as \$row) {
        if ((\$row['ipAddress'] ?? \$row['ip_address'] ?? '') === \$ipAddress) return true;
    }
    return false;
}

// Example usage on failed login:
// ir_send_event('login_failed', \$_SERVER['REMOTE_ADDR'], ['user' => \$email]);
`;

  const nodeSnippet = `// IR-System Node.js client
const IR_BASE_URL = '${BASE_URL}';
const IR_API_KEY = 'YOUR_API_KEY_HERE';

async function irSendEvent(eventType, ipAddress, metadata = {}) {
  await fetch(\`\${IR_BASE_URL}/api/v1/events\`, {
    method: 'POST',
    headers: {
      'Authorization': \`Bearer \${IR_API_KEY}\`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      event_type: eventType,
      ip_address: ipAddress,
      event_id: crypto.randomUUID(),
      metadata,
    }),
  }).catch(() => {}); // fire-and-forget
}

async function irIsBlocked(ipAddress) {
  const res = await fetch(\`\${IR_BASE_URL}/api/v1/security/blocked-ips\`, {
    headers: { 'Authorization': \`Bearer \${IR_API_KEY}\` },
  });
  const body = await res.json();
  const list = body.data || body;
  return list.some((r) => (r.ipAddress || r.ip_address) === ipAddress);
}

// Example: await irSendEvent('login_failed', req.ip, { user: email });
`;

  const aiPrompt = `Integrate IR-System security monitoring into this application.

Base URL: ${BASE_URL}
API Key: (paste the key generated in the IR-System admin dashboard)

Requirements:
1. On every failed login / authentication failure, send a POST to {BASE_URL}/api/v1/events with:
   - Header: Authorization: Bearer {API_KEY}
   - Body JSON: { "event_type": "login_failed", "ip_address": "<client IP>", "event_id": "<unique id>", "metadata": { "user": "<email or username>" } }

2. On successful login, optionally send event_type "login_success".

3. Before processing sensitive requests, call GET {BASE_URL}/api/v1/security/blocked-ips with the same Authorization header. If the client IP is in the returned list, reject the request with HTTP 403.

4. Keep the integration non-blocking (timeouts 2–3s, fire-and-forget for event sends). Do not let IR-System downtime break the main application.

5. Store the API key in environment variables, never hardcode it in source control.

Use the language and framework already present in this codebase.`;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">API Keys</h1>
        <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
          Create a key for each client application. Clients send security events and poll the blocklist.
        </p>
      </div>

      {error && (
        <div className="rounded-[var(--radius)] border border-[var(--critical)]/30 bg-[var(--critical-muted)] px-4 py-3 text-sm text-[var(--critical)]">
          {error}
        </div>
      )}

      {created && (
        <div className="rounded-[var(--radius-md)] border border-[var(--warning)]/40 bg-[var(--warning-muted)] p-4">
          <div className="text-sm font-semibold text-[var(--warning)]">
            Copy this key now — it is shown only once
          </div>
          <div className="mt-2 break-all font-mono text-sm">{created}</div>
          <button
            type="button"
            className="btn btn-secondary mt-3 text-xs"
            onClick={() => void navigator.clipboard.writeText(created)}
          >
            Copy key
          </button>
        </div>
      )}

      {/* Create form */}
      <form onSubmit={create} className="surface p-4">
        <div className="mb-3 text-sm font-medium">Create API key for a client application</div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[220px] flex-1">
            <label className="mb-1 block text-xs text-[var(--text-secondary)]">
              Application name
            </label>
            <input
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production shop / Mobile app / Partner site"
              required
            />
          </div>
          <button type="submit" disabled={busy || !name.trim()} className="btn btn-primary">
            {busy ? 'Creating…' : 'Generate key'}
          </button>
        </div>
      </form>

      {/* Keys table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Scopes</th>
              <th>Status</th>
              <th>Last used</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">Loading…</td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">
                  No API keys yet. Create one for each client application.
                </td>
              </tr>
            )}
            {rows.map((k) => (
              <tr key={k.id}>
                <td className="font-medium">{k.name}</td>
                <td className="mono text-xs">{k.keyPrefix}…</td>
                <td className="text-xs text-[var(--text-secondary)]">{k.scopes}</td>
                <td>
                  {k.isActive && !k.revokedAt ? (
                    <span className="badge badge-low">Active</span>
                  ) : (
                    <span className="badge badge-neutral">Revoked</span>
                  )}
                </td>
                <td className="text-xs text-[var(--text-muted)]">
                  {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'Never'}
                </td>
                <td className="text-xs text-[var(--text-muted)]">
                  {new Date(k.createdAt).toLocaleDateString()}
                </td>
                <td>
                  {k.isActive && !k.revokedAt && (
                    <button
                      type="button"
                      className="btn btn-ghost text-xs text-[var(--critical)]"
                      onClick={() => void revoke(k.id)}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Integration guide */}
      <div className="surface">
        <button
          type="button"
          className="flex w-full items-center justify-between px-4 py-3 text-left"
          onClick={() => setShowIntegration((v) => !v)}
        >
          <span className="text-sm font-semibold">Client integration guide</span>
          <span className="text-xs text-[var(--text-muted)]">
            {showIntegration ? 'Hide' : 'Show code & AI prompt'}
          </span>
        </button>

        {showIntegration && (
          <div className="space-y-5 border-t border-[var(--border)] p-4">
            <p className="text-sm text-[var(--text-secondary)]">
              Each client application needs: (1) an API key, (2) code to send events on login failures
              and other security signals, (3) code to poll the blocklist and enforce it.
            </p>

            <div>
              <div className="mb-1.5 text-xs font-medium text-[var(--text-secondary)]">
                PHP example
              </div>
              <pre className="max-h-64 overflow-auto rounded-[var(--radius)] bg-[var(--bg-base)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                {phpSnippet}
              </pre>
              <button
                type="button"
                className="btn btn-secondary mt-2 text-xs"
                onClick={() => void navigator.clipboard.writeText(phpSnippet)}
              >
                Copy PHP
              </button>
            </div>

            <div>
              <div className="mb-1.5 text-xs font-medium text-[var(--text-secondary)]">
                Node.js example
              </div>
              <pre className="max-h-64 overflow-auto rounded-[var(--radius)] bg-[var(--bg-base)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                {nodeSnippet}
              </pre>
              <button
                type="button"
                className="btn btn-secondary mt-2 text-xs"
                onClick={() => void navigator.clipboard.writeText(nodeSnippet)}
              >
                Copy Node.js
              </button>
            </div>

            <div>
              <div className="mb-1.5 text-xs font-medium text-[var(--text-secondary)]">
                Prompt for your AI coding agent
              </div>
              <pre className="max-h-48 overflow-auto rounded-[var(--radius)] bg-[var(--bg-base)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">
                {aiPrompt}
              </pre>
              <button
                type="button"
                className="btn btn-secondary mt-2 text-xs"
                onClick={() => void navigator.clipboard.writeText(aiPrompt)}
              >
                Copy AI prompt
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
