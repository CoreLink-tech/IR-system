import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-2xl font-semibold">Security Dashboard</h1>
      <p className="mt-2 text-neutral-600">
        IR-System on Next.js with SQLite / Turso. Client websites send events via API key;
        this app stores and analyses them in its own database.
      </p>
      <ul className="mt-6 list-disc space-y-2 pl-5">
        <li>
          <code className="text-sm">GET /api/v1/health</code> — liveness
        </li>
        <li>
          <code className="text-sm">GET /api/v1/health/ready</code> — database
        </li>
        <li>
          <code className="text-sm">POST /api/v1/events</code> — ingest (API key)
        </li>
        <li>
          <code className="text-sm">GET /api/v1/security/blocked-ips</code> — blocklist
        </li>
      </ul>
      <p className="mt-6">
        <Link className="text-blue-600 underline" href="/sign-in">
          Sign in
        </Link>
        {' · '}
        <a className="text-blue-600 underline" href="/api/v1/health">
          Health
        </a>
      </p>
    </main>
  );
}
