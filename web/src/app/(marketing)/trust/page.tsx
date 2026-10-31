export const metadata = { title: 'Trust — Watcher' };

export default function TrustPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16 prose prose-neutral dark:prose-invert">
      <h1>Watcher Trust Center</h1>
      <p>
        Watcher (IR-System) is a commerce security monitoring product. This page summarizes how we handle data for
        pilot deployments.
      </p>
      <h2>Data we process</h2>
      <ul>
        <li>Security events and decisions you send via API</li>
        <li>Optional server logs you ship to Watcher</li>
        <li>Admin account data for the dashboard</li>
      </ul>
      <h2>What we do not want</h2>
      <ul>
        <li>Full payment card numbers, CVV, or raw passwords (redacted at ingest where possible)</li>
        <li>Watcher is designed to stay outside PCI DSS cardholder data scope</li>
      </ul>
      <h2>Security controls</h2>
      <ul>
        <li>API keys hashed at rest with a server pepper</li>
        <li>JWT access tokens (short-lived) + rotating refresh cookies</li>
        <li>Optional TOTP 2FA for dashboard users</li>
        <li>Tamper-evident audit log (hash chain)</li>
        <li>Role-based access (SUPER_ADMIN, SECURITY_ADMIN, ANALYST, VIEWER)</li>
      </ul>
      <h2>Your rights (GDPR / NDPR)</h2>
      <p>
        Workspace admins can export or erase subject data via the privacy API. Contact your Watcher operator for
        requests.
      </p>
      <h2>Status</h2>
      <p>
        Service status: <a href="/status">/status</a>
      </p>
    </main>
  );
}
