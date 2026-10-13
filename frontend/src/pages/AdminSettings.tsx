import { useHealth, useSettings } from '@/api/hooks';
import { Notice, QueryState, Skeleton } from '@/components/ui';

const Row = ({ k, v }: { k: string; v: string }) => <><dt>{k}</dt><dd>{v}</dd></>;

export default function AdminSettingsPage() {
  const s = useSettings();
  const h = useHealth();
  return (
    <div className="stack">
      <h1>Settings</h1>
      <Notice>These are facts about how this system is set up. They are set in the server's configuration file and cannot be changed here. No passwords or keys are ever shown.</Notice>
      <section className="card"><h2>Connection</h2>
        <p>{h.isPending ? 'Checking...' : h.isError ? 'The Security API cannot be reached right now.' : `The Security API is reachable (version ${h.data.version}).`}</p>
      </section>
      <QueryState query={s} skeleton={<Skeleton lines={8} />}>
        {(c) => (
          <div className="grid-2">
            <section className="card"><h2>Address intelligence</h2>
              {c.intelligenceProviders.length === 0 ? <p>No provider is set up. Locations and network types are not looked up, and reports say so.</p> : <p>Providers in use: {c.intelligenceProviders.join(', ')}.</p>}
            </section>
            <section className="card"><h2>Automatic blocking</h2>
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
                <Row k="Automatic blocking" v={c.autoBlock.enabled ? 'On' : 'Off'} />
                <Row k="Blocks at risk score" v={`${c.autoBlock.minimumRisk} or more`} />
                <Row k="Block length" v={`${c.autoBlock.blockMinutes} minutes`} />
              </dl>
            </section>
            <section className="card"><h2>Rate limits</h2>
              <p className="muted small">Per {c.rateLimits.windowSeconds} seconds.</p>
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
                <Row k="Each address" v={`${c.rateLimits.perAddress} requests`} />
                <Row k="Each website key" v={`${c.rateLimits.perWebsiteKey} requests`} />
                <Row k="Sign-in attempts per address" v={`${c.rateLimits.signIn}`} />
              </dl>
            </section>
            <section className="card"><h2>Risk levels</h2>
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
                <Row k="Suspicious from" v={`score ${c.riskLevels.suspicious}`} /><Row k="High from" v={`score ${c.riskLevels.high}`} /><Row k="Critical from" v={`score ${c.riskLevels.critical}`} />
              </dl>
            </section>
            <section className="card"><h2>Sign-in sessions</h2>
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
                <Row k="Short-term pass lasts" v={c.sessions.accessTokenLifetime} /><Row k="Stay signed in up to" v={`${c.sessions.refreshTokenDays} days`} />
                <Row k="Secure cookie" v={c.sessions.secureCookie ? 'Yes' : 'No (only acceptable for local testing)'} />
              </dl>
            </section>
            <section className="card"><h2>Version</h2><p style={{ margin: 0 }}>Security API {c.version}</p></section>
          </div>
        )}
      </QueryState>
    </div>
  );
}
