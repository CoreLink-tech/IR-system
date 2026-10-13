import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { useActiveBlocks, useAllowlist, useIncidents, useIp } from '@/api/hooks';
import { refreshIntelligence } from '@/api/actions';
import { useAuth } from '@/auth/useSession';
import { Button, EmptyState, ErrorPanel, Notice, QueryState, Skeleton } from '@/components/ui';
import { BlockedBadge, RiskBadge, ScopeBadge, SeverityBadge, StatusBadge } from '@/components/badges';
import { ResponsiveTable } from '@/components/table';
import { BlockDialog, ENFORCEMENT_NOTE } from '@/components/BlockDialog';
import { AllowDialog, RemoveAllowDialog, UnblockDialog } from '@/components/IpDialogs';
import { announce } from '@/components/announce';
import { EVENT_LABEL, countdownLabel, scopeOf } from '@/lib/format';
import { Time } from '@/lib/time';

export default function IpDetailPage() {
  const { ip: param = '' } = useParams();
  const ip = decodeURIComponent(param);
  const { can } = useAuth();
  const qc = useQueryClient();
  const detail = useIp(ip);
  const blocks = useActiveBlocks();
  const allow = useAllowlist();
  const incidents = useIncidents({ sourceIp: detail.data?.ip.ipAddress ?? ip, pageSize: 10, sortBy: 'createdAt', sortOrder: 'desc' });
  const [dialog, setDialog] = useState<'block' | 'unblock' | 'allow' | 'unallow' | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshErr, setRefreshErr] = useState<unknown>(null);

  if (detail.isPending) return <Skeleton lines={6} height="1.4rem" />;
  if (detail.isError && !detail.data) return <ErrorPanel error={detail.error} onRetry={() => void detail.refetch()} />;
  const d = detail.data!;
  const addr = d.ip.ipAddress;
  const activeBlock = blocks.data?.data.find((b) => b.ipAddress === addr);
  const allowRow = allow.data?.find((a) => a.ipAddress === addr && (!a.expiresAt || new Date(a.expiresAt).getTime() > Date.now()));
  const checked = !!d.ip.lastIntelUpdate;

  const doRefresh = async () => {
    setRefreshing(true); setRefreshErr(null);
    try { await refreshIntelligence(addr); await qc.invalidateQueries({ queryKey: ['ip'] }); announce('Intelligence refreshed'); } catch (e) { setRefreshErr(e); } finally { setRefreshing(false); }
  };

  return (
    <div className="stack">
      <p className="no-print"><Link to="/ips">All addresses</Link></p>
      <div className="page-head">
        <div>
          <h1 className="mono" style={{ marginBottom: '.25rem' }}>{addr}</h1>
          <div className="toolbar">
            <RiskBadge level={d.ip.riskLevel} /><span className="muted">score {d.ip.riskScore}</span>
            <QueryState query={blocks} skeleton={<span className="muted">Checking block status...</span>}>{() => <BlockedBadge blocked={!!activeBlock} />}</QueryState>
            {allowRow && <span className="badge ok">On the allowlist</span>}
            {d.isPrivate && <span className="badge sev-info">Private or internal address</span>}
          </div>
        </div>
        <div className="toolbar no-print">
          {can('ips.refresh') && <Button onClick={doRefresh} busy={refreshing}>Refresh intelligence</Button>}
          {can('blocks.block') && !activeBlock && <Button variant="danger" disabled={!!allowRow} onClick={() => setDialog('block')}>Block</Button>}
          {can('blocks.unblock') && activeBlock && <Button variant="primary" onClick={() => setDialog('unblock')}>Unblock</Button>}
          {can('allowlist.add') && !allowRow && <Button onClick={() => setDialog('allow')}>Add to allowlist</Button>}
          {can('allowlist.remove') && allowRow && <Button onClick={() => setDialog('unallow')}>Remove from allowlist</Button>}
        </div>
      </div>
      {allowRow && can('blocks.block') && <Notice>This address is on the allowlist, so it cannot be blocked. Remove it from the allowlist first.</Notice>}
      {refreshErr ? <ErrorPanel compact error={refreshErr} /> : null}
      {activeBlock && <Notice title="Currently blocked">{activeBlock.automatic ? 'Blocked automatically' : 'Blocked by an administrator'}: {activeBlock.reason}. Expires {countdownLabel(activeBlock.expiresAt)}. {ENFORCEMENT_NOTE}</Notice>}

      <div className="grid-2">
        <section className="card"><h2>What has been seen</h2>
          <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
            <dt>First seen</dt><dd><Time value={d.ip.firstSeenAt} /></dd>
            <dt>Last seen</dt><dd><Time value={d.ip.lastSeenAt} /></dd>
            <dt>Requests</dt><dd>{d.ip.requestCount}</dd>
            <dt>Events</dt><dd>{d.ip.eventCount}</dd>
            <dt>Failed sign-ins</dt><dd>{d.ip.failedLogins}</dd>
          </dl>
        </section>
        <section className="card"><h2>Where it comes from</h2>
          {!checked ? <p className="muted">No provider has checked this address, so its location and network type are not known. That does not mean it is safe. If no provider is set up, ask your administrator to configure one in the Settings page.</p> : (
            <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '.3rem 1rem' }}>
              <dt>Location</dt><dd>{[d.ip.city, d.ip.region, d.ip.country].filter(Boolean).join(', ') || 'unknown'}</dd>
              <dt>VPN</dt><dd>{d.ip.isVpn ? 'Yes' : 'No'}</dd><dt>Proxy</dt><dd>{d.ip.isProxy ? 'Yes' : 'No'}</dd>
              <dt>Tor</dt><dd>{d.ip.isTor ? 'Yes' : 'No'}</dd><dt>Data centre</dt><dd>{d.ip.isDatacenter ? 'Yes' : 'No'}</dd>
              <dt>Known as malicious</dt><dd>{d.ip.isMalicious ? 'Yes' : 'No'}</dd><dt>Reputation score</dt><dd>{d.ip.reputationScore}</dd>
              <dt>Checked</dt><dd><Time value={d.ip.lastIntelUpdate} /></dd>
            </dl>
          )}
        </section>
      </div>

      <section><h2>Related incidents</h2>
        <QueryState query={incidents} skeleton={<Skeleton lines={3} />}>
          {(r) => r.data.length === 0 ? <EmptyState title="No incidents for this address" /> : (
            <ResponsiveTable caption="Incidents for this address" rows={r.data} rowKey={(i) => i.id}
              columns={[
                { key: 'n', header: 'Incident', cell: (i) => <Link to={`/incidents/${encodeURIComponent(i.incidentId)}`}>{i.incidentId}</Link> },
                { key: 't', header: 'What happened', cell: (i) => i.title },
                { key: 's', header: 'Severity', cell: (i) => <SeverityBadge value={i.severity} /> },
                { key: 'st', header: 'Status', cell: (i) => <StatusBadge value={i.status} /> },
                { key: 'sc', header: 'Affects', cell: (i) => <ScopeBadge scope={scopeOf(i)} /> },
              ]} />
          )}
        </QueryState>
      </section>

      <section><h2>Block history</h2>
        {d.blocks.length === 0 ? <p className="muted">This address has never been blocked or unblocked.</p> : (
          <ResponsiveTable caption="Block history" rows={d.blocks} rowKey={(b) => b.id}
            columns={[
              { key: 'a', header: 'What', cell: (b) => (b.action === 'BLOCK' ? 'Blocked' : 'Unblocked') },
              { key: 'h', header: 'How', cell: (b) => (b.automatic ? 'Automatic' : 'By an administrator') },
              { key: 'r', header: 'Reason', cell: (b) => b.reason },
              { key: 'w', header: 'When', cell: (b) => <Time value={b.createdAt} /> },
              { key: 'e', header: 'Until', cell: (b) => (b.action === 'BLOCK' ? (b.isPermanent ? 'Permanent' : <Time value={b.expiresAt} />) : '') },
            ]} />
        )}
      </section>

      {can('events.read') && (
        <section><h2>Recent events</h2>
          {d.events.length === 0 ? <p className="muted">No events to show.</p> : (
            <ResponsiveTable caption="Recent events" rows={d.events} rowKey={(e) => e.id}
              columns={[
                { key: 't', header: 'When', cell: (e) => <Time value={e.occurredAt} /> },
                { key: 'k', header: 'Kind', cell: (e) => EVENT_LABEL[e.eventType] ?? e.eventType },
                { key: 's', header: 'Severity', cell: (e) => <SeverityBadge value={e.severity} /> },
                { key: 'p', header: 'Path', cell: (e) => <code>{e.requestMethod ? `${e.requestMethod} ` : ''}{e.requestPath ?? ''}</code> },
                { key: 'r', header: 'Risk', cell: (e) => <RiskBadge level={e.riskLevel} /> },
              ]} />
          )}
        </section>
      )}
      {dialog === 'block' && <BlockDialog ip={addr} onClose={() => setDialog(null)} />}
      {dialog === 'unblock' && <UnblockDialog ip={addr} onClose={() => setDialog(null)} />}
      {dialog === 'allow' && <AllowDialog ip={addr} onClose={() => setDialog(null)} />}
      {dialog === 'unallow' && <RemoveAllowDialog ip={addr} onClose={() => setDialog(null)} />}
    </div>
  );
}
