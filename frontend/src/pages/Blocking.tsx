import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useActiveBlocks, useAllowlist, useBlockHistory } from '@/api/hooks';
import { useAuth } from '@/auth/useSession';
import { Button, EmptyState, Notice, QueryState, Skeleton } from '@/components/ui';
import { ResponsiveTable } from '@/components/table';
import { Tabs, TabPanel, type TabDef } from '@/components/Tabs';
import { BlockDialog, ENFORCEMENT_NOTE } from '@/components/BlockDialog';
import { AllowDialog, RemoveAllowDialog, UnblockDialog } from '@/components/IpDialogs';
import { countdownLabel } from '@/lib/format';
import { Time } from '@/lib/time';

/** Re-render every so often so countdowns stay true without refetching. */
function useNow(ms: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}

export default function BlockingPage() {
  const { can } = useAuth();
  const [sp, setSp] = useSearchParams();
  const blocks = useActiveBlocks(30_000);
  const allow = useAllowlist();
  const history = useBlockHistory(can('blocks.history'));
  const now = useNow(30_000);
  const [dialog, setDialog] = useState<null | { kind: 'block' } | { kind: 'allow' } | { kind: 'unblock'; ip: string } | { kind: 'unallow'; ip: string }>(null);
  const tabs: TabDef[] = [{ id: 'active', label: 'Blocked now' }, { id: 'allowlist', label: 'Allowlist' }, ...(can('blocks.history') ? [{ id: 'history', label: 'History' }] : [])];
  const wanted = sp.get('tab') ?? 'active';
  const tab = tabs.some((t) => t.id === wanted) ? wanted : 'active';

  return (
    <div className="stack">
      <div className="page-head">
        <h1>Blocking</h1>
        <div className="toolbar">
          {can('blocks.block') && <Button variant="danger" onClick={() => setDialog({ kind: 'block' })}>Block an address</Button>}
          {can('allowlist.add') && <Button onClick={() => setDialog({ kind: 'allow' })}>Add to allowlist</Button>}
        </div>
      </div>
      <Notice title="How blocking works"><p style={{ margin: '.3rem 0 0' }}>{ENFORCEMENT_NOTE}</p></Notice>
      <Tabs tabs={tabs} value={tab} label="Blocking sections" idPrefix="blk" onChange={(t) => setSp((p) => { const n = new URLSearchParams(p); n.set('tab', t); return n; }, { replace: true })} />

      <TabPanel id="active" idPrefix="blk" active={tab === 'active'}>
        <QueryState query={blocks} skeleton={<Skeleton lines={5} height="2rem" />}>
          {(r) => r.data.length === 0 ? <EmptyState title="Nothing is blocked right now" /> : (
            <ResponsiveTable caption="Addresses blocked now" rows={r.data} rowKey={(b) => `${b.ipAddress}-${b.createdAt}`}
              columns={[
                { key: 'a', header: 'Address', cell: (b) => <Link to={`/ips/${encodeURIComponent(b.ipAddress)}`}>{b.ipAddress}</Link> },
                { key: 'w', header: 'How', cell: (b) => (b.automatic ? 'Automatic' : 'By an administrator') },
                { key: 'r', header: 'Reason', cell: (b) => b.reason },
                { key: 's', header: 'Since', cell: (b) => <Time value={b.createdAt} /> },
                { key: 'e', header: 'Expires', cell: (b) => (b.permanent ? 'Never (permanent)' : <span>{countdownLabel(b.expiresAt, now)} <span className="muted small">(<Time value={b.expiresAt} />)</span></span>) },
                ...(can('blocks.unblock') ? [{ key: 'x', header: 'Action', cell: (b: { ipAddress: string }) => <Button onClick={() => setDialog({ kind: 'unblock', ip: b.ipAddress })}>Unblock<span className="sr-only"> {b.ipAddress}</span></Button> }] : []),
              ]} />
          )}
        </QueryState>
      </TabPanel>

      <TabPanel id="allowlist" idPrefix="blk" active={tab === 'allowlist'}>
        <p className="muted">Addresses here can never be blocked. Use it for your own office, partners and monitoring.</p>
        <QueryState query={allow} skeleton={<Skeleton lines={4} height="2rem" />}>
          {(rows) => rows.length === 0 ? <EmptyState title="The allowlist is empty" /> : (
            <ResponsiveTable caption="Allowlist" rows={rows} rowKey={(a) => a.id}
              columns={[
                { key: 'a', header: 'Address', cell: (a) => <Link to={`/ips/${encodeURIComponent(a.ipAddress)}`}>{a.ipAddress}</Link> },
                { key: 'r', header: 'Reason', cell: (a) => a.reason },
                { key: 'c', header: 'Added', cell: (a) => <Time value={a.createdAt} /> },
                { key: 'e', header: 'Expires', cell: (a) => (a.expiresAt ? countdownLabel(a.expiresAt, now) : 'Until removed') },
                ...(can('allowlist.remove') ? [{ key: 'x', header: 'Action', cell: (a: { ipAddress: string }) => <Button onClick={() => setDialog({ kind: 'unallow', ip: a.ipAddress })}>Remove<span className="sr-only"> {a.ipAddress}</span></Button> }] : []),
              ]} />
          )}
        </QueryState>
      </TabPanel>

      <TabPanel id="history" idPrefix="blk" active={tab === 'history'}>
        <QueryState query={history} skeleton={<Skeleton lines={6} height="2rem" />}>
          {(rows) => rows.length === 0 ? <EmptyState title="No block history yet" /> : (
            <ResponsiveTable caption="Block history" rows={rows} rowKey={(b) => b.id}
              columns={[
                { key: 'w', header: 'When', cell: (b) => <Time value={b.createdAt} /> },
                { key: 'a', header: 'What', cell: (b) => (b.action === 'BLOCK' ? 'Blocked' : 'Unblocked') },
                { key: 'i', header: 'Address', cell: (b) => <Link to={`/ips/${encodeURIComponent(b.ipAddress)}`}>{b.ipAddress}</Link> },
                { key: 'h', header: 'How', cell: (b) => (b.automatic ? 'Automatic' : 'By an administrator') },
                { key: 'r', header: 'Reason', cell: (b) => b.reason },
                { key: 'e', header: 'Until', cell: (b) => (b.action !== 'BLOCK' ? '' : b.isPermanent ? 'Permanent' : countdownLabel(b.expiresAt, now)) },
              ]} />
          )}
        </QueryState>
      </TabPanel>

      {dialog?.kind === 'block' && <BlockDialog onClose={() => setDialog(null)} />}
      {dialog?.kind === 'allow' && <AllowDialog onClose={() => setDialog(null)} />}
      {dialog?.kind === 'unblock' && <UnblockDialog ip={dialog.ip} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'unallow' && <RemoveAllowDialog ip={dialog.ip} onClose={() => setDialog(null)} />}
    </div>
  );
}
