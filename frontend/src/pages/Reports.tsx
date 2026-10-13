import { useSearchParams } from 'react-router-dom';
import { fetchText, periodQuery, useExecutiveSummary, useSecuritySummary } from '@/api/hooks';
import { useAuth } from '@/auth/useSession';
import { QueryState, Skeleton } from '@/components/ui';
import { PeriodSelector, periodLabel } from '@/components/PeriodSelector';
import { ExecutiveView, SecurityView } from '@/components/SummaryViews';
import { CopyButton, DownloadTextButton, PrintButton } from '@/components/actions';
import { Tabs, TabPanel, type TabDef } from '@/components/Tabs';
import { usePeriodParam } from '@/lib/useUrlState';

export default function ReportsPage() {
  const { can } = useAuth();
  const [period, setPeriod] = usePeriodParam();
  const [sp, setSp] = useSearchParams();
  const tabs: TabDef[] = [{ id: 'executive', label: 'Executive summary' }, ...(can('reports.security') ? [{ id: 'security', label: 'Security summary' }] : [])];
  const wanted = sp.get('tab') ?? 'executive';
  const tab = tabs.some((t) => t.id === wanted) ? wanted : 'executive';
  const exec = useExecutiveSummary(period);
  const sec = useSecuritySummary(period, can('reports.security') && tab === 'security');
  const path = tab === 'security' ? '/reports/security-summary' : '/reports/executive-summary';
  const text = () => fetchText(path, periodQuery(period));

  return (
    <div className="stack">
      <div className="page-head">
        <div><h1>Reports</h1><p className="muted" style={{ margin: 0 }}>{periodLabel(period)}. Incident reports are on each incident's page.</p></div>
        <div className="toolbar no-print"><CopyButton onGetText={text} label="Copy as text" /><DownloadTextButton filename={`${tab}-summary.txt`} onGetText={text} /><PrintButton /></div>
      </div>
      <PeriodSelector value={period} onChange={setPeriod} />
      <Tabs tabs={tabs} value={tab} label="Reports" idPrefix="rep" onChange={(t) => setSp((p) => { const n = new URLSearchParams(p); n.set('tab', t); return n; }, { replace: true })} />
      <TabPanel id="executive" idPrefix="rep" active={tab === 'executive'}><QueryState query={exec} skeleton={<Skeleton lines={7} />}>{(s) => <ExecutiveView s={s} />}</QueryState></TabPanel>
      <TabPanel id="security" idPrefix="rep" active={tab === 'security'}><QueryState query={sec} skeleton={<Skeleton lines={7} />}>{(s) => <SecurityView s={s} />}</QueryState></TabPanel>
    </div>
  );
}
