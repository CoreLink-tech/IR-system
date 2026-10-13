import { useQueryClient } from '@tanstack/react-query';
import { useExecutiveSummary, useSecuritySummary, fetchText, periodQuery } from '@/api/hooks';
import { useAuth } from '@/auth/useSession';
import { Button, ErrorPanel, QueryState, Skeleton } from '@/components/ui';
import { PeriodSelector, periodLabel } from '@/components/PeriodSelector';
import { ExecutiveView, SecurityView } from '@/components/SummaryViews';
import { CopyButton, DownloadTextButton, PrintButton } from '@/components/actions';
import { announce } from '@/components/announce';
import { usePeriodParam } from '@/lib/useUrlState';
import { Time } from '@/lib/time';

const REFRESH_MS = 60_000;

export default function OverviewPage() {
  const { can } = useAuth();
  const [period, setPeriod] = usePeriodParam();
  const qc = useQueryClient();
  const exec = useExecutiveSummary(period, REFRESH_MS);
  const analyst = can('reports.security');
  const sec = useSecuritySummary(period, analyst, REFRESH_MS);
  const text = () => fetchText('/reports/executive-summary', periodQuery(period));
  const refresh = async () => { await qc.invalidateQueries({ queryKey: ['executive'] }); await qc.invalidateQueries({ queryKey: ['security-summary'] }); announce('Overview refreshed'); };

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="muted" style={{ margin: 0 }}>{periodLabel(period)}.{' '}
            {exec.dataUpdatedAt > 0 && <span>Last updated <Time value={new Date(exec.dataUpdatedAt).toISOString()} />. Refreshes every minute.</span>}
          </p>
        </div>
        <div className="toolbar no-print">
          <Button onClick={refresh} busy={exec.isFetching && !exec.isPending}>Refresh now</Button>
          <CopyButton onGetText={text} label="Copy as text" />
          <DownloadTextButton filename="security-overview.txt" onGetText={text} />
          <PrintButton />
        </div>
      </div>
      <PeriodSelector value={period} onChange={setPeriod} />
      <QueryState query={exec} skeleton={<Skeleton lines={6} height="1.4rem" />}>{(s) => <ExecutiveView s={s} />}</QueryState>
      {analyst && (
        <section aria-labelledby="det"><h2 id="det">Detail for analysts</h2>
          <QueryState query={sec} skeleton={<Skeleton lines={5} />}>{(s) => <SecurityView s={s} />}</QueryState>
        </section>
      )}
      {exec.isError && exec.data && <ErrorPanel compact error={exec.error} onRetry={() => void exec.refetch()} />}
    </div>
  );
}
