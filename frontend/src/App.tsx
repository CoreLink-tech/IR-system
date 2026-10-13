import { lazy, Suspense, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/auth/useSession';
import { Route, Routes } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { ErrorBoundary, NotFoundPage, RequireAuth, RequireCap } from '@/components/guards';
import { Skeleton } from '@/components/ui';
import SignInPage from '@/pages/SignIn';
import OverviewPage from '@/pages/Overview';

// Pages that are not needed on first load are split out, which keeps the first download small.
const IncidentsPage = lazy(() => import('@/pages/Incidents'));
const IncidentDetailPage = lazy(() => import('@/pages/IncidentDetail'));
const IpsPage = lazy(() => import('@/pages/Ips'));
const IpDetailPage = lazy(() => import('@/pages/IpDetail'));
const BlockingPage = lazy(() => import('@/pages/Blocking'));
const ReportsPage = lazy(() => import('@/pages/Reports'));
const ChangePasswordPage = lazy(() => import('@/pages/ChangePassword'));
const AdminUsersPage = lazy(() => import('@/pages/AdminUsers'));
const AdminApiKeysPage = lazy(() => import('@/pages/AdminApiKeys'));
const AdminRulesPage = lazy(() => import('@/pages/AdminRules'));
const AdminAuditPage = lazy(() => import('@/pages/AdminAudit'));
const AdminSettingsPage = lazy(() => import('@/pages/AdminSettings'));

export default function App() {
  const qc = useQueryClient();
  const { status } = useAuth();
  // Nothing fetched for one person may be shown to the next. Signing out empties the cache.
  useEffect(() => { if (status === 'signedOut') qc.clear(); }, [status, qc]);
  return (
    <ErrorBoundary>
      <Suspense fallback={<main><Skeleton lines={5} /></main>}>
        <Routes>
          <Route path="/sign-in" element={<SignInPage />} />
          <Route element={<RequireAuth><Layout /></RequireAuth>}>
            <Route path="/" element={<RequireCap cap="reports.executive"><OverviewPage /></RequireCap>} />
            <Route path="/incidents" element={<RequireCap cap="incidents.read"><IncidentsPage /></RequireCap>} />
            <Route path="/incidents/:id" element={<RequireCap cap="incidents.read"><IncidentDetailPage /></RequireCap>} />
            <Route path="/ips" element={<RequireCap cap="ips.read"><IpsPage /></RequireCap>} />
            <Route path="/ips/:ip" element={<RequireCap cap="ips.read"><IpDetailPage /></RequireCap>} />
            <Route path="/blocking" element={<RequireCap cap="blocks.read"><BlockingPage /></RequireCap>} />
            <Route path="/reports" element={<RequireCap cap="reports.executive"><ReportsPage /></RequireCap>} />
            <Route path="/account/password" element={<ChangePasswordPage />} />
            <Route path="/admin/users" element={<RequireCap cap="users.manage"><AdminUsersPage /></RequireCap>} />
            <Route path="/admin/api-keys" element={<RequireCap cap="apikeys.manage"><AdminApiKeysPage /></RequireCap>} />
            <Route path="/admin/rules" element={<RequireCap cap="rules.manage"><AdminRulesPage /></RequireCap>} />
            <Route path="/admin/audit" element={<RequireCap cap="audit.read"><AdminAuditPage /></RequireCap>} />
            <Route path="/admin/settings" element={<RequireCap cap="settings.read"><AdminSettingsPage /></RequireCap>} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
