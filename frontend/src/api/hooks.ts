import { QueryClient, useQuery } from '@tanstack/react-query';
import { api } from './client';
import { isApiError } from './errors';
import type {
  ActiveBlock, AllowRow, ApiKeyRow, AssignableUser, AuditRow, ExecutiveSummary, HealthResult, Incident,
  IncidentReport, IpDetail, IpListRow, Paginated, RuleRow, OperationalSettings, SecuritySummary, TechnicalReport, UserRow, BlockRow,
} from './types';

/** Retry connection trouble and server errors a couple of times. Never retry "no", "not found" or "slow down". */
export function shouldRetry(count: number, err: unknown): boolean {
  if (isApiError(err) && err.kind === 'http' && err.status < 500) return false;
  return count < 2;
}

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: shouldRetry, staleTime: 15_000, refetchOnWindowFocus: true, gcTime: 5 * 60_000 } },
  });
}

export interface Period { days?: number; from?: string; to?: string }
const periodQuery = (p: Period) => (p.from && p.to ? { from: p.from, to: p.to } : { days: p.days ?? 7 });

type Q = Record<string, string | number | boolean | undefined | null>;

export const useExecutiveSummary = (p: Period, refetchMs?: number | false) =>
  useQuery({ queryKey: ['executive', p], queryFn: ({ signal }) => api<ExecutiveSummary>('/reports/executive-summary', { query: periodQuery(p), signal }), refetchInterval: refetchMs ?? false });

export const useSecuritySummary = (p: Period, enabled: boolean, refetchMs?: number | false) =>
  useQuery({ queryKey: ['security-summary', p], enabled, queryFn: ({ signal }) => api<SecuritySummary>('/reports/security-summary', { query: periodQuery(p), signal }), refetchInterval: refetchMs ?? false });

export const useIncidents = (params: Q) =>
  useQuery({ queryKey: ['incidents', params], queryFn: ({ signal }) => api<Paginated<Incident>>('/incidents', { query: params, signal }), placeholderData: (prev) => prev });

export const useIncident = (id: string) =>
  useQuery({ queryKey: ['incident', id], queryFn: ({ signal }) => api<Incident>(`/incidents/${encodeURIComponent(id)}`, { signal }) });

export const useIncidentReport = (id: string) =>
  useQuery({ queryKey: ['incident-report', id], queryFn: ({ signal }) => api<IncidentReport>(`/reports/incidents/${encodeURIComponent(id)}`, { signal }) });

export const useTechnicalReport = (id: string, enabled: boolean) =>
  useQuery({ queryKey: ['technical-report', id], enabled, queryFn: ({ signal }) => api<TechnicalReport>(`/reports/technical/${encodeURIComponent(id)}`, { signal }) });

export const useIpList = (params: Q, enabled: boolean) =>
  useQuery({ queryKey: ['ips', params], enabled, queryFn: ({ signal }) => api<Paginated<IpListRow>>('/ips', { query: params, signal }), placeholderData: (prev) => prev });

export const useIp = (ip: string) =>
  useQuery({ queryKey: ['ip', ip], queryFn: ({ signal }) => api<IpDetail>(`/ips/${encodeURIComponent(ip)}`, { signal }) });

export const useActiveBlocks = (refetchMs?: number) =>
  useQuery({ queryKey: ['blocked-ips'], queryFn: ({ signal }) => api<{ data: ActiveBlock[] }>('/security/blocked-ips', { signal }), refetchInterval: refetchMs ?? false });

export const useBlockHistory = (enabled: boolean, ip?: string) =>
  useQuery({ queryKey: ['block-history', ip ?? 'all'], enabled, queryFn: ({ signal }) => api<BlockRow[]>('/security/blocks/history', { query: { ip, limit: 200 }, signal }) });

export const useAllowlist = () =>
  useQuery({ queryKey: ['allowlist'], queryFn: ({ signal }) => api<AllowRow[]>('/security/allowlist', { signal }) });

export const useApiKeys = () =>
  useQuery({ queryKey: ['api-keys'], queryFn: ({ signal }) => api<ApiKeyRow[]>('/api-keys', { signal }) });

export const useUsers = () =>
  useQuery({ queryKey: ['users'], queryFn: ({ signal }) => api<{ data: UserRow[] }>('/auth/users', { signal }) });

export const useAssignees = (enabled: boolean) =>
  useQuery({ queryKey: ['assignees'], enabled, queryFn: ({ signal }) => api<{ data: AssignableUser[] }>('/auth/assignees', { signal }) });

export const useRules = () =>
  useQuery({ queryKey: ['rules'], queryFn: ({ signal }) => api<{ data: RuleRow[] }>('/rules', { signal }) });

export const useAudit = (params: Q, enabled = true) =>
  useQuery({ queryKey: ['audit', params], enabled, queryFn: ({ signal }) => api<Paginated<AuditRow>>('/audit-logs', { query: params, signal }), placeholderData: (prev) => prev });

export const useSettings = () =>
  useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => api<OperationalSettings>('/settings/operational', { signal }) });

/** Is the API reachable at all? Public, so it works when signed out. Checked every 30 s. */
export const useHealth = () =>
  useQuery({ queryKey: ['health'], retry: 0, refetchInterval: 30_000, queryFn: ({ signal }) => api<HealthResult>('/health', { anonymous: true, signal, timeoutMs: 8_000 }) });

export const fetchText = (path: string, query: Q) => api<string>(path, { query: { ...query, format: 'text' }, text: true });
export { periodQuery };
