import { api } from './client';
import type { ApiKeyCreated, Incident, RuleRow, TimelineEntry, UserRow } from './types';

/**
 * Every change the dashboard can make. Each one waits for the server's answer. There are no
 * optimistic updates for security actions: what the screen shows afterwards is what the API
 * says happened.
 */
const post = <T>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body ?? {} });

export const changeStatus = (id: string, status: string, notes?: string) => post<Incident>(`/incidents/${encodeURIComponent(id)}/status`, { status, notes: notes || undefined });
export const assignIncident = (id: string, assignedTo: string) => post<Incident>(`/incidents/${encodeURIComponent(id)}/assign`, { assignedTo });
export const addNote = (id: string, note: string) => post<TimelineEntry>(`/incidents/${encodeURIComponent(id)}/notes`, { note });

export const blockIp = (b: { ipAddress: string; reason: string; permanent?: boolean; ttlMinutes?: number; relatedIncidentId?: string }) => post('/security/block', b);
export const unblockIp = (ipAddress: string, reason: string) => post('/security/unblock', { ipAddress, reason });
export const allowIp = (ipAddress: string, reason: string, ttlMinutes?: number) => post('/security/allow', { ipAddress, reason, ttlMinutes });
export const unallowIp = (ip: string) => api(`/security/allow/${encodeURIComponent(ip)}`, { method: 'DELETE' });
export const refreshIntelligence = (ip: string) => post(`/ips/${encodeURIComponent(ip)}/refresh-intelligence`);

export const createApiKey = (b: { name: string; scopes: string[]; expiresInDays?: number }) => post<ApiKeyCreated>('/api-keys', b);
export const rotateApiKey = (id: string) => post<ApiKeyCreated>(`/api-keys/${encodeURIComponent(id)}/rotate`);
export const revokeApiKey = (id: string) => api(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const createUser = (b: { email: string; password: string; name?: string; role: string; requirePasswordChange?: boolean }) => post<UserRow>('/auth/users', b);
export const updateUser = (id: string, b: { role?: string; isActive?: boolean }) => api<UserRow>(`/auth/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: b });
export const resetUserPassword = (id: string, newPassword: string) => post<{ ok: boolean }>(`/auth/users/${encodeURIComponent(id)}/reset-password`, { newPassword });
export const unlockUser = (id: string) => post<{ ok: boolean }>(`/auth/users/${encodeURIComponent(id)}/unlock`, {});
export const resetUser2fa = (id: string) => post<{ ok: boolean; mustEnrolAtNextSignIn?: boolean }>(`/auth/users/${encodeURIComponent(id)}/2fa/reset`, {});

export const updateRule = (code: string, b: { isEnabled?: boolean; config?: Record<string, number>; reason?: string }) => api<RuleRow>(`/rules/${encodeURIComponent(code)}`, { method: 'PATCH', body: b });
export const resetRule = (code: string, reason?: string) => post<RuleRow>(`/rules/${encodeURIComponent(code)}/reset`, { reason });

export const changePassword = (currentPassword: string, newPassword: string) =>
  api<{ ok: boolean }>('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword }, refusal401: true });
