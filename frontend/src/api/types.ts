import type {
  ExecutiveSummary, IncidentReport, SecuritySummary, TechnicalReport,
} from '@backend/reports/report.types';

// The report shapes come straight from the backend, so a change there breaks this build.
export type { ExecutiveSummary, IncidentReport, SecuritySummary, TechnicalReport };

export type Role = 'SUPER_ADMIN' | 'SECURITY_ADMIN' | 'ANALYST' | 'VIEWER';
export const ROLE_LIST: Role[] = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'];

export interface User { id: string; email: string; name: string | null; role: Role; isActive: boolean; mustChangePassword: boolean; twoFactorEnabled?: boolean }
export interface UserRow extends User { lastLoginAt: string | null; createdAt: string; lockedUntil?: string | null; twoFactorEnabled?: boolean }
export interface Assignee { id: string; email: string; name: string | null }
export interface AssignableUser extends Assignee { role: Role }

export interface Paginated<T> { data: T[]; meta: { page: number; pageSize: number; total: number; totalPages: number } }

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'NORMAL' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type Posture = 'ALL_CLEAR' | 'MONITORING' | 'ACTION_NEEDED' | 'URGENT';

export interface TimelineEntry { id: string; incidentId: string; action: string; actor: string | null; details: string | null; createdAt: string }

export interface SecurityEvent {
  id: string; eventType: string; severity: string; ipAddress: string | null; userId: string | null;
  requestMethod: string | null; requestPath: string | null; riskScore: number; riskLevel: string;
  occurredAt: string; createdAt: string;
}

export interface Incident {
  id: string; incidentId: string; title: string; description: string;
  severity: Severity; riskScore: number; status: IncidentStatus;
  sourceIp: string | null; userId: string | null; detectionRule: string | null;
  assignedTo: string | null; assignee: Assignee | null;
  resolutionNotes: string | null; createdAt: string; updatedAt: string; resolvedAt: string | null;
  timeline?: TimelineEntry[]; events?: SecurityEvent[];
}

export interface IpRecord {
  id: string; ipAddress: string; firstSeenAt: string; lastSeenAt: string;
  requestCount: number; eventCount: number; failedLogins: number;
  riskScore: number; riskLevel: RiskLevel;
  country: string | null; region: string | null; city: string | null;
  isVpn: boolean; isProxy: boolean; isTor: boolean; isDatacenter: boolean; isMalicious: boolean;
  reputationScore: number; lastIntelUpdate: string | null;
}
export interface IpListRow extends IpRecord { blocked: boolean }
export interface BlockRow {
  id: string; ipAddress: string; action: 'BLOCK' | 'UNBLOCK'; reason: string;
  administratorId: string | null; relatedIncidentId: string | null;
  isPermanent: boolean; expiresAt: string | null; active: boolean; automatic: boolean; createdAt: string;
}
export interface IpDetail { ip: IpRecord; events: SecurityEvent[]; blocks: BlockRow[]; isPrivate: boolean }
export interface ActiveBlock { ipAddress: string; reason: string; expiresAt: string | null; permanent: boolean; automatic: boolean; createdAt: string }
export interface AllowRow { id: string; ipAddress: string; reason: string; addedBy: string | null; createdAt: string; expiresAt: string | null }

export interface ApiKeyRow {
  id: string; name: string; keyPrefix: string; scopes: string; isActive: boolean;
  expiresAt: string | null; lastUsedAt: string | null; revokedAt: string | null; createdAt: string;
}
export interface ApiKeyCreated { id: string; name: string; scopes: string[]; expiresAt: string | null; apiKey: string }

export interface RuleLimit { min: number; max: number; editable: boolean }
export interface RuleRow {
  code: string; title: string; name: string; description: string; whyItMatters: string | null;
  isEnabled: boolean; priority: number;
  config: Record<string, number>; defaultConfig: Record<string, number>; isDefault: boolean;
  limits: Record<string, RuleLimit>; updatedAt: string | null;
}

export interface AuditRow {
  id: string; requestId: string | null; actorType: string; actorId: string | null; actorLabel: string | null;
  action: string; targetType: string | null; targetId: string | null; result: string;
  metadata: Record<string, any> | null; ipAddress: string | null; createdAt: string;
}

export interface OperationalSettings {
  version: string; intelligenceProviders: string[];
  autoBlock: { enabled: boolean; minimumRisk: number; blockMinutes: number };
  rateLimits: { windowSeconds: number; perAddress: number; perWebsiteKey: number; signIn: number };
  riskLevels: { suspicious: number; high: number; critical: number };
  sessions: { accessTokenLifetime: string; refreshTokenDays: number; secureCookie: boolean };
}

export interface LoginSession { user: User; accessToken: string; csrfToken?: string; refreshToken?: string; recoveryCodes?: string[] }
export interface LoginTwoFactorRequired { twoFactorRequired: true; challengeToken: string; expiresInSeconds: number }
export interface LoginEnrollmentRequired { twoFactorEnrollmentRequired: true; challengeToken: string; expiresInSeconds: number }
export type LoginResult = LoginSession | LoginTwoFactorRequired | LoginEnrollmentRequired

export function isLoginSession(r: LoginResult): r is LoginSession {
  return 'accessToken' in r && 'user' in r;
}
export function isTwoFactorRequired(r: LoginResult): r is LoginTwoFactorRequired {
  return 'twoFactorRequired' in r && !!(r as LoginTwoFactorRequired).twoFactorRequired;
}
export function isEnrollmentRequired(r: LoginResult): r is LoginEnrollmentRequired {
  return 'twoFactorEnrollmentRequired' in r && !!(r as LoginEnrollmentRequired).twoFactorEnrollmentRequired;
}

export interface TwoFactorStatus {
  enabled: boolean;
  required: boolean;
  recoveryCodesRemaining: number;
  enrolledAt: string | null;
}
export interface SessionRow {
  id: string; device: string | null; ipAddress: string | null;
  createdAt: string; lastUsedAt: string | null; expiresAt: string; current?: boolean;
}
export interface HealthResult { status: string; service: string; version: string; time: string }
