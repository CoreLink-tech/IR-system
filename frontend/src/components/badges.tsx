import type { ReactNode } from 'react';
import { IconAlert, IconBan, IconCheck, IconClock, IconEye, IconFlag, IconInfo, IconOctagon, IconSearch, IconShield, IconUser } from './icons';
import { POSTURE_LABEL, RISK_LABEL, SCOPE_LABEL, SEVERITY_LABEL, STATUS_LABEL, type Scope } from '@/lib/format';

/** The word is always there, and so is an icon. Colour is only a hint. */
const SEV: Record<string, { cls: string; icon: ReactNode }> = {
  CRITICAL: { cls: 'sev-critical', icon: <IconOctagon /> },
  HIGH: { cls: 'sev-high', icon: <IconAlert /> },
  MEDIUM: { cls: 'sev-medium', icon: <IconAlert /> },
  SUSPICIOUS: { cls: 'sev-medium', icon: <IconEye /> },
  LOW: { cls: 'sev-low', icon: <IconInfo /> },
  INFO: { cls: 'sev-info', icon: <IconInfo /> },
  NORMAL: { cls: 'sev-info', icon: <IconCheck /> },
};

export function SeverityBadge({ value }: { value: string }) {
  const s = SEV[value] ?? SEV.INFO;
  return <span className={`badge ${s.cls}`}>{s.icon}<span>{SEVERITY_LABEL[value] ?? value}</span></span>;
}

export function RiskBadge({ level }: { level: string }) {
  const s = SEV[level] ?? SEV.INFO;
  return <span className={`badge ${s.cls}`}>{s.icon}<span>{RISK_LABEL[level] ?? level}</span></span>;
}

export function StatusBadge({ value }: { value: string }) {
  const done = value === 'RESOLVED' || value === 'FALSE_POSITIVE';
  return <span className={`badge ${done ? 'ok' : 'sev-info'}`}>{done ? <IconCheck /> : value === 'OPEN' ? <IconFlag /> : <IconSearch />}<span>{STATUS_LABEL[value] ?? value}</span></span>;
}

export function ScopeBadge({ scope }: { scope: Scope }) {
  return <span className="badge sev-info"><IconUser /><span>{SCOPE_LABEL[scope]}</span></span>;
}

export function UnassignedBadge() {
  return <span className="badge outline"><IconFlag /><span>Unassigned</span></span>;
}

export function BlockedBadge({ blocked }: { blocked: boolean }) {
  return blocked
    ? <span className="badge sev-high"><IconBan /><span>Blocked</span></span>
    : <span className="badge sev-info"><IconCheck /><span>Not blocked</span></span>;
}

export function EnabledBadge({ on }: { on: boolean }) {
  return on ? <span className="badge ok"><IconCheck /><span>On</span></span> : <span className="badge sev-high"><IconBan /><span>Off</span></span>;
}

const POSTURE: Record<string, { cls: string; icon: ReactNode }> = {
  URGENT: { cls: 'posture-urgent', icon: <IconOctagon /> },
  ACTION_NEEDED: { cls: 'posture-action', icon: <IconAlert /> },
  MONITORING: { cls: 'posture-monitor', icon: <IconEye /> },
  ALL_CLEAR: { cls: 'posture-clear', icon: <IconShield /> },
};

export function PostureBanner({ posture, headline }: { posture: string; headline?: string }) {
  const p = POSTURE[posture] ?? POSTURE.MONITORING;
  return (
    <div className={`posture ${p.cls}`} role="status">
      {p.icon}
      <div><div>{POSTURE_LABEL[posture] ?? posture}</div>{headline && <div style={{ fontWeight: 500, fontSize: '1rem' }}>{headline}</div>}</div>
    </div>
  );
}

export function PostureChip({ posture }: { posture?: string }) {
  if (!posture) return <span className="chip role-badge"><IconClock />Checking</span>;
  const p = POSTURE[posture] ?? POSTURE.MONITORING;
  return <span className={`chip ${p.cls}`}>{p.icon}{POSTURE_LABEL[posture] ?? posture}</span>;
}
