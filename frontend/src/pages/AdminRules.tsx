import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAudit, useRules } from '@/api/hooks';
import { resetRule, updateRule } from '@/api/actions';
import type { RuleRow } from '@/api/types';
import { Button, ConfirmDialog, ErrorPanel, Field, Notice, QueryState, Skeleton } from '@/components/ui';
import { EnabledBadge } from '@/components/badges';
import { announce } from '@/components/announce';
import { Time } from '@/lib/time';
import { auditSummary } from '@/lib/format';

/** Plain names for each setting. The setting's own code is only shown in small print. */
const KEY_LABEL: Record<string, string> = {
  threshold: 'How many before the rule triggers', incidentAt: 'How many before an incident is opened',
  riskPerAttempt: 'Risk added for each attempt', maxRisk: 'Most risk this rule can add', riskDelta: 'Risk added when it triggers',
  torRisk: 'Risk for the Tor network', proxyRisk: 'Risk for a proxy', vpnRisk: 'Risk for a VPN',
  distinctUsersThreshold: 'How many different accounts', distinctIpsThreshold: 'How many different addresses',
  failedLoginsThreshold: 'How many failed sign-ins', minFailedLogins: 'Failed sign-ins before it triggers',
  criticalFailedLogins: 'Failed sign-ins that make it critical', criticalFromIps: 'Addresses that make it critical',
  criticalAtIps: 'Addresses that make it critical', windowMinutes: 'Time window (fixed)',
};
const label = (k: string) => KEY_LABEL[k] ?? k;

function History({ code }: { code: string }) {
  const q = useAudit({ targetType: 'rule', targetId: code, pageSize: 10, sortBy: 'createdAt', sortOrder: 'desc' });
  return (
    <QueryState query={q} skeleton={<Skeleton lines={2} />}>
      {(r) => r.data.length === 0 ? <p className="muted">No changes recorded. This rule is as shipped.</p> : (
        <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
          {r.data.map((a) => {
            const oldC = a.metadata?.old?.config ?? {}, newC = a.metadata?.new?.config ?? {};
            const diffs = Object.keys(newC).filter((k) => oldC[k] !== newC[k]).map((k) => `${label(k)}: ${oldC[k]} to ${newC[k]}`);
            if (a.metadata?.old?.isEnabled !== a.metadata?.new?.isEnabled) diffs.unshift(`Turned ${a.metadata?.new?.isEnabled ? 'on' : 'off'}`);
            return <li key={a.id}><strong>{auditSummary(a)}</strong> <span className="muted small">(<Time value={a.createdAt} />)</span>{diffs.length > 0 && <div className="small">{diffs.join('; ')}</div>}{a.metadata?.reason && <div className="small muted">Reason: {a.metadata.reason}</div>}</li>;
          })}
        </ul>
      )}
    </QueryState>
  );
}

function RuleCard({ rule }: { rule: RuleRow }) {
  const qc = useQueryClient();
  const keys = Object.keys(rule.config);
  const fromRule = () => Object.fromEntries(keys.map((k) => [k, String(rule.config[k])]));
  const [draft, setDraft] = useState<Record<string, string>>(fromRule);
  // Show what the server holds. The card stays mounted so its confirmation message is not lost.
  const serverConfig = JSON.stringify(rule.config);
  useEffect(() => { setDraft(fromRule()); }, [serverConfig]); // eslint-disable-line react-hooks/exhaustive-deps
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<'off' | 'reset' | null>(null);
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [showHistory, setShowHistory] = useState(false);
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ['rules'] }), qc.invalidateQueries({ queryKey: ['audit'] })]);

  const changed = keys.filter((k) => rule.limits[k]?.editable && Number(draft[k]) !== rule.config[k]);

  const save = async () => {
    // Only a first look for obvious mistakes. The server checks every range again.
    const bad: Record<string, string> = {};
    for (const k of changed) {
      const n = Number(draft[k]); const lim = rule.limits[k];
      if (draft[k].trim() === '' || !Number.isInteger(n)) bad[k] = 'Enter a whole number.';
      else if (n < lim.min || n > lim.max) bad[k] = `Must be between ${lim.min} and ${lim.max}.`;
    }
    setProblems(bad);
    if (Object.keys(bad).length) return;
    setBusy(true); setError(null); setDone(null);
    try {
      await updateRule(rule.code, { config: Object.fromEntries(changed.map((k) => [k, Number(draft[k])])), reason: reason.trim() || undefined });
      await refresh(); setReason(''); setDone('Saved. The new settings apply to the next event.'); announce('Rule settings saved');
    } catch (e) { setError(e); } finally { setBusy(false); }
  };
  const toggle = async (on: boolean) => {
    setBusy(true); setError(null); setDone(null);
    try { await updateRule(rule.code, { isEnabled: on, reason: reason.trim() || undefined }); await refresh(); setConfirm(null); setDone(on ? 'Turned on.' : 'Turned off.'); announce(on ? 'Rule turned on' : 'Rule turned off'); }
    catch (e) { setError(e); } finally { setBusy(false); }
  };
  const reset = async () => {
    setBusy(true); setError(null); setDone(null);
    try { const r = await resetRule(rule.code, reason.trim() || undefined); setDraft(Object.fromEntries(Object.keys(r.config).map((k) => [k, String(r.config[k])]))); await refresh(); setConfirm(null); setDone('Back to the default settings.'); announce('Rule reset to defaults'); }
    catch (e) { setError(e); } finally { setBusy(false); }
  };

  return (
    <article className="card stack" aria-labelledby={`r-${rule.code}`}>
      <div className="page-head" style={{ marginBottom: 0 }}>
        <div><h2 id={`r-${rule.code}`} style={{ margin: 0 }}>{rule.title}</h2><p className="muted" style={{ margin: '.25rem 0 0' }}>{rule.description}</p></div>
        <div className="toolbar"><EnabledBadge on={rule.isEnabled} />{rule.isDefault ? <span className="badge sev-info">Default settings</span> : <span className="badge sev-medium">Changed</span>}</div>
      </div>
      {rule.whyItMatters && <details><summary>Why this matters</summary><p>{rule.whyItMatters}</p></details>}
      <div className="grid" role="group" aria-label={`Settings for ${rule.title}`}>
        {keys.map((k) => {
          const lim = rule.limits[k];
          return (
            <Field key={k} label={label(k)} hint={lim.editable ? `Default ${rule.defaultConfig[k]}. Allowed ${lim.min} to ${lim.max}.` : `Fixed at ${rule.config[k]}. The detector always looks at the last 10 minutes.`} error={problems[k]}>
              {(p) => <input {...p} type="number" inputMode="numeric" disabled={!lim.editable} value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} />}
            </Field>
          );
        })}
      </div>
      <Field label="Why are you changing this? (optional)">{(p) => <input {...p} type="text" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}</Field>
      {error ? <ErrorPanel compact error={error} /> : null}
      {done && <Notice tone="ok">{done}</Notice>}
      <div className="toolbar">
        <Button variant="primary" disabled={changed.length === 0} busy={busy && !confirm} onClick={() => void save()}>Save changes</Button>
        <Button disabled={rule.isDefault} onClick={() => { setError(null); setConfirm('reset'); }}>Reset to defaults</Button>
        {rule.isEnabled ? <Button onClick={() => { setError(null); setConfirm('off'); }}>Turn off</Button> : <Button onClick={() => void toggle(true)} busy={busy}>Turn on</Button>}
        <Button variant="link" aria-expanded={showHistory} onClick={() => setShowHistory((s) => !s)}>{showHistory ? 'Hide history' : 'Show change history'}</Button>
      </div>
      {showHistory && <History code={rule.code} />}
      {confirm === 'off' && (
        <ConfirmDialog title={`Turn off "${rule.title}"?`} confirmLabel="Turn off" danger busy={busy} error={error} onConfirm={() => void toggle(false)} onClose={() => setConfirm(null)}>
          <p>The system will stop looking for this kind of attack. Attacks of this kind will no longer raise incidents or add to an address's risk until you turn it back on.</p>
        </ConfirmDialog>
      )}
      {confirm === 'reset' && (
        <ConfirmDialog title={`Reset "${rule.title}" to its defaults?`} confirmLabel="Reset" busy={busy} error={error} onConfirm={() => void reset()} onClose={() => setConfirm(null)}>
          <p>Every setting of this rule goes back to the value it shipped with. Whether the rule is on or off does not change.</p>
        </ConfirmDialog>
      )}
    </article>
  );
}

export default function AdminRulesPage() {
  const rules = useRules();
  return (
    <div className="stack">
      <h1>Detection rules</h1>
      <p className="muted">These rules decide what counts as an attack. Detection is rule-based and predictable: the same activity always gives the same result. Changes apply to the next event and are recorded in the audit log.</p>
      <QueryState query={rules} skeleton={<Skeleton lines={8} height="2rem" />}>{(r) => <>{r.data.map((x) => <RuleCard key={x.code} rule={x} />)}</>}</QueryState>
    </div>
  );
}
