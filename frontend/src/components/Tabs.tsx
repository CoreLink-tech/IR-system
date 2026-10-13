import { useRef, type KeyboardEvent } from 'react';

export interface TabDef { id: string; label: string }

/** Arrow keys, Home and End move between tabs, as people expect from a tab list. */
export function Tabs({ tabs, value, onChange, label, idPrefix = 'tab' }: { tabs: TabDef[]; value: string; onChange: (id: string) => void; label: string; idPrefix?: string }) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const move = (e: KeyboardEvent, i: number) => {
    const next = e.key === 'ArrowRight' ? (i + 1) % tabs.length : e.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
    if (next < 0) return;
    e.preventDefault();
    onChange(tabs[next].id);
    refs.current[tabs[next].id]?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button key={t.id} type="button" role="tab" id={`${idPrefix}-${t.id}`} aria-selected={t.id === value} aria-controls={`${idPrefix}-panel-${t.id}`}
          tabIndex={t.id === value ? 0 : -1} ref={(el) => { refs.current[t.id] = el; }} onClick={() => onChange(t.id)} onKeyDown={(e) => move(e, i)}>{t.label}</button>
      ))}
    </div>
  );
}

export function TabPanel({ id, active, idPrefix = 'tab', children }: { id: string; active: boolean; idPrefix?: string; children: React.ReactNode }) {
  return <div role="tabpanel" id={`${idPrefix}-panel-${id}`} aria-labelledby={`${idPrefix}-${id}`} hidden={!active}>{active ? children : null}</div>;
}
