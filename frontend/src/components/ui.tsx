import { useEffect, useId, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { describeError } from '@/api/errors';
import { Dialog } from './Dialog';

export function Button({ variant, busy, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'danger' | 'link'; busy?: boolean }) {
  return <button type="button" {...rest} disabled={rest.disabled || busy} aria-busy={busy || undefined} className={`btn ${variant ?? ''} ${rest.className ?? ''}`.trim()}>{busy ? 'Working...' : children}</button>;
}

export function LinkButton({ to, children, variant }: { to: string; children: ReactNode; variant?: 'primary' }) {
  return <Link to={to} className={`btn ${variant ?? ''}`.trim()}>{children}</Link>;
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string | null; children: (p: { id: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean }) => ReactNode }) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : '', error ? `${id}-err` : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {hint && <span className="hint" id={`${id}-hint`}>{hint}</span>}
      {error && <span className="error-text" id={`${id}-err`} role="alert">{error}</span>}
    </div>
  );
}

export function Skeleton({ lines = 3, height = '1.1rem' }: { lines?: number; height?: string }) {
  return (
    <div role="status" aria-label="Loading" className="stack" style={{ display: 'grid', gap: '.6rem' }}>
      {Array.from({ length: lines }, (_, i) => <div key={i} className="skeleton" style={{ height, width: i === lines - 1 ? '60%' : '100%' }} />)}
      <span className="sr-only">Loading</span>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="card" style={{ textAlign: 'center', padding: '2rem 1rem' }}>
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  );
}

/** Counts down a number of seconds, for "wait N seconds" after a 429. */
export function useCountdown(seconds: number | undefined) {
  const [left, setLeft] = useState(seconds ?? 0);
  useEffect(() => {
    setLeft(seconds ?? 0);
    if (!seconds) return;
    const t = setInterval(() => setLeft((s) => (s <= 1 ? (clearInterval(t), 0) : s - 1)), 1000);
    return () => clearInterval(t);
  }, [seconds]);
  return left;
}

/** How a failed request looks on screen: plain words, a retry button, and a reference for support when the server gave one. */
export function ErrorPanel({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const d = describeError(error);
  const wait = useCountdown(d.retryAfterSeconds);
  return (
    <div className={`card error-box ${compact ? '' : 'stack'}`} role="alert">
      <h3 style={{ marginTop: 0 }}>{d.title}</h3>
      <p>{d.body}</p>
      {d.requestId && <p className="small muted">Reference for support: <code>{d.requestId}</code></p>}
      {d.retryAfterSeconds ? <p aria-live="polite">{wait > 0 ? `You can try again in ${wait} seconds.` : 'You can try again now.'}</p> : null}
      {onRetry && <Button onClick={onRetry} disabled={wait > 0}>Try again</Button>}
    </div>
  );
}

export function Notice({ title, children, tone }: { title?: string; children: ReactNode; tone?: 'ok' }) {
  return <div className={`notice ${tone === 'ok' ? 'ok-box' : ''}`}>{title && <strong>{title}</strong>}{children}</div>;
}

/** Say what an action will do, in plain words, before it is done. */
export function ConfirmDialog({ title, children, confirmLabel, danger, busy, error, onConfirm, onClose }: {
  title: string; children: ReactNode; confirmLabel: string; danger?: boolean; busy?: boolean; error?: unknown; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Dialog title={title} onClose={onClose} busy={busy}>
      {children}
      {error ? <ErrorPanel compact error={error} /> : null}
      <div className="actions">
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} busy={busy}>{confirmLabel}</Button>
      </div>
    </Dialog>
  );
}

/** Show data, or the right loading, empty or error state. One failed panel never blanks the page. */
export function QueryState<T>({ query, children, skeleton }: {
  query: { data?: T; error: unknown; isPending: boolean; isError: boolean; refetch: () => unknown };
  children: (data: T) => ReactNode; skeleton?: ReactNode;
}) {
  if (query.isPending) return <>{skeleton ?? <Skeleton />}</>;
  if (query.isError && query.data === undefined) return <ErrorPanel error={query.error} onRetry={() => void query.refetch()} />;
  return <>{children(query.data as T)}</>;
}
