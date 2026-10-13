import type { ReactNode } from 'react';
import { Button } from './ui';

export interface Column<T> { key: string; header: string; cell: (row: T) => ReactNode }

/**
 * A table on a wide screen and a stack of cards on a narrow one (CSS does the switch, using the
 * data-label of each cell). Explicit roles keep it a table for screen readers either way.
 */
export function ResponsiveTable<T>({ columns, rows, rowKey, caption, rowClass }: {
  columns: Column<T>[]; rows: T[]; rowKey: (r: T) => string; caption: string; rowClass?: (r: T) => string | undefined;
}) {
  return (
    <table className="rtable" role="table">
      <caption className="sr-only">{caption}</caption>
      <thead role="rowgroup"><tr role="row">{columns.map((c) => <th key={c.key} role="columnheader" scope="col">{c.header}</th>)}</tr></thead>
      <tbody role="rowgroup">
        {rows.map((r) => (
          <tr key={rowKey(r)} role="row" className={rowClass?.(r)}>
            {columns.map((c) => <td key={c.key} role="cell" data-label={c.header}>{c.cell(r)}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Pagination({ meta, onPage, noun = 'results' }: { meta: { page: number; pageSize: number; total: number; totalPages: number }; onPage: (p: number) => void; noun?: string }) {
  if (meta.total === 0) return null;
  const from = (meta.page - 1) * meta.pageSize + 1;
  const to = Math.min(meta.page * meta.pageSize, meta.total);
  return (
    <nav className="pager" aria-label="Pages">
      <span className="muted" aria-live="polite">Showing {from} to {to} of {meta.total} {noun}</span>
      <span className="toolbar">
        <Button onClick={() => onPage(meta.page - 1)} disabled={meta.page <= 1}>Previous</Button>
        <span aria-current="page">Page {meta.page} of {Math.max(1, meta.totalPages)}</span>
        <Button onClick={() => onPage(meta.page + 1)} disabled={meta.page >= meta.totalPages}>Next</Button>
      </span>
    </nav>
  );
}
