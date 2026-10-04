import { BadRequestException } from '@nestjs/common';

export interface PaginationQuery {
  page?: number | string;
  pageSize?: number | string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface Paginated<T> {
  data: T[];
  meta: { page: number; pageSize: number; total: number; totalPages: number };
}

/**
 * Parses paging and sorting. When `allowedSort` is given, a sortBy outside the
 * list falls back to the default instead of reaching the database, where an
 * unknown column would cause a 500 error.
 */
export function parsePagination(
  q: PaginationQuery,
  defaults: { pageSize?: number; sortBy?: string; allowedSort?: string[] } = {},
) {
  const page = Math.max(1, Math.floor(Number(q.page)) || 1);
  // A size that is missing, zero, negative or not a number means "use the default".
  const requestedSize = Math.floor(Number(q.pageSize));
  const pageSize = requestedSize > 0 ? Math.min(200, requestedSize) : Math.min(200, defaults.pageSize || 25);
  const fallback = defaults.sortBy || 'createdAt';
  const requested = typeof q.sortBy === 'string' && q.sortBy ? q.sortBy : fallback;
  const sortBy = defaults.allowedSort && !defaults.allowedSort.includes(requested) ? fallback : requested;
  const sortOrder: 'asc' | 'desc' = q.sortOrder === 'asc' ? 'asc' : 'desc';
  return { page, pageSize, skip: (page - 1) * pageSize, take: pageSize, sortBy, sortOrder };
}

export function toPaginated<T>(data: T[], total: number, page: number, pageSize: number): Paginated<T> {
  return { data, meta: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) || 1 } };
}

/** Parses an optional date query parameter. Throws a 400 for an invalid value. */
export function parseDateParam(value: unknown, name: string): Date | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const d = new Date(String(value));
  if (isNaN(d.getTime())) throw new BadRequestException(`Invalid ${name} date`);
  return d;
}
