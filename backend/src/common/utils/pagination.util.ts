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

export function parsePagination(q: PaginationQuery, defaults: { pageSize?: number; sortBy?: string } = {}) {
  const page = Math.max(1, Number(q.page) || 1);
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize) || defaults.pageSize || 25));
  const sortBy = q.sortBy || defaults.sortBy || 'createdAt';
  const sortOrder: 'asc' | 'desc' = q.sortOrder === 'asc' ? 'asc' : 'desc';
  return { page, pageSize, skip: (page - 1) * pageSize, take: pageSize, sortBy, sortOrder };
}

export function toPaginated<T>(data: T[], total: number, page: number, pageSize: number): Paginated<T> {
  return { data, meta: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) || 1 } };
}
