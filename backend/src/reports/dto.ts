import { IsIn, IsInt, IsISO8601, IsOptional, Max, Min } from 'class-validator';

export const REPORT_FORMATS = ['json', 'text'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export class ReportFormatQuery {
  /** json (default) returns structured data; text returns a ready-to-send plain-text report. */
  @IsOptional() @IsIn(REPORT_FORMATS as unknown as string[]) format?: ReportFormat;
}

export class PeriodQuery extends ReportFormatQuery {
  /** Start of the period, ISO 8601. Defaults to `days` before `to`. */
  @IsOptional() @IsISO8601() from?: string;
  /** End of the period, ISO 8601. Defaults to now. */
  @IsOptional() @IsISO8601() to?: string;
  /** Shortcut for the length of the period when `from` is omitted. Default 7. */
  @IsOptional() @IsInt() @Min(1) @Max(366) days?: number;
}

export const DEFAULT_PERIOD_DAYS = 7;

/** Turns query parameters into a concrete [from, to] pair. */
export function resolvePeriod(q: PeriodQuery, now: Date = new Date()): { from: Date; to: Date } {
  const to = q.to ? new Date(q.to) : now;
  const from = q.from
    ? new Date(q.from)
    : new Date(to.getTime() - (q.days ?? DEFAULT_PERIOD_DAYS) * 86400000);
  return { from, to };
}
