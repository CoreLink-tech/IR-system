import { IsBoolean, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateRuleDto {
  @IsOptional() @IsBoolean() isEnabled?: boolean;
  /** Only the settings being changed. Checked against the allowed ranges for this rule. */
  @IsOptional() @IsObject() config?: Record<string, unknown>;
  /** Why the change was made. Kept in the audit log. */
  @IsOptional() @IsString() @MaxLength(500) reason?: string;
}

export class ResetRuleDto {
  @IsOptional() @IsString() @MaxLength(500) reason?: string;
}
