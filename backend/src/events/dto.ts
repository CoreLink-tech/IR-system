import { IsDateString, IsIn, IsObject, IsOptional, IsString, Matches, MaxLength } from 'class-validator';

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export class CreateEventDto {
  @IsString() @MaxLength(64) event_type!: string;
  @IsString() @IsIn(SEVERITIES) severity!: string;
  @IsOptional() @IsString() @MaxLength(45) ip_address?: string;
  @IsOptional() @IsString() @MaxLength(128) user_id?: string;
  @IsOptional() @IsString() @MaxLength(128) session_id?: string;
  @IsOptional() @IsString() @MaxLength(512) user_agent?: string;
  @IsOptional() @IsString() @MaxLength(10) request_method?: string;
  @IsOptional() @IsString() @MaxLength(1024) request_path?: string;
  @IsOptional() @IsString() @MaxLength(128) request_id?: string;
  /**
   * A unique id for this event, chosen by the sender. Sending the same event_id again (for
   * example after a timeout) returns the original result instead of storing a second copy.
   */
  @IsOptional() @IsString() @MaxLength(64) @Matches(/^[A-Za-z0-9._:-]+$/) event_id?: string;
  @IsOptional() @IsObject() metadata?: Record<string, unknown>;
  @IsOptional() @IsDateString() timestamp?: string;
}
