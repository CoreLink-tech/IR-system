import { IsDateString, IsIn, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

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
  @IsOptional() @IsObject() metadata?: Record<string, unknown>;
  @IsOptional() @IsDateString() timestamp?: string;
}
