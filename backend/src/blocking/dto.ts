import { Transform } from 'class-transformer';
import { IsBoolean, IsInt, IsOptional, IsString, MaxLength, Min } from 'class-validator';

export class BlockIpDto {
  @IsString() ipAddress!: string;
  @IsString() @MaxLength(2000) reason!: string;
  // Keep the value exactly as sent. Implicit conversion would turn any non-empty string,
  // including "false", into true, and a mistaken value would create a permanent block.
  @Transform(({ obj, key }) => obj[key])
  @IsOptional() @IsBoolean() permanent?: boolean;
  @IsOptional() @IsInt() @Min(1) ttlMinutes?: number;
  @IsOptional() @IsString() relatedIncidentId?: string;
}

export class UnblockIpDto {
  @IsString() ipAddress!: string;
  @IsString() @MaxLength(2000) reason!: string;
}

export class AllowIpDto {
  @IsString() ipAddress!: string;
  @IsString() @MaxLength(2000) reason!: string;
  @IsOptional() @IsInt() @Min(1) ttlMinutes?: number;
}
