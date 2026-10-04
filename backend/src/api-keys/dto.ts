import { ArrayNotEmpty, IsArray, IsIn, IsInt, IsOptional, IsString, MaxLength, Min } from 'class-validator';
import { SCOPES } from '../common/constants';

export class CreateApiKeyDto {
  @IsString() @MaxLength(128) name!: string;
  // Only known scopes are accepted, so a typo or an invented scope cannot be saved
  // and every key stays least-privilege.
  @IsArray() @ArrayNotEmpty() @IsIn(Object.values(SCOPES), { each: true }) scopes!: string[];
  @IsOptional() @IsInt() @Min(0) expiresInDays?: number;
}
