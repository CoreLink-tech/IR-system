import { ArrayNotEmpty, IsArray, IsInt, IsOptional, IsString, Min } from 'class-validator';

export class CreateApiKeyDto {
  @IsString() name!: string;
  @IsArray() @ArrayNotEmpty() scopes!: string[];
  @IsOptional() @IsInt() @Min(0) expiresInDays?: number;
}
