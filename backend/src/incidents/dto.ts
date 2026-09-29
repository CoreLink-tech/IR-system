import { IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

const STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

export class UpdateIncidentStatusDto {
  @IsString() @IsIn(STATUSES) status!: string;
  @IsOptional() @IsString() @MaxLength(4000) notes?: string;
}

export class AssignIncidentDto {
  @IsString() assignedTo!: string;
}
