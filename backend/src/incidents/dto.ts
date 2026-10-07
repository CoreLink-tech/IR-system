import { IsIn, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

const STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

export class UpdateIncidentStatusDto {
  @IsString() @IsIn(STATUSES) status!: string;
  @IsOptional() @IsString() @MaxLength(4000) notes?: string;
}

export class AssignIncidentDto {
  @IsString() assignedTo!: string;
}

export class AddIncidentNoteDto {
  @IsString() @MinLength(1) @MaxLength(2000) note!: string;
}
