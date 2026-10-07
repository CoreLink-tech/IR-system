import { IsBoolean, IsEmail, IsIn, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { ROLES } from '../common/constants';

export class LoginDto {
  @IsEmail() email!: string;
  @IsString() @MinLength(8) password!: string;
  /**
   * Browsers send true. The refresh token then travels only in an httpOnly cookie and is
   * left out of the response body. Other clients omit it and get the token in the body.
   */
  @IsOptional() @IsBoolean() useCookie?: boolean;
}

export class RefreshDto {
  /** Omitted by browsers, which send the cookie instead. */
  @IsOptional() @IsString() refreshToken?: string;
}

export class ChangePasswordDto {
  @IsString() @MinLength(8) currentPassword!: string;
  @IsString() @MinLength(12) newPassword!: string;
}

export class CreateUserDto {
  @IsEmail() email!: string;
  @IsString() @MinLength(12) password!: string;
  @IsOptional() @IsString() name?: string;
  @IsString() role!: string;
  /** The new account must set its own password before it can do anything else. */
  @IsOptional() @IsBoolean() requirePasswordChange?: boolean;
}

export class UpdateUserDto {
  @IsOptional() @IsIn(Object.values(ROLES)) role?: string;
  @IsOptional() @IsBoolean() isActive?: boolean;
}

export class ResetUserPasswordDto {
  /** A temporary password chosen by the super admin. The person must change it at next sign-in. */
  @IsString() @MinLength(12) @MaxLength(128) newPassword!: string;
}
