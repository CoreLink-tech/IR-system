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
  @IsString() @MinLength(12, { message: 'The new password must be at least 12 characters long.' }) @MaxLength(128, { message: 'The new password must be at most 128 characters long.' }) newPassword!: string;
}

export class CreateUserDto {
  @IsEmail() email!: string;
  @IsString() @MinLength(12, { message: 'The password must be at least 12 characters long.' }) @MaxLength(128, { message: 'The password must be at most 128 characters long.' }) password!: string;
  @IsOptional() @IsString() @MaxLength(120) name?: string;
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
  @IsString() @MinLength(12, { message: 'The password must be at least 12 characters long.' }) @MaxLength(128, { message: 'The password must be at most 128 characters long.' }) newPassword!: string;
}

/** The second step of signing in: the short-lived token from the password step, plus a code or a recovery code. */
export class VerifyTwoFactorDto {
  @IsString() @MaxLength(2000) challengeToken!: string;
  @IsOptional() @IsString() @MaxLength(12) code?: string;
  @IsOptional() @IsString() @MaxLength(40) recoveryCode?: string;
}
export class EnrolStartDto {
  @IsString() @MaxLength(2000) challengeToken!: string;
}
export class EnrolConfirmDto {
  @IsString() @MaxLength(2000) challengeToken!: string;
  @IsString() @MaxLength(12) code!: string;
}
export class CodeDto {
  @IsString() @MaxLength(12) code!: string;
}
/** Changing two-step settings needs the password AND a current code. */
export class PasswordAndCodeDto {
  @IsString() @MaxLength(200) password!: string;
  @IsString() @MaxLength(12) code!: string;
}
