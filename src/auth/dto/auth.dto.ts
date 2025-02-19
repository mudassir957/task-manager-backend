import { IsEmail, IsEnum, IsNotEmpty, MinLength } from 'class-validator';
import { UserRole } from 'src/users/user.entity';

export class AuthDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @IsEnum(UserRole)
  role: UserRole;
}
