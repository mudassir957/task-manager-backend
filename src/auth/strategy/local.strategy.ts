import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { AuthDto } from '../dto/auth.dto';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    console.log(`Validating user: ${email}`);

    const user = await this.authService.validateUser(email, password);
    console.log('User from validateUser:', user);

    if (!user) {
      console.error('Authentication failed: Invalid credentials');
      throw new UnauthorizedException('Invalid credentials');
    }

    console.log('Authentication successful:', user);
    return user;
  }
}
