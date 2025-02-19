import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User, UserRole } from 'src/users/user.entity';
import { Repository } from 'typeorm';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { RedisService } from '../redis/redis.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
    private redisService: RedisService,
  ) {}

  async signup(createUserDto: CreateUserDto) {
    const { email, name, password, role } = createUserDto;
    const userExists = await this.userRepository.findOne({ where: { email } });

    if (userExists) {
      throw new UnauthorizedException('User already exists');
    }

    const user = this.userRepository.create({
      name,
      email,
      password,
      role: role || UserRole.USER,
    });
    await this.userRepository.save(user);
    return { message: 'User registered successfully' };
  }

  async login(authDto: AuthDto): Promise<{ access_token: string }> {
    const { email, password } = authDto;
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const jti = uuidv4();
    this.logger.log(`Validating token with jti: ${jti}`);

    const payload: JwtPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: uuidv4(),
    };

    return { access_token: await this.jwtService.signAsync(payload) };
  }

  async signout(token: string): Promise<{ message: string }> {
    try {
      const decode = this.jwtService.decode(token) as JwtPayload;
      if (!decode || !decode.jti) {
        this.logger.error('No jti found in token');
        throw new Error('Invalid token');
      }
      this.logger.log(`Blacklisting token with jti: ${decode.jti}`);
      // blacklist token in redis
      await this.redisService.blacklistToken(decode.jti, 3600);
      return { message: 'User signed out successfully' };
    } catch (error) {
      this.logger.error('Error signing out user:', error);
      throw new UnauthorizedException('Error signing out user');
    }
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      return null;
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return null;
    }
    return user;
  }

  async validateUserById(id: number): Promise<any> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      return null;
    }
    return user;
  }
}
