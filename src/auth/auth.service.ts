import {
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
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
import { Response } from 'express';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
    private redisService: RedisService,
  ) {}

  // async onModuleInit() {
  //   console.log('Checking Redis connection...');
  //   console.log('Store', this.cacheManager.stores);

  //   try {
  //     await this.cacheManager.set('test_key', 'test_value', 60000);
  //     const value = await this.cacheManager.get('test_key');

  //     console.log('Redis Test Value:', value);

  //     if (value !== 'test_value') {
  //       throw new Error('Redis connection failed');
  //     } else {
  //       console.log('✅ Redis is working properly');
  //     }
  //   } catch (error) {
  //     console.error('❌ Redis Error:', error);
  //     throw error;
  //   }
  // }

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

  async login(authDto: AuthDto, res: Response) {
    try {
      console.log('Login function reached with:', authDto);
      const { email, password } = authDto;

      // Find user by email
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        console.log('User not found');
        throw new UnauthorizedException('Invalid credentials');
      }

      // Compare passwords
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        console.log('Invalid password');
        throw new UnauthorizedException('Invalid credentials');
      }

      // Generate JWT Payload
      const payload: JwtPayload = {
        id: user.id,
        email: user.email,
        role: user.role,
        jti: uuidv4(),
      };

      // Generate Access Token
      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: '15m',
      });

      // Generate Refresh Token
      const refreshToken = await this.jwtService.signAsync(
        { id: user.id },
        { expiresIn: '7d' },
      );

      await this.cacheManager.set(
        `refreshToken:${user.id}`,
        refreshToken,
        7 * 24 * 60 * 60,
      );
      const storedToken = await this.cacheManager.get(
        `refreshToken:${user.id}`,
      );
      console.log('Stored Refresh Token REDIS:', storedToken);

      // Hash Refresh Token before saving in the database
      // const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      await this.userRepository.update(user.id, {
        refreshToken,
      });

      // Set Refresh Token in HTTP-only cookie
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Secure in production
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      console.log('Login successful');
      return res.status(200).json({
        access_token: accessToken,
      });
    } catch (error) {
      console.error('Error during login:', error);
      throw new UnauthorizedException(error.message || 'Login failed');
    }
  }

  async signout(token: string, res: Response) {
    try {
      const decode = this.jwtService.decode(token) as JwtPayload;
      if (!decode || !decode.jti) {
        this.logger.error('No jti found in token');
        throw new Error('Invalid token');
      }
      this.logger.log(`Blacklisting token with jti: ${decode.jti}`);
      // blacklist token in redis
      await this.redisService.blacklistToken(decode.jti, 3600);

      // Remove refresh token from Redis
      await this.cacheManager.del(`refreshToken:${decode.id}`);

      // remove refresh token from database
      await this.userRepository.update(decode.id, {
        refreshToken: null,
      });

      res.cookie('refresh_token', '', {
        expires: new Date(0),
        httpOnly: true,
        secure: true,
      });

      return res.status(200).json({
        message: 'Logout successful',
      });
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

  async refreshAccessToken(
    refreshToken: string,
    res: Response,
  ): Promise<{ access_token: string }> {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    try {
      const decoded = this.jwtService.verify(refreshToken);
      const user = await this.userRepository.findOne({
        where: { id: decoded.id },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('User not found');
      }

      // Validate stored refresh token
      if (refreshToken !== user.refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate a new access token
      const payload: JwtPayload = {
        id: user.id,
        email: user.email,
        role: user.role,
        jti: uuidv4(),
      };

      const newAccessToken = await this.jwtService.signAsync(payload, {
        expiresIn: '15m',
      });

      const newRefreshToken = await this.jwtService.signAsync(
        { id: decoded.id },
        { expiresIn: '7d' },
      );

      // Store new refresh token in Redis
      await this.cacheManager.set(
        `refreshToken:${decoded.id}`,
        newRefreshToken,
        7 * 24 * 60 * 60,
      );

      // update in databasee
      await this.userRepository.update(user.id, {
        refreshToken: newRefreshToken,
      });

      // Set new refresh token in HTTP-only cookie
      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return {
        access_token: newAccessToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }
}
