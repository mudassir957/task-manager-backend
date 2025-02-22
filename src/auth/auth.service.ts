import {
  BadRequestException,
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
import { Resend } from 'resend';
import { jwtConstants } from './constants';
import { Throttle } from '@nestjs/throttler';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private resend = new Resend(process.env.RESEND_API_KEY);
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
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
      isVerified: false,
    });
    await this.userRepository.save(user);

    const verificationToken = await this.jwtService.signAsync(
      { email },
      { secret: jwtConstants.secret, expiresIn: '1h' },
    );

    console.log('Verification Token' + verificationToken);

    await this.cacheManager.set(`verify:${email}`, verificationToken, 60000);

    const verificationLink = `http://localhost:3000/auth/verify-email?token=${verificationToken}`;
    await this.sendVerificationEmail(email, verificationLink);

    return {
      message: 'User registered successfully. Please verify your email.',
      verificationLink,
    };
  }

  async sendVerificationEmail(email: string, verificationLink: string) {
    try {
      await this.resend.emails.send({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Verify your email',
        html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`,
      });
    } catch (error) {
      this.logger.error('Error sending verification email:', error);
      throw new BadRequestException('Failed to send verification email.');
    }
  }

  async verifyEmail(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const email = decoded.email;

      const storedToken = await this.cacheManager.get(`verify:${email}`);
      if (!storedToken || storedToken !== token) {
        throw new UnauthorizedException(
          'Invalid or expired verification token',
        );
      }

      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      await this.userRepository.update(user.id, { isVerified: true });
      await this.cacheManager.del(`verify:${email}`);

      return { message: 'Email successfully verified!' };
    } catch (error) {
      throw new UnauthorizedException('Email verification failed');
    }
  }

  async login(authDto: AuthDto, res: Response) {
    try {
      const { email, password } = authDto;

      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        console.log('User not found');
        throw new UnauthorizedException('Invalid credentials');
      }

      // if (user.isVerified === false) {
      //   throw new UnauthorizedException('First verify throught email link');
      // }

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
        secret: jwtConstants.secret,
        expiresIn: '1h',
      });

      // Generate Refresh Token
      const refreshToken = await this.jwtService.signAsync(
        { id: user.id },
        { expiresIn: '7d' },
      );

      const deviceId = uuidv4();

      await this.cacheManager.set(
        `refreshToken:${user.id}:${deviceId}`,
        refreshToken,
        604800,
      );

      await this.userRepository.update(user.id, {
        refreshToken,
      });

      // Set Refresh Token in HTTP-only cookie
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.cookie('device_id', deviceId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      console.log('Login successful');
      return res.status(200).json({
        access_token: accessToken,
        refresh_token: refreshToken,
        device_id: deviceId,
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
    deviceId: string,
    res: Response,
  ): Promise<{ access_token: string }> {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    if (!deviceId) {
      throw new UnauthorizedException('Device ID missing');
    }

    try {
      const decoded = this.jwtService.verify(refreshToken);
      const user = await this.userRepository.findOne({
        where: { id: decoded.id },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const storedRefreshToken = await this.cacheManager.get<string>(
        `refreshToken:${decoded.id}:${deviceId}`,
      );

      if (!storedRefreshToken || refreshToken !== storedRefreshToken) {
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
        `refreshToken:${decoded.id}:${deviceId}`,
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
      console.error('Error during token refresh:', error);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new UnauthorizedException('User with this email does not exist');
    }

    const resetToken = await this.jwtService.signAsync(
      { email },
      { expiresIn: '15m' },
    );
    console.log(resetToken);

    await this.cacheManager.set(`reset:${email}`, resetToken, 360000);

    const resetLink = `http://localhost:3000/auth/reset-password?token=${resetToken}`;
    await this.sendVerificationEmail(email, resetLink);

    return { message: 'Password reset link sent to your email.', resetLink };
  }

  async resetPassword(token: string, newPassword: string) {
    try {
      console.log('RESET PASSWORD TRIGGERS');
      const decoded = await this.jwtService.verifyAsync(token);
      console.log(decoded);
      const email = decoded.email;

      const storedToken = await this.cacheManager.get(`reset:${email}`);
      if (!storedToken || storedToken !== token) {
        throw new UnauthorizedException('Invalid or expired reset token');
      }

      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      user.password = newPassword;
      await this.userRepository.save(user);
      await this.cacheManager.del(`reset:${email}`);

      return { message: 'Password has been reset successfully.' };
    } catch (error) {
      throw new UnauthorizedException('Password reset failed');
    }
  }
}
