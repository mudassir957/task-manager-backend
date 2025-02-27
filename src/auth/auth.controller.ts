import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { RolesGuard } from './guards/roles.guard';
import { UserRole } from 'src/users/user.entity';
import { Public, Roles } from './decorators/decorator';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { Request, Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @Public()
  signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.signup(createUserDto);
  }

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 30000 } })
  @UseGuards(LocalAuthGuard)
  async login(@Body() authDto: AuthDto, @Res() res: Response) {
    try {
      const { accessToken, refreshToken, deviceId } =
        await this.authService.login(authDto);

      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: false,
        path: '/',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        // maxAge: 60 * 60 * 1000,
        maxAge: 60 * 1000,
      });

      res.cookie('device_id', deviceId, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
      return res.status(200).json({ access_token: accessToken });
    } catch (error) {
      console.error('Error during login:', error);
      throw new UnauthorizedException(error.message || 'Login failed');
    }
  }

  @Post('signout')
  @UseGuards(JwtAuthGuard)
  async signout(@Req() req: Request, @Res() res: Response) {
    try {
      console.log('Cookies Signout', req.cookies); // debugging
      console.log('Authorization Header:', req.headers.authorization);

      const accessToken =
        req.cookies?.access_token || req.headers.authorization?.split(' ')[1];

      const refreshToken = req.cookies?.refresh_token;
      const deviceId = req.cookies?.device_id;

      if (!accessToken || !refreshToken || !deviceId) {
        throw new UnauthorizedException('No valid session found');
      }

      // Call the signout service function
      console.log(accessToken, refreshToken, deviceId);
      await this.authService.signout(accessToken, refreshToken, deviceId);

      // Clear cookies on signout
      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        path: '/',
      });

      res.clearCookie('device_id', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        path: '/',
      });

      res.clearCookie('access_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        path: '/',
      });

      return res.status(200).json({ message: 'Successfully signed out' });
    } catch (error) {
      console.error('Signout error:', error);
      throw new UnauthorizedException('Error signing out user');
    }
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile(@Req() req) {
    return req.user;
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  adminRoute() {
    return { message: 'Welcome, Admin!' };
  }

  @Post('refresh-token')
  @Public()
  async refreshToken(@Req() req: Request, @Res() res: Response) {
    try {
      const refreshToken = req.cookies?.refresh_token || req.body.refreshToken;
      const deviceId = req.cookies?.device_id || req.body.deviceId;

      console.log('Refresh Token from cookies refreshToken', refreshToken);
      console.log('DEVICE ID from cookies', deviceId);

      if (!refreshToken || !deviceId) {
        throw new UnauthorizedException('Refresh token not provided');
      }

      const { access_token, refresh_token } =
        await this.authService.refreshAccessToken(refreshToken, deviceId);

      // Set new access token in cookie
      res.cookie('access_token', access_token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 1000, // 15 minutes
      });

      // Set new access token in cookie
      res.cookie('refresh_token', refresh_token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Set new access token in cookie
      res.cookie('device_id', deviceId, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 15 minutes
      });

      console.log(
        `ACCESS TOKEN ${access_token} and REFRESH TOKEN ${refresh_token}`,
      );

      return res.status(200).json({ access_token });
    } catch (error) {
      throw new UnauthorizedException('Could not refresh access token');
    }
  }

  @Get('verify-email')
  @Public()
  async verifyEmail(@Query('token') token: string) {
    console.log('Verify Email Controller:', token);
    return this.authService.verifyEmail(token);
  }

  @Post('forgot-password')
  @Public()
  async forgotPassword(@Body() forgotPasswordDto: ForgetPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset-password')
  @Public()
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
  }

  // @Post('resend-verification')
  // @Public()
  // async resendVerification(@Body() authDto: AuthDto) {
  //   return this.authService.sendVerificationEmail(authDto.email);
  // }
}
