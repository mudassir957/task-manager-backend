import {
  Body,
  Controller,
  Get,
  Post,
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

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @Public()
  signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.signup(createUserDto);
  }

  @Post('login')
  @UseGuards(LocalAuthGuard)
  login(@Body() authDto: AuthDto, @Res() res: Response) {
    return this.authService.login(authDto, res);
  }

  @Post('signout')
  @UseGuards(JwtAuthGuard)
  async signout(@Req() req: Request, @Res() res: Response) {
    try {
      const token =
        req.cookies?.access_token || req.headers.authorization?.split(' ')[1];

      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      return this.authService.signout(token, res);
    } catch (error) {
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
      console.log('Refresh token Controller:', refreshToken);

      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token not provided');
      }

      const newAccessToken = await this.authService.refreshAccessToken(
        refreshToken,
        res,
      );

      return res
        .status(200)
        .json({ access_token: newAccessToken.access_token });
    } catch (error) {
      throw new UnauthorizedException('Could not refresh access token');
    }
  }
}
