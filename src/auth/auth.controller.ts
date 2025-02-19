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
  login(@Body() authDto: AuthDto) {
    return this.authService.login(authDto);
  }

  @Post('signout')
  @UseGuards(JwtAuthGuard)
  signout(@Req() req: Request, @Res() res: Response) {
    const token =
      req.cookies?.access_token || req.headers.authorization?.split(' ')[1];

    if (token) {
      this.authService.signout(token);
    }

    res.cookie('access_token', '', {
      expires: new Date(0),
      httpOnly: true,
      secure: true,
    });
    return res.status(200).json({ message: 'User signed out successfully' });
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
}
