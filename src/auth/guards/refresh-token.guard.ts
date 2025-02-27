// import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
// import { AuthService } from '../auth.service';

// @Injectable()
// export class RefreshTokenGuard implements CanActivate {
//   constructor(private authService: AuthService) {}

//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const request = context.switchToHttp().getRequest();
//     const refreshToken = request.cookies['refresh_token'];
//     const deviceId = request.body.deviceId;

//     if (!refreshToken || !deviceId) return false;

//     return await this.authService.validateRefreshToken(refreshToken, deviceId);
//   }
// }
