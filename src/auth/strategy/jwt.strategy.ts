import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { jwtConstants } from '../constants';
import { RedisService } from '../../redis/redis.service';
import { Request } from 'express';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);
  constructor(
    private redisService: RedisService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }

  async validate(payload: JwtPayload) {
    this.logger.log(`Validating token with jti: ${payload.jti}`);
    // Check if the token is blacklisted
    const isBlacklisted = await this.redisService.isTokenBlacklisted(
      payload.jti,
    );
    console.log(isBlacklisted);
    if (isBlacklisted) {
      this.logger.warn(`Token ${payload.jti} is blacklisted`);
      throw new UnauthorizedException('Token is blacklisted');
    }

    return {
      id: payload.id,
      email: payload.email,
      role: payload.role,
    };
  }
}
