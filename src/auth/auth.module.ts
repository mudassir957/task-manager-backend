import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { LocalStrategy } from './strategy/local.strategy';
import { JwtStrategy } from './strategy/jwt.strategy';
import { User } from '../users/user.entity';
import { RedisService } from '../redis/redis.service';
import { RedisModule } from 'src/redis/redis.module';
import { CacheModule } from '@nestjs/cache-manager';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.register({
      global: true,
      secret: jwtConstants.secret,
      signOptions: { expiresIn: '1h' },
    }),
    RedisModule,
  ],
  providers: [AuthService, RedisService, LocalStrategy, JwtStrategy],
  exports: [AuthService, RedisService],
  controllers: [AuthController],
})
export class AuthModule {}
